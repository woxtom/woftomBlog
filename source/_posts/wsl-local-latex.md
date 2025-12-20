title: WSL + VS Code 本地配置 LaTeX 全记录：从放弃 MiKTeX 到 TeX Live 
date: 2025-12-20 
tags:
  - LaTeX
  - WSL
  - VS Code
  - 环境配置
categories:[技术, 折腾日志]
---

作为一名 CS 专业的学生，LaTeX 几乎是刚需。虽然 Overleaf 很好用，但受限于网络和免费版编译时长的限制，我决定在本地（WSL2 + VS Code）搭建一套完整的 LaTeX 编译环境。

但这趟旅程比我想象的要曲折——从 MiKTeX 的坑，到 TeX Live 的 4GB 豪横安装，再到安装卡死的惊魂时刻。本文记录了全过程，希望能帮大家避坑。

<!-- more -->

## 为什么要本地化？

1.  **速度**：本地编译秒级响应，不用等云端排队。
2.  **Git 管理**：配合 GitHub 更好地管理论文版本。
3.  **VS Code**：利用强大的插件体系（Copilot、Snippets）提高写作效率。

## 踩坑第一站：水土不服的 MiKTeX

起初，我先试试了 **MiKTeX**，因为它主打“轻量化”，缺什么包就自动下载什么。但在 Linux CLI (WSL) 环境下，这成了噩梦：

*   **权限地狱**：MiKTeX 分为 User 模式和 Admin 模式。经常出现 `pdflatex` 报错，提示管理员没有检查更新，或者 User 模式没权限写入文件。
*   **交互问题**：VS Code 在后台编译时，无法处理 MiKTeX 弹出的 "Do you want to install package X?" 的交互询问，导致编译直接挂起。

**结论**：在 Linux/WSL 环境下，不要折腾 MiKTeX，直接上标准答案 —— **TeX Live**。

## 正确姿势：拥抱 TeX Live (Full)

TeX Live 是 Linux 下最标准的发行版。虽然它有一个 `Basic` 版本，但我强烈建议直接安装 `texlive-full`。

**为什么？**
全量安装虽然高达 4~7GB，但它包含了人类历史上几乎所有的 LaTeX 包（从波兰语支持到乐谱绘制）。这不仅仅是软件，这是一座“亚历山大数字图书馆”。这意味着你以后编译任何论文，永远不会遇到 `Package not found` 的错误。用空间换取内心的宁静，值！

### 1. 清理旧环境（如果有）

如果你像我一样装过 MiKTeX，先卸载干净：

```bash
sudo apt-get remove miktex
sudo apt-get autoremove
rm -rf ~/.miktex
rm -rf ~/miktex-texmf
```

### 2. 安装 TeX Live Full

打开 WSL 终端，运行：

```bash
sudo apt update
sudo apt install texlive-full
```

然后去喝杯咖啡，这需要下载并解压数万个文件。

## 遭遇：卡在 "Pregenerating ConTeXt MarkIV format"

安装过程中，进度条跑得很欢，但在最后阶段，它突然停在了这句话不动了：

> `Pregenerating ConTeXt MarkIV format. This may take some time...`

我等了两个小时，它依然纹丝不动。

### 原因分析
这是 WSL 文件系统 IO 性能的一个瓶颈。安装脚本正在尝试通过 Lua 脚本遍历数万个文件来生成缓存，这一步极易导致进程死锁。

### 解决方案
如果卡住超过 20 分钟，请按以下步骤操作（亲测有效）：

1.  **强制终止**：在终端按 `Ctrl+C` 无法响应时，直接关闭 WSL 窗口。
2.  **彻底重启 WSL**：
    打开 Windows PowerShell，输入：
    ```powershell
    wsl --shutdown
    ```
3.  **修复安装**：
    重新进入 WSL (Ubuntu)，尝试修复：
    ```bash
    sudo dpkg --configure -a
    ```
4.  **跳过死锁环节（关键）**：
    如果修复命令依然卡在 ConTeXt 这一步（且我们要用的只是 LaTeX，不是 ConTeXt），可以直接删除那个导致卡死的安装后脚本：
    ```bash
    # 强制删除 ConTeXt 的配置脚本
    sudo rm /var/lib/dpkg/info/context.postinst
    
    # 再次运行修复
    sudo dpkg --configure -a
    ```
    这时，系统会认为安装已完成。

5.  **验证**：
    运行 `pdflatex --version`，看到 `pdfTeX 3.14...` 字样即宣告成功！

## VS Code 配置

环境装好了，接下来是编辑器配置。

1.  **WSL 插件**：确保 VS Code 安装了 Microsoft 的 `WSL` 插件，并使用 `code .` 命令在 WSL 模式下打开项目文件夹。
2.  **LaTeX Workshop**：在 VS Code 的扩展市场中搜索并安装 `LaTeX Workshop` (James Yu 开发)。**注意：要点击 "Install in WSL: Ubuntu"**。

### 测试 

新建一个 `main.tex` 测试一下：

```latex
\documentclass{article}

% 引入数学和算法包
\usepackage{amsmath}
\usepackage{amssymb} 
\usepackage{listings} 

\begin{document}

\title{My Local Setup Check}
\author{Me}
\maketitle

\section{It Works!}
Hello WSL! This is compiled locally using \texttt{latexmk}.

\section{Math Demo}
CS 离不开数学：
\[
    \lim_{n \to \infty} \sum_{k=1}^n \frac{1}{k^2} = \frac{\pi^2}{6}
\]

\section{Code Demo}
\begin{lstlisting}[language=Python, frame=single]
def hello():
    print("LaTeX is Turing Complete!")
\end{lstlisting}

\end{document}
```

保存文件 (`Ctrl+S`)，LaTeX Workshop 会自动触发 `latexmk` 进行编译。点击侧边栏的 TeX 图标 -> `View LaTeX PDF`，即可看到生成的文档。

## 总结

虽然过程略有波折，但相比于 MiKTeX 的水土不服，**WSL + TeX Live Full + VS Code** 确实是目前 Windows 用户最优雅、最强大的 LaTeX 本地解决方案。

Happy TeXing!
