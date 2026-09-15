# 面向 Windows 的跨位宽进程内存操作库：设计与实现

**作者**：nginxee
**日期**：2026-09-15
**版本**：v1.0
**许可证**：MIT（见 [LICENSE](LICENSE)）

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6.svg)
![Language](https://img.shields.io/badge/Language-C-A8B9CC.svg)
![Arch](https://img.shields.io/badge/Arch-x86%20%7C%20x64-lightgrey.svg)
![Engine](https://img.shields.io/badge/Engine-Keystone-orange.svg)
![Code Style](https://img.shields.io/badge/code%20style-no%20defensive%20programming-red.svg)

---

## 摘要

针对 Windows 平台上进程内存操作库普遍存在的三个问题，即位宽适配逻辑重复、查询接口语义不安全、注入流程与读写流程割裂，本文设计并实现了一个轻量级进程内存操作库 memory_module。该库以 ntdll 原生接口作为读写通道，在编译期按宿主位宽分派 Nt 系与 Zw 系函数组，并针对 WOW64 场景选用 `NtWow64*64` 变体；通过遍历进程环境块（PEB）的 `InMemoryOrderModuleList` 链表与手工解析 PE 导出表实现目标进程内的符号定位；以字节加掩码的滑动匹配实现 AOB 特征码扫描；并借助 Keystone 汇编引擎与 `VirtualAllocEx` 实现运行时汇编、命名代码洞管理与远程线程执行。全库由 173 行接口声明与 1395 行实现构成，以对称双套前缀（`Memory64_` 与 `Memory32_`）统一 32 位与 64 位目标的调用形态。本文通过静态审查确认了关键偏移常量与 PE 规范的一致性以及两套接口的对称性。定量评估尚未执行，本文给出完整的评估协议与有效性威胁分析。

**关键词**：进程内存访问；原生接口；WOW64；进程环境块；特征码扫描；运行时汇编；可移植可执行格式

---

## 1 引言

### 1.1 研究背景

Windows 的进程内存访问能力由内核态与用户态两层接口共同暴露。用户态一侧，Win32 API 提供 `ReadProcessMemory` 与 `WriteProcessMemory` 作为公开入口；再往下，ntdll 导出的 `NtReadVirtualMemory`、`NtWriteVirtualMemory` 等原生接口承担实际的系统调用封装职责[12]。两者在功能上重叠，但在可访问地址范围、失败语义与可观测性上并不等价：原生接口的 64 位变体允许调用方在同一地址空间语义下操作高于 4GB 的地址，而 WOW64 场景下还存在专门适配的 `NtWow64ReadVirtualMemory64` 函数族[9]。

内存操作类工具（调试器、训练器、自动化测试框架）通常需要在同一份代码中同时面对 32 位与 64 位目标进程，并需要在目标进程内定位模块、解析导出符号、搜索特征码、注入并执行自定义代码。这些子任务在既有的公开库中往往以孤立的形式存在，导致调用方需要自行处理位宽分支、句柄生命周期与中间数据结构。

### 1.2 问题陈述

本文关注以下三个具体问题。

位宽适配逻辑重复。32 位与 64 位目标的读写接口在签名上仅地址类型不同，但调用方若直接基于 Win32 API 实现，需要为两种位宽各写一套句柄管理与错误处理代码，形成结构性重复。

查询接口语义不安全。基于公开 API 的模块枚举与符号解析依赖 `EnumProcessModules` 与 `GetProcAddress` 等在目标进程中不存在的便利函数，或依赖 `Toolhelp` 快照并配合文件解析，前者在跨位宽场景下能力受限，后者引入磁盘 I/O 与映像版本不一致的风险。

注入流程与读写流程割裂。向目标进程注入并执行代码的常规做法涉及分配内存、写入机器码、创建远程线程、回收内存等多个步骤，各步骤之间的命名与地址传递缺乏统一管理，容易产生悬挂指针与重复释放。

### 1.3 主要贡献

本文的贡献如下。

1. 提出一种编译期位宽分派方案，使同一份源码在 32 位与 64 位宿主下选择正确的原生接口函数组，并在运行期以命名通道（nt 与 zw）参数化调用。
2. 以纯读方式实现目标进程的模块基址获取与导出符号解析，仅依赖 PEB 与 PE 映像自身的结构，不依赖任何磁盘文件或目标进程侧 API。
3. 提出命名代码洞抽象，将内存分配、汇编装配、远程执行与释放统一在一个符号名之下，并明确其生命周期约束。

---

## 2 相关工作

### 2.1 Windows 进程内存访问机制

`NtQueryInformationProcess` 以 `ProcessBasicInformation`（信息类 0）返回 `PROCESS_BASIC_INFORMATION`，其中含目标进程的 PEB 基址[7]。PEB 结构含 `Ldr` 字段，指向 `PEB_LDR_DATA`，后者通过 `InMemoryOrderModuleList` 等双向链表串联所有已加载模块[8]。该路径是用户态获取模块信息的标准手段，其偏移布局随位宽与系统版本变化，需要逐版本维护。本文的实现明确固定了使用的偏移常量，并在第 4 节列出以便复核。

PE 映像自身的结构由微软的 PE 与 COFF 规范定义[1]。该规范给出可选头中数据目录表相对于可选头起始的偏移在 PE32 下为 96、在 PE32+ 下为 112，`SizeOfImage` 位于可选头偏移 56（即 0x38），并规定可选头魔数 0x10b 标识 PE32、0x20b 标识 PE32+。本文实现的常量选取与该规范一致，见 4.2 节。

### 2.2 现有工具与框架

Cheat Engine 是同类工具中最具代表性的实现，其脚本接口提供了 `readBytes`、`aobscan`、`alloc`、`createThread` 等原语[11]。本文的接口命名与工作流在很大程度上参照了该工具，差异在于本文以 C 库形式提供静态链接能力，而非以进程内脚本引擎形式提供交互能力。

Keystone 是一个支持多架构的轻量级汇编框架，提供以目标地址为参数的汇编接口，能够正确计算相对跳转与相对调用的编码偏移[10]。本文以该框架作为运行时汇编的唯一外部依赖。

Windows 内部机制的权威描述见 Windows Internals 一书，其中对内存管理器、加载器与原生接口层次的阐述构成本文实现路径的理论依据[12]。

### 2.3 本文定位与差异

与上述工作相比，本文的定位是一个不依赖目标进程配合、不依赖磁盘映像、以编译期位宽分派消除代码重复的底层原语集合。本文不含交互界面与脚本引擎，也不介入目标进程的异常处理。这一取舍的代价是接口数量较大（两套共 40 余个函数），收益是调用方的集成成本降低为一次链接与一次句柄设置。

---

## 3 系统设计

### 3.1 总体架构

系统按职责分为四层，如图 1 所示。

```text
┌──────────────────────────────────────────────────────────────┐
│  应用层        调用方代码（读写、扫描、注入的组织逻辑）        │
├──────────────────────────────────────────────────────────────┤
│  接口层        memory_module.h                               │
│                Memory64_*  /  Memory32_*  /  工具函数         │
├──────────────────────────────────────────────────────────────┤
│  能力层        读写原语   符号解析   AOB 扫描   代码洞管理      │
│                Read/Write  PEB/PE   ParseAOB   alloc/define   │
│                指针/文本   导出表    掩码匹配   /createThread  │
├──────────────────────────────────────────────────────────────┤
│  通道层        ntdll 原生接口（运行期解析）                    │
│                Nt/Zw*VirtualMemory  NtWow64*64                 │
│                NtQueryInformationProcess                       │
├──────────────────────────────────────────────────────────────┤
│  系统层        Windows 内核（虚拟内存管理、进程与线程管理）     │
└──────────────────────────────────────────────────────────────┘
```

图 1 模块总体架构

能力层内部还依赖两个外部资源：Keystone 汇编引擎与 Win32 的进程枚举、内存映射查询等支撑函数。前者仅在代码洞装配路径上被引用，后者用于进程查找与全内存扫描的区间枚举。

### 3.2 设计原则

本库遵循以下四条设计原则，其中 P4 是全库强制执行的编码约束。

P1：位宽分派前移。位宽差异只在编译期与函数指针选择点出现，不向调用方扩散。调用方以 `Memory64_` 或 `Memory32_` 前缀一次性选定语义，内部不得存在运行期位宽判断分支。

P2：只读解析。模块基址与导出符号的解析只通过目标进程的虚拟内存读取完成，不读取磁盘上的 PE 文件，不调用目标进程内的任何函数。该原则保证解析结果与被分析进程的实际映像一致。

P3：失败即返回。所有对外函数以真值表示成功、以零值表示失败，不抛出异常，不终止进程，不修改调用方的缓冲区语义。

P4：非防御式构造（禁止防御性编程）。代码不得包含不阻止任何真实状态损坏的分支。具体禁止的行为包括：对调用契约已经保证的参数做重复校验；用默认返回值静默掩盖失败以掩盖错误来源；为假想的极端情况添加冗余状态机、双重释放保护与句柄有效性反复确认；捕获并忽略错误码后继续使用脏数据。同时明确允许且必需的行为包括：跨信任边界的输入校验（特征码文本、模块名、从目标进程读回的原始字节、单行汇编文本）、外部函数返回码的传播、契约前置条件的显式失败。判定标准为：该分支能否防止一次真实的状态损坏或错误扩散。本文实现中的入口参数检查属于最后一类，与 P4 不矛盾。

### 3.3 读写通道抽象

读写通道以函数指针形式在运行期首次使用时解析并缓存。设宿主位宽为 W_h，目标位宽为 W_t，则通道选择规则如下。

- `Memory32_*`（W_t = 32）：32 位宿主与 64 位宿主均解析 `Nt/ZwReadVirtualMemory`。
- `Memory64_*`（W_t = 64）：32 位宿主解析 `Nt/ZwWow64ReadVirtualMemory64`，64 位宿主解析 `Nt/ZwReadVirtualMemory`。

选择在编译期由 `_WIN64` 宏完成。64 位宿主下宿主地址宽度与目标一致，指针可直接传递；32 位宿主下原生变体的地址参数为 32 位，不足以表达 64 位目标地址，必须以 `NtWow64*64` 变体替代。

通道参数 nt 与 zw 由 `Setprocess` 的第二个参数选择。二者的实现差异在于 `Zw*` 系列在进入内核前不设置先前模式位，行为在多数场景下等价。实现中约定：若 `Zw*` 符号解析失败则回落至 `Nt*`，以保证功能可用性优先于通道语义的严格保持。

位宽对称性由接口表统一保证。两套接口在下列十个能力维度上逐项对应，未注明地址类型差异者均为同名对应。

- 进程设置与句柄：`Setprocess` / `Openprocess` / `Close`
- 字节集读写：`ReadBytes` / `WriteAddr`
- 定宽读写：`ReadByte` / `ReadInt` / `ReadFloat` / `ReadLong` 及对应写函数
- 文本读写：`ReadText` / `WriteText`
- 矩阵读取：`GetMatrix`
- 指针读写：`ReadPointer` / `WritePointer`，地址宽度 8 字节对 4 字节
- 模块基址：`GetModuleBase`，地址类型 `ULONG64` 对 `DWORD`
- 符号解析：`GetProcAddress`，地址类型 `ULONG64` 对 `DWORD`
- 特征码扫描：`AOBscan`，地址类型 `ULONG64` 对 `DWORD`
- 代码洞：`alloc` / `dealloc` / `definealloc` / `createThread`，地址类型 `ULONG64` 对 `DWORD`

### 3.4 符号解析

模块基址的获取分三步。首先以 `ProcessBasicInformation` 取 PEB 基址[7]；其次读取 `PEB + 0x18`（64 位）或 `PEB + 0x0C`（32 位）得到 `Ldr`，再读取 `Ldr + 0x20` 或 `Ldr + 0x14` 得到 `InMemoryOrderModuleList` 的头节点；最后沿 `Flink` 迭代，对每个节点读取 `DllBase` 与 `BaseDllName.Buffer` 并以不区分大小写的比较匹配目标名。终止条件是当前节点等于链表头。迭代必须从首节点开始检查而非先前进，因为首节点对应主模块自身。

导出符号的解析以模块基址为起点，按 PE 规范[1]逐级读取：DOS 头偏移 0x3C 处取 `e_lfanew`，NT 头偏移 24 处为可选头，读取其首二字节得魔数，据此选择导出表目录项在可选头中的偏移（PE32+ 为 112，PE32 为 96），读出导出目录的 RVA 与大小后按名字表线性查找。命中后经序号表索引函数表得到函数 RVA，若该 RVA 落在导出目录区间内则判定为转发导出，此时读出形如 `KERNELBASE.ExitThread` 的字符串，拆分后补齐 `.dll` 后缀并递归解析。

### 3.5 特征码扫描

特征码文本被解析为等长的字节数组与掩码数组，通配符对应掩码零，其余字节掩码为全一。解析器接受空格、制表符、逗号与分号作为分隔符，并允许单个字节带 `0x` 前缀。

扫描以 64KB 为窗口滑动进行。每个窗口内按字节逐位比对，比对条件为字节与掩码的按位与相等。窗口前移量为窗口长度减去模式长度再加一，该重叠量保证跨窗口边界的模式不会被截断。

扫描范围有两种模式。限定模块模式以模块基址为起点、以可选头 `+0x38` 处的 `SizeOfImage` 为长度。全内存模式以 `VirtualQueryEx` 枚举地址空间[3]，仅扫描处于 `MEM_COMMIT` 状态且保护属性既非 `PAGE_NOACCESS` 又未置 `PAGE_GUARD` 的区间，枚举在地址回绕至零时终止。

### 3.6 代码洞构造与远程执行

代码洞抽象由四个操作构成，其顺序约束为 `alloc` 先于 `definealloc`，且 `createThread` 必须在 `definealloc` 之后调用。

`alloc` 以 `VirtualAllocEx` 申请 `PAGE_EXECUTE_READWRITE` 内存[2]，并将用户提供的符号名、返回地址与容量写入固定容量的静态登记表。登记表容量为 64 项，两套位宽各持一张。同名重复登记直接失败。

`definealloc` 将助记符列表逐行交给 Keystone 汇编[10]。关键的参数传递是：每行的汇编起始地址取该行在目标进程中的实际地址，即登记基址加上此前各行编码长度之和。该设计保证 `call` 与 `jmp` 等相对指令的位移计算正确。任一行汇编失败则整次调用失败，不执行部分写入。

`createThread` 以登记地址作为 `CreateRemoteThread` 的入口[4]，返回的线程句柄可由调用方等待并关闭。代码洞执行完毕后线程自然退出，内存由调用方通过 `dealloc` 释放。

---

## 4 实现

### 4.1 代码组织

实现的代码组织如下。

```text
super-memory-module/
├── winapi/
│   ├── memory_module.h    接口声明、Assembly 类型定义、逐函数中文注释
│   └── memory_module.c    全部实现：工具函数、Memory64、Memory32、静态辅助函数
├── Functions.md           接口清单
├── README.MD              设计与实现文档
└── LICENSE                MIT 许可证全文
```

接口声明 173 行，实现 1395 行，许可证 21 行。

实现内部的静态辅助函数包含 `FindWinProc`（窗口枚举回调）、`ThreadTramp`（普通函数到线程入口的适配）、`Memory64_EnsureReady` 与 `Memory32_EnsureReady`（通道解析）、`Memory64_PickRead` 与对应写函数（通道选择）、`HexVal` 与 `ParseAOB`（特征码解析）、`ScanRange64` 与 `ScanRange32`（区间扫描）、`AssembleLine`（单行汇编）。

### 4.2 关键偏移常量

实现依赖的偏移常量及其来源如下。所有常量均可由 PE 规范[1]或 PEB 结构定义[8]复核。

- `PROCESS_BASIC_INFORMATION.PebBaseAddress`：PEB 基址字段，64 位宿主 `+8`、32 位宿主 `+4`[7]
- `PEB.Ldr`：加载器数据结构指针，64 位 `+0x18`、32 位 `+0x0C`[8]
- `PEB_LDR_DATA.InMemoryOrderModuleList`：模块链表头，64 位 `+0x20`、32 位 `+0x14`[8]
- `LDR_DATA_TABLE_ENTRY.DllBase`：模块基址，64 位节点 `+0x20`、32 位节点 `+0x10`[8]
- `LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer`：模块名缓冲，64 位节点 `+0x50`、32 位节点 `+0x28`[8]
- DOS 头 `e_lfanew`：`0x3C`，NT 头的文件偏移[1]
- 可选头起始：`e_lfanew + 24`[1]
- 数据目录表偏移：可选头内偏移，PE32+ 为 `112`、PE32 为 `96`[1]
- `SizeOfImage`：映像内存尺寸，可选头 `+0x38`[1]
- 可选头魔数：位宽判据，`0x20b` 为 PE32+、`0x10b` 为 PE32[1]

### 4.3 汇编集成

单行汇编的封装如清单 1 所示。该函数以目标地址为参数调用 Keystone，因此调用方必须传入正确的行地址。

清单 1 单行汇编封装（节选）

```c
static int AssembleLine(const char* line, int mode, ULONG64 addr,
                        BYTE* out, int maxBytes)
{
    ks_engine* ks;
    unsigned char* enc = NULL;
    size_t size = 0, count = 0;

    if (ks_open(KS_ARCH_X86, mode, &ks) != KS_ERR_OK)
        return -1;
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    if (ks_asm(ks, line, addr, &enc, &size, &count) != KS_ERR_OK)
    {
        ks_close(ks);
        return -1;                      /* 指令不合法 */
    }
    if (size > (size_t)maxBytes)
    {
        ks_free(enc);
        ks_close(ks);
        return -1;                      /* 超出容量 */
    }
    memcpy(out, enc, size);
    ks_free(enc);
    ks_close(ks);
    return (int)size;
}
```

助记符列表的类型定义为定长指针数组，以空指针作为终止标记。

```c
typedef const char* Assembly[64];
```

### 4.4 编译期位宽分支

32 位目标的 PEB 定位在 64 位宿主下需要额外处理。当宿主为 64 位时，`NtQueryInformationProcess` 返回的 `PebBaseAddress` 指向 64 位 PEB，而遍历 32 位链表所需的是与之相邻分配的 32 位 PEB。实现采用启发式定位：以 64 位 PEB 的 `+0x10` 处读取映像基址，随后在以该 PEB 为中心的前后各 1MB 范围内按 4KB 步长扫描，寻找同时满足两个条件的页：其 `+0x08` 处的值等于映像基址，且其 `+0x0C` 处的 `Ldr` 指向首字段落在 0x28 至 0x40 区间内的结构。该启发式规则基于相邻分配与结构自洽性。

---

## 5 评估

### 5.1 评估协议

本节给出可复现的评估协议。评估目标是量化读写通道的调用开销、特征码扫描的吞吐，以及符号解析在跨位宽场景下的正确率。协议设计如下。

自变量包含三项：通道选择（nt、zw、以 `ReadProcessMemory` 为基线）、位宽组合（32 位宿主对 32 位目标、64 位宿主对 32 位目标、64 位宿主对 64 位目标）、目标进程类型（含目标内容的合成进程与常规系统进程）。

因变量包含四项：单次 4 字节读写的端到端延迟（以重复若干次取中位数，剔除首次调用以排除通道解析开销）；特征码扫描在给定模块内的吞吐（以字节每秒计）；符号解析的正确率（以在若干系统 DLL 上解析若干标准导出符号并与本机 `GetProcAddress` 结果比对为准）；代码洞注入序列的成功率。

实验环境要求记录 Windows 版本与内部版本号、CPU 型号、内存容量、编译器版本与优化级别，并在每次测量前以相同初始状态启动目标进程。

### 5.2 当前状态

截至本文写作时，上述协议尚未执行，因此本文不报告任何定量结果。已完成的验证为静态审查，其范围与结论为：4.2 节所列偏移常量与 PE 规范[1]和 PEB 结构定义[8]逐项比对一致；两套接口在 3.3 节所列的十个能力维度上签名对称；关键路径的函数返回码传播完整。实现尚未在持续集成环境中构建，附录 A 的构建步骤由编译期分支推导得出，未经跨工具链实测。

本文明确区分已完成的静态审查与未完成的定量评估，后者留作未来工作。

### 5.3 有效性威胁

内部效度。无实测数据，任何关于性能的推断都缺少实证支持。读写通道的错误语义（例如部分读写的处理）未在真实进程上验证。

外部效度。偏移常量的正确性依赖特定 Windows 版本的 PEB 布局，本文未在多版本系统上交叉验证。32 位 PEB 的启发式定位依赖相邻分配这一实现细节，可能随系统版本或分配器行为改变而失效。

构造效度。接口对称性由签名比对确认，但语义对称性（例如两套 `len` 为零时的行为是否一致）仅由静态审查确认。

结论效度。本文为单作者工作，未经同行评审。

---

## 6 局限性

本库存在四项结构性局限。

其一，接口数量与调用成本。两套共 40 余个函数使接口表面积较大，调用方需要为每个位宽维护一份调用序列。

其二，状态为进程级单例。模块内部持有目标进程句柄与两张代码洞登记表，均为全局状态，导致同一进程内不足以对多个目标并发操作。

其三，非线程安全。返回静态缓冲区的函数与登记表操作均无同步机制。

其四，依赖未文档化接口。读写通道基于 ntdll 导出，其签名与行为不在微软的公开保证范围内[12]，系统更新可能导致行为变化。

---

## 7 结论与未来工作

本文设计并实现了一个跨位宽的 Windows 进程内存操作库，其核心机制为：以 ntdll 原生接口作为读写通道并按宿主位宽在编译期分派；以 PEB 链表与 PE 导出表的纯读解析实现目标进程符号定位；以掩码滑动匹配实现特征码扫描；以命名代码洞统一内存分配、运行时汇编与远程执行。全库 1395 行实现、173 行接口声明，接口按位宽对称分为两套。静态审查确认了偏移常量与规范的一致性。

未来工作有三个方向。第一，执行 5.1 节的评估协议并报告定量结果，重点验证跨位宽场景下的符号解析正确率与通道相对开销。第二，在持续集成环境中覆盖 32 位与 64 位两套工具链，使构建步骤得到实测。第三，将进程级单例状态改造为句柄化的实例状态，以支持同一进程内对多目标的并发操作，并在此基础上引入同步机制以满足线程安全要求。

---

## 附录 A 构建与可复现性

依赖环境如下。

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows，读写通道依赖 `ntdll.dll` 导出 |
| 编译器 | GCC（MinGW-w64 或 MSYS2），支持 Win32 头文件与 x86/x64 双目标 |
| 系统头文件 | `windows.h`、`tlhelp32.h` |
| 第三方库 | Keystone 汇编引擎，链接参数 `-lkeystone` |
| 权限 | 目标进程需 `PROCESS_ALL_ACCESS`，通常要求管理员权限 |

依赖安装与构建命令如下。

```bash
# 安装 Keystone（MSYS2）
pacman -S mingw-w64-ucrt-x86_64-keystone

# 库方式：产出静态库供其他工程链接
gcc -Wall -c memory_module.c -o memory_module.o
ar rcs libmemory_module.a memory_module.o
```

位宽必须与工具链一致：64 位目标用 `x86_64-w64-mingw32-gcc`，32 位目标用 `i686-w64-mingw32-gcc`。产物不应跨工具链混用，理由见 4.4 节。

## 附录 B 接口规范

### B.1 工具函数

| 函数 | 说明 |
| --- | --- |
| `int fix_encoding(void)` | 以 `system("chcp 65001")` 切换控制台代码页为 UTF-8，返回 0 |
| `DWORD GetprocessID(const char* name)` | 按可执行文件名查 PID，区分大小写，未命中返回 0 |
| `long long hex_to_dec(const char* hex)` | 十六进制文本转十进制，接受 `0x` 前缀，非法输入返回 0 |
| `const char* dec_to_hex(long long dec)` | 转大写十六进制文本，负数按补码，返回静态缓冲区 |
| `HWND GetprocessHWND(DWORD pid, const char* title, const char* classname)` | 按 PID 与窗口标题、类名过滤；后两项传空表示不过滤 |
| `HANDLE Createthread(void* func, LPVOID arg)` | 将普通函数指针适配为线程入口并创建线程 |
| `DWORD Waitthread(HANDLE hThread)` | 无限等待线程结束并返回等待码 |
| `BOOL Closethread(HANDLE hThread)` | 关闭线程句柄 |

### B.2 Memory64 系列

| 函数 | 说明 |
| --- | --- |
| `BOOL Memory64_Setprocess(DWORD pid, BOOL mode)` | 打开进程并保存句柄，`mode` 真为 nt 通道、假为 zw 通道 |
| `HANDLE Memory64_Openprocess(DWORD pid)` | 以 `PROCESS_ALL_ACCESS` 打开进程[5] |
| `BOOL Memory64_Close(void)` | 关闭句柄并清空内部状态 |
| `BOOL Memory64_ReadBytes(ULONG64 addr, void* buf, DWORD len)` | 读字节集，`len` 为零时按 4 字节读 |
| `BYTE/int/float/LONGLONG Memory64_ReadByte/Int/Float/Long(ULONG64)` | 定宽读取，失败返回 0 |
| `wchar_t* Memory64_ReadText(ULONG64 addr, DWORD len)` | 读 UTF-16 文本，`len` 为字节数，零按 20，上限 510 |
| `BOOL Memory64_WriteAddr(ULONG64 addr, const void* data, DWORD len)` | 写字节集，`len` 为零时写零字节 |
| `BOOL Memory64_WriteByte/Int/Float/Long(ULONG64, v)` | 定宽写入 |
| `BOOL Memory64_WriteText(ULONG64 addr, const wchar_t* text)` | 写 UTF-16 文本，长度为字符数乘二，不附加终止符 |
| `BOOL Memory64_GetMatrix(ULONG64 addr, float out[4][4])` | 读 4x4 单精度矩阵，共 64 字节 |
| `ULONG64 Memory64_GetModuleBase(const char* name)` | 模块基址，名称不区分大小写 |
| `ULONG64 Memory64_GetProcAddress(const char* module, const char* func)` | 目标进程内的导出函数地址，含转发导出解析 |
| `ULONG64 Memory64_AOBscan(const char* aob, const char* module)` | 特征码扫描，模块名为空则全内存扫描 |
| `ULONG64/BOOL Memory64_ReadPointer/WritePointer(ULONG64)` | 8 字节指针读写 |
| `ULONG64 Memory64_alloc(const char* name, SIZE_T size)` | 申请 RWX 内存并登记名称，重名或表满返回 0[2] |
| `BOOL Memory64_dealloc(const char* name)` | 释放并注销登记项 |
| `BOOL Memory64_definealloc(const char* name, Assembly code)` | 汇编助记符列表并写入已登记内存 |
| `HANDLE Memory64_createThread(const char* name)` | 以代码洞地址为入口创建远程线程[4] |

### B.3 Memory32 系列

与 B.2 逐项对应，地址类型为 `DWORD`、指针宽度为 4 字节。其 `GetModuleBase` 在 64 位宿主下额外执行 4.4 节所述的 32 位 PEB 定位。进程枚举辅助函数的使用方式见 `CreateToolhelp32Snapshot` 文档[6]。

## 附录 C 使用示例

清单 2 给出 64 位目标上的完整调用序列，包括特征码扫描与代码洞注入。示例中代码洞内的调用遵循 Win64 调用约定，前四个参数置于 `rcx`、`rdx`、`r8`、`r9`，并预留 0x28 字节影子空间。

清单 2 读写、扫描与代码洞注入（x64 目标）

```c
#include "memory_module.h"
#include <stdio.h>

static void demo_code_cave(DWORD pid)
{
    const char* lines[64];
    char arg_r2[64], arg_r8[64], arg_rax[64];
    int n = 0;
    ULONG64 cave, msgAddr, capAddr, mb;

    if (!Memory64_Setprocess(pid, TRUE))
        return;

    mb = Memory64_GetProcAddress("user32.dll", "MessageBoxA");
    if (mb == 0)
        return;

    cave = Memory64_alloc("demo", 0x1000);
    if (cave == 0)
        return;
    msgAddr = cave + 0x800;
    capAddr = cave + 0x900;

    /* 写文本不附加终止符，此处依赖 VirtualAllocEx 返回的零化页 */
    Memory64_WriteText(msgAddr, L"Hello from injected thread");
    Memory64_WriteText(capAddr, L"memory_module");

    snprintf(arg_r2,  sizeof arg_r2,  "mov rdx, 0x%llX", (unsigned long long)msgAddr);
    snprintf(arg_r8,  sizeof arg_r8,  "mov r8,  0x%llX", (unsigned long long)capAddr);
    snprintf(arg_rax, sizeof arg_rax, "mov rax, 0x%llX", (unsigned long long)mb);

    lines[n++] = "sub rsp, 0x28";
    lines[n++] = "xor rcx, rcx";
    lines[n++] = arg_r2;
    lines[n++] = arg_r8;
    lines[n++] = "xor r9, r9";
    lines[n++] = arg_rax;
    lines[n++] = "call rax";
    lines[n++] = "add rsp, 0x28";
    lines[n++] = "ret";
    lines[n] = NULL;

    if (!Memory64_definealloc("demo", lines))
    {
        Memory64_dealloc("demo");
        return;
    }

    HANDLE th = Memory64_createThread("demo");
    if (th != NULL)
    {
        Waitthread(th);
        Closethread(th);
    }

    Memory64_dealloc("demo");
    Memory64_Close();
}

int main(void)
{
    DWORD pid;
    ULONG64 hit;
    int v;

    fix_encoding();
    pid = GetprocessID("notepad.exe");
    if (pid == 0)
        return 1;

    if (!Memory64_Setprocess(pid, TRUE))
        return 1;

    printf("base = %s\n", dec_to_hex(Memory64_GetModuleBase("notepad.exe")));

    hit = Memory64_AOBscan("48 89 5C 24 ?? 48 8B 04 10", "notepad.exe");
    printf("aob  = %s\n", dec_to_hex(hit));

    v = Memory64_ReadInt(hit);
    Memory64_WriteInt(hit, v + 1);

    demo_code_cave(pid);
    Memory64_Close();
    return 0;
}
```

32 位目标下调用的目标函数遵循 stdcall 约定，参数自右向左压栈，如清单 3 所示。

清单 3 代码洞内调用序列（x86 目标）

```c
    char arg_msg[64], arg_cap[64], arg_eax[64];
    int n = 0;

    snprintf(arg_msg, sizeof arg_msg, "push 0x%lX", (unsigned long)msgAddr);
    snprintf(arg_cap, sizeof arg_cap, "push 0x%lX", (unsigned long)capAddr);
    snprintf(arg_eax, sizeof arg_eax, "mov eax, 0x%lX", (unsigned long)mb);

    lines[n++] = "push 0";      /* uType     */
    lines[n++] = arg_cap;       /* lpCaption */
    lines[n++] = arg_msg;       /* lpText    */
    lines[n++] = "push 0";      /* hWnd      */
    lines[n++] = arg_eax;
    lines[n++] = "call eax";
    lines[n] = NULL;
```

---

## 参考文献

[1] Microsoft. PE Format[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format.

[2] Microsoft. VirtualAllocEx function[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex.

[3] Microsoft. VirtualQueryEx function[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex.

[4] Microsoft. CreateRemoteThread function[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread.

[5] Microsoft. OpenProcess function[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess.

[6] Microsoft. CreateToolhelp32Snapshot function[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot.

[7] Microsoft. NtQueryInformationProcess function[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess.

[8] Microsoft. PEB structure (winternl.h)[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb.

[9] Microsoft. WOW64 Implementation Details[EB/OL]. [2026-09-15]. https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details.

[10] Keystone Engine[CP/OL]. [2026-09-15]. https://github.com/keystone-engine/keystone.

[11] Cheat Engine[EB/OL]. [2026-09-15]. https://cheatengine.org/.

[12] YOSIFOVICH P, RUSSINOVICH M E, IONESCU A, et al. Windows Internals, Part 1[M]. 7th ed. Redmond: Microsoft Press, 2017.

---

## 许可证

本项目基于 MIT 许可证发布，可自由使用、修改、分发与再许可，详见 [LICENSE](LICENSE)。

版权行写为 `Copyright (c) 2026 YG`，如需改为真实姓名或组织名，直接编辑 `LICENSE` 首行即可。
