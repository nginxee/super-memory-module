# 函数文档 (Function.md)

本库有 **Windows 版** 与 **Linux 版** 两套实现，函数名、参数位宽、返回值语义完全一致，
因此下面的函数表两版通用；两版的平台差异（模块/符号解析方式、权限、依赖、文本编码）
集中在文中标注与"六、Linux 版差异"一节。

依赖：

- Windows：需系统安装 Keystone（MSYS2: `pacman -S mingw-w64-ucrt-x86_64-keystone`），编译加 `-lkeystone`，运行时需 `libkeystone.dll` 可被找到
- Linux：编译只需 gcc + binutils；Keystone 为**可选运行时依赖**（dlopen 加载，
  见"七、Linux 版构建与依赖"）

## 一、工具函数

| 函数 | 参数 | 返回值 | 用途 |
|---|---|---|---|
| fix_encoding() | 无 | 整数型 0 | 修复中文输出（Windows=切控制台代码页为 UTF-8；Linux=setlocale） |
| GetprocessID(进程名) | 进程名: 文本型 | 整数型 PID，0=未找到 | 按进程名取进程 ID |
| hex_to_dec(十六进制文本) | 十六进制: 文本型 | 长整数型，非法返回 0 | 十六进制文本转十进制数值 |
| dec_to_hex(十进制数值) | 数值: 长整数型 | 文本型(大写十六进制) | 十进制数值转十六进制文本；**返回静态缓冲区，连续调用互相覆盖** |

## 二、进程 / 窗口 / 线程

| 函数 | 参数 | 返回值 | 用途 |
|---|---|---|---|
| GetprocessHWND(PID, 窗口标题, 窗口类名) | PID: 整数型；标题/类名: 文本型，可空 | 整数型窗口句柄，失败返回 0 | 按 PID+标题+类名找窗口。**Linux 无窗口句柄概念，恒返回 0(NULL)** |
| Createthread(函数指针, 参数) | 函数: 子程序指针；参数: 通用型 | 整数型线程句柄，失败返回 0 | 创建线程(普通函数即可)。Linux 用 pthread 实现 |
| Waitthread(线程句柄) | 句柄: 整数型 | 整数型等待结果(0=线程已结束) | 无限等待线程结束。Linux 远程线程=轮询 /proc/<pid>/task/<tid> 直至退出 |
| Closethread(线程句柄) | 句柄: 整数型 | 逻辑型 | 关闭线程句柄 |

## 三、Memory64（64 位进程读写）

| 函数 | 参数 | 返回值 | 用途 |
|---|---|---|---|
| Memory64_Setprocess(PID, 模式) | PID: 整数型；模式: 逻辑型 | 逻辑型 | 打开进程并保存句柄。Windows：真=nt 假=zw；Linux：真=优先 process_vm_readv，假=优先 /proc/<pid>/mem（两条等价路径，失败自动回退） |
| Memory64_Openprocess(PID) | PID: 整数型 | 整数型进程句柄，失败返回 0 | 打开进程 |
| Memory64_Close() | 无 | 逻辑型 | 关闭句柄并清空状态（Linux 会顺带回收 scratch 内存） |
| Memory64_ReadBytes(地址, 缓冲区, 长度) | 地址: 长整数型；缓冲区: 字节集；长度: 整数型(0=按4) | 逻辑型 | 读字节集 |
| Memory64_ReadByte(地址) | 地址: 长整数型 | 字节型 | 读 1 字节 |
| Memory64_ReadInt(地址) | 地址: 长整数型 | 整数型 | 读 4 字节整数 |
| Memory64_ReadFloat(地址) | 地址: 长整数型 | 小数型 | 读 4 字节浮点 |
| Memory64_ReadLong(地址) | 地址: 长整数型 | 长整数型 | 读 8 字节 |
| Memory64_ReadText(地址, 长度) | 地址: 长整数型；长度: 整数型(0=按20) | 文本型(UTF-16) | 读文本；静态缓冲 |
| Memory64_ReadTextA(地址, 长度) | 同上(0=按32) | 文本型(UTF-8) | **Linux 新增**：读 UTF-8 文本；静态缓冲 |
| Memory64_WriteAddr(地址, 数据, 长度) | 地址: 长整数型；数据: 字节集；长度: 整数型 | 逻辑型 | 写字节集。**Linux 下目标页只读时会自动回退 /proc/<pid>/mem 或 ptrace POKEDATA，可改代码段** |
| Memory64_WriteByte / WriteInt / WriteFloat / WriteLong | 地址 + 数值 | 逻辑型 | 写各类数值 |
| Memory64_WriteText(地址, 文本) | 地址: 长整数型；文本: 文本型 | 逻辑型 | 写文本(UTF-16) |
| Memory64_WriteTextA(地址, 文本) | 同上 | 逻辑型 | **Linux 新增**：写 UTF-8 文本 |
| Memory64_GetMatrix(地址, 矩阵) | 地址: 长整数型；矩阵: 4x4 小数型数组 | 逻辑型 | 读 4x4 矩阵 |
| Memory64_GetModuleBase(模块名) | 模块名: 文本型(如 "kernel32.dll" / "libc.so.6") | 长整数型基址，0=未找到 | 取模块基址。Windows=PEB 遍历；Linux=/proc/<pid>/maps 里 offset=0 映射的起始地址(= ELF 头在目标进程内的地址) |
| Memory64_GetProcAddress(模块名, 函数名) | 模块名/函数名: 文本型 | 长整数型地址，0=未找到 | 取目标进程内 API/符号地址。Windows=PE 导出表(含转发导出递归)；Linux=ELF .dynamic/.dynsym 解析(符号地址 = load_bias + st_value) |
| Memory64_ReadPointer(地址) | 地址: 长整数型 | 长整数型 | 读 8 字节指针 |
| Memory64_WritePointer(地址, 数值) | 地址: 长整数型；数值: 长整数型 | 逻辑型 | 写 8 字节指针 |
| Memory64_alloc(名称, 大小) | 名称: 文本型；大小: 整数型 | 长整数型基址，0=失败 | 申请可执行内存(Code Cave)。Windows=VirtualAllocEx(RWX)；Linux=目标进程内 ptrace 注入 mmap(RWX)。**重名返回 0**(与实现一致) |
| Memory64_dealloc(名称) | 名称: 文本型 | 逻辑型 | 释放 Code Cave(Windows=VirtualFreeEx；Linux=munmap) |
| Memory64_definealloc(名称, 汇编代码) | 名称: 文本型；汇编代码: 文本型数组(每行一条指令) | 逻辑型 | 把汇编助记符写入 Code Cave(Keystone)。**有非法行/超容量/Keystone 不可用则整体失败** |
| Memory64_createThread(名称) | 名称: 文本型(已 alloc 的 Code Cave) | 整数型线程句柄，0=失败 | 在目标进程创建线程，入口为 Code Cave(类似 CE 的 createThread)。Windows=CreateRemoteThread；Linux=clone(CLONE_VM\|CLONE_THREAD...) 注入 |
| Memory64_AOBscan(特征码, 模块名) | 特征码: 文本型(如 "48 89 ?? 24")；模块名: 文本型可空 | 长整数型地址，0=未找到 | AOB 特征码扫描(模块名空=全部可读内存) |

## 四、Memory32（32 位进程读写）

参数与 Memory64 相同，仅地址/返回值宽度为 32 位（整数型）。

| 函数 | 用途 |
|---|---|
| Memory32_Setprocess / Memory32_Openprocess / Memory32_Close | 进程管理 |
| Memory32_ReadBytes / ReadByte / ReadInt / ReadFloat / ReadLong / ReadText / ReadTextA | 读取 |
| Memory32_WriteAddr / WriteByte / WriteInt / WriteFloat / WriteLong / WriteText / WriteTextA | 写入 |
| Memory32_GetMatrix | 读 4x4 矩阵 |
| Memory32_GetModuleBase / Memory32_GetProcAddress | 模块与 API 地址 |
| Memory32_ReadPointer / WritePointer | 指针读写 |
| Memory32_alloc / Memory32_dealloc | Code Cave 管理 |
| Memory32_definealloc | 写入汇编助记符 |
| Memory32_createThread | 目标进程内创建线程执行 Code Cave |
| Memory32_AOBscan | AOB 特征码扫描 |

## 五、用法示例

```易语言
PID ＝ GetprocessID (“game.exe”)                     ' 取进程
Memory64_Setprocess (PID, 假)                        ' 打开
基址 ＝ Memory64_GetModuleBase (“game.exe”)          ' 模块基址
血量地址 ＝ 基址 ＋ hex_to_dec (“1A2B3C”)             ' 计算偏移
Memory64_WriteInt (血量地址, 999)                    ' 写数值
```

```易语言
' 注入 MessageBoxA
Memory64_Setprocess (PID, 假)
API地址 ＝ Memory64_GetProcAddress (“user32.dll”, “MessageBoxA”)
洞地址 ＝ Memory64_alloc (“INJECT”, 1024)
字符串地址 ＝ Memory64_alloc (“lptext”, 32)
Memory64_WriteAddr (字符串地址, “Hello World!”, 13)  ' 字符串写入目标进程
汇编代码 ＝ { “mov rdx,0x” ＋ dec_to_hex (字符串地址) }  ' 文本型数组，每行一条指令
Memory64_definealloc (“INJECT”, 汇编代码)
```

```易语言
' AOB 扫描
地址 ＝ Memory64_AOBscan (“48 89 5C 24 ?? 48 8B 04 10”, “game.exe”)
```

```易语言
' 目标进程内创建线程执行 Code Cave（类似 CE 的 createThread）
Memory32_Setprocess (PID, 真)
Memory32_alloc (“THREAD”, 64)                        ' 申请 Code Cave
汇编代码 ＝ { “mov eax, 0x12345678”, “mov dword ptr [0x400000], eax”, “ret” }
Memory32_definealloc (“THREAD”, 汇编代码)             ' 写入机器码
线程句柄 ＝ Memory32_createThread (“THREAD”)          ' 创建线程并执行
Waitthread (线程句柄)                                 ' 等待线程结束
Closethread (线程句柄)                                ' 关闭线程句柄
Memory32_dealloc (“THREAD”)                          ' 释放 Code Cave
```

## 六、Linux 版差异

| 项 | Windows 版 | Linux 版 |
|---|---|---|
| 类型 | `windows.h` 的 DWORD/BOOL/… | 同名类型在 `linux/memory_module.h` 内自定义，保证原型文本一致 |
| 模块基址 | PEB → Ldr → InMemoryOrderModuleList | `/proc/<pid>/maps` 中 offset=0 映射的起始地址(ELF 头地址) |
| 符号解析 | PE 导出表(含转发导出递归) | ELF `.dynamic` + `.dynsym`(STT_GNU_IFUNC 返回解析器地址，不执行解析) |
| 进程打开 | OpenProcess(PROCESS_ALL_ACCESS) | 校验 `/proc/<pid>` 存在；权限在首次读写/注入时由内核判定 |
| 读写路径 | Nt/ZwReadVirtualMemory(真=nt 假=zw) | 真=process_vm_readv/writev 优先，假=/proc/<pid>/mem 优先，失败自动回退，最后可用 ptrace PEEK/POKEDATA 兜底 |
| 只读页写 | WriteProcessMemory 可写代码段 | process_vm_writev 不行，**/proc/<pid>/mem 可强写**，库内自动回退，故同样可 patch 代码段 |
| Code Cave | VirtualAllocEx / VirtualFreeEx | 目标进程内 mmap / munmap（ptrace 注入 syscall 完成） |
| 远程线程 | CreateRemoteThread | clone(CLONE_VM\|CLONE_FS\|CLONE_FILES\|CLONE_SIGHAND\|CLONE_THREAD\|CLONE_SYSVSEM)，由 wrapper 调代码洞后 exit |
| 线程等待 | WaitForSingleObject | 本地线程=pthread_join；远程线程=轮询 `/proc/<pid>/task/<tid>` 是否存在 |
| 窗口句柄 | EnumWindows 查找 | 恒返回 NULL(无该概念) |
| 文本编码 | wchar_t = 2 字节(UTF-16) | wchar_t = 4 字节，故用固定 2 字节的 `mm_char16` 保持 UTF-16 语义；另提供 ReadTextA/WriteTextA(UTF-8) |
| 权限要求 | 跨进程需管理员(UAC) | 同 uid 子进程可直接操作；跨进程受 `yama/ptrace_scope`、`CAP_SYS_PTRACE` 限制 |
| 汇编依赖 | 链接 `-lkeystone` | dlopen 加载 libkeystone.so(可选依赖) |

## 七、Linux 版构建与依赖

```bash
cd linux
make                 # 构建 libmemory_module.so / .a、test、out/target32
make test            # 构建并运行自测（含 32 位目标用例）
./test out/target32 aob      # 只跑某阶段：tools selfmem module aob cave keystone local remote remote32
```

- Keystone（可选）：`MM_KEYSTONE_LIB=/path/libkeystone.so`，或把 `libkeystone.so`/`.so.1` 放进库搜索路径；
  也可 `./fetch_keystone.sh` 从 PyPI wheel 提取（发行版一般无 keystone 包）。
  不可用时 `definealloc` 返回假，其余功能正常
- 32 位目标测试：由 `target32.s`（`as --32` + `ld -m elf_i386`）生成静态 i386 ELF，**不需要 32 位 libc/multilib**
- 退出码：0 = 全部通过（SKIP 不算失败），1 = 有失败项

## 八、验证状态（Linux 版）

自测 `linux/test.c` 共 **139 项**，在 x86-64 主机 + 32 位(i386)目标进程下**全部通过（0 失败）**，
覆盖：自进程读写全类型/UTF-16/UTF-8/只读页强写、模块基址(与 /proc/maps 独立对照)、
符号解析(与 dlsym 逐项对照)、AOB 扫描(全内存/模块内/反例)、Code Cave 与自进程线程、
Keystone 汇编端到端、本地线程 API，以及**远程目标进程**：远程读写、远程 mmap 注入、
远程 clone 建线程并执行代码洞、注入后目标代码页哈希不变(临时覆盖已还原)、远程 AOB 精确命中，
最后是 **32 位目标**：Memory32 读写、ELF32 位宽判定、只读页强写、i386 mmap2 注入、
i386 clone 建线程并执行代码洞。
