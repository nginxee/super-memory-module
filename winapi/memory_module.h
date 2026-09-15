#ifndef MEMORY_MODULE_H
#define MEMORY_MODULE_H

#include <windows.h>

/* 切换控制台代码页为 UTF-8(65001)，修复中文输出乱码；返回 0 */
int fix_encoding(void);

/* 按进程名获取PID，找不到返回0 */
DWORD GetprocessID(const char* name);

/* 十六进制文本转十进制数值，支持0x前缀，非法输入返回0 */
long long hex_to_dec(const char* hex);

/* 十进制数值转十六进制文本(大写，负数按补码)，返回静态缓冲区，下次调用会覆盖 */
const char* dec_to_hex(long long dec);

/* 按进程ID+窗口标题+窗口类名获取窗口句柄，找不到返回NULL；
   title/classname 传 NULL 或空字符串表示不按该项匹配 */
HWND GetprocessHWND(DWORD pid, const char* title, const char* classname);

/* 创建线程，func 为普通函数(不需要 WINAPI 格式)，成功返回线程句柄，失败返回NULL；
   arg 会原样传给线程函数 */
HANDLE Createthread(void* func, LPVOID arg);

/* 等待线程结束(无限等待)，返回等待结果(WAIT_OBJECT_0=线程已结束) */
DWORD Waitthread(HANDLE hThread);

/* 关闭线程句柄 */
BOOL Closethread(HANDLE hThread);

/* ==================== Memory64：64位进程内存读写 ==================== */

/* 设置进程：打开 pid 并保存句柄；mode 真=nt 假=zw，成功返回真 */
BOOL Memory64_Setprocess(DWORD pid, BOOL mode);

/* 打开进程：返回进程句柄，失败返回 NULL */
HANDLE Memory64_Openprocess(DWORD pid);

/* 关闭句柄并清空内部状态 */
BOOL Memory64_Close(void);

/* 读字节集；len=0 时按 4 字节读，成功返回真 */
BOOL Memory64_ReadBytes(ULONG64 addr, void* buf, DWORD len);

/* 读各类型数据 */
BYTE     Memory64_ReadByte(ULONG64 addr);
int      Memory64_ReadInt(ULONG64 addr);
float    Memory64_ReadFloat(ULONG64 addr);
LONGLONG Memory64_ReadLong(ULONG64 addr);

/* 读文本(UTF-16)；len 为要读的字节数，0 时按 20；返回静态缓冲区，下次调用会覆盖 */
wchar_t* Memory64_ReadText(ULONG64 addr, DWORD len);

/* 写字节集：把 data 的 len 个字节写到 addr，成功返回真 */
BOOL Memory64_WriteAddr(ULONG64 addr, const void* data, DWORD len);

/* 写各类型数据 */
BOOL Memory64_WriteByte(ULONG64 addr, BYTE v);
BOOL Memory64_WriteInt(ULONG64 addr, int v);
BOOL Memory64_WriteFloat(ULONG64 addr, float v);
BOOL Memory64_WriteLong(ULONG64 addr, LONGLONG v);
BOOL Memory64_WriteText(ULONG64 addr, const wchar_t* text);

/* 读 4x4 矩阵，成功返回真 */
BOOL Memory64_GetMatrix(ULONG64 addr, float out[4][4]);

/* 按模块名取模块基址(不区分大小写，如 "kernel32.dll")，找不到返回 0 */
ULONG64 Memory64_GetModuleBase(const char* name);

/* 按模块名+导出函数名取目标进程内函数地址(如 GetProcAddress("user32.dll","MessageBoxA"))，
   找不到返回 0 */
ULONG64 Memory64_GetProcAddress(const char* module, const char* func);

/* AOB 特征码扫描：aob 如 "48 89 5C 24 ?? 48 8B 04 10"，? 为通配符；
   module 传 NULL 或空串扫描全部可读内存，否则只扫该模块；
   命中返回地址(十六进制)，未找到返回 0 */
ULONG64 Memory64_AOBscan(const char* aob, const char* module);

/* 读写 8 字节指针 */
ULONG64 Memory64_ReadPointer(ULONG64 addr);
BOOL    Memory64_WritePointer(ULONG64 addr, ULONG64 v);

/* 在目标进程申请可执行内存(Code Cave)并登记 name，成功返回基址，失败返回 0；
   重名时先 dealloc 再申请 */
ULONG64 Memory64_alloc(const char* name, SIZE_T size);

/* 释放 name 对应的申请内存并注销，成功返回真 */
BOOL Memory64_dealloc(const char* name);

/* 汇编代码数据：文本型数组(固定 64 行)，每行存放一条汇编指令助记符(Intel 语法)；
   未写到的元素自动为 NULL，遍历到 NULL 结束，如 Assembly code = { "nop", "mov rax, rbx" }；
   由内置 Keystone 引擎汇编成机器码 */
typedef const char* Assembly[64];

/* 把汇编数据(助记符)写入 name 对应已申请的内存(需先 Memory64_alloc)，
   成功返回真；名字未登记、指令不合法或超出申请容量返回假 */
BOOL Memory64_definealloc(const char* name, Assembly code);

/* 在目标进程创建线程，入口为 name 对应已申请的内存(需先 Memory64_alloc+definealloc)，
   类似 CE 的 createThread。成功返回远程线程句柄(可 Waitthread/Closethread)，
   失败返回 NULL；线程执行完代码洞后自动退出 */
HANDLE Memory64_createThread(const char* name);

/* ==================== Memory32：32位进程内存读写 ==================== */

/* 设置进程：打开 pid 并保存句柄；mode 真=nt 假=zw，成功返回真 */
BOOL Memory32_Setprocess(DWORD pid, BOOL mode);

/* 打开进程：返回进程句柄，失败返回 NULL */
HANDLE Memory32_Openprocess(DWORD pid);

/* 关闭句柄并清空内部状态 */
BOOL Memory32_Close(void);

/* 读字节集；len=0 时按 4 字节读，成功返回真 */
BOOL Memory32_ReadBytes(DWORD addr, void* buf, DWORD len);

/* 读各类型数据 */
BYTE     Memory32_ReadByte(DWORD addr);
int      Memory32_ReadInt(DWORD addr);
float    Memory32_ReadFloat(DWORD addr);
LONGLONG Memory32_ReadLong(DWORD addr);

/* 读文本(UTF-16)；len 为要读的字节数，0 时按 20；返回静态缓冲区，下次调用会覆盖 */
wchar_t* Memory32_ReadText(DWORD addr, DWORD len);

/* 写字节集：把 data 的 len 个字节写到 addr，成功返回真 */
BOOL Memory32_WriteAddr(DWORD addr, const void* data, DWORD len);

/* 写各类型数据 */
BOOL Memory32_WriteByte(DWORD addr, BYTE v);
BOOL Memory32_WriteInt(DWORD addr, int v);
BOOL Memory32_WriteFloat(DWORD addr, float v);
BOOL Memory32_WriteLong(DWORD addr, LONGLONG v);
BOOL Memory32_WriteText(DWORD addr, const wchar_t* text);

/* 读 4x4 矩阵，成功返回真 */
BOOL Memory32_GetMatrix(DWORD addr, float out[4][4]);

/* 按模块名取模块基址(不区分大小写，如 "kernel32.dll")，找不到返回 0 */
DWORD Memory32_GetModuleBase(const char* name);

/* 按模块名+导出函数名取目标进程内函数地址(如 GetProcAddress("user32.dll","MessageBoxA"))，
   找不到返回 0 */
DWORD Memory32_GetProcAddress(const char* module, const char* func);

/* AOB 特征码扫描：aob 如 "48 89 5C 24 ?? 48 8B 04 10"，? 为通配符；
   module 传 NULL 或空串扫描全部可读内存，否则只扫该模块；
   命中返回地址(十六进制)，未找到返回 0 */
DWORD Memory32_AOBscan(const char* aob, const char* module);

/* 读写 4 字节指针 */
DWORD Memory32_ReadPointer(DWORD addr);
BOOL  Memory32_WritePointer(DWORD addr, DWORD v);

/* 在目标进程申请可执行内存(Code Cave)并登记 name，成功返回基址，失败返回 0；
   重名时先 dealloc 再申请 */
DWORD Memory32_alloc(const char* name, SIZE_T size);

/* 释放 name 对应的申请内存并注销，成功返回真 */
BOOL Memory32_dealloc(const char* name);

/* 把汇编数据(助记符)写入 name 对应已申请的内存(需先 Memory32_alloc)，
   成功返回真；名字未登记、指令不合法或超出申请容量返回假 */
BOOL Memory32_definealloc(const char* name, Assembly code);

/* 在目标进程创建线程，入口为 name 对应已申请的内存(需先 Memory32_alloc+definealloc)，
   类似 CE 的 createThread。成功返回远程线程句柄(可 Waitthread/Closethread)，
   失败返回 NULL；线程执行完代码洞后自动退出 */
HANDLE Memory32_createThread(const char* name);

#endif /* MEMORY_MODULE_H */
