#include "memory_module.h"

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <keystone/keystone.h>

/* 切换控制台代码页为 UTF-8(65001)，修复中文输出乱码；返回 0 */
int fix_encoding(void)
{
    system("chcp 65001>nul");
    return 0;
}

/* 按进程名获取PID，找不到返回0 */
DWORD GetprocessID(const char* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    DWORD pid = 0;

    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe))
    {
        do
        {
            if (strcmp(pe.szExeFile, name) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

/* 十六进制文本转十进制数值，支持0x前缀，非法输入返回0 */
long long hex_to_dec(const char* hex)
{
    char* end;
    long long v;

    if (hex == NULL)
        return 0;
    v = strtoll(hex, &end, 16);
    if (end == hex || *end != '\0')   /* 空串或未完全解析 */
        return 0;
    return v;
}

/* 十进制数值转十六进制文本(大写，负数按补码)，返回静态缓冲区，下次调用会覆盖 */
const char* dec_to_hex(long long dec)
{
    static char buf[32];
    snprintf(buf, sizeof(buf), "%llX", (unsigned long long)dec);
    return buf;
}

/* EnumWindows 回调上下文 */
typedef struct
{
    DWORD pid;
    const char* title;
    const char* classname;
    HWND hwnd;
} FindWinCtx;

static BOOL CALLBACK FindWinProc(HWND hwnd, LPARAM lParam)
{
    FindWinCtx* ctx = (FindWinCtx*)lParam;
    DWORD pid = 0;
    char buf[512];
    char cls[256];

    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid)
        return TRUE;

    /* 标题匹配，空/NULL=不按标题过滤 */
    if (ctx->title != NULL && ctx->title[0] != '\0')
    {
        if (GetWindowTextA(hwnd, buf, sizeof(buf)) == 0)
            return TRUE;
        if (strcmp(buf, ctx->title) != 0)
            return TRUE;
    }

    /* 类名匹配，空/NULL=不按类名过滤 */
    if (ctx->classname != NULL && ctx->classname[0] != '\0')
    {
        if (GetClassNameA(hwnd, cls, sizeof(cls)) == 0)
            return TRUE;
        if (strcmp(cls, ctx->classname) != 0)
            return TRUE;
    }

    ctx->hwnd = hwnd;
    return FALSE; /* 找到，停止枚举 */
}

/* 按进程ID+窗口标题+窗口类名获取窗口句柄，找不到返回NULL */
HWND GetprocessHWND(DWORD pid, const char* title, const char* classname)
{
    FindWinCtx ctx = { pid, title, classname, NULL };
    EnumWindows(FindWinProc, (LPARAM)&ctx);
    return ctx.hwnd;
}

/* 线程入口包装：把普通函数包装成 Windows 线程入口(DWORD WINAPI (LPVOID)) */
typedef struct
{
    void* func;
    LPVOID arg;
} ThreadCtx;

static DWORD WINAPI ThreadTramp(LPVOID param)
{
    ThreadCtx* ctx = (ThreadCtx*)param;
    ((void (*)(LPVOID))ctx->func)(ctx->arg);
    free(ctx);
    return 0;
}

/* 创建线程，func 为普通函数(不需要 WINAPI 格式)，成功返回线程句柄，失败返回NULL；
   arg 会原样传给线程函数 */
HANDLE Createthread(void* func, LPVOID arg)
{
    ThreadCtx* ctx;
    HANDLE h;

    ctx = (ThreadCtx*)malloc(sizeof(ThreadCtx));
    if (ctx == NULL)
        return NULL;
    ctx->func = func;
    ctx->arg = arg;

    h = CreateThread(NULL, 0, ThreadTramp, ctx, 0, NULL);
    if (h == NULL)
    {
        free(ctx);
        return NULL;
    }
    return h;
}

/* 等待线程结束(无限等待)，返回等待结果(WAIT_OBJECT_0=线程已结束) */
DWORD Waitthread(HANDLE hThread)
{
    return WaitForSingleObject(hThread, INFINITE);
}

/* 关闭线程句柄 */
BOOL Closethread(HANDLE hThread)
{
    return CloseHandle(hThread);
}

/* ==================== 申请内存登记表（对应 CE 的 alloc 符号） ==================== */
#define ALLOC_MAX 64
typedef struct
{
    char name[64];
    ULONG64 addr;
    SIZE_T size;
} AllocEntry;

static AllocEntry g_allocs[ALLOC_MAX];   /* Memory64 的登记表 */
static int g_allocCount = 0;
static AllocEntry g32_allocs[ALLOC_MAX]; /* Memory32 的登记表 */
static int g32_allocCount = 0;

/* ==================== Memory64：64位进程内存读写 ==================== */

/* ntdll 原生接口 */
typedef LONG (NTAPI* pfnNtReadVM64)(HANDLE, ULONG64, PVOID, ULONG64, PULONG64);
typedef LONG (NTAPI* pfnNtWriteVM64)(HANDLE, ULONG64, PVOID, ULONG64, PULONG64);
typedef LONG (NTAPI* pfnQueryInfo)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static pfnNtReadVM64  g_ReadNT  = NULL;   /* NtWow64ReadVirtualMemory64  */
static pfnNtReadVM64  g_ReadZW  = NULL;   /* ZwWow64ReadVirtualMemory64  */
static pfnNtWriteVM64 g_WriteNT = NULL;   /* NtWow64WriteVirtualMemory64 */
static pfnNtWriteVM64 g_WriteZW = NULL;   /* ZwWow64WriteVirtualMemory64 */
static pfnQueryInfo   g_QueryInfo = NULL;
static BOOL g_ready = FALSE;

/* 模块内部状态 */
static HANDLE g_hProcess = NULL;
static BOOL   g_mode = TRUE;   /* 真=nt 假=zw */

static BOOL Memory64_EnsureReady(void)
{
    HMODULE h;
    if (g_ready)
        return TRUE;
    h = GetModuleHandleA("ntdll.dll");
    if (h == NULL)
        return FALSE;
#ifdef _WIN64
    /* 64位宿主：用原生 Nt/ZwReadVirtualMemory（地址本机就是 64 位） */
    g_ReadNT    = (pfnNtReadVM64)GetProcAddress(h, "NtReadVirtualMemory");
    g_ReadZW    = (pfnNtReadVM64)GetProcAddress(h, "ZwReadVirtualMemory");
    g_WriteNT   = (pfnNtWriteVM64)GetProcAddress(h, "NtWriteVirtualMemory");
    g_WriteZW   = (pfnNtWriteVM64)GetProcAddress(h, "ZwWriteVirtualMemory");
#else
    /* 32位宿主(wow64)：用 NtWow64*64 变体才能读写 64 位目标进程 */
    g_ReadNT    = (pfnNtReadVM64)GetProcAddress(h, "NtWow64ReadVirtualMemory64");
    g_ReadZW    = (pfnNtReadVM64)GetProcAddress(h, "ZwWow64ReadVirtualMemory64");
    g_WriteNT   = (pfnNtWriteVM64)GetProcAddress(h, "NtWow64WriteVirtualMemory64");
    g_WriteZW   = (pfnNtWriteVM64)GetProcAddress(h, "ZwWow64WriteVirtualMemory64");
#endif
    g_QueryInfo = (pfnQueryInfo)GetProcAddress(h, "NtQueryInformationProcess");
    /* NT 系必须拿到；ZW 系拿不到时退回 NT */
    g_ready = (g_ReadNT != NULL && g_WriteNT != NULL && g_QueryInfo != NULL);
    return g_ready;
}

static pfnNtReadVM64 Memory64_PickRead(void)
{
    if (g_mode)
        return g_ReadNT;
    return g_ReadZW ? g_ReadZW : g_ReadNT;
}

static pfnNtWriteVM64 Memory64_PickWrite(void)
{
    if (g_mode)
        return g_WriteNT;
    return g_WriteZW ? g_WriteZW : g_WriteNT;
}

/* 设置进程：打开 pid 并保存句柄；mode 真=nt 假=zw，成功返回真 */
BOOL Memory64_Setprocess(DWORD pid, BOOL mode)
{
    HANDLE h;
    if (pid == 0)
        return FALSE;
    h = Memory64_Openprocess(pid);
    if (h == NULL)
        return FALSE;
    if (g_hProcess != NULL)
        CloseHandle(g_hProcess);
    g_hProcess = h;
    g_mode = mode;
    return TRUE;
}

/* 打开进程：返回进程句柄，失败返回 NULL */
HANDLE Memory64_Openprocess(DWORD pid)
{
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

/* 关闭句柄并清空内部状态 */
BOOL Memory64_Close(void)
{
    BOOL ok = TRUE;
    if (g_hProcess != NULL)
    {
        ok = CloseHandle(g_hProcess);
        g_hProcess = NULL;
    }
    return ok;
}

/* 读字节集；len=0 时按 4 字节读，成功返回真 */
BOOL Memory64_ReadBytes(ULONG64 addr, void* buf, DWORD len)
{
    LONG st;
    if (g_hProcess == NULL || buf == NULL || !Memory64_EnsureReady())
        return FALSE;
    if (len == 0)
        len = 4;
    st = Memory64_PickRead()(g_hProcess, addr, buf, len, NULL);
    return st == 0;
}

BYTE Memory64_ReadByte(ULONG64 addr)
{
    BYTE v = 0;
    Memory64_ReadBytes(addr, &v, 1);
    return v;
}

int Memory64_ReadInt(ULONG64 addr)
{
    int v = 0;
    Memory64_ReadBytes(addr, &v, 4);
    return v;
}

float Memory64_ReadFloat(ULONG64 addr)
{
    float v = 0;
    Memory64_ReadBytes(addr, &v, 4);
    return v;
}

LONGLONG Memory64_ReadLong(ULONG64 addr)
{
    LONGLONG v = 0;
    Memory64_ReadBytes(addr, &v, 8);
    return v;
}

/* 读文本(UTF-16)；len 为要读的字节数，0 时按 20；返回静态缓冲区，下次调用会覆盖 */
wchar_t* Memory64_ReadText(ULONG64 addr, DWORD len)
{
    static wchar_t buf[256];
    if (len == 0)
        len = 20;
    if (len > sizeof(buf) - 2)
        len = sizeof(buf) - 2;
    buf[0] = 0;
    if (!Memory64_ReadBytes(addr, buf, len))
        return buf;
    buf[len / 2] = 0;
    return buf;
}

/* 写字节集：把 data 的 len 个字节写到 addr，成功返回真 */
BOOL Memory64_WriteAddr(ULONG64 addr, const void* data, DWORD len)
{
    LONG st;
    if (g_hProcess == NULL || data == NULL || !Memory64_EnsureReady())
        return FALSE;
    st = Memory64_PickWrite()(g_hProcess, addr, (PVOID)data, len, NULL);
    return st == 0;
}

BOOL Memory64_WriteByte(ULONG64 addr, BYTE v)
{
    return Memory64_WriteAddr(addr, &v, 1);
}

BOOL Memory64_WriteInt(ULONG64 addr, int v)
{
    return Memory64_WriteAddr(addr, &v, 4);
}

BOOL Memory64_WriteFloat(ULONG64 addr, float v)
{
    return Memory64_WriteAddr(addr, &v, 4);
}

BOOL Memory64_WriteLong(ULONG64 addr, LONGLONG v)
{
    return Memory64_WriteAddr(addr, &v, 8);
}

BOOL Memory64_WriteText(ULONG64 addr, const wchar_t* text)
{
    if (text == NULL)
        return FALSE;
    return Memory64_WriteAddr(addr, text, (DWORD)(wcslen(text) * 2));
}

/* 读 4x4 矩阵，成功返回真 */
BOOL Memory64_GetMatrix(ULONG64 addr, float out[4][4])
{
    BYTE tmp[64];
    if (!Memory64_ReadBytes(addr, tmp, 64))
        return FALSE;
    memcpy(out, tmp, 64);
    return TRUE;
}

/* 按模块名取模块基址(不区分大小写，如 "kernel32.dll")，找不到返回 0。
   走 PEB 的 Ldr->InMemoryOrderModuleList 链表，全用 64 位原生读取 */
ULONG64 Memory64_GetModuleBase(const char* name)
{
    BYTE pbi[48];
    ULONG64 peb = 0, ldr = 0, cur = 0, base = 0, namePtr = 0;
    wchar_t wname[260], wmod[260];
    LONG st;
    ULONG retLen = 0;

    if (g_hProcess == NULL || name == NULL || !Memory64_EnsureReady())
        return 0;
    if (mbstowcs(wname, name, 259) == (size_t)-1)
        return 0;
    wname[259] = 0;

    /* ProcessBasicInformation(0)，PebBaseAddress 在偏移 8 处 */
    st = g_QueryInfo(g_hProcess, 0, pbi, 48, &retLen);
    if (st != 0)
        return 0;
    memcpy(&peb, pbi + 8, 8);

    /* PEB + 24 = Ldr；Ldr + 32 = InMemoryOrderModuleList */
    if (!Memory64_ReadBytes(peb + 24, &ldr, 8))
        return 0;
    if (!Memory64_ReadBytes(ldr + 32, &cur, 8))
        return 0;

    for (;;)
    {
        /* cur 指向某模块的 InMemoryOrderLinks 节点，Flink 在节点 +0；
           cur 为链表头(ldr+0x20)时遍历完毕。注意第一个节点是主模块(EXE)，
           必须先从 cur 开始检查，不能先读 Flink 跳过它 */
        if (cur == ldr + 32)
            break;
        /* 节点 = 条目 + 0x10：DllBase = 条目+0x30 = 节点+0x20；
           BaseDllName.Buffer = 条目+0x60 = 节点+0x50(纯文件名，如 "kernel32.dll") */
        if (!Memory64_ReadBytes(cur + 32, &base, 8))
            return 0;
        if (!Memory64_ReadBytes(cur + 80, &namePtr, 8))
            return 0;
        if (base != 0 && namePtr != 0)
        {
            wmod[0] = 0;
            if (Memory64_ReadBytes(namePtr, wmod, sizeof(wmod) - 2))
            {
                wmod[259] = 0;   /* 补终止符，防止 _wcsicmp 越界读 */
                if (_wcsicmp(wmod, wname) == 0)
                    return base;
            }
        }
        if (!Memory64_ReadBytes(cur, &cur, 8))   /* Flink 前进到下一条目 */
            return 0;
    }
    return 0;
}

/* 按模块名+导出函数名取目标进程内函数地址(如 GetProcAddress("user32.dll","MessageBoxA"))，
   找不到返回 0。走 PE 导出表：DOS头 e_lfanew -> NT头 -> DataDirectory[0] -> 名字表 -> 序号表 -> 函数表 */
ULONG64 Memory64_GetProcAddress(const char* module, const char* func)
{
    ULONG64 base = Memory64_GetModuleBase(module);
    BYTE buf[64];
    DWORD e_lfanew, expRva, expSize, nNames, i, ord, fRva;
    DWORD addrNames, addrOrds, addrFuncs;
    WORD magic;
    char name[256];

    if (base == 0 || func == NULL)
        return 0;

    /* DOS 头 -> e_lfanew */
    if (!Memory64_ReadBytes(base, buf, 64))
        return 0;
    e_lfanew = *(DWORD*)(buf + 0x3C);
    if (e_lfanew == 0)
        return 0;

    /* NT头 + 24 = 可选头，Magic 在可选头偏移 0 */
    if (!Memory64_ReadBytes(base + e_lfanew + 24, buf, 2))
        return 0;
    magic = *(WORD*)buf;

    /* DataDirectory[0](导出表)：PE32+ 在可选头偏移 112，PE32 在 96 */
    if (!Memory64_ReadBytes(base + e_lfanew + 24 + (magic == 0x20B ? 112 : 96), buf, 8))
        return 0;
    expRva = *(DWORD*)buf;
    expSize = *(DWORD*)(buf + 4);
    if (expRva == 0 || expSize < 40)
        return 0;                       /* 模块无导出 */

    /* IMAGE_EXPORT_DIRECTORY(40 字节) */
    if (!Memory64_ReadBytes(base + expRva, buf, 40))
        return 0;
    nNames   = *(DWORD*)(buf + 24);
    addrFuncs = *(DWORD*)(buf + 28);
    addrNames = *(DWORD*)(buf + 32);
    addrOrds  = *(DWORD*)(buf + 36);

    for (i = 0; i < nNames; i++)
    {
        DWORD nameRva;
        /* 三个表字段是相对映像基址的 RVA：表 VA = base + 字段值 */
        if (!Memory64_ReadBytes(base + addrNames + i * 4, &nameRva, 4))
            return 0;
        if (nameRva == 0)
            continue;
        name[0] = 0;
        if (!Memory64_ReadBytes(base + nameRva, name, sizeof(name) - 1))
            continue;
        name[255] = 0;
        if (strcmp(name, func) != 0)
            continue;
        if (!Memory64_ReadBytes(base + addrOrds + i * 2, &ord, 2))
            return 0;
        if (!Memory64_ReadBytes(base + addrFuncs + ord * 4, &fRva, 4))
            return 0;
        if (fRva >= expRva && fRva < expRva + expSize)
        {
            /* 转发导出：fRva 指向 "模块.函数" 字符串，递归解析(如 kernel32 的 ExitThread) */
            char fwd[256], mod[128], fn[128];
            char* dot;
            if (!Memory64_ReadBytes(base + fRva, fwd, sizeof(fwd) - 1))
                return 0;
            fwd[255] = 0;
            dot = strchr(fwd, '.');
            if (dot == NULL || dot - fwd >= (long)sizeof(mod) - 1)
                return 0;
            *dot = 0;
            strcpy(mod, fwd);
            strcpy(fn, dot + 1);
            if (strchr(mod, '.') == NULL)
                strcat(mod, ".dll");   /* "KERNELBASE" -> "KERNELBASE.dll" */
            return Memory64_GetProcAddress(mod, fn);
        }
        return base + fRva;
    }
    return 0;
}

/* ==================== AOB 特征码扫描 ==================== */

/* 十六进制字符转数值，非法返回 -1 */
static int HexVal(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 解析 AOB 文本为 字节+掩码，支持 "48 89 ?? 5C"、逗号分隔、0x 前缀；? 为通配符；
   返回字节数，非法返回 -1，超出容量返回 -2 */
static int ParseAOB(const char* text, BYTE* pat, BYTE* mask, int maxBytes)
{
    int n = 0;
    const char* p = text;

    while (*p)
    {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';')
            p++;
        if (*p == '\0')
            break;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
            p += 2;
        if (*p == '?')          /* 通配符 */
        {
            if (n >= maxBytes)
                return -2;
            pat[n] = 0;
            mask[n] = 0;
            n++;
            p += (p[1] == '?') ? 2 : 1;
        }
        else
        {
            int hi = HexVal(p[0]), lo = HexVal(p[1]);
            if (hi < 0 || lo < 0)
                return -1;
            if (n >= maxBytes)
                return -2;
            pat[n] = (BYTE)(hi * 16 + lo);
            mask[n] = 0xFF;
            n++;
            p += 2;
        }
    }
    return n;
}

/* 在 [start, start+size) 内滑动搜索 AOB，命中返回地址，未找到返回 0 */
static ULONG64 ScanRange64(ULONG64 start, ULONG64 size,
                           const BYTE* pat, const BYTE* mask, int pLen)
{
    BYTE buf[65536];
    ULONG64 addr = start, end = start + size;

    while (addr < end)
    {
        ULONG64 readLen = end - addr;
        ULONG64 i;
        if (readLen > sizeof(buf))
            readLen = sizeof(buf);
        if (readLen < (ULONG64)pLen)
            break;                      /* 余量不足，不可能命中 */
        if (!Memory64_ReadBytes(addr, buf, (DWORD)readLen))
            break;
        for (i = 0; i + pLen <= readLen; i++)
        {
            int j;
            for (j = 0; j < pLen; j++)
            {
                if ((buf[i + j] & mask[j]) != (pat[j] & mask[j]))
                    break;
            }
            if (j == pLen)
                return addr + i;
        }
        addr += readLen - pLen + 1;     /* 跨块重叠，防边界截断 */
    }
    return 0;
}

/* AOB 特征码扫描：aob 如 "48 89 5C 24 ?? 48 8B 04 10"，? 为通配符；
   module 传 NULL 或空串扫描全部可读内存，否则只扫该模块；
   命中返回地址，未找到返回 0 */
ULONG64 Memory64_AOBscan(const char* aob, const char* module)
{
    BYTE pat[64], mask[64];
    int pLen;

    if (g_hProcess == NULL || aob == NULL)
        return 0;
    pLen = ParseAOB(aob, pat, mask, 64);
    if (pLen <= 0)
        return 0;

    if (module != NULL && module[0] != '\0')
    {
        /* 只扫指定模块：基址 + SizeOfImage(可选头 + 0x38) */
        ULONG64 base = Memory64_GetModuleBase(module);
        BYTE b[4];
        DWORD e_lfanew, sizeOfImage;
        if (base == 0)
            return 0;
        if (!Memory64_ReadBytes(base + 0x3C, b, 4))
            return 0;
        e_lfanew = *(DWORD*)b;
        if (!Memory64_ReadBytes(base + e_lfanew + 24 + 0x38, b, 4))
            return 0;
        sizeOfImage = *(DWORD*)b;
        if (sizeOfImage == 0)
            return 0;
        return ScanRange64(base, sizeOfImage, pat, mask, pLen);
    }
    else
    {
        /* 全内存扫描：VirtualQueryEx 遍历已提交的可读区域 */
        ULONG64 addr = 0;
        for (;;)
        {
            MEMORY_BASIC_INFORMATION mbi;
            ULONG64 found;
            if (VirtualQueryEx(g_hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
                break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xFF) != PAGE_NOACCESS
                && !(mbi.Protect & PAGE_GUARD))
            {
                found = ScanRange64((ULONG64)mbi.BaseAddress, mbi.RegionSize,
                                    pat, mask, pLen);
                if (found != 0)
                    return found;
            }
            addr = (ULONG64)mbi.BaseAddress + mbi.RegionSize;
            if (addr == 0)
                break;                  /* 地址空间绕回，遍历完毕 */
        }
        return 0;
    }
}

/* 读写 8 字节指针 */
ULONG64 Memory64_ReadPointer(ULONG64 addr)
{
    ULONG64 v = 0;
    Memory64_ReadBytes(addr, &v, 8);
    return v;
}

BOOL Memory64_WritePointer(ULONG64 addr, ULONG64 v)
{
    return Memory64_WriteAddr(addr, &v, 8);
}

/* 在目标进程申请可执行内存(Code Cave)并登记 name，成功返回基址，失败返回 0；
   重名时先 dealloc 再申请 */
ULONG64 Memory64_alloc(const char* name, SIZE_T size)
{
    ULONG64 addr;
    int i;

    if (g_hProcess == NULL || name == NULL || name[0] == '\0' || size == 0)
        return 0;
    for (i = 0; i < g_allocCount; i++)
    {
        if (strcmp(g_allocs[i].name, name) == 0)
            return 0;   /* 重名 */
    }
    if (g_allocCount >= ALLOC_MAX)
        return 0;

    addr = (ULONG64)VirtualAllocEx(g_hProcess, NULL, size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (addr == 0)
        return 0;

    strncpy(g_allocs[g_allocCount].name, name, 63);
    g_allocs[g_allocCount].name[63] = 0;
    g_allocs[g_allocCount].addr = addr;
    g_allocs[g_allocCount].size = size;
    g_allocCount++;
    return addr;
}

/* 释放 name 对应的申请内存并注销，成功返回真 */
BOOL Memory64_dealloc(const char* name)
{
    int i;

    if (g_hProcess == NULL || name == NULL)
        return FALSE;
    for (i = 0; i < g_allocCount; i++)
    {
        if (strcmp(g_allocs[i].name, name) == 0)
        {
            BOOL ok = VirtualFreeEx(g_hProcess, (LPVOID)g_allocs[i].addr, 0,
                                    MEM_RELEASE);
            /* 释放后无论成败都注销，避免脏条目 */
            g_allocs[i] = g_allocs[g_allocCount - 1];
            g_allocCount--;
            return ok;
        }
    }
    return FALSE;
}

/* ==================== Assembly：把汇编助记符写入已申请内存 ==================== */

/* 用 Keystone 把一行汇编助记符(Intel 语法)汇编成机器码，写入 out，
   返回字节数；指令不合法或超出容量返回 -1。
   addr 是该行指令在目标进程中的实际地址：call/jmp 等相对指令的偏移
   按 (目标-addr-指令长度) 计算，传 0 会导致写入 code cave 后跳转目标全错 */
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

/* 把汇编数据(机器码)写入 name 对应已申请的内存(需先 Memory64_alloc)，
   成功返回真；名字未登记、含非法十六进制或超出申请容量返回假 */
BOOL Memory64_definealloc(const char* name, Assembly code)
{
    BYTE buf[4096];
    const char* const* p;
    int idx, n, total = 0;

    if (g_hProcess == NULL || name == NULL || code == NULL)
        return FALSE;
    for (idx = 0; idx < g_allocCount; idx++)
    {
        if (strcmp(g_allocs[idx].name, name) == 0)
            break;
    }
    if (idx >= g_allocCount)
        return FALSE;                   /* 名字未登记 */

    /* ponytail: 靠 NULL 结尾 + 64 行上限(与 Assembly 数组大小一致)兜底 */
    for (p = code; *p != NULL && (p - code) < 64; p++)
    {
        if ((*p)[strspn(*p, " \t")] == '\0')
            continue;                   /* 空行/纯空格行跳过 */
        n = AssembleLine(*p, KS_MODE_64, g_allocs[idx].addr + total,
                         buf + total, (int)(sizeof(buf) - total));
        if (n < 0)
            return FALSE;               /* 有非法行则整体不写入 */
        total += n;
    }
    if (total == 0)
        return FALSE;
    if ((SIZE_T)total > g_allocs[idx].size)
        return FALSE;                   /* 超出申请容量 */

    return Memory64_WriteAddr(g_allocs[idx].addr, buf, (DWORD)total);
}

/* 在目标进程创建线程，入口为 name 对应已申请的内存(需先 Memory64_alloc+definealloc)，
   类似 CE 的 createThread。成功返回远程线程句柄(可 Waitthread/Closethread)，
   失败返回 NULL；线程执行完代码洞后自动退出 */
HANDLE Memory64_createThread(const char* name)
{
    int idx;

    if (g_hProcess == NULL || name == NULL)
        return NULL;
    for (idx = 0; idx < g_allocCount; idx++)
    {
        if (strcmp(g_allocs[idx].name, name) == 0)
            break;
    }
    if (idx >= g_allocCount)
        return NULL;                    /* 名字未登记 */

    return CreateRemoteThread(g_hProcess, NULL, 0,
                              (LPTHREAD_START_ROUTINE)(ULONG_PTR)g_allocs[idx].addr,
                              NULL, 0, NULL);
}

/* ==================== Memory32：32位进程内存读写 ==================== */

/* ntdll 原生接口（32 位地址版本） */
typedef LONG (NTAPI* pfnNtReadVM32)(HANDLE, PVOID, PVOID, ULONG_PTR, PULONG_PTR);
typedef LONG (NTAPI* pfnNtWriteVM32)(HANDLE, PVOID, PVOID, ULONG_PTR, PULONG_PTR);

static pfnNtReadVM32  g32_ReadNT  = NULL;   /* NtReadVirtualMemory  */
static pfnNtReadVM32  g32_ReadZW  = NULL;   /* ZwReadVirtualMemory  */
static pfnNtWriteVM32 g32_WriteNT = NULL;   /* NtWriteVirtualMemory */
static pfnNtWriteVM32 g32_WriteZW = NULL;   /* ZwWriteVirtualMemory */
static pfnQueryInfo   g32_QueryInfo = NULL;
static BOOL g32_ready = FALSE;

/* 模块内部状态 */
static HANDLE g32_hProcess = NULL;
static BOOL   g32_mode = TRUE;   /* 真=nt 假=zw */

static BOOL Memory32_EnsureReady(void)
{
    HMODULE h;
    if (g32_ready)
        return TRUE;
    h = GetModuleHandleA("ntdll.dll");
    if (h == NULL)
        return FALSE;
    g32_ReadNT    = (pfnNtReadVM32)GetProcAddress(h, "NtReadVirtualMemory");
    g32_ReadZW    = (pfnNtReadVM32)GetProcAddress(h, "ZwReadVirtualMemory");
    g32_WriteNT   = (pfnNtWriteVM32)GetProcAddress(h, "NtWriteVirtualMemory");
    g32_WriteZW   = (pfnNtWriteVM32)GetProcAddress(h, "ZwWriteVirtualMemory");
    g32_QueryInfo = (pfnQueryInfo)GetProcAddress(h, "NtQueryInformationProcess");
    /* NT 系必须拿到；ZW 系拿不到时退回 NT */
    g32_ready = (g32_ReadNT != NULL && g32_WriteNT != NULL && g32_QueryInfo != NULL);
    return g32_ready;
}

static pfnNtReadVM32 Memory32_PickRead(void)
{
    if (g32_mode)
        return g32_ReadNT;
    return g32_ReadZW ? g32_ReadZW : g32_ReadNT;
}

static pfnNtWriteVM32 Memory32_PickWrite(void)
{
    if (g32_mode)
        return g32_WriteNT;
    return g32_WriteZW ? g32_WriteZW : g32_WriteNT;
}

/* 设置进程：打开 pid 并保存句柄；mode 真=nt 假=zw，成功返回真 */
BOOL Memory32_Setprocess(DWORD pid, BOOL mode)
{
    HANDLE h;
    if (pid == 0)
        return FALSE;
    h = Memory32_Openprocess(pid);
    if (h == NULL)
        return FALSE;
    if (g32_hProcess != NULL)
        CloseHandle(g32_hProcess);
    g32_hProcess = h;
    g32_mode = mode;
    return TRUE;
}

/* 打开进程：返回进程句柄，失败返回 NULL */
HANDLE Memory32_Openprocess(DWORD pid)
{
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

/* 关闭句柄并清空内部状态 */
BOOL Memory32_Close(void)
{
    BOOL ok = TRUE;
    if (g32_hProcess != NULL)
    {
        ok = CloseHandle(g32_hProcess);
        g32_hProcess = NULL;
    }
    return ok;
}

/* 读字节集；len=0 时按 4 字节读，成功返回真 */
BOOL Memory32_ReadBytes(DWORD addr, void* buf, DWORD len)
{
    LONG st;
    if (g32_hProcess == NULL || buf == NULL || !Memory32_EnsureReady())
        return FALSE;
    if (len == 0)
        len = 4;
    st = Memory32_PickRead()(g32_hProcess, (PVOID)(ULONG_PTR)addr, buf, len, NULL);
    return st == 0;
}

BYTE Memory32_ReadByte(DWORD addr)
{
    BYTE v = 0;
    Memory32_ReadBytes(addr, &v, 1);
    return v;
}

int Memory32_ReadInt(DWORD addr)
{
    int v = 0;
    Memory32_ReadBytes(addr, &v, 4);
    return v;
}

float Memory32_ReadFloat(DWORD addr)
{
    float v = 0;
    Memory32_ReadBytes(addr, &v, 4);
    return v;
}

LONGLONG Memory32_ReadLong(DWORD addr)
{
    LONGLONG v = 0;
    Memory32_ReadBytes(addr, &v, 8);
    return v;
}

/* 读文本(UTF-16)；len 为要读的字节数，0 时按 20；返回静态缓冲区，下次调用会覆盖 */
wchar_t* Memory32_ReadText(DWORD addr, DWORD len)
{
    static wchar_t buf[256];
    if (len == 0)
        len = 20;
    if (len > sizeof(buf) - 2)
        len = sizeof(buf) - 2;
    buf[0] = 0;
    if (!Memory32_ReadBytes(addr, buf, len))
        return buf;
    buf[len / 2] = 0;
    return buf;
}

/* 写字节集：把 data 的 len 个字节写到 addr，成功返回真 */
BOOL Memory32_WriteAddr(DWORD addr, const void* data, DWORD len)
{
    LONG st;
    if (g32_hProcess == NULL || data == NULL || !Memory32_EnsureReady())
        return FALSE;
    st = Memory32_PickWrite()(g32_hProcess, (PVOID)(ULONG_PTR)addr, (PVOID)data, len, NULL);
    return st == 0;
}

BOOL Memory32_WriteByte(DWORD addr, BYTE v)
{
    return Memory32_WriteAddr(addr, &v, 1);
}

BOOL Memory32_WriteInt(DWORD addr, int v)
{
    return Memory32_WriteAddr(addr, &v, 4);
}

BOOL Memory32_WriteFloat(DWORD addr, float v)
{
    return Memory32_WriteAddr(addr, &v, 4);
}

BOOL Memory32_WriteLong(DWORD addr, LONGLONG v)
{
    return Memory32_WriteAddr(addr, &v, 8);
}

BOOL Memory32_WriteText(DWORD addr, const wchar_t* text)
{
    if (text == NULL)
        return FALSE;
    return Memory32_WriteAddr(addr, text, (DWORD)(wcslen(text) * 2));
}

/* 读 4x4 矩阵，成功返回真 */
BOOL Memory32_GetMatrix(DWORD addr, float out[4][4])
{
    BYTE tmp[64];
    if (!Memory32_ReadBytes(addr, tmp, 64))
        return FALSE;
    memcpy(out, tmp, 64);
    return TRUE;
}

/* 按模块名取模块基址(不区分大小写，如 "kernel32.dll")，找不到返回 0。
   走 PEB 的 Ldr->InMemoryOrderModuleList 链表（32 位布局）。
   注意：64 位宿主查 32 位(WOW64)目标时 NtQueryInformationProcess 返回的
   是 64 位 PEB(地址与 32 位 PEB 相邻)，须先定位 32 位 PEB 再遍历 */
DWORD Memory32_GetModuleBase(const char* name)
{
    BYTE pbi[48];
    DWORD peb = 0, ldr = 0, cur = 0, base = 0, namePtr = 0;
    wchar_t wname[260], wmod[260];
    LONG st;
    ULONG retLen = 0;

    if (g32_hProcess == NULL || name == NULL || !Memory32_EnsureReady())
        return 0;
    if (mbstowcs(wname, name, 259) == (size_t)-1)
        return 0;
    wname[259] = 0;

    /* ProcessBasicInformation(0)：32 位宿主布局 PebBaseAddress 在偏移 4；
       64 位宿主布局在偏移 8 */
    st = g32_QueryInfo(g32_hProcess, 0, pbi, 48, &retLen);
    if (st != 0)
        return 0;
#ifdef _WIN64
    {
        /* 64 位宿主查 32 位(WOW64)目标：NtQueryInformationProcess 返回的是
           64 位 PEB，其 +0x10 是 64 位 ImageBaseAddress(进程基址，如 0x400000)。
           32 位 PEB 与之相邻分配，在其 ±1MB 内按页找特征：
           PEB32+0x08 的 ImageBaseAddress == 进程基址，且 PEB32+0x0C 的 Ldr
           指向 Length 合理的 PEB_LDR_DATA */
        ULONG64 peb64 = 0, img = 0, a;
        ULONG64 lo, hi;
        memcpy(&peb64, pbi + 8, 8);
        if (peb64 == 0)
            return 0;
        if (!Memory32_ReadBytes((DWORD)(ULONG_PTR)peb64 + 16, &img, 8))
            return 0;
        lo = (peb64 > 0x100000) ? peb64 - 0x100000 : 0;
        hi = peb64 + 0x100000;
        for (a = lo; a <= hi && a < 0x100000000ULL; a += 0x1000)
        {
            DWORD iba, ldr32, len;
            if (a == 0)
                continue;
            if (!Memory32_ReadBytes((DWORD)a + 8, &iba, 4))
                continue;
            if (iba != (DWORD)img)
                continue;
            if (!Memory32_ReadBytes((DWORD)a + 12, &ldr32, 4))
                continue;
            if (ldr32 == 0)
                continue;
            if (!Memory32_ReadBytes(ldr32, &len, 4))
                continue;
            if (len < 0x28 || len > 0x40)
                continue;   /* PEB_LDR_DATA.Length 合理范围 */
            peb = (DWORD)a;
            break;
        }
        if (peb == 0)
            return 0;
    }
#else
    memcpy(&peb, pbi + 4, 4);
#endif

    /* 32位 PEB + 12 = Ldr；Ldr + 20 = InMemoryOrderModuleList */
    if (!Memory32_ReadBytes(peb + 12, &ldr, 4))
        return 0;
    if (!Memory32_ReadBytes(ldr + 20, &cur, 4))
        return 0;

    for (;;)
    {
        /* cur 指向某模块的 InMemoryOrderLinks 节点，Flink 在节点 +0；
           cur 为链表头(ldr+0x14)时遍历完毕。注意第一个节点是主模块(EXE)，
           必须先从 cur 开始检查，不能先读 Flink 跳过它 */
        if (cur == ldr + 20)
            break;
        /* 节点 = 条目 + 8：DllBase = 条目+0x18 = 节点+0x10；
           BaseDllName.Buffer = 条目+0x30 = 节点+0x28(纯文件名) */
        if (!Memory32_ReadBytes(cur + 16, &base, 4))
            return 0;
        if (!Memory32_ReadBytes(cur + 40, &namePtr, 4))
            return 0;
        if (base != 0 && namePtr != 0)
        {
            wmod[0] = 0;
            if (Memory32_ReadBytes(namePtr, wmod, sizeof(wmod) - 2))
            {
                wmod[259] = 0;   /* 补终止符，防止 _wcsicmp 越界读 */
                if (_wcsicmp(wmod, wname) == 0)
                    return base;
            }
        }
        if (!Memory32_ReadBytes(cur, &cur, 4))   /* Flink 前进到下一条目 */
            return 0;
    }
    return 0;
}

/* 按模块名+导出函数名取目标进程内函数地址(如 GetProcAddress("user32.dll","MessageBoxA"))，
   找不到返回 0。走 PE 导出表，布局同 Memory64 版 */
DWORD Memory32_GetProcAddress(const char* module, const char* func)
{
    DWORD base = Memory32_GetModuleBase(module);
    BYTE buf[64];
    DWORD e_lfanew, expRva, expSize, nNames, i, ord, fRva;
    DWORD addrNames, addrOrds, addrFuncs;
    WORD magic;
    char name[256];

    if (base == 0 || func == NULL)
        return 0;

    if (!Memory32_ReadBytes(base, buf, 64))
        return 0;
    e_lfanew = *(DWORD*)(buf + 0x3C);
    if (e_lfanew == 0)
        return 0;

    if (!Memory32_ReadBytes(base + e_lfanew + 24, buf, 2))
        return 0;
    magic = *(WORD*)buf;

    if (!Memory32_ReadBytes(base + e_lfanew + 24 + (magic == 0x20B ? 112 : 96), buf, 8))
        return 0;
    expRva = *(DWORD*)buf;
    expSize = *(DWORD*)(buf + 4);
    if (expRva == 0 || expSize < 40)
        return 0;                       /* 模块无导出 */

    if (!Memory32_ReadBytes(base + expRva, buf, 40))
        return 0;
    nNames   = *(DWORD*)(buf + 24);
    addrFuncs = *(DWORD*)(buf + 28);
    addrNames = *(DWORD*)(buf + 32);
    addrOrds  = *(DWORD*)(buf + 36);

    for (i = 0; i < nNames; i++)
    {
        DWORD nameRva;
        /* 三个表字段是相对映像基址的 RVA：表 VA = base + 字段值 */
        if (!Memory32_ReadBytes(base + addrNames + i * 4, &nameRva, 4))
            return 0;
        if (nameRva == 0)
            continue;
        name[0] = 0;
        if (!Memory32_ReadBytes(base + nameRva, name, sizeof(name) - 1))
            continue;
        name[255] = 0;
        if (strcmp(name, func) != 0)
            continue;
        if (!Memory32_ReadBytes(base + addrOrds + i * 2, &ord, 2))
            return 0;
        if (!Memory32_ReadBytes(base + addrFuncs + ord * 4, &fRva, 4))
            return 0;
        if (fRva >= expRva && fRva < expRva + expSize)
        {
            /* 转发导出：fRva 指向 "模块.函数" 字符串，递归解析 */
            char fwd[256], mod[128], fn[128];
            char* dot;
            if (!Memory32_ReadBytes(base + fRva, fwd, sizeof(fwd) - 1))
                return 0;
            fwd[255] = 0;
            dot = strchr(fwd, '.');
            if (dot == NULL || dot - fwd >= (long)sizeof(mod) - 1)
                return 0;
            *dot = 0;
            strcpy(mod, fwd);
            strcpy(fn, dot + 1);
            if (strchr(mod, '.') == NULL)
                strcat(mod, ".dll");   /* "KERNELBASE" -> "KERNELBASE.dll" */
            return Memory32_GetProcAddress(mod, fn);
        }
        return base + fRva;
    }
    return 0;
}

/* 在 [start, start+size) 内滑动搜索 AOB，命中返回地址，未找到返回 0 */
static DWORD ScanRange32(DWORD start, DWORD size,
                         const BYTE* pat, const BYTE* mask, int pLen)
{
    BYTE buf[65536];
    DWORD addr = start;
    ULONG64 end = (ULONG64)start + size;

    while ((ULONG64)addr < end)
    {
        ULONG64 readLen = end - addr;
        ULONG64 i;
        if (readLen > sizeof(buf))
            readLen = sizeof(buf);
        if (readLen < (ULONG64)pLen)
            break;
        if (!Memory32_ReadBytes(addr, buf, (DWORD)readLen))
            break;
        for (i = 0; i + pLen <= readLen; i++)
        {
            int j;
            for (j = 0; j < pLen; j++)
            {
                if ((buf[i + j] & mask[j]) != (pat[j] & mask[j]))
                    break;
            }
            if (j == pLen)
                return addr + (DWORD)i;
        }
        addr += (DWORD)(readLen - pLen + 1);    /* 跨块重叠，防边界截断 */
    }
    return 0;
}

/* AOB 特征码扫描：aob 如 "48 89 5C 24 ?? 48 8B 04 10"，? 为通配符；
   module 传 NULL 或空串扫描全部可读内存，否则只扫该模块；
   命中返回地址，未找到返回 0 */
DWORD Memory32_AOBscan(const char* aob, const char* module)
{
    BYTE pat[64], mask[64];
    int pLen;

    if (g32_hProcess == NULL || aob == NULL)
        return 0;
    pLen = ParseAOB(aob, pat, mask, 64);
    if (pLen <= 0)
        return 0;

    if (module != NULL && module[0] != '\0')
    {
        /* 只扫指定模块：基址 + SizeOfImage(可选头 + 0x38) */
        DWORD base = Memory32_GetModuleBase(module);
        BYTE b[4];
        DWORD e_lfanew, sizeOfImage;
        if (base == 0)
            return 0;
        if (!Memory32_ReadBytes(base + 0x3C, b, 4))
            return 0;
        e_lfanew = *(DWORD*)b;
        if (!Memory32_ReadBytes(base + e_lfanew + 24 + 0x38, b, 4))
            return 0;
        sizeOfImage = *(DWORD*)b;
        if (sizeOfImage == 0)
            return 0;
        return ScanRange32(base, sizeOfImage, pat, mask, pLen);
    }
    else
    {
        /* 全内存扫描：VirtualQueryEx 遍历已提交的可读区域 */
        DWORD addr = 0;
        for (;;)
        {
            MEMORY_BASIC_INFORMATION mbi;
            DWORD found;
            if (VirtualQueryEx(g32_hProcess, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi)) == 0)
                break;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xFF) != PAGE_NOACCESS
                && !(mbi.Protect & PAGE_GUARD))
            {
                found = ScanRange32((DWORD)(ULONG_PTR)mbi.BaseAddress, mbi.RegionSize,
                                    pat, mask, pLen);
                if (found != 0)
                    return found;
            }
            addr = (DWORD)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            if (addr == 0)
                break;                  /* 地址空间绕回，遍历完毕 */
        }
        return 0;
    }
}

/* 读写 4 字节指针 */
DWORD Memory32_ReadPointer(DWORD addr)
{
    DWORD v = 0;
    Memory32_ReadBytes(addr, &v, 4);
    return v;
}

BOOL Memory32_WritePointer(DWORD addr, DWORD v)
{
    return Memory32_WriteAddr(addr, &v, 4);
}

/* 在目标进程申请可执行内存(Code Cave)并登记 name，成功返回基址，失败返回 0；
   重名时先 dealloc 再申请 */
DWORD Memory32_alloc(const char* name, SIZE_T size)
{
    DWORD addr;
    int i;

    if (g32_hProcess == NULL || name == NULL || name[0] == '\0' || size == 0)
        return 0;
    for (i = 0; i < g32_allocCount; i++)
    {
        if (strcmp(g32_allocs[i].name, name) == 0)
            return 0;   /* 重名 */
    }
    if (g32_allocCount >= ALLOC_MAX)
        return 0;

    addr = (DWORD)(ULONG_PTR)VirtualAllocEx(g32_hProcess, NULL, size,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (addr == 0)
        return 0;

    strncpy(g32_allocs[g32_allocCount].name, name, 63);
    g32_allocs[g32_allocCount].name[63] = 0;
    g32_allocs[g32_allocCount].addr = addr;
    g32_allocs[g32_allocCount].size = size;
    g32_allocCount++;
    return addr;
}

/* 释放 name 对应的申请内存并注销，成功返回真 */
BOOL Memory32_dealloc(const char* name)
{
    int i;

    if (g32_hProcess == NULL || name == NULL)
        return FALSE;
    for (i = 0; i < g32_allocCount; i++)
    {
        if (strcmp(g32_allocs[i].name, name) == 0)
        {
            BOOL ok = VirtualFreeEx(g32_hProcess, (LPVOID)(ULONG_PTR)g32_allocs[i].addr,
                                    0, MEM_RELEASE);
            /* 释放后无论成败都注销，避免脏条目 */
            g32_allocs[i] = g32_allocs[g32_allocCount - 1];
            g32_allocCount--;
            return ok;
        }
    }
    return FALSE;
}

/* 把汇编数据(机器码)写入 name 对应已申请的内存(需先 Memory32_alloc)，
   成功返回真；名字未登记、含非法十六进制或超出申请容量返回假 */
BOOL Memory32_definealloc(const char* name, Assembly code)
{
    BYTE buf[4096];
    const char* const* p;
    int idx, n, total = 0;

    if (g32_hProcess == NULL || name == NULL || code == NULL)
        return FALSE;
    for (idx = 0; idx < g32_allocCount; idx++)
    {
        if (strcmp(g32_allocs[idx].name, name) == 0)
            break;
    }
    if (idx >= g32_allocCount)
        return FALSE;                   /* 名字未登记 */

    /* ponytail: 靠 NULL 结尾 + 64 行上限(与 Assembly 数组大小一致)兜底 */
    for (p = code; *p != NULL && (p - code) < 64; p++)
    {
        if ((*p)[strspn(*p, " \t")] == '\0')
            continue;                   /* 空行/纯空格行跳过 */
        n = AssembleLine(*p, KS_MODE_32, g32_allocs[idx].addr + total,
                         buf + total, (int)(sizeof(buf) - total));
        if (n < 0)
            return FALSE;               /* 有非法行则整体不写入 */
        total += n;
    }
    if (total == 0)
        return FALSE;
    if ((SIZE_T)total > g32_allocs[idx].size)
        return FALSE;                   /* 超出申请容量 */

    return Memory32_WriteAddr((DWORD)g32_allocs[idx].addr, buf, (DWORD)total);
}

/* 在目标进程创建线程，入口为 name 对应已申请的内存(需先 Memory32_alloc+definealloc)，
   类似 CE 的 createThread。成功返回远程线程句柄(可 Waitthread/Closethread)，
   失败返回 NULL；线程执行完代码洞后自动退出 */
HANDLE Memory32_createThread(const char* name)
{
    int idx;

    if (g32_hProcess == NULL || name == NULL)
        return NULL;
    for (idx = 0; idx < g32_allocCount; idx++)
    {
        if (strcmp(g32_allocs[idx].name, name) == 0)
            break;
    }
    if (idx >= g32_allocCount)
        return NULL;                    /* 名字未登记 */

    return CreateRemoteThread(g32_hProcess, NULL, 0,
                              (LPTHREAD_START_ROUTINE)(ULONG_PTR)g32_allocs[idx].addr,
                              NULL, 0, NULL);
}
