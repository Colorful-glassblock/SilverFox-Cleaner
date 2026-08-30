/* ============================================================================
 * SilverFox Cleaner C — 重写版 (x86/x64, NT6+)
 * 血泪教训整合:
 *  - 自带启动入口 (xp_crt_shim.c), 不依赖 msvcrt 启动链
 *  - msvcrt 导入仅限经典符号; __p___initenv/_initterm_e/_lock_file
 *    /_unlock_file/__setusermatherr 及 __p__* 访问器一律本地垫片
 *  - UAC: app.manifest requireAdministrator (windres 嵌入)
 *  - 极端模式: 0xC0114514 蓝屏 ×2 + safeboot 安全模式清场 + RunOnce(*) 自拉起
 *  - SFQENC1 与 Rust/WinUI3 版字节级互通
 * ==========================================================================*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

/* ---- 常量 ---- */
#define QUAR_ROOT   "C:\\ProgramData\\sf_quarantine"
#define RUN_KEY     "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUNONCE_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
#define MARK_KEY    "Software\\SFCleaner"
#define BUGCHECK_CODE 0xC0114514u

/* 编译期内嵌驱动 (CI 由 xxd 生成 embed_drv.h -> sfc_drv[] / sfc_drv_len) */
#if defined(__has_include)
#  if __has_include("embed_drv.h") && __has_include("embed_cer.h")
#    include "embed_drv.h"
#    include "embed_cer.h"
#    define HAVE_EMBED 1
#  else
#    define HAVE_EMBED 0
#  endif
#else
#  define HAVE_EMBED 0
#endif
#define QMAGIC "SFQENC1\0"
#define MAXF 1024

static const char *C2_IOCS[]  = {"4d.skendh.com", "de.sjd82.org", "skendh.com", "sjd82.org", "dmo/client"};
static const char *NAME_HITS[] = {"ekxzjr", "dd9ocged", "srl.exe", "wdybq.dll", "steam.exe",
    "drivers.dat", "drivers.dat.0",
    "wow64log.dll", "vafdska.sys", "vmservice.sys",  /* 旧版变种驱动/劫持 DLL (社区工具 IOC) */
    "1.bat", "fhq.bat", "z_1.bat"};
static const char *DIR_HITS[] = {"diamondage", "roning", "minifilterdrv"};
static const char *SVC_PATS[][2] = {{"EkxZJr", "1"}, {"SrL.exe", "1"}, {"cd /d", "0"}};

typedef struct { char kind[12]; char detail[700]; int high; char action[400]; } Finding;
static Finding g_f[MAXF];
static int g_nf;

/* ---- 小工具 ---- */
static CRITICAL_SECTION g_fcs;
static int g_fcs_init = 0;

static void addf(const char *kind, int high, const char *detail, const char *action)
{
    if (g_nf >= MAXF) return;
    if (!g_fcs_init) { InitializeCriticalSection(&g_fcs); g_fcs_init = 1; }
    EnterCriticalSection(&g_fcs);
    if (g_nf >= MAXF) { LeaveCriticalSection(&g_fcs); return; }
    Finding *f = &g_f[g_nf++];
    memset(f, 0, sizeof *f);
    strncpy(f->kind, kind, sizeof f->kind - 1);
    strncpy(f->detail, detail, sizeof f->detail - 1);
    strncpy(f->action, action, sizeof f->action - 1);
    f->high = high;
    LeaveCriticalSection(&g_fcs);
}

static int mem_find_bytes(const unsigned char *h, size_t hl, const unsigned char *n, size_t nl)
{
    size_t i, j;
    if (!n || nl == 0 || hl < nl) return 0;
    for (i = 0; i <= hl - nl; i++) {
        for (j = 0; j < nl; j++) if (h[i + j] != n[j]) break;
        if (j == nl) return 1;
    }
    return 0;
}

static int ascii_utf16le(const char *s, unsigned char *out)
{
    int n = 0;
    for (; *s; s++) { out[n++] = (unsigned char)*s; out[n++] = 0; }
    return n;
}

static void str_lower(char *s)
{
    for (; *s; s++) if (*s >= 'A' && *s <= 'Z') *s += 32;
}

static HWND g_edit; /* 前置: xlog 需要在 GUI 模式回显 phase 日志 (定义处在 GUI 段仅剩 g_btn) */

static void xlog(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    FILE *f;
    SYSTEMTIME st;
    va_start(ap, fmt);
    _vsnprintf(line, sizeof line - 1, fmt, ap);
    va_end(ap);
    line[sizeof line - 1] = 0;
    CreateDirectoryA(QUAR_ROOT, NULL);
    f = fopen(QUAR_ROOT "\\extreme.log", "a");
    if (!f) return;
    GetLocalTime(&st);
    fprintf(f, "[%02u:%02u:%02u] %s\n", st.wHour, st.wMinute, st.wSecond, line);
    fclose(f);
    if (g_edit) { /* GUI 模式同步回显, 不客气/极端阶段不再黑箱 */
        LONG n = GetWindowTextLengthA(g_edit);
        SendMessageA(g_edit, EM_SETSEL, n, n);
        SendMessageA(g_edit, EM_REPLACESEL, FALSE, (LPARAM)line);
        SendMessageA(g_edit, EM_REPLACESEL, FALSE, (LPARAM)"\n");
    }
}

static int run_cmd(const char *fmt, ...)
{
    char cmd[1400], full[1500];
    va_list ap; STARTUPINFOA si; PROCESS_INFORMATION pi; DWORD code = 1;
    va_start(ap, fmt); _vsnprintf(cmd, sizeof cmd - 1, fmt, ap); va_end(ap);
    cmd[sizeof cmd - 1] = 0;
    _snprintf(full, sizeof full - 1, "cmd.exe /c %s", cmd);
    full[sizeof full - 1] = 0;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    if (!CreateProcessA(NULL, full, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 0;
    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return code == 0;
}

static void enable_privs(void)
{
    HANDLE tok; TOKEN_PRIVILEGES tp; LUID luid;
    static const char *privs[] = {"SeTakeOwnershipPrivilege", "SeRestorePrivilege",
        "SeBackupPrivilege", "SeDebugPrivilege", "SeSecurityPrivilege"};
    int i;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    for (i = 0; i < 5; i++) {
        if (LookupPrivilegeValueA(NULL, privs[i], &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
        }
    }
    CloseHandle(tok);
}

static void take_own(const char *path)
{
    run_cmd("takeown /f \"%s\" /a", path);
    run_cmd("icacls \"%s\" /grant Administrators:F", path);
}

static void mkdir_p(const char *path)
{
    char tmp[MAX_PATH]; char *p;
    _snprintf(tmp, sizeof tmp - 1, "%s", path); tmp[sizeof tmp - 1] = 0;
    for (p = tmp + 3; *p; p++) if (*p == '\\') { *p = 0; CreateDirectoryA(tmp, NULL); *p = '\\'; }
    CreateDirectoryA(tmp, NULL);
}

/* ---- SFQENC1 (xorshift64*, 与 Rust/WinUI3 一致) ---- */
static unsigned long long xs_step(unsigned long long *x)
{
    unsigned long long v = *x;
    v ^= v >> 12; v ^= v << 25; v ^= v >> 27;
    *x = v;
    return v * 0x2545F4914F6CDD1DULL;
}

static void apply_ks(unsigned long long seed, unsigned char *d, size_t n)
{
    unsigned long long s = seed ^ 0xA55A5AA50F0F0F0FULL, k;
    size_t off; int i, m, w;
    for (w = 0; w < 4; w++) xs_step(&s);
    for (off = 0; off < n; off += 8) {
        k = xs_step(&s);
        m = (int)((n - off < 8) ? (n - off) : 8);
        for (i = 0; i < m; i++) d[off + i] ^= (unsigned char)(k >> (8 * i));
    }
}

static void put_u64le(unsigned char *p, unsigned long long v) { int i; for (i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (8 * i)); }
static unsigned long long get_u64le(const unsigned char *p) { unsigned long long v = 0; int i; for (i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static void put_u32le(unsigned char *p, unsigned long v) { p[0]=(unsigned char)v; p[1]=(unsigned char)(v>>8); p[2]=(unsigned char)(v>>16); p[3]=(unsigned char)(v>>24); }
static unsigned long get_u32le(const unsigned char *p) { return p[0] | (p[1]<<8) | (p[2]<<16) | ((unsigned long)p[3]<<24); }

static unsigned long long dir_ts(const char *qdir)
{
    const char *base = strrchr(qdir, '\\');
    return base ? _strtoui64(base + 1, NULL, 10) : 0;
}

static int seal_file(const char *staged, const char *origPath, const char *qdir)
{
    FILE *f, *o;
    unsigned char *data, *out;
    wchar_t wsrc[MAX_PATH * 2];
    unsigned long long sz = 0;
    char sealed[MAX_PATH];
    int wlen;
    size_t hdr, total;

    f = fopen(staged, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); sz = (unsigned long long)ftell(f); fseek(f, 0, SEEK_SET);
    data = (unsigned char *)malloc((size_t)sz + 1);
    if (!data) { fclose(f); return 0; }
    if (fread(data, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(data); return 0; }
    fclose(f);
    apply_ks(dir_ts(qdir), data, (size_t)sz);
    wlen = MultiByteToWideChar(CP_ACP, 0, origPath, -1, wsrc, MAX_PATH * 2) - 1;
    if (wlen < 0) { free(data); return 0; }
    hdr = 20 + (size_t)wlen * 2;
    total = hdr + (size_t)sz;
    out = (unsigned char *)malloc(total);
    if (!out) { free(data); return 0; }
    memset(out, 0, hdr);
    memcpy(out, QMAGIC, 8);
    put_u64le(out + 8, sz);
    put_u32le(out + 16, (unsigned long)wlen);
    memcpy(out + 20, wsrc, (size_t)wlen * 2);
    memcpy(out + hdr, data, (size_t)sz);
    _snprintf(sealed, sizeof sealed - 1, "%s.qenc", staged);
    o = fopen(sealed, "wb");
    if (!o) { free(data); free(out); return 0; }
    fwrite(out, 1, total, o);
    fclose(o);
    remove(staged);
    free(data); free(out);
    return 1;
}

static int quarantine_one(const char *src, const char *qdir)
{
    char staged[MAX_PATH];
    const char *base = strrchr(src, '\\');
    if (!base) base = src; else base++;
    if (GetFileAttributesA(src) == INVALID_FILE_ATTRIBUTES) return 1;
    mkdir_p(qdir);
    take_own(src);
    _snprintf(staged, sizeof staged - 1, "%s\\%s", qdir, base);
    if (!MoveFileA(src, staged)) {
        if (!CopyFileA(src, staged, FALSE) || !DeleteFileA(src)) return 0;
    }
    if (!seal_file(staged, src, qdir)) { remove(staged); return 0; }
    return 1;
}

static int unseal_restore(const char *p, unsigned long long ts, char *desc)
{
    FILE *f, *o;
    unsigned char *raw;
    long sz;
    unsigned long long size;
    unsigned long plen;
    size_t hs;
    char target[MAX_PATH], *cut;
    int ok = 0;

    if (desc) desc[0] = 0;
    f = fopen(p, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 24) { fclose(f); return 0; }
    raw = (unsigned char *)malloc((size_t)sz);
    if (!raw) { fclose(f); return 0; }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(raw); return 0; }
    fclose(f);
    if (memcmp(raw, QMAGIC, 8)) { free(raw); return 0; }
    size = get_u64le(raw + 8);
    plen = get_u32le(raw + 16);
    hs = 20 + (size_t)plen * 2;
    if (plen > 4096 || (unsigned long long)sz < hs + size) { free(raw); return 0; }
    memset(target, 0, sizeof target);
    WideCharToMultiByte(CP_ACP, 0, (const wchar_t *)(raw + 20), (int)plen,
                        target, sizeof target - 1, NULL, NULL);
    apply_ks(ts, raw + hs, (size_t)size);
    cut = strrchr(target, '\\');
    if (cut) { *cut = 0; mkdir_p(target); *cut = '\\'; }
    take_own(target);
    o = fopen(target, "wb");
    if (o) { fwrite(raw + hs, 1, (size_t)size, o); fclose(o); remove(p); ok = 1; }
    if (desc) _snprintf(desc, 300, "%s", target);
    free(raw);
    return ok;
}

/* ---- 遍历 (深度≤4, 不进 junction) ---- */
static void walk_paths(const char *dir, int depth, void (*cb)(const char *full, void *ctx), void *ctx)
{
    char path[MAX_PATH], full[MAX_PATH];
    WIN32_FIND_DATAA fd; HANDLE h;
    if (depth > 4 || !cb) return;
    _snprintf(path, sizeof path - 1, "%s\\*", dir); path[sizeof path - 1] = 0;
    h = FindFirstFileA(path, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        _snprintf(full, sizeof full - 1, "%s\\%s", dir, fd.cFileName);
        full[sizeof full - 1] = 0;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) walk_paths(full, depth + 1, cb, ctx);
        } else cb(full, ctx);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* ---- 扫描: 计划任务 ---- */
static void task_cb(const char *full, void *unused);
static void scan_tasks_walk(const char *dir);

static void scan_tasks(void)
{
    scan_tasks_walk("C:\\Windows\\System32\\Tasks");
}

static void task_cb(const char *full, void *unused)
{
    static unsigned char buf[1 << 20];
    char u1[32], u2[32], u3[32], u4[32];
    int l1 = ascii_utf16le("EkxZJr", u1);
    int l2 = ascii_utf16le("SrL.exe", u2);
    int l3 = ascii_utf16le("cd /d", u3);
    int l4 = ascii_utf16le("&& start", u4);
    FILE *f = fopen(full, "rb");
    (void)unused;
    if (!f) return;
    {
        size_t n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        {
            int hi = mem_find_bytes(buf, n, (const unsigned char *)"EkxZJr", 7)
                  || mem_find_bytes(buf, n, (const unsigned char *)"SrL.exe", 7)
                  || mem_find_bytes(buf, n, u1, l1)
                  || mem_find_bytes(buf, n, u2, l2);
            int md = mem_find_bytes(buf, n, u3, l3) && mem_find_bytes(buf, n, u4, l4);
            char det[MAX_PATH + 16], act[MAX_PATH + 64];
            if (hi || md) {
                if (hi) { strncpy(det, full, sizeof det - 1); det[sizeof det - 1] = 0; }
                else _snprintf(det, sizeof det - 1, "%s [链式]", full);
                _snprintf(act, sizeof act - 1, "schtasks /delete /tn \"%s\" /f", full + 35);
                addf("TASK", hi, det, act);
            }
        }
    }
}

static void scan_tasks_walk(const char *dir)
{
    walk_paths(dir, 0, task_cb, NULL);
}

/* ---- 扫描: 服务 ---- */
static int tree_contains(HKEY k, const char *pat, int depth)
{
    DWORD vals = 0, maxv = 0, subs = 0, maxs = 0, i;
    char vn[512], sn[256];
    if (RegQueryInfoKeyA(k, NULL, NULL, NULL, &subs, &maxs, NULL, &vals, &maxv, NULL, NULL, NULL)
        != ERROR_SUCCESS) return 0;
    (void)maxs;
    if (maxv >= sizeof vn) maxv = (DWORD)sizeof vn - 1;
    for (i = 0; i < vals; i++) {
        DWORD vnlen = sizeof vn, dlen = sizeof vn, typ = 0;
        char data[2048];
        if (RegEnumValueA(k, i, vn, &vnlen, NULL, &typ, (BYTE *)data, &dlen) != ERROR_SUCCESS) continue;
        if ((typ == REG_SZ || typ == REG_EXPAND_SZ) && dlen > 0) {
            data[dlen < sizeof data - 1 ? dlen : sizeof data - 1] = 0;
            if (strstr(data, pat)) return 1;
        } else if (typ == REG_MULTI_SZ && dlen >= 2) {
            char *p = data;
            data[dlen < sizeof data - 1 ? dlen : sizeof data - 1] = 0;
            while (*p) { if (strstr(p, pat)) return 1; p += strlen(p) + 1; }
        }
    }
    if (depth >= 3) return 0;
    for (i = 0; i < subs; i++) {
        DWORD l = sizeof sn; HKEY sk; int r;
        if (RegEnumKeyExA(k, i, sn, &l, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) continue;
        if (RegOpenKeyExA(k, sn, 0, KEY_READ, &sk) != ERROR_SUCCESS) continue;
        r = tree_contains(sk, pat, depth + 1);
        RegCloseKey(sk);
        if (r) return 1;
    }
    return 0;
}

/* 旧版变种驱动服务黑名单 (社区清理工具交叉引用) */
static const char *SVC_BLACK[] = {"vafdska", "MiniFilterDrv", "vmservice", "MicrosoftSoftware2ShadowCop4yProvider"};

static void scan_services(void)
{
    HKEY rk; DWORD i, subs = 0;
    static char seen[MAXF][256]; int nseen = 0;
    int p;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &rk)
        != ERROR_SUCCESS) return;
    RegQueryInfoKeyA(rk, NULL, NULL, NULL, &subs, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    for (p = 0; p < 3; p++) {
        int high = SVC_PATS[p][1][0] == '1';
        for (i = 0; i < subs; i++) {
            DWORD l = 256; char name[256]; HKEY sk; int j, dup = 0;
            if (RegEnumKeyExA(rk, i, name, &l, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) continue;
            for (j = 0; j < nseen; j++) if (!_stricmp(seen[j], name)) { dup = 1; break; }
            if (dup) continue;
            {
                int b;
                for (b = 0; b < (int)(sizeof SVC_BLACK / sizeof SVC_BLACK[0]); b++) {
                    if (!_stricmp(name, SVC_BLACK[b])) {
                        char det[300], act[300];
                        _snprintf(det, sizeof det - 1, "%s [银狐变种驱动服务]", name);
                        _snprintf(act, sizeof act - 1, "sc delete \"%s\"", name);
                        addf("SERVICE", 1, det, act);
                        break;
                    }
                }
            }
            if (RegOpenKeyExA(rk, name, 0, KEY_READ, &sk) != ERROR_SUCCESS) continue;
            if (tree_contains(sk, SVC_PATS[p][0], 0)) {
                RegCloseKey(sk);
                if (nseen < MAXF) { strncpy(seen[nseen], name, 255); seen[nseen][255] = 0; nseen++; }
                {
                    char det[300], act[300];
                    if (high) { strncpy(det, name, sizeof det - 1); det[sizeof det - 1] = 0; }
                    else _snprintf(det, sizeof det - 1, "%s [结构]", name);
                    _snprintf(act, sizeof act - 1, "sc delete \"%s\"", name);
                    addf("SERVICE", high, det, act);
                }
            } else RegCloseKey(sk);
        }
    }
    RegCloseKey(rk);
}

/* ---- 扫描: 进程 + 互斥 ---- */
typedef struct { DWORD pid; char name[64]; } PINFO;
static PINFO g_procs[1024]; static int g_np;

static void enum_processes(void)
{
    HANDLE snap; PROCESSENTRY32 pe;
    g_np = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof pe;
    if (Process32First(snap, &pe)) {
        do {
            if (g_np >= 1024) break;
            g_procs[g_np].pid = pe.th32ProcessID;
            strncpy(g_procs[g_np].name, pe.szExeFile, 63);
            g_procs[g_np].name[63] = 0;
            g_np++;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static void scan_procs(void)
{
    int i;
    enum_processes();
    for (i = 0; i < g_np; i++) {
        char digits[16], rev[16], mn[64], det[192];
        HANDLE m;
        int j, len;
        if (!_stricmp(g_procs[i].name, "srl.exe")) {
            _snprintf(det, sizeof det - 1, "SrL.exe (pid %lu)", (unsigned long)g_procs[i].pid);
            _snprintf(mn, sizeof mn - 1, "taskkill /f /pid %lu", (unsigned long)g_procs[i].pid);
            addf("PROCESS", 1, det, mn);
        }
        _snprintf(digits, sizeof digits - 1, "%lu", (unsigned long)g_procs[i].pid);
        len = (int)strlen(digits);
        for (j = 0; j < len; j++) rev[j] = digits[len - 1 - j];
        rev[len] = 0;
        _snprintf(mn, sizeof mn - 1, "Global\\P_%s", rev);
        m = OpenMutexA(0x1F0001, FALSE, mn);
        if (m) {
            CloseHandle(m);
            _snprintf(det, sizeof det - 1, "%s (pid %lu %s)", mn, (unsigned long)g_procs[i].pid, g_procs[i].name);
            addf("MUTEX", 1, det, "随进程终止");
        }
    }
}

/* ---- 扫描: ctfmon 内存 ---- */
static void scan_ctfmon(void)
{
    int i;
    for (i = 0; i < g_np; i++) {
        HANDLE h; ULONG_PTR addr = 0x10000;
        char hits[256]; int nh = 0;
        size_t k;
        if (_stricmp(g_procs[i].name, "ctfmon.exe")) continue;
        h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_procs[i].pid);
        if (!h) continue;
        hits[0] = 0;
        for (;;) {
            MEMORY_BASIC_INFORMATION mbi;
            unsigned char *buf;
            SIZE_T got = 0;
            if (!VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof mbi)) break;
            if ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize <= addr) break;
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)
                && !(mbi.Protect & PAGE_NOACCESS) && mbi.RegionSize > 0
                && mbi.RegionSize <= 0x10000000u) {
                buf = (unsigned char *)VirtualAlloc(NULL, mbi.RegionSize, MEM_COMMIT, PAGE_READWRITE);
                if (buf) {
                    if (ReadProcessMemory(h, mbi.BaseAddress, buf, mbi.RegionSize, &got) && got > 0) {
                        for (k = 0; k < sizeof C2_IOCS / sizeof C2_IOCS[0]; k++) {
                            if (!strstr(hits, C2_IOCS[k])
                                && mem_find_bytes(buf, got, (const unsigned char *)C2_IOCS[k],
                                                  strlen(C2_IOCS[k]))) {
                                if (nh) strncat(hits, ", ", sizeof hits - strlen(hits) - 1);
                                strncat(hits, C2_IOCS[k], sizeof hits - strlen(hits) - 1);
                                nh++;
                            }
                        }
                    }
                    VirtualFree(buf, 0, MEM_RELEASE);
                }
            }
            addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        }
        CloseHandle(h);
        if (nh) {
            char det[384];
            _snprintf(det, sizeof det - 1, "ctfmon.exe (pid %lu) 注入: %s",
                      (unsigned long)g_procs[i].pid, hits);
            addf("PROC-MEM", 1, det, "重启 ctfmon");
        }
    }
}

/* ---- 扫描: 落盘文件 ---- */
static void file_cb(const char *full, void *unused)
{
    char low[MAX_PATH], lfnm[256];
    char *base;
    int j, byNm = 0;
    unsigned long long sz;
    WIN32_FIND_DATAA fd; HANDLE hd;
    (void)unused;
    strncpy(low, full, sizeof low - 1); low[sizeof low - 1] = 0;
    str_lower(low);
    if (strstr(low, "sf_quarantine")) return;
    hd = FindFirstFileA(full, &fd);
    if (hd == INVALID_HANDLE_VALUE) return;
    FindClose(hd);
    base = strrchr(full, '\\');
    base = base ? base + 1 : (char *)full;
    strncpy(lfnm, base, sizeof lfnm - 1); lfnm[sizeof lfnm - 1] = 0;
    str_lower(lfnm);
    for (j = 0; j < (int)(sizeof NAME_HITS / sizeof NAME_HITS[0]); j++)
        if (!strcmp(lfnm, NAME_HITS[j])) byNm = 1;
    if (!strncmp(lfnm, "itqe.", 5)) byNm = 1;
    sz = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    {
        char md[64] = "";
        {
            static const char *exts[] = {".exe", ".dll", ".sys", ".xl", ".xlez"};
            size_t fl = strlen(lfnm);
            int k, isExt = 0;
            for (k = 0; k < (int)(sizeof exts / sizeof exts[0]); k++) {
                size_t el = strlen(exts[k]);
                if (fl > el && !_stricmp(lfnm + fl - el, exts[k])) { isExt = 1; break; }
            }
            if (isExt && (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)))
                strcat(md, " [隐藏+系统]");
            if (strstr(low, "\\public\\downloads\\") && isExt && (fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM))
                strcat(md, " [公共下载可疑]");
        }
        if (sz > 100 * 1024) {
            FILE *f = fopen(full, "rb");
            if (f) {
                unsigned char hd16[16];
                size_t n = fread(hd16, 1, sizeof hd16, f);
                fclose(f);
                if (mem_find_bytes(hd16, n, (const unsigned char *)"STEGR1Xp", 8)) strcat(md, " [STEGR1Xp]");
                if (mem_find_bytes(hd16, n, (const unsigned char *)"JELG", 4)) strcat(md, " [JELG]");
                if (n >= 4 && hd16[0] == 0x89 && hd16[1] == 'P' && hd16[2] == 'N' && hd16[3] == 'G') {
                    size_t fl = strlen(lfnm);
                    if (!(fl >= 4 && !strcmp(lfnm + fl - 4, ".png"))
                        && !strstr(low, "\\packages\\")) /* UWP 磁贴缓存是合法 PNG 头 .bin */
                        strcat(md, " [PNG伪装]");
                }
            }
        }
        if (byNm || md[0]) {
            char det[MAX_PATH + 64], act[MAX_PATH + 16];
            if (byNm) { strncpy(det, full, sizeof det - 1); det[sizeof det - 1] = 0; }
            else _snprintf(det, sizeof det - 1, "%s%s", full, md);
            _snprintf(act, sizeof act - 1, "quarantine %s", full);
            addf("FILE", byNm, det, act);
        }
    }
}

static void scan_files(void)
{
    char roots[8][MAX_PATH]; int nroots = 0, r;
    static const char *envs[] = {"TEMP", "APPDATA", "LOCALAPPDATA", "ProgramData"};
    strcpy(roots[nroots++], "C:\\Drivers");
    strcpy(roots[nroots++], "C:\\Users\\Public");
    for (r = 0; r < 4; r++) {
        char *v = getenv(envs[r]);
        if (v && *v && nroots < 8) strncpy(roots[nroots++], v, MAX_PATH - 1);
    }
    for (r = 0; r < nroots; r++) {
        walk_paths(roots[r], 0, file_cb, NULL);
    }
}

/* 版本资源 OriginalFilename: 改名白加黑的核心信号 —
   腾讯ACE改名steam.exe: 内嵌签名仍有效, 但 OriginalFilename 不会跟着改 */
static int ver_orig_name(const char *path, char *out, unsigned int outn)
{
    /* 动态解析: Ubuntu i686 libversion.a 缺 @装饰符号, 静态 -lversion 不可靠 */
    typedef DWORD (WINAPI *fn_SizeA)(LPCSTR, LPDWORD);
    typedef BOOL  (WINAPI *fn_InfoA)(LPCSTR, DWORD, DWORD, LPVOID);
    typedef BOOL  (WINAPI *fn_QueryA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
    static fn_SizeA pSize = NULL;
    static fn_InfoA pInfo = NULL;
    static fn_QueryA pQuery = NULL;
    static int inited = 0;
    DWORD h = 0, sz;
    UINT tsz = 0, olen = 0;
    static unsigned char vbuf[262144];
    void *ptrans = NULL;
    char *orig = NULL;
    WORD *w;
    char sub[256];
    unsigned int k;
    int ok = 0;

    out[0] = 0;
    if (!inited) {
        HMODULE v = LoadLibraryA("version.dll");
        inited = 1;
        if (v) {
            pSize  = (fn_SizeA)GetProcAddress(v, "GetFileVersionInfoSizeA");
            pInfo  = (fn_InfoA)GetProcAddress(v, "GetFileVersionInfoA");
            pQuery = (fn_QueryA)GetProcAddress(v, "VerQueryValueA");
        }
    }
    if (!pSize || !pInfo || !pQuery) return 0;
    sz = pSize(path, &h);
    if (!sz || sz > sizeof vbuf) return 0;
    if (!pInfo(path, 0, sz, vbuf)) return 0;
    if (!pQuery(vbuf, "\\VarFileInfo\\Translation", &ptrans, &tsz) || tsz < 4) return 0;
    w = (WORD *)ptrans;
    _snprintf(sub, sizeof sub - 1, "\\StringFileInfo\\%04x%04x\\OriginalFilename", w[0], w[1]);
    if (pQuery(vbuf, sub, (void **)&orig, &olen) && orig && olen > 1) {
        for (k = 0; k + 1 < outn && orig[k]; k++) out[k] = orig[k];
        out[k] = 0;
        ok = 1;
    }
    return ok;
}

/* ---- 白加黑检测: 同目录 [有效签名EXE + 未签名DLL] (跨变种结构特征) ---- */
static int bj_catalog_signed(const char *path);

static int bj_is_signed(const char *path)
{
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA wd;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    wchar_t wpath[MAX_PATH];
    LONG res;
    memset(&fi, 0, sizeof fi);
    memset(&wd, 0, sizeof wd);
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = wpath;
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    res = WinVerifyTrust(NULL, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);
    return res == 0 || bj_catalog_signed(path);
}

/* catalog 回退: 系统自带 PE 无内嵌签名, 由 catalog 数据库覆盖.
   内嵌验签 TRUST_E_NOSIGNATURE 时: 算文件哈希 -> 枚举 catalog -> WTD_CHOICE_CATALOG 复验 */
static int bj_catalog_signed(const char *path)
{
    /* catalog 物理库目录是 catroot\{F750E6C3-...} = DRIVER_ACTION_VERIFY subsystem;
       用 GENERIC_VERIFY_V2 做 acquire 枚举不到系统 catalog (Win11 实测全 NULL → 全误报).
       两个 subsystem 都试: 先 DRIVER(物理库对得上), 再 GENERIC 兜底 */
    static const GUID gDriver = { 0xF750E6C3, 0x38EE, 0x11D1, { 0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };
    GUID act = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const GUID *subs[2] = { &gDriver, &act };
    HANDLE fh;
    HCATADMIN hca;
    HCATINFO hc;
    BYTE hash[100];
    DWORD cb = sizeof hash;
    wchar_t wpath[MAX_PATH], wtag[256];
    int ok = 0, i, g;
    fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     NULL, OPEN_EXISTING, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE) return 0;
    if (!CryptCATAdminCalcHashFromFileHandle(fh, &cb, hash, 0) || cb == 0 || cb > sizeof hash) {
        CloseHandle(fh);
        return 0;
    }
    for (i = 0; i < (int)cb; i++)
        _snwprintf(wtag + i * 2, 3, L"%02X", hash[i]);
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, MAX_PATH);
    for (g = 0; g < 2 && !ok; g++) {
        if (!CryptCATAdminAcquireContext(&hca, subs[g], 0)) continue;
        hc = CryptCATAdminEnumCatalogFromHash(hca, hash, cb, 0, NULL);
        if (hc) {
            CATALOG_INFO ci;
            WINTRUST_CATALOG_INFO wci;
            WINTRUST_DATA wd;
            LONG r;
            memset(&ci, 0, sizeof ci);
            ci.cbStruct = sizeof ci;
            if (CryptCATCatalogInfoFromContext(hc, &ci, 0)) {
                memset(&wci, 0, sizeof wci);
                wci.cbStruct = sizeof wci;
                wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                wci.pcwszMemberTag = wtag;
                wci.pcwszMemberFilePath = wpath;
                wci.pbCalculatedFileHash = hash;   /* mingw 头为扩展版字段 */
                wci.cbCalculatedFileHash = cb;
                memset(&wd, 0, sizeof wd);
                wd.cbStruct = sizeof wd;
                wd.dwUIChoice = WTD_UI_NONE;
                wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wd.pCatalog = &wci;
                wd.dwStateAction = WTD_STATEACTION_VERIFY;
                r = WinVerifyTrust(NULL, &act, &wd);
                wd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(NULL, &act, &wd);
                ok = (r == 0);
            }
            CryptCATAdminReleaseCatalogContext(hca, hc, 0);
        }
        CryptCATAdminReleaseContext(hca, 0);
    }
    CloseHandle(fh);
    return ok;
}

static void bj_scan_dir(const char *dir, int depth)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pat[MAX_PATH], full[MAX_PATH];
    /* 枚举先行: 先收集 exe/dll 清单再决定是否验签 —
       无 exe 或无 dll 的目录 (绝大多数) 0 次验签; 配对才查, 找到即停 */
    char exes[24][MAX_PATH];
    char dlls[64][MAX_PATH];
    int nex = 0, ndl = 0, se = 0, ud = 0, w, i;
    char hitbuf[MAX_PATH];
    char sexepath[MAX_PATH];
    static const char *wls[5] = {"\\programs\\", "\\package cache\\", "\\windowsapps\\", "\\microsoft\\", "\\windows\\"};
    int whitelisted = 0;
    if (depth > 4) return;
    {
        static char lowq[1024]; /* 先 lower 再判, 隔离区目录本身要跳过 */
        unsigned int m = (unsigned int)(strlen(dir) < sizeof lowq - 1 ? strlen(dir) : sizeof lowq - 2);
        memcpy(lowq, dir, m); lowq[m] = 0;
        str_lower(lowq);
        if (strstr(lowq, "sf_quarantine")) return;
        for (w = 0; w < 5; w++)   /* 白名单目录: 降级为只跑改名检测 (改名检测无 QQ/微信误报) */
            if (strstr(lowq, wls[w])) whitelisted = 1;
    }
    _snprintf(pat, sizeof pat - 1, "%s\\*", dir); pat[sizeof pat - 1] = 0;
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        size_t fl;
        char low[64];
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        _snprintf(full, sizeof full - 1, "%s\\%s", dir, fd.cFileName);
        full[sizeof full - 1] = 0;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) bj_scan_dir(full, depth + 1);
            continue;
        }
        strncpy(low, fd.cFileName, 63); low[63] = 0;
        str_lower(low);
        fl = strlen(low);
        if (fl > 4 && !_stricmp(low + fl - 4, ".exe")) {
            if (nex < 24) { strncpy(exes[nex], full, MAX_PATH - 1); exes[nex][MAX_PATH - 1] = 0; nex++; }
        } else if (fl > 4 && !_stricmp(low + fl - 4, ".dll")) {
            if (ndl < 64) { strncpy(dlls[ndl], full, MAX_PATH - 1); dlls[ndl][MAX_PATH - 1] = 0; ndl++; }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    /* 白加黑本体 = 配对: [有效签名EXE + 未签名DLL] 同目录.
       改名 (OriginalFilename≠磁盘名) 只作佐证: 升高置信+补细节, 不单独成条 —
       单独成条会误伤 VC_redist 等版本资源残缺的正规安装器 */
    if (nex && ndl) {
        char sexepath[MAX_PATH];
        for (i = 0; i < nex && !se; i++)
            if (bj_is_signed(exes[i])) {
                se = 1;
                strncpy(sexepath, exes[i], sizeof sexepath - 1);
                sexepath[sizeof sexepath - 1] = 0;
            }
        if (se) {
            char orig[260] = "";
            int renamed = 0;
            if (ver_orig_name(sexepath, orig, sizeof orig) && orig[0]) {
                char lowbase[260], loworig[260];
                char *base = strrchr(sexepath, '\\');
                base = base ? base + 1 : sexepath;
                strncpy(lowbase, base, sizeof lowbase - 1); lowbase[sizeof lowbase - 1] = 0;
                strncpy(loworig, orig, sizeof loworig - 1); loworig[sizeof loworig - 1] = 0;
                str_lower(lowbase); str_lower(loworig);
                renamed = strcmp(lowbase, loworig) != 0 && strlen(orig) >= 4;
            }
            /* 白名单目录仅当签名 EXE 被改名时才成立 (正规软件名实一致) */
            if (!whitelisted || renamed) {
                for (i = 0; i < ndl && !ud; i++)
                    if (!bj_is_signed(dlls[i])) {
                        strncpy(hitbuf, dlls[i], sizeof hitbuf - 1);
                        hitbuf[sizeof hitbuf - 1] = 0;
                        ud = 1;
                    }
            }
            if (se && ud) {
                char det[MAX_PATH + 192], act[MAX_PATH + 16];
                if (renamed)
                    _snprintf(det, sizeof det - 1, "%s [白加黑: 签名EXE被改名 (OriginalFilename=%s)+未签名DLL]", hitbuf, orig);
                else
                    _snprintf(det, sizeof det - 1, "%s [白加黑: 有效签名EXE+未签名DLL]", hitbuf);
                _snprintf(act, sizeof act - 1, "quarantine %s", hitbuf);
                addf("FILE", renamed, det, act);
            }
        }
    }
}

static void scan_bj(void)
{
    char roots[8][MAX_PATH]; int nroots = 0, r;
    static const char *envs[] = {"TEMP", "APPDATA", "LOCALAPPDATA", "ProgramData"};
    strcpy(roots[nroots++], "C:\\Drivers");
    strcpy(roots[nroots++], "C:\\Users\\Public");
    for (r = 0; r < 4; r++) {
        char *v = getenv(envs[r]);
        if (v && *v && nroots < 8) strncpy(roots[nroots++], v, MAX_PATH - 1);
    }
    for (r = 0; r < nroots; r++) bj_scan_dir(roots[r], 0);
}


/* ---- SHA-512 (自足实现, 驱动制品哈希排除用) ---- */
typedef struct { unsigned long long h[8], len; unsigned char buf[128]; unsigned int bl; } SFC_SHA512;
static const unsigned long long K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

#define SFC_ROR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
static void sfc_sha512_block(SFC_SHA512 *c, const unsigned char *p)
{
    unsigned long long w[80], a, b, cc, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((unsigned long long)p[i*8] << 56) | ((unsigned long long)p[i*8+1] << 48) |
               ((unsigned long long)p[i*8+2] << 40) | ((unsigned long long)p[i*8+3] << 32) |
               ((unsigned long long)p[i*8+4] << 24) | ((unsigned long long)p[i*8+5] << 16) |
               ((unsigned long long)p[i*8+6] << 8) | (unsigned long long)p[i*8+7];
    for (i = 16; i < 80; i++) {
        unsigned long long s0 = SFC_ROR64(w[i-15],1) ^ SFC_ROR64(w[i-15],8) ^ (w[i-15] >> 7);
        unsigned long long s1 = SFC_ROR64(w[i-2],19) ^ SFC_ROR64(w[i-2],61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3]; e=c->h[4]; f=c->h[5]; g=c->h[6]; hh=c->h[7];
    for (i = 0; i < 80; i++) {
        unsigned long long S1 = SFC_ROR64(e,14) ^ SFC_ROR64(e,18) ^ SFC_ROR64(e,41);
        unsigned long long ch = (e & f) ^ ((~e) & g);
        t1 = hh + S1 + ch + K512[i] + w[i];
        unsigned long long S0 = SFC_ROR64(a,28) ^ SFC_ROR64(a,34) ^ SFC_ROR64(a,39);
        unsigned long long mj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=hh;
}
static void sfc_sha512_init(SFC_SHA512 *c)
{
c->h[0]=0x6a09e667f3bcc908ULL; c->h[1]=0xbb67ae8584caa73bULL;
    c->h[2]=0x3c6ef372fe94f82bULL; c->h[3]=0xa54ff53a5f1d36f1ULL;
    c->h[4]=0x510e527fade682d1ULL; c->h[5]=0x9b05688c2b3e6c1fULL;
    c->h[6]=0x1f83d9abfb41bd6bULL; c->h[7]=0x5be0cd19137e2179ULL;
    c->len = 0; c->bl = 0;
}
static void sfc_sha512_update(SFC_SHA512 *c, const unsigned char *d, unsigned long long n)
{
    c->len += n;
    while (n) {
        unsigned long long take = 128 - c->bl; if (take > n) take = n;
        { unsigned long long k; for (k = 0; k < take; k++) c->buf[c->bl + k] = d[k]; }
        c->bl += (unsigned int)take; d += take; n -= take;
        if (c->bl == 128) { sfc_sha512_block(c, c->buf); c->bl = 0; }
    }
}
static void sfc_sha512_final(SFC_SHA512 *c, unsigned char *out)
{
    unsigned long long bits = c->len * 8;
    unsigned char pad[129];
    unsigned int padlen;
    int i;
    unsigned char tail[16];
    pad[0] = 0x80;
    padlen = (c->bl < 112) ? (112 - c->bl) : (240 - c->bl);
    for (i = 1; i < (int)padlen; i++) pad[i] = 0;
    for (i = 0; i < 8; i++) tail[i] = 0;                                  /* 128bit 高 64 位恒 0 */
    for (i = 0; i < 8; i++) tail[8 + i] = (unsigned char)(bits >> (56 - i * 8));
    sfc_sha512_update(c, pad, padlen);   /* 注意: update 会累加 len — 先存 bits 已处理 */
    sfc_sha512_update(c, tail, 16);
    for (i = 0; i < 8; i++) {
        out[i*8]   = (unsigned char)(c->h[i] >> 56); out[i*8+1] = (unsigned char)(c->h[i] >> 48);
        out[i*8+2] = (unsigned char)(c->h[i] >> 40); out[i*8+3] = (unsigned char)(c->h[i] >> 32);
        out[i*8+4] = (unsigned char)(c->h[i] >> 24); out[i*8+5] = (unsigned char)(c->h[i] >> 16);
        out[i*8+6] = (unsigned char)(c->h[i] >> 8);  out[i*8+7] = (unsigned char)(c->h[i]);
    }
}

/* ---- %WINDIR% 随机名 PE/bat 检测 (银狐新变种浅层落盘) ----
 * 随机名 + 未签名 双条件: 系统 PE 走 catalog 签名, 随机名但验签通过 → 放行 */
static const char *WD_SKIP[] = {
    "\\winsxs", "\\softwaredistribution", "\\driverstore", "\\installer",
    "\\assembly", "\\microsoft.net", "\\servicing", "\\logfiles", "\\logs",
    "\\spool", "\\catroot", "\\fonts", "\\media", "\\ime", "\\web",
    "\\wallpaper", "\\oledb", "\\mui", "\\ehome", "\\pchealth", "\\resources",
    "\\livekernelreports", "\\minidump", "\\prefetch", "\\appcompat",
    "\\apppatch", "\\csc", "\\diagnostics", "\\panther", "\\performance",
    "\\pla", "\\registration", "\\shellcomponents", "\\triage", "\\winstore",
    "\\tokens", "\\csp", "\\containers", "\\config", "\\msdtc", NULL
};

static int wd_random_name(const char *fn) /* fn=原始文件名(含扩展名); 返回: 0否 1pe 2bat */
{
    const char *dot = strrchr(fn, '.');
    size_t bl, i;
    int dig = 0, up = 0, is_pe = 0, is_bat = 0;
    char extl[8];
    if (!dot) return 0;
    strncpy(extl, dot, sizeof extl - 1); extl[sizeof extl - 1] = 0; str_lower(extl);
    if (!strcmp(extl, ".exe") || !strcmp(extl, ".dll") || !strcmp(extl, ".sys")) is_pe = 1;
    else if (!strcmp(extl, ".bat")) is_bat = 1;
    else return 0;
    bl = (size_t)(dot - fn);
    if (bl < 6 || bl > 16) return 0;
    for (i = 0; i < bl; i++) {
        char c = fn[i];
        if (c >= '0' && c <= '9') { dig++; continue; }
        if (c >= 'A' && c <= 'Z') { up++; continue; }
        if (c >= 'a' && c <= 'z') continue;
        return 0; /* 含分隔符/非ASCII → 非随机名形态 */
    }
    if (is_bat) return 2; /* windir 下随机名 bat 本身即高置信 */
    if (dig >= 2 || up || bl >= 8) return 1;
    return 0;
}

static int drv_is_selfdrv(const char *path, long long sz);

static void wd_scan_dir(const char *dir, int depth)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pat[MAX_PATH], full[MAX_PATH];
    int w;
    if (depth > 4) return;
    {
        char low[MAX_PATH + 8];
        strncpy(low, dir, sizeof low - 2); low[sizeof low - 2] = 0;
        str_lower(low);
        for (w = 0; WD_SKIP[w]; w++)
            if (strstr(low, WD_SKIP[w])) return;
    }
    _snprintf(pat, sizeof pat - 1, "%s\\*", dir); pat[sizeof pat - 1] = 0;
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        int rt;
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        _snprintf(full, sizeof full - 1, "%s\\%s", dir, fd.cFileName);
        full[sizeof full - 1] = 0;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) wd_scan_dir(full, depth + 1);
            continue;
        }
        rt = wd_random_name(fd.cFileName);
        if (!rt) continue;
        {
            long long fsz = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (drv_is_selfdrv(full, fsz)) continue; /* SHA-512 等于本版驱动才豁免 */
        }
        if (rt == 1 && bj_is_signed(full)) continue; /* 随机名但签名有效 → 放行 */
        {
            char det[MAX_PATH + 40], act[MAX_PATH + 16];
            _snprintf(det, sizeof det - 1, "%s [%s]", full, rt == 1 ? "随机名未签名PE" : "随机名bat");
            _snprintf(act, sizeof act - 1, "quarantine %s", full);
            addf("FILE", 1, det, act);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static unsigned char g_drvsha[64];
static long long g_drvlen = -1;
static int g_drvsha_ok = 0;

static void drv_selfsha_init(void)
{
#if HAVE_EMBED
    SFC_SHA512 c;
    sfc_sha512_init(&c);
    sfc_sha512_update(&c, sfc_drv, sfc_drv_len);
    sfc_sha512_final(&c, g_drvsha);
    g_drvlen = (long long)sfc_drv_len;
    g_drvsha_ok = 1;
#endif
}

/* 哈希排除: 逐字节等于本版驱动才豁免 (改名伪装照样被扫) */
static int drv_is_selfdrv(const char *path, long long sz)
{
    static unsigned char sbuf[65536];
    SFC_SHA512 c;
    unsigned char d[64];
    FILE *f;
    if (!g_drvsha_ok || sz != g_drvlen || sz < 0 || sz > (long long)sizeof sbuf) return 0;
    f = fopen(path, "rb");
    if (!f) return 0;
    if (fread(sbuf, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); return 0; }
    fclose(f);
    sfc_sha512_init(&c);
    sfc_sha512_update(&c, sbuf, (unsigned long long)sz);
    sfc_sha512_final(&c, d);
    return memcmp(d, g_drvsha, 64) == 0;
}

static void scan_windir(void)
{
    char wd[MAX_PATH], probe[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("WINDIR", wd, sizeof wd);
    if (!n || n >= sizeof wd - 4) strcpy(wd, "C:\\Windows");
    drv_selfsha_init();
    /* 启动自检: actxprxy.dll 是 catalog-only 系统文件(无内嵌签名), 验不过说明 catalog 回退不可用,
       此时扫描 windir 会把大量系统文件误报 — 直接跳过并提示 */
    _snprintf(probe, sizeof probe - 1, "%s\\System32\\actxprxy.dll", wd);
    probe[sizeof probe - 1] = 0;
    if (!bj_is_signed(probe)) {
        xlog("windir: [跳过] catalog 验签自检未通过 (%s) — 本轮不做 windir 随机名扫描", probe);
        return;
    }
    wd_scan_dir(wd, 0);
}

/* 默认 hosts 内容 (Windows 出厂样式) */
static const char *DEFAULT_HOSTS =
    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
    "#\r\n"
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
    "# This file contains the mappings of IP addresses to host names. Each\r\n"
    "# entry should be kept on an individual line. The IP address should\r\n"
    "# be placed in the first column followed by the corresponding host name.\r\n"
    "# The IP address and the host name should be separated by at least one space.\r\n"
    "#\r\n"
    "# localhost name resolution is handled within DNS itself.\r\n"
    "#\t127.0.0.1       localhost\r\n"
    "#\t::1             localhost\r\n";

/* hosts 篡改检测: 任何非注释活动条目且非 localhost 映射即判定可疑 (银狐常用于封杀软更新域) */
static void scan_hosts(void)
{
    const char *hp = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    FILE *f = fopen(hp, "r");
    char line[1024];
    int suspicious = 0;
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        char *c = line;
        while (*c == ' ' || *c == '\t') c++;
        if (*c == 0 || *c == '\n' || *c == '\r' || *c == '#') continue;
        if (strncmp(c, "127.0.0.1", 9) != 0 && strncmp(c, "::1", 3) != 0) {
            suspicious = 1;
            break;
        }
    }
    fclose(f);
    if (suspicious) {
        addf("HOSTS", 1, "hosts 文件被篡改 (存在活动解析条目)", "重置为默认并隔离原件");
    }
}

/* Windows 更新服务篡改检测 (银狐尾巴; 单独恢复脚本由社区作者发布) */
static void scan_wu(void)
{
    static const char *wus[] = {"wuauserv", "UsoSvc", "uhssvc", "WaaSMedicSvc"};
    int i;
    for (i = 0; i < (int)(sizeof wus / sizeof wus[0]); i++) {
        HKEY sk;
        char path[128];
        DWORD start = 0, cb = sizeof start, typ = 0;
        char dep[512]; DWORD dcb = sizeof dep;
        _snprintf(path, sizeof path - 1, "SYSTEM\\CurrentControlSet\\Services\\%s", wus[i]);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &sk) != ERROR_SUCCESS) continue;
        RegQueryValueExA(sk, "Start", NULL, &typ, (BYTE *)&start, &cb);
        dep[0] = 0;
        RegQueryValueExA(sk, "DependOnService", NULL, &typ, (BYTE *)dep, &dcb);
        RegCloseKey(sk);
        if (start == 4) { /* 仅禁用(4)才报; 3=demand 是 Win11 默认手动启动, 误报 */
            char det[300], act[300];
            _snprintf(det, sizeof det - 1, "Windows 更新服务被禁用: %s (Start=%lu)", wus[i], (unsigned long)start);
            _snprintf(act, sizeof act - 1, "sc config %s start= auto", wus[i]);
            addf("WU", 1, det, act);
        }
        if (dep[0] && !strstr(dep, "RpcSs")) {
            char det[300], act[300];
            _snprintf(det, sizeof det - 1, "更新服务依赖被篡改: %s", wus[i]);
            _snprintf(act, sizeof act - 1, "sc config %s depend= RpcSs", wus[i]);
            addf("WU", 0, det, act);
        }
    }
}

static DWORD WINAPI scan_group(LPVOID p)
{
    switch ((int)(size_t)p) {
    case 0: scan_tasks(); scan_services(); break;
    case 1: scan_procs(); scan_ctfmon(); break;
    case 2: scan_files(); break;
    case 3: scan_bj(); break;
    case 4: scan_windir(); break;
    case 5: scan_wu(); scan_hosts(); break;
    }
    return 0;
}

static void scan_all(void)
{
    HANDLE th[6];
    int i;
    enable_privs();
    g_nf = 0;
    if (!g_fcs_init) { InitializeCriticalSection(&g_fcs); g_fcs_init = 1; }
    for (i = 0; i < 6; i++) {
        th[i] = CreateThread(NULL, 0, scan_group, (LPVOID)(size_t)i, 0, NULL);
        if (!th[i]) scan_group((LPVOID)(size_t)i); /* 建线程失败退化串行 */
    }
    for (i = 0; i < 6; i++) {
        if (!th[i]) continue;
        /* UI 线程等待期间继续泵消息: 界面不冻结, xlog 回显照常送达 */
        while (MsgWaitForMultipleObjects(1, &th[i], FALSE, INFINITE, QS_ALLINPUT)
               == WAIT_OBJECT_0 + 1) {
            MSG m;
            while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&m);
                DispatchMessageA(&m);
            }
        }
        CloseHandle(th[i]);
    }
}

/* ---- 清除 ---- */
static void kill_srl(void)
{
    int i;
    enum_processes();
    for (i = 0; i < g_np; i++) {
        HANDLE h;
        if (_stricmp(g_procs[i].name, "srl.exe")) continue;
        h = OpenProcess(PROCESS_TERMINATE, FALSE, g_procs[i].pid);
        if (h) { TerminateProcess(h, 1); CloseHandle(h); }
    }
}

static void do_clean(char *extra, size_t esz)
{
    char qdir[MAX_PATH];
    SYSTEMTIME st;
    unsigned long long ts;
    int i, ok = 0, fail = 0, has_mem = 0;
    extra[0] = 0;
    enable_privs();
    for (i = 0; i < g_nf; i++) if (!strcmp(g_f[i].kind, "PROC-MEM")) has_mem = 1;
    if (has_mem) {
        run_cmd("taskkill /f /im ctfmon.exe");
        strncat(extra, "[*] 已重启 ctfmon\n", esz - strlen(extra) - 1);
    }
    GetLocalTime(&st);
    ts = (unsigned long long)st.wYear * 10000000000ULL + st.wMonth * 100000000ULL
       + st.wDay * 1000000ULL + st.wHour * 10000ULL + st.wMinute * 100ULL + st.wSecond;
    _snprintf(qdir, sizeof qdir - 1, "%s\\%llu", QUAR_ROOT, ts);
    for (i = 0; i < g_nf; i++) {
        int s = 1;
        if (!strcmp(g_f[i].kind, "PROCESS")) kill_srl();
        else if (!strcmp(g_f[i].kind, "TASK")) {
            char t[700];
            strncpy(t, g_f[i].detail, sizeof t - 1); t[sizeof t - 1] = 0;
            s = run_cmd("schtasks /delete /tn \"%s\" /f", t);
        } else if (!strcmp(g_f[i].kind, "SERVICE")) {
            char n[300], *c;
            strncpy(n, g_f[i].detail, sizeof n - 1); n[sizeof n - 1] = 0;
            c = strstr(n, " [");
            if (c) *c = 0;
            run_cmd("sc stop \"%s\"", n);
            s = run_cmd("sc delete \"%s\"", n);
        } else if (!strcmp(g_f[i].kind, "FILE")) {
            char src[MAX_PATH], *c;
            strncpy(src, g_f[i].detail, sizeof src - 1); src[sizeof src - 1] = 0;
            c = strstr(src, " [");
            if (c) *c = 0;
            s = quarantine_one(src, qdir);
        } else if (!strcmp(g_f[i].kind, "WU")) {
            char svc[64];
            if (sscanf(g_f[i].detail, "Windows %*[^:]: %[^  ]", svc) < 1) strcpy(svc, g_f[i].detail);
            s = run_cmd("sc config %s start= auto", svc);
            run_cmd("sc config %s depend= RpcSs", svc);
            run_cmd("sc start %s", svc);
        } else if (!strcmp(g_f[i].kind, "HOSTS")) {
            const char *hp = "C:\\Windows\\System32\\drivers\\etc\\hosts";
            s = quarantine_one(hp, qdir);           /* 加密隔离原件 (失败也不阻塞) */
            {
                FILE *o = fopen(hp, "w");
                if (o) {
                    fwrite(DEFAULT_HOSTS, 1, strlen(DEFAULT_HOSTS), o);
                    fclose(o);
                    s = 1;
                } else s = 0;
            }
        }
        if (s) ok++; else fail++;
    }
    _snprintf(extra + strlen(extra), esz - strlen(extra) - 1, "完成: %d 成功, %d 失败", ok, fail);
}

/* ---- 隔离区还原/清空 ---- */
static void restore_all(char *report, size_t rsz)
{
    char root[] = QUAR_ROOT;
    char path[MAX_PATH];
    WIN32_FIND_DATAA fd, f2; HANDLE h, h2;
    int okc = 0, failc = 0;
    char desc[320];
    report[0] = 0;
    enable_privs();
    _snprintf(path, sizeof path - 1, "%s\\*", root);
    h = FindFirstFileA(path, &fd);
    if (h == INVALID_HANDLE_VALUE) { strncat(report, "隔离区为空", rsz - 1); return; }
    do {
        char batch[MAX_PATH];
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        _snprintf(batch, sizeof batch - 1, "%s\\%s", root, fd.cFileName);
        _snprintf(path, sizeof path - 1, "%s\\*.qenc", batch);
        h2 = FindFirstFileA(path, &f2);
        if (h2 == INVALID_HANDLE_VALUE) continue;
        do {
            char qp[MAX_PATH];
            _snprintf(qp, sizeof qp - 1, "%s\\%s", batch, f2.cFileName);
            if (unseal_restore(qp, _strtoui64(fd.cFileName, NULL, 10), desc)) {
                okc++;
                strncat(report, "[+] 已还原 ", rsz - strlen(report) - 1);
                strncat(report, desc, rsz - strlen(report) - 1);
            } else {
                failc++;
                strncat(report, "[-] 还原失败 ", rsz - strlen(report) - 1);
                strncat(report, qp, rsz - strlen(report) - 1);
            }
            strncat(report, "\n", rsz - strlen(report) - 1);
        } while (FindNextFileA(h2, &f2));
        FindClose(h2);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    _snprintf(path, sizeof path - 1, "\n还原: %d 成功, %d 失败", okc, failc);
    strncat(report, path, rsz - strlen(report) - 1);
}

static void quarantine_stats(int *count, unsigned long long *bytes)
{
    struct { char path[MAX_PATH]; int depth; } stk[256];
    int sp = 0;
    WIN32_FIND_DATAA fd; HANDLE h; char path[MAX_PATH];
    *count = 0; *bytes = 0;
    strcpy(stk[sp].path, QUAR_ROOT); stk[sp].depth = 0; sp++;
    while (sp > 0) {
        char dir[MAX_PATH];
        sp--;
        strcpy(dir, stk[sp].path);
        _snprintf(path, sizeof path - 1, "%s\\*", dir); path[sizeof path - 1] = 0;
        h = FindFirstFileA(path, &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            char full[MAX_PATH];
            if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
            _snprintf(full, sizeof full - 1, "%s\\%s", dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (sp < 250) { strcpy(stk[sp].path, full); stk[sp].depth = 0; sp++; }
            } else {
                (*count)++;
                *bytes += ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
}

static int wipe_dir_recursive(const char *dir)
{
    WIN32_FIND_DATAA fd; HANDLE h; char path[MAX_PATH];
    _snprintf(path, sizeof path - 1, "%s\\*", dir); path[sizeof path - 1] = 0;
    h = FindFirstFileA(path, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        char full[MAX_PATH];
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        _snprintf(full, sizeof full - 1, "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) wipe_dir_recursive(full);
        else DeleteFileA(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return RemoveDirectoryA(dir);
}

/* ---- 极端模式 ---- */
typedef int (WINAPI *fn_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef int (WINAPI *fn_NtRaiseHardError)(LONG, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

static int trigger_bsod(void) /* 返回 0 = 未能触发(调用方提示手动重启); 成功则永不返回 */
{
    fn_RtlAdjustPrivilege rap;
    fn_NtRaiseHardError nrhe;
    BOOLEAN old = FALSE;
    ULONG resp = 0;
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) nt = LoadLibraryA("ntdll.dll");
    if (!nt) ExitProcess(1);
    rap = (fn_RtlAdjustPrivilege)GetProcAddress(nt, "RtlAdjustPrivilege");
    nrhe = (fn_NtRaiseHardError)GetProcAddress(nt, "NtRaiseHardError");
    if (rap) rap(19, TRUE, FALSE, &old);
    if (nrhe) {
        if (nrhe(BUGCHECK_CODE, 0, 0, NULL, 6, &resp) == 0)
            for (;;) Sleep(3600000);            /* 已触发, 等死机 */
        if (nrhe(0xC0000420, 0, 0, NULL, 6, &resp) == 0)
            for (;;) Sleep(3600000);
    }
    return 0; /* 两次都没触发 (常见: SeShutdownPrivilege 未拿到) — 让调用方提示手动重启 */
}

static void marker_set(int v)
{
    HKEY rk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, MARK_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &rk, NULL)
        == ERROR_SUCCESS) {
        DWORD d = (DWORD)v;
        RegSetValueExA(rk, "ExtremePhase", 0, REG_DWORD, (const BYTE *)&d, sizeof d);
        RegCloseKey(rk);
    }
}

static int marker_get(void)
{
    HKEY rk; DWORD v = 0, t = 0, cb = sizeof v;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, MARK_KEY, 0, KEY_QUERY_VALUE, &rk) == ERROR_SUCCESS) {
        RegQueryValueExA(rk, "ExtremePhase", NULL, &t, (BYTE *)&v, &cb);
        RegCloseKey(rk);
    }
    return (int)v;
}

static void marker_del(void)
{
    HKEY rk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, MARK_KEY, 0, KEY_SET_VALUE, &rk) == ERROR_SUCCESS) {
        RegDeleteValueA(rk, "ExtremePhase");
        RegCloseKey(rk);
    }
}

static void autorun_set(void)
{
    char data[MAX_PATH + 64], exe[MAX_PATH], shortp[MAX_PATH];
    HKEY rk;
    GetModuleFileNameA(NULL, exe, sizeof exe);
    /* 优先 8.3 短路径写 Run/RunOnce: 短路径无括号/空格/非ASCII,
       winlogon 各解析阶段不会再有歧义; 拿不到 (系统禁 8.3) 才回退引号长路径 */
    if (GetShortPathNameA(exe, shortp, sizeof shortp))
        _snprintf(data, sizeof data - 1, "%s --extreme", shortp);
    else
        _snprintf(data, sizeof data - 1, "\"%s\" --extreme", exe);
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, RUN_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &rk, NULL)
        == ERROR_SUCCESS) {
        RegSetValueExA(rk, "SFCleaner", 0, REG_SZ, (const BYTE *)data, (DWORD)strlen(data) + 1);
        RegSetValueExA(rk, "*SFCleaner", 0, REG_SZ, (const BYTE *)data, (DWORD)strlen(data) + 1);
        RegCloseKey(rk);
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, RUNONCE_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &rk, NULL)
        == ERROR_SUCCESS) {
        RegSetValueExA(rk, "*SFCleaner", 0, REG_SZ, (const BYTE *)data, (DWORD)strlen(data) + 1);
        RegCloseKey(rk);
    }
}

static void autorun_del(void)
{
    HKEY rk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, RUN_KEY, 0, KEY_SET_VALUE, &rk) == ERROR_SUCCESS) {
        RegDeleteValueA(rk, "SFCleaner");
        RegDeleteValueA(rk, "*SFCleaner");
        RegCloseKey(rk);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, RUNONCE_KEY, 0, KEY_SET_VALUE, &rk) == ERROR_SUCCESS) {
        RegDeleteValueA(rk, "SFCleaner");
        RegDeleteValueA(rk, "*SFCleaner");
        RegCloseKey(rk);
    }
}

/* bcdedit 必须经 64 位路径调用: 32 位进程里 PATH 解析会被重定向到 SysWOW64,
   那里没有 bcdedit.exe → 命令静默失败 (x86 版曾因此 testsigning 从未生效).
   Sysnative 别名仅 32 位进程可见, 恰好只在 x86 构建里需要 */
static int run_bcdedit(const char *fmt, ...)
{
    char args[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(args, sizeof args - 1, fmt, ap);
    va_end(ap);
    args[sizeof args - 1] = 0;
#ifdef _WIN64
    return run_cmd("bcdedit %s", args);
#else
    return run_cmd("%WINDIR%\\Sysnative\\bcdedit.exe %s", args);
#endif
}

/* 不客气 phase2 自启动: RunOnce 一次性 (普通登录 + 安全模式两种值), 短路径消歧义 */
static void nomore_autorun_set(void)
{
    char data[MAX_PATH + 64], exe[MAX_PATH], shortp[MAX_PATH];
    HKEY rk;
    GetModuleFileNameA(NULL, exe, sizeof exe);
    if (GetShortPathNameA(exe, shortp, sizeof shortp))
        _snprintf(data, sizeof data - 1, "%s --nomore2", shortp);
    else
        _snprintf(data, sizeof data - 1, "\"%s\" --nomore2", exe);
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, RUNONCE_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &rk, NULL)
        == ERROR_SUCCESS) {
        RegSetValueExA(rk, "SFCleaner", 0, REG_SZ, (const BYTE *)data, (DWORD)strlen(data) + 1);
        RegSetValueExA(rk, "*SFCleaner", 0, REG_SZ, (const BYTE *)data, (DWORD)strlen(data) + 1);
        RegCloseKey(rk);
    }
}

static void safeboot_set(void)
{
    xlog("safeboot: set minimal");
    run_bcdedit("/set {current} safeboot minimal");
}

static void safeboot_clear(void)
{
    xlog("safeboot: clear");
    run_bcdedit("/deletevalue {current} safeboot");
}

static void schedule_self_delete(void)
{
    char exe[MAX_PATH], old[MAX_PATH];
    GetModuleFileNameA(NULL, exe, sizeof exe);
    _snprintf(old, sizeof old - 1, "%s.sfld", exe);
    MoveFileA(exe, old);
    MoveFileExA(old, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}

static void extreme_run(void)
{
    char msg[128];
    enable_privs();
    if (marker_get() == 2) {
        xlog("phase2: boot cleanup (safe mode)");
        scan_all();
        do_clean(msg, sizeof msg);
        xlog("phase2: %s", msg);
        safeboot_clear();
        autorun_del();
        marker_del();
        schedule_self_delete();
        xlog("phase2: self-destruct scheduled, bsod now");
        trigger_bsod();
    } else {
        xlog("phase1: arming extreme mode");
        autorun_set();
        marker_set(2);
        safeboot_set();
        scan_all();
        do_clean(msg, sizeof msg);
        xlog("phase1: %s, bsod now", msg);
        trigger_bsod();
    }
}

static void msgbox(const char *text);
static void fmt_report(char *out, size_t rsz);
/* ---- 不客气模式: 自定义证书 + 内核驱动清理 ----
 * 材料: 与程序同目录放 SFCleanerDrv.sys(测试签名内核驱动) + SFCleanerCert.pfx(自定义证书)
 * 流程: phase1(标记=3): testsigning on + 导入证书 + 部署/注册 driver → 蓝屏重启
 *       phase2: 启动 driver 清理 → 卸载 → 删证书 → testsigning 恢复 → 提示重启 */
#define DRV_SVC   "SFCleanerDrv"
#define CERT_CN   "SFCleaner Test"

static int secureboot_on(void)
{
    HKEY k; DWORD v = 0, sz = sizeof v, t = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                      0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return 0;
    LONG r = RegQueryValueExA(k, "UEFISecureBootEnabled", NULL, &t, (BYTE *)&v, &sz);
    RegCloseKey(k);
    return r == ERROR_SUCCESS && t == REG_DWORD && v == 1;
}

static void nomore_material_paths(char *drv, char *pfx, char *cer, size_t n)
{
    char exe[MAX_PATH], *s;
    GetModuleFileNameA(NULL, exe, sizeof exe);
    s = strrchr(exe, '\\');
    if (s) *s = 0;
    _snprintf(drv, n - 1, "%s\\SFCleanerDrv.sys", exe);       drv[n - 1] = 0;
    _snprintf(pfx, n - 1, "%s\\SFCleanerCert.pfx", exe);      pfx[n - 1] = 0;
    _snprintf(cer, n - 1, "%s\\SFCleanerCert.cer", exe);      cer[n - 1] = 0;
}

static int nomore_phase1(void)
{
    char drv[MAX_PATH], pfx[MAX_PATH], cer[MAX_PATH], dst[MAX_PATH];
    int hp, hc;

    nomore_material_paths(drv, pfx, cer, MAX_PATH);
#if HAVE_EMBED
    {
        /* 材料必须先落盘再导入: 否则全新机器首跑时证书没机会进存储, 驱动必然加载失败 */
        FILE *o = fopen(drv, "wb");
        if (o) { fwrite(sfc_drv, 1, sfc_drv_len, o); fclose(o); xlog("nomore: 内嵌驱动已释放"); }
        if (GetFileAttributesA(pfx) == INVALID_FILE_ATTRIBUTES
            && GetFileAttributesA(cer) == INVALID_FILE_ATTRIBUTES) {
            FILE *c = fopen(cer, "wb");   /* cer 内容写 cer 名, 不再伪装成 pfx */
            if (c) { fwrite(sfc_cer, 1, sfc_cer_len, c); fclose(c); xlog("nomore: 内嵌证书已释放 (cer)"); }
        }
    }
#endif
    if (GetFileAttributesA(drv) == INVALID_FILE_ATTRIBUTES) {
        xlog("nomore: [中止] 缺 SFCleanerDrv.sys (%s)", drv);
        return 0;
    }
    hp = GetFileAttributesA(pfx) != INVALID_FILE_ATTRIBUTES;
    hc = GetFileAttributesA(cer) != INVALID_FILE_ATTRIBUTES;
    if (!hp && !hc) {
        xlog("nomore: [中止] 缺证书材料 (%s 或 %s)", pfx, cer);
        return 0;
    }

    if (secureboot_on()) {
        xlog("nomore: [中止] Secure Boot 开启 — testsigning 会被安全启动策略拒绝");
        xlog("nomore: VMware: 虚拟机设置->选项->高级->固件类型UEFI, 取消勾选'启用安全引导'后重启 VM");
        return 0;
    }
    xlog("nomore: testsigning on");
    if (!run_bcdedit("/set testsigning on")) {
        xlog("nomore: [中止] bcdedit testsigning 失败 — 固件 Secure Boot 开着会被拒, 请在 VM 设置里关掉 Secure Boot 再试");
        return 0;
    }

    xlog("nomore: import cert (%s)", hp ? "pfx" : "cer");
    if (hp) {
        int r1 = run_cmd("certutil -f -p sf-cleaner -importpfx \"%s\" ROOT", pfx);
        int r2 = run_cmd("certutil -f -p sf-cleaner -importpfx \"%s\" TrustedPublisher", pfx);
        if (!r1 && !r2) { xlog("nomore: [中止] pfx 导入失败 (密码 sf-cleaner)"); return 0; }
    } else {
        int r1 = run_cmd("certutil -addstore -f ROOT \"%s\"", cer);
        int r2 = run_cmd("certutil -addstore -f TrustedPublisher \"%s\"", cer);
        if (!r1 && !r2) { xlog("nomore: [中止] cer 导入失败"); return 0; }
    }

    _snprintf(dst, sizeof dst - 1, "C:\\Windows\\System32\\drivers\\%s.sys", DRV_SVC);
    DeleteFileA(dst);
    take_own(dst);
    if (!CopyFileA(drv, dst, FALSE)) {
        xlog("nomore: [中止] 部署 driver 失败 -> %s", dst);
        return 0;
    }
    run_cmd("sc stop %s", DRV_SVC);
    run_cmd("sc delete %s", DRV_SVC);
    xlog("nomore: register service (SYSTEM_START — 重启后早于恶意软件加载)");
    if (!run_cmd("sc create %s binPath= System32\\drivers\\%s.sys type= kernel start= system", DRV_SVC, DRV_SVC)) {
        xlog("nomore: [中止] sc create 失败");
        return 0;
    }
    return 1;
}

/* 把本次扫描的全部 FILE 发现喂给驱动: DrvPaths (REG_MULTI_SZ) —
   驱动 SYSTEM_START 自启后每轮清杀照单执行 (无头自动版的本机目标清单) */
static void nomore_phase2(void)
{
    char dst[MAX_PATH];
    autorun_del(); /* 先清 RunOnce, 防完成后残留条目把 phase1 再拉起来 */
    xlog("nomore: phase2 - 先解除 testsigning (已装载的驱动不受影响, 防后续异常残留)");
    run_bcdedit("/set testsigning off");
    xlog("nomore: phase2 — 驱动应已随系统启动自载 (SYSTEM_START) 并完成多轮清扫");
    if (!run_cmd("sc query %s | find \"RUNNING\"", DRV_SVC))
        xlog("nomore: [警告] 驱动未在运行 — 检查 testsigning 是否在重启后生效 / Secure Boot");
    Sleep(2000); /* 让当前轮次扫完 */
    run_cmd("sc stop %s", DRV_SVC);
    run_cmd("sc delete %s", DRV_SVC);
    _snprintf(dst, sizeof dst - 1, "C:\\Windows\\System32\\drivers\\%s.sys", DRV_SVC);
    DeleteFileA(dst);
    xlog("nomore: remove cert");
    run_cmd("certutil -delstore ROOT \"%s\"", CERT_CN);
    run_cmd("certutil -delstore TrustedPublisher \"%s\"", CERT_CN);
    marker_del();
    msgbox("不客气模式完成\\n\\n"
           "驱动已装载→清理→卸载, 证书已移除\\n"
           "testsigning 已关闭(重启后生效) — 请重启");
}

static void nomore_run(void)
{
    enable_privs();
    if (marker_get() == 3) {
        nomore_phase2();
    } else {
        char msg[128];
        xlog("nomore: 先扫描留档 — 驱动为纯内建检测, 不依赖注册表喂单");
        scan_all();
        fmt_report(msg, sizeof msg);
        xlog(msg);
        if (!nomore_phase1()) {
            msgbox("不客气模式未启动\\n详见界面日志 — 常见: Secure Boot 开启 / 缺 SFCleanerDrv.sys / 证书导入失败");
            return;
        }
        marker_set(3);
        nomore_autorun_set();
        xlog("nomore: phase1 done, bsod (testsigning 生效需重启; 重启后 RunOnce 自动进 phase2)");
        if (!trigger_bsod())
            msgbox("蓝屏触发失败\n请手动重启 — testsigning 需重启后生效;\n重启登录后将自动进入 phase2 (RunOnce);\n若未自动弹出也可手动再运行一次本程序");
    }
}

/* ---- GUI ---- */
static HWND g_btn[7];
#define GUI_BG 0x141218
#define GUI_FG 0xE6E0E9
#define GUI_MUT 0x938F99
#define GUI_ACC 0xFFB4AB

static void gui_append(const char *s)
{
    LONG n = GetWindowTextLengthA(g_edit);
    SendMessageA(g_edit, EM_SETSEL, n, n);
    SendMessageA(g_edit, EM_REPLACESEL, FALSE, (LPARAM)s);
}

static void fmt_report(char *out, size_t rsz)
{
    int i, hi = 0;
    char line[1200];
    if (g_nf == 0) { _snprintf(out, rsz - 1, "[OK] 未发现银狐痕迹\n"); return; }
    out[0] = 0;
    for (i = 0; i < g_nf; i++) {
        if (g_f[i].high) hi++;
        _snprintf(line, sizeof line - 1, "[%-8s] %s\n           -> %s\n",
                  g_f[i].kind, g_f[i].detail, g_f[i].action);
        strncat(out, line, rsz - strlen(out) - 1);
    }
    _snprintf(line, sizeof line - 1, "\n共 %d 项 (高置信 %d, 结构 %d)\n", g_nf, hi, g_nf - hi);
    strncat(out, line, rsz - strlen(out) - 1);
}

static void msgbox(const char *text)
{
    MessageBoxA(NULL, text, "SilverFox Cleaner C", MB_OK);
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT m, WPARAM wp, LPARAM lp)
{
    char buf[16384];
    switch (m) {
    case WM_DESTROY: PostQuitMessage(0); return 0;
    case WM_COMMAND:
        if (HIWORD(wp)) break; /* 仅接受 BN_CLICKED: EDIT 控件(同ID 7)的 EN_UPDATE/EN_CHANGE
                                  通知也走 WM_COMMAND, 不拦会导致启动即弹不客气确认 */
        switch (LOWORD(wp)) {
        case 1:
            gui_append("[..] 扫描中...\n");
            scan_all();
            fmt_report(buf, sizeof buf);
            gui_append(buf);
            gui_append("[提示] 点击 [清除] 处理以上项\n\n");
            EnableWindow(g_btn[1], g_nf > 0);
            return 0;
        case 2:
            if (MessageBoxA(hwnd, "确认清除所有检出项?\n文件将加密移入隔离区。",
                            "SilverFox Cleaner C", MB_OKCANCEL | MB_ICONWARNING) == IDOK) {
                char extra[256];
                gui_append("[..] 清除中...\n");
                do_clean(extra, sizeof extra);
                gui_append("[*] ");
                gui_append(extra);
                gui_append("\n建议重启确认无复活\n\n");
            }
            return 0;
        case 3:
            msgbox("SilverFox Cleaner C (x86/x64, NT6+)\n\n"
                   "检测: 持久化/落盘/互斥/SrL/ctfmon注入\n"
                   "隔离: SFQENC1 时间戳加密 (三版互通)\n"
                   "极端: --extreme 蓝屏(安全模式清场)x2 + 自毁\n"
                   "解除: --extreme-abort");
            return 0;
        case 4:
            restore_all(buf, sizeof buf);
            gui_append("[..] 隔离区还原:\n");
            gui_append(buf);
            gui_append("\n\n");
            return 0;
        case 5: {
            int n; unsigned long long b;
            quarantine_stats(&n, &b);
            if (!n) { gui_append("隔离区已为空\n\n"); return 0; }
            _snprintf(buf, sizeof buf - 1, "删除隔离区全部 %d 个文件 (共 %.1f MB)?\n不可恢复!", n, b / 1048576.0);
            if (MessageBoxA(hwnd, buf, "清空隔离区", MB_OKCANCEL | MB_ICONWARNING) == IDOK) {
                enable_privs();
                gui_append(wipe_dir_recursive(QUAR_ROOT) ? "[*] 已清空隔离区\n\n" : "[!] 清空失败\n\n");
            }
            return 0;
        }
        case 7:
            if (MessageBoxA(hwnd, "不客气模式确认\n\n"
                            "导入自定义证书 + 装载内核驱动清理\n"
                            "testsigning ON → 蓝屏重启 → 驱动清理\n"
                            "→ 卸载 → 删证书 → testsigning OFF\n\n"
                            "材料: SFCleanerDrv.sys + SFCleanerCert.pfx 与程序同目录",
                            "SilverFox Cleaner 不客气模式", MB_OKCANCEL | MB_ICONWARNING) == IDOK) {
                gui_append("[!!] 不客气模式启动\n");
                nomore_run();
            }
            return 0;
        case 8:
            break;
        case 6:
            if (MessageBoxA(hwnd, "极端模式确认\n\n"
                            "序列: 自启动+标记 -> 安全模式启动 -> 清除 -> 蓝屏\n"
                            "重启(安全模式): 再清除 -> 解除safeboot -> 自毁 -> 蓝屏\n\n"
                            "共两次蓝屏! 请保存所有工作!",
                            "SilverFox Cleaner 极端模式", MB_OKCANCEL | MB_ICONWARNING) == IDOK) {
                gui_append("[!!] 极端模式启动\n");
                extreme_run();
            }
            return 0;
        }
        break;
    }
    return DefWindowProcA(hwnd, m, wp, lp);
}

static void run_gui(void)
{
    WNDCLASSA wc; HWND hwnd; HFONT font;
    static const char *btns[7] = {"扫描", "清除", "关于", "还原隔离区", "清空隔离区", "极端", "不客气"};
    static const int bx[7] = {14, 144, 274, 364, 504, 624, 744};
    static const int bw[7] = {120, 120, 80, 130, 150, 110, 130};
    g_btn[5] = NULL; g_btn[6] = NULL;
    int i;
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = CreateSolidBrush(RGB(20, 18, 24));
    wc.lpszClassName = "SFC5";
    RegisterClassA(&wc);
    hwnd = CreateWindowExA(0, "SFC5", "SilverFox Cleaner C - NT6+ (x86/x64)",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE, 200, 200, 920, 640,
                           NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) return;
    font = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                       0, 0, CLEARTYPE_QUALITY, 0, "Microsoft YaHei UI");
    if (!font) font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    for (i = 0; i < 7; i++) {
        g_btn[i] = CreateWindowExA(0, "BUTTON", btns[i], WS_CHILD | WS_VISIBLE,
                                   bx[i], 12, bw[i], 38, hwnd, (HMENU)(size_t)(i + 1),
                                   wc.hInstance, NULL);
        SendMessageA(g_btn[i], WM_SETFONT, (WPARAM)font, TRUE);
    }
    g_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                             WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL
                             | ES_AUTOVSCROLL | ES_WANTRETURN,
                             14, 58, 876, 490, hwnd, (HMENU)7, wc.hInstance, NULL);
    SendMessageA(g_edit, WM_SETFONT, (WPARAM)font, TRUE);
    gui_append("SilverFox Cleaner C (NT6+, 重写版) - dmo/client\n"
               "build: " __DATE__ " " __TIME__ "\n"
               "检测: 持久化 / 落盘物 / 互斥 / SrL / ctfmon内存注入\n"
               "隔离: 时间戳加密 SFQENC1 (三版互通)\n"
               "极端: 安全模式两阶段蓝屏清除 (0xC0114514)\n\n");
    {
        /* 启动即自检 catalog 验签: 界面直接给出状态, 误报问题一眼定位 */
        char probe[MAX_PATH];
        _snprintf(probe, sizeof probe - 1, "C:\\Windows\\System32\\actxprxy.dll");
        gui_append(bj_is_signed(probe)
                   ? "[OK] catalog 验签自检通过 (系统文件签名识别正常)\n\n"
                   : "[!] catalog 验签自检失败 — windir 随机名扫描将跳过\n\n");
    }
    {
        MSG msg;
        while (GetMessageA(&msg, NULL, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
}

/* ---- WinMain (自带入口在 xp_crt_shim.c) ---- */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)nShow;
    if (cmd && cmd[0]) {
        char c2[64]; int i;
        char *c = cmd;
        while (*c == ' ') c++;
        for (i = 0; i < 63 && c[i] && c[i] != ' ' && c[i] != '\t'; i++) c2[i] = c[i];
        c2[i] = 0;
        if (!strcmp(c2, "scan")) {
            char rep[65536];
            scan_all();
            fmt_report(rep, sizeof rep);
            msgbox(rep);
        } else if (!strcmp(c2, "clean")) {
            char rep[65536], extra[256];
            scan_all();
            if (g_nf) { do_clean(extra, sizeof extra); _snprintf(rep, sizeof rep - 1, "%s\n建议重启确认无复活", extra); }
            else strcpy(rep, "[OK] 未发现银狐痕迹");
            msgbox(rep);
        } else if (!strcmp(c2, "restore")) {
            char rep[65536];
            restore_all(rep, sizeof rep);
            msgbox(rep);
        } else if (!strcmp(c2, "--extreme")) {
            extreme_run();
        } else if (!strcmp(c2, "--nomore")) {
            nomore_run();
        } else if (!strcmp(c2, "--nomore2")) {
            /* RunOnce 自动链专用: 只允许执行 phase2, marker 不在绝不重演 phase1 */
            enable_privs();
            if (marker_get() == 3) nomore_phase2();
        } else if (!strcmp(c2, "--extreme-abort")) {
            enable_privs();
            safeboot_clear();
            autorun_del();
            marker_del();
            msgbox("极端模式已解除 (自启动+标记+safeboot 已清除)");
        } else if (!strcmp(c2, "--wipe-quarantine")) {
            int n; unsigned long long b; char m[160];
            quarantine_stats(&n, &b);
            enable_privs();
            if (wipe_dir_recursive(QUAR_ROOT))
                _snprintf(m, sizeof m - 1, "已清空隔离区: %d 个文件 (%.1f MB)", n, b / 1048576.0);
            else strcpy(m, "清空失败");
            msgbox(m);
        } else {
            msgbox("用法: SFCleaner [scan|clean|restore|--extreme|--extreme-abort|--wipe-quarantine]");
        }
        return 0;
    }
    run_gui();
    return 0;
}