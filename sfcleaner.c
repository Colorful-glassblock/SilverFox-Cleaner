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
static const char *NAME_HITS[] = {"ekxzjr", "dd9ocged", "srl.exe", "wdybq.dll",
    "drivers.dat", "drivers.dat.0",
    "wow64log.dll", "vafdska.sys", "vmservice.sys",  /* 旧版变种驱动/劫持 DLL (社区工具 IOC) */
    "1.bat", "fhq.bat", "z_1.bat"};
static const char *DIR_HITS[] = {"diamondage", "roning", "minifilterdrv"};
static const char *SVC_PATS[][2] = {{"EkxZJr", "1"}, {"SrL.exe", "1"}, {"cd /d", "0"}};

typedef struct { char kind[12]; char detail[700]; int high; char action[400]; } Finding;
static Finding g_f[MAXF];
static int g_nf;

/* ---- 小工具 ---- */
static void addf(const char *kind, int high, const char *detail, const char *action)
{
    if (g_nf >= MAXF) return;
    Finding *f = &g_f[g_nf++];
    memset(f, 0, sizeof *f);
    strncpy(f->kind, kind, sizeof f->kind - 1);
    strncpy(f->detail, detail, sizeof f->detail - 1);
    strncpy(f->action, action, sizeof f->action - 1);
    f->high = high;
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
                    if (!(fl >= 4 && !strcmp(lfnm + fl - 4, ".png"))) strcat(md, " [PNG伪装]");
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
    for (r = 0; r < 4; r++) {
        char *v = getenv(envs[r]);
        if (v && *v && nroots < 8) strncpy(roots[nroots++], v, MAX_PATH - 1);
    }
    for (r = 0; r < nroots; r++) {
        walk_paths(roots[r], 0, file_cb, NULL);
    }
}

/* ---- 白加黑检测: 同目录 [有效签名EXE + 未签名DLL] (跨变种结构特征) ---- */
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
    return res == 0;
}

static void bj_scan_dir(const char *dir, int depth)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pat[MAX_PATH], full[MAX_PATH];
    int se = 0, ud = 0;
    int has_dll = 0;
    static char hitbuf[MAX_PATH];
    static const char *wls[5] = {"\\programs\\", "\\package cache\\", "\\windowsapps\\", "\\microsoft\\", "\\windows\\"};
    int w;
    if (depth > 4) return;
    {
        static char lowq[1024]; /* 先 lower 再判, 隔离区目录本身要跳过 */
        unsigned int m = (unsigned int)(strlen(dir) < sizeof lowq - 1 ? strlen(dir) : sizeof lowq - 2);
        memcpy(lowq, dir, m); lowq[m] = 0;
        str_lower(lowq);
        if (strstr(lowq, "sf_quarantine")) return;
        for (w = 0; w < 5; w++)   /* 正规软件目录白名单: 显著降低 QQ/微信等未签名DLL误报 */
            if (strstr(lowq, wls[w])) return;
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
            if (!se && bj_is_signed(full)) se = 1;   /* 找到即停, 避免大目录重复验签 */
        } else if (fl > 4 && !_stricmp(low + fl - 4, ".dll")) {
            if (!ud && !bj_is_signed(full)) {
                strncpy(hitbuf, full, sizeof hitbuf - 1);
                hitbuf[sizeof hitbuf - 1] = 0;
                has_dll = 1;
                ud = 1;
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (se && ud && has_dll) {
        char det[MAX_PATH + 64], act[MAX_PATH + 16];
        _snprintf(det, sizeof det - 1, "%s [白加黑: 有效签名EXE+未签名DLL]", hitbuf);
        _snprintf(act, sizeof act - 1, "quarantine %s", hitbuf);
        addf("FILE", 0, det, act);
    }
}

static void scan_bj(void)
{
    char roots[8][MAX_PATH]; int nroots = 0, r;
    static const char *envs[] = {"TEMP", "APPDATA", "LOCALAPPDATA", "ProgramData"};
    strcpy(roots[nroots++], "C:\\Drivers");
    for (r = 0; r < 4; r++) {
        char *v = getenv(envs[r]);
        if (v && *v && nroots < 8) strncpy(roots[nroots++], v, MAX_PATH - 1);
    }
    for (r = 0; r < nroots; r++) bj_scan_dir(roots[r], 0);
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
        if (start != 2) {
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

static void scan_all(void)
{
    enable_privs();
    g_nf = 0;
    scan_tasks();
    scan_services();
    scan_procs();
    scan_ctfmon();
    scan_files();
    scan_wu();
    scan_hosts();
    scan_bj();
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

static void trigger_bsod(void)
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
        nrhe(BUGCHECK_CODE, 0, 0, NULL, 6, &resp);
        nrhe(0xC0000420, 0, 0, NULL, 6, &resp); /* 兜底 */
    }
    for (;;) Sleep(3600000);
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
    char data[MAX_PATH + 32], exe[MAX_PATH];
    HKEY rk;
    GetModuleFileNameA(NULL, exe, sizeof exe);
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
        RegDeleteValueA(rk, "*SFCleaner");
        RegCloseKey(rk);
    }
}

static void safeboot_set(void)
{
    xlog("safeboot: set minimal");
    run_cmd("bcdedit /set {current} safeboot minimal");
}

static void safeboot_clear(void)
{
    xlog("safeboot: clear");
    run_cmd("bcdedit /deletevalue {current} safeboot");
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

/* ---- 不客气模式: 自定义证书 + 内核驱动清理 ----
 * 材料: 与程序同目录放 SFCleanerDrv.sys(测试签名内核驱动) + SFCleanerCert.pfx(自定义证书)
 * 流程: phase1(标记=3): testsigning on + 导入证书 + 部署/注册 driver → 蓝屏重启
 *       phase2: 启动 driver 清理 → 卸载 → 删证书 → testsigning 恢复 → 提示重启 */
#define DRV_SVC   "SFCleanerDrv"
#define CERT_CN   "SFCleaner Test"

static void nomore_deploy_paths(char *drv, char *pfx, size_t n)
{
    char exe[MAX_PATH], cer[MAX_PATH];
    char *s;
    GetModuleFileNameA(NULL, exe, sizeof exe);
    s = strrchr(exe, '\\');
    if (s) *s = 0;
    _snprintf(drv, n, "%s\\SFCleanerDrv.sys", exe);
    _snprintf(pfx, n, "%s\\SFCleanerCert.pfx", exe);
    _snprintf(cer, n, "%s\\SFCleanerCert.cer", exe);
    if (GetFileAttributesA(pfx) != INVALID_FILE_ATTRIBUTES) {
        run_cmd("certutil -f -p sf-cleaner -importpfx \"%s\" ROOT", pfx);
        run_cmd("certutil -f -p sf-cleaner -importpfx \"%s\" TrustedPublisher", pfx);
    } else if (GetFileAttributesA(cer) == INVALID_FILE_ATTRIBUTES) {
        /* 无可用证书材料, 交由 phase1 校验失败提示 */
    } else {
        run_cmd("certutil -addstore -f ROOT \"%s\"", cer);
        run_cmd("certutil -addstore -f TrustedPublisher \"%s\"", cer);
    }
}

static int nomore_phase1(void)
{
    char drv[MAX_PATH], pfx[MAX_PATH], dst[MAX_PATH];
    nomore_deploy_paths(drv, pfx, sizeof drv);
#if HAVE_EMBED
    {
        /* 全部内嵌: 无条件释放驱动与证书到程序目录 */
        FILE *o = fopen(drv, "wb");
        if (o) { fwrite(sfc_drv, 1, sfc_drv_len, o); fclose(o); xlog("nomore: 内嵌驱动已释放"); }
        if (GetFileAttributesA(pfx) == INVALID_FILE_ATTRIBUTES) {
            FILE *c = fopen(pfx, "wb");
            if (c) { fwrite(sfc_cer, 1, sfc_cer_len, c); fclose(c); xlog("nomore: 内嵌证书已释放"); }
        }
    }
#endif
    if (GetFileAttributesA(drv) == INVALID_FILE_ATTRIBUTES) {
        xlog("nomore: 缺 SFCleanerDrv.sys (%s)", drv);
        return 0;
    }
    if (GetFileAttributesA(pfx) == INVALID_FILE_ATTRIBUTES) {
        xlog("nomore: 缺 SFCleanerCert.pfx (%s)", pfx);
        return 0;
    }
    xlog("nomore: testsigning on");
    run_cmd("bcdedit /set testsigning on");
    xlog("nomore: import cert (pfx 优先, cer 回退)");
    _snprintf(dst, sizeof dst - 1, "C:\\Windows\\System32\\drivers\\%s.sys", DRV_SVC);
    DeleteFileA(dst);
    take_own(dst);
    if (!CopyFileA(drv, dst, FALSE)) {
        xlog("nomore: 部署 driver 失败");
        return 0;
    }
    run_cmd("sc stop %s", DRV_SVC);
    run_cmd("sc delete %s", DRV_SVC);
    xlog("nomore: register service");
    run_cmd("sc create %s binPath= System32\\drivers\\%s.sys type= kernel start= demand", DRV_SVC, DRV_SVC);
    return 1;
}

static void nomore_phase2(void)
{
    char dst[MAX_PATH];
    xlog("nomore: phase2 - 先解除 testsigning (已装载的驱动不受影响, 防后续异常残留)");
    run_cmd("bcdedit /set testsigning off");
    xlog("nomore: phase2 start driver");
    run_cmd("sc start %s", DRV_SVC);
    Sleep(10000); /* 给内核清理留时间窗 */
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
        if (!nomore_phase1()) {
            msgbox("不客气模式缺材料\\n请将 SFCleanerDrv.sys 与 SFCleanerCert.pfx 与程序同目录放置");
            return;
        }
        marker_set(3);
        xlog("nomore: phase1 done, bsod (testsigning 生效需重启)");
        trigger_bsod();
    }
}

/* ---- GUI ---- */
static HWND g_edit, g_btn[6];
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
        if (HIWORD(wp)) break; /* 仅接受 BN_CLICKED: EDIT 控件(HMENU 7 与不客气按钮同ID)的 EN_UPDATE/EN_CHANGE
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
               "检测: 持久化 / 落盘物 / 互斥 / SrL / ctfmon内存注入\n"
               "隔离: 时间戳加密 SFQENC1 (三版互通)\n"
               "极端: 安全模式两阶段蓝屏清除 (0xC0114514)\n\n");
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