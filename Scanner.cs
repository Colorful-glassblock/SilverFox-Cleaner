// SilverFox Cleaner 检测/清除引擎 — 自 Rust v4 (silverfox-cleaner/src/main.rs) 移植
// 常量与判定逻辑保持一致：互斥体 Global\P_<倒序PID>、C2 IOC、文件名特征、STEGR1Xp/JELG 魔数
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace SFCleaner;

public sealed class Finding
{
    public required string Kind { get; init; }
    public required string Detail { get; init; }
    public bool High { get; init; }
    public required string Action { get; init; }

    public string Head => $"{(High ? "🔴" : "🟡")} [{Kind}]  {Detail}";
}

public sealed record CleanStats(int Ok, int Fail);

internal static partial class Native
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr OpenMutexW(uint desiredAccess, bool inheritHandle, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool ReadProcessMemory(IntPtr h, IntPtr baseAddr, byte[] buffer,
        nint size, out nint read);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr,
        out MEMORY_BASIC_INFORMATION mbi, nint len);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool LookupPrivilegeValueW(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint len, IntPtr prev, IntPtr retLen);

    // x64 下顺序布局自动补齐到 48 字节（BaseAddress@0 / RegionSize@24 / State@32 / Protect@36）
    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool MoveFileExW(string src, IntPtr dst, uint flags);

    [DllImport("ntdll.dll")]
    internal static extern int RtlAdjustPrivilege(uint privilege, bool enable, bool currentThread, out byte previous);

    [DllImport("ntdll.dll")]
    internal static extern int NtRaiseHardError(uint status, uint paramCount, uint unicodeMask,
        IntPtr parameters, uint validResponseOption, out uint response);

    // 白加黑检测: Authenticode 验签 (wintrust)
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    internal static extern int WinVerifyTrust(IntPtr hwnd, ref Guid actionId, ref WINTRUST_DATA data);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetShortPathName(string lpszLongPath, StringBuilder lpszShortPath, uint cchBuffer);

    // catalog 验签: 系统 PE 无内嵌签名, 由 catalog 数据库覆盖
    [DllImport("wintrust.dll")]
    internal static extern bool CryptCATAdminAcquireContext(out IntPtr hCatAdmin, ref Guid pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    internal static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

    [DllImport("wintrust.dll")]
    internal static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    internal static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll")]
    internal static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll")]
    internal static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public string pcwszCatalogFilePath;
        public string pcwszMemberTag;
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string? pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    internal static readonly Guid WinTrustActionGenericVerifyV2 =
        new Guid(0x00AAC56B, 0xCD44, 0x11D0, 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE);
}

// 加密隔离容器（与 Rust v4.1 字节级兼容）
// 头部: SFQENC1\0 | u64 明文长度 | u32 原路径UTF16字符数 | 原路径 | 密文体（xorshift64* 时间戳密钥流）
internal static class QuarCrypt
{
    public static readonly byte[] Magic = "SFQENC1\0"u8.ToArray();
    private const ulong SeedSalt = 0xA55A5AA50F0F0F0F;

    public static ulong TsFromDirName(string name) =>
        ulong.TryParse(name, out var t) ? t : 0;

    private static ulong Step(ref ulong x)
    {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        return x * 0x2545F4914F6CDD1DUL;
    }

    public static void ApplyKeystream(ulong seed, Span<byte> data)
    {
        ulong s = seed ^ SeedSalt;
        for (int w = 0; w < 4; w++) Step(ref s);
        for (int off = 0; off < data.Length; off += 8)
        {
            ulong k = Step(ref s);
            int n = Math.Min(8, data.Length - off);
            for (int i = 0; i < n; i++)
                data[off + i] ^= (byte)(k >> (8 * i));
        }
    }

    public static byte[] Seal(byte[] plain, ulong ts, string origPath)
    {
        ApplyKeystream(ts, plain);
        byte[] p16 = Encoding.Unicode.GetBytes(origPath);
        using var ms = new MemoryStream(plain.Length + 24 + p16.Length);
        using var bw = new BinaryWriter(ms);
        bw.Write(Magic.AsSpan());
        bw.Write((ulong)plain.Length);
        bw.Write((uint)(p16.Length / 2));
        bw.Write(p16.AsSpan());
        bw.Write(plain.AsSpan());
        bw.Flush();
        return ms.ToArray();
    }

    public static (string OrigPath, byte[] Body) Unseal(byte[] sealedBytes, ulong ts)
    {
        if (sealedBytes.Length < 24 || !sealedBytes.AsSpan(0, 8).SequenceEqual(Magic))
            throw new InvalidDataException("格式不符");
        ulong size = BitConverter.ToUInt64(sealedBytes, 8);
        uint plen = BitConverter.ToUInt32(sealedBytes, 16);
        int hs = 20 + (int)plen * 2;
        if (plen > 4096 || sealedBytes.Length < hs || (ulong)(sealedBytes.Length - hs) < size)
            throw new InvalidDataException("头部损坏");
        string origPath = Encoding.Unicode.GetString(sealedBytes, 20, (int)plen * 2);
        var body = new byte[size];
        Array.Copy(sealedBytes, hs, body, 0, (long)size);
        ApplyKeystream(ts, body);
        return (origPath, body);
    }
}

public sealed record QuarItem(string SealedPath, ulong Ts, long Size, string OrigPath);

public static class Scanner
{
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_NOACCESS = 0x01;
    private const ulong MAX_REGION = 0x10000000;

    private static readonly string[] C2Iocs =
        ["4d.skendh.com", "de.sjd82.org", "skendh.com", "sjd82.org", "dmo/client"];

    private static readonly string[] NameHits =
        ["ekxzjr", "dd9ocged", "srl.exe", "wdybq.dll", "drivers.dat", "drivers.dat.0",
         "wow64log.dll", "vafdska.sys", "vmservice.sys"];

    private static readonly byte[] StegMagic = "STEGR1Xp"u8.ToArray();
    private static readonly byte[] JelgMagic = "JELG"u8.ToArray();

    private static readonly (string Pat, bool High)[] ServicePatterns =
        [("EkxZJr", true), ("SrL.exe", true), ("cd /d", false),
         ("vafdska", true), ("MiniFilterDrv", true), ("vmservice", true),
         ("MicrosoftSoftware2ShadowCop4yProvider", true)];

    // ---- 权限 ----

    public static void EnablePrivileges()
    {
        if (!Native.OpenProcessToken(Native.GetCurrentProcess(), 0x28, out var tok)) return;
        try
        {
            foreach (var pn in new[]
            {
                "SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege",
                "SeDebugPrivilege", "SeSecurityPrivilege"
            })
            {
                if (!Native.LookupPrivilegeValueW(null, pn, out var luid)) continue;
                var tp = new Native.TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = 2 };
                Native.AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
        }
        finally { Native.CloseHandle(tok); }
    }

    // ---- 扫描入口 ----

    public static List<Finding> ScanAll()
    {
        EnablePrivileges();
        var t1 = Task.Run(() =>
        {
            var f = ScanTasks();
            f.AddRange(ScanServices());
            return f;
        });
        var t2 = Task.Run(() =>
        {
            var f = ScanProcs();
            f.AddRange(ScanCtfmon());
            return f;
        });
        var t3 = Task.Run(() =>
        {
            var f = ScanFiles();
            f.AddRange(ScanHosts());
            f.AddRange(ScanWu());
            return f;
        });
        var t4 = Task.Run(() =>
        {
            var f = ScanWb();
            f.AddRange(ScanWd());
            return f;
        });
        Task.WaitAll(t1, t2, t3, t4);
        var all = t1.Result.Concat(t2.Result).Concat(t3.Result).Concat(t4.Result).ToList();
        all.Sort((a, b) => b.High.CompareTo(a.High));
        return all;
    }

    // ---- 计划任务 ----

    public static List<Finding> ScanTasks()
    {
        var res = new List<Finding>();
        const string root = @"C:\Windows\System32\Tasks";
        if (!Directory.Exists(root)) return res;
        foreach (var p in Walk(root, 4))
        {
            byte[] dt;
            try { dt = File.ReadAllBytes(p); } catch { continue; }
            bool hi = Contains(dt, Encoding.ASCII.GetBytes("EkxZJr"))
                   || Contains(dt, Encoding.ASCII.GetBytes("SrL.exe"))
                   || Contains(dt, Encoding.Unicode.GetBytes("EkxZJr"))
                   || Contains(dt, Encoding.Unicode.GetBytes("SrL.exe"));
            bool md = Contains(dt, Encoding.Unicode.GetBytes("cd /d"))
                   && Contains(dt, Encoding.Unicode.GetBytes("&& start"));
            if (!(hi || md)) continue;
            string nm = Path.GetRelativePath(root, p);
            res.Add(new Finding
            {
                Kind = "TASK",
                Detail = hi ? nm : $"{nm} [链式]",
                High = hi,
                Action = $"schtasks /delete /tn \"{nm}\" /f"
            });
        }
        return res;
    }

    // ---- 服务（原生注册表遍历，等价 reg query /s /f <pat> /d）----

    public static List<Finding> ScanServices()
    {
        var res = new List<Finding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var rk = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (rk is null) return res;
        foreach (var (pat, high) in ServicePatterns)
        {
            foreach (var svc in rk.GetSubKeyNames())
            {
                if (seen.Contains(svc)) continue;
                try
                {
                    using var sk = rk.OpenSubKey(svc);
                    if (sk is null || !KeyTreeContains(sk, pat, 0)) continue;
                }
                catch { continue; }
                seen.Add(svc);
                res.Add(new Finding
                {
                    Kind = "SERVICE",
                    Detail = high ? svc : $"{svc} [结构]",
                    High = high,
                    Action = $"sc delete \"{svc}\""
                });
            }
        }
        return res;
    }

    private static bool KeyTreeContains(RegistryKey k, string pat, int depth)
    {
        foreach (var vn in k.GetValueNames())
        {
            object? v;
            try { v = k.GetValue(vn, null, RegistryValueOptions.DoNotExpandEnvironmentNames); }
            catch { continue; }
            switch (v)
            {
                case string s when s.Contains(pat, StringComparison.Ordinal):
                    return true;
                case string[] arr when arr.Any(x => x.Contains(pat, StringComparison.Ordinal)):
                    return true;
            }
        }
        if (depth >= 3) return false;
        foreach (var sub in k.GetSubKeyNames())
        {
            try
            {
                using var sk = k.OpenSubKey(sub);
                if (sk is not null && KeyTreeContains(sk, pat, depth + 1)) return true;
            }
            catch { /* 忽略无权限子键 */ }
        }
        return false;
    }

    // ---- 进程 / 互斥体 ----

    private sealed record ProcInfo(uint Id, string Name);

    private static IEnumerable<ProcInfo> SafeProcesses()
    {
        Process[] ps;
        try { ps = Process.GetProcesses(); } catch { yield break; }
        foreach (var p in ps)
        {
            uint id;
            string name;
            try { id = (uint)p.Id; name = p.ProcessName + ".exe"; }
            catch { p.Dispose(); continue; }
            yield return new ProcInfo(id, name);
            p.Dispose();
        }
    }

    public static List<Finding> ScanProcs()
    {
        var res = new List<Finding>();
        foreach (var (id, name) in SafeProcesses())
        {
            if (name.Equals("srl.exe", StringComparison.OrdinalIgnoreCase))
            {
                res.Add(new Finding
                {
                    Kind = "PROCESS", High = true,
                    Detail = $"SrL.exe (pid {id})",
                    Action = $"taskkill /f /pid {id}"
                });
            }
            string mn = $"Global\\P_{new string(id.ToString().Reverse().ToArray())}";
            var h = Native.OpenMutexW(0x1F0001, false, mn);
            if (h != IntPtr.Zero)
            {
                Native.CloseHandle(h);
                res.Add(new Finding
                {
                    Kind = "MUTEX", High = true,
                    Detail = $"{mn} (pid {id} {name})",
                    Action = "随进程终止"
                });
            }
        }
        return res;
    }

    // ---- ctfmon 内存注入检测 ----

    public static List<Finding> ScanCtfmon()
    {
        var res = new List<Finding>();
        foreach (var (id, _) in SafeProcesses())
        {
            if (!IsCtfmon(id)) continue;
            var h = Native.OpenProcess(0x0410, false, id); // QUERY_INFORMATION | VM_READ
            if (h == IntPtr.Zero) continue;
            var hits = new List<string>();
            try
            {
                ulong addr = 0x10000;
                while (true)
                {
                    if (Native.VirtualQueryEx(h, (IntPtr)addr, out var mbi,
                        Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>()) == IntPtr.Zero) break;
                    ulong rb = (ulong)mbi.BaseAddress;
                    ulong rs = (ulong)mbi.RegionSize;
                    ulong nx = unchecked(rb + rs);
                    if (nx <= addr) break;
                    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
                        (mbi.Protect & PAGE_NOACCESS) == 0 && rs > 0 && rs <= MAX_REGION)
                    {
                        var buf = new byte[(int)rs];
                        if (Native.ReadProcessMemory(h, (IntPtr)rb, buf, (nint)rs, out var got) && got > 0)
                        {
                            var span = buf.AsSpan(0, (int)got);
                            foreach (var ioc in C2Iocs)
                                if (!hits.Contains(ioc) && span.IndexOf(Encoding.ASCII.GetBytes(ioc)) >= 0)
                                    hits.Add(ioc);
                        }
                    }
                    addr = nx;
                }
            }
            finally { Native.CloseHandle(h); }
            if (hits.Count > 0)
            {
                res.Add(new Finding
                {
                    Kind = "PROC-MEM", High = true,
                    Detail = $"ctfmon.exe (pid {id}) 注入: {string.Join(", ", hits)}",
                    Action = "重启 ctfmon"
                });
            }
        }
        return res;
    }

    private static bool IsCtfmon(uint id)
    {
        try { using var p = Process.GetProcessById((int)id); return p.ProcessName.Equals("ctfmon", StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    // ---- 落盘文件 ----

    // hosts 篡改检测 (银狐常用手法: 封杀软更新域)
    private const string DefaultHosts =
        "# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
        "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n" +
        "# This file contains the mappings of IP addresses to host names.\r\n" +
        "#\r\n" +
        "# localhost name resolution is handled within DNS itself.\r\n" +
        "#\t127.0.0.1       localhost\r\n" +
        "#\t::1             localhost\r\n";

    private const string HostsPath = @"C:\Windows\System32\drivers\etc\hosts";

    public static List<Finding> ScanWu()
    {
        var res = new List<Finding>();
        foreach (var svc in new[] { "wuauserv", "UsoSvc", "uhssvc", "WaaSMedicSvc" })
        {
            try
            {
                using var sk = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svc}");
                var start = Convert.ToInt32(sk?.GetValue("Start", 2));
                if (start == 4) /* 仅禁用(4)才报; 3=demand 是 Win11 默认手动启动 */
                {
                    res.Add(new Finding
                    {
                        Kind = "WU", High = true,
                        Detail = $"Windows 更新服务被禁用: {svc} (Start={start})",
                        Action = $"sc config {svc} start= auto"
                    });
                }
            }
            catch { /* 服务不存在忽略 */ }
        }
        return res;
    }

    public static List<Finding> ScanHosts()
    {
        var res = new List<Finding>();
        try
        {
            foreach (var line in File.ReadAllLines(HostsPath))
            {
                var c = line.TrimStart();
                if (c.Length == 0 || c[0] == '#') continue;
                if (!c.StartsWith("127.0.0.1") && !c.StartsWith("::1"))
                {
                    res.Add(new Finding
                    {
                        Kind = "HOSTS", High = true, Detail = "hosts 文件被篡改 (存在活动解析条目)",
                        Action = "重置为默认并隔离原件"
                    });
                    break;
                }
            }
        }
        catch { /* 文件不可读忽略 */ }
        return res;
    }

    // 白加黑: 每目录聚合 [有效签名EXE + 未签名DLL] — 对随机名称跨变种同样有效
    private const uint WTD_UI_NONE = 2;   // 1=WTD_UI_ALL 会弹"要运行此文件吗", 必须 2
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private static readonly string[] WbWhitelist =
        { @"\programs\", @"\package cache\", @"\windowsapps\", @"\microsoft\", @"\windows\" };

    private static bool IsValidSigned(string path)
    {
        // WINTRUST_FILE_INFO 含 string 非 blittable, 不能用 GCHandle pin —
        // 走 StructureToPtr 编组到非托管内存, WINTRUST_DATA.pFile 指向它
        var fi = new Native.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };
        IntPtr pFi = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fi, pFi, false);
            var wd = new Native.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = 0,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFi,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = null,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero,
            };
            var act = Native.WinTrustActionGenericVerifyV2;
            int r = Native.WinVerifyTrust(IntPtr.Zero, ref act, ref wd);
            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            Native.WinVerifyTrust(IntPtr.Zero, ref act, ref wd);
            return r == 0 || IsCatalogSigned(path);
        }
        finally { Marshal.FreeHGlobal(pFi); }
    }

    // catalog 回退: 系统 PE 无内嵌签名 — 算哈希 -> 第一个含此哈希的 catalog -> WTD_CHOICE_CATALOG 复验
    private static bool IsCatalogSigned(string path)
    {
        const uint WTD_CHOICE_CATALOG = 2;
        if (!File.Exists(path)) return false;
        // catalog 物理库 catroot\{F750E6C3-...} 对应 DRIVER_ACTION_VERIFY subsystem;
        // GENERIC_VERIFY_V2 acquire 在 Win11 枚举不到系统 catalog → 双 GUID 都试
        IntPtr hCatAdmin = IntPtr.Zero;
        var action = Native.WinTrustActionGenericVerifyV2;
        var driverAction = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
        try
        {
            using var fs = File.OpenRead(path);
            var hash = new byte[100];
            uint cb = (uint)hash.Length;
            if (!Native.CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(), ref cb, hash, 0)
                || cb == 0 || cb > hash.Length) return false;
            var tag = new StringBuilder((int)cb * 2 + 1);
            for (int i = 0; i < cb; i++) tag.AppendFormat("{0:X2}", hash[i]);
            foreach (var sub in new[] { driverAction, action })
            {
                var subGuid = sub;   // foreach 变量不能作 ref 实参 (CS1657)
                if (!Native.CryptCATAdminAcquireContext(out hCatAdmin, ref subGuid, 0)) continue;
                IntPtr hCat = Native.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cb, 0, IntPtr.Zero);
                if (hCat != IntPtr.Zero)
                {
                    try
                    {
                        var ci = new Native.CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<Native.CATALOG_INFO>() };
                        if (Native.CryptCATCatalogInfoFromContext(hCat, ref ci, 0))
                        {
                            // WinVerifyTrust 第三参必须是 WINTRUST_DATA: union choice 指向 catalog info
                            var hashPtr = Marshal.AllocHGlobal(hash.Length);
                            var wciPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WINTRUST_CATALOG_INFO>());
                            try
                            {
                                Marshal.Copy(hash, 0, hashPtr, hash.Length);
                                var wci = new Native.WINTRUST_CATALOG_INFO
                                {
                                    cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_CATALOG_INFO>(),
                                    dwCatalogVersion = 0,
                                    pcwszCatalogFilePath = ci.wszCatalogFile,
                                    pcwszMemberTag = tag.ToString(),
                                    pcwszMemberFilePath = path,
                                    hMemberFile = IntPtr.Zero,
                                    pbCalculatedFileHash = hashPtr,
                                    cbCalculatedFileHash = cb,
                                    pcCatalogContext = IntPtr.Zero,
                                };
                                Marshal.StructureToPtr(wci, wciPtr, false);
                                var wd = new Native.WINTRUST_DATA
                                {
                                    cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_DATA>(),
                                    pPolicyCallbackData = IntPtr.Zero,
                                    pSIPClientData = IntPtr.Zero,
                                    dwUIChoice = WTD_UI_NONE,
                                    fdwRevocationChecks = 0,
                                    dwUnionChoice = WTD_CHOICE_CATALOG,
                                    pFile = wciPtr,
                                    dwStateAction = WTD_STATEACTION_VERIFY,
                                    hWVTStateData = IntPtr.Zero,
                                    pwszURLReference = null,
                                    dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
                                    dwUIContext = 0,
                                    pSignatureSettings = IntPtr.Zero,
                                };
                                int r = Native.WinVerifyTrust(IntPtr.Zero, ref action, ref wd);
                                wd.dwStateAction = WTD_STATEACTION_CLOSE;
                                Native.WinVerifyTrust(IntPtr.Zero, ref action, ref wd);
                                if (r == 0) return true;
                            }
                            finally { Marshal.FreeHGlobal(hashPtr); Marshal.FreeHGlobal(wciPtr); }
                        }
                    }
                    finally { Native.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCat, 0); }
                }
                Native.CryptCATAdminReleaseContext(hCatAdmin, 0);
                hCatAdmin = IntPtr.Zero;
            }
            return false;
        }
        catch { return false; }
        finally { if (hCatAdmin != IntPtr.Zero) Native.CryptCATAdminReleaseContext(hCatAdmin, 0); }
    }

    private static void ScanWbDir(string dir, int depth, List<Finding> res)
    {
        if (depth > 4) return;
        string low = dir.ToLowerInvariant();
        if (low.Contains("sf_quarantine") || WbWhitelist.Any(w => low.Contains(w))) return;
        /* 枚举先行: 无 exe 或无 dll 的目录 (绝大多数) 0 次验签; 配对才查, 找到即停 */
        var exes = new List<string>(24);
        var dlls = new List<string>(64);
        var subs = new List<string>();
        string[] entries;
        try { entries = Directory.GetFileSystemEntries(dir); } catch { return; }
        foreach (var e in entries)
        {
            FileAttributes fa;
            try { fa = File.GetAttributes(e); } catch { continue; }
            if (fa.HasFlag(FileAttributes.Directory))
            {
                if (!fa.HasFlag(FileAttributes.ReparsePoint)) subs.Add(e);
                continue;
            }
            string fnm = Path.GetFileName(e).ToLowerInvariant();
            if (fnm.EndsWith(".exe")) { if (exes.Count < 24) exes.Add(e); }
            else if (fnm.EndsWith(".dll")) { if (dlls.Count < 64) dlls.Add(e); }
        }
        if (exes.Count > 0 && dlls.Count > 0)
        {
            bool se = exes.Any(IsValidSigned);
            if (se)
            {
                string? hit = dlls.FirstOrDefault(d => !IsValidSigned(d));
                if (hit != null)
                    res.Add(new Finding
                    {
                        Kind = "FILE",
                        Detail = $"{hit} [白加黑: 有效签名EXE+未签名DLL]",
                        High = false,
                        Action = $"quarantine {hit}",
                    });
            }
        }
        foreach (var sd in subs) ScanWbDir(sd, depth + 1, res);
    }

    public static List<Finding> ScanWb()
    {
        var res = new List<Finding>();
        var roots = new List<string> { @"C:\Drivers" };
        AddEnv(roots, "TEMP");
        AddEnv(roots, "APPDATA");
        AddEnv(roots, "LOCALAPPDATA");
        AddEnv(roots, "ProgramData");
        foreach (var root in roots.Where(Directory.Exists)) ScanWbDir(root, 0, res);
        return res;
    }

    // ---- %WINDIR% 随机名 PE/bat 检测 (随机名+未签名双条件) ----
    private static readonly string[] WdSkip =
    {
        "\\winsxs", "\\softwaredistribution", "\\driverstore", "\\installer",
        "\\assembly", "\\microsoft.net", "\\servicing", "\\logfiles", "\\logs",
        "\\spool", "\\catroot", "\\fonts", "\\media", "\\ime", "\\web",
        "\\wallpaper", "\\oledb", "\\mui", "\\ehome", "\\pchealth", "\\resources",
        "\\livekernelreports", "\\minidump", "\\prefetch", "\\appcompat",
        "\\apppatch", "\\csc", "\\diagnostics", "\\panther", "\\performance",
        "\\pla", "\\registration", "\\shellcomponents", "\\triage", "\\winstore",
        "\\tokens", "\\csp", "\\msdtc",
    };

    private static int WdRandomName(string fnm) /* 0否 1pe 2bat */
    {
        int dot = fnm.LastIndexOf('.');
        if (dot < 0) return 0;
        string ext = fnm[dot..].ToLowerInvariant();
        bool isPe = ext is ".exe" or ".dll" or ".sys";
        if (!isPe && ext != ".bat") return 0;
        string baseName = fnm[..dot];
        if (baseName.Length < 6 || baseName.Length > 16) return 0;
        int dig = 0, up = 0;
        foreach (var c in baseName)
        {
            if (c >= '0' && c <= '9') dig++;
            else if (c >= 'A' && c <= 'Z') up++;
            else if (c >= 'a' && c <= 'z') continue;   // 纯 ASCII 区间判定, 不依赖 char.IsAscii* (部分 TFM 缺失)
            else return 0;
        }
        if (!isPe) return 2;
        if (dig >= 2 || up > 0 || baseName.Length >= 8) return 1;
        return 0;
    }

    private static void WdScanDir(string dir, int depth, List<Finding> res)
    {
        if (depth > 4) return;
        string low = dir.ToLowerInvariant();
        if (WdSkip.Any(w => low.Contains(w))) return;
        string[] entries;
        try { entries = Directory.GetFileSystemEntries(dir); } catch { return; }
        foreach (var e in entries)
        {
            FileAttributes fa;
            try { fa = File.GetAttributes(e); } catch { continue; }
            if (fa.HasFlag(FileAttributes.Directory))
            {
                if (!fa.HasFlag(FileAttributes.ReparsePoint)) WdScanDir(e, depth + 1, res);
                continue;
            }
            int rt = WdRandomName(Path.GetFileName(e));
            if (rt == 0) continue;
            if (rt == 1 && IsValidSigned(e)) continue;   // 随机名但签名有效 → 放行
            res.Add(new Finding
            {
                Kind = "FILE",
                Detail = $"{e} [{(rt == 1 ? "随机名未签名PE" : "随机名bat")}]",
                High = true,
                Action = $"quarantine {e}",
            });
        }
    }

    public static List<Finding> ScanWd()
    {
        var res = new List<Finding>();
        string wd = Environment.GetEnvironmentVariable("WINDIR") ?? @"C:\Windows";
        WdScanDir(wd, 0, res);
        return res;
    }

    public static List<Finding> ScanFiles()
    {
        var res = new List<Finding>();
        var roots = new List<string> { @"C:\Drivers" };
        AddEnv(roots, "TEMP");
        AddEnv(roots, "APPDATA");
        AddEnv(roots, "LOCALAPPDATA");
        AddEnv(roots, "ProgramData");
        byte[] headBuf = new byte[16];
        foreach (var root in roots.Where(Directory.Exists))
        {
            foreach (var p in Walk(root, 4))
            {
                if (p.ToLowerInvariant().Contains("sf_quarantine")) continue;
                string fnm;
                long sz;
                try
                {
                    fnm = Path.GetFileName(p).ToLowerInvariant();
                    sz = new FileInfo(p).Length;
                }
                catch { continue; }
                bool byNm = NameHits.Contains(fnm) || fnm.StartsWith("itqe.");
                bool isExt = fnm.EndsWith(".exe") || fnm.EndsWith(".dll") || fnm.EndsWith(".sys")
                          || fnm.EndsWith(".xl") || fnm.EndsWith(".xlez");
                string md = "";
                if (sz > 100 * 1024)
                {
                    int n = ReadHead(p, headBuf);
                    var head = headBuf.AsSpan(0, n);
                    if (head.IndexOf(StegMagic) >= 0) md += " [STEGR1Xp]";
                    if (head.IndexOf(JelgMagic) >= 0) md += " [JELG]";
                    if (n >= 4 && head[0] == 0x89 && head[1] == (byte)'P' && head[2] == (byte)'N' &&
                        head[3] == (byte)'G' && !fnm.EndsWith(".png")
                        && !p.ToLowerInvariant().Contains(@"\packages\")) md += " [PNG伪装]"; /* UWP 磁贴缓存合法 */
                }
                string hs = "";
                try
                {
                    var fa = File.GetAttributes(p);
                    if (fa.HasFlag(FileAttributes.Hidden) || fa.HasFlag(FileAttributes.System))
                        hs = " [隐藏+系统]";
                }
                catch { /* 属性不可读忽略 */ }
                if (byNm || md.Length > 0 || (hs.Length > 0 && isExt))
                {
                    res.Add(new Finding
                    {
                        Kind = "FILE",
                        Detail = byNm ? p : p + md + hs,
                        High = byNm,
                        Action = $"quarantine {p}"
                    });
                }
            }
        }
        return res;
    }

    private static void AddEnv(List<string> list, string var)
    {
        var v = Environment.GetEnvironmentVariable(var);
        if (!string.IsNullOrEmpty(v)) list.Add(v);
    }

    private static int ReadHead(string path, Span<byte> dst)
    {
        try
        {
            using var f = File.OpenRead(path);
            return f.ReadAtLeast(dst, dst.Length, throwOnEndOfStream: false);
        }
        catch { return 0; }
    }

    // ---- 目录遍历（深度上限 4，不进 reparse point 防junction环）----

    private static IEnumerable<string> Walk(string dir, int maxDepth)
    {
        var stack = new Stack<(string Path, int Depth)>();
        stack.Push((dir, 0));
        while (stack.Count > 0)
        {
            var (cur, d) = stack.Pop();
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(cur); } catch { continue; }
            foreach (var e in entries)
            {
                FileAttributes fa;
                try { fa = File.GetAttributes(e); } catch { continue; }
                if (fa.HasFlag(FileAttributes.Directory))
                {
                    if (!fa.HasFlag(FileAttributes.ReparsePoint) && d < maxDepth)
                        stack.Push((e, d + 1));
                }
                else yield return e;
            }
        }
    }

    private static bool Contains(byte[] hay, byte[] needle) =>
        needle.Length > 0 && hay.AsSpan().IndexOf(needle) >= 0;

    // ---- 清除 ----

    public static CleanStats Clean(IReadOnlyList<Finding> fs, IProgress<string>? log = null)
    {
        EnablePrivileges();
        int ok = 0, fail = 0;
        if (fs.Any(x => x.Kind == "PROC-MEM"))
        {
            Run("taskkill", "/f", "/im", "ctfmon.exe");
            log?.Report("[*] 已重启 ctfmon");
        }
        long ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string qd = $@"C:\ProgramData\sf_quarantine\{ts}";
        foreach (var f in fs)
        {
            bool s;
            switch (f.Kind)
            {
                case "PROC-MEM": s = true; break;
                case "PROCESS":
                    string pid = AfterLast(f.Detail, "pid ").Trim().TrimEnd(')');
                    s = Run("taskkill", "/f", "/pid", pid);
                    break;
                case "TASK":
                    s = Run("schtasks", "/delete", "/tn", BeforeBracket(f.Detail), "/f");
                    break;
                case "SERVICE":
                {
                    string n = BeforeBracket(f.Detail);
                    Run("sc", "stop", n);
                    s = Run("sc", "delete", n);
                    break;
                }
                case "FILE":
                    s = Quarantine(BeforeBracket(f.Detail), qd, log);
                    break;
                case "WU":
                {
                    var nm = f.Detail.Split(": ").Last();
                    Run("sc", "config", nm, "start=", "auto");
                    Run("sc", "config", nm, "depend=", "RpcSs");
                    Run("sc", "start", nm);
                    s = true;
                    break;
                }
                case "HOSTS":
                    Quarantine(HostsPath, qd, log); // 隔离原件 (失败不阻塞)
                    try
                    {
                        File.WriteAllText(HostsPath, DefaultHosts);
                        s = true;
                    }
                    catch { s = false; }
                    break;
                default: s = true; break;
            }
            if (s) ok++; else fail++;
        }
        return new CleanStats(ok, fail);
    }

    private static string BeforeBracket(string detail)
    {
        int i = detail.IndexOf(" [", StringComparison.Ordinal);
        return i < 0 ? detail : detail[..i];
    }

    private static string AfterLast(string detail, string marker)
    {
        int i = detail.LastIndexOf(marker, StringComparison.Ordinal);
        return i < 0 ? "" : detail[(i + marker.Length)..];
    }

    private static bool Run(string exe, params string[] args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(exe, args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });
            if (p is null) return false;
            p.WaitForExit(30000);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    private static void TakeOwn(string path)
    {
        Run("takeown", "/f", path, "/a");
        Run("icacls", path, "/grant", "Administrators:F");
    }

    private static bool Quarantine(string src, string qdir, IProgress<string>? log)
    {
        if (!File.Exists(src)) return true;
        try { Directory.CreateDirectory(qdir); } catch { /* 已存在 */ }
        ulong ts = QuarCrypt.TsFromDirName(Path.GetFileName(qdir));
        TakeOwn(src);
        string staged = Path.Combine(qdir, Path.GetFileName(src));
        try { File.Move(src, staged); }
        catch
        {
            try
            {
                File.Copy(src, staged, overwrite: true);
                File.Delete(src);
            }
            catch { return false; }
        }
        try
        {
            byte[] data = File.ReadAllBytes(staged);
            string sealedPath = staged + ".qenc";
            File.WriteAllBytes(sealedPath, QuarCrypt.Seal(data, ts, src));
            File.Delete(staged);
            log?.Report($"[*] 已加密隔离 {src}");
            return true;
        }
        catch
        {
            try { File.Delete(staged); } catch { /* 尽力清理 */ }
            return false;
        }
    }

    // ---- 隔离区还原 ----

    public static List<QuarItem> ListQuarantine()
    {
        var res = new List<QuarItem>();
        const string root = @"C:\ProgramData\sf_quarantine";
        if (!Directory.Exists(root)) return res;
        string[] batches;
        try { batches = Directory.GetDirectories(root); } catch { return res; }
        foreach (var batch in batches)
        {
            ulong ts = QuarCrypt.TsFromDirName(Path.GetFileName(batch));
            string[] files;
            try { files = Directory.GetFiles(batch, "*.qenc"); } catch { continue; }
            foreach (var f in files)
            {
                long sz;
                string? orig;
                try
                {
                    sz = new FileInfo(f).Length;
                    orig = PeekOrigPath(f);
                }
                catch { continue; }
                res.Add(new QuarItem(f, ts, sz, orig ?? "(未知原路径)"));
            }
        }
        return res;
    }

    private static string? PeekOrigPath(string path)
    {
        byte[] hb = new byte[20];
        try
        {
            using var f = File.OpenRead(path);
            if (f.ReadAtLeast(hb, hb.Length, throwOnEndOfStream: false) < hb.Length) return null;
            if (!hb.AsSpan(0, 8).SequenceEqual(QuarCrypt.Magic)) return null;
            uint plen = BitConverter.ToUInt32(hb, 16);
            if (plen == 0 || plen > 4096) return null;
            byte[] pb = new byte[plen * 2];
            if (f.ReadAtLeast(pb, pb.Length, throwOnEndOfStream: false) < pb.Length) return null;
            return Encoding.Unicode.GetString(pb);
        }
        catch { return null; }
    }

    public static bool Restore(QuarItem item)
    {
        EnablePrivileges();
        try
        {
            var (origPath, body) = QuarCrypt.Unseal(File.ReadAllBytes(item.SealedPath), item.Ts);
            if (string.IsNullOrWhiteSpace(origPath)) return false;
            var parent = Path.GetDirectoryName(origPath);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            if (File.Exists(origPath)) TakeOwn(origPath);
            File.WriteAllBytes(origPath, body);
            File.Delete(item.SealedPath);
            return true;
        }
        catch { return false; }
    }

    // ---- 隔离区清空 ----

    private const string QuarRoot = @"C:\ProgramData\sf_quarantine";

    public static (int Count, long Bytes) QuarantineStats()
    {
        int n = 0;
        long bytes = 0;
        if (!Directory.Exists(QuarRoot)) return (0, 0);
        var stack = new Stack<string>();
        stack.Push(QuarRoot);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(dir); } catch { continue; }
            foreach (var e in entries)
            {
                try
                {
                    var fa = File.GetAttributes(e);
                    if (fa.HasFlag(FileAttributes.Directory)) stack.Push(e);
                    else { n++; bytes += new FileInfo(e).Length; }
                }
                catch { /* 竞争删除忽略 */ }
            }
        }
        return (n, bytes);
    }

    public static bool QuarantineWipe()
    {
        EnablePrivileges();
        if (!Directory.Exists(QuarRoot)) return true;
        try { Directory.Delete(QuarRoot, recursive: true); return true; }
        catch { return false; }
    }

    // ---- 极端模式 ----

    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string MarkKeyPath = @"Software\SFCleaner";

    private static void Xlog(string s)
    {
        try
        {
            Directory.CreateDirectory(QuarRoot);
            File.AppendAllText(Path.Combine(QuarRoot, "extreme.log"),
                $"[{DateTime.Now:HH:mm:ss}] {s}\n");
        }
        catch { /* 日志尽力而为 */ }
    }

    private const string RunOnceKeyPath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";

    private static void AutorunSet()
    {
        // 优先 8.3 短路径写 Run/RunOnce (无括号/空格歧义), 拿不到才回退引号长路径
        var exe = Environment.ProcessPath ?? "";
        var shortBuf = new StringBuilder(520);
        uint n = Native.GetShortPathName(exe, shortBuf, 520);
        var data = n > 0 && n < 520 ? $"{shortBuf} --extreme" : $"\"{exe}\" --extreme";
        using (var rk = Registry.LocalMachine.CreateSubKey(RunKeyPath))
        {
            rk.SetValue("SFCleaner", data);
            rk.SetValue("*SFCleaner", data); // 安全模式只执行带 * 前缀条目
        }
        using (var ro = Registry.LocalMachine.CreateSubKey(RunOnceKeyPath))
        {
            ro.SetValue("*SFCleaner", data);
        }
    }

    // 安全模式启动 (safeboot minimal; 安全模式下 UAC 禁用 → 阶段二可改回)
    // 不客气 phase2 自启动: RunOnce 一次性 (普通登录 + 安全模式), 短路径消歧义
    private static void NomoreAutorunSet()
    {
        var exe = Environment.ProcessPath ?? "";
        var shortBuf = new StringBuilder(520);
        uint n = Native.GetShortPathName(exe, shortBuf, 520);
        var data = n > 0 && n < 520 ? $"{shortBuf} --nomore2" : $"\"{exe}\" --nomore2";
        try
        {
            using var ro = Registry.LocalMachine.CreateSubKey(RunOnceKeyPath);
            ro.SetValue("SFCleaner", data);
            ro.SetValue("*SFCleaner", data);
        }
        catch { /* 注册表失败则退化为手动二段 */ }
    }

    // RunOnce 自动链专用: 只允许 phase2, marker 不在绝不重演 phase1
    public static void NomorePhase2Auto()
    {
        EnablePrivileges();
        if (MarkerGet() == 3) NomorePhase2();
    }

    private static void SafebootSet() => Run("bcdedit", "/set", "{current}", "safeboot", "minimal");
    private static void SafebootClear() => Run("bcdedit", "/deletevalue", "{current}", "safeboot");

    private static void AutorunDel()
    {
        try
        {
            using var rk = Registry.LocalMachine.OpenSubKey(RunKeyPath, writable: true);
            rk?.DeleteValue("SFCleaner", throwOnMissingValue: false);
            rk?.DeleteValue("*SFCleaner", throwOnMissingValue: false);
        }
        catch { /* 已不存在 */ }
        try
        {
            using var ro = Registry.LocalMachine.OpenSubKey(RunOnceKeyPath, writable: true);
            ro?.DeleteValue("SFCleaner", throwOnMissingValue: false);
            ro?.DeleteValue("*SFCleaner", throwOnMissingValue: false);
        }
        catch { /* 已不存在 */ }
    }

    private static void MarkerSet(int v)
    {
        using var rk = Registry.LocalMachine.CreateSubKey(MarkKeyPath);
        rk.SetValue("ExtremePhase", v, RegistryValueKind.DWord);
    }

    private static int MarkerGet()
    {
        try
        {
            using var rk = Registry.LocalMachine.OpenSubKey(MarkKeyPath);
            return Convert.ToInt32(rk?.GetValue("ExtremePhase", 0));
        }
        catch { return 0; }
    }

    private static void MarkerDel()
    {
        try
        {
            using var rk = Registry.LocalMachine.OpenSubKey(MarkKeyPath, writable: true);
            rk?.DeleteValue("ExtremePhase", throwOnMissingValue: false);
        }
        catch { /* 已不存在 */ }
    }

    // 自毁: 改名绕开运行中 exe 的锁定, MoveFileEx 延迟到下次开机删除
    private static void ScheduleSelfDelete()
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe)) return;
        var old = Path.ChangeExtension(exe, ".sfold");
        File.Move(exe, old);
        Native.MoveFileExW(old, IntPtr.Zero, 0x4); // MOVEFILE_DELAY_UNTIL_REBOOT
    }

    private static bool TriggerBsod() // false = 未能触发(调用方提示手动重启); 成功则永不返回
    {
        Native.RtlAdjustPrivilege(19 /*SeShutdownPrivilege*/, true, false, out _);
        // ResponseOption 必须是 6 (OptionShutdownSystem) 才会 bugcheck;
        // 传 1 (OptionOk) 只会弹系统硬错误对话框然后正常返回
        if (Native.NtRaiseHardError(0xC0114514, 0, 0,
                IntPtr.Zero, 6, out _) == 0)
            Thread.Sleep(Timeout.Infinite);
        return false;
    }

    // 阶段一: 自启动+标记+清除+蓝屏; 阶段二: 再清除+解除+自毁+蓝屏
    public static void ExtremeRun(IProgress<string>? log)
    {
        EnablePrivileges();
        if (MarkerGet() == 2)
        {
            Xlog("phase2: boot cleanup");
            var fs = ScanAll();
            var r = Clean(fs, log);
            log?.Report($"[!!] 第二阶段清除完成 {r.Ok}/{r.Ok + r.Fail}");
            AutorunDel();
            MarkerDel();
            SafebootClear(); // 解除安全模式 → 本次蓝屏后回正常启动
            ScheduleSelfDelete();
            Xlog("phase2: self-destruct scheduled, bsod now");
            log?.Report("[!!] 已解除自启动并计划自毁 — 蓝屏中");
            Thread.Sleep(1200);
            TriggerBsod();
        }
        else
        {
            Xlog("phase1: arming extreme mode");
            AutorunSet();
            MarkerSet(2);
            SafebootSet(); // 下一轮重启进安全模式再清场
            log?.Report("[!!] 已写入自启动与阶段标记, 下次重启进安全模式");
            var fs = ScanAll();
            var r = Clean(fs, log);
            log?.Report($"[!!] 第一阶段清除完成 {r.Ok}/{r.Ok + r.Fail}");
            Xlog($"phase1: clean {r.Ok} ok, bsod now");
            Thread.Sleep(1200);
            TriggerBsod();
        }
    }

    public static void ExtremeAbort()
    {
        EnablePrivileges();
        SafebootClear();
        AutorunDel();
        MarkerDel();
    }

    // ---- 不客气模式: 自定义证书 + 内核驱动装载 ----
    private const string DrvSvc = "SFCleanerDrv";
    private const string CertCn = "SFCleaner Test";

    private static void Extract(string resName, string outPath)
    {
        try
        {
            using var st = typeof(Scanner).Assembly.GetManifestResourceStream(resName);
            if (st == null) return;
            using var o = File.Create(outPath);
            st.CopyTo(o);
            Xlog($"nomore: 内嵌资源已释放 {Path.GetFileName(outPath)}");
        }
        catch { /* 无内嵌资源时走外部材料 */ }
    }

    private static (string Drv, string Pfx, string Cer) NomorePaths()
    {
        var dir = Path.GetDirectoryName(Environment.ProcessPath) ?? "";
        return (Path.Combine(dir, "SFCleanerDrv.sys"),
                Path.Combine(dir, "SFCleanerCert.pfx"),
                Path.Combine(dir, "SFCleanerCert.cer"));
    }

    private static bool NomoreImportCert()
    {
        var (_, pfx, cer) = NomorePaths();
        if (File.Exists(pfx))
        {
            bool r1 = Run("certutil", "-f", "-p", "sf-cleaner", "-importpfx", pfx, "ROOT");
            bool r2 = Run("certutil", "-f", "-p", "sf-cleaner", "-importpfx", pfx, "TrustedPublisher");
            return r1 || r2;
        }
        if (File.Exists(cer))
        {
            bool r1 = Run("certutil", "-addstore", "-f", "ROOT", cer);
            bool r2 = Run("certutil", "-addstore", "-f", "TrustedPublisher", cer);
            return r1 || r2;
        }
        return false;
    }

    private static bool SecureBootOn()
    {
        // HKLM\...\SecureBoot\State\UEFISecureBootEnabled == 1 (无键 = 非 UEFI/未启用)
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            return k?.GetValue("UEFISecureBootEnabled") is int v && v == 1;
        }
        catch { return false; }
    }

    private static bool NomorePhase1()
    {
        var (drv, pfx, cer) = NomorePaths();
        Extract("SFCleaner.SFCleanerDrv.sys", drv);   // 全部内嵌: 无条件释放
        if (!File.Exists(pfx) && !File.Exists(cer)) Extract("SFCleaner.SFCleanerCert.cer", cer);
        if (!File.Exists(drv)) { Xlog($"nomore: [中止] 缺 {drv}"); return false; }
        if (!File.Exists(pfx) && !File.Exists(cer))
        { Xlog($"nomore: [中止] 缺证书材料 ({pfx} 或 {cer})"); return false; }

        if (SecureBootOn())
        {
            Xlog("nomore: [中止] Secure Boot 开启 — testsigning 会被安全启动策略拒绝");
            Xlog("nomore: VMware: 虚拟机设置->选项->高级->固件类型UEFI, 取消勾选'启用安全引导'后重启 VM");
            return false;
        }
        Xlog("nomore: testsigning on");
        if (!Run("bcdedit", "/set", "testsigning", "on"))
        {
            Xlog("nomore: [中止] bcdedit testsigning 失败 — 固件 Secure Boot 开着会被拒, 请在 VM 设置里关掉再试");
            return false;
        }
        if (!NomoreImportCert())
        {
            Xlog("nomore: [中止] 证书导入失败 (pfx 密码 sf-cleaner / cer 格式)");
            return false;
        }
        var dst = $@"C:\Windows\System32\drivers\{DrvSvc}.sys";
        try { File.Copy(drv, dst, true); } catch { Xlog("nomore: [中止] 部署 driver 失败"); return false; }
        Run("sc", "stop", DrvSvc);
        Run("sc", "delete", DrvSvc);
        if (!Run("sc", "create", DrvSvc, $"binPath= System32\\drivers\\{DrvSvc}.sys",
                 "type=", "kernel", "start=", "demand"))
        {
            Xlog("nomore: [中止] sc create 失败");
            return false;
        }
        return true;
    }

    private static void NomorePhase2()
    {
        AutorunDel(); // 先清 RunOnce, 防完成后残留条目把 phase1 再拉起来
        Xlog("nomore: phase2 - 先解除 testsigning (已装载驱动不受影响, 防后续异常残留)");
        Run("bcdedit", "/set", "testsigning", "off");
        Xlog("nomore: phase2 start driver");
        if (!Run("sc", "start", DrvSvc))
            Xlog("nomore: [警告] 驱动未启动 — 常见: phase1 后没重启(testsigning 要重启生效) / Secure Boot / 证书未导入");
        Thread.Sleep(10000);
        Run("sc", "stop", DrvSvc);
        Run("sc", "delete", DrvSvc);
        try { File.Delete($@"C:\Windows\System32\drivers\{DrvSvc}.sys"); } catch { }
        Run("certutil", "-delstore", "ROOT", CertCn);
        Run("certutil", "-delstore", "TrustedPublisher", CertCn);
        MarkerDel();
        Xlog("nomore: phase2 done");
    }

    public static void NomoreRun(IProgress<string>? log = null)
    {
        EnablePrivileges();
        if (MarkerGet() == 3)
        {
            NomorePhase2();
        }
        else
        {
            if (!NomorePhase1())
            {
                log?.Report("[!] 不客气模式未启动 — 详见日志: 常见 Secure Boot 开启 / 缺材料 / 证书导入失败");
                return;
            }
            MarkerSet(3);
            NomoreAutorunSet();
            log?.Report("[!!] 不客气模式已武装 — 蓝屏重启后 RunOnce 自动进 phase2 驱动清理");
            Xlog("nomore: phase1 done, bsod (testsigning 生效需重启; 重启后 RunOnce 自动进 phase2)");
            Thread.Sleep(1200);
            if (!TriggerBsod())
                log?.Report("[!] 蓝屏触发失败 — 请手动重启; 重启登录后自动进入 phase2 (RunOnce), 未弹出也可手动再运行一次");
        }
    }
}
