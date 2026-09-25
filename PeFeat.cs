// PeFeat.cs — 静态 PE 特征提取 (字节级, 与 ml/extract_features.py 语义一致).
//
// 用途: cleaner 内"结构匹配"文件的 ML 复核打分 (结构命中 → 打分 > 0.7 升为高置信).
// 与 ml-dotnet/FeatExtract.cs 的区别: 后者服务于 ONNX 训练管线 (ML.NET 自己的口径);
// 本文件是 Python 训练语料 (corpus.csv / model_linear.json) 的口径, 逐字节复刻,
// 已对 888 样本 × 22 特征与 corpus.csv 零偏差, 且与 C/Rust 版实现逐值一致.
//
// 关键口径 (勿"修正"):
//   - 读取窗口 前 4MB; 节熵 = entropy(data[roff .. roff+min(rsize,1MB)]) 截断到窗口内, 空=0.0,
//     所有能解析的节都进列表 (不是"仅窗口内才计入")
//   - suspicious_apis 只数列表里本就小写的条目 (socket/connect/recv/send)
//   - has_injection/persistence/net 用各自精确名单 (区分大小写字节包含)
//   - n_import_dlls 的 RVA 取「数据目录[0]」(导出表) — 训练端 unpack_from(...+112/96) 未 +8
//   - entry_section_entropy 用未取整熵再取整; ep_high_entropy 用取整熵 >= 7.5
//   - authenticode: 最小 BER/PKCS7 + SignerInfo 序列号锁叶子 + RDN OID + 兜底扫描
//   - 签名黑名单按 UTF-8 字节子串比对 (与 C/Rust 一致, 中文 CN 不走 latin1 摩斯码)
using System.Text;

namespace SFCleaner;

internal static class PeFeat
{
    const int ReadLimit = 4 << 20;
    const int AuthCap = 8 << 20;

    static readonly string[] LowApiNames = ["socket", "connect", "recv", "send"];
    static readonly string[] InjApis =
        ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
         "QueueUserAPC", "NtUnmapViewOfSection"];
    static readonly string[] PersApis =
        ["RegSetValueEx", "RegCreateKeyEx", "CreateService", "StartService",
         "SetWindowsHookEx", "SetWindowsHookExW"];
    static readonly string[] NetApis =
        ["URLDownloadToFile", "InternetOpen", "InternetOpenUrl", "HttpSendRequest"];
    // 被滥用签名证书黑名单: (名称子串, EV 序列号) — 与 Python ABUSED_SIGNERS 顺序一致
    static readonly (string Word, string Serial)[] AbusedSigners =
    {
        ("贝锐", "91310110787862412b"), ("awesun", "91310110787862412b"), ("oray", ""),
        ("duojiayu", "91510107maacgc6jxl"), ("多加鱼", ""),
        ("dingtalk", "91330110ma2b00r29g"), ("钉钉", ""),
        ("iray", ""), ("alibaba", "91330100716105852f"),
    };

    // ---------------- 小工具 ----------------

    static double Entropy(ReadOnlySpan<byte> s)
    {
        if (s.Length == 0) return 0.0;
        var counts = new int[256];
        foreach (var b in s) counts[b]++;
        double e = 0, n = s.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / n;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    /// Python round(x, 4): 半数取偶 (Math.Round 默认即 ToEven)
    static double Round4(double x) => Math.Round(x, 4, MidpointRounding.ToEven);

    static bool Find(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length) return false;
        return hay.IndexOf(needle) >= 0;
    }

    static bool Contains(ReadOnlySpan<byte> hay, string s) => Find(hay, Encoding.ASCII.GetBytes(s));

    static uint U16(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8));
    static uint U32(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

    static byte[] L(byte[] b, int o, int n) { var r = new byte[n]; Array.Copy(b, o, r, 0, n); return r; }

    /// latin1 语义 lowercase: ASCII + 0xC0-0xDE (除 0xD7)
    static byte[] LowerLatin1(byte[] s)
    {
        var r = new byte[s.Length];
        for (int i = 0; i < s.Length; i++)
        {
            byte c = s[i];
            if (c >= 'A' && c <= 'Z') c = (byte)(c + 32);
            else if (c >= 0xC0 && c <= 0xDE && c != 0xD7) c = (byte)(c + 32);
            r[i] = c;
        }
        return r;
    }

    static byte[]? ReadAt(string path, long off, int sz)
    {
        try
        {
            using var f = File.OpenRead(path);
            if (off < 0 || off >= f.Length) return null;
            f.Seek(off, SeekOrigin.Begin);
            int n = Math.Min(sz, AuthCap);
            if (n <= 0) return null;
            var b = new byte[n];
            int got = f.ReadAtLeast(b, n, throwOnEndOfStream: false);
            if (got <= 0) return null;
            if (got < n) Array.Resize(ref b, got);
            return b;
        }
        catch { return null; }
    }

    // ---------------- BER TLV ----------------

    struct Tlv { public byte Tag; public int Vo, Vl, Next; }

    static bool Ber(byte[] b, int pos, int n, out Tlv t)
    {
        t = default;
        if (pos + 2 > n) return false;
        byte tag = b[pos];
        int ln = b[pos + 1];
        int p = pos + 2;
        if (ln == 0x80) return false;
        if ((ln & 0x80) != 0)
        {
            int nb = ln & 0x7F;
            if (nb == 0 || nb > 4 || p + nb > n) return false;
            long v = 0;
            for (int k = 0; k < nb; k++) v = (v << 8) | b[p + k];
            p += nb;
            if (v > int.MaxValue) return false;
            ln = (int)v;
        }
        if (p + ln > n) return false;
        t = new Tlv { Tag = tag, Vo = p, Vl = ln, Next = p + ln };
        return true;
    }

    // ---------------- RDN (CN / O / serialNumber) ----------------

    sealed class Rdn
    {
        public byte[] Cn = [], O = [], Serial = [];
        public bool Empty => Cn.Length == 0 && O.Length == 0 && Serial.Length == 0;
    }

    static void CollectAtv(byte[] b, int start, int end, Rdn outRdn, int depth)
    {
        if (depth > 12) return;
        int i = start;
        while (i < end)
        {
            if (!Ber(b, i, end, out var t)) break;
            if (t.Tag == 0x06 && t.Next < end)
            {
                var oid = L(b, t.Vo, t.Vl);
                if (Ber(b, t.Next, end, out var v) &&
                    (v.Tag is 0x0C or 0x13 or 0x16 or 0x1E or 0x12))
                {
                    int take = Math.Min(v.Vl, 127);
                    if (take > 0)
                    {
                        if (oid.Length >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x03 && outRdn.Cn.Length == 0)
                            outRdn.Cn = L(b, v.Vo, take);
                        else if (oid.Length >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x0A && outRdn.O.Length == 0)
                            outRdn.O = L(b, v.Vo, take);
                        else if (oid.Length >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x05 && outRdn.Serial.Length == 0)
                            outRdn.Serial = L(b, v.Vo, take);
                    }
                    i = v.Next;
                    continue;
                }
            }
            if (t.Tag is 0x30 or 0x31) CollectAtv(b, t.Vo, t.Vo + t.Vl, outRdn, depth + 1);
            i = t.Next;
        }
    }

    static Rdn RdnOf(byte[] b, int start, int len)
    {
        var r = new Rdn();
        CollectAtv(b, start, Math.Min(start + len, b.Length), r, 0);
        return r;
    }

    /// 兜底扫描 "letters=printable{2,80}" — 取最后一个 key 恰为 CN/O/serialNumber 的
    static void ScanSubject(byte[] b, Rdn outRdn)
    {
        int n = b.Length, i = 0;
        (int off, int len)? cn = null, o = null, ser = null;
        while (i < n)
        {
            byte c0 = b[i];
            if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z'))) { i++; continue; }
            int j = i, k = 0;
            while (j < n && k < 32 && ((b[j] >= 'A' && b[j] <= 'Z') || (b[j] >= 'a' && b[j] <= 'z'))) { j++; k++; }
            int v = i;
            if (j < n && b[j] == (byte)'=')
            {
                v = j + 1;
                int vlen = 0;
                while (v < n && vlen < 80 && b[v] >= 0x20 && b[v] <= 0x7E) { v++; vlen++; }
                if (vlen >= 2)
                {
                    if (k == 2 && b[i] == 'C' && b[i + 1] == 'N') cn = (j + 1, vlen);
                    else if (k == 1 && b[i] == 'O') o = (j + 1, vlen);
                    else if (k == 12 && i + 12 <= n && Encoding.ASCII.GetString(b, i, 12) == "serialNumber") ser = (j + 1, vlen);
                }
            }
            i = v > j ? v : j + 1;
        }
        if (cn is { } c) outRdn.Cn = L(b, c.off, c.len);
        if (o is { } oo) outRdn.O = L(b, oo.off, oo.len);
        if (ser is { } s) outRdn.Serial = L(b, s.off, s.len);
    }

    // ---------------- 证书 ----------------

    sealed class CertPart
    {
        public required Rdn Sub;
        public required byte[] Serial;
        public bool SelfSigned;
    }

    static CertPart? CertParts(byte[] der)
    {
        if (!Ber(der, 0, der.Length, out var ot) || ot.Tag != 0x30) return null;
        if (!Ber(der, ot.Vo, der.Length, out var tbt)) return null;
        int start, end;
        if (tbt.Tag == 0x30) { start = tbt.Vo; end = tbt.Vo + tbt.Vl; }
        else if (tbt.Tag is 0xA0 or 0x80) { start = ot.Vo; end = ot.Next; }
        else return null;
        var elems = new List<Tlv>();
        int p2 = start;
        while (p2 < end && elems.Count < 64)
        {
            if (!Ber(der, p2, end, out var e)) break;
            elems.Add(e);
            p2 = e.Next;
        }
        int idx = elems.Count > 0 && elems[0].Tag is 0xA0 or 0x80 ? 1 : 0;
        if (elems.Count < idx + 5 || elems[idx].Tag != 0x02) return null;
        var serial = L(der, elems[idx].Vo, elems[idx].Vl);
        var iss = RdnOf(der, elems[idx + 2].Vo, elems[idx + 2].Vl);
        var sub = RdnOf(der, elems[idx + 4].Vo, elems[idx + 4].Vl);
        bool self = iss.Cn.AsSpan().SequenceEqual(sub.Cn) && iss.O.AsSpan().SequenceEqual(sub.O)
                    && iss.Serial.AsSpan().SequenceEqual(sub.Serial)
                    && !(iss.Cn.Length == 0 && iss.O.Length == 0 && iss.Serial.Length == 0);
        return new CertPart { Sub = sub, Serial = serial, SelfSigned = self };
    }

    // ---------------- Authenticode ----------------

    public struct AuthRes { public int Auth, Certs, SelfSigned, Blacklisted; }

    static int SignerBlacklisted(Rdn s)
    {
        var joined = new List<byte>();
        joined.AddRange(LowerLatin1(s.Cn));
        joined.Add((byte)' ');
        joined.AddRange(LowerLatin1(s.O));
        var joinedB = joined.ToArray();
        var serialB = LowerLatin1(s.Serial);
        foreach (var (word, certSerial) in AbusedSigners)
        {
            if (word.Length > 0 && Find(joinedB, Encoding.UTF8.GetBytes(word))) return 1;
            if (certSerial.Length > 0 && Find(serialB, Encoding.ASCII.GetBytes(certSerial))) return 1;
        }
        return 0;
    }

    static AuthRes ParseAuthenticode(string path, long fsize, long off, long sz)
    {
        var r = new AuthRes();
        if (off <= 0 || sz < 16 || off + sz > fsize) return r;
        var blob = ReadAt(path, off, (int)Math.Min(sz, AuthCap));
        if (blob == null || blob.Length < 8) return r;
        if (U16(blob, 4) != 0x0200 || U16(blob, 6) != 0x0002) return r;
        var pkcs = L(blob, 8, blob.Length - 8);
        if (!Ber(pkcs, 0, pkcs.Length, out var pk) || pk.Tag != 0x30) return r;
        if (!Ber(pkcs, pk.Vo, pkcs.Length, out var oid) || oid.Tag != 0x06) return r;
        int p = oid.Next;
        if (p >= pkcs.Length || pkcs[p] != 0xA0) return r;
        if (!Ber(pkcs, p, pkcs.Length, out var iv)) return r;
        var inner = L(pkcs, iv.Vo, iv.Vl);
        if (!Ber(inner, 0, inner.Length, out var top) || top.Tag != 0x30) return r;
        var fields = new List<Tlv>();
        var certs = new List<byte[]>();
        p = top.Vo;
        while (p < top.Vo + top.Vl && fields.Count < 32)
        {
            if (!Ber(inner, p, inner.Length, out var t)) break;
            fields.Add(t);
            if (t.Tag == 0xA0)
            {
                int cp = t.Vo;
                while (cp < t.Vo + t.Vl && certs.Count < 128)
                {
                    if (!Ber(inner, cp, inner.Length, out var c) || c.Tag != 0x30) break;
                    certs.Add(L(inner, c.Vo, c.Vl));
                    cp = c.Next;
                }
            }
            p = t.Next;
        }
        if (certs.Count == 0) return r;
        r.Auth = 1;
        r.Certs = certs.Count;
        var parts = certs.Select(CertParts).Where(x => x != null).Select(x => x!).ToList();
        if (parts.Count == 0) return r;
        // SignerInfo (最后一个可解析 0x31 SET) 的序列号 → 顺序无关锁叶子
        byte[]? signerSerial = null;
        for (int fi = fields.Count - 1; fi >= 0; fi--)
        {
            if (fields[fi].Tag != 0x31) continue;
            if (!Ber(inner, fields[fi].Vo, inner.Length, out var st) || st.Tag != 0x30) continue;
            if (!Ber(inner, st.Vo, inner.Length, out var ver) || ver.Tag != 0x02) continue;
            if (!Ber(inner, ver.Next, inner.Length, out var ias) || ias.Tag != 0x30) continue;
            if (!Ber(inner, ias.Vo, inner.Length, out var nm)) continue;
            int sp = nm.Next;
            while (sp < ias.Vo + ias.Vl)
            {
                if (!Ber(inner, sp, inner.Length, out var ser)) break;
                if (ser.Tag == 0x02) { signerSerial = L(inner, ser.Vo, ser.Vl); break; }
                sp = ser.Next;
            }
            if (signerSerial != null) break;
        }
        int leaf = 0;
        if (signerSerial != null)
            for (int i = 0; i < parts.Count; i++)
                if (parts[i].Serial.AsSpan().SequenceEqual(signerSerial)) { leaf = i; break; }
        r.SelfSigned = parts[leaf].SelfSigned ? 1 : 0;
        var signer = parts[leaf].Sub;
        if (signer.Empty)
        {
            // 与 Python 一致: 兜底扫描 (leaf 索引 = 过滤后 parts 的索引)
            ScanSubject(leaf < certs.Count ? certs[leaf] : [], signer);
            if (signer.Empty) ScanSubject(pkcs, signer);
        }
        r.Blacklisted = SignerBlacklisted(signer);
        return r;
    }

    // ---------------- 正则等价手扫 ----------------

    static bool IsWs(byte c) => c is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x0C or 0x0B;
    static bool IsDigit(byte c) => c >= '0' && c <= '9';

    static int CountC2IpPort(byte[] d)
    {
        int n = d.Length, i = 0, cnt = 0;
        while (i < n)
        {
            int j = i; bool ipok = true;
            for (int g = 0; g < 3; g++)
            {
                int gd = 0;
                while (j < n && IsDigit(d[j]) && gd < 3) { j++; gd++; }
                if (gd == 0 || j >= n || d[j] != (byte)'.') { ipok = false; break; }
                j++;
            }
            if (ipok)
            {
                int gd = 0;
                while (j < n && IsDigit(d[j]) && gd < 3) { j++; gd++; }
                if (gd > 0)
                {
                    int k = j;
                    while (k < n && IsWs(d[k])) k++;
                    if (k < n && d[k] is (byte)':' or (byte)'|' or (byte)',' or (byte)'.')
                    {
                        int m = k + 1;
                        while (m < n && IsWs(d[m])) m++;
                        if (m < n && IsDigit(d[m]))
                        {
                            int pd = 0;
                            while (m < n && IsDigit(d[m]) && pd < 5) { m++; pd++; }
                            cnt++;
                            i = m;
                            continue;
                        }
                    }
                }
            }
            i = j > i ? j : i + 1;
        }
        return cnt;
    }

    static int CountUrls(byte[] d)
    {
        int n = d.Length, i = 0, cnt = 0;
        while (i < n)
        {
            bool https = n - i >= 8 && d[i] == 'h' && d[i + 1] == 't' && d[i + 2] == 't' && d[i + 3] == 'p'
                         && d[i + 4] == 's' && d[i + 5] == ':' && d[i + 6] == '/' && d[i + 7] == '/';
            bool http = n - i >= 7 && d[i] == 'h' && d[i + 1] == 't' && d[i + 2] == 't' && d[i + 3] == 'p'
                        && d[i + 4] == ':' && d[i + 5] == '/' && d[i + 6] == '/';
            if (https || http)
            {
                int j = i + (https ? 8 : 7), k = j;
                while (k < n && d[k] != 0 && d[k] != (byte)'"' && d[k] != (byte)'\'' && d[k] != (byte)' ') k++;
                if (k > j) { cnt++; i = k; continue; }
            }
            i++;
        }
        return cnt;
    }

    static int CountStrings(byte[] d)
    {
        int n = d.Length, i = 0, cnt = 0;
        while (i < n)
        {
            if (d[i] >= 0x20 && d[i] <= 0x7E)
            {
                int j = i;
                while (j < n && d[j] >= 0x20 && d[j] <= 0x7E) j++;
                if (j - i >= 6) cnt++;
                i = j;
            }
            else i++;
        }
        return cnt;
    }

    // ---------------- 导入 DLL 数 (口径见下) ----------------

    /// 与训练端一致: ml/extract_features.py 把「数据目录[0] (导出表)」的 RVA 当导入描述符表
    /// 遍历 (unpack_from("<II", ...+112/96) 未 +8), 计数已固化进 model_linear.json.
    static int CountImportDlls(byte[] data, uint impRva, int secOff, int nsec)
    {
        if (impRva == 0) return 0;
        int nlen = data.Length;
        var secs = new List<(long Va, long Vsz, long Roff)>();
        for (int i = 0; i < nsec && i < 64 && secOff + i * 40 + 24 <= nlen; i++)
        {
            int s = secOff + i * 40;
            long vsize = U32(data, s + 8), vaddr = U32(data, s + 12);
            long rsize = U32(data, s + 16), roff = U32(data, s + 20);
            secs.Add((vaddr, Math.Max(vsize, rsize), roff));
        }
        long? Rva2Off(long rva)
        {
            foreach (var (va, vsz, roff) in secs)
                if (rva >= va && rva < va + vsz) return roff + (rva - va);
            return null;
        }
        var o = Rva2Off(impRva);
        if (o == null) return 0;
        var dlls = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < 2048; i++)
        {
            long off = o.Value + i * 20;
            if (off < 0 || off + 20 > nlen) break;
            uint oft = U32(data, (int)off), nameRva = U32(data, (int)off + 12);
            if (oft == 0 && nameRva == 0) break;
            if (nameRva != 0)
            {
                var no = Rva2Off(nameRva);
                if (no is { } n0 && n0 >= 0 && n0 < nlen)
                {
                    int st = (int)n0;
                    int end = Math.Min(st + 64, nlen), e = st;
                    while (e < end && data[e] != 0) e++;
                    if (e > st)
                    {
                        var raw = L(data, st, e - st);
                        dlls.Add(Encoding.Latin1.GetString(LowerLatin1(raw)));
                    }
                }
            }
        }
        return dlls.Count;
    }

    // ---------------- 22 特征 (顺序 = MlModel.Features) ----------------

    public static double[]? Extract(string path)
    {
        byte[] data;
        long flen;
        try
        {
            using var f = File.OpenRead(path);
            flen = f.Length;
            int n = (int)Math.Min(flen, ReadLimit);
            data = new byte[n];
            int got = f.ReadAtLeast(data, n, throwOnEndOfStream: false);
            if (got != n) return null;
        }
        catch { return null; }
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return null;
        int e_lfanew = (int)U32(data, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 4 > data.Length) return null;
        if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E' || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0) return null;
        int off = e_lfanew + 4;
        if (off + 24 > data.Length) return null;
        int nsec = (int)U16(data, off + 2);
        int optsz = (int)U16(data, off + 16);
        uint magic = U16(data, e_lfanew + 24);
        bool is64 = magic == 0x20B;
        if (magic != 0x10B && magic != 0x20B) return null;
        int opt = e_lfanew + 24;
        if (opt + 20 > data.Length) return null;
        long epRva = U32(data, opt + 16);
        int secOff = e_lfanew + 4 + 20 + optsz;

        var secEnts = new List<double>();
        var secEnt4 = new List<double>();
        var secNames = new List<string>();
        var secVsz = new List<long>();
        var secRsz = new List<long>();
        var secVa = new List<long>();
        for (int i = 0; i < nsec && i < 128 && secOff + i * 40 + 24 <= data.Length; i++)
        {
            int s = secOff + i * 40;
            secNames.Add(Encoding.Latin1.GetString(data, s, 8).TrimEnd('\0'));
            long vsize = U32(data, s + 8), vaddr = U32(data, s + 12);
            long rsize = U32(data, s + 16), roff = U32(data, s + 20);
            // Python: entropy(data[roff : roff+min(rsize,1MB)]) — 截断到窗口内, 空=0.0
            long start = Math.Max(roff, 0);
            long want = Math.Min(rsize, 1 << 20);
            long end = Math.Min(start + Math.Max(want, 0), data.Length);
            double e = start >= data.Length || end <= start ? 0.0 : Entropy(data.AsSpan((int)start, (int)(end - start)));
            secEnts.Add(e);
            secEnt4.Add(Round4(e));
            secVsz.Add(vsize);
            secRsz.Add(rsize);
            secVa.Add(vaddr);
        }
        int nsecs = secNames.Count;
        var x = new double[28];

        x[0] = Contains(data, "Go build ID:") ? 1 : 0;
        x[1] = Contains(data, "golang.org") || Contains(data, "runtime.main") || Contains(data, "main.main") ? 1 : 0;
        int unusual = 0;
        bool hasFptable = false;
        for (int i = 0; i < nsecs; i++)
        {
            var nm = secNames[i];
            if (nm.Length > 0 && !nm.StartsWith('.')) unusual++;
            var low = nm.ToLowerInvariant();
            if (low.Contains("fptable") || low == ".fpt" || low == ".fptable") hasFptable = true;
        }
        x[2] = unusual;
        int sus = 0;
        foreach (var a in LowApiNames) if (Contains(data, a)) sus++;
        x[3] = sus;
        x[4] = InjApis.Any(a => Contains(data, a)) ? 1 : 0;
        x[5] = PersApis.Any(a => Contains(data, a)) ? 1 : 0;
        x[6] = NetApis.Any(a => Contains(data, a)) ? 1 : 0;
        x[7] = nsecs > 0 ? Round4(secEnts.Max()) : 0.0;
        x[8] = CountStrings(data);
        x[9] = Round4(Math.Log(flen + 1.0));
        x[10] = CountUrls(data);

        // n_import_dlls: RVA 取「数据目录[0]」— 复刻训练端口径
        int dd = opt + (is64 ? 112 : 96);
        uint impRva = dd + 4 <= data.Length ? U32(data, dd) : 0;
        x[14] = CountImportDlls(data, impRva, secOff, nsec);

        long secDirOff = 0, secDirSz = 0;
        if (dd + 32 + 8 <= data.Length)
        {
            secDirOff = U32(data, dd + 32);
            secDirSz = U32(data, dd + 36);
        }
        var auth = ParseAuthenticode(path, flen, secDirOff, secDirSz);
        x[11] = auth.Auth;
        x[12] = auth.Certs;
        x[13] = auth.SelfSigned;
        x[15] = auth.Blacklisted;
        x[16] = hasFptable && auth.Auth == 0 ? 1 : 0;

        int raw0 = 0, epRawless = 0;
        for (int i = 0; i < nsecs; i++)
        {
            var low = secNames[i].ToLowerInvariant();
            if (secVsz[i] > 0 && secRsz[i] == 0 && low != ".bss" && low != ".tls")
            {
                raw0++;
                long span = Math.Max(secVsz[i], 1);
                if (secVa[i] <= epRva && epRva < secVa[i] + span) epRawless = 1;
            }
        }
        x[17] = raw0;
        x[18] = epRawless;
        x[19] = CountC2IpPort(data);
        // 第一遍 (取整熵): ep_high_entropy
        double ep4 = 0;
        for (int i = 0; i < nsecs; i++)
        {
            long span = Math.Max(secVsz[i], 1);
            if (secVsz[i] > 0 && secVa[i] <= epRva && epRva < secVa[i] + span) { ep4 = secEnt4[i]; break; }
        }
        // 第二遍 (Python 最终覆盖): entry_section_entropy = 未取整熵, 无 vsz>0 限制
        double epf = 0;
        for (int i = 0; i < nsecs; i++)
        {
            long span = Math.Max(secVsz[i], 1);
            if (secVa[i] <= epRva && epRva < secVa[i] + span) { epf = secEnts[i]; break; }
        }
        x[20] = Round4(epf);
        x[21] = ep4 >= 7.5 ? 1 : 0;
        // 2026-09-25 新判别特征 (FEATURES[22..28])
        {
            var vsKeys = new[] { "CompanyName", "OriginalFilename", "FileDescription",
                                 "FileVersion", "ProductName", "LegalCopyright", "InternalName" }
                .Select(n => Encoding.Unicode.GetBytes(n)).ToArray();
            x[22] = vsKeys.Count(k => Find(data, k));
            x[23] = Find(data, "manifestVersion"u8.ToArray())
                    || Find(data, Encoding.Unicode.GetBytes("manifestVersion")) ? 1 : 0;
            int ddoff = opt + (is64 ? 112 : 96);
            int nrv = ddoff >= 4 ? (int)U32(data, ddoff - 4) : 0;
            uint D(int i) => nrv > i && ddoff + (i + 1) * 8 <= data.Length ? U32(data, ddoff + i * 8) : 0;
            x[24] = D(9) != 0 ? 1 : 0;
            x[25] = opt + 64 + 4 <= data.Length && U32(data, opt + 64) == 0 ? 1 : 0;
            x[26] = D(6) != 0 ? 1 : 0;
            x[27] = D(0) != 0 ? 1 : 0;
        }
        return x;
    }
}