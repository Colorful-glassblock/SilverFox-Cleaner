// ml_feat.rs — 静态 PE 特征提取 + 逻辑回归打分.
//
// 语义与 ml/extract_features.py 一致 (Python 端为 model_linear.json 的训练口径,
// 经 ml/parity_check.py 跨语言逐特征核对: C/Rust/C# 三版必须给出同一个分).
// 纯 std 实现 (无 ONNX 运行时): 22 个权重的逻辑回归等价于 ONNX 推理的数学本身,
// 且 C 版 (XP/msvcrt) 无法承载运行时 — 三版统一用内嵌权重才能保证同判.
//
// 关键口径 (勿"修正", 模型是按这些语义训练的):
//   - 读取窗口 前 4MB; 节熵 = entropy(data[roff .. roff+min(rsize,1MB)]) 截断到窗口内, 空=0.0
//   - suspicious_apis 只数列表里本就小写的条目 present (socket/connect/recv/send)
//   - has_injection/persistence/net 用各自精确名单 (区分大小写字节包含)
//   - n_import_dlls 的 RVA 取「数据目录[0]」(导出表) — 复刻训练端 unpack_from(...+112/96) 未 +8
//   - entry_section_entropy 用未取整熵再 round4; ep_high_entropy 用取整熵 >= 7.5
//   - authenticode: 最小 BER/PKCS7 + SignerInfo 序列号锁叶子 + RDN OID + 兜底扫描
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::ml_model::{SFC_ML_B, SFC_ML_MEANS, SFC_ML_N, SFC_ML_STDS, SFC_ML_W};

const READ_LIMIT: usize = 4 << 20; // 特征窗口
const AUTH_CAP: usize = 8 << 20;   // SECURITY 目录读取上限

// 22 特征索引 (顺序 = ml_model.rs SFC_ML_FEATURES)
pub const F_HAS_GO_BUILDID: usize = 0;
pub const F_HAS_GOLANG: usize = 1;
pub const F_UNUSUAL_SECTIONS: usize = 2;
pub const F_SUSPICIOUS_APIS: usize = 3;
pub const F_HAS_INJECTION_API: usize = 4;
pub const F_HAS_PERSISTENCE_API: usize = 5;
pub const F_HAS_NET_API: usize = 6;
pub const F_MAX_SECTION_ENTROPY: usize = 7;
pub const F_N_STRINGS: usize = 8;
pub const F_LOG_SIZE: usize = 9;
pub const F_N_URLS: usize = 10;
pub const F_HAS_AUTHENTICODE: usize = 11;
pub const F_CERT_COUNT: usize = 12;
pub const F_IS_SELF_SIGNED: usize = 13;
pub const F_N_IMPORT_DLLS: usize = 14;
pub const F_SIGNER_BLACKLISTED: usize = 15;
pub const F_FPTABLE_UNSIGNED: usize = 16;
pub const F_EMPTY_RAW_SECTIONS: usize = 17;
pub const F_ENTRY_IN_RAWLESS: usize = 18;
pub const F_C2_IP_PORT: usize = 19;
pub const F_ENTRY_SECTION_ENTROPY: usize = 20;
pub const F_EP_HIGH_ENTROPY: usize = 21;

/* ---------------- 小工具 ---------------- */

fn entropy(d: &[u8]) -> f64 {
    if d.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in d {
        counts[b as usize] += 1;
    }
    let n = d.len() as f64;
    let mut e = 0.0f64;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / n;
        e -= p * p.log2();
    }
    e
}

/// Python round(x, 4): 半数取偶
fn round4(x: f64) -> f64 {
    let s = x * 1e4;
    let r = s.floor();
    let frac = s - r;
    let r = if frac > 0.5 {
        r + 1.0
    } else if frac == 0.5 {
        if (r % 2.0) != 0.0 {
            r + 1.0
        } else {
            r
        }
    } else {
        r
    };
    r / 1e4
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn contains(hay: &[u8], s: &str) -> bool {
    find(hay, s.as_bytes())
}

fn read_at(path: &Path, off: u64, sz: usize, cap: usize) -> Option<Vec<u8>> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if off >= len {
        return None;
    }
    let want = sz.min(cap);
    if want == 0 {
        return None;
    }
    f.seek(SeekFrom::Start(off)).ok()?;
    let mut b = vec![0u8; want];
    let mut got = 0usize;
    while got < want {
        match f.read(&mut b[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => break,
        }
    }
    if got == 0 {
        return None;
    }
    b.truncate(got);
    Some(b)
}

fn rd_u16(b: &[u8], o: usize) -> u16 {
    (b[o] as u16) | ((b[o + 1] as u16) << 8)
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    (b[o] as u32) | ((b[o + 1] as u32) << 8) | ((b[o + 2] as u32) << 16) | ((b[o + 3] as u32) << 24)
}

/* ---------------- BER TLV (对齐 Python _ber_tlv) ---------------- */

/// (tag, value_offset, value_len, next)
fn ber_tlv(b: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    if pos + 2 > b.len() {
        return None;
    }
    let tag = b[pos];
    let mut ln = b[pos + 1] as usize;
    let mut p = pos + 2;
    if ln == 0x80 {
        return None; // 不定长不接受
    }
    if ln & 0x80 != 0 {
        let nb = ln & 0x7F;
        if nb == 0 || nb > 4 || p + nb > b.len() {
            return None;
        }
        let mut v: u64 = 0;
        for k in 0..nb {
            v = (v << 8) | b[p + k] as u64;
        }
        p += nb;
        if v > i32::MAX as u64 {
            return None;
        }
        ln = v as usize;
    }
    if p + ln > b.len() {
        return None;
    }
    Some((tag, p, ln, p + ln))
}

/* ---------------- RDN 属性 (CN / O / serialNumber) ---------------- */

#[derive(Default, Clone, PartialEq)]
pub struct Rdn {
    pub cn: Vec<u8>,
    pub o: Vec<u8>,
    pub serial: Vec<u8>,
}

impl Rdn {
    fn empty(&self) -> bool {
        self.cn.is_empty() && self.o.is_empty() && self.serial.is_empty()
    }
}

fn collect_atv(b: &[u8], start: usize, end: usize, out: &mut Rdn, depth: u32) {
    if depth > 12 {
        return;
    }
    let mut i = start;
    while i < end {
        let (tag, vo, vl, nxt) = match ber_tlv(&b[..end.min(b.len())], i) {
            Some(t) => t,
            None => break,
        };
        if tag == 0x06 && nxt < end {
            let oid = &b[vo..(vo + vl).min(b.len())];
            if let Some((vt, vvo, vvl, vn)) = ber_tlv(&b[..end.min(b.len())], nxt) {
                if matches!(vt, 0x0C | 0x13 | 0x16 | 0x1E | 0x12) {
                    let v = &b[vvo..(vvo + vvl).min(b.len())];
                    let take = &v[..v.len().min(127)];
                    if oid.len() >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x03 && out.cn.is_empty() {
                        out.cn = take.to_vec();
                    } else if oid.len() >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x0A && out.o.is_empty() {
                        out.o = take.to_vec();
                    } else if oid.len() >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x05 && out.serial.is_empty() {
                        out.serial = take.to_vec();
                    }
                    i = vn;
                    continue;
                }
            }
        }
        if tag == 0x30 || tag == 0x31 {
            collect_atv(b, vo, vo + vl, out, depth + 1);
        }
        i = nxt;
    }
}

fn rdn_of(b: &[u8], start: usize, len: usize) -> Rdn {
    let mut out = Rdn::default();
    let end = (start + len).min(b.len());
    collect_atv(b, start.min(b.len()), end, &mut out, 0);
    out
}

fn is_letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// 兜底扫描: "letters=printable{2,80}", 取最后一个 key 恰为 CN/O/serialNumber 的
fn scan_subject(b: &[u8], out: &mut Rdn) {
    let n = b.len();
    let mut i = 0usize;
    let mut last: [Option<(usize, usize)>; 3] = [None, None, None];
    while i < n {
        if !is_letter(b[i]) {
            i += 1;
            continue;
        }
        let mut j = i;
        let mut k = 0usize;
        while j < n && k < 32 && is_letter(b[j]) {
            j += 1;
            k += 1;
        }
        let mut v = i;
        if j < n && b[j] == b'=' {
            v = j + 1;
            let mut vlen = 0usize;
            while v < n && vlen < 80 && (0x20..=0x7E).contains(&b[v]) {
                v += 1;
                vlen += 1;
            }
            if vlen >= 2 {
                if k == 2 && b[i] == b'C' && b[i + 1] == b'N' {
                    last[0] = Some((j + 1, vlen));
                } else if k == 1 && b[i] == b'O' {
                    last[1] = Some((j + 1, vlen));
                } else if k == 12 && &b[i..(i + 12).min(n)] == b"serialNumber" {
                    last[2] = Some((j + 1, vlen));
                }
            }
        }
        i = if v > j { v } else { j + 1 };
    }
    if let Some((o, l)) = last[0] {
        out.cn = b[o..o + l].to_vec();
    }
    if let Some((o, l)) = last[1] {
        out.o = b[o..o + l].to_vec();
    }
    if let Some((o, l)) = last[2] {
        out.serial = b[o..o + l].to_vec();
    }
}

/* ---------------- 证书解析 ---------------- */

struct CertPart {
    sub: Rdn,
    serial: Vec<u8>,
    self_signed: bool,
}

fn cert_parts(der: &[u8]) -> Option<CertPart> {
    let (ot, oo, _ol, on) = ber_tlv(der, 0)?;
    if ot != 0x30 {
        return None;
    }
    let (tbt, tbo, tbl, _tbn) = ber_tlv(der, oo)?;
    let (start, end) = if tbt == 0x30 {
        (tbo, tbo + tbl)
    } else if tbt == 0xA0 || tbt == 0x80 {
        (oo, on)
    } else {
        return None;
    };
    let mut elems: Vec<(u8, usize, usize, usize)> = Vec::new();
    let mut p2 = start;
    while p2 < end && elems.len() < 64 {
        match ber_tlv(der, p2) {
            Some(e) => {
                elems.push(e);
                p2 = e.3;
            }
            None => break,
        }
    }
    let idx = if !elems.is_empty() && (elems[0].0 == 0xA0 || elems[0].0 == 0x80) { 1 } else { 0 };
    if elems.len() < idx + 5 || elems[idx].0 != 0x02 {
        return None;
    }
    let serial = der[elems[idx].1..elems[idx].1 + elems[idx].2].to_vec();
    let iss = rdn_of(der, elems[idx + 2].1, elems[idx + 2].2);
    let sub = rdn_of(der, elems[idx + 4].1, elems[idx + 4].2);
    let self_signed = iss == sub && !(iss.cn.is_empty() && iss.o.is_empty() && iss.serial.is_empty());
    Some(CertPart { sub, serial, self_signed })
}

/* ---------------- Authenticode (对齐 Python _parse_authenticode) ---------------- */

const ABUSED_WORDS: [&str; 9] = ["贝锐", "awesun", "oray", "duojiayu", "多加鱼", "dingtalk", "钉钉", "iray", "alibaba"];
const ABUSED_SERIALS: [&str; 9] = [
    "91310110787862412b", "91310110787862412b", "", "91510107maacgc6jxl", "",
    "91330110ma2b00r29g", "", "", "91330100716105852f",
];

pub struct AuthRes {
    pub auth: i32,
    pub certs: i32,
    pub self_signed: i32,
    pub blacklisted: i32,
}

fn lower_latin1(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&c| {
            if c.is_ascii_uppercase() {
                c + 32
            } else if (0xC0..=0xDE).contains(&c) && c != 0xD7 {
                c + 32
            } else {
                c
            }
        })
        .collect()
}

/// Python: bytes.decode("latin1").lower() — 每字节一个码位, 非法序列不会被折叠
fn latin1_string_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect::<String>().to_lowercase()
}

/// 黑名单按「UTF-8 字节子串」比对: 证书里的中文 CN 是 UTF-8 字节, 与 Python 端
/// (_dec 优先 UTF-8 解码后 str 比对) 等价; 不做 latin1 解码以免中文变摩斯码.
fn signer_blacklisted(s: &Rdn) -> i32 {
    let mut joined = lower_latin1(&s.cn);
    joined.push(b' ');
    joined.extend_from_slice(&lower_latin1(&s.o));
    let serial = lower_latin1(&s.serial);
    for i in 0..ABUSED_WORDS.len() {
        if !ABUSED_WORDS[i].is_empty() && find(&joined, ABUSED_WORDS[i].as_bytes()) {
            return 1;
        }
        if !ABUSED_SERIALS[i].is_empty() && find(&serial, ABUSED_SERIALS[i].as_bytes()) {
            return 1;
        }
    }
    0
}

fn parse_authenticode(path: &Path, fsize: u64, off: i64, sz: i64) -> AuthRes {
    let mut r = AuthRes { auth: 0, certs: 0, self_signed: 0, blacklisted: 0 };
    if off <= 0 || sz < 16 || off as u64 + sz as u64 > fsize {
        return r;
    }
    let blob = match read_at(path, off as u64, sz as usize, AUTH_CAP) {
        Some(b) if b.len() >= 8 => b,
        _ => return r,
    };
    // WIN_CERTIFICATE: dwLength(4) wRevision(2)=0x0200 wCertificateType(2)=0x0002
    if rd_u16(&blob, 4) != 0x0200 || rd_u16(&blob, 6) != 0x0002 {
        return r;
    }
    let pkcs = &blob[8..];
    let (tag, vo, _vl, _nxt) = match ber_tlv(pkcs, 0) {
        Some(t) if t.0 == 0x30 => t,
        _ => return r,
    };
    let _ = tag;
    let oid = match ber_tlv(pkcs, vo) {
        Some(t) if t.0 == 0x06 => t,
        _ => return r,
    };
    let p = oid.3;
    if p >= pkcs.len() || pkcs[p] != 0xA0 {
        return r;
    }
    let iv = match ber_tlv(pkcs, p) {
        Some(t) => t,
        None => return r,
    };
    let inner = &pkcs[iv.1..iv.1 + iv.2];
    let top = match ber_tlv(inner, 0) {
        Some(t) if t.0 == 0x30 => t,
        _ => return r,
    };
    let mut fields: Vec<(u8, usize, usize, usize)> = Vec::new();
    let mut certs: Vec<&[u8]> = Vec::new();
    let mut p = top.1;
    while p < top.1 + top.2 && fields.len() < 32 {
        let t = match ber_tlv(inner, p) {
            Some(t) => t,
            None => break,
        };
        fields.push(t);
        if t.0 == 0xA0 {
            let mut cp = t.1;
            while cp < t.1 + t.2 && certs.len() < 128 {
                match ber_tlv(inner, cp) {
                    Some(c) if c.0 == 0x30 => {
                        certs.push(&inner[c.1..c.1 + c.2]);
                        cp = c.3;
                    }
                    _ => break,
                }
            }
        }
        p = t.3;
    }
    if certs.is_empty() {
        return r;
    }
    r.auth = 1;
    r.certs = certs.len() as i32;

    let parts: Vec<CertPart> = certs.iter().filter_map(|c| cert_parts(c)).collect();
    if parts.is_empty() {
        return r;
    }
    // SignerInfo (最后一个可解析 0x31 SET) 里的序列号 → 顺序无关锁叶子
    let mut signer_serial: Option<Vec<u8>> = None;
    for fi in (0..fields.len()).rev() {
        if fields[fi].0 != 0x31 {
            continue;
        }
        let st = match ber_tlv(inner, fields[fi].1) {
            Some(t) if t.0 == 0x30 => t,
            _ => continue,
        };
        let ver = match ber_tlv(inner, st.1) {
            Some(t) if t.0 == 0x02 => t,
            _ => continue,
        };
        let ias = match ber_tlv(inner, ver.3) {
            Some(t) if t.0 == 0x30 => t,
            _ => continue,
        };
        let nm = match ber_tlv(inner, ias.1) {
            Some(t) => t,
            None => continue,
        };
        let mut sp = nm.3;
        while sp < ias.1 + ias.2 {
            match ber_tlv(inner, sp) {
                Some(s) if s.0 == 0x02 => {
                    signer_serial = Some(inner[s.1..s.1 + s.2].to_vec());
                    break;
                }
                Some(s) => sp = s.3,
                None => break,
            }
        }
        if signer_serial.is_some() {
            break;
        }
    }
    let mut leaf = 0usize;
    if let Some(ss) = &signer_serial {
        for (i, pp) in parts.iter().enumerate() {
            if &pp.serial == ss {
                leaf = i;
                break;
            }
        }
    }
    let lp = &parts[leaf];
    r.self_signed = if lp.self_signed { 1 } else { 0 };
    let mut signer = lp.sub.clone();
    if signer.empty() {
        // 与 Python 一致: 兜底扫描 (leaf 索引 = 过滤后 parts 的索引)
        scan_subject(certs.get(leaf).copied().unwrap_or(&[]), &mut signer);
        if signer.empty() {
            scan_subject(pkcs, &mut signer);
        }
    }
    r.blacklisted = signer_blacklisted(&signer);
    r
}

/* ---------------- 正则等价手扫 ---------------- */

fn is_ws(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' || c == 0x0C || c == 0x0B
}

fn count_c2_ip_port(d: &[u8]) -> i32 {
    let n = d.len();
    let mut i = 0usize;
    let mut cnt = 0i32;
    while i < n {
        let mut j = i;
        let mut ipok = true;
        for _ in 0..3 {
            let mut gd = 0;
            while j < n && d[j].is_ascii_digit() && gd < 3 {
                j += 1;
                gd += 1;
            }
            if gd == 0 || j >= n || d[j] != b'.' {
                ipok = false;
                break;
            }
            j += 1;
        }
        if ipok {
            let mut gd = 0;
            while j < n && d[j].is_ascii_digit() && gd < 3 {
                j += 1;
                gd += 1;
            }
            if gd > 0 {
                let mut k = j;
                while k < n && is_ws(d[k]) {
                    k += 1;
                }
                if k < n && matches!(d[k], b':' | b'|' | b',' | b'.') {
                    let mut m = k + 1;
                    while m < n && is_ws(d[m]) {
                        m += 1;
                    }
                    if m < n && d[m].is_ascii_digit() {
                        let mut pd = 0;
                        while m < n && d[m].is_ascii_digit() && pd < 5 {
                            m += 1;
                            pd += 1;
                        }
                        cnt += 1;
                        i = m;
                        continue;
                    }
                }
            }
        }
        i = if j > i { j } else { i + 1 };
    }
    cnt
}

fn count_urls(d: &[u8]) -> i32 {
    let n = d.len();
    let mut i = 0usize;
    let mut cnt = 0i32;
    while i < n {
        let https = n - i >= 8 && &d[i..i + 8] == b"https://";
        let http = n - i >= 7 && &d[i..i + 7] == b"http://";
        if https || http {
            let j = i + if https { 8 } else { 7 };
            let mut k = j;
            while k < n && d[k] != 0 && d[k] != b'"' && d[k] != b'\'' && d[k] != b' ' {
                k += 1;
            }
            if k > j {
                cnt += 1;
                i = k;
                continue;
            }
        }
        i += 1;
    }
    cnt
}

fn count_strings(d: &[u8]) -> i32 {
    let n = d.len();
    let mut i = 0usize;
    let mut cnt = 0i32;
    while i < n {
        if (0x20..=0x7E).contains(&d[i]) {
            let mut j = i;
            while j < n && (0x20..=0x7E).contains(&d[j]) {
                j += 1;
            }
            if j - i >= 6 {
                cnt += 1;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    cnt
}

/* ---------------- 导入 DLL 数 (口径见下) ---------------- */

/// 注意: 与训练端一致 —— ml/extract_features.py 把「数据目录[0] (导出表)」的 RVA
/// 当导入描述符表遍历 (unpack_from("<II", ...+112/96) 未 +8), 其计数已固化进
/// model_linear.json 的 means/stds/w (w=+1.49). 调用方须传 dir[0] 的 RVA.
fn count_import_dlls(data: &[u8], imp_rva: u32, sec_off: usize, nsec: u16) -> i32 {
    if imp_rva == 0 {
        return 0;
    }
    let nlen = data.len();
    let mut secs: Vec<(i64, i64, i64)> = Vec::new(); // (vaddr, max(vsize,rsize), roff)
    let mut i = 0usize;
    while i < nsec as usize && i < 64 && sec_off + i * 40 + 24 <= nlen {
        let s = sec_off + i * 40;
        let vsize = rd_u32(data, s + 8) as i64;
        let vaddr = rd_u32(data, s + 12) as i64;
        let rsize = rd_u32(data, s + 16) as i64;
        let roff = rd_u32(data, s + 20) as i64;
        secs.push((vaddr, vsize.max(rsize), roff));
        i += 1;
    }
    let rva2off = |rva: i64| -> Option<i64> {
        for (va, vsz, roff) in secs.iter() {
            if rva >= *va && rva < *va + *vsz {
                return Some(roff + (rva - va));
            }
        }
        None
    };
    let o = match rva2off(imp_rva as i64) {
        Some(v) => v,
        None => return 0,
    };
    let mut dlls: Vec<String> = Vec::new();
    for i in 0..2048usize {
        let off = o + (i * 20) as i64;
        if off < 0 || off as usize + 20 > nlen {
            break;
        }
        let off = off as usize;
        let oft = rd_u32(data, off);
        let name_rva = rd_u32(data, off + 12);
        if oft == 0 && name_rva == 0 {
            break;
        }
        if name_rva != 0 {
            if let Some(no) = rva2off(name_rva as i64) {
                if no >= 0 && (no as usize) < nlen {
                    let no = no as usize;
                    let end = (no + 64).min(nlen);
                    let mut e = no;
                    while e < end && data[e] != 0 {
                        e += 1;
                    }
                    let raw = &data[no..e];
                    if !raw.is_empty() {
                        let name = latin1_string_lower(raw);
                        if !dlls.iter().any(|d| *d == name) {
                            dlls.push(name);
                        }
                    }
                }
            }
        }
    }
    dlls.len() as i32
}

/* ---------------- 22 特征提取 ---------------- */

pub fn ml_feat_extract(path: &Path) -> Option<[f64; SFC_ML_N]> {
    let mut f = File::open(path).ok()?;
    let flen = f.metadata().ok()?.len();
    let nlen = (flen as usize).min(READ_LIMIT);
    let mut data = vec![0u8; nlen];
    let mut got = 0usize;
    while got < nlen {
        match f.read(&mut data[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    if got != nlen {
        return None;
    }
    if nlen < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let e_lfanew = rd_u32(&data, 0x3C) as usize;
    if e_lfanew + 4 > nlen || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let off = e_lfanew + 4;
    if off + 24 > nlen {
        return None;
    }
    let nsec = rd_u16(&data, off + 2);
    let optsz = rd_u16(&data, off + 16) as usize;
    let magic = rd_u16(&data, e_lfanew + 24);
    let is64 = magic == 0x20B;
    if magic != 0x10B && magic != 0x20B {
        return None;
    }
    let opt = e_lfanew + 24;
    if opt + 20 > nlen {
        return None;
    }
    let ep_rva = rd_u32(&data, opt + 16) as i64;
    let sec_off = e_lfanew + 4 + 20 + optsz;

    let mut sec_ents: Vec<f64> = Vec::new();
    let mut sec_entropy4: Vec<f64> = Vec::new();
    let mut sec_names: Vec<[u8; 9]> = Vec::new();
    let mut sec_vsz: Vec<i64> = Vec::new();
    let mut sec_rsz: Vec<i64> = Vec::new();
    let mut sec_va: Vec<i64> = Vec::new();
    let mut i = 0usize;
    while i < nsec as usize && i < 128 && sec_off + i * 40 + 24 <= nlen {
        let s = sec_off + i * 40;
        let mut nm = [0u8; 9];
        let mut j = 0usize;
        while j < 8 && data[s + j] != 0 {
            nm[j] = data[s + j];
            j += 1;
        }
        sec_names.push(nm);
        let vsize = rd_u32(&data, s + 8) as i64;
        let vaddr = rd_u32(&data, s + 12) as i64;
        let rsize = rd_u32(&data, s + 16) as i64;
        let roff = rd_u32(&data, s + 20) as i64;
        // Python: entropy(data[roff : roff+min(rsize,1MB)]) — 截断到窗口内, 空=0.0
        let start = roff.max(0) as usize;
        let want = (rsize.min(1 << 20)).max(0) as usize;
        let end = (start + want).min(nlen);
        let e = if start >= nlen || end <= start { 0.0 } else { entropy(&data[start..end]) };
        sec_ents.push(e);
        sec_entropy4.push(round4(e));
        sec_vsz.push(vsize);
        sec_rsz.push(rsize);
        sec_va.push(vaddr);
        i += 1;
    }
    let nsecs = sec_names.len();

    let mut out = [0.0f64; SFC_ML_N];
    let name_str = |idx: usize| -> String {
        let nm = &sec_names[idx];
        let l = nm.iter().position(|&c| c == 0).unwrap_or(8);
        String::from_utf8_lossy(&nm[..l]).to_string()
    };
    out[F_HAS_GO_BUILDID] = if contains(&data, "Go build ID:") { 1.0 } else { 0.0 };
    out[F_HAS_GOLANG] = if contains(&data, "golang.org") || contains(&data, "runtime.main") || contains(&data, "main.main") {
        1.0
    } else {
        0.0
    };
    let mut has_fptable = 0.0;
    let mut unusual = 0.0;
    for idx in 0..nsecs {
        let nm = name_str(idx);
        if !nm.is_empty() && !nm.starts_with('.') {
            unusual += 1.0;
        }
        let low = nm.to_lowercase();
        if low.contains("fptable") || low == ".fpt" || low == ".fptable" {
            has_fptable = 1.0;
        }
    }
    out[F_UNUSUAL_SECTIONS] = unusual;

    // suspicious_apis: 只数列表里本就小写的条目 (socket/connect/recv/send) —— 训练端口径
    const LOW_APIS: [&str; 4] = ["socket", "connect", "recv", "send"];
    let mut sus = 0.0;
    for a in LOW_APIS.iter() {
        if contains(&data, a) {
            sus += 1.0;
        }
    }
    out[F_SUSPICIOUS_APIS] = sus;
    const INJ: [&str; 6] = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtUnmapViewOfSection"];
    const PERS: [&str; 6] = ["RegSetValueEx", "RegCreateKeyEx", "CreateService", "StartService", "SetWindowsHookEx", "SetWindowsHookExW"];
    const NET: [&str; 4] = ["URLDownloadToFile", "InternetOpen", "InternetOpenUrl", "HttpSendRequest"];
    out[F_HAS_INJECTION_API] = if INJ.iter().any(|a| contains(&data, a)) { 1.0 } else { 0.0 };
    out[F_HAS_PERSISTENCE_API] = if PERS.iter().any(|a| contains(&data, a)) { 1.0 } else { 0.0 };
    out[F_HAS_NET_API] = if NET.iter().any(|a| contains(&data, a)) { 1.0 } else { 0.0 };
    out[F_MAX_SECTION_ENTROPY] = if nsecs > 0 {
        round4(sec_ents.iter().cloned().fold(f64::MIN, f64::max))
    } else {
        0.0
    };
    out[F_N_STRINGS] = count_strings(&data) as f64;
    out[F_LOG_SIZE] = round4((flen as f64).ln_1p());
    out[F_N_URLS] = count_urls(&data) as f64;

    // n_import_dlls: RVA 取「数据目录[0]」— 复刻训练端口径 (见 count_import_dlls 注释)
    let dd = opt + if is64 { 112 } else { 96 };
    let mut imp_rva = 0u32;
    if dd + 4 <= nlen {
        imp_rva = rd_u32(&data, dd);
    }
    out[F_N_IMPORT_DLLS] = count_import_dlls(&data, imp_rva, sec_off, nsec) as f64;

    // SECURITY 目录 (数据目录[4], 文件偏移)
    let mut sec_dir_off = 0i64;
    let mut sec_dir_sz = 0i64;
    if dd + 32 + 8 <= nlen {
        sec_dir_off = rd_u32(&data, dd + 32) as i64;
        sec_dir_sz = rd_u32(&data, dd + 36) as i64;
    }
    let auth = parse_authenticode(path, flen, sec_dir_off, sec_dir_sz);
    out[F_HAS_AUTHENTICODE] = auth.auth as f64;
    out[F_CERT_COUNT] = auth.certs as f64;
    out[F_IS_SELF_SIGNED] = auth.self_signed as f64;
    out[F_SIGNER_BLACKLISTED] = auth.blacklisted as f64;
    out[F_FPTABLE_UNSIGNED] = if has_fptable == 1.0 && auth.auth == 0 { 1.0 } else { 0.0 };

    let mut raw0 = 0.0;
    let mut ep_rawless = 0.0;
    for idx in 0..nsecs {
        let low = name_str(idx).to_lowercase();
        if sec_vsz[idx] > 0 && sec_rsz[idx] == 0 && low != ".bss" && low != ".tls" {
            raw0 += 1.0;
            let span = sec_vsz[idx].max(1);
            if sec_va[idx] <= ep_rva && ep_rva < sec_va[idx] + span {
                ep_rawless = 1.0;
            }
        }
    }
    out[F_EMPTY_RAW_SECTIONS] = raw0;
    out[F_ENTRY_IN_RAWLESS] = ep_rawless;
    out[F_C2_IP_PORT] = count_c2_ip_port(&data) as f64;
    // 第一遍 (Python 取整熵): ep_high_entropy
    let mut ep4 = 0.0;
    for idx in 0..nsecs {
        let span = sec_vsz[idx].max(1);
        if sec_vsz[idx] > 0 && sec_va[idx] <= ep_rva && ep_rva < sec_va[idx] + span {
            ep4 = sec_entropy4[idx];
            break;
        }
    }
    // 第二遍 (Python 最终覆盖): entry_section_entropy = 未取整熵, 无 vsz>0 限制
    let mut epf = 0.0;
    for idx in 0..nsecs {
        let span = sec_vsz[idx].max(1);
        if sec_va[idx] <= ep_rva && ep_rva < sec_va[idx] + span {
            epf = sec_ents[idx];
            break;
        }
    }
    out[F_ENTRY_SECTION_ENTROPY] = round4(epf);
    out[F_EP_HIGH_ENTROPY] = if ep4 >= 7.5 { 1.0 } else { 0.0 };
    Some(out)
}

/* ---------------- 逻辑回归打分 ---------------- */

/// Some(p) 概率 [0,1]; None = 非 PE / 读取失败 (调用方保持原结构匹配判定)
pub fn ml_score(path: &Path) -> Option<f64> {
    let x = ml_feat_extract(path)?;
    let mut z = SFC_ML_B;
    for i in 0..SFC_ML_N {
        z += SFC_ML_W[i] * ((x[i] - SFC_ML_MEANS[i]) / SFC_ML_STDS[i]);
    }
    let zc = z.clamp(-50.0, 50.0);
    Some(1.0 / (1.0 + (-zc).exp()))
}