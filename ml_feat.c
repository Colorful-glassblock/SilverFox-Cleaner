/* ml_feat.c — 静态 PE 特征提取 + 逻辑回归打分.
 * 语义对齐 ml/extract_features.py (Python 端为模型训练口径, 经 score_pe.py 跨语言核对):
 *   - 读取窗口: 前 4MB
 *   - suspicious_apis 只数列表里本就小写的条目 present (socket/connect/recv/send)
 *   - has_injection/persistence/net 用各自精确名单 (大小写敏感字节包含)
 *   - 节熵: entropy(data[roff : roff+min(rsize,1MB)]) 截断到窗口内, 空节熵 0.0,
 *     所有能解析的节都进 sec_ents (Python 语义, 非"仅窗口内才计入")
 *   - entry_section_entropy 用未取整熵 (再 round4), ep_high_entropy 用 4 位取整熵 >= 7.5
 *   - log_size = round(log1p(size), 4)
 *   - authenticode: 最小 BER/PKCS7 + SignerInfo 序列号锁叶子 + RDN OID + _scan_subject 兜底
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "ml_feat.h"

#ifndef _WIN32
#define _snprintf snprintf
#endif

#define READ_LIMIT (4 << 20)   /* 特征窗口 4MB */
#define AUTH_CAP   (8 << 20)   /* SECURITY 目录读取上限 */

/* ---------------- 小工具 ---------------- */

static double sfc_log1p(double x)
{
    /* msvcrt (XP) 没有 log1p — 经典公式保证精度 */
    double p = 1.0 + x;
    if (p == 1.0) return x;
    return log(p) + (x - (p - 1.0)) / p;
}

/* Python round(x, 4): 半数取偶 */
static double round4(double x)
{
    double s = x * 1e4;
    double r = floor(s);
    double frac = s - r;
    if (frac > 0.5) r += 1.0;
    else if (frac == 0.5) {
        double low = fmod(r, 2.0);
        if (low != 0.0 && low != -0.0) r += 1.0;   /* 奇数 -> 偶数 */
    }
    return r / 1e4;
}

static int bfind(const unsigned char *buf, size_t n, const unsigned char *pat, size_t plen)
{
    size_t i, j;
    if (plen == 0 || n < plen) return 0;
    for (i = 0; i <= n - plen; i++) {
        if (buf[i] == pat[0]) {
            for (j = 1; j < plen; j++)
                if (buf[i + j] != pat[j]) break;
            if (j == plen) return 1;
        }
    }
    return 0;
}

static int bcontains(const unsigned char *buf, size_t n, const char *s)
{
    return bfind(buf, n, (const unsigned char *)s, strlen(s));
}

static double entropy(const unsigned char *d, size_t n)
{
    long counts[256];
    size_t i;
    double e = 0.0;
    if (n == 0) return 0.0;
    memset(counts, 0, sizeof counts);
    for (i = 0; i < n; i++) counts[d[i]]++;
    for (i = 0; i < 256; i++) {
        double p;
        if (counts[i] == 0) continue;
        p = (double)counts[i] / (double)n;
        e -= p * log(p) / 0.69314718055994530941723212145818;   /* log2, XP msvcrt 无 log2 */
    }
    return e;
}

/* 按文件偏移读 (authenticode 段可能在 4MB 窗口外) */
static unsigned char *read_at(const char *path, long off, int sz, int cap, int *got)
{
    FILE *f;
    long len;
    int n;
    unsigned char *b;
    *got = 0;
    f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    if (off < 0 || off >= len) { fclose(f); return NULL; }
    fseek(f, off, SEEK_SET);
    n = sz < cap ? sz : cap;
    if (n <= 0 || n > 64 << 20) { fclose(f); return NULL; }
    b = (unsigned char *)malloc((size_t)n);
    if (!b) { fclose(f); return NULL; }
    *got = (int)fread(b, 1, (size_t)n, f);
    fclose(f);
    if (*got <= 0) { free(b); return NULL; }
    return b;
}

/* ---------------- BER TLV (对齐 Python _ber_tlv) ---------------- */

static int ber_tlv(const unsigned char *b, int pos, int n,
                   unsigned char *tag, int *vo, int *vl, int *next)
{
    int ln, p;
    if (pos + 2 > n) return 0;
    *tag = b[pos];
    ln = b[pos + 1];
    p = pos + 2;
    if (ln == 0x80) return 0;                      /* 不定长不接受 */
    if (ln & 0x80) {
        int nb = ln & 0x7F, k;
        long v = 0;
        if (nb == 0 || p + nb > n) return 0;
        for (k = 0; k < nb; k++) v = (v << 8) | b[p + k];
        p += nb;
        if (v > 0x7FFFFFFFL) return 0;
        ln = (int)v;
    }
    if (p + ln > n) return 0;
    *vo = p; *vl = ln; *next = p + ln;
    return 1;
}

/* ---------------- RDN 属性收集 (CN/O/serialNumber) ---------------- */

typedef struct { char cn[128]; int cnl; char o[128]; int ol; char serial[128]; int serl; } Rdn;

static void collect_atv(const unsigned char *b, int start, int end, Rdn *out, int *depth)
{
    int i = start;
    if (*depth > 12) return;
    while (i < end) {
        unsigned char tag;
        int vo, vl, nxt;
        if (!ber_tlv(b, i, end, &tag, &vo, &vl, &nxt)) break;
        if (tag == 0x06 && nxt < end) {
            unsigned char oid[16];
            int oidn = vl < 16 ? vl : 16;
            unsigned char vt; int vvo, vvl, vn;
            memcpy(oid, b + vo, (size_t)oidn);
            if (ber_tlv(b, nxt, end, &vt, &vvo, &vvl, &vn)
                && (vt == 0x0C || vt == 0x13 || vt == 0x16 || vt == 0x1E || vt == 0x12)) {
                int take = vvl < 127 ? vvl : 127;
                if (take > 0) {
                    if (oidn >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x03 && !out->cnl) {
                        memcpy(out->cn, b + vvo, (size_t)take); out->cnl = take;
                    } else if (oidn >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x0A && !out->ol) {
                        memcpy(out->o, b + vvo, (size_t)take); out->ol = take;
                    } else if (oidn >= 3 && oid[0] == 0x55 && oid[1] == 0x04 && oid[2] == 0x05 && !out->serl) {
                        memcpy(out->serial, b + vvo, (size_t)take); out->serl = take;
                    }
                }
                i = vn;
                continue;
            }
        }
        if (tag == 0x30 || tag == 0x31) {
            (*depth)++;
            collect_atv(b, vo, vo + vl, out, depth);
            (*depth)--;
        }
        i = nxt;
    }
}

static void rdn_of(const unsigned char *b, int start, int len, Rdn *out)
{
    int d = 0;
    memset(out, 0, sizeof *out);
    collect_atv(b, start, start + len, out, &d);
}

static int rdn_empty(const Rdn *r)
{
    return r->cnl == 0 && r->ol == 0 && r->serl == 0;
}

static int is_letter(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* _scan_subject 兜底: 扫 "letters=printable{2,80}", 取最后一个 key 恰为 CN/O/serialNumber 的 */
static void scan_subject(const unsigned char *b, int n, Rdn *out)
{
    int i = 0;
    int last_cn = -1, cn_len = 0, last_o = -1, o_len = 0, last_ser = -1, ser_len = 0;
    while (i < n) {
        int j, k, v = i, vlen;
        if (!is_letter(b[i])) { i++; continue; }
        j = i; k = 0;
        while (j < n && k < 32 && is_letter(b[j])) { j++; k++; }
        if (j < n && b[j] == '=') {
            v = j + 1; vlen = 0;
            while (v < n && vlen < 80 && b[v] >= 0x20 && b[v] <= 0x7E) { v++; vlen++; }
            if (vlen >= 2) {
                if (k == 2 && b[i] == 'C' && b[i + 1] == 'N') { last_cn = j + 1; cn_len = vlen; }
                else if (k == 1 && b[i] == 'O') { last_o = j + 1; o_len = vlen; }
                else if (k == 12 && memcmp(b + i, "serialNumber", 12) == 0) { last_ser = j + 1; ser_len = vlen; }
            }
        }
        if (v > j) i = v; else i = j + 1;
    }
    if (last_cn >= 0) { int t = cn_len < 127 ? cn_len : 127; memcpy(out->cn, b + last_cn, (size_t)t); out->cnl = t; }
    if (last_o >= 0) { int t = o_len < 127 ? o_len : 127; memcpy(out->o, b + last_o, (size_t)t); out->ol = t; }
    if (last_ser >= 0) { int t = ser_len < 127 ? ser_len : 127; memcpy(out->serial, b + last_ser, (size_t)t); out->serl = t; }
}

/* ---------------- 证书解析 ---------------- */

typedef struct {
    Rdn iss, sub;
    unsigned char serialb[64]; int serialn;
    int self;
    int ok;
} CertPart;

void cert_parts(const unsigned char *der, int n, CertPart *out)
{
    unsigned char ot; int oo, ol, on;        /* 外层 Certificate SEQUENCE */
    unsigned char tbt; int tbo, tbl, tbn;    /* tbsCertificate SEQUENCE */
    int start, end, has = 0;
    int elems[64][4]; int nelem = 0, idx;
    int p2, i;
    memset(out, 0, sizeof *out);
    if (!ber_tlv(der, 0, n, &ot, &oo, &ol, &on) || ot != 0x30) return;
    if (!ber_tlv(der, oo, n, &tbt, &tbo, &tbl, &tbn)) return;
    if (tbt == 0x30) { start = tbo; end = tbo + tbl; has = 1; }
    else if (tbt == 0xA0 || tbt == 0x80) { start = oo; end = on; has = 1; }
    if (!has) return;
    p2 = start;
    while (p2 < end && nelem < 64) {
        unsigned char e; int evo, evl, en;
        if (!ber_tlv(der, p2, end, &e, &evo, &evl, &en)) break;
        elems[nelem][0] = e; elems[nelem][1] = evo; elems[nelem][2] = evl; elems[nelem][3] = en;
        nelem++;
        p2 = en;
    }
    idx = (nelem > 0 && (elems[0][0] == 0xA0 || elems[0][0] == 0x80)) ? 1 : 0;
    if (nelem < idx + 5 || elems[idx][0] != 0x02) return;
    out->serialn = elems[idx][2];
    if (out->serialn > 64) out->serialn = 64;
    memcpy(out->serialb, der + elems[idx][1], (size_t)out->serialn);
    rdn_of(der, elems[idx + 2][1], elems[idx + 2][2], &out->iss);
    rdn_of(der, elems[idx + 4][1], elems[idx + 4][2], &out->sub);
    if (out->iss.cnl == out->sub.cnl && out->iss.ol == out->sub.ol && out->iss.serl == out->sub.serl
        && memcmp(out->iss.cn, out->sub.cn, (size_t)out->iss.cnl) == 0
        && memcmp(out->iss.o, out->sub.o, (size_t)out->iss.ol) == 0
        && memcmp(out->iss.serial, out->sub.serial, (size_t)out->iss.serl) == 0
        && (out->iss.cnl || out->iss.ol || out->iss.serl))
        out->self = 1;
    out->ok = 1;
    (void)i;
}

/* ---------------- Authenticode (对齐 Python _parse_authenticode) ---------------- */

typedef struct {
    int auth, certs, self_signed, blacklisted;
    Rdn signer;
} AuthRes;

/* 中文证书主体按 UTF-8 字节写死: 编译带 -fexec-charset=GBK, 普通中文字面量会变 GBK,
 * 与证书里 UTF-8 编码的 CN 对不上 (Python 端 _dec 优先 UTF-8 解码后比对). */
static const char *const ABUSED_WORDS[] = { "\xe8\xb4\x9d\xe9\x94\x90", "awesun", "oray", "duojiayu",
                                            "\xe5\xa4\x9a\xe5\x8a\xa0\xe9\xb1\xbc",
                                            "dingtalk", "\xe9\x92\x89\xe9\x92\x89", "iray", "alibaba" };
static const char *const ABUSED_SERIALS[] = { "91310110787862412b", "91310110787862412b", "",
                                              "91510107maacgc6jxl", "", "91330110ma2b00r29g", "",
                                              "", "91330100716105852f" };

static void lower_ascii(const char *in, int inl, char *out, int ocap)
{
    int i;
    for (i = 0; i < inl && i < ocap - 1; i++)
        out[i] = (char)(in[i] >= 'A' && in[i] <= 'Z' ? in[i] + 32 : in[i]);
    out[i] = 0;
}

static int signer_blacklisted(const Rdn *s)
{
    char joined[320];
    char cnlo[160], orlo[160], serlo[160];
    int j;
    lower_ascii(s->cn, s->cnl, cnlo, sizeof cnlo);
    lower_ascii(s->o, s->ol, orlo, sizeof orlo);
    lower_ascii(s->serial, s->serl, serlo, sizeof serlo);
    _snprintf(joined, sizeof joined - 1, "%s %s", cnlo, orlo);
    for (j = 0; j < (int)(sizeof ABUSED_WORDS / sizeof ABUSED_WORDS[0]); j++) {
        if (ABUSED_WORDS[j][0] && strstr(joined, ABUSED_WORDS[j])) return 1;
        if (ABUSED_SERIALS[j][0] && strstr(serlo, ABUSED_SERIALS[j])) return 1;
    }
    return 0;
}

static void parse_authenticode(const char *path, long fsize, int off, int sz, AuthRes *r)
{
    unsigned char *blob;
    unsigned char *pkcs, *inner;
    int n, pklen, inlen;
    unsigned char tag; int vo, vl, nxt;
    int p;
    int fields[32][4]; int nf = 0;
    int certs_start[128]; int certs_len[128]; int ncerts = 0;
    CertPart parts[64]; int nparts = 0;
    int i;
    memset(r, 0, sizeof *r);
    if (off <= 0 || sz < 16 || (long)off + sz > fsize) return;
    blob = read_at(path, off, sz, AUTH_CAP, &n);
    if (!blob || n < 8) { free(blob); return; }
    /* WIN_CERTIFICATE: dwLength(4) wRevision(2)=0x0200 wCertificateType(2)=0x0002 */
    if (((unsigned short)blob[4] | ((unsigned short)blob[5] << 8)) != 0x0200
        || ((unsigned short)blob[6] | ((unsigned short)blob[7] << 8)) != 0x0002) { free(blob); return; }
    pkcs = blob + 8;
    pklen = n - 8;
    if (pklen < 1 || !ber_tlv(pkcs, 0, pklen, &tag, &vo, &vl, &nxt) || tag != 0x30) { free(blob); return; }
    if (!ber_tlv(pkcs, vo, pklen, &tag, &vo, &vl, &nxt) || tag != 0x06) { free(blob); return; }
    p = nxt;
    if (p >= pklen || pkcs[p] != 0xA0) { free(blob); return; }
    {
        unsigned char it; int ivo, ivl, ivn;
        if (!ber_tlv(pkcs, p, pklen, &it, &ivo, &ivl, &ivn)) { free(blob); return; }
        inner = pkcs + ivo;
        inlen = ivl;
    }
    if (inlen < 1 || !ber_tlv(inner, 0, inlen, &tag, &vo, &vl, &nxt) || tag != 0x30) { free(blob); return; }
    p = vo;
    while (p < vo + vl && nf < 32) {
        unsigned char t2; int t2o, t2l, t2n;
        if (!ber_tlv(inner, p, inlen, &t2, &t2o, &t2l, &t2n)) break;
        fields[nf][0] = t2; fields[nf][1] = t2o; fields[nf][2] = t2l; fields[nf][3] = t2n;
        if (t2 == 0xA0) {                      /* certificates SET */
            int cp = t2o;
            while (cp < t2o + t2l && ncerts < 128) {
                unsigned char ct; int cvo, cvl, cn;
                if (!ber_tlv(inner, cp, inlen, &ct, &cvo, &cvl, &cn) || ct != 0x30) break;
                certs_start[ncerts] = cvo; certs_len[ncerts] = cvl;
                ncerts++;
                cp = cn;
            }
        }
        nf++;
        p = t2n;
    }
    if (ncerts == 0) { free(blob); return; }
    r->auth = 1;
    r->certs = ncerts;
    for (i = 0; i < ncerts && i < 64; i++) {
        CertPart cp;
        cert_parts(inner + certs_start[i], certs_len[i], &cp);
        if (cp.ok) parts[nparts++] = cp;
    }
    if (nparts == 0) { free(blob); return; }
    /* SignerInfo (最后一个可解析 0x31 SET) 里的签名者序列号 → 锁定叶子 */
    {
        unsigned char *signer_serial = NULL;
        int signer_serial_len = 0;
        for (i = nf - 1; i >= 0; i--) {
            unsigned char st; int sto, stl, stn;
            unsigned char ver; int vvo, vvl, vvn;
            unsigned char ias; int ivo2, ivl2, ivn2;
            unsigned char nm; int nvo, nvl, nvn;
            int sp;
            if (fields[i][0] != 0x31) continue;
            if (!ber_tlv(inner, fields[i][1], inlen, &st, &sto, &stl, &stn) || st != 0x30) continue;
            if (!ber_tlv(inner, sto, inlen, &ver, &vvo, &vvl, &vvn) || ver != 0x02) continue;
            if (!ber_tlv(inner, vvn, inlen, &ias, &ivo2, &ivl2, &ivn2) || ias != 0x30) continue;
            if (!ber_tlv(inner, ivo2, inlen, &nm, &nvo, &nvl, &nvn)) continue;
            sp = nvn;
            while (sp < ivo2 + ivl2) {
                unsigned char sn; int sno, snl, snn;
                if (!ber_tlv(inner, sp, inlen, &sn, &sno, &snl, &snn)) break;
                if (sn == 0x02) { signer_serial = inner + sno; signer_serial_len = snl; break; }
                sp = snn;
            }
            if (signer_serial) break;
        }
        if (signer_serial) {
            int leaf = 0;
            for (i = 0; i < nparts; i++)
                if (parts[i].serialn == signer_serial_len
                    && memcmp(parts[i].serialb, signer_serial, (size_t)signer_serial_len) == 0) { leaf = i; break; }
            r->self_signed = parts[leaf].self;
            r->signer = parts[leaf].sub;
            if (rdn_empty(&r->signer)) {
                /* 与 Python 一致: 兜底扫描 (leaf 索引 = 过滤后 parts 的索引) */
                scan_subject(inner + certs_start[leaf], certs_len[leaf], &r->signer);
                if (rdn_empty(&r->signer)) scan_subject(pkcs, pklen, &r->signer);
            }
        } else {
            r->self_signed = parts[0].self;
            r->signer = parts[0].sub;
        }
    }
    r->blacklisted = signer_blacklisted(&r->signer);
    free(blob);
}

/* ---------------- 正则等价手扫 ---------------- */

static int is_ws(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == 0x0B;
}

/* (?:\d{1,3}\.){3}\d{1,3}\s*[:|,.]\s*\d{1,5} 非重叠计数 */
static int count_c2_ip_port(const unsigned char *d, size_t n)
{
    size_t i = 0;
    int cnt = 0;
    while (i < n) {
        size_t j = i;
        int group, gd, ipok = 1;
        for (group = 0; group < 3; group++) {
            gd = 0;
            while (j < n && d[j] >= '0' && d[j] <= '9' && gd < 3) { j++; gd++; }
            if (gd == 0 || j >= n || d[j] != '.') { ipok = 0; break; }
            j++;
        }
        if (ipok) {
            gd = 0;
            while (j < n && d[j] >= '0' && d[j] <= '9' && gd < 3) { j++; gd++; }
            if (gd > 0) {
                size_t k = j;
                while (k < n && is_ws(d[k])) k++;
                if (k < n && (d[k] == ':' || d[k] == '|' || d[k] == ',' || d[k] == '.')) {
                    size_t m = k + 1;
                    while (m < n && is_ws(d[m])) m++;
                    if (m < n && d[m] >= '0' && d[m] <= '9') {
                        int pd = 0;
                        while (m < n && d[m] >= '0' && d[m] <= '9' && pd < 5) { m++; pd++; }
                        cnt++;
                        i = m;
                        continue;
                    }
                }
            }
        }
        i = (j > i) ? j : i + 1;
    }
    return cnt;
}

/* https?://[^\x00"' ]+ 非重叠计数 (tail >= 1 字符) */
static int count_urls(const unsigned char *d, size_t n)
{
    size_t i = 0;
    int cnt = 0;
    while (i < n) {
        int https = (n - i >= 8 && d[i] == 'h' && d[i + 1] == 't' && d[i + 2] == 't'
                     && d[i + 3] == 'p' && d[i + 4] == 's' && d[i + 5] == ':' && d[i + 6] == '/'
                     && d[i + 7] == '/');
        int http = (n - i >= 7 && d[i] == 'h' && d[i + 1] == 't' && d[i + 2] == 't'
                    && d[i + 3] == 'p' && d[i + 4] == ':' && d[i + 5] == '/' && d[i + 6] == '/');
        if (https || http) {
            size_t j = i + (https ? 8 : 7);
            size_t k = j;
            while (k < n && d[k] != 0x00 && d[k] != '"' && d[k] != '\'' && d[k] != ' ') k++;
            if (k > j) { cnt++; i = k; continue; }
        }
        i++;
    }
    return cnt;
}

/* [\x20-\x7e]{6,} 非重叠计数 = 极大可打印跑 (len>=6) 计数 */
static int count_strings(const unsigned char *d, size_t n)
{
    size_t i = 0;
    int cnt = 0;
    while (i < n) {
        if (d[i] >= 0x20 && d[i] <= 0x7E) {
            size_t j = i;
            while (j < n && d[j] >= 0x20 && d[j] <= 0x7E) j++;
            if (j - i >= 6) cnt++;
            i = j;
        } else i++;
    }
    return cnt;
}

/* ---------------- 导入 DLL 数 ---------------- */

/* 注意: 与 ml/extract_features.py 的训练口径一致 —— 训练端把「数据目录[0] (导出表)」
 * 的 RVA 当导入描述符表遍历 (extract_features.py 里 unpack_from("<II", ...+112/96) 未 +8),
 * 其计数已固化进 model_linear.json 的 means/stds/w. 改用真导入目录 (dir[1]) 会使
 * n_import_dlls 偏离训练分布 (w=+1.49). 故此处刻意复刻: 调用方传 dir[0] 的 RVA. */
static int count_import_dlls(const unsigned char *data, int nlen, int imp_rva, int sec_off, int nsec)
{
    int va[64], vsz[64], roff[64];
    int i, nsecs = 0, o = -1, found = -1;
    static char dlls[2048][65];        /* 行宽 65: 名字上限 64 字节 + NUL (64 会让 64 字节名溢出踩掉下一行首 NUL) */
    int ndlls = 0;
    int idx;
    if (!imp_rva) return 0;
    for (i = 0; i < nsec && i < 64 && sec_off + i * 40 + 24 <= nlen; i++) {
        int s = sec_off + i * 40;
        int rsz;
        va[nsecs] = (int)((unsigned)data[s + 12] | ((unsigned)data[s + 13] << 8)
                          | ((unsigned)data[s + 14] << 16) | ((unsigned)data[s + 15] << 24));
        vsz[nsecs] = (int)((unsigned)data[s + 8] | ((unsigned)data[s + 9] << 8)
                           | ((unsigned)data[s + 10] << 16) | ((unsigned)data[s + 11] << 24));
        rsz = (int)((unsigned)data[s + 16] | ((unsigned)data[s + 17] << 8)
                    | ((unsigned)data[s + 18] << 16) | ((unsigned)data[s + 19] << 24));
        if (rsz > vsz[nsecs]) vsz[nsecs] = rsz;   /* max(vsize, rsize) */
        roff[nsecs] = (int)((unsigned)data[s + 20] | ((unsigned)data[s + 21] << 8)
                            | ((unsigned)data[s + 22] << 16) | ((unsigned)data[s + 23] << 24));
        nsecs++;
    }
    for (i = 0; i < nsecs; i++)
        if (imp_rva >= va[i] && imp_rva < va[i] + vsz[i] && roff[i] >= 0) { found = i; break; }
    if (found >= 0) o = roff[found] + (imp_rva - va[found]);
    if (o < 0) return 0;
    for (i = 0; i < 2048 && o + i * 20 + 20 <= nlen; i++) {
        int oft, name_rva, no = -1;
        oft = (int)((unsigned)data[o + i * 20] | ((unsigned)data[o + i * 20 + 1] << 8)
                    | ((unsigned)data[o + i * 20 + 2] << 16) | ((unsigned)data[o + i * 20 + 3] << 24));
        name_rva = (int)((unsigned)data[o + i * 20 + 12] | ((unsigned)data[o + i * 20 + 13] << 8)
                         | ((unsigned)data[o + i * 20 + 14] << 16) | ((unsigned)data[o + i * 20 + 15] << 24));
        if (oft == 0 && name_rva == 0) break;
        if (name_rva) {
            char buf[65];
            int bl = 0, end;
            int dup = 0;
            for (idx = 0; idx < nsecs; idx++)
                if (name_rva >= va[idx] && name_rva < va[idx] + vsz[idx] && roff[idx] >= 0) { no = roff[idx] + (name_rva - va[idx]); break; }
            if (no < 0 || no >= nlen) continue;
            end = no;
            while (end < nlen && end - no < 64 && data[end] != 0) end++;
            while (bl < end - no && bl < 64) {
                unsigned char c = data[no + bl];
                /* latin1 -> lower (Python str.lower): ASCII 与 0xC0-0xDE (除 0xD7) */
                if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
                else if (c >= 0xC0 && c <= 0xDE && c != 0xD7) c = (unsigned char)(c + 32);
                buf[bl++] = (char)c;
            }
            buf[bl] = 0;
            if (bl == 0) continue;
            for (idx = 0; idx < ndlls; idx++)
                if (strcmp(buf, dlls[idx]) == 0) { dup = 1; break; }
            if (!dup && ndlls < 2048) { memcpy(dlls[ndlls], buf, (size_t)bl + 1); ndlls++; }
        }
    }
    return ndlls;
}

/* ---------------- 22 特征提取 (顺序 = SFC_ML_FEATURES) ---------------- */

enum {
    F_HAS_GO_BUILDID, F_HAS_GOLANG, F_UNUSUAL_SECTIONS, F_SUSPICIOUS_APIS,
    F_HAS_INJECTION_API, F_HAS_PERSISTENCE_API, F_HAS_NET_API, F_MAX_SECTION_ENTROPY,
    F_N_STRINGS, F_LOG_SIZE, F_N_URLS, F_HAS_AUTHENTICODE, F_CERT_COUNT, F_IS_SELF_SIGNED,
    F_N_IMPORT_DLLS, F_SIGNER_BLACKLISTED, F_FPTABLE_UNSIGNED, F_EMPTY_RAW_SECTIONS,
    F_ENTRY_IN_RAWLESS, F_C2_IP_PORT, F_ENTRY_SECTION_ENTROPY, F_EP_HIGH_ENTROPY
};

static const char *const LOW_APIS[] = { "socket", "connect", "recv", "send" };
static const char *const INJ[] = { "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                                   "CreateRemoteThread", "QueueUserAPC", "NtUnmapViewOfSection" };
static const char *const PERS[] = { "RegSetValueEx", "RegCreateKeyEx", "CreateService",
                                    "StartService", "SetWindowsHookEx", "SetWindowsHookExW" };
static const char *const NET[] = { "URLDownloadToFile", "InternetOpen", "InternetOpenUrl",
                                   "HttpSendRequest" };

int ml_feat_extract(const char *path, double out[22])
{
    FILE *f;
    unsigned char *data;
    int nlen;
    unsigned char *tail;
    long len;
    int e_lfanew, off, opt, sec_off, ep_rva = 0;
    unsigned short nsec, optsz, magic;
    int is64;
    double sec_ents[128];
    double sec_entropy4[128];
    char sec_names[128][9];
    int sec_vsz[128], sec_rsz[128], sec_va[128];
    int nsecs = 0;
    int i;
    int raw0 = 0, ep_rawless = 0;
    double ep_sec_ent4 = 0.0, ep_sec_ent_final = 0.0;
    int has_fptable = 0, unusual = 0, sus_apis = 0;
    int has_inj = 0, has_pers = 0, has_net = 0;
    int imp_off, imp_rva = 0, sec_off_dir = 0, sec_sz_dir = 0;
    AuthRes auth;

    f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    nlen = len < READ_LIMIT ? (int)len : READ_LIMIT;
    data = (unsigned char *)malloc((size_t)nlen + 1);
    if (!data) { fclose(f); return -1; }
    if (fread(data, 1, (size_t)nlen, f) != (size_t)nlen) { free(data); fclose(f); return -1; }
    fclose(f);
    data[nlen] = 0;
    tail = data;
    (void)tail;
    if (nlen < 0x40 || data[0] != 'M' || data[1] != 'Z') { free(data); return -1; }
    e_lfanew = (int)((unsigned)data[0x3C] | ((unsigned)data[0x3D] << 8)
                     | ((unsigned)data[0x3E] << 16) | ((unsigned)data[0x3F] << 24));
    if (e_lfanew + 4 > nlen || data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E'
        || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0) { free(data); return -1; }
    off = e_lfanew + 4;
    if (off + 24 > nlen) { free(data); return -1; }
    nsec = (unsigned short)(data[off + 2] | (data[off + 3] << 8));
    optsz = (unsigned short)(data[off + 16] | (data[off + 17] << 8));
    magic = (unsigned short)(data[e_lfanew + 24] | (data[e_lfanew + 25] << 8));
    is64 = (magic == 0x20B);
    if (magic != 0x10B && magic != 0x20B) { free(data); return -1; }
    opt = e_lfanew + 24;
    if (opt + 20 > nlen) { free(data); return -1; }
    ep_rva = (int)((unsigned)data[opt + 16] | ((unsigned)data[opt + 17] << 8)
                   | ((unsigned)data[opt + 18] << 16) | ((unsigned)data[opt + 19] << 24));
    sec_off = e_lfanew + 4 + 20 + optsz;

    for (i = 0; i < nsec && i < 128 && sec_off + i * 40 + 24 <= nlen; i++) {
        int s = sec_off + i * 40;
        int vsize, vaddr, rsize, roff;
        int j, e2;
        double e;
        for (j = 0; j < 8 && data[s + j]; j++) sec_names[nsecs][j] = (char)data[s + j];
        sec_names[nsecs][j] = 0;
        vsize = (int)((unsigned)data[s + 8] | ((unsigned)data[s + 9] << 8)
                      | ((unsigned)data[s + 10] << 16) | ((unsigned)data[s + 11] << 24));
        vaddr = (int)((unsigned)data[s + 12] | ((unsigned)data[s + 13] << 8)
                      | ((unsigned)data[s + 14] << 16) | ((unsigned)data[s + 15] << 24));
        rsize = (int)((unsigned)data[s + 16] | ((unsigned)data[s + 17] << 8)
                      | ((unsigned)data[s + 18] << 16) | ((unsigned)data[s + 19] << 24));
        roff = (int)((unsigned)data[s + 20] | ((unsigned)data[s + 21] << 8)
                     | ((unsigned)data[s + 22] << 16) | ((unsigned)data[s + 23] << 24));
        /* Python: sdata = data[roff : roff + min(rsize, 1MB)] — 截断到窗口内, 空=0.0 */
        {
            int start = roff, want = rsize < (1 << 20) ? rsize : (1 << 20), end2 = start + want;
            if (end2 > nlen) end2 = nlen;
            if (start >= nlen || end2 <= start) e = 0.0;
            else e = entropy(data + start, (size_t)(end2 - start));
        }
        sec_ents[nsecs] = e;
        sec_entropy4[nsecs] = round4(e);
        sec_vsz[nsecs] = vsize;
        sec_rsz[nsecs] = rsize;
        sec_va[nsecs] = vaddr;
        nsecs++;
        (void)e2;
    }

    /* ---- 特征 ---- */
    out[F_HAS_GO_BUILDID] = bcontains(data, (size_t)nlen, "Go build ID:") ? 1 : 0;
    out[F_HAS_GOLANG] = (bcontains(data, (size_t)nlen, "golang.org")
                         || bcontains(data, (size_t)nlen, "runtime.main")
                         || bcontains(data, (size_t)nlen, "main.main")) ? 1 : 0;
    for (i = 0; i < nsecs; i++) {
        const char *nm = sec_names[i];
        char low[9];
        int k;
        size_t nl = strlen(nm);
        if (nl > 0 && nm[0] != '.') unusual++;
        for (k = 0; k < 8 && nm[k]; k++) low[k] = (char)(nm[k] >= 'A' && nm[k] <= 'Z' ? nm[k] + 32 : nm[k]);
        low[k] = 0;
        if (strstr(low, "fptable") || !strcmp(low, ".fpt") || !strcmp(low, ".fptable")) has_fptable = 1;
    }
    out[F_UNUSUAL_SECTIONS] = unusual;
    for (i = 0; i < (int)(sizeof LOW_APIS / sizeof LOW_APIS[0]); i++)
        if (bcontains(data, (size_t)nlen, LOW_APIS[i])) sus_apis++;
    out[F_SUSPICIOUS_APIS] = sus_apis;
    for (i = 0; i < (int)(sizeof INJ / sizeof INJ[0]); i++)
        if (bcontains(data, (size_t)nlen, INJ[i])) has_inj = 1;
    out[F_HAS_INJECTION_API] = has_inj;
    for (i = 0; i < (int)(sizeof PERS / sizeof PERS[0]); i++)
        if (bcontains(data, (size_t)nlen, PERS[i])) has_pers = 1;
    out[F_HAS_PERSISTENCE_API] = has_pers;
    for (i = 0; i < (int)(sizeof NET / sizeof NET[0]); i++)
        if (bcontains(data, (size_t)nlen, NET[i])) has_net = 1;
    out[F_HAS_NET_API] = has_net;
    if (nsecs > 0) {
        double mx = sec_ents[0];
        for (i = 1; i < nsecs; i++) if (sec_ents[i] > mx) mx = sec_ents[i];
        out[F_MAX_SECTION_ENTROPY] = round4(mx);
    } else out[F_MAX_SECTION_ENTROPY] = 0.0;
    out[F_N_STRINGS] = count_strings(data, (size_t)nlen);
    out[F_LOG_SIZE] = round4(sfc_log1p((double)len));
    out[F_N_URLS] = count_urls(data, (size_t)nlen);

    /* n_import_dlls 的 RVA 取「数据目录[0]」——刻意复刻训练端口径, 见 count_import_dlls 注释 */
    imp_off = opt + (is64 ? 112 : 96);
    if (imp_off + 4 <= nlen)
        imp_rva = (int)((unsigned)data[imp_off] | ((unsigned)data[imp_off + 1] << 8)
                        | ((unsigned)data[imp_off + 2] << 16) | ((unsigned)data[imp_off + 3] << 24));
    out[F_N_IMPORT_DLLS] = count_import_dlls(data, nlen, imp_rva, sec_off, nsec);

    /* SECURITY 目录 (数据目录 4, 文件偏移) */
    {
        int sec_off_pos = opt + (is64 ? 112 : 96) + 32;
        if (sec_off_pos + 8 <= nlen) {
            sec_off_dir = (int)((unsigned)data[sec_off_pos] | ((unsigned)data[sec_off_pos + 1] << 8)
                                | ((unsigned)data[sec_off_pos + 2] << 16) | ((unsigned)data[sec_off_pos + 3] << 24));
            sec_sz_dir = (int)((unsigned)data[sec_off_pos + 4] | ((unsigned)data[sec_off_pos + 5] << 8)
                               | ((unsigned)data[sec_off_pos + 6] << 16) | ((unsigned)data[sec_off_pos + 7] << 24));
        }
    }
    parse_authenticode(path, len, sec_off_dir, sec_sz_dir, &auth);
    out[F_HAS_AUTHENTICODE] = auth.auth;
    out[F_CERT_COUNT] = auth.certs;
    out[F_IS_SELF_SIGNED] = auth.self_signed;
    out[F_SIGNER_BLACKLISTED] = auth.blacklisted;
    out[F_FPTABLE_UNSIGNED] = (has_fptable && !auth.auth) ? 1 : 0;

    for (i = 0; i < nsecs; i++) {
        const char *nm = sec_names[i];
        char low[9];
        int k;
        for (k = 0; k < 8 && nm[k]; k++) low[k] = (char)(nm[k] >= 'A' && nm[k] <= 'Z' ? nm[k] + 32 : nm[k]);
        low[k] = 0;
        if (sec_vsz[i] > 0 && sec_rsz[i] == 0 && strcmp(low, ".bss") != 0 && strcmp(low, ".tls") != 0) {
            raw0++;
            if (sec_va[i] <= ep_rva && ep_rva < sec_va[i] + (sec_vsz[i] > 1 ? sec_vsz[i] : 1)) ep_rawless = 1;
        }
    }
    out[F_EMPTY_RAW_SECTIONS] = raw0;
    out[F_ENTRY_IN_RAWLESS] = ep_rawless;
    out[F_C2_IP_PORT] = count_c2_ip_port(data, (size_t)nlen);
    /* 第一遍 (Python 取整熵): ep_high_entropy */
    for (i = 0; i < nsecs; i++) {
        if (sec_vsz[i] > 0 && sec_va[i] <= ep_rva && ep_rva < sec_va[i] + (sec_vsz[i] > 1 ? sec_vsz[i] : 1)) {
            ep_sec_ent4 = sec_entropy4[i];
            break;
        }
    }
    /* 第二遍 (Python 最终覆盖): entry_section_entropy = 未取整熵, 无 vsz>0 限制 */
    for (i = 0; i < nsecs; i++) {
        if (sec_va[i] <= ep_rva && ep_rva < sec_va[i] + (sec_vsz[i] > 1 ? sec_vsz[i] : 1)) {
            ep_sec_ent_final = sec_ents[i];
            break;
        }
    }
    out[F_ENTRY_SECTION_ENTROPY] = round4(ep_sec_ent_final);
    out[F_EP_HIGH_ENTROPY] = ep_sec_ent4 >= 7.5 ? 1 : 0;

    free(data);
    return 0;
}

/* ---------------- 逻辑回归打分 ---------------- */

extern const int SFC_ML_N;
extern const double SFC_ML_MEANS[];
extern const double SFC_ML_STDS[];
extern const double SFC_ML_W[];
extern const double SFC_ML_B;

double ml_score(const char *path)
{
    double x[22], z;
    int i;
    if (ml_feat_extract(path, x) != 0) return -1.0;
    z = SFC_ML_B;
    for (i = 0; i < SFC_ML_N; i++)
        z += SFC_ML_W[i] * ((x[i] - SFC_ML_MEANS[i]) / SFC_ML_STDS[i]);
    if (z > 50.0) z = 50.0;
    if (z < -50.0) z = -50.0;
    return 1.0 / (1.0 + exp(-z));
}