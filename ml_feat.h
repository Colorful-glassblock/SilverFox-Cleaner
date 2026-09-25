/* ml_feat.h — 静态 PE 特征提取 + 逻辑回归打分 (与 ml/extract_features.py + model_linear.json 语义一致)
 * 纯 msvcrt 依赖 (XP 兼容): 仅 stdio/string/stdlib/math, 不依赖 regex 库.
 * ml_score(path):
 *   返回 [0,1] 概率, 或 -1.0 (非 PE / 读取失败). 结构匹配 FILE 发现用它复核.
 */
#ifndef SFC_ML_FEAT_H
#define SFC_ML_FEAT_H

/* 22 个精选特征, 顺序与 model_linear.json "features" 一致 */
int ml_feat_extract(const char *path, double out[28]);
double ml_score(const char *path);

/* 内嵌 Authenticode「结构级合法签名」: 有证书链 + 非自签 + 签名者不在滥用名单.
 * 不依赖本机证书库/WinVerifyTrust — 24H2 catalog 枚举失败或证书库被清空的 VM 上仍确定可靠. */
int ml_feat_legit_sig(const double x28[28]);

#endif