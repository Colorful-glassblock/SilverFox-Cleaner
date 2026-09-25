// ml_dual.rs — 双模型推理: 表格 MLP-28(256-128) + delta/head 图像 CNN + 灵敏度三档.
// 权重在 ml_net.rs (硬编码). 前向全部 fp32, 与 Python 参照 (ml/score_dual.py) 对齐.
// 灵敏度档位: 0=高检测 1=平衡(默认) 2=低误杀 (阈值见 rule 函数, 2026-09-25 折外标定).
use std::path::Path;

use crate::ml_feat::{ml_feat_extract, F_COUNT};
use crate::ml_net::*;

fn relu(x: f32) -> f32 { if x > 0.0 { x } else { 0.0 } }

/// 表格分支: 28 特征 -> 256 -> 128 -> 1, sigmoid.
pub fn tabular_p(x: &[f64; F_COUNT]) -> f32 {
    let mut h1 = [0f32; 256];
    for j in 0..256 {
        let mut s = TAB_B1[j];
        for i in 0..28 {
            let xn = (x[i] as f32 - TAB_MEANS[i]) / TAB_STDS[i];
            s += TAB_W1[j * 28 + i] * xn;
        }
        h1[j] = relu(s);
    }
    let mut h2 = [0f32; 128];
    for j in 0..128 {
        let mut s = TAB_B2[j];
        for i in 0..256 { s += TAB_W2[j * 256 + i] * h1[i]; }
        h2[j] = relu(s);
    }
    let mut z = TAB_B3;
    for i in 0..128 { z += TAB_W3[i] * h2[i]; }
    1.0 / (1.0 + (-z.clamp(-50.0, 50.0)).exp())
}

/// delta/head 编码: 前 3072 字节 -> 相邻字节差分 (mod 256) -> 32×32×3.
pub fn delta_image(path: &Path) -> Option<[u8; 3072]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut raw = [0u8; 3072];
    let mut got = 0usize;
    while got < 3072 {
        match f.read(&mut raw[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    let mut a = [0u8; 3072];
    a[0] = raw[0];
    for i in 1..3072 {
        a[i] = raw[i].wrapping_sub(raw[i - 1]);
    }
    Some(a)
}

fn conv3x3(inp: &[f32], h: usize, w: usize, cin: usize, cout: usize,
           wm: &[f32], bm: &[f32], out: &mut [f32]) {
    // 输入 (cin,h,w) 行主序; 权重 (cout,cin,3,3)
    for co in 0..cout {
        for y in 0..h {
            for x in 0..w {
                let mut s = bm[co];
                for ci in 0..cin {
                    for ky in 0..3usize {
                        let yy = y as isize + ky as isize - 1;
                        if yy < 0 || yy >= h as isize { continue; }
                        for kx in 0..3usize {
                            let xx = x as isize + kx as isize - 1;
                            if xx < 0 || xx >= w as isize { continue; }
                            let wi = ((co * cin + ci) * 9) + (ky * 3 + kx);
                            s += wm[wi] * inp[ci * h * w + yy as usize * w + xx as usize];
                        }
                    }
                }
                out[co * h * w + y * w + x] = s;
            }
        }
    }
}

/// 图像分支: 32×32×3 delta 图 -> conv(16/32/64,3×3) + ReLU + pool2 → 4×4×64 →
/// adaptive-pool(8) 平铺 → FC(4096→128) → out(128→1) → sigmoid.
pub fn image_p(img: &[u8; 3072]) -> f32 {
    // 归一化 + 反交织: 像素主序 (RGBRGB…) -> 通道主序 (R×1024, G×1024, B×1024)
    let mut in32 = [0f32; 3 * 32 * 32];
    for i in 0..3072 {
        in32[(i % 3) * 1024 + i / 3] = (img[i] as f32 - IMG_MEAN) / IMG_STD;
    }
    // conv1 -> 16×32×32
    let mut c1 = [0f32; 16 * 32 * 32];
    conv3x3(&in32, 32, 32, 3, 16, &IMG_C1W, &IMG_C1B, &mut c1);
    for v in c1.iter_mut() { *v = relu(*v); }
    // pool2 -> 16×16×16
    let mut p1 = [0f32; 16 * 16 * 16];
    for c in 0..16 { for y in 0..16 { for x in 0..16 {
        let a = c1[c * 32 * 32 + (y * 2) * 32 + x * 2];
        let b = c1[c * 32 * 32 + (y * 2) * 32 + x * 2 + 1];
        let d = c1[c * 32 * 32 + (y * 2 + 1) * 32 + x * 2];
        let e = c1[c * 32 * 32 + (y * 2 + 1) * 32 + x * 2 + 1];
        p1[c * 16 * 16 + y * 16 + x] = a.max(b).max(d).max(e);
    }}}
    // conv2 -> 32×16×16
    let mut c2 = [0f32; 32 * 16 * 16];
    conv3x3(&p1, 16, 16, 16, 32, &IMG_C2W, &IMG_C2B, &mut c2);
    for v in c2.iter_mut() { *v = relu(*v); }
    // pool2 -> 32×8×8
    let mut p2 = [0f32; 32 * 8 * 8];
    for c in 0..32 { for y in 0..8 { for x in 0..8 {
        let a = c2[c * 16 * 16 + (y * 2) * 16 + x * 2];
        let b = c2[c * 16 * 16 + (y * 2) * 16 + x * 2 + 1];
        let d = c2[c * 16 * 16 + (y * 2 + 1) * 16 + x * 2];
        let e = c2[c * 16 * 16 + (y * 2 + 1) * 16 + x * 2 + 1];
        p2[c * 8 * 8 + y * 8 + x] = a.max(b).max(d).max(e);
    }}}
    // conv3 -> 64×8×8
    let mut c3 = [0f32; 64 * 8 * 8];
    conv3x3(&p2, 8, 8, 32, 64, &IMG_C3W, &IMG_C3B, &mut c3);
    for v in c3.iter_mut() { *v = relu(*v); }
    // pool2 -> 64×4×4, adaptive-pool(8)=2×2 平铺 -> 4096
    let mut flat8 = [0f32; 4096];
    for c in 0..64 {
        let (mut ay, mut ax);
        for oy in 0..8 { for ox in 0..8 {
            ay = oy / 2; ax = ox / 2;
            let v = c3[c * 8 * 8 + ay * 8 + ax];
            // 先 pool2 (4×4) 再平铺: c3 已是 8×8; 4×4 池化后每 2×2 → 平均
            let (p0, p1, p2_, p3);
            p0 = c3[c * 8 * 8 + ay * 2 * 8 + ax * 2];
            p1 = c3[c * 8 * 8 + ay * 2 * 8 + ax * 2 + 1];
            p2_ = c3[c * 8 * 8 + (ay * 2 + 1) * 8 + ax * 2];
            p3 = c3[c * 8 * 8 + (ay * 2 + 1) * 8 + ax * 2 + 1];
            flat8[c * 64 + oy * 8 + ox] = p0.max(p1).max(p2_).max(p3);
            let _ = v;
        }}
    }
    // FC1: 4096 -> 128 (ReLU)
    let mut h = [0f32; 128];
    for j in 0..128 {
        let mut s = IMG_F1B[j];
        for i in 0..4096 { s += IMG_F1W[j * 4096 + i] * flat8[i]; }
        h[j] = relu(s);
    }
    let mut z = IMG_F2B;
    for i in 0..128 { z += IMG_F2W[i] * h[i]; }
    1.0 / (1.0 + (-z.clamp(-50.0, 50.0)).exp())
}

/// 灵敏度档位判定 (mode: 0=高检测 1=平衡 2=低误杀).
/// 返回 (展示分, 是否判高). 深扫/结构匹配共用.
pub struct Verdict { pub score: f32, pub high: bool }

pub fn verdict(tab: f32, img: f32, mode: i32) -> Verdict {
    match mode {
        0 => { // 高检测: 0.2·tab + 0.3·img > 0.1992
            let s = 0.2 * tab + 0.3 * img;
            Verdict { score: s, high: s > 0.1992 }
        }
        2 => { // 低误杀: AND(tab>0.20, img>0.85)
            Verdict { score: if tab < img { tab } else { img }, high: tab > 0.20 && img > 0.85 }
        }
        _ => { // 平衡: AND(tab>0.40, img>0.25)
            Verdict { score: if tab < img { tab } else { img }, high: tab > 0.40 && img > 0.25 }
        }
    }
}

/// 结构匹配升级阈值 (仅表格): mode 0 -> 0.60, 1 -> 0.70, 2 -> 0.85
pub fn tab_threshold(mode: i32) -> f32 {
    match mode { 0 => 0.60, 2 => 0.85, _ => 0.70 }
}

/// 双模型打分入口: (tab, img); None = 非 PE.
pub fn ml_dual(path: &Path) -> Option<(f32, f32)> {
    let x = ml_feat_extract(path)?;
    let img = delta_image(path)?;
    Some((tabular_p(&x), image_p(&img)))
}

/// 结构匹配路径: 仅表格分支 (mode 阈值).
pub fn ml_tab_high(path: &Path, mode: i32) -> Option<(f32, bool)> {
    let x = ml_feat_extract(path)?;
    let p = tabular_p(&x);
    Some((p, p > tab_threshold(mode)))
}

/// 调试: 各层均值 (仅验证用)
pub fn dbg_image(img: &[u8; 3072]) -> [f32; 8] {
    let mut m = [0f32; 8];
    let mut in32 = [0f32; 3 * 32 * 32];
    for i in 0..3072 { in32[(i % 3) * 1024 + i / 3] = (img[i] as f32 - IMG_MEAN) / IMG_STD; }
    m[0] = in32.iter().sum::<f32>() / 3072.0;
    let mut c1 = [0f32; 16 * 32 * 32];
    conv3x3(&in32, 32, 32, 3, 16, &IMG_C1W, &IMG_C1B, &mut c1);
    for v in c1.iter_mut() { *v = relu(*v); }
    m[1] = c1.iter().sum::<f32>() / 16384.0;
    let mut p1 = [0f32; 16 * 16 * 16];
    for c in 0..16 { for y in 0..16 { for x in 0..16 {
        let a = c1[c * 1024 + (y * 2) * 32 + x * 2];
        let b = c1[c * 1024 + (y * 2) * 32 + x * 2 + 1];
        let d = c1[c * 1024 + (y * 2 + 1) * 32 + x * 2];
        let e = c1[c * 1024 + (y * 2 + 1) * 32 + x * 2 + 1];
        p1[c * 256 + y * 16 + x] = a.max(b).max(d).max(e);
    }}}
    m[2] = p1.iter().sum::<f32>() / 4096.0;
    let mut c2 = [0f32; 32 * 16 * 16];
    conv3x3(&p1, 16, 16, 16, 32, &IMG_C2W, &IMG_C2B, &mut c2);
    for v in c2.iter_mut() { *v = relu(*v); }
    m[3] = c2.iter().sum::<f32>() / 8192.0;
    let mut p2 = [0f32; 32 * 8 * 8];
    for c in 0..32 { for y in 0..8 { for x in 0..8 {
        let a = c2[c * 256 + (y * 2) * 16 + x * 2];
        let b = c2[c * 256 + (y * 2) * 16 + x * 2 + 1];
        let d = c2[c * 256 + (y * 2 + 1) * 16 + x * 2];
        let e = c2[c * 256 + (y * 2 + 1) * 16 + x * 2 + 1];
        p2[c * 64 + y * 8 + x] = a.max(b).max(d).max(e);
    }}}
    m[4] = p2.iter().sum::<f32>() / 2048.0;
    let mut c3 = [0f32; 64 * 8 * 8];
    conv3x3(&p2, 8, 8, 32, 64, &IMG_C3W, &IMG_C3B, &mut c3);
    for v in c3.iter_mut() { *v = relu(*v); }
    m[5] = c3.iter().sum::<f32>() / 4096.0;
    let mut flat8 = [0f32; 4096];
    for c in 0..64 { for oy in 0..8 { for ox in 0..8 {
        let ay = oy / 2; let ax = ox / 2;
        let p0 = c3[c * 64 + ay * 2 * 8 + ax * 2];
        let p1 = c3[c * 64 + ay * 2 * 8 + ax * 2 + 1];
        let p2_ = c3[c * 64 + (ay * 2 + 1) * 8 + ax * 2];
        let p3 = c3[c * 64 + (ay * 2 + 1) * 8 + ax * 2 + 1];
        flat8[c * 64 + oy * 8 + ox] = p0.max(p1).max(p2_).max(p3);
    }}}
    m[6] = flat8.iter().sum::<f32>() / 4096.0;
    m[7] = image_p(img);
    m
}
