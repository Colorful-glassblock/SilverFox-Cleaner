// MlInfer.cs — 双模型推理: 表格 MLP-28 + delta/head 图像 CNN + 灵敏度三档.
// 权重在 MlNet.cs (硬编码); 算法与 ml/score_dual.py (fp32 参照) 一致.
using System;

namespace SFCleaner;

internal static class MlInfer
{
    static float Relu(float x) => x > 0 ? x : 0;

    /// 表格分支: 28 特征 -> 256 -> 128 -> 1, sigmoid.
    public static float TabularP(double[] x)
    {
        var h1 = new float[256];
        for (int j = 0; j < 256; j++)
        {
            float s = MlNet.TabB1[j];
            for (int i = 0; i < 28; i++)
                s += MlNet.TabW1[j * 28 + i] * ((float)x[i] - MlNet.TabMeans[i]) / MlNet.TabStds[i];
            h1[j] = Relu(s);
        }
        var h2 = new float[128];
        for (int j = 0; j < 128; j++)
        {
            float s = MlNet.TabB2[j];
            for (int i = 0; i < 256; i++) s += MlNet.TabW2[j * 256 + i] * h1[i];
            h2[j] = Relu(s);
        }
        float z = MlNet.TabB3;
        for (int i = 0; i < 128; i++) z += MlNet.TabW3[i] * h2[i];
        z = Math.Clamp(z, -50f, 50f);
        return 1f / (1f + MathF.Exp(-z));
    }

    /// delta/head 编码: 前 3072 字节 -> 相邻字节差分.
    public static bool DeltaImg(string path, byte[] outB)
    {
        try
        {
            using var f = File.OpenRead(path);
            int got = f.Read(outB, 0, 3072);
            if (got <= 0) return false;
            if (got < 3072) Array.Clear(outB, got, 3072 - got);
            var raw = (byte[])outB.Clone();
            outB[0] = raw[0];
            for (int i = 1; i < 3072; i++) outB[i] = (byte)(raw[i] - raw[i - 1]);
            return true;
        }
        catch { return false; }
    }

    static void Conv3x3(float[] inp, int h, int w, int cin, int cout, float[] wm, float[] bm, float[] outp)
    {
        for (int co = 0; co < cout; co++)
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                {
                    float s = bm[co];
                    for (int ci = 0; ci < cin; ci++)
                        for (int ky = 0; ky < 3; ky++)
                        {
                            int yy = y + ky - 1;
                            if (yy < 0 || yy >= h) continue;
                            for (int kx = 0; kx < 3; kx++)
                            {
                                int xx = x + kx - 1;
                                if (xx < 0 || xx >= w) continue;
                                s += wm[((co * cin + ci) * 9) + ky * 3 + kx]
                                   * inp[ci * h * w + yy * w + xx];
                            }
                        }
                    outp[co * h * w + y * w + x] = s;
                }
    }

    static void MaxPool(float[] inp, int h, int w, int c, float[] outp)
    {
        int hh = h / 2, ww = w / 2;
        for (int cc = 0; cc < c; cc++)
            for (int y = 0; y < hh; y++)
                for (int x = 0; x < ww; x++)
                {
                    float a = inp[cc * h * w + (y * 2) * w + x * 2];
                    float b = inp[cc * h * w + (y * 2) * w + x * 2 + 1];
                    float d = inp[cc * h * w + (y * 2 + 1) * w + x * 2];
                    float e = inp[cc * h * w + (y * 2 + 1) * w + x * 2 + 1];
                    float m1 = a > b ? a : b, m2 = d > e ? d : e;
                    outp[cc * hh * ww + y * ww + x] = m1 > m2 ? m1 : m2;
                }
    }

    /// 图像分支: 32×32×3 delta 图.
    public static float ImageP(byte[] img)
    {
        var in32 = new float[3072];
        for (int i = 0; i < 3072; i++)
            in32[(i % 3) * 1024 + i / 3] = (img[i] - MlNet.ImgMean) / MlNet.ImgStd;
        var c1 = new float[16 * 32 * 32]; var p1 = new float[16 * 16 * 16];
        var c2 = new float[32 * 16 * 16]; var p2 = new float[32 * 8 * 8];
        var c3 = new float[64 * 8 * 8]; var flat8 = new float[4096]; var h = new float[128];
        Conv3x3(in32, 32, 32, 3, 16, MlNet.ImgC1W, MlNet.ImgC1B, c1);
        for (int i = 0; i < c1.Length; i++) c1[i] = Relu(c1[i]);
        MaxPool(c1, 32, 32, 16, p1);
        Conv3x3(p1, 16, 16, 16, 32, MlNet.ImgC2W, MlNet.ImgC2B, c2);
        for (int i = 0; i < c2.Length; i++) c2[i] = Relu(c2[i]);
        MaxPool(c2, 16, 16, 32, p2);
        Conv3x3(p2, 8, 8, 32, 64, MlNet.ImgC3W, MlNet.ImgC3B, c3);
        for (int i = 0; i < c3.Length; i++) c3[i] = Relu(c3[i]);
        for (int c = 0; c < 64; c++)
            for (int oy = 0; oy < 8; oy++)
                for (int ox = 0; ox < 8; ox++)
                {
                    int ay = oy / 2, ax = ox / 2;
                    float a = c3[c * 64 + ay * 2 * 8 + ax * 2];
                    float b = c3[c * 64 + ay * 2 * 8 + ax * 2 + 1];
                    float d = c3[c * 64 + (ay * 2 + 1) * 8 + ax * 2];
                    float e = c3[c * 64 + (ay * 2 + 1) * 8 + ax * 2 + 1];
                    float m1 = a > b ? a : b, m2 = d > e ? d : e;
                    flat8[c * 64 + oy * 8 + ox] = m1 > m2 ? m1 : m2;
                }
        for (int j = 0; j < 128; j++)
        {
            float s = MlNet.ImgF1B[j];
            for (int i = 0; i < 4096; i++) s += MlNet.ImgF1W[j * 4096 + i] * flat8[i];
            h[j] = Relu(s);
        }
        float z = MlNet.ImgF2B;
        for (int i = 0; i < 128; i++) z += MlNet.ImgF2W[i] * h[i];
        z = Math.Clamp(z, -50f, 50f);
        return 1f / (1f + MathF.Exp(-z));
    }

    public readonly record struct Verdict(float Score, bool High);

    /// 灵敏度: 0=高检测 1=平衡(默认) 2=低误杀
    public static Verdict Decide(float tab, float img, int mode) => mode switch
    {
        0 => new Verdict(0.2f * tab + 0.3f * img, 0.2f * tab + 0.3f * img > 0.1992f),
        2 => new Verdict(Math.Min(tab, img), tab > 0.20f && img > 0.85f),
        _ => new Verdict(Math.Min(tab, img), tab > 0.40f && img > 0.25f),
    };

    public static float TabThreshold(int mode) => mode == 0 ? 0.60f : (mode == 2 ? 0.85f : 0.70f);
}
