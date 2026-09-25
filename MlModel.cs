// MlModel.cs — 双模型打分入口 (权重与前向在 MlNet.cs / MlInfer.cs)
using System;

namespace SFCleaner;

internal static class MlModel
{
    /// <summary>双模型打分 (tab, img); null = 非 PE / 无法编码.</summary>
    public static (float Tab, float Img)? DualScore(string path)
    {
        var x = PeFeat.Extract(path);
        if (x == null) return null;
        var img = new byte[3072];
        if (!MlInfer.DeltaImg(path, img)) return null;
        return (MlInfer.TabularP(x), MlInfer.ImageP(img));
    }

    /// <summary>结构匹配升级: 仅表格分支 + 灵敏度阈值.</summary>
    public static (float Score, bool High)? TabScore(string path, int mode)
    {
        var x = PeFeat.Extract(path);
        if (x == null) return null;
        float p = MlInfer.TabularP(x);
        return (p, p > MlInfer.TabThreshold(mode));
    }
}
