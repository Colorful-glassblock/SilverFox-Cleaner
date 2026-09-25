using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System.Collections.ObjectModel;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Windowing;
using Windows.Graphics;
using System.Reflection;

namespace SFCleaner;

public sealed partial class MainWindow : Window
{
    /// 版本号: CI 按命名规则注入 (<branch>-release-<ver> / <branch>-pre-<sha8>) 到
    /// AssemblyInformationalVersion; 本地构建缺省 v5.1-dev (csproj 兜底).
    private static string AppVer()
    {
        try
        {
            var s = typeof(MainWindow).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion ?? "v5.1-dev";
            int p = s.IndexOf('+');   // SourceLink 追加的 +<sha> 截掉
            return p > 0 ? s[..p] : s;
        }
        catch { return "v5.1-dev"; }
    }
    private List<Finding> _findings = [];
    private readonly ObservableCollection<Finding> _items = [];   /* 实时上屏 (增量动画) */
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
        Title = $"SilverFox Cleaner {AppVer()} — 银狐检测清除 (WinUI3)";
        SystemBackdrop = new MicaBackdrop();
        try { AppWindow.Resize(new SizeInt32(1020, 720)); } catch { /* N/A 桌面 */ }

        AppendLog($"SilverFox Cleaner {AppVer()} (WinUI3) — dmo/client");
        AppendLog("检测: 持久化 / 落盘物 / 互斥 / SrL / ctfmon内存注入");
        AppendLog("权限: SYSTEM + TrustedInstaller 提权 | 隔离: 时间戳加密 SFQENC1 (仅本工具可还原)");
        AppendLog("扫描: 多线程并行 (任务+服务 | 进程+内存 | 文件)");
        AppendLog("");
        LvFindings.ItemsSource = _items;   /* 增量集合: 发现即插入, 配合 Entrance/Add 动画 */
    }

    private void AppendLog(string s) => TbLog.Text += s + "\n";

    // ---- 扫描 ----

    private void MlToggle_Click(object sender, RoutedEventArgs e)
    {
        Scanner.MlEnabled = MlToggle.IsChecked == true;
        Scanner.SaveMlConfig();   // 持久化, 极端模式跨重启继承
        AppendLog(Scanner.MlEnabled
            ? "[ML] 结构匹配 ML 复核已开启 (实验性; 打分>0.7 升为高置信)"
            : "[ML] 结构匹配 ML 复核已关闭 (默认)");
        TblStatus.Text = Scanner.MlEnabled ? "ML 复核: 开 (实验性)" : "ML 复核: 关";
    }

    private void DeepScanToggle_Click(object sender, RoutedEventArgs e)
    {
        Scanner.DeepMlScan = DeepScanToggle.IsChecked == true;
        Scanner.SaveMlConfig();   // 持久化, 极端模式跨重启继承
        AppendLog(Scanner.DeepMlScan
            ? "[ML] 深度 ML 扫描已开启 (实验性; AppData/TEMP/PF/ProgramData 全量 PE 打分, >0.7 报 ML深度)"
            : "[ML] 深度 ML 扫描已关闭 (默认)");
        TblStatus.Text = Scanner.DeepMlScan ? "深度ML: 开 (实验性)" : "深度ML: 关";
    }

    private void SetMode(int mode, string name)
    {
        Scanner.MlMode = mode;
        Scanner.SaveMlConfig();   // 持久化, 极端模式跨重启继承
        ModeHigh.IsChecked = mode == 0;
        ModeBal.IsChecked = mode == 1;
        ModeLow.IsChecked = mode == 2;
        AppendLog($"[ML] 灵敏度: {name}");
        TblStatus.Text = $"ML灵敏度: {name}";
    }

    private void ModeHigh_Click(object sender, RoutedEventArgs e) => SetMode(0, "高检测率");
    private void ModeBal_Click(object sender, RoutedEventArgs e) => SetMode(1, "平衡 (默认)");
    private void ModeLow_Click(object sender, RoutedEventArgs e) => SetMode(2, "低误杀");

    private async void Scan_Click(object sender, RoutedEventArgs e) => await RunScanAsync();

    private async Task RunScanAsync()
    {
        if (_busy) return;
        _busy = true;
        BtnScan.IsEnabled = BtnClean.IsEnabled = false;
        BusyRing.IsActive = true;
        _items.Clear();
        TblEmpty.Visibility = Visibility.Collapsed;
        BarScan.Value = 0;
        BarScan.IsIndeterminate = true;
        TblLive.Text = "准备中…";
        TblStatus.Text = "扫描中 (多线程并行)…";
        AppendLog($"[{DateTime.Now:HH:mm:ss}] 扫描中…");

        /* 三段实时回报: 日志 / 进度(0..1) / 发现项(即时插入 → 动画上屏) */
        var log = new Progress<string>(AppendLog);
        var prog = new Progress<double>(p =>
        {
            BarScan.IsIndeterminate = false;
            BarScan.Value = Math.Round(p * 100);
            TblLive.Text = $"已发现 {_items.Count} 项 · {p * 100:F0}%";
        });
        var found = new Progress<Finding>(f =>
        {
            _items.Add(f);
            TblLive.Text = $"已发现 {_items.Count} 项" + (BarScan.IsIndeterminate ? "" : $" · {BarScan.Value:F0}%");
        });

        _findings = await Task.Run(() => Scanner.ScanAll(log, prog, found));

        BarScan.IsIndeterminate = false;
        BarScan.Value = 100;
        TblLive.Text = $"完成 · {_findings.Count} 项";
        bool none = _findings.Count == 0;
        TblEmpty.Visibility = none ? Visibility.Visible : Visibility.Collapsed;
        int hi = _findings.Count(f => f.High);
        TblStats.Text = none
            ? "[OK] 未发现银狐痕迹"
            : $"共 {_findings.Count} 项 (高置信 {hi} · 结构 {_findings.Count - hi})";
        TblStatus.Text = none ? "系统干净" : "建议清除后重启确认无复活";

        foreach (var f in _findings)
            AppendLog($"[{f.Kind,-8}] {f.Detail}\n           → {f.Action}");
        if (!none) AppendLog("[提示] 点击「清除」处理以上项");

        BusyRing.IsActive = false;
        BtnScan.IsEnabled = true;
        BtnClean.IsEnabled = !none;
        _busy = false;
    }

    // ---- 清除 ----

    private async void Clean_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _findings.Count == 0) return;
        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = "确认清除",
            Content = $"发现 {_findings.Count} 项银狐痕迹\n确认清除？文件将移入隔离区。",
            PrimaryButtonText = "清除",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Primary,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return;

        _busy = true;
        BtnScan.IsEnabled = BtnClean.IsEnabled = false;
        BusyRing.IsActive = true;
        TblStatus.Text = "清除中 (TrustedInstaller 提权)…";
        AppendLog($"[{DateTime.Now:HH:mm:ss}] 清除中…");

        var log = new Progress<string>(AppendLog);
        var prog = new Progress<double>(p2 =>
        {
            BarScan.IsIndeterminate = false;
            BarScan.Value = Math.Round(p2 * 100);
            TblLive.Text = $"清除中 {p2:P0}";
        });
        var res = await Task.Run(() => Scanner.Clean(_findings, log, prog));

        BarScan.IsIndeterminate = false;
        BarScan.Value = 100;
        TblLive.Text = $"清除完成 · {res.Ok}/{_findings.Count}";
        AppendLog($"完成: {res.Ok} 成功, {res.Fail} 失败");
        AppendLog("建议重启确认无复活");
        TblStatus.Text = $"清除完成: {res.Ok} 成功, {res.Fail} 失败";
        BusyRing.IsActive = false;
        BtnScan.IsEnabled = true;
        _busy = false;

        await RunScanAsync(); // 清后复扫验证
    }

    // ---- 隔离区（加密还原）----

    private async void Quar_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var items = await Task.Run(Scanner.ListQuarantine);
        if (items.Count == 0)
        {
            await ShowInfoAsync("隔离区为空", "尚无隔离项。清除文件后会以清理时间戳为密钥加密封存到 C:\\ProgramData\\sf_quarantine\\<时间戳>\\*.qenc。");
            return;
        }

        var lv = new ListView { SelectionMode = ListViewSelectionMode.Single, Height = 320 };
        foreach (var it in items)
            lv.Items.Add($"{System.IO.Path.GetFileName(it.SealedPath)}  ({it.Size / 1024} KB)  ←  {it.OrigPath}");

        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = $"隔离区 — {items.Count} 项 (SFQENC1 时间戳加密)",
            Content = lv,
            PrimaryButtonText = "还原选中",
            SecondaryButtonText = "全部还原",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
        };
        var r = await dlg.ShowAsync();

        List<QuarItem> targets = r switch
        {
            ContentDialogResult.Primary when lv.SelectedIndex >= 0 => [items[lv.SelectedIndex]],
            ContentDialogResult.Secondary => [.. items],
            _ => [],
        };
        if (targets.Count == 0) return;

        _busy = true;
        BtnScan.IsEnabled = BtnClean.IsEnabled = false;
        BusyRing.IsActive = true;
        TblStatus.Text = $"还原中 ({targets.Count} 项)…";

        var log = new Progress<string>(AppendLog);
        int ok = 0;
        await Task.Run(() =>
        {
            foreach (var t in targets)
            {
                bool s = Scanner.Restore(t);
                ((IProgress<string>)log).Report((s ? "[+] 已还原 " : "[-] 还原失败 ") + t.OrigPath);
                if (s) Interlocked.Increment(ref ok);
            }
        });

        AppendLog($"还原完成: {ok} 成功, {targets.Count - ok} 失败");
        TblStatus.Text = $"还原完成: {ok}/{targets.Count}";
        BusyRing.IsActive = false;
        BtnScan.IsEnabled = true;
        _busy = false;
    }

    private async Task ShowInfoAsync(string title, string message)
    {
        await new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = title,
            Content = message,
            CloseButtonText = "确定",
        }.ShowAsync();
    }

    // ---- 清空隔离区 ----

    private async void Wipe_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var (count, bytes) = await Task.Run(Scanner.QuarantineStats);
        if (count == 0)
        {
            await ShowInfoAsync("隔离区为空", "没有可清空的隔离文件。");
            return;
        }
        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = "清空隔离区",
            Content = $"删除全部 {count} 个隔离文件（共 {bytes / 1048576.0:F1} MB）？\n不可恢复！如需个别还原请用「隔离区」按钮。",
            PrimaryButtonText = "全部删除",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return;
        bool ok = await Task.Run(Scanner.QuarantineWipe);
        AppendLog(ok ? $"[*] 已清空隔离区 ({count} 个文件)" : "[!] 清空隔离区失败");
        TblStatus.Text = ok ? $"隔离区已清空 ({count} 项)" : "清空失败";
    }

    // ---- 极端模式 ----

    private async void Extreme_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = "☢ 极端模式确认",
            Content = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 440,
                Text = "序列: 写入自启动 → 扫描清除 → 蓝屏重启\n"
                     + "重启后自动: 再次清除 → 解除自启动 → 自毁 → 再蓝屏\n\n"
                     + "共两次蓝屏！请保存所有工作！\n"
                     + "（逃生门: SFCleaner.exe --extreme-abort）",
            },
            PrimaryButtonText = "启动极端模式",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return;

        _busy = true;
        BusyRing.IsActive = true;
        TblStatus.Text = "极端模式执行中…";
        var log = new Progress<string>(AppendLog);
        await Task.Run(() => Scanner.ExtremeRun(log));
        // 正常不会走到这里 — TriggerBsod 之后进程不复存在
        BusyRing.IsActive = false;
        _busy = false;
    }

    private async void Nomore_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = "⚡ 不客气模式确认 (实验性功能 — 不稳定)",
            Content = new TextBlock
            {
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 440,
                Text = "⚠ 实验性功能, 不稳定! 仅限虚拟机, 请保存所有工作!\n\n"
                     + "导入自定义证书 + 装载内核驱动清理\n"
                     + "testsigning ON → 蓝屏重启 → 驱动清理 → 卸载 → 删证书 → testsigning OFF\n\n"
                     + "材料: SFCleanerDrv.sys + SFCleanerCert.pfx/cer 与程序同目录",
            },
            PrimaryButtonText = "启动不客气模式",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
        };
        if (await dlg.ShowAsync() != ContentDialogResult.Primary) return;
        _busy = true;
        BusyRing.IsActive = true;
        TblStatus.Text = "不客气模式执行中…";
        var log = new Progress<string>(AppendLog);
        await Task.Run(() => Scanner.NomoreRun(log));
        BusyRing.IsActive = false;
        _busy = false;
    }

    // ---- 关于 ----

    private async void About_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = "关于",
            CloseButtonText = "关闭",
        };
        dlg.Content = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 420,
            Text = $"""
                SilverFox Cleaner {AppVer()} (WinUI3)

                银狐木马 (dmo/client Go RAT) 检测清除工具。

                检测:
                  • 计划任务 (EkxZJr / SrL.exe / cd /d && start)
                  • 服务持久化 (注册表 Services 树遍历)
                  • 进程 SrL.exe + 互斥体 Global\P_<倒序PID>
                  • ctfmon.exe 内存注入 (C2 域名特征扫描)
                  • 落盘文件 (名称特征 + STEGR1Xp/JELG/PNG 伪装魔数)

                权限: SYSTEM + TrustedInstaller 式 takeown/icacls
                隔离: C:\ProgramData\sf_quarantine\<时间戳>\*.qenc
                      以清理时间戳为密钥加密，明文 PE 不落盘防复活；
                      还原仅经「隔离区」按钮在应用内解密回写原路径。

                IOC: C2 RSA-2048 SHA256(DER)=3cef796a…
                """,
        };
        await dlg.ShowAsync();
    }
}
