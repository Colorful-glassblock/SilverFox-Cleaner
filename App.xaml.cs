using Microsoft.UI.Xaml;

namespace SFCleaner;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // 无头命令行模式（自启动 / 手动调用）:
        //   --extreme          进入极端模式(两阶段蓝屏+自毁), 阶段标记在 HKLM\Software\SFCleaner
        //   --extreme-abort    解除自启动与阶段标记
        var cli = Environment.GetCommandLineArgs();
        if (cli.Any(a => a == "--extreme"))
        {
            Scanner.ExtremeRun(null);
            // 正常不会走到这里 —— TriggerBsod 后进程随系统蓝屏消亡
            Environment.Exit(0);
            return;
        }
        if (cli.Any(a => a == "--extreme-abort"))
        {
            Scanner.ExtremeAbort();
            Environment.Exit(0);
            return;
        }
        if (cli.Any(a => a == "--wipe-quarantine"))
        {
            var (n, b) = Scanner.QuarantineStats();
            Scanner.QuarantineWipe();
            Environment.Exit(0);
            return;
        }
        if (cli.Any(a => a == "scan"))
        {
            var f = Scanner.ScanAll();
            Environment.Exit(0);
            return;
        }
        _window = new MainWindow();
        _window.Activate();
    }
}
