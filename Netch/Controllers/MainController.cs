using Microsoft.VisualStudio.Threading;
using Netch.Interfaces;
using Netch.Models;
using Netch.Models.Modes;
using Netch.Servers;
using Netch.Services;
using Netch.Services.Dns;
using Netch.Enums;
using Netch.Models.Modes.TunMode;
using Netch.Utils;
using System.Diagnostics;

namespace Netch.Controllers;

public static class MainController
{
    public static SocksServer? Socks5Server { get; private set; }

    public static Server? Server { get; private set; }

    public static Mode? Mode { get; private set; }

    public static IServerController? ServerController { get; private set; }

    public static IModeController? ModeController { get; private set; }

    private static readonly AsyncSemaphore Lock = new(1);

    public static async Task StartAsync(Server server, Mode? mode = null)
    {
        using var releaser = await Lock.EnterAsync();

        Log.Information("Start MainController: {Server} {Mode}", $"{server.ConfigType}", mode == null ? "Null" : $"[{(int)mode.Type}]{mode.i18NRemark}");

        await StopLockedAsync();

        Server = server;
        Mode = mode;

        var stage = "准备 DNS 服务";
        void Phase(string name) => stage = name;
        try
        {
            if (!DnsRuntime.Strict && DnsRuntime.Protection.Active)
                throw new MessageException("DNS 保护仍在生效。切换到允许本地解析前，请先使用“停止并恢复系统 DNS”。");
            DnsRuntime.Ipv4Only = mode is TunMode;
            Phase(stage);
            await DnsRuntime.PrepareAsync();
            if (DnsRuntime.Strict)
            {
                Phase("检查节点配置");
                // Validate every leaf and routing dependency before changing system DNS.
                // Strict config generation uses only literal IPs or explicit mappings.
                if (server.ConfigType is EConfigType.TUIC or EConfigType.Anytls)
                    _ = await SingboxConfigUtils.GenerateClientConfigAsync(server);
                else
                    _ = await V2rayConfigUtils.GenerateClientConfigAsync(server);
                Phase("建立 DNS 防护");
                await DnsRuntime.Protection.EnableAsync(mode is TunMode);
            }
            Phase("初始化网络");
            await Task.WhenAll(Task.Run(NativeMethods.RefreshDNSCache), Task.Run(Firewall.AddNetchFwRules));
            if (mode != null)
            {
                ModeController = ModeService.GetModeControllerByType(mode.Type, out var modePort, out var portName);


                if (modePort != null)
                    TryReleaseTcpPort((ushort)modePort, portName);
            }

            //如果是 Socks5 服务器且没有密码
            //或者如果是 Socks5 服务器，且模式控制器支持 Socks5 则直接使用该服务器
            //if (Server is SocksServer socks5 && (ModeController == null ? socks5.Auth() : (!socks5.Auth() || ModeController.Features.HasFlag(ModeFeature.SupportSocks5Auth))))
            //{

            //    Socks5Server = socks5;
            //}
            //else
            //{
            // Start Server Controller to get a local socks5 server
            Log.Debug("Server Information: {Data}", $"{server.ConfigType} {server.MaskedData()}");

            ServerController = server.ConfigType is EConfigType.TUIC or EConfigType.Anytls
                ? new SingboxController() : new V2rayController();
            if (ServerController is Guard guard)
            {
                guard.Instance.EnableRaisingEvents = true;
                guard.Instance.Exited += (_, _) =>
                {
                    if (ReferenceEquals(ServerController, guard)) DnsRuntime.Suspend();
                };
            }
            Global.MainForm.StatusText(i18N.TranslateFormat("Starting {0}", ServerController.Name));

            TryReleaseTcpPort(ServerController.Socks5LocalPort(), "Socks5");
            Phase("启动代理核心");
            Socks5Server = await ServerController.StartAsync(server);
            Phase("连接远程 DNS");
            await DnsRuntime.ReadyAsync();

            StatusPortInfoText.Socks5Port = (ushort)Socks5Server.Port;
            StatusPortInfoText.UpdateShareLan();
            //}

            // Start Mode Controller
            if (mode != null)
            {
                Phase("启动代理模式");
                Global.MainForm.StatusText(i18N.TranslateFormat("Starting {0}", ModeController.Name));
                await ModeController.StartAsync(Socks5Server, mode);
                // Mode setup may change routes or filtering; recheck the final DNS path.
                Phase("验证远程 DNS");
                await DnsRuntime.Service!.ProbeAsync();
            }
        }
        catch (Exception e)
        {
            Log.Error(e, "MainController startup failed during {Stage}", stage);
            await RecordStartupFailureAsync(stage, e);
            await StopLockedAsync();

            switch (e)
            {
                case DllNotFoundException:
                    throw new Exception(e.Message + "\n\n" + i18N.Translate("Missing File or runtime components"));
                case FileNotFoundException missingFile:
                    throw new MessageException(string.IsNullOrWhiteSpace(missingFile.FileName)
                        ? "启动时系统资源访问失败。请查看 logging/application.log 中的完整错误。"
                        : $"启动所需文件不存在：{missingFile.FileName}");
                case MessageException:
                    throw;
                default:
                    throw new MessageException($"启动失败：{stage}（0x{e.HResult:X8}）。\n{e.Message}\n\n详细信息见 data/startup-error.log。");
            }
        }
    }

    public static async Task StopAsync()
    {
        using var _ = await Lock.EnterAsync();
        await StopLockedAsync();
    }

    private static async Task RecordStartupFailureAsync(string stage, Exception exception)
    {
        try
        {
            // The legacy launcher clears logging/ on every start. Keep the most recent
            // startup failure in data/ so restarting or reverting does not erase it.
            Directory.CreateDirectory(Configuration.DataDirectoryFullName);
            await File.WriteAllTextAsync(Path.Combine(Configuration.DataDirectoryFullName, "startup-error.log"),
                $"{DateTimeOffset.Now:O} Netch {UpdateChecker.Version}\n阶段：{stage}\n{exception}\n");
        }
        catch (Exception logError) { Log.Warning(logError, "Could not preserve startup failure details"); }
    }

    public static async Task RestoreDnsAsync()
    {
        using var _ = await Lock.EnterAsync();
        await StopLockedAsync();
        await DnsRuntime.Protection.RestoreAsync();
        await DnsRuntime.DisposeServiceAsync();
        DnsRuntime.Report("已恢复系统 DNS，DNS 保护已解除。");
    }

    private static async Task StopLockedAsync()
    {
        DnsRuntime.Suspend();

        if (ServerController == null && ModeController == null)
            return;

        Log.Information("Stop Main Controller");
        StatusPortInfoText.Reset();
        var stopErrors = new List<string>();

        try
        {
            if (ModeController != null) await ModeController.StopAsync();
            ModeController = null;
        }

        catch (Exception e)
        {
            Log.Error(e, "MainController Stop Error");
            stopErrors.Add(e.Message);
        }

        try { if (ServerController != null) await ServerController.StopAsync(); ServerController = null; }
        catch (Exception e) { Log.Error(e, "Server controller stop failed"); stopErrors.Add(e.Message); }
        Socks5Server = null;
        if (stopErrors.Count > 0) throw new MessageException("停止未完成，DNS 保护保持。请重试停止或恢复：" + string.Join("；", stopErrors));
    }

    public static void PortCheck(ushort port, string portName, PortType portType = PortType.Both)
    {
        try
        {
            PortHelper.CheckPort(port, portType);
        }
        catch (PortInUseException)
        {
            throw new MessageException(i18N.TranslateFormat("The {0} port is in use.", $"{portName} ({port})"));
        }
        catch (PortReservedException)
        {
            throw new MessageException(i18N.TranslateFormat("The {0} port is reserved by system.", $"{portName} ({port})"));
        }
    }

    public static void TryReleaseTcpPort(ushort port, string portName)
    {
        // A port conflict must never terminate another application or this DNS listener.
        PortCheck(port, portName, PortType.TCP);
    }

    public static List<int> GetPidByUdpPort(int port)
    {
        var pids = new List<int>();

        var startInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c netstat -ano -p udp | findstr :{port}",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo);
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        if (string.IsNullOrWhiteSpace(output))
            return pids;

        var lines = output.Split('\n');

        foreach (var line in lines)
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 4)
                continue;

            if (int.TryParse(parts[^1], out int pid))
            {
                pids.Add(pid);
            }
        }

        return pids;
    }

    public static Task<NatTypeTestResult> DiscoveryNatTypeAsync(CancellationToken ctx = default)
    {
        Debug.Assert(Socks5Server != null, nameof(Socks5Server) + " != null");
        return Socks5ServerTestUtils.DiscoveryNatTypeAsync(Socks5Server, ctx);
    }

    public static Task<int?> HttpConnectAsync(CancellationToken ctx = default)
    {
        Debug.Assert(Socks5Server != null, nameof(Socks5Server) + " != null");
        try
        {
            return Socks5ServerTestUtils.HttpConnectAsync(Socks5Server, ctx);
        }
        catch (OperationCanceledException)
        {
            // ignored
        }
        catch (Exception e)
        {
            Log.Warning(e, "Unhandled Socks5ServerTestUtils.HttpConnectAsync Exception");
        }

        return Task.FromResult<int?>(null);
    }
}
