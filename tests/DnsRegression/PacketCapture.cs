using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

internal sealed class PacketCapture(string root) : IDisposable
{
    private readonly string _directory = Path.Combine(root, ".build", "acceptance");
    private bool _filters;
    private bool _started;

    private string Run(params string[] args)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "pktmon.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info)!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15000)) { process.Kill(); throw new Exception("Packet monitor command timeout"); }
        var result = output.GetAwaiter().GetResult() + error.GetAwaiter().GetResult();
        File.AppendAllText(Path.Combine(_directory, "pktmon.log"), string.Join(" ", args) + "\n" + result);
        if (process.ExitCode != 0) throw new Exception("Packet monitor failed: " + result);
        return result;
    }

    public void Start()
    {
        Directory.CreateDirectory(_directory);
        var status = Run("status"); var filters = Run("filter", "list");
        if (!(status.Contains("没有运行") || status.Contains("not running", StringComparison.OrdinalIgnoreCase)))
            throw new Exception("Existing capture not confirmed idle; left untouched");
        if (!(filters.Split('\n').Any(l => l.Trim() == "无") || filters.Contains("No filters", StringComparison.OrdinalIgnoreCase)))
            throw new Exception("Preexisting capture filters; left untouched");
        File.WriteAllText(Path.Combine(_directory, "components.json"), Run("list", "--json"));
        foreach (var port in new[] { 53, 853, 5353, 5355, 137, 45453 })
        {
            Run("filter", "add", "NetchAcceptance-" + port, "-p", port.ToString()); _filters = true;
        }
        Run("start", "--capture", "--comp", "nics", "--pkt-size", "256", "--file-size", "16", "--file-name", Path.Combine(_directory, "coexist.etl"));
        _started = true;
    }

    public async Task ControlAsync()
    {
        // Deliberately non-DNS payload on an unrelated port, used only to prove
        // capture observed outbound traffic. Never count an empty capture as proof.
        foreach (var ip in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().GatewayAddresses).Select(g => g.Address)
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork).Distinct())
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            await udp.SendAsync(Encoding.ASCII.GetBytes("NETCH-CAPTURE-CONTROL"), new System.Net.IPEndPoint(ip, 45453));
        }
    }

    public void Checkpoint(string name) => File.WriteAllText(Path.Combine(_directory, name + "-counters.json"), Run("counters", "--json", "--zero"));
    public void ResetCounters() => Run("reset");

    public void Dispose()
    {
        try
        {
            if (_started)
            {
                Run("counters"); Run("stop"); _started = false;
                Run("etl2pcap", Path.Combine(_directory, "coexist.etl"), "--out", Path.Combine(_directory, "coexist.pcapng"));
            }
        }
        finally { if (_filters) { Run("filter", "remove"); _filters = false; } }
    }
}
