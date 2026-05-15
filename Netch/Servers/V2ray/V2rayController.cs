using System.Net;
using System.Text.Json;
using Netch.Controllers;
using Netch.Interfaces;
using Netch.Models;

namespace Netch.Servers;

public class V2rayController : Guard, IServerController
{
    public V2rayController() : base("xray.exe")
    {
    }

    protected override IEnumerable<string> StartedKeywords => new[] { "started" };

    protected override IEnumerable<string> FailedKeywords => new[] { "config file not readable", "failed to" };

    public override string Name => "Xray";

    public ushort? Socks5LocalPort { get; set; }

    public string? LocalAddress { get; set; }

    public virtual async Task<SocksServer> StartAsync(Server s)
    {
        var config = await V2rayConfigUtils.GenerateClientConfigAsync(s);
        Log.Information(
            "Generated Xray config for {ConfigType}: {OutboundCount} outbound(s): {Outbounds}",
            s.ConfigType,
            config.outbounds?.Count ?? 0,
            string.Join(", ", config.outbounds?.Select(o => $"{o.tag}:{o.protocol}:dialer={o.streamSettings?.sockopt?.dialerProxy ?? "-"}") ?? []));

        await using (var fileStream = new FileStream(Constants.TempConfig, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            await JsonSerializer.SerializeAsync(fileStream, config, Global.NewCustomJsonSerializerOptions());
        }

        await StartGuardAsync("run -c ..\\data\\last.json");
        return new SocksServer(IPAddress.Loopback.ToString(), this.Socks5LocalPort(), s.Address);
    }
}
