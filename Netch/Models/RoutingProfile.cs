namespace Netch.Models;

public class RoutingProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string Remarks { get; set; } = "Default";

    public bool Enabled { get; set; } = true;

    public List<RoutingRule> Rules { get; set; } = new();
}

public class RoutingRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string Remarks { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public string OutboundServerId { get; set; } = RoutingOutbound.Proxy;

    public List<string> Domain { get; set; } = new();

    public List<string> Ip { get; set; } = new();

    public string Port { get; set; } = string.Empty;

    public string Network { get; set; } = string.Empty;

    public List<string> Protocol { get; set; } = new();

    public List<string> InboundTag { get; set; } = new();

    public List<string> Process { get; set; } = new();
}

public static class RoutingOutbound
{
    public const string Proxy = "proxy";
    public const string Direct = "direct";
    public const string Block = "block";
}
