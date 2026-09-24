using System.Net;

namespace Netch.Models;

public sealed class DnsPolicyConfig
{
    public int PolicyVersion { get; set; } = 1;
    public bool AllowLocalResolution { get; set; }
    public bool AllowLocalFallback { get; set; }
    public List<string> RemoteResolvers { get; set; } = ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"];
    public List<string> LocalDomainRules { get; set; } = [];
    public Dictionary<string, string> BootstrapMappings { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public int QueryTimeoutMs { get; set; } = 5000;
    public bool FakeIpEnabled { get; set; }
    public string FakeIpRange { get; set; } = "198.18.0.0/15";
    public int FakeIpTtlSeconds { get; set; } = 60;
    public List<string> FakeIpBypassDomains { get; set; } = ["localhost", "*.localhost", "*.lan", "*.local"];

    public void Validate()
    {
        if (PolicyVersion != 1 || LocalDomainRules == null || BootstrapMappings == null)
            throw new MessageException("DNS 策略版本或配置无效，请在设置中重新保存。");
        if (RemoteResolvers is not { Count: > 0 and <= 4 })
            throw new MessageException("请设置 1 至 4 个远程 DNS（https:// 或 tls://）。");
        foreach (var address in RemoteResolvers)
        {
            if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
                uri.Scheme is not ("https" or "tls") || string.IsNullOrEmpty(uri.Host) ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
                uri.Port == 0 || (uri.Scheme == "tls" && (uri.Query.Length > 0 || uri.AbsolutePath != "/" && uri.AbsolutePath != "")))
                throw new MessageException("远程 DNS 仅支持有效的 HTTPS/DoT 地址，不能包含账号或路由片段。");
        }
        if (QueryTimeoutMs is < 1000 or > 30000)
            throw new MessageException("DNS 总超时必须在 1000 至 30000 毫秒之间。");
        if (AllowLocalFallback && !AllowLocalResolution)
            throw new MessageException("本地 DNS 已关闭，不能启用本地回退。");
        if (FakeIpBypassDomains == null || FakeIpTtlSeconds is < 1 or > 300)
            throw new MessageException("Fake-IP 配置无效：映射 TTL 必须为 1 至 300 秒。");
        _ = Services.Dns.FakeIpPool.ParseRange(FakeIpRange);
        foreach (var rule in FakeIpBypassDomains) Services.Dns.FakeIpPool.ValidateDomainRule(rule);
        if (FakeIpEnabled && (AllowLocalResolution || AllowLocalFallback))
            throw new MessageException("验证型 Fake-IP 需要关闭本地 DNS 解析和本地回退。");
        foreach (var pair in BootstrapMappings)
            if (string.IsNullOrWhiteSpace(pair.Key) || !IPAddress.TryParse(pair.Value, out _))
                throw new MessageException("节点连接映射格式必须为：域名=IP地址。");
    }

    public bool IsLocalDomain(string domain)
    {
        if (!AllowLocalResolution) return false;
        var name = domain.TrimEnd('.');
        return LocalDomainRules.Any(rule =>
        {
            var suffix = rule.Trim().TrimStart('*', '.').TrimEnd('.');
            return suffix.Length > 0 && (name.Equals(suffix, StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase));
        });
    }

    public string? FindBootstrapAddress(string hostname)
    {
        if (IPAddress.TryParse(hostname, out var ip)) return ip.ToString();
        var match = BootstrapMappings.FirstOrDefault(p => p.Key.TrimEnd('.').Equals(hostname.TrimEnd('.'), StringComparison.OrdinalIgnoreCase));
        return IPAddress.TryParse(match.Value, out ip) ? ip.ToString() : null;
    }
}
