using WindowsFirewallHelper;
using WindowsFirewallHelper.FirewallRules;

namespace Netch.Utils;

public static class Firewall
{
    private const string Netch = "Netch";

    /// <summary>
    ///     Netch 自带程序添加防火墙
    /// </summary>
    public static void AddNetchFwRules()
    {
        if (!FirewallWAS.IsLocallySupported)
        {
            Log.Warning("Windows Firewall Locally Unsupported");
            return;
        }

        try
        {
            // An existing rule for an older version must not suppress new core paths.
            var covered = FirewallManager.Instance.Rules.Where(r => r.Name == Netch
                    && r.Direction == FirewallDirection.Inbound && r.Action == FirewallAction.Allow && r.IsEnable)
                .Select(r => r.ApplicationName).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var path in Directory.GetFiles(Global.NetchDir, "*.exe", SearchOption.AllDirectories))
                if (!covered.Contains(path)) AddFwRule(Netch, path);
        }
        catch (Exception e)
        {
            Log.Warning(e, "Create Netch Firewall rules error");
        }
    }

    /// <summary>
    ///     清除防火墙规则 (Netch 自带程序)
    /// </summary>
    public static void RemoveNetchFwRules()
    {
        if (!FirewallWAS.IsLocallySupported)
            return;

        try
        {
            foreach (var rule in FirewallManager.Instance.Rules.Where(r
                         => r.ApplicationName?.StartsWith(Global.NetchDir, StringComparison.OrdinalIgnoreCase) ?? r.Name == Netch))
                FirewallManager.Instance.Rules.Remove(rule);
        }
        catch (Exception e)
        {
            Log.Warning(e, "Remove Netch Firewall rules error");
        }
    }

    #region 封装

    private static void AddFwRule(string ruleName, string exeFullPath)
    {
        var rule = new FirewallWASRule(ruleName,
            exeFullPath,
            FirewallAction.Allow,
            FirewallDirection.Inbound,
            FirewallProfiles.Private | FirewallProfiles.Public | FirewallProfiles.Domain);

        FirewallManager.Instance.Rules.Add(rule);
    }

    #endregion
}
