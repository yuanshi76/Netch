using Netch.Enums;
using Netch.Models;
using Netch.Utils;

namespace Netch.Servers;

public static class GroupServerHelper
{
    private static readonly HashSet<EConfigType> SecondaryOnlyConfigTypes =
    [
        EConfigType.HTTP,
        EConfigType.SOCKS
    ];

    public static bool IsSecondaryOnlyProxy(Server server)
    {
        return SecondaryOnlyConfigTypes.Contains(server.ConfigType);
    }

    public static bool CanBePrimaryProxy(Server server)
    {
        return !IsSecondaryOnlyProxy(server);
    }

    public static string PrimaryProxyValidationMessage(Server server)
    {
        return $"{server.ConfigType} [{server.Remarks}] 只能作为链式代理中的后续出口使用，请把 VLESS、VMess、Trojan、Shadowsocks 等节点放在第一跳。";
    }

    public static List<string> ChildIds(Server server)
    {
        return Utils.Utils.String2List(server.ProtoExtra.ChildItems) ?? [];
    }

    public static List<Server> ChildServers(Server server)
    {
        return ChildIds(server)
            .Select(id => Global.Settings.Server.FirstOrDefault(s => s.Id == id))
            .Where(s => s != null)
            .Cast<Server>()
            .ToList();
    }

    public static bool HasCycle(Server server, IReadOnlyCollection<string>? childIds = null)
    {
        var stack = new HashSet<string>();
        return HasCycleCore(server.Id, childIds ?? ChildIds(server), stack);
    }

    private static bool HasCycleCore(string rootId, IReadOnlyCollection<string> childIds, HashSet<string> stack)
    {
        foreach (var childId in childIds.Where(id => !id.IsNullOrWhiteSpace()))
        {
            if (childId == rootId || !stack.Add(childId))
            {
                return true;
            }

            var child = Global.Settings.Server.FirstOrDefault(s => s.Id == childId);
            if (child?.ConfigType is EConfigType.PolicyGroup or EConfigType.ProxyChain)
            {
                if (HasCycleCore(rootId, ChildIds(child), stack))
                {
                    return true;
                }
            }

            stack.Remove(childId);
        }

        return false;
    }

    public static string ChildNames(Server server)
    {
        return string.Join(" -> ", ChildServers(server).Select(s => s.Remarks.ValueOrDefault($"{s.Address}:{s.Port}")));
    }
}
