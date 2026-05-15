using Netch.Enums;
using Netch.Interfaces;
using Netch.Models;
using Netch.Services;

namespace Netch.Servers;

public class ProxyChainUtil : GroupServerUtilBase<ProxyChainServer>
{
    public override ushort Priority => 1000;
    public override string TypeName => EConfigType.ProxyChain.ToString();
    public override string FullName => "Proxy Chain";
    public override string ShortName => "CHAIN";
    public override string[] UriScheme => [];
    public override Type ServerType => typeof(ProxyChainServer);
    protected override EConfigType ConfigType => EConfigType.ProxyChain;
}

public class PolicyGroupUtil : GroupServerUtilBase<PolicyGroupServer>
{
    public override ushort Priority => 1001;
    public override string TypeName => EConfigType.PolicyGroup.ToString();
    public override string FullName => "Policy Group";
    public override string ShortName => "GROUP";
    public override string[] UriScheme => [];
    public override Type ServerType => typeof(PolicyGroupServer);
    protected override EConfigType ConfigType => EConfigType.PolicyGroup;
}

public abstract class GroupServerUtilBase<TServer> : ServerUtilBase, IServerUtil where TServer : Server, new()
{
    protected abstract EConfigType ConfigType { get; }

    public abstract ushort Priority { get; }
    public abstract string TypeName { get; }
    public abstract string FullName { get; }
    public abstract string ShortName { get; }
    public abstract string[] UriScheme { get; }
    public abstract Type ServerType { get; }

    public void Edit(Server s)
    {
        new GroupServerForm(s, ConfigType).ShowDialog();
    }

    public void Create()
    {
        new GroupServerForm(new TServer(), ConfigType).ShowDialog();
    }

    public string GetShareLink(Server s)
    {
        return string.Empty;
    }

    public IServerController GetController()
    {
        return new V2rayController();
    }

    public IEnumerable<Server> ParseUri(string text)
    {
        return [];
    }

    public bool CheckServer(Server s)
    {
        return s.ConfigType == ConfigType;
    }
}
