using Netch.Enums;
using Netch.Models;

namespace Netch.Servers;

public class ProxyChainServer : Server
{
    public override EConfigType ConfigType { get; } = EConfigType.ProxyChain;

    public ProxyChainServer()
    {
        Address = "127.0.0.1";
        Port = 1;
        ProtoExtra.GroupType = EConfigType.ProxyChain.ToString();
    }

    public override string MaskedData()
    {
        return $"Chain: {ProtoExtra.ChildItems}";
    }
}
