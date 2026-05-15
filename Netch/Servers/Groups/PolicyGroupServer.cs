using Netch.Enums;
using Netch.Models;

namespace Netch.Servers;

public class PolicyGroupServer : Server
{
    public override EConfigType ConfigType { get; } = EConfigType.PolicyGroup;

    public PolicyGroupServer()
    {
        Address = "127.0.0.1";
        Port = 1;
        ProtoExtra.GroupType = EConfigType.PolicyGroup.ToString();
    }

    public override string MaskedData()
    {
        return $"Group: {ProtoExtra.ChildItems}";
    }
}
