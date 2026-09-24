using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using Netch.Models;

namespace Netch.Services;

/// <summary>Applies the loopback opt-out to the existing NF API, including dual-stack sockets.</summary>
public static class NfLoopbackPolicy
{
    // NF_RULE is packed to one byte in Redirector/include/nfdriver.h. Windows
    // unsigned long is 32 bits on x64 too: family at 13, remote at 47, mask at 63.
    public static byte[][] BuildRules()
    {
        byte[] Rule(ushort family, string address, int prefix)
        {
            var rule = new byte[83];
            BinaryPrimitives.WriteUInt16LittleEndian(rule.AsSpan(13), family);
            IPAddress.Parse(address).GetAddressBytes().CopyTo(rule, 47);
            for (var bit = 0; bit < prefix; bit++) rule[63 + bit / 8] |= (byte)(128 >> (bit % 8));
            return rule; // NF_ALLOW = 0; all protocols/processes/directions.
        }
        return [Rule(2, "127.0.0.0", 8), Rule(23, "::1", 128), Rule(23, "::ffff:127.0.0.0", 104)];
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int AddRule(IntPtr rule, int toHead);

    public static void Apply()
    {
        // Load the same installed nfapi.dll used by Redirector.bin. No driver or
        // original bin file is replaced; this remains a single-EXE update.
        var library = NativeLibrary.Load(Path.Combine(Global.NetchDir, "bin", "nfapi.dll"));
        try
        {
            var add = Marshal.GetDelegateForFunctionPointer<AddRule>(NativeLibrary.GetExport(library, "nf_addRule"));
            var buffer = Marshal.AllocHGlobal(83);
            try
            {
                foreach (var rule in BuildRules())
                {
                    Marshal.Copy(rule, 0, buffer, rule.Length);
                    var status = add(buffer, 1);
                    if (status != 0) throw new MessageException($"无法保护本机回环连接，Redirector 规则失败（{status}）。");
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            Log.Information("Redirector loopback bypass installed for IPv4, IPv6 and mapped IPv4");
        }
        finally { NativeLibrary.Free(library); }
    }
}
