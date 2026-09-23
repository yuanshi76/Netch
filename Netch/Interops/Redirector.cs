using System.Runtime.InteropServices;

namespace Netch.Interops;

public static class Redirector
{
    public enum NameList
    {
        AIO_FILTERLOOPBACK,
        AIO_FILTERINTRANET, // LAN
        AIO_FILTERPARENT,
        AIO_FILTERICMP,
        AIO_FILTERTCP,
        AIO_FILTERUDP,
        AIO_FILTERDNS,

        AIO_ICMPING,

        AIO_DNSONLY,
        AIO_DNSPROX,
        AIO_DNSHOST,
        AIO_DNSPORT,

        AIO_TGTHOST,
        AIO_TGTPORT,
        AIO_TGTUSER,
        AIO_TGTPASS,

        AIO_CLRNAME,
        AIO_ADDNAME,
        AIO_BYPNAME
    }

    public static bool Dial(NameList name, bool value)
    {
        Log.Verbose($"[Redirector] Dial {name}: {value}");
        return aio_dial(name, value.ToString().ToLower());
    }

    public static bool Dial(NameList name, string value)
    {
        Log.Verbose($"[Redirector] Dial {name}: {value}");
        return aio_dial(name, value);
    }

    private static readonly SemaphoreSlim LifecycleGate = new(1);
    private static bool _cleanupRequired;

    public static async Task<bool> InitAsync()
    {
        await LifecycleGate.WaitAsync();
        try
        {
            if (_cleanupRequired) throw new InvalidOperationException("Redirector is already initialized.");
            var success = await Task.Run(aio_init);
            // aio_init acquires Winsock before initializing its handlers/driver. Even
            // a reported initialization failure can therefore need paired cleanup.
            // DLL load/entry-point failures never acquire native resources.
            _cleanupRequired = true;
            return success;
        }
        finally { LifecycleGate.Release(); }
    }

    public static async Task FreeAsync()
    {
        await LifecycleGate.WaitAsync();
        try
        {
            // A controller may exist before remote DNS startup succeeds. Calling
            // aio_free without aio_init steals .NET's Winsock reference, cancels
            // every pending socket (995), and breaks subsequent sockets (10093).
            if (!_cleanupRequired) return;
            await Task.Run(aio_free);
            _cleanupRequired = false;
        }
        finally { LifecycleGate.Release(); }
    }

    private const string Redirector_bin = "Redirector.bin";

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool aio_register([MarshalAs(UnmanagedType.LPWStr)] string value);

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool aio_unregister([MarshalAs(UnmanagedType.LPWStr)] string value);

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool aio_dial(NameList name, [MarshalAs(UnmanagedType.LPWStr)] string value);

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool aio_init();

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern void aio_free();

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern ulong aio_getUP();

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern ulong aio_getDL();
}
