# DNS regression suite

Current recorded result: **28 regression groups passed for 1.9.11-dns-preview.6** on 2026-09-23. See the [implementation summary](../../docs/DNS_IMPLEMENTATION_STATUS.zh-CN.md) and [preview.6 report](../../docs/DNS_ACCEPTANCE_PREVIEW6.zh-CN.md). This separately built developer harness is not included in the replacement Netch.exe.

Build with a Windows .NET 8 SDK:

```powershell
dotnet build tests/DnsRegression/DnsRegression.csproj -c Release -p:Platform=x64
# Run the produced DnsRegression.exe, passing this repository's absolute path.
```

The default is offline mode (`--offline`): no listening sockets, outbound connections or core processes. Config tests use synthetic port values and serialization only. All injected resolver replies and failures are in memory. It includes cleanup of an already-faulted receive task (Win32 995), repeated disposal, and detachment of the stale runtime service.

`DnsRegression.exe <repository> --allow-listeners` explicitly enables the additional loopback and core tests below. Place copies of the installation's `xray.exe` and `sing-box.exe` in `.build/baseline` for that mode. It uses synthetic credentials and reserved test domains/addresses; it never loads the user's settings or connects to their proxy. The default suite does not opt into these tests automatically.

The suite runs DNS codec/fuzz, failure/timeout/cache, local opt-in, TCP/UDP IPv4/IPv6 loopback, SOCKS remote-name, TLS rejection, config migration and native core configuration tests. The Xray runtime fixture listens only on random loopback ports and uses a synthetic local DNS broker and SOCKS endpoint. Firewall COM rule properties and recovery are checked using an in-memory collection, including both FileNotFoundException and COMException mappings, ownership and permission errors. A real Windows firewall lookup also confirms that a nonexistent rule is handled correctly; this query is read-only. No rules are installed.

The preview.6 regression `--udp-client-lifecycle` uses only temporary loopback ports. Eight clients depart before delayed replies are released, reproducing Windows ICMP/10054 notifications. Both IP families and both production/default and explicitly re-enabled reset notifications must keep the shared DNS listener healthy; other clients must work, and suspension must still return SERVFAIL. It is also included in `--allow-listeners`.

`DnsRegression.exe <repository> --render-ui` renders settings offscreen to `.build/regression/dns-settings.png`. It does not activate any buttons, start the main application, bind sockets, or start any proxy. All manual-test windows, self-check report buttons, session recording and debug statistics were removed from the product in preview.5.

`DnsRegression.exe <repository> --firewall-integration` is a separate, opt-in Windows administrator test. It calls the production rule builder with `enabled=false` through a collection adapter that **refuses to register enabled rules**. TCP, UDP and IPv6 rules are checked for initial creation, reconnect without duplicates, reapplication of address coverage, rejection of unexpected application/service restrictions, and repeated recovery. Unique `Netch.DisabledRegression.<random>` names are removed in `finally`, including duplicate copies if a regression creates them. It never enables the temporary rules, accesses live Netch rules, changes adapter DNS, or starts a proxy. Do not describe the default memory-only suite as testing registration with Windows.

The offline, loopback and disabled-firewall suites do **not** validate system adapter mutation/restoration, installed firewall enforcement, physical packet capture, real TUN/Redirector drivers, sleep/resume, or real proxy connectivity. Do not infer those results from the 28-group regression suite. System acceptance is a separate workflow below; its recorded results apply to preview.5, not a repeat of system acceptance on preview.6.

## System acceptance and recovery

These modes can change system-wide DNS/firewall state and interrupt connectivity. Schedule them deliberately with a recovery operator/process ready; do not run them as part of normal build, documentation work or the default regression suite.

| Mode | Behavior and scope |
| --- | --- |
| `--live-dns` | Probes the existing loopback DNS listener and attempts external TCP/UDP DNS-port traffic. Does not configure protection; UDP send success is marked `CAPTURE_REQUIRED`, not a pass. Its exit code alone does not establish acceptance: inspect the saved outcomes. |
| `--system-acceptance` | Uses the real selected node and installed component copies; exercises startup failure, connection, test-owned core termination, stop, restore and reconnect. Temporarily changes adapter DNS and firewall rules. |
| `--capture-acceptance` | Runs a real connection and test-owned core termination with Windows Packet Monitor, DNS-port probes and positive controls; writes phase counters for interpretation. |
| `--restore-acceptance` | Restores the isolated harness's DNS journal and removes its own application allow rules. It does not terminate a still-running test/core or stop a leftover Packet Monitor session. |

The system/capture harness is specific to the 2026-09-23 test installation: it reads `D:\Netch\data\settings.json` and `D:\Netch\mode\Custom\桌面常用.json`, uses copies of the installation's native components, and restricts the process interception list to `NetchAcceptanceProbe`. Review these paths before adapting it to another machine. Real node settings and credentials remain local and must not be committed.

System execution requires Windows administrator rights and a separately staged test executable under `.build/acceptance-host`, with required component copies in its `bin` directory. The harness rejects running Netch processes, occupied port 53, existing DNS protection journals or existing guard rules. It writes a baseline, normally restores in `finally`, and checks that adapter values match afterwards. Forced termination cannot execute `finally`: arrange an independent timeout/recovery process, retain the harness journal, and verify cleanup separately.

The recorded preview.5 run used an independent local administrator supervisor with a 180-second timeout, followed by recovery and verification. That machine-specific supervisor resides in ignored `.build` material and is not a portable runner supplied by this repository. For capture recovery, also verify Packet Monitor has stopped and remove only filters created by the test; do not interfere with another capture session.

The [preview.5 system report](../../docs/DNS_ACCEPTANCE_PREVIEW5.zh-CN.md) records the FastLink/WLAN coexistence conditions, the initial failed harness run and recovery, later successful tests, and the invalid ETL-to-PCAP export. Counter-based evidence with positive controls is distinct from raw packet evidence. Standalone Netch, TUN, arbitrary application DoH, sleep/resume and main-process crash acceptance remain outside those results. Test logs, copied components and recovery journals stay in ignored `.build` directories.
