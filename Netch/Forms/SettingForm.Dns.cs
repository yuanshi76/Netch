using Netch.Controllers;
using Netch.Models;
using Netch.Services.Dns;
using Netch.Utils;
using System.Text.Json;

namespace Netch.Forms;

public partial class SettingForm
{
    private CheckBox _allowLocal = null!;
    private CheckBox _allowFallback = null!;
    private TextBox _remoteDns = null!;
    private TextBox _bootstrap = null!;
    private TextBox _localRules = null!;
    private NumericUpDown _dnsTimeout = null!;
    private CheckBox _fakeIp = null!;
    private TextBox _fakeRange = null!;
    private TextBox _fakeRules = null!;
    private NumericUpDown _fakeTtl = null!;

    private void InitializeDnsSettings()
    {
        ClientSize = new Size(ClientSize.Width, Math.Min(680, Math.Max(420, Screen.FromControl(this).WorkingArea.Height - 160)));
        TabControl.Height = ClientSize.Height - 44;
        var policy = Global.Settings.DnsPolicy;
        var page = new TabPage("DNS 与隐私") { AutoScroll = true };
        var layout = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, Padding = new Padding(9), AutoSizeMode = AutoSizeMode.GrowAndShrink };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        void Add(Control control) { control.Dock = DockStyle.Top; layout.Controls.Add(control); }
        void Label(string text) => Add(new Label { Text = text, AutoSize = true, MaximumSize = new Size(500, 0) });
        TextBox TextInput(IEnumerable<string> lines, int height)
        {
            var box = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, Height = height, Text = string.Join(Environment.NewLine, lines) };
            Add(box); return box;
        }
        _allowLocal = new CheckBox { Text = "允许本地 DNS 解析", Checked = policy.AllowLocalResolution, AutoSize = true };
        _allowFallback = new CheckBox { Text = "远程解析失败时允许本地回退", Checked = policy.AllowLocalFallback, AutoSize = true };
        Add(_allowLocal);
        Label("默认关闭：解析仅经代理发送，失败时报错。启用严格模式会保护系统 DNS；停止或退出后保护保持，可用下方按钮恢复。TUN 模式同时阻断不支持的 IPv6。");
        Add(_allowFallback);
        _allowLocal.CheckedChanged += (_, _) => { _allowFallback.Enabled = _allowLocal.Checked; _localRules.Enabled = _allowLocal.Checked; if (!_allowLocal.Checked) _allowFallback.Checked = false; };
        _allowFallback.Enabled = _allowLocal.Checked;
        Label("远程 DNS（每行一个 https:// 或 tls://，全部通过代理）");
        _remoteDns = TextInput(policy.RemoteResolvers, 60);
        Label("节点连接映射（每行 域名=IP；严格模式的域名节点必须填写，TLS 域名保留）");
        _bootstrap = TextInput(policy.BootstrapMappings.Select(p => p.Key + "=" + p.Value), 60);
        Label("允许本地解析的域名后缀（每行一个；仅在允许本地解析时生效）");
        _localRules = TextInput(policy.LocalDomainRules, 48);
        _localRules.Enabled = _allowLocal.Checked;
        Label("远程解析超时（毫秒）");
        _dnsTimeout = new NumericUpDown { Minimum = 1000, Maximum = 30000, Increment = 500, Value = Math.Clamp(policy.QueryTimeoutMs, 1000, 30000) };
        Add(_dnsTimeout);
        _fakeIp = new CheckBox { Text = "启用 Fake-IP（先验证远程解析）", Checked = policy.FakeIpEnabled, AutoSize = true };
        Add(_fakeIp);
        Label("需要 TUN 或全进程接管，并关闭本地解析。域名恢复后仍按代理/直连规则处理。选择性进程及共享模式请保持关闭。TUN 仅支持 IPv4；IPv6 保护保持。");
        Label("Fake-IP IPv4 地址池（198.18.0.0/15 内的 /15 至 /24 子网）");
        _fakeRange = TextInput([policy.FakeIpRange], 26);
        _fakeRange.Multiline = false; _fakeRange.ScrollBars = ScrollBars.None;
        Label("映射有效期上限（秒；不超过远程 DNS 剩余有效期）");
        _fakeTtl = new NumericUpDown { Minimum = 1, Maximum = 300, Value = Math.Clamp(policy.FakeIpTtlSeconds, 1, 300) };
        Add(_fakeTtl);
        Label("兼容域名（返回远程真实 IP；每行完整域名或 *.example.com，不允许本地解析）");
        _fakeRules = TextInput(policy.FakeIpBypassDomains, 65);
        Label("失效映射会拒绝连接，请让应用重新解析。地址池耗尽时可关闭 Fake-IP；请保留 data 中的分配记录，避免旧地址被重复使用。");
        void EnableFakeFields() { _fakeRange.Enabled = _fakeTtl.Enabled = _fakeRules.Enabled = _fakeIp.Checked; }
        _fakeIp.CheckedChanged += (_, _) => EnableFakeFields();
        EnableFakeFields();
        Label("应用自己的 HTTPS DNS 需要该应用的流量也经过代理；仅代理部分进程不能保护其他进程的 HTTPS DNS。");
        var restore = new Button { Text = "停止并恢复系统 DNS", AutoSize = true };
        restore.Click += async (_, _) =>
        {
            restore.Enabled = false;
            try { await _mainForm.RestoreDnsAsync(); }
            catch (Exception ex) { MessageBoxX.Show(ex.Message); }
            finally { restore.Enabled = true; }
        };
        Add(restore);
        page.Controls.Add(layout);
        TabControl.TabPages.Insert(0, page);
        TabControl.SelectedTab = page;
        // Retain legacy data for compatibility, but expose only one active DNS policy.
        TabControl.TabPages.Remove(AioDNSTabPage);
        foreach (Control control in new Control[] { OutboundDNSComboBox, UseOutboundDNSCheckBox, UseDomainNameRadioButton,
            UseResolvedIPRadioButton, OutboundDNSDeleteCurrentPictureBox, FilterDNSCheckBox, DNSHijackHostTextBox,
            DNSProxyCheckBox, HandleProcDNSCheckBox, UseCustomDNSCheckBox, TUNTAPDNSTextBox, ProxyDNSCheckBox })
        { control.Enabled = false; control.Visible = false; }
    }

    private DnsPolicyConfig ReadDnsSettings()
    {
        static List<string> Lines(TextBox input) => input.Lines.Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
        var policy = new DnsPolicyConfig
        {
            AllowLocalResolution = _allowLocal.Checked,
            AllowLocalFallback = _allowLocal.Checked && _allowFallback.Checked,
            RemoteResolvers = Lines(_remoteDns), LocalDomainRules = Lines(_localRules), QueryTimeoutMs = (int)_dnsTimeout.Value,
            FakeIpEnabled = _fakeIp.Checked, FakeIpRange = _fakeRange.Text.Trim(),
            FakeIpTtlSeconds = (int)_fakeTtl.Value, FakeIpBypassDomains = Lines(_fakeRules)
        };
        foreach (var line in Lines(_bootstrap))
        {
            var parts = line.Split('=', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2 || !policy.BootstrapMappings.TryAdd(parts[0], parts[1]))
                throw new MessageException("节点映射必须为不重复的 域名=IP。");
        }
        policy.Validate();
        if (MainController.ServerController != null && JsonSerializer.Serialize(policy) != JsonSerializer.Serialize(Global.Settings.DnsPolicy))
            throw new MessageException("请先停止代理再更改 DNS 设置；停止期间 DNS 保护仍会保持。");
        if (policy.AllowLocalResolution && DnsRuntime.Protection.Active)
            throw new MessageException("启用本地解析前，请先使用“停止并恢复系统 DNS”解除现有保护。");
        return policy;
    }
}
