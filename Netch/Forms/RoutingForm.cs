using Netch.Models;
using Netch.Utils;
using System.ComponentModel;

namespace Netch.Forms;

[DesignerCategory(@"Code")]
public class RoutingForm : Form
{
    private readonly DataGridView _grid = new();
    private readonly Button _saveButton = new();
    private readonly Button _cancelButton = new();
    private readonly Label _hintLabel = new();
    private readonly Dictionary<string, string> _outboundMap = new();

    public RoutingForm()
    {
        InitializeComponent();
        LoadData();
    }

    private void InitializeComponent()
    {
        Text = "路由规则";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1040, 560);
        ClientSize = new Size(1080, 560);

        _grid.Dock = DockStyle.Top;
        _grid.Height = 485;
        _grid.AllowUserToAddRows = true;
        _grid.AllowUserToDeleteRows = true;
        _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        _grid.RowHeadersWidth = 28;

        _grid.Columns.Add(new DataGridViewCheckBoxColumn
        {
            Name = "Enabled",
            HeaderText = "启用",
            FillWeight = 45
        });
        _grid.Columns.Add("Remarks", "备注");
        _grid.Columns.Add(new DataGridViewComboBoxColumn
        {
            Name = "Outbound",
            HeaderText = "出口",
            FlatStyle = FlatStyle.Flat,
            FillWeight = 130
        });
        _grid.Columns.Add("Domain", "域名，逗号分隔");
        _grid.Columns.Add("Ip", "IP，逗号分隔");
        _grid.Columns.Add("Port", "端口");
        _grid.Columns.Add("Network", "网络 tcp/udp");
        _grid.Columns.Add("Protocol", "协议，逗号分隔");
        _grid.Columns.Add("InboundTag", "入站标签，逗号分隔");
        _grid.Columns.Add("Process", "进程，逗号分隔");

        _hintLabel.Text = "规则按从上到下的顺序匹配；域名支持 full:google.com、domain:google.com、geosite:google；IP 支持 geoip:cn。使用 geosite/geoip 前请先更新 GeoSite/GeoIP 数据。";
        _hintLabel.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
        _hintLabel.Location = new Point(12, 497);
        _hintLabel.Size = new Size(880, 40);
        _hintLabel.AutoEllipsis = true;

        _saveButton.Text = "保存";
        _saveButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        _saveButton.Location = new Point(912, 516);
        _saveButton.Size = new Size(75, 28);
        _saveButton.Click += (_, _) => Save();

        _cancelButton.Text = "取消";
        _cancelButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        _cancelButton.Location = new Point(993, 516);
        _cancelButton.Size = new Size(75, 28);
        _cancelButton.Click += (_, _) => Close();

        Controls.Add(_grid);
        Controls.Add(_hintLabel);
        Controls.Add(_saveButton);
        Controls.Add(_cancelButton);
    }

    private void LoadData()
    {
        var outboundColumn = (DataGridViewComboBoxColumn)_grid.Columns["Outbound"];
        AddOutbound(outboundColumn, RoutingOutbound.Proxy, "当前主代理 (proxy)");
        AddOutbound(outboundColumn, RoutingOutbound.Direct, "直连 (direct)");
        AddOutbound(outboundColumn, RoutingOutbound.Block, "阻断 (block)");

        foreach (var server in Global.Settings.Server)
        {
            AddOutbound(outboundColumn, server.Id, $"{server.Remarks} [{server.ConfigType}]");
        }

        var profile = GetActiveProfile();
        foreach (var rule in profile.Rules)
        {
            var outboundText = _outboundMap.FirstOrDefault(kv => kv.Value == rule.OutboundServerId).Key ?? "当前主代理 (proxy)";
            _grid.Rows.Add(
                rule.Enabled,
                rule.Remarks,
                outboundText,
                string.Join(",", rule.Domain),
                string.Join(",", rule.Ip),
                rule.Port,
                rule.Network,
                string.Join(",", rule.Protocol),
                string.Join(",", rule.InboundTag),
                string.Join(",", rule.Process));
        }
    }

    private void AddOutbound(DataGridViewComboBoxColumn column, string id, string text)
    {
        var uniqueText = text;
        var suffix = 2;
        while (_outboundMap.ContainsKey(uniqueText))
        {
            uniqueText = $"{text} ({suffix++})";
        }

        _outboundMap[uniqueText] = id;
        column.Items.Add(uniqueText);
    }

    private RoutingProfile GetActiveProfile()
    {
        var profile = Global.Settings.RoutingProfiles.FirstOrDefault(p => p.Id == Global.Settings.ActiveRoutingProfileId);
        if (profile != null)
        {
            return profile;
        }

        profile = new RoutingProfile();
        Global.Settings.RoutingProfiles.Add(profile);
        Global.Settings.ActiveRoutingProfileId = profile.Id;
        return profile;
    }

    private void Save()
    {
        _grid.EndEdit();
        var rules = new List<RoutingRule>();
        foreach (DataGridViewRow row in _grid.Rows)
        {
            if (row.IsNewRow)
            {
                continue;
            }

            var outboundText = CellText(row, "Outbound");
            if (!_outboundMap.TryGetValue(outboundText, out var outboundId))
            {
                outboundId = RoutingOutbound.Proxy;
            }

            var rule = new RoutingRule
            {
                Enabled = row.Cells["Enabled"].Value is bool enabled ? enabled : true,
                Remarks = CellText(row, "Remarks"),
                OutboundServerId = outboundId,
                Domain = SplitList(CellText(row, "Domain")),
                Ip = SplitList(CellText(row, "Ip")),
                Port = CellText(row, "Port"),
                Network = CellText(row, "Network"),
                Protocol = SplitList(CellText(row, "Protocol")),
                InboundTag = SplitList(CellText(row, "InboundTag")),
                Process = SplitList(CellText(row, "Process"))
            };

            if (rule.Domain.Count == 0 &&
                rule.Ip.Count == 0 &&
                rule.Port.IsNullOrWhiteSpace() &&
                rule.Network.IsNullOrWhiteSpace() &&
                rule.Protocol.Count == 0 &&
                rule.InboundTag.Count == 0 &&
                rule.Process.Count == 0)
            {
                continue;
            }

            rules.Add(rule);
        }

        GetActiveProfile().Rules = rules;
        MessageBoxX.Show(i18N.Translate("Saved"));
        Close();
    }

    private static string CellText(DataGridViewRow row, string columnName)
    {
        return row.Cells[columnName].Value?.ToString()?.Trim() ?? string.Empty;
    }

    private static List<string> SplitList(string value)
    {
        return value
            .Split([',', '，', ';', '；', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
    }
}
