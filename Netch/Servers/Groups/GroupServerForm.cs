using Netch.Enums;
using Netch.Forms;
using Netch.Models;
using Netch.Utils;
using System.ComponentModel;

namespace Netch.Servers;

[DesignerCategory(@"Code")]
public class GroupServerForm : Form
{
    private readonly Server _server;
    private readonly EConfigType _configType;
    private readonly TextBox _remarkTextBox = new();
    private readonly ListBox _availableListBox = new();
    private readonly ListBox _selectedListBox = new();
    private readonly Button _addButton = new();
    private readonly Button _removeButton = new();
    private readonly Button _upButton = new();
    private readonly Button _downButton = new();
    private readonly Button _saveButton = new();

    private readonly BindingList<Server> _selectedServers = new();

    public GroupServerForm(Server server, EConfigType configType)
    {
        _server = server;
        _configType = configType;
        InitializeComponent();
        LoadData();
    }

    private void InitializeComponent()
    {
        Text = _configType == EConfigType.ProxyChain ? "链式代理" : "策略组";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(700, 420);

        var remarkLabel = new Label
        {
            Text = "备注",
            Location = new Point(12, 17),
            AutoSize = true
        };
        _remarkTextBox.Location = new Point(82, 12);
        _remarkTextBox.Size = new Size(590, 23);

        var availableLabel = new Label
        {
            Text = "可选节点",
            Location = new Point(12, 50),
            AutoSize = true
        };
        _availableListBox.Location = new Point(12, 75);
        _availableListBox.Size = new Size(285, 285);
        _availableListBox.DisplayMember = nameof(Server.Remarks);

        var selectedLabel = new Label
        {
            Text = _configType == EConfigType.ProxyChain ? "链路顺序（第一跳在上，最终出口在下）" : "策略组成员",
            Location = new Point(403, 50),
            AutoSize = true
        };
        _selectedListBox.Location = new Point(403, 75);
        _selectedListBox.Size = new Size(285, 285);
        _selectedListBox.DisplayMember = nameof(Server.Remarks);

        _addButton.Text = ">";
        _addButton.Location = new Point(317, 125);
        _addButton.Size = new Size(66, 28);
        _addButton.Click += (_, _) => AddSelected();

        _removeButton.Text = "<";
        _removeButton.Location = new Point(317, 165);
        _removeButton.Size = new Size(66, 28);
        _removeButton.Click += (_, _) => RemoveSelected();

        _upButton.Text = "上移";
        _upButton.Location = new Point(317, 220);
        _upButton.Size = new Size(66, 28);
        _upButton.Click += (_, _) => MoveSelected(-1);

        _downButton.Text = "下移";
        _downButton.Location = new Point(317, 260);
        _downButton.Size = new Size(66, 28);
        _downButton.Click += (_, _) => MoveSelected(1);

        _saveButton.Text = "保存";
        _saveButton.Location = new Point(597, 380);
        _saveButton.Size = new Size(75, 28);
        _saveButton.Click += (_, _) => Save();

        Controls.AddRange([
            remarkLabel,
            _remarkTextBox,
            availableLabel,
            _availableListBox,
            selectedLabel,
            _selectedListBox,
            _addButton,
            _removeButton,
            _upButton,
            _downButton,
            _saveButton
        ]);
    }

    private void LoadData()
    {
        _remarkTextBox.Text = _server.Remarks;
        var selectedIds = GroupServerHelper.ChildIds(_server);
        var available = Global.Settings.Server
            .Where(s => s.Id != _server.Id && s.ConfigType is not EConfigType.PolicyGroup and not EConfigType.ProxyChain)
            .ToList();

        _availableListBox.Items.AddRange(available.Cast<object>().ToArray());

        foreach (var childId in selectedIds)
        {
            var server = Global.Settings.Server.FirstOrDefault(s => s.Id == childId);
            if (server != null)
            {
                _selectedServers.Add(server);
            }
        }

        _selectedListBox.DataSource = _selectedServers;
    }

    private void AddSelected()
    {
        if (_availableListBox.SelectedItem is not Server server || _selectedServers.Any(s => s.Id == server.Id))
        {
            return;
        }

        _selectedServers.Add(server);
    }

    private void RemoveSelected()
    {
        if (_selectedListBox.SelectedItem is not Server server)
        {
            return;
        }

        _selectedServers.Remove(server);
    }

    private void MoveSelected(int delta)
    {
        if (_selectedListBox.SelectedItem is not Server server)
        {
            return;
        }

        var oldIndex = _selectedServers.IndexOf(server);
        var newIndex = oldIndex + delta;
        if (newIndex < 0 || newIndex >= _selectedServers.Count)
        {
            return;
        }

        _selectedServers.RemoveAt(oldIndex);
        _selectedServers.Insert(newIndex, server);
        _selectedListBox.SelectedIndex = newIndex;
    }

    private void Save()
    {
        _server.Remarks = _remarkTextBox.Text.Trim();
        if (_server.Remarks.IsNullOrWhiteSpace())
        {
            MessageBoxX.Show(i18N.Translate("Please fill Remark"));
            return;
        }

        var minCount = _configType == EConfigType.ProxyChain ? 2 : 1;
        if (_selectedServers.Count < minCount)
        {
            MessageBoxX.Show(_configType == EConfigType.ProxyChain
                ? "链式代理至少需要两个节点。"
                : "策略组至少需要一个节点。");
            return;
        }

        var childIds = _selectedServers.Select(s => s.Id).ToList();
        if (_configType == EConfigType.ProxyChain && GroupServerHelper.IsSecondaryOnlyProxy(_selectedServers.First()))
        {
            MessageBoxX.Show(GroupServerHelper.PrimaryProxyValidationMessage(_selectedServers.First()));
            return;
        }

        if (_configType == EConfigType.ProxyChain && _selectedServers.Last().ConfigType == EConfigType.HTTP)
        {
            var result = MessageBoxX.Show(
                "检测到链式代理的最终出口是 HTTP。Xray/v2rayN 中 HTTP 作为链式落地出口兼容性较差，可能无法正常访问；建议改用 SOCKS 作为二级/落地出口。仍要保存吗？",
                LogLevel.WARNING,
                "兼容性提示",
                confirm: true,
                owner: this);
            if (result != DialogResult.OK)
            {
                return;
            }
        }

        if (GroupServerHelper.HasCycle(_server, childIds))
        {
            MessageBoxX.Show("组配置不能引用自身，也不能形成循环。");
            return;
        }

        _server.ProtoExtra.GroupType = _configType.ToString();
        _server.ProtoExtra.ChildItems = string.Join(",", childIds);

        if (!Global.Settings.Server.Contains(_server))
        {
            Global.Settings.Server.Add(_server);
        }

        MessageBoxX.Show(i18N.Translate("Saved"));
        Close();
    }
}
