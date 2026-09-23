# 个人自用，随缘更新
<p align="center"><img src="https://github.com/NetchX/Netch/blob/main/Netch/Resources/Netch.png?raw=true" width="128" /></p>

<div align="center">

# Netch
A simple proxy client

[![](https://img.shields.io/badge/自用版本Telegram-讨论组-green?style=flat-square)](https://t.me/+Se4RSc06w8QK1HiS)
[![](https://img.shields.io/badge/源Telegram-讨论组-green?style=flat-square)](https://t.me/netch_group)
[![](https://img.shields.io/badge/自用版本Telegram-公告板-blue?style=flat-square)](https://t.me/ClashR_for_Windows_Channel)
[![](https://img.shields.io/badge/源telegram-公告版-blue?style=flat-square)](https://t.me/netch_channel)
[![](https://img.shields.io/github/downloads/BoyceLig/Netch/total.svg?style=flat-square)](https://github.com/BoyceLig/Netch/releases/download/1.9.9/Netch.v1.9.9.7z)
[![](https://img.shields.io/github/v/release/BoyceLig/Netch?style=flat-square)](https://github.com/BoyceLig/Netch/releases)
</div>

## DNS 严格远程解析预览版

当前交付版本为 **1.9.11-dns-preview.6**。设置中的“允许本地 DNS 解析”默认关闭；DNS 通过所选代理访问远程 DoH/DoT，远程失败返回错误，不自动回退系统或路由器 DNS。域名节点首次连接需要在“DNS 与隐私”中填写“域名=IP”映射，或使用明确的连接 IP。

普通停止和退出会保留 DNS 保护；恢复普通联网请使用“服务器 → 停止并恢复系统 DNS”。交付仅需替换 `Netch.exe`，继续使用原有 `bin`、`data`、`mode` 和 `i18n`。验证型 Fake-IP 尚未实现，当前验收也不代表全设备、全模式零泄露。

- [任务总结、实施状态与替换说明](docs/DNS_IMPLEMENTATION_STATUS.zh-CN.md)
- [设计方案与后续范围](docs/DNS_SECURITY_DESIGN.zh-CN.md)
- [preview.5 系统级验收](docs/DNS_ACCEPTANCE_PREVIEW5.zh-CN.md) / [preview.6 首次启动修复](docs/DNS_ACCEPTANCE_PREVIEW6.zh-CN.md)
- [开发回归测试说明](tests/DnsRegression/README.md)

在 Windows 的 .NET 8 SDK 环境运行 `./build-replacement.ps1`，生成 `artifacts/replacement/Netch.exe` 及 SHA-256 校验文件。该脚本只生成交付文件，不覆盖现用安装。

## Features
Some features may not be implemented in version 1

### Modes
- `ProcessMode` - Use Netfilter driver to intercept process traffic
- `ShareMode` - Share your network based on WinPcap / Npcap
- `TunMode` - Use WinTUN driver to create virtual adapter
- `WebMode` - Web proxy mode

### Protocols
- [`Socks5`](https://www.wikiwand.com/en/SOCKS)
- [`Shadowsocks`](https://shadowsocks.org)
- [`ShadowsocksR`](https://github.com/shadowsocksrr/shadowsocksr-libev)
- [`WireGuard`](https://www.wireguard.com)
- [`Trojan`](https://trojan-gfw.github.io/trojan)
- [`VMess`](https://www.v2fly.org)
- [`VLESS`](https://xtls.github.io)

### Others
- UDP NAT FullCone (Limited by your server)
- .NET 8.0 x64

## Sponsor
<a href="https://www.jetbrains.com/?from=Netch"><img src="jetbrains.svg" alt="JetBrains" width="200"/></a>
<a href="https://visualstudio.microsoft.com/"><img src="visual-studio-26-icon.webp" alt="Visual Studio" width="100"/></a>

## License
Netch is licensed under the [GPLv3](https://raw.githubusercontent.com/netchx/netch/main/LICENSE) license



