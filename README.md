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

## 1.9.12：严格远程 DNS 与可选 Fake-IP

当前交付版本为 **1.9.12**，无 preview 后缀；生成到 `artifacts/release-1.9.12/Netch.exe`，未覆盖现用安装。设置中的“允许本地 DNS 解析”默认关闭；DNS 通过所选代理访问远程 DoH/DoT，远程失败返回错误，不自动回退系统或路由器 DNS。域名节点首次连接需要在“DNS 与隐私”中填写“域名=IP”映射，或使用明确的连接 IP。

普通停止和退出会保留 DNS 保护；恢复普通联网请使用“服务器 → 停止并恢复系统 DNS”。交付仅需替换 `Netch.exe`，继续使用原有 `bin`、`data`、`mode` 和 `i18n`。新版内置 Xray 26.3.27 和 sing-box 1.13.21，首次启动代理时离线部署到 bin/cores 的版本目录，保留原核心。验证型 Fake-IP 已实现并默认关闭，仅对 TUN 或符合条件的全进程模式开放。回环修复后的全进程实际复验已通过，覆盖 TCP/UDP DNS、透明 HTTPS、核心故障、重连和旧映射拒绝。TUN 已实际运行：DNS、域名恢复和正常路由清理成功，但 HTTPS 超时，完整验收未通过。当前交付不能视为 TUN 已验证可用；详情见正式版本记录。

- [1.9.12 交付、实际验收结果与已知限制](docs/RELEASE_1.9.12.zh-CN.md)
- [任务总结、实施状态与替换说明](docs/DNS_IMPLEMENTATION_STATUS.zh-CN.md)
- [设计方案与后续范围](docs/DNS_SECURITY_DESIGN.zh-CN.md)
- [preview.5 系统级验收](docs/DNS_ACCEPTANCE_PREVIEW5.zh-CN.md) / [preview.6 首次启动修复](docs/DNS_ACCEPTANCE_PREVIEW6.zh-CN.md)
- [preview.7 启动连接重置修复](docs/DNS_ACCEPTANCE_PREVIEW7.zh-CN.md)
- [preview.8 核心升级、已知问题与验收](docs/CORE_UPGRADE_PREVIEW8.zh-CN.md)
- [preview.9 Fake-IP、断线诊断与实际测试失败记录](docs/FAKEIP_PREVIEW9.zh-CN.md)
- [preview.10 回环修复、实际恢复结果与待验收项](docs/DNS_ACCEPTANCE_PREVIEW10.zh-CN.md)
- [独立定时恢复、备用任务与当前限制](tests/NetworkRecovery/README.zh-CN.md)
- [开发回归测试说明](tests/DnsRegression/README.md)

在 Windows 的 .NET 8 SDK 环境运行 `./build-replacement.ps1 -OutputDirectory artifacts/release-1.9.12`，生成正式版 EXE 及 SHA-256 校验文件。该脚本只生成交付文件，不覆盖现用安装。保留 `artifacts/replacement` 中的 preview.9 产物供已建立的实际验收恢复基线核验。

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
