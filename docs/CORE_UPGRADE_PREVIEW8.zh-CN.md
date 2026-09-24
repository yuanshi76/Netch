# preview.8 核心升级与验收

核查日期：2026-09-24。交付：`1.9.11-dns-preview.8`，Windows x64，自包含单 EXE。

## 版本选择

| 核心 | 本机原版本 | 本次固定版本 | 选择依据 |
| --- | --- | --- | --- |
| Xray | 26.2.6 | **26.3.27**，commit `d2758a0`，Go 1.26.1 | 核查时官方 `/releases/latest` 指向此版，`prerelease=false`；26.4.13 至 26.9.9 的所查发布均标记为预发布。选择正式发布线上的保守升级。 |
| sing-box | 1.12.21 | **1.13.21**，commit `628cb31`，Go 1.26.7 | 2026-08-30 发布，非预发布；暂缓使用有 TUIC/BBR 性能问题报告的 1.14.1。 |

来源：[Xray 26.3.27](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)、[Xray 发布 API](https://api.github.com/repos/XTLS/Xray-core/releases/latest)、[sing-box 1.13.21](https://github.com/SagerNet/sing-box/releases/tag/v1.13.21)。发布标记不等于没有 bug。选择结合了现用版本、Netch 实际协议范围和隔离实测；Xray 三月版较保守，并非按发布日期最新。

## 已知问题与边界

- [Xray #6794](https://github.com/XTLS/Xray-core/issues/6794)：仍为 Open。报告涉及 Vision 切换 direct copy 后，外层 TLS 收尾记录干扰内层 TLS，出现 `bad record MAC`。26.9.9 和 26.7.28 均能复现。因此不能说是 26.9.9 独有，也不能声称 26.3.27 已修复或不受影响。本次未复现该报告的完整矩阵。
- [sing-box #4520](https://github.com/SagerNet/sing-box/issues/4520)：仍为 Open。报告针对 sing-box 客户端连接 Xray 26.9.8+ REALITY **服务端**时的握手兼容性，不能推导为所有 Xray 客户端都有故障。Netch 的 VLESS 使用 Xray，TUIC/AnyTLS 使用 sing-box。
- [sing-box #4538](https://github.com/SagerNet/sing-box/issues/4538)：仍为 Open。1.14.1 的 Linux CLI 复现显示 TUIC/BBR 下载后再次上传吞吐下降。本项目也使用 TUIC/BBR，因此暂缓切换至 1.14；该报告没有证明 Windows 全场景相同，也没有证明 1.13.21 不受影响。本次连接测试不是性能 A/B 测试。
- [sing-box #4468](https://github.com/SagerNet/sing-box/issues/4468)：1.13.19–1.13.21 有 DNS UDP detour 经 gRPC 超时的报告。当前 Netch 自身 DNS 服务通过专用 SOCKS 处理 DoH/DoT，sing-box 仅用于 TUIC/AnyTLS 单节点，不采用该 UDP DNS/gRPC 路径。

## 实现

1. `Storage/cores.lock.json` 固定官方下载地址、压缩包和部署文件的 SHA-256，以及源代码地址。`prepare-cores.ps1` 验证完整性，下载/校验失败即停止。两个旧核心构建入口不再自动挑选 `latest`。
2. 官方压缩包内置于 EXE。首次启动代理时，在修改系统 DNS/防火墙之前离线校验并释放：`bin/cores/xray/26.3.27/xray.exe`、`bin/cores/sing-box/1.13.21/sing-box.exe`、各自 `LICENSE` 和 sing-box 的 `libcronet.dll`。
3. 控制器使用明确的版本路径；原有 `bin/xray.exe`、`bin/sing-box.exe` 保留用于旧版回退。直接查询旧路径仍显示旧版本是正常现象。`logging/application.log` 的 `Verified bundled core` 记录实际版本和路径。
4. 每次启动检查文件：正确文件不重写，损坏/缺失文件从内置资源修复，临时文件验证后原子替换。无法写入、文件占用或校验失败时报错，不回退旧核心；受管理目录内的符号链接/目录联接拒绝写入。
5. 工作目录保持 `bin`；Xray 的 `XRAY_LOCATION_ASSET` 指向既有 `bin`，保留现用 `geoip.dat`、`geosite.dat`。应用入站允许规则按路径补充，旧路径规则不再导致跳过新核心。
6. 新 sing-box 实际拒绝原先的 `inbound.sniff`。迁移到 `route.rules` 的 `action: sniff`，仅匹配 mixed 入站；远程 DNS 专用路由始终优先，关闭嗅探时不生成该规则。[官方迁移说明](https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions)

用户仍只需替换 EXE；无需另外下载核心。这轮没有增加 Fake-IP，也没有改变严格远程 DNS 的失败策略。

## 验证

**40 组开发回归通过**，使用内置并实际解压的核心：

- 首次部署、保留旧文件、重复部署、修复丢失 DLL/损坏 EXE、锁定损坏文件时明确失败且清理临时文件；核对控制器路径、工作目录和解压后核心版本。
- TUIC/BBR、AnyTLS 各自的本机客户端/服务端 TLS：测试证书与凭据，通过 DNS 专用 SOCKS 和启用嗅探的 mixed 入站分别传输并校验 32 KiB 数据。均为随机 loopback 端口，没有使用真实节点或外部 DNS。
- Xray 单节点/代理链/策略组，以及 sing-box TUIC/AnyTLS 嗅探开关组合的原生配置校验。
- Xray 运行时 DNS 专用路由优先于 DIRECT，DIRECT 使用受控 DNS，失败拒绝连接；保留报文、缓存、双栈监听、证书拒绝、启动重试等既有回归。
- 另外，Xray 26.3.27 对现用 `D:/Netch/data/last.json` 执行只解析配置的 `run -test`，退出码为 0。没有启动该配置、占用其端口或输出节点凭据。

构建成功，仍有仓库既有静态分析警告。本轮没有停止、覆盖或重启现用程序，没有修改网卡 DNS、防火墙或 FastLink；现用 Netch/Xray 的进程 ID 和开始时间在测试前后保持一致。

这些结果不等于真实节点长期运行、Vision 问题修复、性能测试或新版系统 DNS 出口验收。实际安装的新版本首次连接需在用户替换后完成。

本地证据（Git 忽略）：`.build/tests-preview8.log`、`.build/tests-build-preview8.log`、`.build/core-upgrade/embedded-versions.log`、`.build/core-upgrade/anytls-loopback/`、`.build/core-upgrade/tuic-loopback/`、`.build/core-upgrade/installed-config-check.log`、`.build/publish-preview8.log`。

## 交付与回退

文件：`artifacts/replacement/Netch.exe`；大小：238832768 字节（约 227.8 MiB，包含两个核心压缩包）。SHA-256：

```text
2988ce0cce7f288c28643d6d608156eef7191c7fe976ebec49ce0b1f681286bb
```

完全退出旧程序、备份旧 EXE，仅把新 EXE 放入原 `D:/Netch` 目录，保留其他目录。新版显示 `dns-preview.8`，首次启动代理增加上述版本目录。普通停止/退出保留 DNS 保护；需要恢复普通联网或回退旧版本时，先使用“服务器 → 停止并恢复系统 DNS”，再退出并换回备份 EXE。不要手动删除尚未恢复的 DNS 状态文件。

构建：`./build-replacement.ps1`。已有完整缓存时可加 `-NoRestore -OfflineCores`；指定 SOCKS 下载可用 `-SocksProxy 127.0.0.1:7897`。构建只输出产物，不部署到现用目录。
