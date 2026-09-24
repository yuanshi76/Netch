# Netch 1.9.12 交付记录

日期：2026-09-24，时间为北京时间。用户要求下一正式版本编号，因此使用 **1.9.12**，无 preview 后缀。正式编号不等于所有模式已经验收通过。

## 交付与替换

交付文件：`artifacts/release-1.9.12/Netch.exe`。只需备份旧 EXE、完全退出 Netch，再替换 `D:\Netch\Netch.exe`。继续使用现有 `bin`、`data`、`mode`、`i18n` 等目录。本次未覆盖现用安装，已恢复运行的是原 preview.9。

内置核心固定为 Xray 26.3.27、sing-box 1.13.21，离线校验并释放到 `bin/cores` 的版本目录，不需要另外下载核心。EXE 是 Windows x64 自包含构建；版本资源 ProductVersion 为 1.9.12、FileVersion 为 1.9.12.0。相邻 `Netch.exe.sha256` 和 `Netch.release.json` 保存本次构建校验值。

构建：`./build-replacement.ps1 -NoRestore -OfflineCores -OutputDirectory artifacts/release-1.9.12`。

## 已交付功能

- 本地 DNS 解析开关；默认严格远程 DoH/DoT，失败报错、不回落本地。节点域名需要明确的连接 IP 或域名映射。
- 可选 Fake-IP 开关、IPv4 地址池设置、兼容域名列表、连接时域名恢复、Xray/sing-box 域名规则适配。
- 有界映射、TTL、重连后旧地址拒绝和持久分配游标；Fake-IP 默认关闭，仅开放符合条件的全进程与 TUN 模式。地址池冲突仍明确拒绝，未为测试放宽生产检查。
- 全进程回环放行覆盖 IPv4、IPv6 和 IPv4 映射 IPv6，修复本机 TCP DNS 被送进远端代理的问题。通过已有 nfapi.dll 完成，继续支持只换 EXE。
- TUN 路由创建前保存拥有记录；正常停止或恢复只删除仍精确匹配的本程序路由。
- 保留正常故障日志、DNS 保护与显式恢复功能；开发测试按钮和脚本未打入产品。

## 验收结果

| 项目 | 结果及证据边界 |
| --- | --- |
| 正式源代码隔离回归 | 61 组通过，含两核心配置/运行、映射生命周期、DNS 协议与失败策略、回环规则、路由记录；不是系统逐包泄露证明 |
| 恢复脚本 | 9 项替身/静态检查通过；包括缺失外部网卡时继续其他恢复、拒绝操作另一 GUID |
| 全进程实际复验 | 14:24–14:25 通过：回环 TCP/UDP DNS、外部程序 Fake-IP HTTPS、核心退出返回 SERVFAIL、重连、旧地址拒绝，原程序自动恢复；使用与正式版相同的回环修复和 Fake-IP 数据路径 |
| TUN 实际启动与 DNS | 15:41–15:42 启动成功；UDP/TCP DNS 成功，返回 Fake-IP |
| TUN 连接时域名恢复 | tun2socks 接收 `198.18.0.2:443`，Xray 记录 `accepted tcp:example.com:443 [mixed >> proxy]`，证明恢复后的域名到达核心 |
| TUN HTTPS | **失败**：15 秒超时。DNS 在模式启动前已出现间歇超时，模式就绪后也有超时；现有证据不足以确定是远端路径还是 TUN 数据路径造成，不能宣称已修复 |
| TUN 故障/重连/旧映射 | 未执行：HTTPS 失败后进入收尾，不能沿用全进程结果当作 TUN 通过 |
| TUN 正常路由清理 | 完成，宿主 `data/tun-owned-routes.json` 为 `[]`；强制崩溃后的真实 TUN 清理未验证 |

## TUN 测试恢复故障与修正

用户允许临时断开 FastLink 后，测试监督脚本先设置三分钟独立恢复进程和约四分钟备用任务，再暂时禁用记录的 FastLink 网卡。旧 Wintun 在 15:41:59 明确记录 `Removed orphaned adapter "FastLink"`；因此按原 GUID 重新启用网卡的恢复方法失效。主恢复和备用恢复均因网卡缺失退出，没有按期完成恢复。

随后网卡重新出现并处于 Up 状态，重新运行同一恢复流程：15:49:37 恢复已记录的 DNS/规则并重启原 Netch，15:49:42 两次远程 DNS 应答成功；随后核对无本轮临时恢复任务残留。不能把网卡重现归因于自动脚本，也不能把这次事件记为自动恢复全程通过。

为防重现，`Prepare` 和 `Run` 在任何中断前拒绝禁用网卡测试路径，移除实际禁用操作。旧计划的 Watchdog 仍保留兼容恢复：外部网卡恢复失败单独保存 pending；其 DNS 快照保留，继续清理其余接口和 Netch 拥有的路由/规则、尝试重连原程序。结果显式区分外部网卡未恢复。此修正经过替身回归，没有再次中断联网实测。

## 使用边界

当前可依据实际结果使用全进程 Fake-IP；**不应把本次交付视为 TUN 已验收可用**。选择性进程模式保持 Fake-IP 关闭，使用严格远程真实 IP。普通停止和退出会保留保护，恢复普通联网使用“服务器 → 停止并恢复系统 DNS”。

尚未完成 TUN 完整复验、系统出口逐包验证、长期运行、睡眠/换网和实际恢复竞争测试。此前 11:55 断线及后续间歇 DNS 超时根因仍未确证；没有把短时成功、正式版本编号或缺少报错视为长期稳定证明。

## 本地证据

私有节点配置和完整日志保留于忽略目录，不提交到 Git：

- `.build/regression-1912.log`：正式源代码 61 组回归。
- `.build/recovery-regression-1912.log`：9 项恢复检查。
- `.build/tests-build-1912.log`、`.build/publish-1912.log`：编译与发布。
- `.build/network-acceptance/session-0defb3373c9d4a0081e1c7127c870a18/`：全进程通过与恢复。
- `.build/network-acceptance/session-2af40ca7537f4410a05f16f1b090d000/`：TUN 失败、tun2socks/Xray 证据、首次及备用恢复失败、后续恢复成功；保留失败文件，不以 `restored.json` 存在覆盖历史失败。
