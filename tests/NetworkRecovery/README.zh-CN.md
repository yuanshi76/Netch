# 断线验收的独立定时恢复

开发验收使用的 Windows PowerShell 脚本，不打包进产品，不增加调试按钮。恢复进程和备用计划任务均在本机运行，不依赖 Codex 或互联网。

## 当前状态：全进程通过，TUN 实测未通过

最新结果见 [1.9.12 记录](../../docs/RELEASE_1.9.12.zh-CN.md)。15:41 的 TUN 窗口通过 DNS 和域名恢复，但 HTTPS 超时。旧 Wintun 明确记录删除已禁用的 FastLink 网卡，主/备用恢复因网卡缺失失败；网卡重新出现后重跑恢复成功。这不是自动恢复全程成功。`-TemporarilyDisableFastLink` 已废止，在快照/测试前直接拒绝；旧计划仍可由 Watchdog 恢复，外部网卡失败会单独记为 pending，继续其余网络清理。九项替身/静态恢复回归通过，不代替真实断线验收。以下早期记录保留历史事实。

三秒独立计时演练、结束主进程后由备用任务接管模拟恢复均通过。2026-09-24 12:43 实际测试却暴露空 JSON 路由数组错误：DNS 命令执行后恢复仍被判为失败，未自动重连，四分钟备用任务也失败。用户 12:54 手动恢复后，旧恢复计划还原 DNS 与新实例冲突。12:58 已恢复该实例的保护并清理任务，FastLink 未被操作。详见 [preview.9 记录](../../docs/FAKEIP_PREVIEW9.zh-CN.md)。

已修复空数组迭代、GUID 比较和宿主路径尾分隔符问题；新增停止前宿主预检、恢复值回读、重启后 DNS 检查、用户先行重连时不再重写网络。2026-09-24 13:45 的恢复专用窗口、13:48 的全进程失败收尾，以及 14:24–14:25 修复后的全进程通过窗口，均由独立进程恢复基线并重启原 Netch，两次 DNS 应答成功后记录 `ProxyReconnected=true`，备用任务已清理。全进程的回环 TCP/UDP DNS、透明 HTTPS、核心故障、重连和旧映射检查均已通过。TUN 已接入持久路由记录和测试入口，但其 Windows 管理员确认返回取消，尚未实际运行。手动接管竞争及真实计时到期/备用接管仍待实测。详见 [preview.10 记录](../../docs/DNS_ACCEPTANCE_PREVIEW10.zh-CN.md)。

## 脚本职责

| 文件 | 行为 |
| --- | --- |
| `Prepare.ps1` | 只读系统状态，保存原 EXE/配置哈希、PID/创建时间、静态或 DHCP DNS 与路由基线 |
| `Stage.ps1` | 复制测试宿主、探针和组件到私有会话目录，不改安装目录或网络 |
| `Arm.ps1` | 注册约四分钟后的管理员备用任务，再启动三分钟独立进程，核对就绪 PID/计划哈希 |
| `Run.ps1` | 全进程或 TUN Fake-IP 窗口：核验快照、执行宿主预检、Arm、停止记录的原 Netch、登记测试进程、允许其执行；收尾请求同一恢复路径；`-RecoveryOnly` 仅验证停止和恢复 |
| `Start.ps1` | 管理员入口，依次准备、复制和运行；会影响网络，不能当作普通编译检查 |
| `Watchdog.ps1` | 定时或主动恢复、身份校验、DNS/规则/明确拥有的路由恢复、尝试重连，写结果 |
| `Rehearse.ps1` | 模拟文件恢复；`-ExerciseBackupTask` 验证结束主恢复进程后备用任务接管并清理 |
| `Regression.ps1` | 在 Windows PowerShell 5.1 中提取实际恢复函数，以内存替身执行生产分支，覆盖空列表、多路由、GUID、产品 TUN 路由记录；另检查手动接管分支顺序，不改网络 |

私有会话位于 `.build/network-acceptance/session-*`，配置备份只授予当前用户、管理员和 SYSTEM。自动重连能力核验构建生成的 `Netch.release.json` 与 EXE SHA-256；当前基线明确限定为已安装的 preview.9，保留 `artifacts/replacement` 中的对应产物。preview.10 另存于候选目录。旧文件版本资源不能区分预览后缀，不能单凭 `1.9.11.0` 判断支持 `-start`；preview.10 已将完整预览版本写入 ProductVersion。

## 执行约束

用户后来允许临时断开 FastLink，并要求尽快交付；任何断线测试仍保留定时恢复。网卡禁用方案在实际失败后已废止，不能因既有授权继续使用不可靠的恢复路径。现有授权不能替代就绪、身份和恢复检查；实际测试不在普通回归中自动运行。

管理员上下文须先验证本地模块、EXE/配置、快照时效及原进程身份。期限从独立进程就绪开始，固定 180 秒；到期开始恢复，命令本身仍需时间。备用任务约 240 秒触发，不能防御同一恢复实现自身的缺陷。

测试宿主位于 `test/host`，探针位于 `test/probe`。按 PID、路径、创建时间核验，不按名称批量结束。子核心由宿主 Job 管理，恢复时还检查已登记宿主的测试目录内子进程。宿主先登记，再允许其修改网络。

`Start.ps1 -AcceptanceMode FullProcess` 使用全进程模式，`-AcceptanceMode Tun` 使用 TUN；默认 FullProcess。两者均经过同一监督和恢复流程。TUN 产品控制器在创建路由前持久保存完整元组（网卡 GUID、前缀、下一跳、metric）到 `data/tun-owned-routes.json`；拒绝接管已存在的路由。恢复进程读取测试宿主的这份记录及会话 `owned-routes.json`，仅清理仍精确匹配的路由，禁止按前后差异批量删除。TUN 实际 Windows 路由行为尚未验收。旧 system/capture 驱动未接入，不能直接运行。

## 恢复结果

创建 `restore-now` 可提前触发；没有 `test-started` 不改网络。正常收尾也请求同一恢复路径。恢复最多重试三次，并回读 DNS、路由及规则。

发现用户已自行启动原 Netch 时，不再覆盖网络，写 `user-restarted-network-untouched`。这不是基线恢复完成，需核对现用状态；目前仅验证了该分支的静态顺序，真实竞争仍待验收。

通常恢复后用 `-start` 启动核验过的原 Netch，不改 `StartWhenOpened`。检查新进程拥有的 DNS 监听器，两次成功应答后标记 `ProxyReconnected=true`。45 秒内未恢复则结束本恢复程序刚启动的实例，再还原基线 DNS，记录 `network-restored-proxy-unavailable`；无法承诺故障节点一定重连。

必须解读 `restored.json` 的具体 `Result`、`ProxyReconnected` 和可选 `NetworkRestored`；文件存在不是全项通过。失败日志仍保留。当前恢复完成或用户已接管并核对状态后才清理该次备用任务。

旧禁用网卡计划另外记录 `ExternalAdapterRestored`；为 false 时成功重连最多记录 `netch-restored-external-adapter-pending`，并保留 `adapter-restore-pending.json` 及原 DNS 快照。不操作其他 GUID，也不把未恢复的外部程序算作成功。该容错分支只经过替身回归，没有再中断用户代理进行故障复现。

独占锁允许备用进程接管已退出/被结束的主恢复进程，目前不能接管仍存活却卡住的进程。断电、权限撤销、调度故障或远端故障也不在保证范围。先完善这些边界的验证，再扩大真实断线范围。
