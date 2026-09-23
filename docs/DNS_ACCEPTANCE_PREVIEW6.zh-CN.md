# preview.6：客户端关闭不再导致整个 DNS 监听停止

## 用户日志与复现

用户的 preview.5 日志显示，2026-09-23 23:39:03 首次启动，23:39:19 连续出现 UDP 接收错误 10054，达到三次重试上限后记录 `DNS UDP listener failed`。第二次启动在 23:40:23，之后仍出现同类 10054。第二次能用只是没有再次达到连续错误阈值，并非错误已经消失。

Windows 会把向已关闭客户端 UDP 端口发送应答产生的 ICMP 不可达通知，报告给共享的 UDP 接收套接字。此前代码把它和监听器自身中断一起计数；单个或多个客户端提前关闭会使整个 DNS 服务停止。

新增回归用例先在旧实现上运行：在本机临时端口接收八个查询，等待客户端关闭后，依次释放应答，旧实现发生相同的监听停止。证据：`.build/udp-departure-before.log`。无需断开现用代理或使用系统 53 端口即可复现。

## 修复

- IPv4/IPv6 的 DNS UDP 服务套接字设置 `SIO_UDP_CONNRESET=false`，避免已离开的查询客户端触发共享套接字的连接重置通知。
- 防御性处理仍可能收到的 10054：不计入监听器故障上限，短暂让出执行后继续接收；过载时回复失败也不会因该通知停止整个监听器。
- 真实的监听故障仍明确报告并停止解析。没有改变远程 DNS 通道、系统防护或禁止本地回退的策略；没有增加重连按钮或测试界面。

该套接字选项语义见 [Microsoft Winsock IOCTLs：SIO_UDP_CONNRESET](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_udp_connreset-opcode-setting-i-t3)。

## 验证与交付

新增用例覆盖 IPv4/IPv6，以及生产默认设置/主动重新开启 Windows 重置通知两种情况，共四个客户端退出突发场景。修复后全部成功；每组同时确认其他 TCP/UDP 客户端继续得到正常应答，暂停解析后返回 SERVFAIL。证据：`.build/udp-departure-after.log`。

**28 组完整回归通过**，结果保存于 `.build/tests-full-preview6.log`。本次不修改运行中的 Netch、防火墙、网卡 DNS 或路由，不把 preview.5 的系统级验收当作 preview.6 重新执行的结果。此前进程模式、FastLink 共存及逐包导出受限的边界仍然适用。

交付仅为 `artifacts/replacement/Netch.exe`，版本 1.9.11-dns-preview.6，大小 196848768 字节，SHA-256：

```text
f104550dfe10009e61a88d38c464a53bd6e9f950c4249559155450b2f917689a
```

同目录 `Netch.exe.sha256` 保存相同校验值。用户完全退出旧版后替换 EXE，继续使用已有组件和配置。整体实现与后续范围见[任务总结与实施状态](DNS_IMPLEMENTATION_STATUS.zh-CN.md)。
