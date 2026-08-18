# NetAssess Windows 进程流量监视器

NetAssess 是一个原生 x64 Windows GUI 程序，使用 ETW 实时统计本机进程的 TCP/UDP 上下行流量。它不解析报文内容，不需要抓包驱动或第三方运行库。

## 支持范围与权限

- 支持 Windows Server 2016、2019、2022、2025 及后续保持兼容的版本，要求 Desktop Experience。
- 仅支持 x64；不支持 Server Core、Windows 容器、ARM64、x86 或远程主机。
- 程序清单声明了 `requireAdministrator`。启动时 Windows 会自动显示 UAC 提升提示；取消提升则程序不启动。

## 构建与测试

要求 Visual Studio 2022 Professional、MSVC、Windows SDK 和 CMake。在仓库根目录打开 PowerShell，执行：

```powershell
$netAssessCmake = 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
& $netAssessCmake -S . -B build -A x64
& $netAssessCmake --build build --config Debug
& $netAssessCmake --build build --config Release
& $netAssessCmake --build build --config Debug --target RUN_TESTS
```

Release 可执行文件位于 `build/Release/NetAssess.exe`。这是 Windows 子系统程序，不会打开控制台窗口。

## 使用方法

1. 运行 `build/Release/NetAssess.exe` 并在 UAC 提示中允许提升。主窗口打开后会自动开始采集。
2. “开始采集/停止采集”用于启停 ETW 采集。停止再启动不会清除已有累计值。
3. “清零统计”用于清空所有历史行、累计值和速度基线，但不停止采集。
4. “进程名筛选”不区分大小写，只影响当前显示，不影响后台统计。
5. 默认按上行速度与下行速度之和降序显示；点击列头可按该列排序，再次点击切换升序/降序。
6. 退出程序时会停止并清理本程序创建的私有 ETW 会话。

表格每秒刷新一次，共有九列：

| 列 | 含义 |
|---|---|
| 进程名 | 可执行文件名；无法查询时显示“受限进程 (PID)” |
| PID | Windows 进程标识符 |
| 状态 | “运行中”或“已结束”；进程结束后累计行保留至清零 |
| 传输层协议 | TCP 或 UDP |
| 推断应用协议 | 依据传输层和端口推断的应用协议 |
| 上行累计 | 采集开始后 ETW 报告的发送 IP 字节数 |
| 上行速度 | 当前发送速率 |
| 下行累计 | 采集开始后 ETW 报告的接收 IP 字节数 |
| 下行速度 | 当前接收速率 |

状态栏显示当前采集状态、ETW 丢失事件数、解析失败事件数和最近错误。会话启动失败时，窗口仍保持可操作；请根据系统错误码排查后重试，不要停止其他 ETW 会话。

## 统计口径

- 每行按“进程实例（PID + 创建时间）+ TCP/UDP + 推断应用协议”聚合，因此 PID 被复用时不会并入旧进程数据。
- 累计值只包含开始采集后收到的 ETW IP 网络事件字节，不是网卡线速字节，也不包含所有链路层开销。
- 界面约每秒取一次快照。速度是两次快照的字节差除以单调时钟的实际时间差，并非假定间隔永远恰好为 1.000 秒。首次快照、清零后的首次快照、无正时间差或计数回退时，速度显示为 0。
- 字节数使用 1024 进制格式化为 B/KB/MB/GB/TB，速度显示为 B/s、KB/s、MB/s 或 GB/s。
- 当状态栏的“ETW 丢失”计数非零时，部分事件已无法补回；此时显示的累计值只是实际流量的下界。“解析失败”事件也不会进入统计。
- 64 位累计值溢出时会饱和到 `UINT64_MAX`，不会回绕。

## 端口协议推断

“HTTPS/TLS”、“QUIC”、“DNS”等标签都是端口推断，不是对报文内容或 TLS 握手的识别。发送事件优先使用目标端口，接收事件优先使用源端口；首选端口未命中时才尝试另一端口。

| 传输层/端口 | 推断协议 |
|---|---|
| TCP 20/21 | FTP |
| TCP 22 | SSH |
| TCP 25/465/587 | SMTP |
| TCP/UDP 53 | DNS |
| UDP 67/68 | DHCP |
| TCP 80 | HTTP |
| TCP 110/995 | POP3 |
| UDP 123 | NTP |
| TCP 143/993 | IMAP |
| TCP 389/636、UDP 389 | LDAP |
| TCP 443 | HTTPS/TLS |
| UDP 443 | QUIC |
| TCP 445 | SMB |
| UDP 500/4500 | IPsec/IKE |
| TCP 1433 | SQL Server |
| TCP 3306 | MySQL |
| TCP/UDP 3389 | RDP |
| TCP 5432 | PostgreSQL |
| TCP 6379 | Redis |
| TCP 27017 | MongoDB |

非标准端口、端口复用、隧道和加密内层协议可能被推断为错误协议或“其他”。

## 已知限制

- 极高事件率或系统资源不足时 ETW 可能丢失事件，程序只能显示计数，不能补回。
- Windows 会限制可并存的系统记录器数量。槽位耗尽时 NetAssess 拒绝采集，不会查找、停止或修改其他 ETW 会话。
- 首版仅提供实时 GUI，不提供历史恢复、曲线图、文件导出、数据库、远程管理或报文深度解析。
