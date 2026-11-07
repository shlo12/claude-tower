# CC Shield · Windows 测试版 1.0.0

原生 Windows 系统匣哨兵，使用系统 .NET Framework 4.8 / WinForms；不依赖浏览器常驻，不需要管理员权限。源码由 shlo 维护，遵循仓库 AGPL-3.0 许可。

**当前验收状态：交叉编译成功，共用会话策略通过 37 项运行测试；Windows 11 实机验收尚未完成。请作为 Pre-release 使用。**

## 使用

1. 完整解压分发 ZIP，双击 `Install.cmd`。安装到 `%LOCALAPPDATA%\CCTower\App`，创建桌面和开始菜单快捷方式；也可直接运行 `WindowsShield.exe`。
2. 在 Clash Verge / FlClash 等 Mihomo 客户端开启系统代理、TUN、全局模式。在客户端查看本机 `external-controller` 地址和 `secret`；仅支持数字回环 HTTP 接口，默认 `http://127.0.0.1:9090`，不会替你开启接口。
3. 点击哨兵“监测接口 / 客户端”，填写接口及密钥，选择 Anthropic 有效签名的 `Claude.exe`；商店安装包会尝试自动发现。保持瞭望先检查结果。
4. 正常退出 Claude，切到“戒严”，点击“检查后启动 Claude”。关闭面板后仍在系统匣运行；点击系统匣图标重新打开。右键可自行开启开机自启。
5. “体检与维护”按需打开本地 Python 页面；关闭它的终端会结束体检服务，不会结束原生哨兵。结束使用请点击“结束本次使用”，再改节点或代理设置。

## 两个档位

| 档位 | 行为 |
| --- | --- |
| 瞭望（默认） | 周期检测及提醒，不自动结束 Claude；退出瞭望也不会结束 Claude |
| 戒严（主动选择） | 使用前完整检查；本次会话绑定节点选择链、TUN 接口、时区和完整出口。未获本次准入的 Claude 桌面进程会被请求退出 |

使用中约每 10 秒巡检，空闲约每 30 秒；2 秒检查一次受管进程及证据过期。启动检查不通过或任一关键证据不明，不准入。正常网络波动只有在节点、代理、路由、IPv6 与 TCP 采样仍有效时才给最多 120 秒恢复期；关键路由证据超过 45 秒、明确证书错误、直连路由、节点／时区／已知出口变化会结束会话。

结束时先请求正常退出，5 秒后仍存活才结束相同路径、相同启动时间的进程（含同路径辅助进程）；不会按 `claude*` 名称批量杀进程。更新客户端后路径或签名变化，需要重新选择并检查。正在运行的旧哨兵须先退出，再更新文件。

## 证据和边界

- 支持提供本机 Mihomo 控制 API 的客户端；首版不支持其他协议控制器、远程控制 API，也不自动修改代理、DNS、TUN 或节点。
- TUN 要同时有 API 开关和 Windows 最佳路由到受支持虚拟适配器；IPv6 须无默认路由或同一 TUN。检查 Claude 已建立 TCP 连接的当前路由，不能追溯连接建立时的路径，也不覆盖每一条 UDP/QUIC 连接。
- HTTPS 经本机显式代理查询 Claude 两个域名出口，STUN 单独测试系统 UDP 路径。完整出口只在内存比较；两者不一致或 STUN 无结果会阻止首次准入。首版采用保守的单一出口要求，多出口、IPv4/IPv6 混合出口可能无法通过；这不等于已经发生泄露。
- DNS 行只证明系统解析成功，不证明解析器身份或解析出口。代理节点选择链是客户端 API 提供的证据，不能识别所有同名节点内部配置变化。
- 仅监测所选、有效 Anthropic 签名的 Claude 桌面客户端，不覆盖 CLI、浏览器或全部应用；这不是防火墙，启动及采样之间存在窗口。哨兵崩溃、退出或系统挂起后不提供内核断网保障，也不承诺防封或零泄漏。首次安装不等于已完成保护配置。

## 隐私与存储

接口、密钥和客户端位置保存在 `%LOCALAPPDATA%\CCTower\Shield\settings.dpapi`，使用 Windows DPAPI 当前用户范围加密，不保留明文副本。当前用户上下文中的恶意程序仍可能访问设置，DPAPI 不防同用户恶意软件。设置无法解密时退回瞭望并提醒，不冒充戒严恢复。

`events.log` 只记录时间、操作类别及固定原因，不记录完整出口、接口密钥、节点名或命令行；64 KiB 后轮换一份。完整节点选择摘要与出口、准入凭据只在内存，重启后重新检查。开机自启使用当前用户 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CCShield`，仅用户主动点击后写入。

联网目标为 `claude.ai`、`claude.com`、`api.anthropic.com`，以及 Google / Cloudflare 的公共 STUN；不附带 Claude 登录凭据或 Cookie。网络服务仍可看到请求来源。体检工具原有数据边界见根目录 SECURITY.md。

## 开发与验证

在 Windows 源码根目录运行 `windows\shield\build.cmd`，输出 `windows\shield\WindowsShield.exe`。使用系统 CSC 编译，无需 NuGet 或第三方 UI 库。将 EXE 放到分发根目录；开发构建可复制到 `build\windows\WindowsShield.exe` 后由打包脚本组装。

```powershell
$p = Start-Process windows\shield\WindowsShield.exe -ArgumentList ('--self-test '+[char]34+$env:TEMP+'\shield-tests.json'+[char]34) -Wait -PassThru
Get-Content "$env:TEMP\shield-tests.json"
# 只读诊断：未配置环境必须显示未确认，而非通过
$p = Start-Process windows\shield\WindowsShield.exe -ArgumentList ('--probe-report '+[char]34+$env:TEMP+'\shield-probe.json'+[char]34) -Wait -PassThru
Get-Content "$env:TEMP\shield-probe.json"
```

`--self-test` 包含策略、DPAPI、回环接口限制及未签名程序拒绝验证；不结束真实 Claude、不改网络或系统代理。GitHub Windows 工作流会编译并运行这些检查。交叉编译仅证明能生成 PE，不能替代系统匣、真实代理、MSIX、进程退出及断网恢复实机验收。

尚未提供代码签名证书，Windows 可能提示未知发布者；请核对来源和 SHA256，不要关闭安全软件。卸载前退出哨兵并关闭其开机自启，然后删除用户应用目录及两个快捷方式；删除 Shield 数据目录会清除其加密设置与操作日志，体检数据独立保留。
