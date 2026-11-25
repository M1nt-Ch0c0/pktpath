# Studio：微内核、服务与前端

[文档目录](index.md) · [插件契约](plugins.md) · [构建](build-test.md)

## 源码导航

| 路径 | 职责 |
| --- | --- |
| [cmd/pktpath-studio/main.go](../../studio/cmd/pktpath-studio/main.go) | `//go:build windows` 桌面入口、参数、运行时解包、localhost server、浏览器/WebView2、自测；产品版本 2.0.0 |
| [kernel/kernel.go](../../studio/pkg/kernel/kernel.go) / [types.go](../../studio/pkg/kernel/types.go) | Plugin 接口 `Meta/Schema/Apply`、effect scope、扩展点、配置/启用状态、依赖、生命周期与内核插件物化 |
| [plugins/register.go](../../studio/pkg/plugins/register.go) | 13 个内置插件，包含 2 个 capture.mode；旧 README 的 11 漏计 oneshot/daemon |
| [server/server.go](../../studio/pkg/server/server.go) / [kernel_api.go](../../studio/pkg/server/kernel_api.go) / [plugins.go](../../studio/pkg/server/plugins.go) | HTTP、kernel 配置、插件生命周期和 API 入口；端点/方法以 handler 注册为准 |
| [server/capture.go](../../studio/pkg/server/capture.go) / [sessions.go](../../studio/pkg/server/sessions.go) | 目标采集、会话导入/读取与任务状态 |
| [adb/runtime.go](../../studio/pkg/adb/runtime.go) / [sshclient/client.go](../../studio/pkg/sshclient/client.go) | 系统工具发现、采集器同步与远程执行；不是内核模拟器 |
| [web/app.js](../../studio/web/app.js) / [plugin-center.js](../../studio/web/plugin-center.js) | 工作台、插槽与插件中心；更新前端应联查 API 返回结构 |

13 个内置插件：ADB、SSH、offline 三个 transport；ebpf-tc、kernel-ext 两个 collector；oneshot、daemon 两个 capture.mode；dag-reconstruct、anomaly-radar 两个 analyzer；pcapng、redact、csv-report 三个 exporter；一个 ui.theme。注册/禁用影响扩展可用性，不能只靠隐藏前端控件完成卸载。

## Windows 使用与验证

以下为 Windows PowerShell 示例，只有真实 Windows 环境才能验证桌面行为：

```powershell
.\bin\pktpath-studio.exe --headless --port 18080
.\bin\pktpath-studio.exe --window
.\bin\pktpath-studio.exe --adb C:\platform-tools\adb.exe
.\bin\pktpath-studio.exe --plugin-dir D:\my-plugins
# 仅在设备和采集权限已获准时运行；wlan0 换成真实接口
.\bin\pktpath-studio.exe --selftest --dev wlan0 --report .\selftest.json
```

入口还提供 `--serial`、`--app-dir`、`--keep-session` 等，准确选项查 main.go。默认应用目录由 `adb.DefaultAppDir()` 决定；实例信息、日志、运行时、插件配置都是用户本地状态，不应写回源码树。

不捆绑 adb：可显式 `--adb`，或由 `PKTPATH_ADB`、PATH、SDK 路径发现。Linux SSH 使用主机 OpenSSH/`scp` 工具，目标架构由 probe 匹配采集器；不要因为源码支持 SSH 就报告所有目标可用。

`--headless` 仍然是同一个 Windows 编译入口，不能据此推断 Linux 可直接 `go run ./cmd/pktpath-studio`。Linux 下可测通用包，Windows 打包/启动、WebView2、浏览器和设备自测需另列结果。

## 修改后的验收

1. 先做 [无设备测试](build-test.md)；kernel 生命周期、配置持久化与依赖级联参考 `kernel_test.go`。
2. API 改动测状态码、错误响应、启停顺序；[server_test.go](../../studio/pkg/server/server_test.go) 包含生命周期与 DNS rebinding guard 的测试。
3. 前端在实际工作台检查表单默认值、配置保存、禁用后资源撤销、session 切换和导出错误，不以 Go 单测代替浏览器测试。
4. 外部脚本及 JS 拥有主机/工作台权限，localhost guard 不是插件沙箱。未做安全审计就不能声称插件安全。
5. `--selftest` 会涉及真实设备，不是单纯离线单测；无设备时标为未运行，不创建假采集器凑出绿色打包或自测结果。
