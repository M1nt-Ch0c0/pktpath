# Wei 纯 Cordis 对齐返工交接单（运行时 / 启动脚本 / Windows 对话框）

- **时间**：2026-11-27 亚洲/上海
- **基线**：`4c89a054312e96689413a9376e94fc5f322743a2`（`preview-cordis-20261127-wave1`，干净检出，未带共享树脏改动）
- **本地目录**：`/workspace/wei-cordis-parity-rework-20261127`
- **本地分支**：`wei/cordis-parity-rework-20261127`
- **未推送**：是（严禁 push / tag / 发布 / 操作用户 Windows 电脑）

## 提交

本地分支 `wei/cordis-parity-rework-20261127` 的 tip（以 `git rev-parse HEAD` 为准，交接汇报中写完整 SHA）。工作树应保持干净，未推送。

## 改动文件与 SHA256

| 文件 | SHA256 | 说明 |
|---|---|---|
| `studio-cordis/src/server/app.ts` | `10d29c5b5def0c086852780e8975eedadb1136c7b710d84b4b34ea662ed95ce8` | P1-12 自动退出 + SSE 计数/初始事件 + 对话框 HTTP 状态 |
| `studio-cordis/src/main.ts` | `d756311378ac3b5dcbeabcf7462aa5a7f8674784eb5b012e21243262c53798b5` | `--no-auto-quit` / `--auto-quit-ms` / 环境变量，挂接 `CaptureController` |
| `studio-cordis/src/plugins/adb/capture-controller.ts` | `34176b53aa54f60f04678a2084eda2dde02d65cf9125e4169d8f1a484e0cd49a` | 只读 `hasActiveCapture()`（running/pulling），无业务逻辑改动 |
| `studio-cordis/src/server/dialog.ts` | `a5b9fa768589c35f1a9bb2a7938d70343abb1be90939e5f437ff0a0f1490f573` | Y-AUDIT-03 Windows 原生对话框完整修复 |
| `scripts/package_preview_bundle.py` | `7b41301f81b531be1538393049e5e7d1484934a319058f18bd01e0ef4de17457` | `write_launchers` 保留/补写 `.ps1` UTF-8 BOM；未改 workflows |
| `studio-cordis/scripts/start-studio.ps1` | `d588fe98f0bc0fb1ccb4ddf91c9a7fa249c6615038633d9508f4af2166e75960` | 仍为 UTF-8 BOM+CRLF；补 `--no-auto-quit` 用法说明 |
| `studio-cordis/scripts/start-studio.sh` | `304f9f077c452baba7c448f73e33fb0662b2a2714967a54392580159b5a0a1ae` | **新增**，与 Windows 启动器同一套口径，供 `--launchers-dir` |
| `studio-cordis/scripts/stop-studio.sh` | `b92039adb36c80af66cb2f81915ebfab66604229bdb6b2030fa8fe5ce052fc55` | **新增**，转调 `start-studio.sh --stop` |
| `studio-cordis/scripts/start-studio.cmd` | `4e2c702d3ee8b3b254ea77858d840c59f252b6732645778431fdf2bd09cec950` | 未改（无 BOM + CRLF + `chcp 65001 >nul`） |
| `studio-cordis/scripts/stop-studio.cmd` | `4acdc11d4d46825b609846c2d09a5de5853acc15dd216e5f8c6ccc0d09692b48` | 未改 |
| `studio-cordis/scripts/stop-studio.ps1` | `5f9ff06a7176827d01f2328203e3fe44d07a70756b792009a63ee20ada883e35` | 未改（UTF-8 BOM + CRLF） |
| `studio-cordis/test/auto-quit.test.ts` | `f408163aa5cc4c8088bbe37288ef891a459d715bfe3f524f479f795542fdb35f` | P1-12 六条路径 + CLI 解析 |
| `studio-cordis/test/dialog.test.ts` | `98febe771c521c768203f92879efe4213734ad7cfa9aa8126042a2d676e04d0c` | Y-AUDIT-03 + P2-13 |
| `studio-cordis/test/launch-scripts.test.ts` | `c5016835e0230d7657b82f0abca8d2c50d842cfbc902f509f2e2715130b5a31b` | P1-13 / P2-12 / P2-14 与 `write_launchers` 干跑 |
| `studio-cordis/scripts/mock-cordis-server.mjs` | `ad5e19484dcca5f9a92bdb4f21f47d7fcea2ba6f8962f305aa3bb8f2bcba15d2` | 供已有 `verify-launch.mjs` 使用的 mock 入口 |

## 审计项对照

### P1-12 关闭最后一个标签页后自动优雅退出

已对齐旧 Go `pktpath-studio/main.go:229-245` + `server.go` SSE 计数：

- 追踪 `everHadClient` 与当前 SSE 客户端集合；`req`/`res` 的 `close` 只递减一次。
- 初始事件同时发送 `: connected\n\n`（对齐 Go）和 `event: ready\ndata: {"ok":true}`（兼容现有前端 EventSource）；响应头补 `Cache-Control: no-cache, no-store` 与 `X-Accel-Buffering: no`。
- `hasActiveCapture` 由 `main.ts` 注入 `CaptureController.hasActiveCapture()`（`running` 或 `pulling` 视为活跃，采集/拉取期间不误退）。
- 默认 25000ms；有新 SSE 或采集开始则取消倒计时；采集结束后若仍无客户端会重新启动倒计时（事件 + 定时轮询双保险）。
- 开关：`--no-auto-quit`、`--auto-quit-ms <ms>` / `--auto-quit-ms=<ms>`，环境变量 `PKTPATH_NO_AUTO_QUIT=1|true`、`PKTPATH_AUTO_QUIT_MS`。从未连过 SSE 或显式禁用时，现有无头测试不受影响。

### P1-13 启动脚本参数转义、采集器 fail-closed、`--stop`

- `Get-WinArgvQuoted` 保持原算法；已用移植实现覆盖空格、中文、引号、尾部反斜杠（无空格时不强制加引号；有空格时关闭引号前把尾部 `\` 加倍）。
- 未知参数（含 `--no-auto-quit`、`--auto-quit-ms`）经 `Forward` 原样交给 `main.ts`。
- `collectors\android-arm64\pktpath` fail-closed 与 `--stop` → `POST /api/app/quit` 逻辑未改。
- `START-HERE.md` 仍由打包脚本在发预览时生成，本次不改发布名称。

### P2-12 `start-studio.sh` 源真相

- 已把完整口径的 `start-studio.sh` / `stop-studio.sh` 放入 `studio-cordis/scripts/`。
- `prerelease.yml` 已使用 `--launchers-dir studio-cordis/scripts`（未改 workflow）。
- 本次只微改 `write_launchers`：拷贝 `.ps1` 时保留或补写 UTF-8 BOM，避免打包后丢掉 Y-W1-WEI-01 的 BOM（旧实现 `read_text` + `encode("utf-8")` 会剥 BOM）。
- 未带 `--launchers-dir` 时，打包脚本仍回退到内置简化模板；正式预览请继续走 `--launchers-dir studio-cordis/scripts`。
- 干跑：Windows 打入 `start-studio.cmd/.ps1` + `stop-studio.cmd/.ps1`（`.ps1` 与源字节级一致，含 BOM）；Linux 打入 `start-studio.sh` + `stop-studio.sh`（LF、可执行、与源字节级一致）。

### P2-13 非 Windows 对话框 501

保持既有 Cordis 行为：`{ok:false, unsupported:true, error:"native dialog \"…\" is only available on Windows; please enter the path manually"}`，HTTP 501。已在 `dialog.test.ts` 与 HTTP 层覆盖。

### P2-14 隐藏窗口 / 双击闪烁

- `start-studio.ps1` 仍用 `WindowStyle Hidden` / `CreateNoWindow` 拉起 Node。
- `start-studio.cmd` 作为双击入口必须保留可见控制台，以便 fail-closed 中文报错能显示；就绪后 ps1 在隐藏窗口启动 Node 并退出，黑窗只会短暂出现。未做会吞掉报错的 hidden-cmd 改动。
- **未做 Windows 11 真机双击实测。**

### Y-AUDIT-03 [P1] Windows 原生对话框

对齐 Go `sessions.go:450-515` 与 `dialog_windows.go`（在 Node 侧用 WinForms，不引入新依赖）：

1. PowerShell 启动前设置 `[Console]::OutputEncoding/InputEncoding` 与 `$OutputEncoding = [System.Text.UTF8Encoding]::new($false)`；Node 以 UTF-8 解码 stdout。
2. 透传 `initial_dir` / `filter` / `title` / `default_name`；单引号按 PowerShell 规则转义（`'` → `''`）；不存在或非目录的 `initial_dir` 不写入对话框；`pick-folder` 在 HTTP 层默认 `sessionsRoot`；`save-file` 空目录时回退 Downloads/`USERPROFILE`；文件名按 Go 规则消毒。
3. 用户取消返回 `{ ok: false, cancelled: true, path: '' }`，HTTP 200（不再错误地 `ok:true` 或 400）。
4. `reveal`：目录 `explorer.exe <dir>`，文件 `explorer.exe /select,"<file>"`；WinForms 弹窗挂隐藏 `TopMost` owner `Form`，`ShowDialog($owner)` 后 `Dispose()`。
5. 通过可注入 `DialogHooks` 在 Linux 盒覆盖上述行为；默认生产路径不变。

## 测试

在 `/workspace/wei-cordis-parity-rework-20261127/studio-cordis`（Node v24.22.1）：

```bash
npm run check    # checked 40 files
npm test         # 78/78 passed, 0 failed
```

其中新增：

- `test/auto-quit.test.ts`：7 项（CLI + 六条自动退出路径）全部通过
- `test/dialog.test.ts`：6 项（Y-AUDIT-03 + P2-13）全部通过
- `test/launch-scripts.test.ts`：3 项（编码、引号、`write_launchers` 双端干跑）全部通过

未新增 npm 依赖，保持纯 Node 24 `erasableSyntaxOnly` TypeScript。

## 验收边界

Linux 盒单测 + `write_launchers --launchers-dir` 打包结构自测通过。

**不是**：Windows 11 真机双击启动、中文 Windows PowerShell 5.1 路径乱码实跑、真浏览器关闭最后一个标签后自动退出、或真机原生对话框实点。这些仍须 Cosmo 原始授权后在真机上验收。

## 提交 SHA

本地分支 tip，以 `git rev-parse HEAD` 为准，完整 SHA 写在给 Max 的交接汇报中。
