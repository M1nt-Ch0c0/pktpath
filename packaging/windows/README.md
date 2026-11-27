# Windows 方案 1：托盘宿主 + NSIS 安装程序

本目录是纯 Cordis 预览的 Windows 标准安装交付（**不修改旧 `studio/`**）。

- 轻量托盘宿主：`packaging/windows/tray/`（纯 Go，零 CGO，零第三方依赖）
- 标准安装程序：`packaging/windows/installer/pktpath-studio.nsi`（NSIS Unicode，per-user 免 UAC）
- 图标与资源：`packaging/windows/assets/pktpath-studio.ico`，由 `tools/gen_icon.py` / `tools/gen_syso.py` 生成

## 交叉编译托盘宿主（Linux 盒或 CI 均可）

图标与 `.syso` 已入库。若需重生：

```bash
python3 packaging/windows/tools/gen_icon.py
python3 packaging/windows/tools/gen_syso.py
```

```bash
cd packaging/windows/tray
go test -v ./...
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o PktPathStudio.exe .
```

`go build` 会自动链入同目录的 `rsrc_windows_amd64.syso`（图标 ID=1 + VERSIONINFO）。不需要先跑生成脚本也能出带图标的 exe。

## 与 `package_preview_bundle.py` 的对接

1. 准备 staging 目录，根部只放：
   - `PktPathStudio.exe`
   - `node/`（官方 Node v24.22.1 win-x64，`node.exe` SHA256 `d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5`）
   - `studio-cordis/`
   - `collectors/`
   - `LICENSE`、`LICENSES/`、`MANIFEST.sha256`
   - **不要**放入 `.cmd` / `.ps1` 或旧 Go `pktpath-studio.exe`
2. 调用 makensis（Linux 盒原生 `nsis` 或 GitHub Actions `windows-latest` 的 `makensis` 均可）：

```bash
makensis -V4 \
  -DAPP_VERSION=20261127-preview \
  -DSTAGING_DIR=/abs/path/to/staging \
  -DOUT_FILE=/abs/path/to/PktPath-Studio-Setup-preview-win-x64.exe \
  packaging/windows/installer/pktpath-studio.nsi
```

安装行为：per-user 免 UAC，默认目录 `%LOCALAPPDATA%\Programs\PktPath Studio`；覆盖升级前通过 `FindWindow("PktPathStudioTrayWindowClass")` + `WM_CLOSE` 优雅停旧托盘；卸载和覆盖升级**不删除** `%LOCALAPPDATA%\PktPathStudio` 下的会话 / 日志 / 配置 / 外部插件。支持 `/S` 静默安装与卸载。
