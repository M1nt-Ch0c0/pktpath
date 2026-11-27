# PktPath 纯 Cordis 预览版发布说明

这是 PktPath 全面转向 **纯 Cordis 架构** 后的完整预览版，面向 **Windows 电脑分析 + Android 手机采集** 场景（同步提供 Linux x64 预览包）。本版彻底移除了旧版 Go 桌面程序，所有分析、导出、采集控制与插件管理统一由随包内置的 Node v24.22.1 环境驱动，并在系统默认浏览器中打开使用。

## 本版重点变化

- **Windows 标准安装程序与托盘体验**：提供单文件 Windows x64 标准安装程序（`PktPath-Studio-Setup-<tag>-win-x64.exe`），默认安装到当前用户目录（`%LOCALAPPDATA%\Programs\PktPath Studio\`，无需管理员权限），自动创建桌面与开始菜单快捷方式；运行时无黑框常驻系统托盘，自动打开默认浏览器，卸载或覆盖升级时默认保留 `%LOCALAPPDATA%\PktPathStudio` 下的会话与日志数据。
- **流向图体验升级**：队列路径流向图支持缩放、拖拽平移与重置视图，支持点击节点联动筛选样本明细，并修复了面板拉矮时底部节点被裁切的问题。
- **完整离线分析与三种导出**：支持离线会话重建与异常提示，内置 **CSV 报表**、**PCAPNG 标准抓包文件** 和 **不可逆脱敏会话** 三种导出方式（脱敏导出写入新目录，不改动原始数据）。
- **Android ADB 单次与持续抓包**：连接已 root 的 Android 手机后，支持定时单次采集，以及持续录制过程中的**立即落盘**保存。
- **插件中心与核心保护**：支持浅色/深色主题切换以及外部插件管理；核心内置底座插件在插件页明确标注为不可关闭，避免误停导致核心功能异常。

## 快速体验

### Windows（标准安装程序）

1. 从本 Release 页面下载 `PktPath-Studio-Setup-<tag>-win-x64.exe` 并双击安装（安装路径默认位于 `%LOCALAPPDATA%\Programs\PktPath Studio\`）。
2. 通过桌面或开始菜单中的 **PktPath Studio** 图标启动，托盘图标就绪后会自动在默认浏览器打开工作台。
3. 右键系统托盘图标可快速打开 Studio、打开会话目录、查看日志、重启服务或优雅退出；如需卸载，可通过 Windows“应用和功能”完成（默认保留历史会话数据）。

### Linux（tar.gz 预览包）

1. 解压 `pktpath-linux-x64-<tag>.tar.gz`。
2. 运行 `./start-studio.sh` 启动并打开工作台，运行 `./stop-studio.sh` 优雅停止。

## 边界与注意事项

- Windows 端仅用于分析与控制，不支持 Windows 本机抓包；Android 采集需要本机已有 `adb` 且手机已具备 root 与 eBPF 条件。
- 本预览版**暂不包含** Linux SSH 远程抓包和自定义内核扩展。
- 每次发版的实际真机与回归验证范围以该 Release 正文说明为准。

## 下载校验

- 请以本 Release 页面附带的 `SHA256SUMS.txt` 为唯一权威校验清单（覆盖当前 Release 页面全部发布资产）。
- 安装目录及 Linux 解压目录内另附 `MANIFEST.sha256`，可用于核对包内每个文件的 SHA-256。
