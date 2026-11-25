# 构建、测试与命令契约

[文档目录](index.md) · [平台与排障](platforms-troubleshooting.md)

以下 shell 命令除特别注明外都从仓库根执行。先检查工作区；不要在他人的 checkout 或正在打包的 staging 目录并发构建。

## 无设备基线

Python CLI 只用标准库；最低版本声明为 Python 3.10。Go 模块的版本声明见 [go.mod](../../studio/go.mod)（`go 1.22`）。最低版本不是本次实测矩阵。

```sh
python3 --version
go version
python3 -m unittest discover -s tests -v
python3 pktpath.py --help
python3 pktpath.py show --help
python3 pktpath.py stats --help
python3 pktpath.py export --help
python3 pktpath.py redact --help
(cd studio && go test ./...)
(cd studio && go vet ./...)
```

预期：Python unittest `OK`；Go 命令退出 0（无测试包可显示 `[no test files]`）；help 显示真实参数。Linux 上 `go test ./...` 不覆盖带 Windows build tag 的桌面入口。

测试依据：

- [Python pipeline](../../tests/test_analyzer_pipeline.py)：构造 wire 会话、重建、统计、pcapng、脱敏及 CRC 损坏拒绝。
- [Python 示例插件](../../tests/test_example_plugins.py)：JSON 解析、hello hook 分析/导出，不是设备 BPF 测试。
- Go：[wire](../../studio/pkg/wire/wire_test.go)、[reconstruct](../../studio/pkg/reconstruct/reconstruct_test.go)、[export](../../studio/pkg/export/export_test.go)、[kernel](../../studio/pkg/kernel/kernel_test.go)、[plugins](../../studio/pkg/plugins/plugins_test.go)、[HTTP server](../../studio/pkg/server/server_test.go)。构造数据的断言不代表真实流量端到端覆盖。

## eBPF 头文件再生成

[build_bpf.py](../../scripts/build_bpf.py) 依赖 `clang` 的 `bpfel` 后端和 Python `pyelftools`（`elftools.elf.elffile`）。建议隔离环境安装依赖，不向系统 Python 强塞包。

```sh
python3 scripts/build_bpf.py
```

**此脚本没有 argparse、没有 `--arch` / `--help` 选项。** `main()` 总是依次生成 arm64、x86_64 和分发头；附加参数不会选择架构，`--help` 也不是只读帮助操作。不要照搬 README 旧的 `--arch all` 写法。

产物：`bpf/generated_progs_arm64.h`、`bpf/generated_progs_x86_64.h`、`bpf/generated_progs.h`。脚本执行严格告警、指令/栈和 relocation 检查；成功输出各架构 `BUILD_BPF_OK`。这不是内核 verifier 验证。纯文档任务无需再生成；产品改动应检查生成 diff 并在目标内核测试。

## 采集器

```sh
python3 scripts/build_device.py --help
python3 scripts/build_device.py --target linux-x86_64
python3 scripts/build_device.py --target linux-arm64
python3 scripts/build_device.py --target android-arm64
```

[build_device.py](../../scripts/build_device.py) 的唯一自定义选项 `--target` 为 `all|android-arm64|linux-x86_64|linux-arm64`，默认 `all`，不是 `--arch`。

| 目标 | 工具链 / 产物与限制 |
| --- | --- |
| Linux x86_64 | Linux 下优先 gcc 再 clang；输出 `bin/pktpath-linux-x86_64`；先 `-static`，失败会重试动态链接，故文件名不能保证静态；用 `file` / `readelf` 检查。非 Linux 分支使用 WSL |
| Linux arm64 | `aarch64-linux-gnu-gcc`；输出 `bin/pktpath-linux-arm64`；显式目标缺工具链应失败，`all` 可跳过。脚本没有为原生 arm64 自动选本机 gcc 的逻辑 |
| Android arm64 | NDK `aarch64-linux-android28-clang`；可设 `PKTPATH_NDK_CLANG` 为存在的编译器路径，或 `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT`；输出 `bin/pktpath-android-arm64`。API 28 工具链不等于任意 Android 内核都有 BPF 能力 |

`--target all` 先尝试 Android，缺 NDK 时会在 Linux 目标前失败；只需 Linux 时明确选目标。构建使用已提交 BPF 头，不会自动重新生成 BPF。成功应有 `BUILD_OK`，但仍需确认目标架构和链接方式。

```sh
./bin/pktpath-linux-x86_64 --help
file bin/pktpath-linux-x86_64
```

## Studio 打包（Windows 产品）

[build_studio.py](../../studio/scripts/build_studio.py) 始终设 `GOOS=windows`、`GOARCH=amd64`、`CGO_ENABLED=0`，不是 Linux 桌面构建脚本。

```sh
python3 studio/scripts/build_studio.py --help
# 先用真正的 Android NDK 生成采集器；不能把 Linux 二进制改名冒充 Android
python3 studio/scripts/build_studio.py --agent bin/pktpath-android-arm64 --out bin/pktpath-studio.exe
```

选项只有 `--agent`、`--out`、`--keep-staged` 和 help。Android 采集器必需；存在的 Linux x86_64/arm64 产物会被一同打包。脚本清理 `studio/assets_stage/`、复制采集器并写 SHA-256 manifest，构建后验证 PE subsystem 为 2，默认清除 staging 复制件。不要往此目录放人工文件。成功摘要 `ok=true` / `pe_subsystem=2` 不代表 Windows GUI 或真实设备自测通过；不捆绑 adb。

## 本次实际结果

2026-11-25（Asia/Shanghai，UTC+8），基于 [目录页所列 SHA](index.md)：Python 3.13.5 / Go 1.27.3 linux/amd64 下，Python 4 项 unittest、Go `test ./...` / `vet ./...`、Linux x86_64 采集器构建，以及上述 CLI/help 检查通过。具体命令和完整日志由本次 PR 交付记录提供。

未执行 BPF 再生成、arm64 / Android 编译、Windows 打包/GUI、真实设备 inspect/record、SSH/ADB E2E；本次不报告任何 CI 通过结论。后续贡献者必须记录自己的命令、环境与退出码，不能继承这段文字当作自己的测试结果。
