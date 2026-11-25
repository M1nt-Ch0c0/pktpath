# Linux / Android arm64 与排障

[文档目录](index.md) · [构建命令](build-test.md)

## 平台边界

Linux x86_64/arm64 和 Android arm64 是采集目标；当前 Studio 桌面入口是 Windows amd64。README 声明内核 >=5.10，但真实可用性依赖目标 BTF、符号、BPF 配置、kprobe/kretprobe、权限/安全策略、qdisc 和驱动实现。内核版本号和 root 身份本身都不足以保证成功。本次没有新增任何设备验证矩阵。

先记录目标 `uname -m` / `uname -r`、设备型号/系统、接口、qdisc、工具链与采集器 SHA；不要收集或提交 SSH 私钥等凭据。构建方法见 [构建文档](build-test.md)。SSH probe 支持 root 或 `sudo -n` 权限状态；交互密码/授权流程不由本文自动绕过。

## 目标上的最小验证流程

以下步骤只在已获准的测试目标上执行，`eth0`/`wlan0` 及会话路径必须替换。采集会访问内核并写数据；先核对测试范围、磁盘预算和隐私，不在生产机盲跑。Android 在自己的已授权 root shell 中使用 `/data/local/tmp/pktpath-android-arm64`；部署/提权方式按设备策略处理，不保证通用 `su` 写法。

```sh
# Linux x86_64 目标；arm64 换成相应产物
./bin/pktpath-linux-x86_64 --help
./bin/pktpath-linux-x86_64 inspect --dev eth0 --scope tc-egress --json
./bin/pktpath-linux-x86_64 record --mode oneshot --dev eth0 --scope tc-egress --duration 5s --out /tmp/pktpath-test-run
# 若需扁平 runtime JSON，在 inspect 和 record 都加同一 --plugin 文件
```

只有获得相应权限后才在自己的测试 shell 提权运行；本文不自动调用 sudo。每次用新的输出目录，避免覆盖已有会话。`inspect` 验证环境/准入，不代表 record 已挂接或产生了可重建的流量。选择 oneshot、短 duration，按约定制造可识别测试流量，检查 stderr、manifest 准入/partial 状态和事件质量，再将完整会话拉回主机分析。

```sh
# 主机离线操作：run-dir 换成拉回的完整会话目录
python3 pktpath.py show run-dir --evidence --json
python3 pktpath.py stats run-dir --json
python3 pktpath.py export run-dir --format pcapng --out capture.pcapng
python3 pktpath.py redact run-dir --out redacted-run
```

这些含占位路径的命令是流程示例，不是本次实测。导出/脱敏写新路径；分享前人工复核内容。`--capture-hdr` 会增大隐私暴露面；只在需要且获准时开启。

## 按症状定位

| 症状 | 检查与解释 | 源码 |
| --- | --- | --- |
| Linux 构建被 NDK 错误阻断 | 默认 `all` 先构建 Android；改用真实目标 `--target linux-x86_64`，不是改编译器路径伪装 Android | [build_device.py](../../scripts/build_device.py) |
| BPF 构建找不到 elftools / bpfel | 检查当前 Python 的 pyelftools 和 clang BPF target；脚本无 `--arch`/help；不要用其他架构头掩盖错误 | [build_bpf.py](../../scripts/build_bpf.py) |
| 编译成功但加载/挂接失败 | 收集实际 errno/verifier/准入报告；检查 BTF、kallsyms、tracefs、权限、内核配置与符号。分开报告 BPF load 与 attach，不把“不支持”硬改成成功 | [recorder.c](../../device/recorder.c)、[kallsyms.c](../../device/kallsyms.c) |
| 字段没有值 | 检查扁平/嵌套格式、全局槽位、目标 BTF 字段是否可解析及 enabled/warning；配置成功不是字段采到 | [plugin_loader.c](../../device/plugin_loader.c) |
| bundle 说安装成功但设备没扩展 | 查是否激活、是否执行物化、是否同步了本次扁平文件；不要直接喂嵌套 manifest | [kernel.go](../../studio/pkg/kernel/kernel.go)、[capture.go](../../studio/pkg/server/capture.go) |
| 输出是 incomplete / unknown | 查看 `gap_reasons`、QUALITY、partial coverage、未闭合 visit/call、序列/尾部；SEQ_GAP 还需排除 CPU 模16共槽假缺口，不能直接定性丢包 | [reconstruct.py](../../analyzer/reconstruct.py) |
| CRC/UUID 错误或崩溃尾部 | 不混合不同会话块，不手改 CRC；保留原件，在副本上复现，区分损坏与容忍不完整尾部 | [wire.py](../../analyzer/wire.py)、[Go wire](../../studio/pkg/wire/wire.go) |
| Windows 找不到 adb / hook | 检查主机 PATH 或显式 adb 路径，hook 的解释器/相对路径及 stderr；不要捆绑凭据或把日志混到 stdout | [runtime.go](../../studio/pkg/adb/runtime.go)、[external.go](../../studio/pkg/kernel/external.go) |
| Linux Go 单测绿但无桌面入口 | 入口受 windows build tag 限制，必须另做 Windows 打包与运行；不是 Linux GUI 已通过 | [main.go](../../studio/cmd/pktpath-studio/main.go) |

独立复核已有宿主 `inspect` 记录在 `thread_info.preempt.count` 必需 BTF 字段缺失处失败；这在 scope 检查前发生，不能计为 RX/scope、内核挂接或 Android 验证通过。本次文档工作未在目标内核复跑该 inspect；后续验收应保留失败原文并在兼容目标重测，而不是移除必需字段校验来取得绿色结果。

## 报告问题最小材料

提交可复现命令、基准/改动 SHA、工具版本、目标架构与内核、脱敏后的错误/准入信息、预期和实际、观察到的证据及至少一种反方解释。设备数据、用户名/IP/路径和进程信息先审查再分享。没有真实设备时可以报告源码风险或构造用例，但应标记为待验证，不能将猜测登记为已证实内核 bug。
