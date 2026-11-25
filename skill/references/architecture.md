# 架构、数据流与证据边界

[文档目录](index.md)

## 分层与主路径

```text
目标 Linux / Android arm64
  device/main.c -> inspect 规划 / record 控制
  device/btf_parse.c + kallsyms.c + topo_netlink.c + plugin_loader.c
  device/recorder.c -> BPF maps / 程序加载 / 探针挂接 / ringbuf / 会话落盘
  bpf/probe_core.bpf.c -> include/pktpath_bpf.h 共享运行时 ABI
                       |
                       v
  会话目录 manifest.json + dict.json + block_*.pktb
  include/pktpath_wire.h 定义离线线格式
                       |
          +------------+---------------------+
          v                                  v
  pktpath.py / analyzer/            studio/pkg/wire/、reconstruct/、export/
  Python show/stats/export/redact   Go 重建、概览、导出
                                             |
                                 studio/pkg/server/ -> studio/web/
                                 kernel 微内核 + 内置/外部插件
```

源码：[控制入口](../../device/main.c)、[采集器](../../device/recorder.c)、[探针](../../bpf/probe_core.bpf.c)、[Python CLI](../../pktpath.py)、[Studio 服务](../../studio/pkg/server/server.go)。Studio 通过 [ADB](../../studio/pkg/adb/record.go) 或 [SSH](../../studio/pkg/sshclient/client.go) 同步采集器/物化后的插件、启动采集、拉回会话；离线分析本身不需要设备。

C/BPF 共享 ABI 与持久化 wire 不是同一结构体。修改其中一个不能只改 Python 或只改 Go。wire 头定义 magic `PKTB`（`0x42544B50`）与 v1.0；Studio 入口的产品版本为 `2.0.0`，插件 `version` 是另一条独立元数据。

## 重建不是按时间排序画一条线

- [Python 重建](../../analyzer/reconstruct.py) 和 [Go 重建](../../studio/pkg/reconstruct/reconstruct.go) 关联 sample/object、clone/copy 后继、队列 visit、调用/返回及分支终点，形成多分支 DAG。
- [Python wire](../../analyzer/wire.py) / [Go wire](../../studio/pkg/wire/wire.go) 校验块结构、CRC、会话 UUID，处理落盘尾部与未知 TLV；不要为了“读出来”而跳过这些校验。
- `manifest.json` / `dict.json` 描述能力准入、适配器、拓扑、字典；事件块含事件流与质量检查点/结束标记。不能只拷贝几个事件而假定保留了所有上下文。

## 证据等级与完整性

[wire 定义](../../include/pktpath_wire.h) 的四级 evidence 是：`DIRECT=1`、`CONTRACT_DERIVED=2`、`ANNOTATION=3`、`GAP=4`。观测、契约推导、注解和缺口不可混称为“直接证明”。

Python `reconstruct()` 按分支检查：未知 MUST TLV、partial coverage、显式 GAP、identity conflict、后继截断、未完成/超时、非正常尾部、序列缺口、质量丢失窗口、未闭合或歧义的 visit/call。其结果为 `complete` / `incomplete` / `unknown`，再汇总到 sample。适配器 `missed_source == "none"` 可产生 `UNOBSERVABLE_MISSED_SOURCE`；没有报告丢失不等于没有丢失。Go 对应逻辑也应独立核对，不能只凭功能同名就假定两边完全一致。

开发结论必须区分：

- `--allow-partial` 只是允许降级采集，不会补回缺失事件，更不能把 incomplete 改写为完整。
- 没有看到某一步不证明它从未发生；丢包、缺探针、采样与截断需要分开讨论。
- `tgid_fallback` / UID 等归属标签不是发送进程身份的无条件证明；qdisc 函数签名、BTF 与时序都影响解释。
- 抓取头部、pcapng、地址/端口/进程归属和会话路径可能含敏感数据；脱敏后仍需人工检查，不能承诺绝对匿名。

## 当前实现的审计陷阱与验收反例

以下依据本基准源码复核；宿主构造用例与真机 BPF/设备运行必须分开报告。

1. **SEQ_GAP 不等于丢包或 ringbuf 丢事件**：[BPF `next_cpu_seq()`](../../bpf/probe_core.bpf.c) 以 `cpu & (PKT_MAX_CPUS - 1)` 索引，[共享头](../../include/pktpath_bpf.h) 的 `PKT_MAX_CPUS=16`；Go/Python 消费者却按真实 `(producer_type,cpu)` 分流。CPU0/16 共用计数槽时，全部收到的 `CPU0:1, CPU16:2, CPU0:3` 会使 CPU0 的消费者报缺 1；CPU0/1 独立的 `1,1,2` 是无缺口对照。需有同模16的 CPU 都实际发射事件才触发，不能只看机器 CPU 数。本结论的可复现证据是宿主源函数/消费者反例，不是 >16 CPU 真机、嵌入字节码或 Android 验证。告警只能描述序号不连续/证据待复核，不能直接断言丢包数量或原因。
2. **dict site 等级不是时间线统一等级**：[recorder 的 dict writer](../../device/recorder.c) 将 site 元数据等级写成 1，但转码仍保留事件等级，[Go views](../../studio/pkg/reconstruct/views.go) 也可产生 2 级派生边界、3 级注解与 4 级缺口。验收时分别检查 dict、事件头、重建卡片；不要把全部 dict=1 推成“所有事件都是直接证据”，也不能反向声称派生等级完全未实现。
3. **`tgid_fallback` 并非全链路失效**：[recorder 转码](../../device/recorder.c) 在没有非零 owner TGID 且有效插件值存在时，可将 fallback role 转为 TGID TLV，而不作为普通 plugin tag 输出。有效值 4242 / owner=99 / 插件无效三组应分别检查补值、owner 优先、不补值。当前源码的 raw helper 忽略 `tgid_io`、不按 role 填充 `plugin_tgid`，而 `--tgid` admission 不读取 fallback 字段值/role；因此这个 fallback 是用户态落盘行为，不是内核 `--tgid` admission 的输入。这是源码合同核对，不是本次复跑 fallback 夹具；真实漏采仍需可达的过滤/归属集成用例，不得拿受控 owner fixture 直接声称真机漏采。
4. **scope 是请求条件，不是覆盖凭证**：[RX 检查](../../device/recorder.c) 对 `rx-sock` 无 allow-partial 拒绝，允许时设 partial；不能仅凭 manifest 的 scope 推断 RX sites 已挂接。`fwd` 确将 `filter_netns` 设为 0，不能泛称所有 scope 无效。应检查实际 adapters/sites、partial 和加载/挂接结果；一次更早的 BTF 失败不能证明 scope 分支已经执行。

5. **队列0有效，但来源不明的0不是队列身份证明**：[QSTATE 发射逻辑](../../bpf/probe_core.bpf.c) 先置 `txq=0`；非零 BTF offset 下仍可能读失败、base=0、指针范围不符而保留0，成功推导 `diff=0` 也为真实队列0。[QSTATE ABI](../../include/pktpath_bpf.h)、[recorder 转码](../../device/recorder.c) 与 [QStateSpan](../../studio/pkg/reconstruct/views.go) 当前未携带逐事件读取成功/失败来源位。非零 offset、DIRECT、字段存在或由 txq 推导的 queue_gen，都不能代替成功证据。来源不明时，0=0不能确认同队列，0!=1也不能确定排除关联；只能作为同设备时间候选，甚至 STOP/WAKE 的窗口配对本身也需复核。若两侧身份均有可靠来源，则真实队列0应保留，已知不同队列不应匹配。外部权威单硬件TX队列证明可作契约推导，但当前 schema 没有这条通路，不能用“只看到一个事件/qdisc”冒充证明。
6. **严重性与证据可信度分开**：`warn` 可表示需要优先复核，不意味着高可信已证明丢失；[Insight 类型](../../studio/pkg/kernel/types.go) 没有独立 confidence/source 字段时，应在已有 summary/metric 中明确来源和不确定性。SEQ_GAP 汇总、RB_DROP_DELTA 等各自报告，不能据计数确定同一缺口的 ringbuf 原因或换算丢包数量。合成 valid 标记和新插件 fixtures 只能测试假设算法，不会补回生产 wire 已丢失的来源，也不构成运行时集成验证。

开发者应保留上述最小反例和对照，按当前源码重跑；如实现发生修正，应更新本文限制和对应回归，而非永久假定缺陷存在。

## 改动影响检查

| 改动 | 必须联查 |
| --- | --- |
| BPF 事件 / map ABI | `include/pktpath_bpf.h`、`bpf/probe_core.bpf.c`、`device/recorder.c`、双架构 generated headers |
| wire / TLV | `include/pktpath_wire.h`、Python/Go wire 与重建、导出/脱敏、构造会话测试 |
| 队列适配器 / 插件标签 | C loader、BTF 解析、探针模板、manifest 准入、16 个插件值 TLV、Go/Python 展示 |
| 分析结论 / 指标 | 重建原始证据、完整性、统计分母、CLI 与 Studio 各自测试；性能主张需要独立基准 |

不要依赖源码注释中的 `详细设计.md`：本基准树没有该文件。可执行事实应回到上述源码和测试。
