# Cordis3 离线 analyzer 宿主（F01 candidate）

**默认关闭；开发候选，不是发行完成或全量迁移。** 只用 Cordis `@cordisjs/core@3.18.1`（锁文件同时固定 cosmokit 1.8.1）。本轮实际运行 Node24.22.1 / Linux x86_64；候选自身要求 Node>=22，不把该要求冒充 core 的 engines 声明。Windows GUI、安装包、真机及性能未验收。

## 边界

- Cordis插件用 required service 与 effect 注册 analyzer ID；Go仍持任务账本、配置writer和唯一原stdio runner。内建Go analyzers、exporter、UI/kernel扩展以及采集/重建/设备层不因此迁走。
- Node只收控制元数据；原外部 analyzer 的请求/响应JSON由Go传递及解析，overview与sample_ids不经JS Number或重编码，manifest/stdio协议不变。
- 一次显式调用只能执行原runner一次。初始化/ACK/断连失败均不静默fallback；回旧路是关闭候选后的一次**新调用**，不是重跑未知旧任务。
- host incarnation、activation generation（同配置reload也变化）、config snapshot digest、manifest/path package identity、session/analyzer/task ID独立记录。package identity不是全目录内容签名。
- disable/reload撤新入口；已接单的Go hook按原快照继续，caller取消/15秒timeout仍生效。迟到旧代输出保留在Go内存历史，不进入新代聚合。Go `Tasks()`可读历史body；现有`GET /api/kernel/state`仅加可选诊断元数据，不把历史body重新灌进浏览器。历史非持久审计，空闲时最多保留256条；无需把API打开成功称UI验收。
- Cordis3不await异步dispose。本宿主另外跟踪Go在途、Node cleanup promises、drain ACK与Node进程退出。drain失败/超时必须返回/记录，不称clean。

## 启动（仅说明，不是安装器）

在本目录明确执行 `npm ci --ignore-scripts --no-audit --no-fund`，正常应用启动**不运行npm、不下载依赖**。Node为候选外置runtime，未决定内置/旁置发行。所有包与Node路径均为可信可执行代码，scope不是沙箱。

通过应用新增CLI选项显式指定：

```text
pktpath-studio --cordis-analyzer-host <absolute-path>/host.mjs --cordis-analyzer-node <absolute-path-to-node>
```

`--cordis-analyzer-host`为空即旧Go路径：不探测Node，不创建Cordis loader文件，不改配置格式。仅设置Node路径不会启用候选。启用后不可用会进入插件activation error，混合插件整个Apply按既有回滚规则失败；本次先使用analyzer-only无害包，不能据此承诺混合包无损故障隔离。

核实backend：候选接单后`GET /api/kernel/state`的可选`analyzer_host.tasks`含backend、实际Node/core版本、协议、单终态与代次。退出时宿主尝试显式drain，错误进入原Go日志。关闭候选重新启动只让新调用走Go，不改变已运行任务的归属。

## 包租约政策（F01最小保护，不是安装重写）

Go在同一互斥域内取得任务lease或进入mutation；有lease时现有Kernel install/uninstall及legacy import/delete返回busy（HTTP409），mutation中新候选任务立即拒绝；锁不跨hook或文件I/O持有。保护的是**同一个Go宿主**管理的包操作；不能约束另一个进程/用户手工写盘。

本轮无害测试hook不创建子孙进程，lease持续到原`exec.Cmd.Run`观察直接子进程退出。**任意fork/daemon子孙的完整资源保活/退出仍未解决，不承诺任意插件安全卸载。** 子进程拥有宿主权限，包lease不是权限隔离。安装失败自动恢复旧包仍属后续工作，不因busy保护宣称已具备。

## 配置回退的真实限制

仍使用原Go唯一writer。实际测试会展示：B Apply失败后B仍可落盘，再由明确SetConfig(A)恢复A。这不是自动事务回滚；未知字段schema迁移/备份/旧版降级留F03，不称配置事务已修。

## 受控验收入口

```sh
PKTPATH_TEST_CORDIS_HOST="$PWD/cordis-analyzer-host/host.mjs" go test -race -count=1 -timeout=100s ./...
```

从studio目录运行。集成用例只在显式提供该变量时启动Node；默认测试跳过可选Node集成，不能把SKIP称PASS。用例包含原15s timeout；`-short`会跳过它。fixture原始十进制覆盖2^53相邻值/u64max，失败ACK/host退出不重复执行、同ID阻塞重载、资源读两次/真实删除保护、反向mutation状态拒接、单终态、配置显式恢复、Linux中文空格路径。禁止用该命令替代Windows/设备/发行验收。


## F02 v4 cleanup-budget correction (local candidate, not accepted/default)

`CleanupTimeout` is an **observation** bound (default 2s), not proof that Apply
or cleanup finished. `CleanupExecutionTimeout` is an independent bounded budget
(default 2s) for the **whole LIFO hook chain**, freshly started only after the real
Go Apply returned and its cleanup list is sealed. Caller RPC/Close cancellation,
Node death and newer desired intent never erase the old resource cleanup debt.
They still fence recovery/commit. Actual error/panic/execution-budget overrun
is quarantined; Reload cannot bypass it. Returning nil after that execution
budget does not count as success. A successful, timely drain only consumes a
previously eligible dependency recovery ticket once, after existing fences.

Snapshot `cleanup_scopes` reports generation, disposal cause, waiting Apply,
Apply-observation timeout, hooks started/returned, execution timeout, actual
completion observed, cleanup result and resource-slot hold separately. The
current plugin's `cleanup_phase` is cleared on a new activation; old generations
remain identified in the scope ledger. `cleanupDone` closes only after all hooks
actually returned and owner recorded the result. No resource slot is released
just because an observer timed out. Close has a bounded observer and its original
failure result remains historical even if the old cleanup later finishes.

**Not forced cancellation:** arbitrary in-process Go code that never returns
cannot be killed by context. One held obligation/waiter per old scope and the
quarantined slot remain observable; no repeated worker/retry is spawned. Such
a hook needs explicit resource repair or controlled owning-process retirement,
not a successful Reload. This candidate does not claim arbitrary plugin or
descendant safety, eventual reclamation of uncooperative code, or process sandboxing.

**Distribution pairing:** `pktpath.cordis3.lifecycle/2` alone is not a build
compatibility promise. v3 introduced a required per-worker session, not present
in v2. Ship/review the exact candidate Go binary + `host.mjs` + `lifecycle.mjs` +
lockfile from the same fixed source index, never mix by protocol-string equality.
v4 changes the Go cleanup policy/diagnostics; no new capability negotiation or
full mixed-version distribution acceptance is claimed. F01 analyzer/1 is unchanged.
