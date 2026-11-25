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

## F03.0 opt-in metadata configuration compensation

Only with `--cordis-plugin-host=... --cordis-config-transactions` (and explicit
external Node). No plugin host means the original Go path, no Node probe, no
transaction claim. Core3/lock/runtime are unchanged. F02 without the new switch
retains its earlier nontransactional configuration semantics.

This is an activate-then-save protocol, not an atomic transaction over arbitrary
plugin side effects. It requires an enabled, proven-live metadata baseline A.
A successful request means a fresh B generation and its file bytes were both
confirmed. Failure attempts exactly one *new-generation* A activation plus exact
original file bytes/absence restoration, and still returns an error. Failed or
uncertain compensation is `recovery-required`, not a relabelled old revision;
ordinary config/Reset/reload cannot wash it away. Reset means schema defaults,
not restore-previous. Unknown old/request config keys and unsupported envelopes
are rejected rather than silently calling them migrated; F03.1 is incomplete.

`config_operations` identifies every admitted operation and reports requested /
rollback / current desired / real live scope configuration and generation,
last-successful configuration/generation/revision, observed disk hash, separate
activation/disk/compensation errors, and terminal outcome. Effective revision is
still historical, never proof that A is alive. New intent can supersede a waiting
operation; stale activation, compensation, and disk restore cannot overwrite C.
A dedicated file fence serializes narrow write/restore phases against intent
admission; lifecycle mutex is not held for filesystem work, Apply or cleanup.
Other whole-file writers advance a disk epoch; old whole-file rollback is then
refused. External byte changes also fail closed. Pending file compensation or
recovery-required refuses ordinary config admission.

Caller cancellation before admission has no activation/file effects; cancellation
after admission ends caller observation only, with operation ID to query. A caller
queued behind filesystem admission cannot forcibly interrupt the OS file operation.
An unknown Node ACK never causes a second B or an automatic Go fallback.
Temporary writes check short writes, Sync/Close/Rename, then directory Sync; raw
A bytes and permissions are retained in memory. **No durable journal, restart
reconciliation, arbitrary filesystem timeout, power-loss atomicity, general plugin
rollback, cross-process writer protection, or Windows execution acceptance.**
Only controlled four metadata plugins/synthetic faults are covered. Actual
capture ownership, C/rebuild/transport and Go default remain unchanged.


## F03.1a: known-schema compatibility admission (local candidate)

The existing explicit F03 switch now checks the Studio configuration BEFORE
Kernel discovery/Apply and BEFORE spawning Node. Existing file version 2, legacy
missing-version, missing-file and documented null/default forms remain supported.
Known managed plugin config keys/types must validate. ConfigSchema has no schema
version API: any managed entry `schemaVersion` is rejected, NOT assumed to be 1
or Cordis major 3. No migration, version stamp or backup is written.

Bad/uninterpretable input makes this experimental Kernel startup fail closed;
HTTP state still exposes `config_compatibility` with scope, reason, source and a
zoned observation time/hash. Normal config/toggle/reset/reload admission and the
single normal file writer check the same known schema. F03 transactions validate
their own captured image too. Quarantine is sticky in-process; ordinary Reset or
editing the file does not silently clear it. Running A is not automatically killed
if incompatibility is discovered later; actual runtime state stays separate.

This is **known-managed-schema/file-version admission only**, not arbitrary
configuration compatibility. Opaque envelope/entry fields are accepted without
interpretation and unchanged by startup; general legacy whole-file writer opaque
roundtrip is NOT solved by this slice. No orphan-entry/uninstall policy is changed.
No field transformation, downgrade/backup restore, persistent journal, crash
transaction recovery, cross-process file locking or arbitrary plugin rollback.
A startup format check does NOT restore a lost F03.0 operation after restart or
persist `recovery-required`. F04 package mutations/legacy plugin APIs are outside
this admission slice. Default Go and F02 without F03 switch retain prior behavior.

### F03.1a v2: managed object-merge representations

The v1 candidate was rejected: Go's struct/map decoder can merge repeated
`plugins`/managed `config` objects while the RawMessage checker kept only the
last object. The shared image guard now preserves decoded member occurrences:
multiple root `plugins` members are unsupported if any contains a managed ID;
multiple `config` members in an effective managed entry are unsupported, even
if equal/null. This is explicit rejection before effects, not a new last-wins
consumer or a file migration. JSON-escaped keys count after decoding; case-fold
alias rejection remains in place.

This is not a blanket duplicate-key ban: opaque root/entry/deep values, foreign-
only repeated `plugins`, duplicate plugin IDs (map-value replacement), and
ordinary scalar/list config keys (legacy last-value) retain their scoped prior
semantics and have positive tests. The guard is shared by startup, ordinary
controls/writer and the exact transaction capture; an early public check alone
is insufficient. Valid opaque preservation by all later writers, migrations,
backup/downgrade, journal/restart recovery and Windows execution remain outside
this slice.
