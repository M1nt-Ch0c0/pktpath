# 插件：设备 runtime JSON 与 Studio bundle 是两层契约

[文档目录](index.md) · [现有 SDK 与示例](../../plugins/README.md)

**最重要的规则：不要把包含 `kernel_extensions` 的 Studio `manifest.json` 直接传给设备 `pktpath --plugin`。C loader 只识别顶层 `sock_fields` / `qdiscs`；未知嵌套内容会被跳过，可能显示已载入一个插件却贡献 0 个字段/队列，而不是明确报错。**

## 第一层：设备扁平 runtime JSON

消费者：[device/plugin_loader.c](../../device/plugin_loader.c) 的 `load_one_plugin_file()` / `plugin_registry_load()`；参数见 [device/main.c](../../device/main.c)。Python 离线 analyzer 读取已经采集的 wire 数据，不是另一个 Studio bundle 安装器。

[最小字段示例](../../plugins/examples/sock_mark_example.json) 与 [qdisc 示例](../../plugins/examples/custom_qdisc_example.json) 是设备可直接加载的扁平文件，例如：

```json
{
  "id": "example.sock-mark",
  "name": "Socket mark",
  "sock_fields": [
    {"struct": "sock", "field": "sk_mark", "size": 4, "role": "tag", "label": "mark"}
  ]
}
```

| 项目 | 当前源码行为 / 开发约束 |
| --- | --- |
| 顶层 | `id`、`name`、`sock_fields[]`、`qdiscs[]`；其它 key 跳过；不能依赖严格 schema 拒绝拼错字段 |
| socket 字段 | `struct` 默认 `sock`，`field` 必须非空才加入；`size` 合法值 1/2/4/8，不合法 C 值回退为 8；未知 role 回退 tag。开发者应主动提供合法值，而非利用宽松解析 |
| 字段解析 | 目标 `/sys/kernel/btf/vmlinux` 解析字段 offset；解析失败或 offset 为 0 时不启用并保留 warning；非零 offset 也只证明定位，不证明每次内核读取成功，不因 JSON 合法就保证能采到 |
| qdisc | `id/name/kind/mode/enqueue_sym/dequeue_sym`；缺 kind 或 enqueue 时不加入；C 只有精确 `leaf` 视作 leaf，其它值视为 classful；leaf 缺 dequeue 报错。必须显式使用 `leaf` 或 `classful` |
| 上限 | [device_common.h](../../device/device_common.h)：32 个插件路径、全局 16 个 socket 字段、全局 32 个 qdisc（不是每包各 32）；单文件最大 256 KiB |
| 加载顺序 | 显式 `--plugin` 先加入，再扫描 `--plugin-dir` 的 `.json`（文件名排序）；需避免 ID/内容重复和跨插件容量冲突 |

设备采集器在已有 BPF 模板上动态克隆并 patch site_id，不是任意 BPF 代码运行平台。qdisc 符号和函数参数语义必须与模板契约匹配，新增符号名字本身不能证明适配正确。BTF `struct` 虽可配置，读取的基址仍应结合 BPF socket 逻辑审查，不能宣传可安全读取任意无关结构。

扩展值通过 `include/pktpath_bpf.h` 进入事件，再由 [wire TLV](../../include/pktpath_wire.h) 的 `0x0320..0x032F` 共 16 个值槽表达；Python/Go 解码、展示和脱敏需同步关注。

## 第二层：Studio 外部包

权威定义：[ExternalManifest / 解析及 hook](../../studio/pkg/kernel/external.go)、[扩展 payload 类型](../../studio/pkg/kernel/types.go)、[配置 schema](../../studio/pkg/kernel/schema.go)。支持目录、含 `manifest.json` 的 `.zip` / `.pktplugin`、独立 `.json`。安装器还兼容顶层旧扁平字段，不能反推设备也兼容新 bundle。

| 字段 | Studio 解释 |
| --- | --- |
| `id/name/version/author/description/category/tags/requires` | 包元数据/依赖；ID 会 sanitize，`builtin.` 前缀会改为 `ext.`，缺 name/version 有默认值；前缀不是安全边界 |
| `kernel_extensions` | 嵌套 `sock_fields` / `qdiscs`，也可和旧顶层字段合并；为 `kernel.ext` 注册声明，不是 BPF 已加载证明 |
| `entrypoint.command` | 字符串数组，由主机创建子进程，不经 shell 拼接；相对可执行文件/现存相对参数以 bundle 路径解析，工作目录为 bundle |
| `analyzers[]` | `id/name/description/priority`；有 entrypoint 才注册实际 hook |
| `exporters[]` | `id/name/button_label/icon/description/default_ext/file_filter/is_directory/priority`；有 entrypoint 才注册实际 hook |
| `ui_slots[]` | `id/slot/title/script/style/order`，加载 JS/CSS；内置 UI 使用 `canvas.banner`、`workbench.toolbar`、`sample.extra`、`sidebar.extra` |
| `config_schema` | `fields[]` 的 key/label/type/default/required/min/max/options/item_fields 等，自动表单；支持 string/number/boolean/select/path/file/dir/list，不是通用 JSON Schema |

**校验差异不能隐去**：Go preview 对不合法 size / mode 会给 warning，其能力说明不等于设备执行结果；C 的 size/mode 回退行为不同。请在插件侧严格检查，并测试最终物化的 JSON，而非只测试 preview。未被 schema 声明的配置项可能在规范化时被去掉；有 list/item_fields 时需按嵌套字段提供数据。

### Hook 输入输出

分析 action `analyze` 的 stdin 是一个 JSON 对象：`plugin_id`、`analyzer_id`、`config`、`session_id`、`session_dir`、`overview`；输出对应 `AnalyzeOutput`：`insights[]`、`kpis[]`、`notes[]`，超时 15 秒。

导出 action `export` 额外使用 `exporter_id`、`out_path`、`params`（代替 analyzer_id）；输出对应 `ExportOutput`：`ok`、`out_path`、`is_directory`、`summary`、`details`，超时 60 秒。空 out_path 会回填请求路径。完整类型以 `types.go` 为准。

**overview 不等于 detail**：[SessionOverview / SampleRow / SampleSummary](../../studio/pkg/reconstruct/views.go) 的结构不同。当前 hook 不自动接收每个 SampleDetail 的 plugin_tags、mark、qstates 或 branches；`sample.extra` 插槽名也不意味着回调含完整 detail。验收反例：detail 的 `sock_mark=4660`，overview 没提供对应字段时，应输出 unknown/未读取，不能默认为 0 或“未打标”。需要深读时显式使用 session_dir 解码会话并处理版本/资源/隐私边界，或声明不支持，不假装 overview 拥有所需证据。

stdout 必须是可整体解析的 JSON，调试日志走 stderr；非零退出会成为 hook 错误。[hello 示例](../../plugins/examples/hello-ext-bundle/hook.py) 和 [manifest](../../plugins/examples/hello-ext-bundle/manifest.json) 是可测试的起点，解释器名应按实际主机安装选择，不能宣称它在 Android 自动运行。

### 两层桥接

[kernel.go](../../studio/pkg/kernel/kernel.go) 的 `MaterializeKernelPluginFiles()` 把**已激活**的 `kernel.ext` 写成 `<app-dir>/.staged_kernel_plugins/` 下的扁平 `id/name/description/sock_fields/qdiscs` JSON。[capture.go](../../studio/pkg/server/capture.go) 在启用采集请求 `EnablePlugins` 时取得物化文件，经 ADB/SSH 同步到设备插件目录。禁用插件后应重新物化/采集确认它不再贡献内容，不能检查旧的 staged 文件就宣称仍激活。

[嵌套 kernel-ext-bundle 示例](../../plugins/examples/kernel-ext-bundle/manifest.json) 不能跳过这一步直接作为设备扩展使用。未来独立插件仓库宜分别提供 Studio bundle 和 device-flat.json，但本次不创建、不发布独立仓库。

## 测试与安全检查单

```sh
python3 -m unittest tests.test_example_plugins -v
(cd studio && go test ./pkg/kernel ./pkg/plugins ./pkg/server)
```

设备入口验收必须检查数量：官方嵌套 kernel-ext-bundle 直接经 C loader 可 exit 0 且字段/队列为 0/0；将**同一内容**提升为顶层后应得到 1/3（宿主 NULL BTF harness 只验证解析数量，字段未解析启用，不是内核成功）。不以进程 exit 0 代替加载数、resolved 和 adapter/site 检查。

Go `TestExternalZipBundleLifecycleAndSecurity` 检查安装生命周期、物化及 ZipSlip 拒绝；`TestKernelExtBuilderMultiQdisc` 检查多队列声明。它们不验证真实内核上函数签名和挂接效果。新增插件还应测无效字段、容量超限、重复贡献、禁用/卸载、hook 非 JSON/超时/非零退出与 UI 资源缺失。

**外部 hook 和 UI 是可信代码扩展，不是沙箱。** hook 以 Studio 用户权限运行，JS 在工作台上下文执行；能力预览、ZipSlip 检查、单文件复制限额（32 MiB）都不是签名、隔离或安全认证。不安装/执行不可信包，不把本地 API 暴露给公网。私有插件放仓库外或已忽略的 `plugins/local/`，不要提交会话、密钥或内部流量。
