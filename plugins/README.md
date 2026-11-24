# PktPath Studio v2.0 Plugin SDK

PktPath Studio v2.0 runs on a Cordis-inspired **"Everything is a Plugin"** microkernel. The core repository is **100% pure upstream Linux**. Both built-in capabilities and external third-party packages extend the workbench through the same open-ended extension points — with **zero C/BPF or Go recompilation**.

Keep private or internal plugins outside this repository (or under `plugins/local/`, which is `.gitignore`d).

---

## 1. Visual Configuration (No JSON Required)

For `struct sock` BTF fields and custom TC qdiscs, end users do **not** need to write JSON files:
1. Open **🧩 插件中心** in PktPath Studio.
2. Select **🧬 内核 BTF 与自定义队列可视化构建器** (`builtin.collector.kernel-ext`).
3. Click **「＋ 新增 Socket 字段」** or **「＋ 新增自定义队列」** and click **「💾 保存并热生效」**.

Under the hood, the device collector dynamically clones compiled BPF probe templates at runtime (patching `site_id` immediates before `BPF_PROG_LOAD`), supporting up to **32 concurrent custom qdiscs** and **16 concurrent BTF-resolved `struct sock` fields**.

---

## 2. External Plugin Bundle Format (`.pktplugin` / `.zip` / Folder / `.json`)

An external plugin bundle is either a folder or a `.zip` / `.pktplugin` archive containing `manifest.json` (plus optional scripts and UI assets):

```text
my-plugin/
├── manifest.json          # Required: identity, config_schema, capabilities & hooks
├── hook.py                # Optional: out-of-process JSON-over-stdio entrypoint
└── ui/
    ├── widget.js          # Optional: calls window.PktPathUI.registerSlot(id, renderFn)
    └── widget.css         # Optional: scoped styles
```

> Legacy single-file kernel extension `.json` manifests (with top-level `sock_fields` and/or `qdiscs`) are also supported and auto-wrapped on install.

### `manifest.json` Capabilities

Any external bundle can combine **all four** extension modes:

| Section | Extension Point | Description |
|---|---|---|
| `kernel_extensions` | `kernel.ext` | Declares `sock_fields[]` (BTF offset resolved at runtime, width `1/2/4/8`, role `tag` or `tgid_fallback`) and `qdiscs[]` (`mode: "classful"` or `"leaf"`, dynamically cloned BPF templates). |
| `entrypoint` + `analyzers[]` | `analyzer` | Runs out-of-process with `HideConsole` (zero console flash) on session load. Receives `{"action":"analyze","config":...,"overview":...}` on `stdin` and returns `{"insights":[...],"kpis":[...]}` on `stdout`. |
| `entrypoint` + `exporters[]` | `exporter` | Registers a custom export button in the Workbench toolbar. Receives `{"action":"export","out_path":...,"config":...,"overview":...}` on `stdin` and returns `{"ok":true,"out_path":...,"summary":...}`. |
| `ui_slots[]` | `ui.slot` | Mounts `script` / `style` into named Workbench slots (`canvas.banner`, `workbench.toolbar`, `sample.extra`, `sidebar.extra`) via `window.PktPathUI.registerSlot(slotId, (container, ctx) => ...)`. |
| `config_schema` | Visual Form | Schemastery-style typed fields (`string`, `number`, `boolean`, `select`, `file`, `dir`, `list`) rendered automatically in Plugin Center and persisted to `plugins_config.json`. |

---

## 3. Runnable Examples

- [examples/hello-ext-bundle/](examples/hello-ext-bundle/): Full-featured SLA Auditor bundle demonstrating **Visual Config Schema + External Analyzer + Custom Markdown Exporter + Live `canvas.banner` UI Slot Widget** in one installable bundle.
- [examples/kernel-ext-bundle/](examples/kernel-ext-bundle/): Multi-qdisc dynamic kernel extension bundle hooking **3 concurrent custom leaf qdiscs (`netem`, `tbf`, `fq`)** + `struct sock.sk_mark` simultaneously.
- [examples/sock_mark_example.json](examples/sock_mark_example.json) & [examples/custom_qdisc_example.json](examples/custom_qdisc_example.json): Minimal single-file declarative examples.
