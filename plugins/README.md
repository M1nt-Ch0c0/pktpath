# PktPath Runtime Plugin SDK

`pktpath` ships a **100% pure upstream Linux** core (BPF probes, device recorder, Python analyzer, and PktPath Studio). Any kernel-specific `struct sock` extension fields or out-of-tree TC qdiscs can be attached at **runtime via declarative JSON manifests** — with **zero C/BPF recompilation**.

Keep private or internal plugin manifests outside this repository (or under `plugins/local/`, which is `.gitignore`d).

## Where to Place Plugins

| Runtime Mode | Plugin Location |
|---|---|
| **PktPath Studio (Windows)** | `%LOCALAPPDATA%\PktPathStudio\plugins\*.json` (click **「📂 打开插件目录」** in Advanced Filter, or pass `--plugin-dir <dir>`) |
| **Device CLI (`pktpath-android-arm64`)** | `--plugin <file.json>` (repeatable, up to 8 files) or `--plugin-dir <dir>` |

PktPath Studio automatically syncs local `*.json` manifests to `/data/local/tmp/.pktpath_studio/plugins/` before `inspect` and `record`.

---

## Manifest Schema

Each `.json` file describes optional `sock_fields` and/or `qdiscs`:

```json
{
  "name": "My Kernel Extensions",
  "version": "1.0",
  "description": "Optional runtime socket field tags and custom qdisc probes",
  "sock_fields": [
    {
      "struct": "sock",
      "field": "sk_mark",
      "size": 4,
      "role": "tag",
      "label": "sock_mark"
    }
  ],
  "qdiscs": [
    {
      "id": "my_leaf",
      "name": "My Leaf Qdisc Adapter",
      "kind": "my_leaf",
      "mode": "leaf",
      "enqueue_sym": "my_leaf_enqueue",
      "dequeue_sym": "my_leaf_dequeue"
    }
  ]
}
```

### 1. `sock_fields[]` (up to 4 slots across all loaded plugins)

Every entry is resolved dynamically against `/sys/kernel/btf/vmlinux` at startup (`btf_resolve_field`):

| Field | Type | Description |
|---|---|---|
| `struct` | string | Kernel struct name (currently `"sock"`). |
| `field` | string | Exact member name inside `struct sock` (e.g. `"sk_mark"`, `"sk_priority"`, or a custom kernel field). If absent in the device's vmlinux BTF, the slot is safely skipped. |
| `size` | integer | Field width in bytes (`1`, `2`, `4`, or `8`). |
| `role` | string | `"tag"`: recorded into wire TLV `0x0320..0x0323` (`plugin_tags[label]` in Studio & `[label=val]` in `pktpath.py show`). `"tgid_fallback"`: used as fallback `tgid` when standard socket attribution has `tgid == 0`. |
| `label` | string | Human-readable display key written into `dict.json` (`plugin_fields[]`). |

### 2. `qdiscs[]` (up to 2 `classful` + 2 `leaf` slots across all loaded plugins)

Every entry binds pre-compiled generic BPF kprobe/kretprobe slots to the target kernel symbols at runtime:

| Field | Type | Description |
|---|---|---|
| `id` | string | Short unique identifier (`[a-z0-9_-]+`). Exposed as adapter `plugin_qdisc_<id>`. |
| `name` | string | Display name shown in `inspect` and Studio's topology card. |
| `kind` | string | TC qdisc kind name as reported by netlink (`tc qdisc show`), e.g. `"cake"`, `"codel"`, or a custom out-of-tree qdisc kind. |
| `mode` | string | `"classful"` (tracks `enqueue_sym` classification/entry) or `"leaf"` (tracks `enqueue_sym` entry+return and `dequeue_sym` entry+return to measure exact per-packet sojourn latency). |
| `enqueue_sym` | string | Kernel function name for `Qdisc_ops.enqueue(skb, sch, to_free)`. |
| `dequeue_sym` | string | Kernel function name for `Qdisc_ops.dequeue(sch)` (required for `"leaf"`). |

## Examples

- [sock_mark_example.json](examples/sock_mark_example.json): Reads standard Linux `struct sock.sk_mark` via BTF and attaches it as a `sock_mark` tag on every traced packet.
- [custom_qdisc_example.json](examples/custom_qdisc_example.json): Template showing how to bind an out-of-tree or additional Linux qdisc (`classful` / `leaf`) at runtime.
