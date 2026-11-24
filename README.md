# pktpath & PktPath Studio

`pktpath` is an evidence-centric, zero-intrusion single-packet path tracing framework for **Linux** and **Android arm64** kernels (`>= 5.10`, tested on GKI `6.1`–`6.12`).

It traces individual packets through the Linux egress/TC/qdisc/driver pipeline (such as `HTB -> fq_codel / pfifo / sfq -> ndo_start_xmit`), builds exact multi-branch SKB object DAGs (`clone`, `copy`, `requeue`, `txq STOP/WAKE`), measures per-queue sojourn latency, exports Wireshark `.pcapng` traces, and supports **declarative runtime JSON plugins** for custom `struct sock` fields and out-of-tree TC qdiscs without recompiling eBPF.

---

## PktPath Studio (Windows Desktop Workbench)

**PktPath Studio** (`bin/pktpath-studio.exe`) is a single-file Windows GUI workbench (`CGO_ENABLED=0`, `PE Subsystem = Windows GUI`, **zero black console window flash**) supporting **Android (ADB)**, **remote Linux hosts (SSH, `x86_64` & `arm64`)**, and **offline session analysis**. It embeds:

- `pktpath-android-arm64` & `pktpath-linux-x86_64` (multi-arch eBPF collectors, auto-matched by remote `uname -m` & SHA-256 verified)
- Offline high-DPI Web UI with a built-in **Plugin Manager & Capability Inspector** (import `.json` plugins with pre-load capability preview, per-plugin enable/disable toggles, and live kernel BTF/symbol match status)
- Pure-Go offline reconstruction engine, `.pcapng` exporter, and privacy redactor

### System ADB Requirement (No Bundled `adb.exe`)

PktPath Studio does **not** bundle `adb.exe` or USB DLLs. It discovers your system `adb` automatically in order:

1. `--adb <path>` CLI flag
2. `PKTPATH_ADB` environment variable
3. `adb.exe` on `PATH`
4. `adb.exe` next to `pktpath-studio.exe`
5. `ANDROID_SDK_ROOT` / `ANDROID_HOME` / `%LOCALAPPDATA%\Android\Sdk\platform-tools` / `C:\platform-tools\adb.exe`

Every `adb` invocation runs with `CREATE_NO_WINDOW` (`0x08000000`) + `HideWindow = true`, so Windows never flashes a console window. Even if `adb` is not installed, Studio still opens offline historical sessions normally.

### Quick Start

```powershell
# Launch PktPath Studio (opens default browser, zero console window)
.\bin\pktpath-studio.exe

# Optional flags
.\bin\pktpath-studio.exe --window                          # Native Win32 WebView2 window
.\bin\pktpath-studio.exe --adb C:\platform-tools\adb.exe   # Explicit system adb path
.\bin\pktpath-studio.exe --plugin-dir D:\my-plugins        # Custom runtime JSON plugins directory
.\bin\pktpath-studio.exe --headless --port 18080           # Headless localhost HTTP API
.\bin\pktpath-studio.exe --selftest --dev wlan0            # Automated runtime + device E2E check
```

---

## Runtime Plugin Architecture

The core codebase is **100% pure upstream Linux**. To extract extra `struct sock` fields (resolved dynamically via `/sys/kernel/btf/vmlinux`) or hook custom/out-of-tree TC qdiscs without touching C/BPF source:

- Drop `.json` manifests into `%LOCALAPPDATA%\PktPathStudio\plugins\` (or pass `--plugin <file.json>` / `--plugin-dir <dir>` on the device CLI).
- See [plugins/README.md](plugins/README.md) and [plugins/examples/](plugins/examples/) for the schema and runnable examples (`sock_mark_example.json`, `custom_qdisc_example.json`).

---

## Repository Layout

```
pktpath/
├── include/
│   ├── pktpath_wire.h         # Wire format v1.0 (.pktb blocks, TLV tags 0x0320..0x0323)
│   └── pktpath_bpf.h          # Shared BPF/userspace ABI + generic plugin slot structs
├── bpf/
│   └── probe_core.bpf.c       # eBPF probes (TC/qdisc, HTB, fq_codel, pfifo, sfq, dynamic plugin slots)
├── device/
│   ├── main.c                 # Device CLI: inspect, record (--plugin / --plugin-dir)
│   ├── recorder.c             # BPF loader, kprobe/tracepoint/ringbuf controller & dynamic plugin binder
│   ├── plugin_loader.c        # Zero-dependency C11 JSON plugin loader + BTF field resolver
│   ├── btf_parse.c            # Pure-C /sys/kernel/btf/vmlinux parser
│   ├── tc_topo.c              # Netlink RTM_GETQDISC / RTM_GETTCLASS topology dumper
│   └── ...                    # Ring buffer, block storage, budget & trigger engines
├── analyzer/                  # Python offline analyzer (reconstruct, stats, show, export_pcapng, redact)
├── studio/                    # Go Windows workbench (pkg/adb, pkg/wire, pkg/reconstruct, pkg/server, web/)
├── plugins/                   # Runtime Plugin SDK docs & pure upstream Linux JSON examples
├── scripts/                   # Reproducible build scripts (build_bpf.py, build_device.py)
├── pktpath.py                 # Host Python CLI entrypoint
├── LICENSE                    # Apache-2.0 (userspace/host) + Dual BSD/GPL (bpf/)
└── README.md
```

---

## Build Instructions

### Prerequisites

- **eBPF**: `clang` (`>= 15`, BPF target `bpfel`)
- **Device arm64 binary**: Android NDK (`aarch64-linux-android28-clang`) or `aarch64-linux-gnu-gcc`
- **Host CLI**: Python `>= 3.10` (standard library only)
- **PktPath Studio (Windows)**: Go `>= 1.22` (`CGO_ENABLED=0`)

### 1. Build eBPF Object (`bpf/probe_core.bpf.o` + embedded C header)

```powershell
python scripts/build_bpf.py
```

### 2. Build Android arm64 Device Collector (`bin/pktpath-android-arm64`)

```powershell
python scripts/build_device.py
```

### 3. Build PktPath Studio (`bin/pktpath-studio.exe`)

```powershell
python studio/scripts/build_studio.py
```

This embeds `bin/pktpath-android-arm64` and `studio/web/*` (no `adb.exe`), compiles with `-ldflags="-H=windowsgui -s -w"`, and verifies `PE Subsystem = 2 (IMAGE_SUBSYSTEM_WINDOWS_GUI)`.

---

## Device CLI Usage

```bash
# 1. Inspect interface TC qdisc/class topology, adapters, and optional runtime plugins
/data/local/tmp/pktpath inspect --dev wlan0 --json
/data/local/tmp/pktpath inspect --dev wlan0 --plugin-dir /data/local/tmp/plugins --json

# 2. Short-window capture (oneshot)
/data/local/tmp/pktpath record \
  --mode oneshot --dev wlan0 --scope tc-egress \
  --sample 1/1 --duration 10s --capture-hdr 96 \
  --out /data/local/tmp/pktpath_run

# 3. Always-on flight recorder (daemon, zero disk I/O until sojourn threshold triggers)
/data/local/tmp/pktpath record \
  --mode daemon --dev wlan0 --scope tc-egress \
  --sample 1/100 --trigger sojourn_us>20000 \
  --pre-window 5s --post-window 2s \
  --out /data/local/tmp/pktpath_daemon
```

Key flags:
- `--plugin <file.json>` (repeatable) / `--plugin-dir <dir>`: Load runtime JSON plugins for `struct sock` BTF fields and custom qdiscs.
- `--uid <uid>`, `--tgid <pid>`, `--proto tcp|udp|icmp|icmpv6`, `--src-ip`, `--dst-ip`, `--src-port`, `--dst-port`, `--mark <val[/mask]>`: In-kernel eBPF filter.
- `--profile default|sendmsg`: `sendmsg` enables exact `tcp_sendmsg`/`udp_sendmsg` TID and socket-create timestamp capture.
- `--capture-hdr <0..128>`: Embed packet headers for Wireshark `.pcapng` export.

---

## Host Python Analyzer CLI

```bash
# Single-packet multi-branch timeline with evidence levels and plugin tags
python pktpath.py show ./pktpath_run --sample-id 1 --evidence

# Aggregate latency & path statistics
python pktpath.py stats ./pktpath_run --group-by path

# Export Wireshark .pcapng (optional --redact for deterministic IP/port/UID anonymization)
python pktpath.py export ./pktpath_run --format pcapng --out trace.pcapng
python pktpath.py export ./pktpath_run --format pcapng --redact --out trace_redacted.pcapng

# Redact an entire session directory in-place to a new directory
python pktpath.py redact ./pktpath_run --out ./pktpath_run_redacted
```

---

## License

- Host tools, device userspace controller, and PktPath Studio: **Apache License 2.0** (see [LICENSE](LICENSE)).
- eBPF kernel probes (`bpf/`): **Dual BSD/GPL**.
