#!/usr/bin/env python3
"""
Compile bpf/probe_core.bpf.c -> bpf/generated_progs.h (zero target libbpf/compiler).

Validates:
  1. Zero clang warnings/errors (`-Wall -Wextra -Werror`)
  2. Exact map relocation indices matching `enum pkt_map_idx` (0..6)
  3. Zero out-of-line subprog/libc calls (every BPF_CALL targets a kernel helper)
  4. Strict BPF stack usage <= 512 B per program section
"""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT_DIR = Path(__file__).resolve().parent.parent
INC_DIR = ROOT_DIR / "include"
SRC_PATH = ROOT_DIR / "bpf" / "probe_core.bpf.c"
OUT_HDR = ROOT_DIR / "bpf" / "generated_progs.h"

REQUIREMENTS_BUILD_NAME = "requirements-build.txt"
# Fallback when this checkout has no requirements-build.txt (for example an
# older main). Keep in sync with that file when it is present.
PYELFTOOLS_REQUIREMENT = "pyelftools==0.33"


def requirements_build_path() -> Path:
    return ROOT_DIR / REQUIREMENTS_BUILD_NAME


def pinned_pyelftools_requirement(requirements_file):
    if requirements_file is not None and requirements_file.is_file():
        for raw in requirements_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            name = line.split("==")[0].split(">")[0].split("<")[0].split("[")[0].strip()
            if name.lower() == "pyelftools":
                return line
    return PYELFTOOLS_REQUIREMENT


def is_missing_elftools_module(exc: BaseException) -> bool:
    """True only when the pyelftools package itself is not installed.

    Other ImportError values (broken install, missing transitive import,
    "cannot import name") must be left unchanged.
    """
    if not isinstance(exc, ModuleNotFoundError):
        return False
    name = exc.name
    if not name:
        return False
    return name == "elftools" or name.startswith("elftools.")


def format_missing_pyelftools_message(
    *,
    interpreter: str,
    requirements_file,
    windows: bool,
) -> str:
    pin = pinned_pyelftools_requirement(requirements_file)
    req_exists = requirements_file is not None and requirements_file.is_file()
    if windows:
        venv_python = ".venv\\Scripts\\python.exe"
        script_path = "scripts\\build_bpf.py"
        tested_note = (
            "The Windows command shape is shown because this interpreter "
            "reports a Windows platform. These exact commands were not "
            "executed as a tested Windows matrix in this change."
        )
    else:
        venv_python = ".venv/bin/python"
        script_path = "scripts/build_bpf.py"
        tested_note = (
            "A Windows venv on the same interpreter would use "
            ".venv\\Scripts\\python.exe instead of .venv/bin/python. "
            "Those Windows commands were not executed for this change; "
            "do not treat them as a tested Windows matrix."
        )

    lines = [
        "error: pyelftools is not installed for this Python interpreter.",
        f"  interpreter: {interpreter}",
        "",
        "scripts/build_bpf.py needs the PyPI package pyelftools to read compiled BPF ELF objects.",
    ]
    if req_exists:
        req = requirements_file.resolve()
        lines.extend(
            [
                "",
                "This checkout includes the build-dependency file:",
                f"  {req}",
                f"  (declares {pin})",
                "",
                "Create a virtual environment with this same interpreter and install from that file.",
                "Do not use pip to modify a system-managed Python (PEP 668 / externally managed environments).",
                "",
                f'  "{interpreter}" -m venv .venv',
                f'  "{venv_python}" -m pip install -r "{req}"',
                f'  "{venv_python}" {script_path}',
            ]
        )
    else:
        lines.extend(
            [
                "",
                "This checkout has no requirements-build.txt, so there is no local requirements path to give.",
                "That file exists on main after the CI build-dependency fix; older checkouts may lack it.",
                f"This source revision expects: {pin}",
                "",
                "Create a virtual environment with this same interpreter and install that package.",
                "Do not use pip to modify a system-managed Python (PEP 668 / externally managed environments).",
                "",
                f'  "{interpreter}" -m venv .venv',
                f'  "{venv_python}" -m pip install "{pin}"',
                f'  "{venv_python}" {script_path}',
            ]
        )
    lines.extend(["", tested_note])
    return "\n".join(lines)


def require_elffile():
    """Return ELFFile, or exit with an actionable install hint if pyelftools is missing."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        if is_missing_elftools_module(exc):
            req = requirements_build_path()
            print(
                format_missing_pyelftools_message(
                    interpreter=sys.executable,
                    requirements_file=req if req.is_file() else None,
                    windows=(sys.platform == "win32"),
                ),
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        raise
    return ELFFile

# Exact map relocation order matching `enum pkt_map_idx` in include/pktpath_bpf.h
MAP_NAMES = [
    "active_slots",  # 0: PKT_MAP_ACTIVE_SLOTS
    "control",       # 1: PKT_MAP_CONTROL
    "calls",         # 2: PKT_MAP_CALLS
    "rb",            # 3: PKT_MAP_RB
    "socks",         # 4: PKT_MAP_SOCKS
    "cpu_seq",       # 5: PKT_MAP_CPU_SEQ
    "btf_off",       # 6: PKT_MAP_BTF_OFF
]

MAX_RELOCS = 64
MAX_STACK_BYTES = 512

# (sec_name, prog_type_macro, is_retprobe, layer, site_enum, attach_group, attach_name)
PROBES = [
    # L1 Socket Attribution & Optional Enrichment (7)
    ("tp_sock_create",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 1, "PKT_SITE_TP_SOCK_CREATE",     None,  "security_socket_post_create"),
    ("kp_tcp_v4_conn",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 1, "PKT_SITE_KP_TCP_V4_CONN",     None,  "tcp_v4_connect"),
    ("kp_tcp_v6_conn",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 1, "PKT_SITE_KP_TCP_V6_CONN",     None,  "tcp_v6_connect"),
    ("kr_inet_accept",     "PKT_BPF_PROG_TYPE_KPROBE",     1, 1, "PKT_SITE_KR_INET_ACCEPT",     None,  "inet_csk_accept"),
    ("kp_sk_destruct",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 1, "PKT_SITE_KP_SK_DESTRUCT",     None,  "sk_destruct"),
    ("kp_tcp_sendmsg",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 1, "PKT_SITE_KP_TCP_SENDMSG",     None,  "tcp_sendmsg_locked"),
    ("kp_udp_sendmsg",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 1, "PKT_SITE_KP_UDP_SENDMSG",     None,  "udp_sendmsg"),
    # L2 Upstream Linux Datapath, Qdisc, Xmit Handoff, Drops, Transforms & QSTATE (31)
    ("tp_net_dev_queue",   "PKT_BPF_PROG_TYPE_TRACEPOINT", 0, 2, "PKT_SITE_TP_NET_DEV_QUEUE",   "net", "net_dev_queue"),
    ("kp_htb_enq",         "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_HTB_ENQ",         None,  "htb_enqueue"),
    ("kp_fq_codel_enq",    "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_FQ_CODEL_ENQ",    None,  "fq_codel_enqueue"),
    ("kr_fq_codel_enq",    "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_FQ_CODEL_ENQ",    None,  "fq_codel_enqueue"),
    ("kr_fq_codel_deq",    "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_FQ_CODEL_DEQ",    None,  "fq_codel_dequeue"),
    ("kp_pfifo_enq",       "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_PFIFO_ENQ",       None,  "pfifo_fast_enqueue"),
    ("kr_pfifo_enq",       "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_PFIFO_ENQ",       None,  "pfifo_fast_enqueue"),
    ("kr_pfifo_deq",       "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_PFIFO_DEQ",       None,  "pfifo_fast_dequeue"),
    ("kp_sch_direct_xmit", "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_SCH_DIRECT_XMIT", None,  "sch_direct_xmit"),
    ("kp_dev_requeue",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_DEV_REQUEUE",     None,  "dev_requeue_skb"),
    ("tp_start_xmit",      "PKT_BPF_PROG_TYPE_TRACEPOINT", 0, 2, "PKT_SITE_TP_START_XMIT",      "net", "net_dev_start_xmit"),
    ("tp_xmit_ret",        "PKT_BPF_PROG_TYPE_TRACEPOINT", 0, 2, "PKT_SITE_TP_XMIT_RET",        "net", "net_dev_xmit"),
    ("tp_kfree_skb",       "PKT_BPF_PROG_TYPE_TRACEPOINT", 0, 2, "PKT_SITE_TP_KFREE_SKB",       "skb", "kfree_skb"),
    ("tp_consume_skb",     "PKT_BPF_PROG_TYPE_TRACEPOINT", 0, 2, "PKT_SITE_TP_CONSUME_SKB",     "skb", "consume_skb"),
    ("kp_skb_clone",       "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_SKB_CLONE",       None,  "skb_clone"),
    ("kr_skb_clone",       "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_SKB_CLONE",       None,  "skb_clone"),
    ("kp_pskb_expand",     "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_PSKB_EXPAND",     None,  "pskb_expand_head"),
    ("kp_txq_stop",        "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_TXQ_STOP",        None,  "netif_tx_stop_queue"),
    ("kp_txq_wake",        "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_TXQ_WAKE",        None,  "netif_tx_wake_queue"),
    ("kp_fifo_enq",        "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_FIFO_ENQ",        None,  "pfifo_enqueue"),
    ("kr_fifo_enq",        "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_FIFO_ENQ",        None,  "pfifo_enqueue"),
    ("kp_bfifo_enq",       "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_BFIFO_ENQ",       None,  "bfifo_enqueue"),
    ("kr_bfifo_enq",       "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_BFIFO_ENQ",       None,  "bfifo_enqueue"),
    ("kp_ptail_enq",       "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_PTAIL_ENQ",       None,  "pfifo_tail_enqueue"),
    ("kr_ptail_enq",       "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_PTAIL_ENQ",       None,  "pfifo_tail_enqueue"),
    ("kr_fifo_deq",        "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_FIFO_DEQ",        None,  "qdisc_dequeue_head"),
    ("kp_sfq_enq",         "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_SFQ_ENQ",         None,  "sfq_enqueue"),
    ("kr_sfq_enq",         "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_SFQ_ENQ",         None,  "sfq_enqueue"),
    ("kr_sfq_deq",         "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_SFQ_DEQ",         None,  "sfq_dequeue"),
    ("kp_tcf_classify",    "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_KP_TCF_CLASSIFY",    None,  "tcf_classify"),
    ("kr_tcf_classify",    "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_KR_TCF_CLASSIFY",    None,  "tcf_classify"),
    # L2 Reusable Dynamic Qdisc Probe Templates (4 — cloned & patched per plugin at runtime)
    ("kp_plug_cls_tmpl",      "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_TMPL_PLUG_CLS_ENQ",  None,  ""),
    ("kp_plug_leaf_enq_tmpl", "PKT_BPF_PROG_TYPE_KPROBE",     0, 2, "PKT_SITE_TMPL_PLUG_LEAF_ENQ", None,  ""),
    ("kr_plug_leaf_enq_tmpl", "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_TMPL_PLUG_LEAF_RET", None,  ""),
    ("kr_plug_leaf_deq_tmpl", "PKT_BPF_PROG_TYPE_KPROBE",     1, 2, "PKT_SITE_TMPL_PLUG_LEAF_DEQ", None,  ""),
]


def analyze_bpf_insns(sec_name: str, data: bytes) -> int:
    """Verify helper-only calls, forbid PTR_TO_CTX ALU, and compute static max stack depth."""
    if len(data) == 0 or (len(data) % 8) != 0:
        raise RuntimeError(f"Section {sec_name} has invalid byte length {len(data)}")

    n_insns = len(data) // 8
    max_stack = 0
    # Track registers copied from r10 (`rX = r10; rX += -imm`)
    fp_derived = {}
    # Track registers holding PTR_TO_CTX (entry r1, copies, and stack spill/reloads)
    ctx_regs = {1}
    spilled_ctx_offs = set()

    i = 0
    while i < n_insns:
        code, regs, off, imm = struct.unpack_from("<BBhi", data, i * 8)
        dst_reg = regs & 0x0F
        src_reg = (regs >> 4) & 0x0F
        cls = code & 0x07

        # 16-byte LD_IMM64 spans two instruction slots
        if code == 0x18:
            fp_derived.pop(dst_reg, None)
            ctx_regs.discard(dst_reg)
            i += 2
            continue

        # Reject BPF-to-BPF subprog or external libc calls (code == 0x85)
        if code == 0x85:
            if src_reg != 0 or imm <= 0 or imm > 255:
                raise RuntimeError(
                    f"Section {sec_name} insn #{i}: unsupported non-helper call "
                    f"(src_reg={src_reg}, imm={imm})"
                )
            for clob in (0, 1, 2, 3, 4, 5):
                fp_derived.pop(clob, None)
                ctx_regs.discard(clob)
            i += 1
            continue

        # Direct memory load/store/atomic
        if cls in (0x01, 0x02, 0x03):  # BPF_LDX, BPF_ST, BPF_STX
            base_reg = src_reg if cls == 0x01 else dst_reg
            if base_reg == 10 and off < 0:
                if -off > max_stack:
                    max_stack = -off
            elif base_reg in fp_derived:
                tot = fp_derived[base_reg] + off
                if tot < 0 and -tot > max_stack:
                    max_stack = -tot

            # Track PTR_TO_CTX spills and reloads via frame pointer r10
            if cls == 0x03 and dst_reg == 10:  # STX [r10 + off] = src_reg
                if src_reg in ctx_regs:
                    spilled_ctx_offs.add(off)
                else:
                    spilled_ctx_offs.discard(off)
            elif cls == 0x02 and dst_reg == 10:  # ST [r10 + off] = imm
                spilled_ctx_offs.discard(off)
            elif cls == 0x01:  # LDX dst_reg = [src_reg + off]
                fp_derived.pop(dst_reg, None)
                if src_reg == 10 and off in spilled_ctx_offs:
                    ctx_regs.add(dst_reg)
                else:
                    ctx_regs.discard(dst_reg)
        elif code == 0xBF:  # MOV64_REG: r_dst = r_src
            if src_reg == 10:
                fp_derived[dst_reg] = 0
            elif src_reg in fp_derived:
                fp_derived[dst_reg] = fp_derived[src_reg]
            else:
                fp_derived.pop(dst_reg, None)

            if src_reg in ctx_regs:
                ctx_regs.add(dst_reg)
            else:
                ctx_regs.discard(dst_reg)
        elif code in (0xB7, 0xB4, 0xBC):  # MOV64_IMM, MOV32_IMM, MOV32_REG overwrite dst_reg
            fp_derived.pop(dst_reg, None)
            ctx_regs.discard(dst_reg)
        elif cls in (0x04, 0x07):  # ALU32 / ALU64
            op = code & 0xF0
            is_reg_src = (code & 0x08) != 0
            if dst_reg in ctx_regs or (is_reg_src and op == 0x00 and src_reg in ctx_regs):
                raise RuntimeError(
                    f"Section {sec_name} insn #{i}: illegal ALU on PTR_TO_CTX "
                    f"(code=0x{code:02x}, dst=r{dst_reg}, src=r{src_reg}, imm={imm})"
                )
            if code == 0x07 and dst_reg in fp_derived:  # ADD64_IMM: rX += imm
                fp_derived[dst_reg] += imm
                if fp_derived[dst_reg] < 0 and -fp_derived[dst_reg] > max_stack:
                    max_stack = -fp_derived[dst_reg]
            elif is_reg_src and dst_reg in fp_derived:
                raise RuntimeError(
                    f"Section {sec_name} insn #{i}: variable register ALU on PTR_TO_STACK "
                    f"(code=0x{code:02x}, dst=r{dst_reg}, src=r{src_reg})"
                )
            else:
                fp_derived.pop(dst_reg, None)

        i += 1

    if max_stack > MAX_STACK_BYTES:
        raise RuntimeError(
            f"Section {sec_name} exceeds BPF stack limit: {max_stack} B > {MAX_STACK_BYTES} B"
        )

    verify_stack_init_cfg(sec_name, data)
    return max_stack


def verify_stack_init_cfg(sec_name: str, data: bytes) -> None:
    """CFG forward must-analysis proving 0 uninitialized r10 stack reads (Linux 6.1 verifier)."""
    n_insns = len(data) // 8
    sz_map = {0: 4, 1: 2, 2: 1, 3: 8}  # BPF_W, BPF_H, BPF_B, BPF_DW
    all_offs = frozenset(range(-MAX_STACK_BYTES, 0))

    # Map valid instruction indices
    valid_pcs = []
    pc = 0
    while pc < n_insns:
        valid_pcs.append(pc)
        code = data[pc * 8]
        pc += 2 if code == 0x18 else 1

    in_init = {p: (frozenset() if p == 0 else all_offs) for p in valid_pcs}
    in_regs = {p: ({} if p == 0 else None) for p in valid_pcs}

    def merge_reg_maps(a, b):
        if a is None:
            return dict(b)
        out = {}
        for k, va in a.items():
            if b.get(k) == va:
                out[k] = va
        return out

    changed = True
    while changed:
        changed = False
        for p in valid_pcs:
            if in_regs[p] is None:
                continue
            cur_init = set(in_init[p])
            cur_regs = dict(in_regs[p])

            code, regs, off, imm = struct.unpack_from("<BBhi", data, p * 8)
            dst = regs & 0x0F
            src = (regs >> 4) & 0x0F
            cls = code & 0x07
            sz = sz_map.get((code >> 3) & 0x03, 8)
            next_seq = p + (2 if code == 0x18 else 1)
            succs = []

            if code == 0x18:
                cur_regs[dst] = ("imm", imm)
                succs = [next_seq]
            elif code == 0x95:  # EXIT
                succs = []
            elif code == 0x85:  # CALL helper
                # Helpers writing output buffer at r1 of size r2: probe_read_k(113), get_comm(16)
                if imm in (113, 16):
                    r1v = cur_regs.get(1)
                    r2v = cur_regs.get(2)
                    if r1v and r1v[0] == "fp" and r2v and r2v[0] == "imm" and r2v[1] > 0:
                        for b in range(r1v[1], min(0, r1v[1] + r2v[1])):
                            cur_init.add(b)
                for clob in (0, 1, 2, 3, 4, 5):
                    cur_regs.pop(clob, None)
                succs = [next_seq]
            elif cls in (0x02, 0x03):  # BPF_ST / BPF_STX
                base_off = None
                if dst == 10 and off < 0:
                    base_off = off
                elif cur_regs.get(dst, (None,))[0] == "fp":
                    base_off = cur_regs[dst][1] + off
                if base_off is not None and base_off < 0:
                    for b in range(base_off, min(0, base_off + sz)):
                        cur_init.add(b)
                succs = [next_seq]
            elif cls == 0x01:  # BPF_LDX
                cur_regs.pop(dst, None)
                succs = [next_seq]
            elif code == 0xBF:  # MOV64_REG
                if src == 10:
                    cur_regs[dst] = ("fp", 0)
                elif src in cur_regs:
                    cur_regs[dst] = cur_regs[src]
                else:
                    cur_regs.pop(dst, None)
                succs = [next_seq]
            elif code in (0xB7, 0xB4):  # MOV64_IMM / MOV32_IMM
                cur_regs[dst] = ("imm", imm)
                succs = [next_seq]
            elif code == 0x07 and cur_regs.get(dst, (None,))[0] == "fp":  # ADD64_IMM on fp
                cur_regs[dst] = ("fp", cur_regs[dst][1] + imm)
                succs = [next_seq]
            elif cls in (0x04, 0x07):
                cur_regs.pop(dst, None)
                succs = [next_seq]
            elif cls in (0x05, 0x06):  # BPF_JMP / BPF_JMP32
                op = code & 0xF0
                target = p + 1 + off
                if op == 0x00:  # JA unconditional
                    succs = [target]
                else:
                    succs = [next_seq, target]
            else:
                succs = [next_seq]

            out_frozen = frozenset(cur_init)
            for s in succs:
                if s not in in_init:
                    continue
                new_init = in_init[s] & out_frozen
                new_regs = merge_reg_maps(in_regs[s], cur_regs)
                if new_init != in_init[s] or new_regs != in_regs[s]:
                    in_init[s] = new_init
                    in_regs[s] = new_regs
                    changed = True

    # Final verification pass: assert every reachable LDX from stack reads initialized bytes
    for p in valid_pcs:
        if in_regs[p] is None:
            continue
        code, regs, off, imm = struct.unpack_from("<BBhi", data, p * 8)
        cls = code & 0x07
        if cls == 0x01:  # BPF_LDX
            src = (regs >> 4) & 0x0F
            sz = sz_map.get((code >> 3) & 0x03, 8)
            base_off = None
            if src == 10 and off < 0:
                base_off = off
            elif in_regs[p].get(src, (None,))[0] == "fp":
                base_off = in_regs[p][src][1] + off
            if base_off is not None and base_off < 0:
                for b in range(base_off, min(0, base_off + sz)):
                    if b not in in_init[p]:
                        raise RuntimeError(
                            f"Section {sec_name} insn #{p}: uninitialized stack read at "
                            f"r10{base_off} (byte r10{b}, size={sz})"
                        )


def format_byte_array(data: bytes, per_line: int = 16) -> str:
    lines = []
    for off in range(0, len(data), per_line):
        chunk = data[off : off + per_line]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    return "\n".join(lines)


def c_str_or_null(val):
    return "NULL" if val is None else f'"{val}"'


def build_one_arch(arch: str, extra_defines: list[str], out_hdr: Path) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        obj_path = Path(tmpdir) / f"probe_core_{arch}.bpf.o"
        cmd = [
            "clang",
            "-target",
            "bpfel",
            "-mcpu=v3",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{INC_DIR}",
            *extra_defines,
            "-c",
            str(SRC_PATH),
            "-o",
            str(obj_path),
        ]
        subprocess.run(cmd, check=True)

        extracted = []
        max_seen_stack = 0

        ELFFile = require_elffile()
        with open(obj_path, "rb") as fh:
            elf = ELFFile(fh)
            for entry in PROBES:
                sec_name, prog_type, is_ret, layer, site_enum, grp, sym = entry
                sec = elf.get_section_by_name(sec_name)
                if sec is None:
                    raise RuntimeError(f"Missing ELF section '{sec_name}' in {SRC_PATH}")

                raw = sec.data()
                stack_sz = analyze_bpf_insns(sec_name, raw)
                if stack_sz > max_seen_stack:
                    max_seen_stack = stack_sz

                relocs = []
                rel_sec = elf.get_section_by_name(".rel" + sec_name)
                if rel_sec is not None:
                    symtab = elf.get_section(rel_sec["sh_link"])
                    for r in rel_sec.iter_relocations():
                        sname = symtab.get_symbol(r["r_info_sym"]).name
                        if sname not in MAP_NAMES:
                            raise RuntimeError(
                                f"Section '{sec_name}' references unknown symbol '{sname}'"
                            )
                        insn_idx = r["r_offset"] // 8
                        map_idx = MAP_NAMES.index(sname)
                        relocs.append((insn_idx, map_idx))

                if len(relocs) > MAX_RELOCS:
                    raise RuntimeError(
                        f"Section '{sec_name}' has {len(relocs)} relocations (> {MAX_RELOCS})"
                    )

                extracted.append((entry, raw, relocs, stack_sz))

    guard = f"PKTPATH_GENERATED_PROGS_{arch.upper()}_H"
    out_lines = [
        f"/* AUTO-GENERATED BY scripts/build_bpf.py ({arch}) — DO NOT EDIT MANUALLY */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        '#include "pktpath_bpf.h"',
        "#include <stddef.h>",
        "",
        f"#define PKT_BPF_PROG_COUNT {len(extracted)}U",
        "",
        "enum pkt_prog_idx {",
    ]

    for idx, (entry, _, _, _) in enumerate(extracted):
        sec_name = entry[0]
        out_lines.append(f"    PKT_PROG_{sec_name.upper()} = {idx},")
    out_lines.append("};")
    out_lines.append("")

    for entry, raw, _, stack_sz in extracted:
        sec_name = entry[0]
        n_insns = len(raw) // 8
        out_lines.append(
            f"/* {sec_name}: {n_insns} insns ({len(raw)} B), static max stack {stack_sz} B */"
        )
        out_lines.append(
            f"static unsigned char __attribute__((aligned(8))) pkt_bpf_code_{sec_name}[] = {{"
        )
        out_lines.append(format_byte_array(raw))
        out_lines.append("};")
        out_lines.append("")

    out_lines.append(
        "static struct bpf_prog_img __attribute__((unused)) pkt_bpf_progs[PKT_BPF_PROG_COUNT] = {"
    )
    for entry, raw, relocs, _ in extracted:
        sec_name, prog_type, is_ret, layer, site_enum, grp, sym = entry
        n_insns = len(raw) // 8
        rel_str = ", ".join(f"{{{ix}U, {mp}U}}" for ix, mp in relocs)
        out_lines.append("    {")
        out_lines.append(f'        .sec_name = "{sec_name}",')
        out_lines.append(f"        .attach_group = {c_str_or_null(grp)},")
        out_lines.append(f'        .attach_name = "{sym}",')
        out_lines.append(f"        .prog_type = {prog_type},")
        out_lines.append(f"        .is_retprobe = {is_ret}U,")
        out_lines.append(f"        .layer = {layer}U,")
        out_lines.append(f"        .site_id = {site_enum},")
        out_lines.append(f"        .insns = pkt_bpf_code_{sec_name},")
        out_lines.append(f"        .insn_cnt = {n_insns}U,")
        out_lines.append(f"        .reloc_cnt = {len(relocs)}U,")
        out_lines.append(f"        .relocs = {{{rel_str}}},")
        out_lines.append("    },")
    out_lines.append("};")
    out_lines.append("")
    out_lines.extend(
        [
            "static inline struct bpf_prog_img * __attribute__((unused))",
            "pkt_find_prog_by_sec(const char *sec_name) {",
            "    if (!sec_name)",
            "        return NULL;",
            "    for (unsigned i = 0; i < PKT_BPF_PROG_COUNT; i++) {",
            "        const char *a = pkt_bpf_progs[i].sec_name;",
            "        const char *b = sec_name;",
            "        while (*a && *a == *b) { a++; b++; }",
            "        if (*a == '\\0' && *b == '\\0')",
            "            return &pkt_bpf_progs[i];",
            "    }",
            "    return NULL;",
            "}",
            "",
            f"#endif /* {guard} */",
            "",
        ]
    )

    out_hdr.parent.mkdir(parents=True, exist_ok=True)
    out_hdr.write_text("\n".join(out_lines), encoding="utf-8")

    print(
        f"BUILD_BPF_OK [{arch}]: {len(extracted)} sections -> {out_hdr.name} "
        f"(max_stack={max_seen_stack} B <= {MAX_STACK_BYTES} B)"
    )


def main() -> int:
    require_elffile()
    arm64_hdr = OUT_HDR.parent / "generated_progs_arm64.h"
    x86_hdr = OUT_HDR.parent / "generated_progs_x86_64.h"
    build_one_arch("arm64", [], arm64_hdr)
    build_one_arch("x86_64", ["-DPKT_ARCH_X86_64"], x86_hdr)

    dispatcher = "\n".join(
        [
            "/* AUTO-GENERATED BY scripts/build_bpf.py — DO NOT EDIT MANUALLY */",
            "#ifndef PKTPATH_GENERATED_PROGS_H",
            "#define PKTPATH_GENERATED_PROGS_H",
            "",
            "#if defined(__x86_64__) || defined(_M_X64)",
            '#include "generated_progs_x86_64.h"',
            "#else",
            '#include "generated_progs_arm64.h"',
            "#endif",
            "",
            "#endif /* PKTPATH_GENERATED_PROGS_H */",
            "",
        ]
    )
    OUT_HDR.write_text(dispatcher, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
