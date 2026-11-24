"""End-to-end unit tests for wire v1.0 codec, DAG reconstruction, stats, pcapng & redaction."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
import uuid
from pathlib import Path

from analyzer import pcapng_export, reconstruct, redact, stats, wire


def _u8(v: int) -> bytes:
    return struct.pack("<B", v)


def _u16(v: int) -> bytes:
    return struct.pack("<H", v)


def _u32(v: int) -> bytes:
    return struct.pack("<I", v)


def _u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def _make_event(
    kind: int,
    site: int,
    seq: int,
    ts_ns: int,
    obj_id: int,
    tlvs: list[tuple[int, bytes]],
    cpu: int = 1,
) -> bytes:
    ev = wire.DecodedEvent(
        total_len=0,
        kind=kind,
        object_type=int(wire.ObjectType.SKB),
        evidence_level=int(wire.EvidenceLevel.DIRECT),
        site_dict_idx=site,
        cpu=cpu,
        flags=0,
        seq=seq,
        ts_ns=ts_ns,
        object_id=obj_id,
    )
    return wire.encode_event(ev, tlvs)


def _make_synthetic_session(run_dir: Path) -> None:
    sid_uuid = uuid.UUID("11223344-5566-4777-8888-99aabbccddee")
    manifest = {
        "session_uuid": str(sid_uuid),
        "dev": "eth0",
        "scope": "tc-egress",
        "mode": "oneshot",
        "sample_rate": "1/1",
        "adapters": [
            {"adapter_id": "l2_tc_egress_core", "enabled": True, "missed_source": "recursion_misses"},
        ],
        "admissions": {"matched": 1, "selected": 1, "created": 1, "rejected": 0},
    }
    dict_doc = {
        "sites": [
            {"site_idx": 1, "adapter_id": "l2_tc_egress_core", "name": "tp_net_dev_queue", "stage": 1},
            {"site_idx": 100, "adapter_id": "plugin_qdisc_netem", "name": "plug_netem_enq", "qdisc_kind": "netem", "stage": 3},
            {"site_idx": 101, "adapter_id": "plugin_qdisc_netem", "name": "plug_netem_enq_ret", "qdisc_kind": "netem", "stage": 4},
            {"site_idx": 102, "adapter_id": "plugin_qdisc_netem", "name": "plug_netem_deq", "qdisc_kind": "netem", "stage": 5},
            {"site_idx": 20, "adapter_id": "l2_tc_egress_core", "name": "tp_start_xmit", "stage": 9},
            {"site_idx": 21, "adapter_id": "l2_tc_egress_core", "name": "tp_xmit_ret", "stage": 10},
        ],
        "plugin_fields": [
            {"slot": 0, "plugin_id": "test", "label": "sock_mark", "role": "tag", "resolved": True},
            {"slot": 15, "plugin_id": "test", "label": "slot15_tag", "role": "tag", "resolved": True},
        ],
        "topology_epochs": [
            {
                "epoch_id": 1,
                "ts_ns": 1000,
                "netns_inum": 4026531840,
                "devices": [{"ifindex": 2, "dev_gen": 1, "name": "eth0", "linktype": 101}],
                "qdiscs": [{"ifindex": 2, "dev_gen": 1, "queue_gen": 77, "kind": "netem", "handle": 1310720, "parent": 65568}],
            }
        ],
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "dict.json").write_text(json.dumps(dict_doc), encoding="utf-8")

    raw_ipv4_icmp = bytes([
        0x45, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
        192, 168, 10, 5, 198, 51, 100, 9,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
    ])
    seq = 0

    def nxt(kind, site, ts, obj, tlvs):
        nonlocal seq
        seq += 1
        return _make_event(kind, site, seq, ts, obj, tlvs)

    payload = b"".join([
        nxt(wire.EventKind.OBJECT, 1, 1_000_000, 0x1000, [(wire.TLV_OBJ_SAMPLE_ID, _u64(1))]),
        nxt(wire.EventKind.SUMMARY, 1, 1_000_100, 0x1000, [
            (wire.TLV_SUM_PKT_LEN, _u32(28)),
            (wire.TLV_SUM_LINEAR_LEN, _u32(28)),
            (wire.TLV_SUM_IFINDEX, _u32(2)),
            (wire.TLV_SUM_DIR, _u8(wire.Dir.TX)),
            (wire.TLV_SUM_IP_VERSION, _u8(4)),
            (wire.TLV_SUM_L4_PROTO, _u8(1)),
            (wire.TLV_SUM_SRC_IP, bytes([192, 168, 10, 5])),
            (wire.TLV_SUM_DST_IP, bytes([198, 51, 100, 9])),
            (wire.TLV_SUM_UID, _u32(10234)),
            (wire.TLV_SUM_COMM, b"ping".ljust(16, b"\x00")),
            (wire.TLV_SUM_PLUGIN_VAL_BASE + 0, _u64(4660)),
            (wire.TLV_SUM_PLUGIN_VAL_BASE + 15, _u64(9999)),
            (wire.TLV_SUM_LINKTYPE, _u16(101)),
            (wire.TLV_SUM_HDR_BYTES, raw_ipv4_icmp),
        ]),
        nxt(wire.EventKind.STEP, 1, 1_000_200, 0x1000, [
            (wire.TLV_STEP_IFINDEX, _u32(2)), (wire.TLV_STEP_DIR, _u8(wire.Dir.TX)), (wire.TLV_STEP_STAGE, _u8(wire.Stage.ENTRY)),
        ]),
        nxt(wire.EventKind.STEP, 100, 1_100_000, 0x1000, [
            (wire.TLV_STEP_VISIT_ID, _u64(1)), (wire.TLV_STEP_IFINDEX, _u32(2)), (wire.TLV_STEP_STAGE, _u8(wire.Stage.QDISC_ENQ)),
            (wire.TLV_STEP_QUEUE_GEN, _u64(77)), (wire.TLV_STEP_QDISC_HANDLE, _u32(1310720)),
        ]),
        nxt(wire.EventKind.STEP, 101, 1_101_000, 0x1000, [
            (wire.TLV_STEP_VISIT_ID, _u64(1)), (wire.TLV_STEP_STAGE, _u8(wire.Stage.QDISC_ENQ_RET)), (wire.TLV_STEP_RAW_RET, _u32(0)),
        ]),
        nxt(wire.EventKind.STEP, 102, 11_100_000, 0x1000, [
            (wire.TLV_STEP_VISIT_ID, _u64(1)), (wire.TLV_STEP_IFINDEX, _u32(2)), (wire.TLV_STEP_STAGE, _u8(wire.Stage.QDISC_DEQ)),
            (wire.TLV_STEP_QUEUE_GEN, _u64(77)), (wire.TLV_STEP_QDISC_HANDLE, _u32(1310720)),
        ]),
        nxt(wire.EventKind.RELATION, 1, 11_150_000, 0x1000, [
            (wire.TLV_REL_OP_ID, _u64(9)), (wire.TLV_REL_TYPE, _u8(wire.RelType.CLONE)),
            (wire.TLV_REL_SRC_OBJECT_ID, _u64(0x1000)), (wire.TLV_REL_DST_OBJECT_ID, _u64(0x2000)),
        ]),
        nxt(wire.EventKind.OBJECT, 1, 11_151_000, 0x2000, [
            (wire.TLV_OBJ_SAMPLE_ID, _u64(1)), (wire.TLV_OBJ_END_REASON, _u16(wire.EndReason.CONSUME)),
        ]),
        nxt(wire.EventKind.STEP, 20, 11_200_000, 0x1000, [
            (wire.TLV_STEP_CALL_ID, _u64(5)), (wire.TLV_STEP_IFINDEX, _u32(2)), (wire.TLV_STEP_STAGE, _u8(wire.Stage.XMIT_START)),
            (wire.TLV_STEP_TXQ, _u16(0)),
        ]),
        nxt(wire.EventKind.STEP, 21, 11_210_000, 0x1000, [
            (wire.TLV_STEP_CALL_ID, _u64(5)), (wire.TLV_STEP_STAGE, _u8(wire.Stage.XMIT_RET)), (wire.TLV_STEP_RAW_RET, _u32(0)),
        ]),
        nxt(wire.EventKind.OBJECT, 21, 11_211_000, 0x1000, [
            (wire.TLV_OBJ_SAMPLE_ID, _u64(1)), (wire.TLV_OBJ_END_REASON, _u16(wire.EndReason.TX_OK)),
        ]),
    ])

    hdr1 = wire.BlockHeader(
        magic=wire.BLOCK_MAGIC,
        major=wire.WIRE_MAJOR,
        minor=wire.WIRE_MINOR,
        block_type=int(wire.BlockType.EVENT_BATCH),
        producer_type=int(wire.ProducerType.KERNEL_BPF),
        flags=0,
        payload_len=len(payload),
        epoch=1,
        block_no=1,
        reserved=0,
        session_uuid=sid_uuid.bytes,
        min_ts_ns=1_000_000,
        max_ts_ns=11_211_000,
    )
    hdr_end = wire.BlockHeader(
        magic=wire.BLOCK_MAGIC,
        major=wire.WIRE_MAJOR,
        minor=wire.WIRE_MINOR,
        block_type=int(wire.BlockType.END_MARKER),
        producer_type=int(wire.ProducerType.CONTROLLER),
        flags=0,
        payload_len=0,
        epoch=1,
        block_no=2,
        reserved=0,
        session_uuid=sid_uuid.bytes,
        min_ts_ns=11_211_000,
        max_ts_ns=11_211_000,
    )
    (run_dir / "block_000001.pktb").write_bytes(wire.encode_block(hdr1, payload))
    (run_dir / "block_000002.pktb").write_bytes(wire.encode_block(hdr_end, b""))


class TestAnalyzerPipeline(unittest.TestCase):
    def test_wire_reconstruct_stats_pcapng_and_redact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            run_dir.mkdir()
            _make_synthetic_session(run_dir)

            # 1. Load & reconstruct
            sess = reconstruct.reconstruct_session(run_dir)
            self.assertIn(1, sess.samples)
            sg = sess.samples[1]
            self.assertEqual(len(sg.branches), 2)
            self.assertEqual(sg.attribution["plugin_vals"][0], 4660)
            self.assertEqual(sg.attribution["plugin_vals"][15], 9999)

            # 2. Stats check (10 ms netem sojourn)
            st = stats.compute_stats(sess)
            self.assertEqual(st["samples"]["total"], 1)
            self.assertTrue(any(q["kind"] == "netem" and 9900 <= q["p50_us"] <= 10100 for q in st["queues"]))

            # 3. Export pcapng
            pcap_out = Path(td) / "out.pcapng"
            pcapng_export.export_pcapng(run_dir, pcap_out)
            raw = pcap_out.read_bytes()
            self.assertGreater(len(raw), 32)
            self.assertEqual(struct.unpack("<I", raw[:4])[0], 0x0A0D0D0A)

            # 4. Redact session
            red_dir = Path(td) / "redacted"
            redact.redact_session(run_dir, red_dir, key="ci-test-key")
            red_sess = reconstruct.reconstruct_session(red_dir)
            red_obj_id = red_sess.samples[1].object_ids[0]
            red_sm = red_sess.objects[red_obj_id].summaries[0]
            self.assertNotEqual(red_sm.get("src_ip"), "192.168.10.5")
            self.assertNotEqual(red_sm.get("uid"), 10234)

    def test_crc_corruption_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            run_dir.mkdir()
            _make_synthetic_session(run_dir)
            raw = bytearray((run_dir / "block_000001.pktb").read_bytes())
            raw[-1] ^= 0xFF
            with self.assertRaises(wire.WireError):
                wire.decode_block(bytes(raw))


if __name__ == "__main__":
    unittest.main()
