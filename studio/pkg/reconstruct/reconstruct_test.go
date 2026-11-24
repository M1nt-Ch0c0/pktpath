package reconstruct

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"pktpath/studio/pkg/wire"
)

func u8b(v uint8) []byte   { return []byte{v} }
func u16b(v uint16) []byte { var b [2]byte; binary.LittleEndian.PutUint16(b[:], v); return b[:] }
func u32b(v uint32) []byte { var b [4]byte; binary.LittleEndian.PutUint32(b[:], v); return b[:] }
func u64b(v uint64) []byte { var b [8]byte; binary.LittleEndian.PutUint64(b[:], v); return b[:] }

func buildSyntheticSessionDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	uuidStr := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	uuid, _ := wire.ParseUUID(uuidStr)

	manifest := `{
		"session_uuid": "` + uuidStr + `",
		"dev": "eth0",
		"scope": "tc-egress",
		"mode": "oneshot",
		"sample_rate": "1/1",
		"adapters": [{"adapter_id": "l2_tc_egress_core", "enabled": true, "missed_source": "recursion_misses"}],
		"admissions": {"matched": 1, "selected": 1, "created": 1, "rejected": 0}
	}`
	dict := `{
		"sites": [
			{"site_idx": 1, "adapter_id": "l2_tc_egress_core", "name": "tp_net_dev_queue", "stage": 1},
			{"site_idx": 100, "adapter_id": "plugin_qdisc_netem", "name": "plug_netem_enq", "qdisc_kind": "netem", "stage": 3},
			{"site_idx": 101, "adapter_id": "plugin_qdisc_netem", "name": "plug_netem_enq_ret", "qdisc_kind": "netem", "stage": 4},
			{"site_idx": 102, "adapter_id": "plugin_qdisc_netem", "name": "plug_netem_deq", "qdisc_kind": "netem", "stage": 5},
			{"site_idx": 20, "adapter_id": "l2_tc_egress_core", "name": "tp_start_xmit", "stage": 9},
			{"site_idx": 21, "adapter_id": "l2_tc_egress_core", "name": "tp_xmit_ret", "stage": 10}
		],
		"plugin_fields": [{"slot": 0, "plugin_id": "test", "label": "sock_mark", "role": "tag", "resolved": true}],
		"topology_epochs": [{
			"epoch_id": 1, "ts_ns": 1000, "netns_inum": 4026531840,
			"devices": [{"ifindex": 2, "dev_gen": 1, "name": "eth0", "linktype": 1}],
			"qdiscs": [{"ifindex": 2, "dev_gen": 1, "queue_gen": 77, "kind": "netem", "handle": 1310720, "parent": 65568}]
		}]
	}`
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "dict.json"), []byte(dict), 0o644)

	var seq uint64
	mkEv := func(kind uint16, site uint16, ts uint64, obj uint64, tlvs []wire.TLV) []byte {
		seq++
		return wire.EncodeEvent(&wire.Event{
			Kind: kind, ObjectType: wire.ObjSKB, EvidenceLevel: wire.EvidenceDirect,
			SiteDictIdx: site, CPU: 1, Seq: seq, TsNs: ts, ObjectID: obj,
		}, tlvs)
	}

	var pay []byte
	// Root SKB obj=0x1000, sample_id=1
	pay = append(pay, mkEv(wire.KindObject, 1, 1_000_000, 0x1000, []wire.TLV{{Tag: wire.TLVObjSampleID, Val: u64b(1)}})...)
	pay = append(pay, mkEv(wire.KindSummary, 1, 1_000_100, 0x1000, []wire.TLV{
		{Tag: wire.TLVSumPktLen, Val: u32b(98)},
		{Tag: wire.TLVSumLinearLen, Val: u32b(98)},
		{Tag: wire.TLVSumIfindex, Val: u32b(2)},
		{Tag: wire.TLVSumDir, Val: u8b(wire.DirTX)},
		{Tag: wire.TLVSumIPVersion, Val: u8b(4)},
		{Tag: wire.TLVSumL4Proto, Val: u8b(1)},
		{Tag: wire.TLVSumSrcIP, Val: []byte{192, 0, 2, 1}},
		{Tag: wire.TLVSumDstIP, Val: []byte{198, 51, 100, 2}},
		{Tag: wire.TLVSumUID, Val: u32b(0)},
		{Tag: wire.TLVSumComm, Val: []byte("ping\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")},
		{Tag: wire.TLVSumPluginVal0, Val: u64b(4660)},
		{Tag: wire.TLVSumLinktype, Val: u16b(101)},
		{Tag: wire.TLVSumHdrBytes, Val: []byte{0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 0, 2, 1, 198, 51, 100, 2, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}},
	})...)
	pay = append(pay, mkEv(wire.KindStep, 1, 1_000_200, 0x1000, []wire.TLV{
		{Tag: wire.TLVStepIfindex, Val: u32b(2)}, {Tag: wire.TLVStepDir, Val: u8b(wire.DirTX)}, {Tag: wire.TLVStepStage, Val: u8b(wire.StageEntry)},
	})...)
	// Enqueue into netem (queue_gen=77, visit_id=1) at 1.1ms -> Dequeue at 11.1ms (sojourn = 10ms = 10,000 us)
	pay = append(pay, mkEv(wire.KindStep, 100, 1_100_000, 0x1000, []wire.TLV{
		{Tag: wire.TLVStepVisitID, Val: u64b(1)}, {Tag: wire.TLVStepIfindex, Val: u32b(2)}, {Tag: wire.TLVStepStage, Val: u8b(wire.StageQdiscEnq)},
		{Tag: wire.TLVStepQueueGen, Val: u64b(77)}, {Tag: wire.TLVStepQdiscHandle, Val: u32b(1310720)},
	})...)
	pay = append(pay, mkEv(wire.KindStep, 101, 1_101_000, 0x1000, []wire.TLV{
		{Tag: wire.TLVStepVisitID, Val: u64b(1)}, {Tag: wire.TLVStepStage, Val: u8b(wire.StageQdiscEnqRet)}, {Tag: wire.TLVStepRawRet, Val: u32b(0)},
	})...)
	pay = append(pay, mkEv(wire.KindStep, 102, 11_100_000, 0x1000, []wire.TLV{
		{Tag: wire.TLVStepVisitID, Val: u64b(1)}, {Tag: wire.TLVStepIfindex, Val: u32b(2)}, {Tag: wire.TLVStepStage, Val: u8b(wire.StageQdiscDeq)},
		{Tag: wire.TLVStepQueueGen, Val: u64b(77)}, {Tag: wire.TLVStepQdiscHandle, Val: u32b(1310720)},
	})...)
	// CLONE relation to child SKB 0x2000 (CONSUME)
	pay = append(pay, mkEv(wire.KindRelation, 1, 11_150_000, 0x1000, []wire.TLV{
		{Tag: wire.TLVRelOpID, Val: u64b(9)}, {Tag: wire.TLVRelType, Val: u8b(wire.RelClone)},
		{Tag: wire.TLVRelSrcObjectID, Val: u64b(0x1000)}, {Tag: wire.TLVRelDstObjectID, Val: u64b(0x2000)},
	})...)
	pay = append(pay, mkEv(wire.KindObject, 1, 11_151_000, 0x2000, []wire.TLV{
		{Tag: wire.TLVObjSampleID, Val: u64b(1)}, {Tag: wire.TLVObjEndReason, Val: u16b(wire.EndConsume)},
	})...)
	// XMIT_START + XMIT_RET (TX_OK) on root 0x1000
	pay = append(pay, mkEv(wire.KindStep, 20, 11_200_000, 0x1000, []wire.TLV{
		{Tag: wire.TLVStepCallID, Val: u64b(5)}, {Tag: wire.TLVStepIfindex, Val: u32b(2)}, {Tag: wire.TLVStepStage, Val: u8b(wire.StageXmitStart)}, {Tag: wire.TLVStepTxq, Val: u16b(0)},
	})...)
	pay = append(pay, mkEv(wire.KindStep, 21, 11_210_000, 0x1000, []wire.TLV{
		{Tag: wire.TLVStepCallID, Val: u64b(5)}, {Tag: wire.TLVStepStage, Val: u8b(wire.StageXmitRet)}, {Tag: wire.TLVStepRawRet, Val: u32b(0)},
	})...)
	pay = append(pay, mkEv(wire.KindObject, 21, 11_211_000, 0x1000, []wire.TLV{
		{Tag: wire.TLVObjSampleID, Val: u64b(1)}, {Tag: wire.TLVObjEndReason, Val: u16b(wire.EndTxOK)},
	})...)

	blk1, _ := wire.EncodeBlock(wire.BlockHeader{
		Magic: wire.BlockMagic, Major: wire.WireMajor, Minor: wire.WireMinor,
		BlockType: wire.BlockEventBatch, ProducerType: wire.ProdKernelBPF,
		Epoch: 1, BlockNo: 1, SessionUUID: uuid, MinTsNs: 1_000_000, MaxTsNs: 11_211_000,
	}, pay)
	blkEnd, _ := wire.EncodeBlock(wire.BlockHeader{
		Magic: wire.BlockMagic, Major: wire.WireMajor, Minor: wire.WireMinor,
		BlockType: wire.BlockEndMarker, ProducerType: wire.ProdController,
		Epoch: 1, BlockNo: 2, SessionUUID: uuid, MinTsNs: 11_211_000, MaxTsNs: 11_211_000,
	}, nil)
	_ = os.WriteFile(filepath.Join(dir, "block_000001.pktb"), blk1, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "block_000002.pktb"), blkEnd, 0o644)
	return dir
}

func TestMultiBranchDAGSojournAndPluginTag(t *testing.T) {
	dir := buildSyntheticSessionDir(t)
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	ov := BuildOverview(s)
	if len(ov.Samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(ov.Samples))
	}
	row := ov.Samples[0]
	if row.BranchCount != 2 {
		t.Fatalf("expected 2 branches (root + CLONE), got %d", row.BranchCount)
	}
	if row.MaxSojournUs < 9900 || row.MaxSojournUs > 10100 {
		t.Fatalf("expected ~10000us sojourn, got %.2f", row.MaxSojournUs)
	}
	if len(ov.Stats.Queues) == 0 || ov.Stats.Queues[0].Kind != "netem" {
		t.Fatalf("expected netem queue stat, got %+v", ov.Stats.Queues)
	}

	det, err := BuildSampleDetail(s, 1)
	if err != nil {
		t.Fatalf("BuildSampleDetail failed: %v", err)
	}
	if det.Summary.PluginTags["sock_mark"] != 4660 {
		t.Fatalf("expected plugin_tags[sock_mark]=4660, got %+v", det.Summary.PluginTags)
	}
}
