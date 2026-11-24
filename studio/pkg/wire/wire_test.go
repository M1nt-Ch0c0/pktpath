package wire

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func u64b(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

func u32b(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func TestBlockRoundtripAnd16PluginVals(t *testing.T) {
	uuid, err := ParseUUID("11223344-5566-4777-8888-99aabbccddee")
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}

	// Build a SUMMARY event containing all 16 plugin_val0..15 + optional unknown + must-understand unknown
	tlvs := []TLV{
		{Tag: TLVSumPktLen, Val: u32b(1280)},
		{Tag: TLVSumUID, Val: u32b(1000)},
		{Tag: TLVSumComm, Val: []byte("curl\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")},
	}
	for i := uint16(0); i < 16; i++ {
		tlvs = append(tlvs, TLV{Tag: TLVSumPluginVal0 + i, Val: u64b(uint64(1000 + i))})
	}
	tlvs = append(tlvs,
		TLV{Tag: 0x07FE, Val: u32b(77)},                  // unknown optional
		TLV{Tag: 0x07FF | TLVMustUnderstand, Val: u32b(88)}, // unknown must-understand
	)

	evBytes := EncodeEvent(&Event{
		Kind:          KindSummary,
		ObjectType:    ObjSKB,
		EvidenceLevel: EvidenceDirect,
		SiteDictIdx:   1,
		CPU:           2,
		Seq:           42,
		TsNs:          1_000_000,
		ObjectID:      0x101,
	}, tlvs)

	blkBytes, err := EncodeBlock(BlockHeader{
		Magic:        BlockMagic,
		Major:        WireMajor,
		Minor:        WireMinor,
		BlockType:    BlockEventBatch,
		ProducerType: ProdKernelBPF,
		Epoch:        1,
		BlockNo:      1,
		SessionUUID:  uuid,
		MinTsNs:      1_000_000,
		MaxTsNs:      1_000_000,
	}, evBytes)
	if err != nil {
		t.Fatalf("EncodeBlock: %v", err)
	}

	rec, err := DecodeBlock(blkBytes, "block_000001.pktb")
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}
	if len(rec.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(rec.Events))
	}
	ev := rec.Events[0]
	if comm, ok := ev.Str("comm"); !ok || comm != "curl" {
		t.Fatalf("unexpected comm: %q %v", comm, ok)
	}
	for i := 0; i < 16; i++ {
		want := uint64(1000 + i)
		got, ok := ev.Get("plugin_val" + string([]byte{'0' + byte(i/10), '0' + byte(i%10)}))
		if i < 10 {
			got, ok = ev.Get("plugin_val" + string([]byte{'0' + byte(i)}))
		}
		if !ok || got != want {
			t.Fatalf("plugin_val%d mismatch: got=%d ok=%v want=%d", i, got, ok, want)
		}
	}
	if len(ev.UnknownOptional) != 1 || len(ev.UnknownMust) != 1 || !ev.UnknownMust[0].MustUnderstand {
		t.Fatalf("unknown TLV classification mismatch: opt=%d must=%d", len(ev.UnknownOptional), len(ev.UnknownMust))
	}

	// Corrupt last byte -> CRC error
	bad := append([]byte(nil), blkBytes...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := DecodeBlock(bad, "bad.pktb"); !errors.Is(err, ErrCRC) {
		t.Fatalf("expected ErrCRC, got %v", err)
	}
}

func TestLoadSessionCrashTolerantTail(t *testing.T) {
	dir := t.TempDir()
	uuidStr := "11223344-5566-4777-8888-99aabbccddee"
	uuid, _ := ParseUUID(uuidStr)

	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"session_uuid":"`+uuidStr+`","dev":"eth0","scope":"tc-egress"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "dict.json"), []byte(`{"sites":[],"topology_epochs":[]}`), 0o644)

	evBytes := EncodeEvent(&Event{
		Kind: KindObject, ObjectType: ObjSKB, EvidenceLevel: EvidenceDirect,
		CPU: 0, Seq: 1, TsNs: 5000, ObjectID: 1,
	}, []TLV{{Tag: TLVObjSampleID, Val: u64b(1)}})
	blk1, _ := EncodeBlock(BlockHeader{
		Magic: BlockMagic, Major: WireMajor, Minor: WireMinor,
		BlockType: BlockEventBatch, ProducerType: ProdKernelBPF,
		Epoch: 1, BlockNo: 1, SessionUUID: uuid, MinTsNs: 5000, MaxTsNs: 5000,
	}, evBytes)
	_ = os.WriteFile(filepath.Join(dir, "block_000001.pktb"), blk1, 0o644)
	// Truncated crash tail block
	_ = os.WriteFile(filepath.Join(dir, "block_000002.pktb"), blk1[:24], 0o644)

	ls, err := LoadSession(dir, false)
	if err != nil {
		t.Fatalf("crash-tolerant load should succeed: %v", err)
	}
	if !ls.UncleanTail() || !ls.HasCorruptedTail || len(ls.Events) != 1 {
		t.Fatalf("unexpected crash tail state: unclean=%v corrupt=%v events=%d", ls.UncleanTail(), ls.HasCorruptedTail, len(ls.Events))
	}
}
