package export

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"pktpath/studio/pkg/reconstruct"
	"pktpath/studio/pkg/wire"
)

func u8b(v uint8) []byte   { return []byte{v} }
func u16b(v uint16) []byte { var b [2]byte; binary.LittleEndian.PutUint16(b[:], v); return b[:] }
func u32b(v uint32) []byte { var b [4]byte; binary.LittleEndian.PutUint32(b[:], v); return b[:] }
func u64b(v uint64) []byte { var b [8]byte; binary.LittleEndian.PutUint64(b[:], v); return b[:] }

func makeExportSessionDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	uuidStr := "12345678-1234-4123-8123-123456789abc"
	uuid, _ := wire.ParseUUID(uuidStr)

	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"session_uuid":"`+uuidStr+`","dev":"eth0","scope":"tc-egress"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "dict.json"), []byte(`{"sites":[],"topology_epochs":[{"epoch_id":1,"devices":[{"ifindex":2,"name":"eth0","linktype":101}]}]}`), 0o644)

	var pay []byte
	pay = append(pay, wire.EncodeEvent(&wire.Event{
		Kind: wire.KindObject, ObjectType: wire.ObjSKB, EvidenceLevel: wire.EvidenceDirect,
		CPU: 0, Seq: 1, TsNs: 1_000_000, ObjectID: 1,
	}, []wire.TLV{{Tag: wire.TLVObjSampleID, Val: u64b(1)}, {Tag: wire.TLVObjEndReason, Val: u16b(wire.EndTxOK)}})...)
	pay = append(pay, wire.EncodeEvent(&wire.Event{
		Kind: wire.KindSummary, ObjectType: wire.ObjSKB, EvidenceLevel: wire.EvidenceDirect,
		CPU: 0, Seq: 2, TsNs: 1_000_100, ObjectID: 1,
	}, []wire.TLV{
		{Tag: wire.TLVSumPktLen, Val: u32b(28)},
		{Tag: wire.TLVSumLinearLen, Val: u32b(28)},
		{Tag: wire.TLVSumIfindex, Val: u32b(2)},
		{Tag: wire.TLVSumDir, Val: u8b(wire.DirTX)},
		{Tag: wire.TLVSumIPVersion, Val: u8b(4)},
		{Tag: wire.TLVSumL4Proto, Val: u8b(1)},
		{Tag: wire.TLVSumSrcIP, Val: []byte{192, 168, 10, 5}},
		{Tag: wire.TLVSumDstIP, Val: []byte{198, 51, 100, 9}},
		{Tag: wire.TLVSumUID, Val: u32b(10234)},
		{Tag: wire.TLVSumComm, Val: []byte("ping\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")},
		{Tag: wire.TLVSumLinktype, Val: u16b(101)},
		{Tag: wire.TLVSumHdrBytes, Val: []byte{0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 192, 168, 10, 5, 198, 51, 100, 9, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}},
	})...)

	blk1, _ := wire.EncodeBlock(wire.BlockHeader{
		Magic: wire.BlockMagic, Major: wire.WireMajor, Minor: wire.WireMinor,
		BlockType: wire.BlockEventBatch, ProducerType: wire.ProdKernelBPF,
		Epoch: 1, BlockNo: 1, SessionUUID: uuid, MinTsNs: 1_000_000, MaxTsNs: 1_000_100,
	}, pay)
	blkEnd, _ := wire.EncodeBlock(wire.BlockHeader{
		Magic: wire.BlockMagic, Major: wire.WireMajor, Minor: wire.WireMinor,
		BlockType: wire.BlockEndMarker, ProducerType: wire.ProdController,
		Epoch: 1, BlockNo: 2, SessionUUID: uuid, MinTsNs: 1_000_100, MaxTsNs: 1_000_100,
	}, nil)
	_ = os.WriteFile(filepath.Join(dir, "block_000001.pktb"), blk1, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "block_000002.pktb"), blkEnd, 0o644)
	return dir
}

func TestExportPcapngAndRedactSession(t *testing.T) {
	src := makeExportSessionDir(t)

	// 1. Export pcapng and verify SHB magic (0x0A0D0D0A)
	pcap := filepath.Join(t.TempDir(), "trace.pcapng")
	n, err := ExportPcapng(src, pcap, false, "")
	if err != nil || n != 1 {
		t.Fatalf("ExportPcapng failed: n=%d err=%v", n, err)
	}
	b, err := os.ReadFile(pcap)
	if err != nil || len(b) < 32 || binary.LittleEndian.Uint32(b[:4]) != 0x0A0D0D0A {
		t.Fatalf("invalid pcapng SHB header")
	}

	// 2. Redact session and verify original IP & comm are replaced
	redDir := filepath.Join(t.TempDir(), "redacted")
	if err := RedactSession(src, redDir, "unit-test-key"); err != nil {
		t.Fatalf("RedactSession failed: %v", err)
	}
	s, err := reconstruct.Open(redDir)
	if err != nil {
		t.Fatalf("Open redacted session failed: %v", err)
	}
	ov := reconstruct.BuildOverview(s)
	if len(ov.Samples) != 1 {
		t.Fatalf("expected 1 redacted sample, got %d", len(ov.Samples))
	}
	if ov.Samples[0].SrcIP == "192.168.10.5" || ov.Samples[0].DstIP == "198.51.100.9" {
		t.Fatalf("sensitive IPs leaked after redaction: %+v", ov.Samples[0])
	}
	if ov.Samples[0].UID != nil && *ov.Samples[0].UID == 10234 {
		t.Fatalf("sensitive UID leaked after redaction: %+v", ov.Samples[0])
	}
}
