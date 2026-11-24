package export

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"pktpath/studio/pkg/reconstruct"
	"pktpath/studio/pkg/wire"
)

const (
	shbType     uint32 = 0x0A0D0D0A
	idbType     uint32 = 0x00000001
	epbType     uint32 = 0x00000006
	pcapngBOMLE uint32 = 0x1A2B3C4D

	optEndOfOpt uint16 = 0
	optComment  uint16 = 1

	shbUserAppl   uint16 = 4
	ifNameOpt     uint16 = 2
	ifDescOpt     uint16 = 3
	ifTsResolOpt  uint16 = 9
	epbFlagsOpt   uint16 = 2
	defaultSnapLn uint32 = 262144
)

type pcapOpt struct {
	code uint16
	val  []byte
}

func pad4(b []byte) []byte {
	rem := len(b) % 4
	if rem == 0 {
		return b
	}
	out := make([]byte, len(b)+(4-rem))
	copy(out, b)
	return out
}

func packOptions(opts []pcapOpt) []byte {
	if len(opts) == 0 {
		return nil
	}
	var buf bytes.Buffer
	var hdr [4]byte
	for _, o := range opts {
		binary.LittleEndian.PutUint16(hdr[0:], o.code)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(o.val)))
		buf.Write(hdr[:])
		buf.Write(pad4(o.val))
	}
	binary.LittleEndian.PutUint16(hdr[0:], optEndOfOpt)
	binary.LittleEndian.PutUint16(hdr[2:], 0)
	buf.Write(hdr[:])
	return buf.Bytes()
}

func wrapPcapngBlock(btype uint32, body []byte) []byte {
	pb := pad4(body)
	total := uint32(12 + len(pb))
	out := make([]byte, 8+len(pb)+4)
	binary.LittleEndian.PutUint32(out[0:], btype)
	binary.LittleEndian.PutUint32(out[4:], total)
	copy(out[8:], pb)
	binary.LittleEndian.PutUint32(out[8+len(pb):], total)
	return out
}

func manifestOrDefault(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	if v == nil {
		return "None"
	}
	return fmt.Sprint(v)
}

func buildSHB(sess *reconstruct.Session, redacted bool) []byte {
	comment := fmt.Sprintf("session_uuid=%s scope=%s clock_domain=%s redacted=%t",
		sess.Loaded.SessionUUIDString(),
		manifestOrDefault(sess.Manifest, "scope", "tc-egress"),
		manifestOrDefault(sess.Manifest, "clock_domain", "CLOCK_BOOTTIME"),
		redacted,
	)
	opts := packOptions([]pcapOpt{
		{optComment, []byte(comment)},
		{shbUserAppl, []byte("pktpath-v3")},
	})
	var fixed [16]byte
	binary.LittleEndian.PutUint32(fixed[0:], pcapngBOMLE)
	binary.LittleEndian.PutUint16(fixed[4:], 1)
	binary.LittleEndian.PutUint16(fixed[6:], 0)
	secLen := int64(-1)
	binary.LittleEndian.PutUint64(fixed[8:], uint64(secLen))
	return wrapPcapngBlock(shbType, append(fixed[:], opts...))
}

type idbKey struct {
	netns    uint64
	ifindex  uint64
	devGen   uint64
	stage    int
	linktype int
}

func buildIDB(devName string, k idbKey) []byte {
	stageName, ok := wire.StageNames[k.stage]
	if !ok {
		stageName = fmt.Sprintf("STAGE_%d", k.stage)
	}
	ifName := fmt.Sprintf("%s@ns%d:gen%d:%s", devName, k.netns, k.devGen, stageName)
	ifDesc := fmt.Sprintf("netns=%d ifindex=%d dev_gen=%d stage=%s(%d) linktype=%d",
		k.netns, k.ifindex, k.devGen, stageName, k.stage, k.linktype)
	opts := packOptions([]pcapOpt{
		{ifNameOpt, []byte(ifName)},
		{ifDescOpt, []byte(ifDesc)},
		{ifTsResolOpt, []byte{0x09}},
	})
	var fixed [8]byte
	binary.LittleEndian.PutUint16(fixed[0:], uint16(k.linktype))
	binary.LittleEndian.PutUint16(fixed[2:], 0)
	binary.LittleEndian.PutUint32(fixed[4:], defaultSnapLn)
	return wrapPcapngBlock(idbType, append(fixed[:], opts...))
}

func buildEPB(ifID uint32, tsNs int64, pkt []byte, origLen uint32, dirOpt reconstruct.OptU, comment string) []byte {
	var tsU uint64
	if tsNs > 0 {
		tsU = uint64(tsNs)
	}
	tsHigh := uint32(tsU >> 32)
	tsLow := uint32(tsU & 0xFFFFFFFF)
	capLen := uint32(len(pkt))
	effOrig := origLen
	if capLen > effOrig {
		effOrig = capLen
	}
	optList := []pcapOpt{{optComment, []byte(comment)}}
	if dirOpt.OK {
		var f [4]byte
		switch dirOpt.V {
		case wire.DirRX:
			binary.LittleEndian.PutUint32(f[:], 1)
			optList = append(optList, pcapOpt{epbFlagsOpt, f[:]})
		case wire.DirTX:
			binary.LittleEndian.PutUint32(f[:], 2)
			optList = append(optList, pcapOpt{epbFlagsOpt, f[:]})
		}
	}
	opts := packOptions(optList)
	var fixed [20]byte
	binary.LittleEndian.PutUint32(fixed[0:], ifID)
	binary.LittleEndian.PutUint32(fixed[4:], tsHigh)
	binary.LittleEndian.PutUint32(fixed[8:], tsLow)
	binary.LittleEndian.PutUint32(fixed[12:], capLen)
	binary.LittleEndian.PutUint32(fixed[16:], effOrig)
	var body bytes.Buffer
	body.Write(fixed[:])
	body.Write(pad4(pkt))
	body.Write(opts)
	return wrapPcapngBlock(epbType, body.Bytes())
}

func absDiffU64(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return b - a
}

func inferSummaryHookContext(sess *reconstruct.Session, obj *reconstruct.ObjectNode, summ *wire.Event) idbKey {
	ifidx := summ.U("ifindex")
	site := sess.ResolveSite(summ.SiteDictIdx)
	stage := wire.StageEntry
	if site != nil && site.HasStage {
		stage = int(site.Stage)
	}

	var bestStep *wire.Event
	var bestDist uint64
	for _, st := range obj.Steps {
		d := absDiffU64(st.TsNs, summ.TsNs)
		if bestStep == nil || d < bestDist {
			bestDist = d
			bestStep = st
		}
	}

	var defaultNetns uint64
	if eps, ok := sess.Dict["topology_epochs"].([]any); ok && len(eps) > 0 {
		if em, ok2 := eps[0].(map[string]any); ok2 {
			if n, ok3 := wire.AsInt(em["netns_inum"]); ok3 {
				defaultNetns = uint64(n)
			}
		}
	}

	netns := defaultNetns
	devGen := uint64(1)
	if bestStep != nil {
		if n := bestStep.U("netns_inum"); n != 0 {
			netns = n
		}
		if dg := bestStep.U("dev_gen"); dg != 0 {
			devGen = dg
		}
		if ifidx == 0 {
			ifidx = bestStep.U("ifindex")
		}
		if site == nil && bestStep.Has("stage") {
			stage = bestStep.Stage()
		}
	}

	var linktype int
	if lt, ok := summ.Get("linktype"); ok {
		linktype = int(lt)
	} else {
		linktype = sess.ResolveDevLinktype(ifidx, reconstruct.Some(devGen))
	}
	return idbKey{netns: netns, ifindex: ifidx, devGen: devGen, stage: stage, linktype: linktype}
}

type epbRec struct {
	ts  uint64
	seq uint64
	raw []byte
}

// WritePcapng writes a valid multi-IDB .pcapng stream for an already-reconstructed
// session to w and returns the number of exported EPB packet blocks.
func WritePcapng(sess *reconstruct.Session, w io.Writer, redact bool, key string) (int, error) {
	var red *Redactor
	if redact {
		red = NewRedactor(key)
	}
	if _, err := w.Write(buildSHB(sess, redact)); err != nil {
		return 0, err
	}

	oids := make([]uint64, 0, len(sess.Objects))
	for oid := range sess.Objects {
		oids = append(oids, oid)
	}
	sort.Slice(oids, func(i, j int) bool { return oids[i] < oids[j] })

	idbMap := map[idbKey]uint32{}
	var idbBlocks [][]byte
	var epbs []epbRec

	for _, oid := range oids {
		obj := sess.Objects[oid]
		for _, summ := range obj.Summaries {
			hdr, ok := summ.Bytes("hdr_bytes")
			if !ok || len(hdr) == 0 {
				continue
			}
			k := inferSummaryHookContext(sess, obj, summ)
			ifID, exists := idbMap[k]
			if !exists {
				ifID = uint32(len(idbMap))
				idbMap[k] = ifID
				devName := sess.ResolveDevName(k.ifindex, reconstruct.Some(k.devGen), reconstruct.Some(k.netns))
				idbBlocks = append(idbBlocks, buildIDB(devName, k))
			}

			outHdr := hdr
			if red != nil {
				outHdr = red.RedactHdrBytes(hdr, k.linktype)
			}
			rtNs, errNs, isCal := sess.CalibrateBoottimeToRealtime(summ.TsNs)
			errTxt := "uncalibrated"
			if isCal {
				errTxt = fmt.Sprintf("%d", errNs)
			}
			evName, ok := wire.EvidenceNames[int(summ.EvidenceLevel)]
			if !ok {
				evName = fmt.Sprintf("%d", summ.EvidenceLevel)
			}
			evZH := wire.EvidenceLabelsZH[int(summ.EvidenceLevel)]
			snaplen := len(outHdr)
			origLen := uint32(snaplen)
			if pl := summ.U("pkt_len"); pl > 0 {
				origLen = uint32(pl)
			}
			var dirOpt reconstruct.OptU
			if d, ok := summ.Get("dir"); ok {
				dirOpt = reconstruct.Some(d)
			}
			comment := fmt.Sprintf("event_id=%s object_id=%d sample_id=%d evidence_level=%s(%d:%s) snaplen=%d clock_err_ns=%s",
				summ.EventID(), summ.ObjectID, obj.PrimarySampleID, evName, summ.EvidenceLevel, evZH, snaplen, errTxt)
			epb := buildEPB(ifID, rtNs, outHdr, origLen, dirOpt, comment)
			epbs = append(epbs, epbRec{ts: summ.TsNs, seq: summ.Seq, raw: epb})
		}
	}

	sort.SliceStable(epbs, func(i, j int) bool {
		if epbs[i].ts != epbs[j].ts {
			return epbs[i].ts < epbs[j].ts
		}
		return epbs[i].seq < epbs[j].seq
	})

	for _, b := range idbBlocks {
		if _, err := w.Write(b); err != nil {
			return 0, err
		}
	}
	for _, e := range epbs {
		if _, err := w.Write(e.raw); err != nil {
			return 0, err
		}
	}
	return len(epbs), nil
}

// ExportPcapng reconstructs sessionDir and writes a valid multi-IDB .pcapng file
// to outPath, returning the number of exported EPB packet blocks.
func ExportPcapng(sessionDir string, outPath string, redact bool, key string) (int, error) {
	sess, err := reconstruct.Open(sessionDir)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return 0, err
	}
	var buf bytes.Buffer
	n, err := WritePcapng(sess, &buf, redact, key)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		return 0, err
	}
	return n, nil
}
