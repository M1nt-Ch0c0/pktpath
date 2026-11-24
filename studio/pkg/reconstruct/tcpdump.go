package reconstruct

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"

	"pktpath/studio/pkg/wire"
)

const (
	linktypeEthernet = 1
	linktypeRaw      = 101
	linktypeLinuxSLL = 113
	linktypeIPv4     = 228
	linktypeIPv6     = 229
	linktypeSLL2     = 276
)

// PcapPacket is one dissected frame from a classic .pcap or .pcapng file.
type PcapPacket struct {
	FrameIndex    int
	RealtimeNs    int64
	CapturedLen   int
	OrigLen       int
	Linktype      int
	Direction     OptU // DirRX / DirTX when known
	Ifindex       OptU
	IPVersion     OptU
	IPTotalLen    OptU
	IPID          OptU
	FragOffset    int
	IsFragment    bool
	L4Proto       OptU
	SrcIP         string
	DstIP         string
	SrcPort       OptU
	DstPort       OptU
	TCPSeq        OptU
	TCPSeqEnd     OptU
	TCPFlags      OptU
	TCPPayloadLen OptU
	RawBytes      []byte
}

// TcpdumpCandidate is a strictly Level-3 (ANNOTATION) external capture match.
type TcpdumpCandidate struct {
	FrameIndex       int    `json:"frame_index"`
	RealtimeNs       int64  `json:"realtime_ns"`
	EstBoottimeNs    uint64 `json:"est_boottime_ns"`
	DeltaFromXmitNs  int64  `json:"delta_from_xmit_ns"`
	ClockErrNs       int64  `json:"clock_err_ns"`
	EvidenceLevel    int    `json:"evidence_level"`
	MatchKind        string `json:"match_kind"`
	IsBusyDuplicate  bool   `json:"is_busy_duplicate"`
	IsSuperframe     bool   `json:"is_superframe"`
	IsGSOSegment     bool   `json:"is_gso_segment"`
	AttemptIndex     *int   `json:"attempt_index,omitempty"`
	OrigLen          int    `json:"orig_len"`
	SrcIP            string `json:"src_ip,omitempty"`
	DstIP            string `json:"dst_ip,omitempty"`
	SrcPort          *uint64 `json:"src_port,omitempty"`
	DstPort          *uint64 `json:"dst_port,omitempty"`
	TCPSeq           *uint64 `json:"tcp_seq,omitempty"`
	TCPSeqEnd        *uint64 `json:"tcp_seq_end,omitempty"`
	Note             string `json:"note"`
}

func dissectFrame(idx int, rtNs int64, origLen, linktype int, raw []byte, epbDir OptU) PcapPacket {
	p := PcapPacket{
		FrameIndex:  idx,
		RealtimeNs:  rtNs,
		CapturedLen: len(raw),
		OrigLen:     origLen,
		Linktype:    linktype,
		Direction:   epbDir,
		RawBytes:    append([]byte(nil), raw...),
	}
	n := len(raw)
	pos := 0
	ethertype := -1

	switch linktype {
	case linktypeEthernet:
		if n >= 14 {
			ethertype = int(binary.BigEndian.Uint16(raw[12:14]))
			pos = 14
			for (ethertype == 0x8100 || ethertype == 0x88A8 || ethertype == 0x9100) && pos+4 <= n {
				ethertype = int(binary.BigEndian.Uint16(raw[pos+2 : pos+4]))
				pos += 4
			}
		}
	case linktypeRaw, linktypeIPv4, linktypeIPv6:
		if n >= 1 {
			switch raw[0] >> 4 {
			case 4:
				ethertype = 0x0800
			case 6:
				ethertype = 0x86DD
			}
		}
	case linktypeLinuxSLL:
		if n >= 16 {
			pkttype := binary.BigEndian.Uint16(raw[0:2])
			ethertype = int(binary.BigEndian.Uint16(raw[14:16]))
			pos = 16
			if pkttype == 4 {
				p.Direction = Some(wire.DirTX)
			} else if pkttype <= 2 {
				p.Direction = Some(wire.DirRX)
			}
		}
	case linktypeSLL2:
		if n >= 20 {
			ethertype = int(binary.BigEndian.Uint16(raw[0:2]))
			p.Ifindex = Some(uint64(binary.BigEndian.Uint32(raw[4:8])))
			pkttype := raw[10]
			pos = 20
			if pkttype == 4 {
				p.Direction = Some(wire.DirTX)
			} else if pkttype <= 2 {
				p.Direction = Some(wire.DirRX)
			}
		}
	}

	l4Expected := -1
	if ethertype == 0x0800 && pos+20 <= n {
		vihl := raw[pos]
		if vihl>>4 == 4 {
			ihl := int(vihl&0x0F) * 4
			if ihl >= 20 && pos+ihl <= n {
				p.IPVersion = Some(4)
				totLen := int(binary.BigEndian.Uint16(raw[pos+2 : pos+4]))
				if totLen <= 0 && origLen > pos {
					totLen = origLen - pos
				}
				p.IPTotalLen = Some(uint64(totLen))
				p.IPID = Some(uint64(binary.BigEndian.Uint16(raw[pos+4 : pos+6])))
				frag := binary.BigEndian.Uint16(raw[pos+6 : pos+8])
				p.FragOffset = int(frag&0x1FFF) * 8
				p.IsFragment = (frag&0x2000 != 0) || p.FragOffset > 0
				p.L4Proto = Some(uint64(raw[pos+9]))
				p.SrcIP = netip.AddrFrom4([4]byte(raw[pos+12 : pos+16])).String()
				p.DstIP = netip.AddrFrom4([4]byte(raw[pos+16 : pos+20])).String()
				if totLen >= ihl {
					l4Expected = totLen - ihl
				} else {
					l4Expected = 0
				}
				pos += ihl
			}
		}
	} else if ethertype == 0x86DD && pos+40 <= n {
		if raw[pos]>>4 == 6 {
			p.IPVersion = Some(6)
			plen := int(binary.BigEndian.Uint16(raw[pos+4 : pos+6]))
			if plen <= 0 && origLen > pos+40 {
				plen = origLen - pos - 40
			}
			p.IPTotalLen = Some(uint64(40 + plen))
			nxt := int(raw[pos+6])
			p.SrcIP = netip.AddrFrom16([16]byte(raw[pos+8 : pos+24])).String()
			p.DstIP = netip.AddrFrom16([16]byte(raw[pos+24 : pos+40])).String()
			pos += 40
			ext := 0
			for (nxt == 0 || nxt == 43 || nxt == 44 || nxt == 60) && pos+8 <= n {
				if nxt == 44 {
					nxtHdr := int(raw[pos])
					fo := binary.BigEndian.Uint16(raw[pos+2 : pos+4])
					p.FragOffset = int(fo & 0xFFF8)
					p.IsFragment = (fo&0x0001 != 0) || p.FragOffset > 0
					p.IPID = Some(uint64(binary.BigEndian.Uint32(raw[pos+4:pos+8]) & 0xFFFF))
					nxt = nxtHdr
					pos += 8
					ext += 8
				} else {
					nxtHdr := int(raw[pos])
					hlen := (int(raw[pos+1]) + 1) * 8
					if hlen <= 0 || pos+hlen > n {
						break
					}
					nxt = nxtHdr
					pos += hlen
					ext += hlen
				}
			}
			p.L4Proto = Some(uint64(nxt))
			if plen >= ext {
				l4Expected = plen - ext
			} else {
				l4Expected = 0
			}
		}
	}

	if p.IPVersion.OK && p.FragOffset == 0 && p.L4Proto.OK {
		switch p.L4Proto.V {
		case 6: // TCP
			if pos+14 <= n {
				p.SrcPort = Some(uint64(binary.BigEndian.Uint16(raw[pos : pos+2])))
				p.DstPort = Some(uint64(binary.BigEndian.Uint16(raw[pos+2 : pos+4])))
				seq := binary.BigEndian.Uint32(raw[pos+4 : pos+8])
				thl := int((raw[pos+12]>>4)&0x0F) * 4
				if thl < 20 {
					thl = 20
				}
				p.TCPSeq = Some(uint64(seq))
				p.TCPFlags = Some(uint64(raw[pos+13]))
				if l4Expected >= 0 {
					pay := 0
					if l4Expected > thl {
						pay = l4Expected - thl
					}
					p.TCPPayloadLen = Some(uint64(pay))
					p.TCPSeqEnd = Some(uint64(uint32(int64(seq) + int64(pay))))
				}
			}
		case 17: // UDP
			if pos+8 <= n {
				p.SrcPort = Some(uint64(binary.BigEndian.Uint16(raw[pos : pos+2])))
				p.DstPort = Some(uint64(binary.BigEndian.Uint16(raw[pos+2 : pos+4])))
			}
		}
	}
	return p
}

// ParseCaptureBytes parses classic .pcap or .pcapng bytes into dissected packets.
func ParseCaptureBytes(data []byte) ([]PcapPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("capture buffer too small (%d B)", len(data))
	}
	m := binary.LittleEndian.Uint32(data[0:4])
	switch m {
	case 0xA1B2C3D4:
		return parseClassicPcap(data, binary.LittleEndian, 1000)
	case 0xD4C3B2A1:
		return parseClassicPcap(data, binary.BigEndian, 1000)
	case 0xA1B23C4D:
		return parseClassicPcap(data, binary.LittleEndian, 1)
	case 0x4D3CB2A1:
		return parseClassicPcap(data, binary.BigEndian, 1)
	case 0x0A0D0D0A:
		return parsePcapngBytes(data)
	}
	return nil, fmt.Errorf("unrecognized capture magic 0x%08x", m)
}

// ParseCaptureFile reads and parses a .pcap or .pcapng file on disk.
func ParseCaptureFile(path string) ([]PcapPacket, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCaptureBytes(b)
}

func parseClassicPcap(data []byte, bo binary.ByteOrder, subToNs int64) ([]PcapPacket, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("truncated classic pcap header")
	}
	linktype := int(bo.Uint32(data[20:24]))
	pos := 24
	idx := 0
	var out []PcapPacket
	for pos+16 <= len(data) {
		sec := int64(bo.Uint32(data[pos : pos+4]))
		sub := int64(bo.Uint32(data[pos+4 : pos+8]))
		incl := int(bo.Uint32(data[pos+8 : pos+12]))
		orig := int(bo.Uint32(data[pos+12 : pos+16]))
		pos += 16
		if incl < 0 || pos+incl > len(data) {
			break
		}
		raw := data[pos : pos+incl]
		pos += incl
		idx++
		out = append(out, dissectFrame(idx, sec*1_000_000_000+sub*subToNs, orig, linktype, raw, OptU{}))
	}
	return out, nil
}

func decodeTsResol(b byte) (uint64, uint64) {
	p := uint(b & 0x7F)
	if b&0x80 != 0 {
		if p > 62 {
			p = 62
		}
		return 1_000_000_000, 1 << p
	}
	if p <= 9 {
		n := uint64(1)
		for i := uint(0); i < 9-p; i++ {
			n *= 10
		}
		return n, 1
	}
	d := uint64(1)
	for i := uint(0); i < p-9 && i < 18; i++ {
		d *= 10
	}
	return 1, d
}

func parsePcapngBytes(data []byte) ([]PcapPacket, error) {
	var bo binary.ByteOrder = binary.LittleEndian
	type ifInfo struct {
		lt       int
		num, den uint64
	}
	var ifaces []ifInfo
	var out []PcapPacket
	pos, n, idx := 0, len(data), 0

	for pos+12 <= n {
		if binary.LittleEndian.Uint32(data[pos:pos+4]) == 0x0A0D0D0A {
			if pos+16 > n {
				break
			}
			bom := binary.LittleEndian.Uint32(data[pos+8 : pos+12])
			switch bom {
			case 0x1A2B3C4D:
				bo = binary.LittleEndian
			case 0x4D3C2B1A:
				bo = binary.BigEndian
			default:
				return nil, fmt.Errorf("invalid pcapng BOM 0x%08x", bom)
			}
			ifaces = nil
		}
		btype := bo.Uint32(data[pos : pos+4])
		blen := int(bo.Uint32(data[pos+4 : pos+8]))
		if blen < 12 || pos+blen > n {
			break
		}
		bs, be := pos+8, pos+blen-4
		switch btype {
		case 0x00000001: // IDB
			if bs+8 <= be {
				lt := int(bo.Uint16(data[bs : bs+2]))
				num, den := uint64(1000), uint64(1)
				op := bs + 8
				for op+4 <= be {
					oc := bo.Uint16(data[op : op+2])
					ol := int(bo.Uint16(data[op+2 : op+4]))
					op += 4
					if oc == 0 {
						break
					}
					if oc == 9 && ol >= 1 && op < be {
						num, den = decodeTsResol(data[op])
					}
					op += (ol + 3) &^ 3
				}
				ifaces = append(ifaces, ifInfo{lt, num, den})
			}
		case 0x00000006: // EPB
			if bs+20 <= be {
				ifID := int(bo.Uint32(data[bs : bs+4]))
				tsH := uint64(bo.Uint32(data[bs+4 : bs+8]))
				tsL := uint64(bo.Uint32(data[bs+8 : bs+12]))
				capL := int(bo.Uint32(data[bs+12 : bs+16]))
				origL := int(bo.Uint32(data[bs+16 : bs+20]))
				ps := bs + 20
				if capL >= 0 && ps+capL <= be {
					raw := data[ps : ps+capL]
					op := ps + ((capL + 3) &^ 3)
					var dir OptU
					for op+4 <= be {
						oc := bo.Uint16(data[op : op+2])
						ol := int(bo.Uint16(data[op+2 : op+4]))
						op += 4
						if oc == 0 {
							break
						}
						if oc == 2 && ol >= 4 && op+4 <= be {
							switch bo.Uint32(data[op:op+4]) & 0x03 {
							case 1:
								dir = Some(wire.DirRX)
							case 2:
								dir = Some(wire.DirTX)
							}
						}
						op += (ol + 3) &^ 3
					}
					ii := ifInfo{linktypeEthernet, 1000, 1}
					if ifID >= 0 && ifID < len(ifaces) {
						ii = ifaces[ifID]
					}
					ts64 := (tsH << 32) | tsL
					// Compute (ts64 * num) / den avoiding uint64 overflow when num==1 and ts64 is ~1.8e18 ns.
					var rtNs int64
					if ii.num == 1 && ii.den == 1 {
						rtNs = int64(ts64)
					} else {
						rtNs = int64((ts64 / ii.den) * ii.num + ((ts64%ii.den)*ii.num)/ii.den)
					}
					idx++
					out = append(out, dissectFrame(idx, rtNs, origL, ii.lt, raw, dir))
				}
			}
		case 0x00000003: // SPB
			if bs+4 <= be {
				origL := int(bo.Uint32(data[bs : bs+4]))
				lt := linktypeEthernet
				if len(ifaces) > 0 {
					lt = ifaces[0].lt
				}
				idx++
				out = append(out, dissectFrame(idx, 0, origL, lt, data[bs+4:be], OptU{}))
			}
		}
		pos += blen
	}
	return out, nil
}

func tcpSeqLE(a, b uint32) bool { return (b - a) < 0x80000000 }

func tcpRangesOverlap(s1, e1, s2, e2 uint32) bool {
	if s1 == s2 {
		return true
	}
	if e1 == s1 {
		return tcpSeqLE(s2, s1) && tcpSeqLE(s1, e2)
	}
	if e2 == s2 {
		return tcpSeqLE(s1, s2) && tcpSeqLE(s2, e1)
	}
	return tcpSeqLE(s1, e2) && s1 != e2 && tcpSeqLE(s2, e1) && s2 != e1
}

// AttachTcpdumpCandidates attaches external capture frames strictly as Level-3
// ANNOTATIONs without ever mutating DAG edges, objects, or completeness.
func (s *Session) AttachTcpdumpCandidates(packets []PcapPacket, windowMarginNs int64) []*TcpdumpCandidate {
	if windowMarginNs <= 0 {
		windowMarginNs = 50_000_000
	}
	var all []*TcpdumpCandidate
	for _, br := range s.Branches {
		cands := s.matchBranchPackets(br, packets, windowMarginNs)
		br.Tcpdump = cands
		all = append(all, cands...)
	}
	return all
}

func (s *Session) matchBranchPackets(br *BranchPath, packets []PcapPacket, marginNs int64) []*TcpdumpCandidate {
	if len(br.Summaries) == 0 {
		return nil
	}
	rtStart, errS, isCal := s.CalibrateBoottimeToRealtime(br.StartTsNs)
	rtEnd, errE, _ := s.CalibrateBoottimeToRealtime(br.EndTsNs)
	errNs := errS
	if errE > errNs {
		errNs = errE
	}
	winLo := rtStart - errNs - marginNs
	winHi := rtEnd + errNs + marginNs

	var xmits []*wire.Event
	busy := br.RequeueCount > 0
	for _, st := range br.Steps {
		switch st.Stage() {
		case wire.StageXmitStart:
			xmits = append(xmits, st)
		case wire.StageXmitRet:
			if rc, ok := st.I("raw_ret"); ok && rc == NetdevTxBusy {
				busy = true
			}
		}
	}
	if len(xmits) > 1 {
		busy = true
	}
	anchorBt := br.EndTsNs
	if len(xmits) > 0 {
		anchorBt = xmits[len(xmits)-1].TsNs
	}
	anchorRt, _, _ := s.CalibrateBoottimeToRealtime(anchorBt)

	type hit struct {
		pkt            PcapPacket
		super, gsoSeg  bool
	}
	var hits []hit
	seen := map[int]bool{}

	for _, pkt := range packets {
		if seen[pkt.FrameIndex] {
			continue
		}
		if pkt.RealtimeNs > 0 && (pkt.RealtimeNs < winLo || pkt.RealtimeNs > winHi) {
			continue
		}
		for _, summ := range br.Summaries {
			if sd, ok := summ.Get("dir"); ok && pkt.Direction.OK && (sd == wire.DirRX || sd == wire.DirTX) && pkt.Direction.V != sd {
				continue
			}
			if iv, ok := summ.Get("ip_version"); ok && (!pkt.IPVersion.OK || pkt.IPVersion.V != iv) {
				continue
			}
			proto, hasProto := summ.Get("l4_proto")
			if hasProto && (!pkt.L4Proto.OK || pkt.L4Proto.V != proto) {
				continue
			}
			if sip, ok := summ.Str("src_ip"); ok && pkt.SrcIP != sip {
				continue
			}
			if dip, ok := summ.Str("dst_ip"); ok && pkt.DstIP != dip {
				continue
			}
			if hasProto && (proto == 6 || proto == 17) {
				if sp, ok := summ.Get("src_port"); ok && (!pkt.SrcPort.OK || pkt.SrcPort.V != sp) {
					continue
				}
				if dp, ok := summ.Get("dst_port"); ok && (!pkt.DstPort.OK || pkt.DstPort.V != dp) {
					continue
				}
			}
			sLen := int(summ.U("pkt_len"))
			isSuper, isSeg := false, false
			if hasProto && proto == 6 {
				if bs, ok := summ.Get("tcp_seq"); ok && pkt.TCPSeq.OK {
					be := bs
					if bev, ok2 := summ.Get("tcp_seq_end"); ok2 && bev != 0 {
						be = bev
					}
					ps := uint32(pkt.TCPSeq.V)
					pe := ps
					if pkt.TCPSeqEnd.OK {
						pe = uint32(pkt.TCPSeqEnd.V)
					}
					if !tcpRangesOverlap(uint32(bs), uint32(be), ps, pe) {
						continue
					}
					bSpan := uint32(be) - uint32(bs)
					pSpan := pe - ps
					if pSpan > bSpan && bSpan > 0 {
						isSuper = true
					} else if bSpan > pSpan && pSpan > 0 {
						isSeg = true
					}
				}
			}
			if sLen > 0 && pkt.IPTotalLen.OK {
				if int(pkt.IPTotalLen.V) > sLen+32 {
					isSuper = true
				} else if sLen > pkt.OrigLen+32 {
					isSeg = true
				}
			}
			seen[pkt.FrameIndex] = true
			hits = append(hits, hit{pkt, isSuper, isSeg})
			break
		}
	}

	multi := len(hits) > 1
	var out []*TcpdumpCandidate
	for i, h := range hits {
		attempt := i + 1
		estBt := anchorBt
		var delta int64
		if isCal || h.pkt.RealtimeNs > 0 {
			delta = h.pkt.RealtimeNs - anchorRt
			if int64(anchorBt)+delta > 0 {
				estBt = uint64(int64(anchorBt) + delta)
			}
		}
		isBusyDup := busy && multi && !h.gsoSeg
		var mkind, note string
		switch {
		case isBusyDup:
			mkind = "XMIT_BUSY_DUPLICATE"
			note = fmt.Sprintf("xmit_one()/dev_queue_xmit_nit() BUSY 重试产生第 %d/%d 条外部抓包副本 (仅作辅助旁注，不新建对象身份)", attempt, len(hits))
		case h.super:
			mkind = "GSO_GRO_SUPERFRAME"
			note = "外部 pcap 捕获到 GSO/GRO 聚合超大帧 (仅作辅助旁注)"
		case h.gsoSeg:
			mkind = "GSO_SEGMENT_FRAME"
			note = "外部 pcap 捕获到分段后子帧 (仅作辅助旁注)"
		case multi:
			mkind = "AMBIGUOUS_MULTI_CANDIDATE"
			note = fmt.Sprintf("同五元组/序号存在 %d 个候选帧 (#%d/%d，仅作辅助旁注，不反向连边)", len(hits), attempt, len(hits))
		default:
			mkind = "EXACT_CANDIDATE"
			note = "外部 tcpdump 候选匹配 (仅作辅助旁注)"
		}
		var attPtr *int
		if isBusyDup {
			a := attempt
			attPtr = &a
		}
		out = append(out, &TcpdumpCandidate{
			FrameIndex:      h.pkt.FrameIndex,
			RealtimeNs:      h.pkt.RealtimeNs,
			EstBoottimeNs:   estBt,
			DeltaFromXmitNs: delta,
			ClockErrNs:      errNs,
			EvidenceLevel:   int(wire.EvidenceAnnotation),
			MatchKind:       mkind,
			IsBusyDuplicate: isBusyDup,
			IsSuperframe:    h.super,
			IsGSOSegment:    h.gsoSeg,
			AttemptIndex:    attPtr,
			OrigLen:         h.pkt.OrigLen,
			SrcIP:           h.pkt.SrcIP,
			DstIP:           h.pkt.DstIP,
			SrcPort:         optPtr(h.pkt.SrcPort),
			DstPort:         optPtr(h.pkt.DstPort),
			TCPSeq:          optPtr(h.pkt.TCPSeq),
			TCPSeqEnd:       optPtr(h.pkt.TCPSeqEnd),
			Note:            note,
		})
	}
	return out
}
