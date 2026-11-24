// Package export implements pure-Go multi-IDB .pcapng export and keyed
// HMAC-SHA256 session redaction (matching analyzer/pcapng_export.py & redact.py).
package export

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"pktpath/studio/pkg/wire"
)

// Redactor deterministically anonymizes IPs, ports, UIDs, MACs, and L3/L4 headers
// within a single run using keyed HMAC-SHA256 truncation.
type Redactor struct {
	key []byte
}

// NewRedactor creates a Redactor from key. When key is empty, a fresh 32-byte
// cryptographic random key is generated for this run.
func NewRedactor(key string) *Redactor {
	k := make([]byte, 32)
	if key == "" {
		_, _ = rand.Read(k)
	} else {
		sum := sha256.Sum256([]byte(key))
		copy(k, sum[:])
	}
	return &Redactor{key: k}
}

func (r *Redactor) prf(domain string, data []byte) []byte {
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(domain))
	mac.Write([]byte(":"))
	mac.Write(data)
	return mac.Sum(nil)
}

// RedactIPBytes anonymizes a 4-byte IPv4 or 16-byte IPv6 address.
func (r *Redactor) RedactIPBytes(ip []byte) []byte {
	switch len(ip) {
	case 4:
		d := r.prf("ipv4", ip)
		out := []byte{d[0], d[1], d[2], d[3]}
		if out[0] == 0 || out[0] == 127 || out[0] >= 224 {
			out[0] = 10
		}
		if bytes.Equal(out, ip) {
			out[3] ^= 0x01
		}
		return out
	case 16:
		d := r.prf("ipv6", ip)
		out := make([]byte, 16)
		out[0] = 0xFD // ULA fd00::/8
		copy(out[1:16], d[:15])
		if bytes.Equal(out, ip) {
			out[15] ^= 0x01
		}
		return out
	default:
		return append([]byte(nil), ip...)
	}
}

// RedactIPStr anonymizes an IPv4 or IPv6 literal string.
func (r *Redactor) RedactIPStr(s string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	if addr.Is4() {
		b4 := addr.As4()
		rb := r.RedactIPBytes(b4[:])
		return netip.AddrFrom4([4]byte(rb)).String(), nil
	}
	b16 := addr.As16()
	rb := r.RedactIPBytes(b16[:])
	return netip.AddrFrom16([16]byte(rb)).String(), nil
}

// RedactPort anonymizes a TCP/UDP port (preserving 0).
func (r *Redactor) RedactPort(port uint16) uint16 {
	if port == 0 {
		return 0
	}
	var pb [2]byte
	binary.LittleEndian.PutUint16(pb[:], port)
	d := r.prf("port", pb[:])
	v := uint16(1024 + (int(binary.LittleEndian.Uint16(d[:2])) % 64511))
	if v == port {
		v = uint16(1024 + ((int(v) - 1024 + 1) % 64511))
	}
	return v
}

// RedactUID anonymizes a Linux/Android UID (preserving 0xFFFFFFFF wildcard).
func (r *Redactor) RedactUID(uid uint32) uint32 {
	if uid == 0xFFFFFFFF {
		return uid
	}
	var ub [4]byte
	binary.LittleEndian.PutUint32(ub[:], uid)
	d := r.prf("uid", ub[:])
	v := uint32(100000 + (uint64(binary.LittleEndian.Uint32(d[:4])) % 800000))
	if v == uid {
		v++
	}
	return v
}

// RedactHdrBytes anonymizes MACs, IPv4/IPv6 addresses, TCP/UDP ports, and zeros
// L4 payload bytes in captured packet headers.
func (r *Redactor) RedactHdrBytes(hdr []byte, linktype int) []byte {
	buf := append([]byte(nil), hdr...)
	n := len(buf)
	pos := 0
	ethertype := -1

	switch linktype {
	case wire.LinkTypeEthernet:
		if n < 14 {
			return buf
		}
		dstH := r.prf("mac", buf[0:6])
		srcH := r.prf("mac", buf[6:12])
		buf[0] = (buf[0] & 0x01) | 0x02
		copy(buf[1:6], dstH[:5])
		buf[6] = (buf[6] & 0x01) | 0x02
		copy(buf[7:12], srcH[:5])
		ethertype = int(binary.BigEndian.Uint16(buf[12:14]))
		pos = 14
		for (ethertype == 0x8100 || ethertype == 0x88A8 || ethertype == 0x9100) && pos+4 <= n {
			ethertype = int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
			pos += 4
		}
	case wire.LinkTypeRawIP:
		if n >= 1 {
			switch buf[0] >> 4 {
			case 4:
				ethertype = 0x0800
			case 6:
				ethertype = 0x86DD
			}
		}
	}

	l4Proto := -1
	fragOff := 0

	if ethertype == 0x0800 && pos+20 <= n {
		ihl := int(buf[pos]&0x0F) * 4
		if ihl >= 20 && pos+ihl <= n {
			l4Proto = int(buf[pos+9])
			fragField := binary.BigEndian.Uint16(buf[pos+6 : pos+8])
			fragOff = int(fragField&0x1FFF) * 8
			copy(buf[pos+12:pos+16], r.RedactIPBytes(buf[pos+12:pos+16]))
			copy(buf[pos+16:pos+20], r.RedactIPBytes(buf[pos+16:pos+20]))
			buf[pos+10], buf[pos+11] = 0, 0
			pos += ihl
		}
	} else if ethertype == 0x86DD && pos+40 <= n {
		nxt := int(buf[pos+6])
		copy(buf[pos+8:pos+24], r.RedactIPBytes(buf[pos+8:pos+24]))
		copy(buf[pos+24:pos+40], r.RedactIPBytes(buf[pos+24:pos+40]))
		pos += 40
		for (nxt == 0 || nxt == 43 || nxt == 44 || nxt == 60) && pos+8 <= n {
			if nxt == 44 {
				nxtHdr := int(buf[pos])
				fragOffM := binary.BigEndian.Uint16(buf[pos+2 : pos+4])
				fragOff = int(fragOffM & 0xFFF8)
				nxt = nxtHdr
				pos += 8
			} else {
				nxtHdr := int(buf[pos])
				hlen := (int(buf[pos+1]) + 1) * 8
				if hlen <= 0 || pos+hlen > n {
					break
				}
				nxt = nxtHdr
				pos += hlen
			}
		}
		l4Proto = nxt
	}

	if l4Proto >= 0 && fragOff == 0 {
		switch l4Proto {
		case 6: // TCP
			if pos+4 <= n {
				sp := binary.BigEndian.Uint16(buf[pos : pos+2])
				dp := binary.BigEndian.Uint16(buf[pos+2 : pos+4])
				binary.BigEndian.PutUint16(buf[pos:pos+2], r.RedactPort(sp))
				binary.BigEndian.PutUint16(buf[pos+2:pos+4], r.RedactPort(dp))
				if pos+18 <= n {
					buf[pos+16], buf[pos+17] = 0, 0
				}
				doff := 20
				if pos+13 <= n {
					if d := int((buf[pos+12]>>4)&0x0F) * 4; d > 20 {
						doff = d
					}
				}
				for k := pos + doff; k < n; k++ {
					buf[k] = 0
				}
			}
		case 17: // UDP
			if pos+4 <= n {
				sp := binary.BigEndian.Uint16(buf[pos : pos+2])
				dp := binary.BigEndian.Uint16(buf[pos+2 : pos+4])
				binary.BigEndian.PutUint16(buf[pos:pos+2], r.RedactPort(sp))
				binary.BigEndian.PutUint16(buf[pos+2:pos+4], r.RedactPort(dp))
				if pos+8 <= n {
					buf[pos+6], buf[pos+7] = 0, 0
				}
				for k := pos + 8; k < n; k++ {
					buf[k] = 0
				}
			}
		}
	}
	return buf
}

// RedactEvent returns a redacted clone of a SUMMARY event (non-SUMMARY events are returned unchanged).
func (r *Redactor) RedactEvent(ev *wire.Event, defaultLinktype int) *wire.Event {
	if ev.Kind != wire.KindSummary {
		return ev
	}
	out := ev.Clone()
	ltype := defaultLinktype
	if lt, ok := ev.Get("linktype"); ok && lt != 0 {
		ltype = int(lt)
	}
	newTLVs := make([]wire.TLV, 0, len(ev.RawTLVs))
	for _, t := range ev.RawTLVs {
		base := t.Tag & 0x7FFF
		switch {
		case base == wire.TLVSumSrcIP && (len(t.Val) == 4 || len(t.Val) == 16):
			rv := r.RedactIPBytes(t.Val)
			newTLVs = append(newTLVs, wire.TLV{Tag: t.Tag, Val: rv})
			out.SetBytes("src_ip_raw", rv)
			out.SetStr("src_ip", wire.FormatIP(rv))
		case base == wire.TLVSumDstIP && (len(t.Val) == 4 || len(t.Val) == 16):
			rv := r.RedactIPBytes(t.Val)
			newTLVs = append(newTLVs, wire.TLV{Tag: t.Tag, Val: rv})
			out.SetBytes("dst_ip_raw", rv)
			out.SetStr("dst_ip", wire.FormatIP(rv))
		case base == wire.TLVSumSrcPort && len(t.Val) == 2:
			rp := r.RedactPort(binary.LittleEndian.Uint16(t.Val))
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], rp)
			newTLVs = append(newTLVs, wire.TLV{Tag: t.Tag, Val: b[:]})
			out.SetNum("src_port", uint64(rp))
		case base == wire.TLVSumDstPort && len(t.Val) == 2:
			rp := r.RedactPort(binary.LittleEndian.Uint16(t.Val))
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], rp)
			newTLVs = append(newTLVs, wire.TLV{Tag: t.Tag, Val: b[:]})
			out.SetNum("dst_port", uint64(rp))
		case base == wire.TLVSumUID && len(t.Val) == 4:
			ru := r.RedactUID(binary.LittleEndian.Uint32(t.Val))
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], ru)
			newTLVs = append(newTLVs, wire.TLV{Tag: t.Tag, Val: b[:]})
			out.SetNum("uid", uint64(ru))
		case base == wire.TLVSumHdrBytes:
			rh := r.RedactHdrBytes(t.Val, ltype)
			newTLVs = append(newTLVs, wire.TLV{Tag: t.Tag, Val: rh})
			out.SetBytes("hdr_bytes", rh)
		default:
			newTLVs = append(newTLVs, wire.TLV{Tag: t.Tag, Val: append([]byte(nil), t.Val...)})
		}
	}
	out.RawTLVs = newTLVs
	return out
}

func cloneJSONMap(m map[string]any) map[string]any {
	raw, err := json.Marshal(m)
	if err != nil {
		return map[string]any{}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out map[string]any
	_ = dec.Decode(&out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

// RedactSession reads inDir, anonymizes IPs/ports/UIDs/captured headers, and writes
// a valid CRC32-checked session directory into outDir.
func RedactSession(inDir, outDir, key string) error {
	srcAbs, err := filepath.Abs(inDir)
	if err != nil {
		return err
	}
	dstAbs, err := filepath.Abs(outDir)
	if err != nil {
		return err
	}
	if strings.EqualFold(filepath.Clean(srcAbs), filepath.Clean(dstAbs)) {
		return fmt.Errorf("outDir must be distinct from input session directory")
	}
	loaded, err := wire.LoadSession(srcAbs, false)
	if err != nil {
		return err
	}
	red := NewRedactor(key)
	if err := os.MkdirAll(dstAbs, 0o755); err != nil {
		return err
	}

	redManifest := cloneJSONMap(loaded.Manifest)
	redManifest["redacted"] = true
	redManifest["redaction_scheme"] = "hmac-sha256-trunc-v1"
	if flt, ok := redManifest["filters"].(map[string]any); ok {
		for _, k := range []string{"src_ip", "dst_ip"} {
			if s, ok := flt[k].(string); ok && s != "" {
				ipPart := strings.SplitN(s, "/", 2)[0]
				if rs, err := red.RedactIPStr(ipPart); err == nil {
					flt[k] = rs
				}
			}
		}
		for _, k := range []string{"src_port", "dst_port"} {
			if v, ok := flt[k]; ok && v != nil {
				if p, ok2 := wire.AsInt(v); ok2 {
					flt[k] = red.RedactPort(uint16(p))
				}
			}
		}
		if v, ok := flt["uid"]; ok && v != nil {
			if u, ok2 := wire.AsInt(v); ok2 {
				flt["uid"] = red.RedactUID(uint32(u))
			}
		}
	}

	manBytes, err := json.MarshalIndent(redManifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dstAbs, "manifest.json"), manBytes, 0o644); err != nil {
		return err
	}

	srcDict := filepath.Join(srcAbs, "dict.json")
	if b, err := os.ReadFile(srcDict); err == nil {
		if err := os.WriteFile(filepath.Join(dstAbs, "dict.json"), b, 0o644); err != nil {
			return err
		}
	} else {
		db, err := json.MarshalIndent(loaded.Dictionary, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dstAbs, "dict.json"), db, 0o644); err != nil {
			return err
		}
	}

	devLinktypes := map[uint64]int{}
	if eps, ok := loaded.Dictionary["topology_epochs"].([]any); ok {
		for _, ep := range eps {
			em, _ := ep.(map[string]any)
			devs, _ := em["devices"].([]any)
			for _, dv := range devs {
				dm, _ := dv.(map[string]any)
				ifx, ok1 := wire.AsInt(dm["ifindex"])
				lt, ok2 := wire.AsInt(dm["linktype"])
				if ok1 && ok2 {
					devLinktypes[uint64(ifx)] = int(lt)
				}
			}
		}
	}

	for idx, blk := range loaded.Blocks {
		var payload []byte
		if blk.MetaPayload != nil {
			payload, err = json.Marshal(blk.MetaPayload)
			if err != nil {
				return err
			}
		} else {
			var buf bytes.Buffer
			for _, ev := range blk.Events {
				if ev.Kind == wire.KindSummary {
					defLT := wire.LinkTypeEthernet
					if lt, ok := devLinktypes[ev.U("ifindex")]; ok {
						defLT = lt
					}
					rev := red.RedactEvent(ev, defLT)
					buf.Write(wire.EncodeEvent(rev, nil))
				} else {
					buf.Write(wire.EncodeEvent(ev, nil))
				}
			}
			payload = buf.Bytes()
		}
		nh := blk.Header
		nh.Flags &^= wire.BlockFlagZstd
		nh.PayloadLen = uint32(len(payload))
		rawBlk, err := wire.EncodeBlock(nh, payload)
		if err != nil {
			return err
		}
		outName := blk.SourceFile
		if outName == "" {
			outName = fmt.Sprintf("block_%06d.pktb", idx)
		}
		if err := os.WriteFile(filepath.Join(dstAbs, outName), rawBlk, 0o644); err != nil {
			return err
		}
	}
	return nil
}
