package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// Sentinel error kinds. Every decode error satisfies errors.Is(err, ErrWire).
var (
	ErrWire            = errors.New("pktpath wire error")
	ErrMagic           = errors.New("invalid block magic")
	ErrVersion         = errors.New("incompatible wire major version")
	ErrPayloadTooLarge = errors.New("block payload exceeds 16 MiB cap")
	ErrCRC             = errors.New("block CRC32 mismatch")
	ErrTruncated       = errors.New("truncated wire data")
	ErrUUIDMismatch    = errors.New("session UUID mismatch")
	ErrZstdUnsupported = errors.New("ZSTD-compressed block payloads are not supported")
)

// Error is a typed wire error carrying a sentinel kind and a detailed message.
type Error struct {
	Kind error
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Is makes errors.Is match both the specific kind and the generic ErrWire.
func (e *Error) Is(target error) bool { return target == ErrWire || target == e.Kind }

// Unwrap returns the sentinel kind.
func (e *Error) Unwrap() error { return e.Kind }

func werr(kind error, format string, args ...any) error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

// TLV is one raw (tag, value) pair as found on the wire.
type TLV struct {
	Tag uint16
	Val []byte
}

// UnknownTLV is a TLV the decoder did not understand (or with an unexpected length).
type UnknownTLV struct {
	Tag            uint16 `json:"tag"`
	Length         uint16 `json:"len"`
	Raw            []byte `json:"-"`
	MustUnderstand bool   `json:"must_understand"`
}

// RawHex returns the hex-encoded raw TLV value.
func (u UnknownTLV) RawHex() string { return hex.EncodeToString(u.Raw) }

// TagHex returns the tag formatted as 0x%04x.
func (u UnknownTLV) TagHex() string { return fmt.Sprintf("0x%04x", u.Tag) }

// Event is one decoded pkt_event_hdr_v1 plus its TLV fields.
type Event struct {
	TotalLen      uint16
	Kind          uint16
	ObjectType    uint8
	EvidenceLevel uint8
	SiteDictIdx   uint16
	CPU           uint32
	Flags         uint32
	Seq           uint64
	TsNs          uint64
	ObjectID      uint64
	ProducerType  uint16
	Epoch         uint32
	BlockNo       uint32

	// Decoded fields keyed by the same names as wire.py (e.g. "stage", "ifindex").
	// Scalars are stored as uint64 (s32 values are sign-extended).
	nums map[string]uint64
	strs map[string]string
	bins map[string][]byte

	RawTLVs         []TLV
	UnknownOptional []UnknownTLV
	UnknownMust     []UnknownTLV
}

// EventID returns the canonical "p<prod>:c<cpu>:s<seq>" identifier.
func (e *Event) EventID() string {
	return fmt.Sprintf("p%d:c%d:s%d", e.ProducerType, e.CPU, e.Seq)
}

// DedupKey is the (producer_type, cpu, seq) identity.
type DedupKey struct {
	Producer uint16
	CPU      uint32
	Seq      uint64
}

// DedupKey returns the deduplication key of the event.
func (e *Event) DedupKey() DedupKey { return DedupKey{e.ProducerType, e.CPU, e.Seq} }

// Get returns a scalar field and whether it is present.
func (e *Event) Get(name string) (uint64, bool) {
	v, ok := e.nums[name]
	return v, ok
}

// U returns a scalar field or 0 when absent (Python `int(ev.get(k, 0) or 0)`).
func (e *Event) U(name string) uint64 { return e.nums[name] }

// I returns a scalar field interpreted as signed int64 (for raw_ret).
func (e *Event) I(name string) (int64, bool) {
	v, ok := e.nums[name]
	return int64(v), ok
}

// Has reports whether any field with this name exists.
func (e *Event) Has(name string) bool {
	if _, ok := e.nums[name]; ok {
		return true
	}
	if _, ok := e.strs[name]; ok {
		return true
	}
	_, ok := e.bins[name]
	return ok
}

// Str returns a string field (src_ip, dst_ip, comm).
func (e *Event) Str(name string) (string, bool) {
	v, ok := e.strs[name]
	return v, ok
}

// Bytes returns a binary field (hdr_bytes, src_ip_raw, dst_ip_raw, comm_raw).
func (e *Event) Bytes(name string) ([]byte, bool) {
	v, ok := e.bins[name]
	return v, ok
}

// Stage returns the STEP stage (0 if absent).
func (e *Event) Stage() int { return int(e.nums["stage"]) }

// SetNum sets a scalar field (used by redaction & synthetic builders).
func (e *Event) SetNum(name string, v uint64) {
	if e.nums == nil {
		e.nums = map[string]uint64{}
	}
	e.nums[name] = v
}

// SetStr sets a string field.
func (e *Event) SetStr(name, v string) {
	if e.strs == nil {
		e.strs = map[string]string{}
	}
	e.strs[name] = v
}

// SetBytes sets a binary field.
func (e *Event) SetBytes(name string, v []byte) {
	if e.bins == nil {
		e.bins = map[string][]byte{}
	}
	e.bins[name] = v
}

// Clone returns a deep-enough copy of the event (maps and slices duplicated).
func (e *Event) Clone() *Event {
	c := *e
	c.nums = make(map[string]uint64, len(e.nums))
	for k, v := range e.nums {
		c.nums[k] = v
	}
	c.strs = make(map[string]string, len(e.strs))
	for k, v := range e.strs {
		c.strs[k] = v
	}
	c.bins = make(map[string][]byte, len(e.bins))
	for k, v := range e.bins {
		c.bins[k] = append([]byte(nil), v...)
	}
	c.RawTLVs = make([]TLV, len(e.RawTLVs))
	for i, t := range e.RawTLVs {
		c.RawTLVs[i] = TLV{Tag: t.Tag, Val: append([]byte(nil), t.Val...)}
	}
	c.UnknownOptional = append([]UnknownTLV(nil), e.UnknownOptional...)
	c.UnknownMust = append([]UnknownTLV(nil), e.UnknownMust...)
	return &c
}

// BlockHeader is a decoded pkt_block_hdr_v1.
type BlockHeader struct {
	Magic        uint32
	Major        uint16
	Minor        uint16
	BlockType    uint16
	ProducerType uint16
	Flags        uint32
	PayloadLen   uint32
	Epoch        uint32
	BlockNo      uint32
	Reserved     uint32
	SessionUUID  [16]byte
	MinTsNs      uint64
	MaxTsNs      uint64
}

// BlockRecord is one validated block.
type BlockRecord struct {
	Header      BlockHeader
	CRC32       uint32
	Events      []*Event
	MetaPayload map[string]any // JSON payload for DICT_DELTA / END_MARKER / QUALITY_CHECKPOINT
	SourceFile  string
}

// LoadedSession is the result of LoadSession.
type LoadedSession struct {
	RunDir                    string
	Manifest                  map[string]any
	Dictionary                map[string]any
	SessionUUID               [16]byte
	Blocks                    []*BlockRecord
	Events                    []*Event
	HasEndMarker              bool
	HasCorruptedTail          bool
	TailErrors                []string
	LastQualityCheckpointTsNs uint64
}

// UncleanTail is true when END_MARKER is missing or the tail was corrupted.
func (l *LoadedSession) UncleanTail() bool { return !l.HasEndMarker || l.HasCorruptedTail }

// SessionUUIDString returns the canonical 8-4-4-4-12 UUID string.
func (l *LoadedSession) SessionUUIDString() string { return FormatUUID(l.SessionUUID) }

// FormatUUID renders a 16-byte UUID as canonical lowercase text.
func FormatUUID(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ParseUUID parses a UUID string (with or without hyphens/braces/urn prefix).
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	c := strings.ToLower(strings.TrimSpace(s))
	c = strings.TrimPrefix(c, "urn:uuid:")
	c = strings.Trim(c, "{}")
	c = strings.ReplaceAll(c, "-", "")
	if len(c) != 32 {
		return out, fmt.Errorf("badly formed hexadecimal UUID string: %q", s)
	}
	b, err := hex.DecodeString(c)
	if err != nil {
		return out, fmt.Errorf("badly formed hexadecimal UUID string: %q", s)
	}
	copy(out[:], b)
	return out, nil
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// DecodeBlockHeader validates and unpacks a 64-byte header BEFORE payload allocation.
func DecodeBlockHeader(b []byte) (BlockHeader, error) {
	var h BlockHeader
	if len(b) < BlockHdrSize {
		if len(b) >= 4 {
			if m := binary.LittleEndian.Uint32(b); m != BlockMagic {
				return h, werr(ErrMagic, "Invalid block magic 0x%08x (expected 0x%08x)", m, BlockMagic)
			}
		}
		return h, werr(ErrTruncated, "Truncated block header: expected %d bytes, got %d", BlockHdrSize, len(b))
	}
	le := binary.LittleEndian
	h.Magic = le.Uint32(b[0:])
	h.Major = le.Uint16(b[4:])
	h.Minor = le.Uint16(b[6:])
	h.BlockType = le.Uint16(b[8:])
	h.ProducerType = le.Uint16(b[10:])
	h.Flags = le.Uint32(b[12:])
	h.PayloadLen = le.Uint32(b[16:])
	h.Epoch = le.Uint32(b[20:])
	h.BlockNo = le.Uint32(b[24:])
	h.Reserved = le.Uint32(b[28:])
	copy(h.SessionUUID[:], b[32:48])
	h.MinTsNs = le.Uint64(b[48:])
	h.MaxTsNs = le.Uint64(b[56:])

	if h.Magic != BlockMagic {
		return h, werr(ErrMagic, "Invalid block magic 0x%08x (expected 0x%08x)", h.Magic, BlockMagic)
	}
	if h.Major != WireMajor {
		return h, werr(ErrVersion, "Incompatible wire major version %d.%d (expected major=%d)", h.Major, h.Minor, WireMajor)
	}
	if h.PayloadLen > MaxPayloadLen {
		return h, werr(ErrPayloadTooLarge, "Block payload_len %d exceeds 16 MiB cap (%d)", h.PayloadLen, MaxPayloadLen)
	}
	return h, nil
}

// EncodeBlockHeader packs a header (PayloadLen taken from the struct).
func EncodeBlockHeader(h BlockHeader) []byte {
	b := make([]byte, BlockHdrSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], h.Magic)
	le.PutUint16(b[4:], h.Major)
	le.PutUint16(b[6:], h.Minor)
	le.PutUint16(b[8:], h.BlockType)
	le.PutUint16(b[10:], h.ProducerType)
	le.PutUint32(b[12:], h.Flags)
	le.PutUint32(b[16:], h.PayloadLen)
	le.PutUint32(b[20:], h.Epoch)
	le.PutUint32(b[24:], h.BlockNo)
	le.PutUint32(b[28:], h.Reserved)
	copy(b[32:48], h.SessionUUID[:])
	le.PutUint64(b[48:], h.MinTsNs)
	le.PutUint64(b[56:], h.MaxTsNs)
	return b
}

func scalarLen(c tlvCodec) int {
	switch c {
	case codecU8:
		return 1
	case codecU16:
		return 2
	case codecU32, codecS32:
		return 4
	case codecU64:
		return 8
	}
	return -1
}

// DecodeEvent decodes one event header + packed TLVs at offset; returns the event and the next offset.
func DecodeEvent(buf []byte, offset int, producerType uint16, epoch, blockNo uint32) (*Event, int, error) {
	rem := len(buf) - offset
	if rem < EventHdrSize {
		return nil, 0, werr(ErrTruncated, "Truncated event header at offset %d: %d < %d", offset, rem, EventHdrSize)
	}
	le := binary.LittleEndian
	b := buf[offset:]
	ev := &Event{
		TotalLen:      le.Uint16(b[0:]),
		Kind:          le.Uint16(b[2:]),
		ObjectType:    b[4],
		EvidenceLevel: b[5],
		SiteDictIdx:   le.Uint16(b[6:]),
		CPU:           le.Uint32(b[8:]),
		Flags:         le.Uint32(b[12:]),
		Seq:           le.Uint64(b[16:]),
		TsNs:          le.Uint64(b[24:]),
		ObjectID:      le.Uint64(b[32:]),
		ProducerType:  producerType,
		Epoch:         epoch,
		BlockNo:       blockNo,
		nums:          map[string]uint64{},
		strs:          map[string]string{},
		bins:          map[string][]byte{},
	}
	total := int(ev.TotalLen)
	if total < EventHdrSize {
		return nil, 0, werr(ErrWire, "Invalid event total_len %d (< %d)", total, EventHdrSize)
	}
	if total > rem {
		return nil, 0, werr(ErrTruncated, "Truncated event payload at offset %d: need %d, have %d", offset, total, rem)
	}
	pos := offset + EventHdrSize
	end := offset + total
	for pos < end {
		if end-pos < TLVHdrSize {
			return nil, 0, werr(ErrTruncated, "Truncated TLV header at byte %d", pos)
		}
		tag := le.Uint16(buf[pos:])
		tlen := int(le.Uint16(buf[pos+2:]))
		pos += TLVHdrSize
		if end-pos < tlen {
			return nil, 0, werr(ErrTruncated, "Truncated TLV 0x%04x value: need %d, have %d", tag, tlen, end-pos)
		}
		val := append([]byte(nil), buf[pos:pos+tlen]...)
		pos += tlen
		ev.RawTLVs = append(ev.RawTLVs, TLV{Tag: tag, Val: val})

		must := tag&TLVMustUnderstand != 0
		base := tag & 0x7FFF
		unk := UnknownTLV{Tag: tag, Length: uint16(tlen), Raw: val, MustUnderstand: must}
		spec, ok := knownTLVs[base]
		if !ok {
			ev.addUnknown(unk)
			continue
		}
		switch spec.codec {
		case codecU8, codecU16, codecU32, codecS32, codecU64:
			if tlen != scalarLen(spec.codec) {
				ev.addUnknown(unk)
				continue
			}
			var v uint64
			switch spec.codec {
			case codecU8:
				v = uint64(val[0])
			case codecU16:
				v = uint64(le.Uint16(val))
			case codecU32:
				v = uint64(le.Uint32(val))
			case codecS32:
				v = uint64(int64(int32(le.Uint32(val))))
			case codecU64:
				v = le.Uint64(val)
			}
			ev.nums[spec.name] = v
			if base == TLVQualSiteDictIdx {
				if _, exists := ev.nums["site_dict_idx"]; !exists {
					ev.nums["site_dict_idx"] = v
				}
			}
		case codecIP:
			if tlen == 4 || tlen == 16 {
				ev.strs[spec.name] = FormatIP(val)
				ev.bins[spec.name+"_raw"] = val
			} else {
				ev.addUnknown(unk)
			}
		case codecComm:
			ev.bins["comm_raw"] = val
			s := val
			if i := bytes.IndexByte(s, 0); i >= 0 {
				s = s[:i]
			}
			ev.strs[spec.name] = strings.ToValidUTF8(string(s), string(utf8.RuneError))
		case codecBytes:
			ev.bins[spec.name] = val
		}
	}
	return ev, end, nil
}

func (e *Event) addUnknown(u UnknownTLV) {
	if u.MustUnderstand {
		e.UnknownMust = append(e.UnknownMust, u)
	} else {
		e.UnknownOptional = append(e.UnknownOptional, u)
	}
}

// FormatIP formats a 4- or 16-byte address exactly like Python's ipaddress module.
func FormatIP(b []byte) string {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b)).String()
	case 16:
		return netip.AddrFrom16([16]byte(b)).String()
	}
	return hex.EncodeToString(b)
}

// EncodeEvent re-encodes an event from its RawTLVs (or the given override list).
func EncodeEvent(ev *Event, tlvs []TLV) []byte {
	if tlvs == nil {
		tlvs = ev.RawTLVs
	}
	var body bytes.Buffer
	for _, t := range tlvs {
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:], t.Tag)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(t.Val)))
		body.Write(hdr[:])
		body.Write(t.Val)
	}
	out := make([]byte, EventHdrSize, EventHdrSize+body.Len())
	le := binary.LittleEndian
	le.PutUint16(out[0:], uint16(EventHdrSize+body.Len()))
	le.PutUint16(out[2:], ev.Kind)
	out[4] = ev.ObjectType
	out[5] = ev.EvidenceLevel
	le.PutUint16(out[6:], ev.SiteDictIdx)
	le.PutUint32(out[8:], ev.CPU)
	le.PutUint32(out[12:], ev.Flags)
	le.PutUint64(out[16:], ev.Seq)
	le.PutUint64(out[24:], ev.TsNs)
	le.PutUint64(out[32:], ev.ObjectID)
	return append(out, body.Bytes()...)
}

// EncodeBlock encodes header + payload + IEEE CRC32 (PayloadLen is overwritten).
func EncodeBlock(h BlockHeader, payload []byte) ([]byte, error) {
	if uint64(len(payload)) > uint64(MaxPayloadLen) {
		return nil, werr(ErrPayloadTooLarge, "Payload length %d exceeds %d", len(payload), MaxPayloadLen)
	}
	h.PayloadLen = uint32(len(payload))
	body := append(EncodeBlockHeader(h), payload...)
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], crc32.ChecksumIEEE(body))
	return append(body, crc[:]...), nil
}

// ReadBlock reads and validates one block from r. Returns (nil, nil) on clean EOF.
func ReadBlock(r io.Reader, sourceName string) (*BlockRecord, error) {
	hdr := make([]byte, BlockHdrSize)
	n, err := io.ReadFull(r, hdr)
	if n == 0 && (err == io.EOF || err == io.ErrUnexpectedEOF) {
		return nil, nil
	}
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	h, herr := DecodeBlockHeader(hdr[:n])
	if herr != nil {
		return nil, herr
	}
	// Safe to allocate: payload_len <= 16 MiB verified above.
	payload := make([]byte, h.PayloadLen)
	if pn, perr := io.ReadFull(r, payload); perr != nil {
		if perr == io.EOF || perr == io.ErrUnexpectedEOF {
			return nil, werr(ErrTruncated, "Truncated block payload in %s: expected %d, got %d", sourceName, h.PayloadLen, pn)
		}
		return nil, perr
	}
	crcb := make([]byte, CRC32Size)
	if _, cerr := io.ReadFull(r, crcb); cerr != nil {
		if cerr == io.EOF || cerr == io.ErrUnexpectedEOF {
			return nil, werr(ErrTruncated, "Truncated block CRC32 trailer in %s", sourceName)
		}
		return nil, cerr
	}
	expected := binary.LittleEndian.Uint32(crcb)
	c := crc32.NewIEEE()
	c.Write(hdr)
	c.Write(payload)
	if actual := c.Sum32(); actual != expected {
		return nil, werr(ErrCRC, "CRC32 mismatch in %s block #%d: expected 0x%08x, computed 0x%08x", sourceName, h.BlockNo, expected, actual)
	}
	if h.Flags&BlockFlagZstd != 0 {
		return nil, werr(ErrZstdUnsupported, "Block has ZSTD flag set in %s, but zstd decompression is unavailable", sourceName)
	}
	rec := &BlockRecord{Header: h, CRC32: expected, SourceFile: sourceName}
	if len(payload) > 0 {
		isMeta := h.BlockType == BlockDictDelta || h.BlockType == BlockEndMarker || h.BlockType == BlockQualityCheckpoint
		if isMeta && payload[0] == '{' {
			m, jerr := decodeJSONObject(payload)
			if jerr != nil {
				return nil, werr(ErrWire, "Malformed JSON payload in %s: %v", sourceName, jerr)
			}
			rec.MetaPayload = m
		} else {
			off := 0
			for off < len(payload) {
				ev, next, eerr := DecodeEvent(payload, off, h.ProducerType, h.Epoch, h.BlockNo)
				if eerr != nil {
					return nil, eerr
				}
				rec.Events = append(rec.Events, ev)
				off = next
			}
		}
	}
	return rec, nil
}

// DecodeBlock strictly decodes a single block from memory.
func DecodeBlock(data []byte, sourceName string) (*BlockRecord, error) {
	rec, err := ReadBlock(bytes.NewReader(data), sourceName)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, werr(ErrTruncated, "Empty block buffer in %s", sourceName)
	}
	return rec, nil
}

func decodeJSONObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Session loader
// ---------------------------------------------------------------------------

func mergeDictDelta(d map[string]any, delta map[string]any) {
	if sites, ok := delta["sites"].([]any); ok {
		existing := map[int64]any{}
		var keys []int64
		cur, _ := d["sites"].([]any)
		add := func(s any) {
			m, ok := s.(map[string]any)
			if !ok {
				return
			}
			idx, ok := AsInt(m["site_idx"])
			if !ok {
				return
			}
			if _, seen := existing[idx]; !seen {
				keys = append(keys, idx)
			}
			existing[idx] = m
		}
		for _, s := range cur {
			add(s)
		}
		for _, s := range sites {
			add(s)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		out := make([]any, 0, len(keys))
		for _, k := range keys {
			out = append(out, existing[k])
		}
		d["sites"] = out
	}
	if eps, ok := delta["topology_epochs"].([]any); ok {
		cur, _ := d["topology_epochs"].([]any)
		d["topology_epochs"] = append(cur, eps...)
	}
}

func readJSONFile(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	m, err := decodeJSONObject(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return m, nil
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func globFiles(dir, pattern string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, pattern))
	var out []string
	for _, m := range matches {
		if isFile(m) {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// LoadSession loads manifest.json, dict.json and all valid block_*.pktb files.
//
// With strictTail=false, a truncated / CRC-corrupted trailing block (or a missing
// END_MARKER) is tolerated: all prior CRC-valid blocks are replayed and the session
// is flagged UncleanTail so reconstruction marks open branches UNKNOWN_TAIL.
func LoadSession(runDir string, strictTail bool) (*LoadedSession, error) {
	st, err := os.Stat(runDir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("session directory not found: %s", runDir)
	}
	manifest := map[string]any{}
	if p := filepath.Join(runDir, "manifest.json"); isFile(p) {
		m, err := readJSONFile(p)
		if err != nil {
			return nil, err
		}
		manifest = m
	}
	dictionary := map[string]any{"sites": []any{}, "topology_epochs": []any{}}
	if p := filepath.Join(runDir, "dict.json"); isFile(p) {
		m, err := readJSONFile(p)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			dictionary[k] = v
		}
	}

	var expected *[16]byte
	if s, ok := manifest["session_uuid"].(string); ok && s != "" {
		u, err := ParseUUID(s)
		if err != nil {
			return nil, err
		}
		expected = &u
	}

	blockFiles := globFiles(runDir, "block_*.pktb")
	if len(blockFiles) == 0 {
		blockFiles = globFiles(runDir, "*.pktb")
	}

	ls := &LoadedSession{RunDir: runDir, Manifest: manifest, Dictionary: dictionary}
	if tmps := globFiles(runDir, "*.tmp"); len(tmps) > 0 {
		names := make([]string, len(tmps))
		for i, t := range tmps {
			names[i] = filepath.Base(t)
		}
		ls.TailErrors = append(ls.TailErrors, "Uncommitted temporary files present: "+strings.Join(names, ", "))
	}

	for fileIdx, path := range blockFiles {
		isLast := fileIdx == len(blockFiles)-1
		name := filepath.Base(path)
		if err := ls.loadFile(path, name, isLast, strictTail, &expected); err != nil {
			return nil, err
		}
		if ls.HasCorruptedTail {
			break
		}
	}
	if expected != nil {
		ls.SessionUUID = *expected
	}
	return ls, nil
}

func (ls *LoadedSession) loadFile(path, name string, isLast, strictTail bool, expected **[16]byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	inFile := 0
	for {
		blk, err := ReadBlock(f, name)
		if err != nil {
			if errors.Is(err, ErrCRC) || errors.Is(err, ErrTruncated) {
				if strictTail {
					return err
				}
				if isLast || len(ls.Blocks) > 0 {
					ls.HasCorruptedTail = true
					ls.TailErrors = append(ls.TailErrors, err.Error())
					return nil
				}
			}
			return err
		}
		if blk == nil {
			if inFile == 0 {
				if st, serr := f.Stat(); serr == nil && st.Size() == 0 {
					if strictTail {
						return werr(ErrTruncated, "Zero-length block file %s", name)
					}
					ls.HasCorruptedTail = true
					ls.TailErrors = append(ls.TailErrors, "Zero-length trailing block file "+name)
				}
			}
			return nil
		}
		inFile++
		if *expected == nil {
			u := blk.Header.SessionUUID
			*expected = &u
		} else if blk.Header.SessionUUID != **expected {
			return werr(ErrUUIDMismatch, "Session UUID mismatch in %s: got %s, expected %s",
				name, FormatUUID(blk.Header.SessionUUID), FormatUUID(**expected))
		}
		ls.Blocks = append(ls.Blocks, blk)
		ls.Events = append(ls.Events, blk.Events...)
		switch blk.Header.BlockType {
		case BlockQualityCheckpoint:
			if blk.Header.MaxTsNs > ls.LastQualityCheckpointTsNs {
				ls.LastQualityCheckpointTsNs = blk.Header.MaxTsNs
			}
			for _, ev := range blk.Events {
				if ev.TsNs > ls.LastQualityCheckpointTsNs {
					ls.LastQualityCheckpointTsNs = ev.TsNs
				}
				if w := ev.U("win_end_ns"); w > ls.LastQualityCheckpointTsNs {
					ls.LastQualityCheckpointTsNs = w
				}
			}
		case BlockDictDelta:
			if blk.MetaPayload != nil {
				mergeDictDelta(ls.Dictionary, blk.MetaPayload)
			}
		case BlockEndMarker:
			ls.HasEndMarker = true
			if blk.MetaPayload != nil {
				if adm, ok := blk.MetaPayload["admissions"]; ok && !Truthy(ls.Manifest["admissions"]) {
					ls.Manifest["admissions"] = adm
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// JSON value helpers (json.Number aware)
// ---------------------------------------------------------------------------

// AsInt converts a decoded JSON value to int64.
func AsInt(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i, true
		}
		if u, err := parseUint(string(x)); err == nil {
			return int64(u), true
		}
		if f, err := x.Float64(); err == nil {
			return int64(f), true
		}
	case float64:
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint64:
		return int64(x), true
	case uint32:
		return int64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case string:
		var i int64
		if _, err := fmt.Sscan(x, &i); err == nil {
			return i, true
		}
	}
	return 0, false
}

func parseUint(s string) (uint64, error) {
	var u uint64
	_, err := fmt.Sscan(s, &u)
	return u, err
}

// IntOr returns AsInt(v) or def; JSON null / missing / falsy-zero follow Python `or` semantics
// only when orDefault is used by callers explicitly.
func IntOr(v any, def int64) int64 {
	if i, ok := AsInt(v); ok {
		return i
	}
	return def
}

// Truthy mimics Python truthiness for decoded JSON values.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := x.Float64()
		return err == nil && f != 0
	case float64:
		return x != 0
	case int64:
		return x != 0
	case int:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}
