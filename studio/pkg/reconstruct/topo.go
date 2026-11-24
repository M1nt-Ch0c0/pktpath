package reconstruct

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"pktpath/studio/pkg/wire"
)

// OptU is an optional unsigned value (Python `None` vs int).
type OptU struct {
	V  uint64
	OK bool
}

// Some builds a present OptU.
func Some(v uint64) OptU { return OptU{V: v, OK: true} }

func evOpt(ev *wire.Event, name string) OptU {
	v, ok := ev.Get(name)
	return OptU{V: v, OK: ok}
}

// Site is one dict.json sites[] entry.
type Site struct {
	SiteIdx       int64  `json:"site_idx"`
	AdapterID     string `json:"adapter_id"`
	Name          string `json:"name"`
	Symbol        string `json:"symbol"`
	QdiscKind     string `json:"qdisc_kind,omitempty"`
	ProbeType     string `json:"probe_type"`
	ProbeVersion  string `json:"probe_version"`
	Stage         int64  `json:"stage"`
	HasStage      bool   `json:"-"`
	EvidenceLevel int64  `json:"evidence_level"`
}

type topoDevice struct {
	Ifindex     int64
	HasIfindex  bool
	DevGen      int64
	Name        string
	Linktype    int64
	HasLinktype bool
}

type topoQdisc struct {
	Ifindex     int64
	HasIfindex  bool
	DevGen      int64
	QueueGen    int64
	HasQueueGen bool
	Kind        string
	Handle      int64
	HasHandle   bool
	Parent      int64
	HasParent   bool
}

// ClassInfo is a resolved dict.json topology_epochs[].classes[] entry.
type ClassInfo struct {
	Ifindex    int64  `json:"ifindex"`
	HasIfindex bool   `json:"-"`
	DevGen     int64  `json:"dev_gen"`
	Kind       string `json:"kind"`
	Handle     uint32 `json:"handle"`
	HasHandle  bool   `json:"-"`
	Parent     uint32 `json:"parent"`
	HasParent  bool   `json:"-"`
	Leaf       uint32 `json:"leaf"`
	Prio       int64  `json:"prio"`
	HasPrio    bool   `json:"-"`
	Quantum    int64  `json:"quantum"`
	RateBps    uint64 `json:"rate_bps"`
	CeilBps    uint64 `json:"ceil_bps"`
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	Drops      uint64 `json:"drops"`
	Overlimits uint64 `json:"overlimits"`
}

type topoEpoch struct {
	EpochID   int64
	TsNs      int64
	NetnsInum int64
	HasNetns  bool
	Devices   []topoDevice
	Qdiscs    []topoQdisc
	Classes   []ClassInfo
}

type calibration struct {
	BoottimeNs int64
	RealtimeNs int64
	ErrNs      int64
}

func jstr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// parseTCHandleAny parses either an integer u32 handle or a tc string ("1:10", ":1", "root").
func parseTCHandleAny(v any) (uint32, bool) {
	if v == nil {
		return 0, false
	}
	if s, ok := v.(string); ok {
		st := strings.ToLower(strings.TrimSpace(s))
		if st == "" {
			return 0, false
		}
		if st == "root" {
			return 0xFFFFFFFF, true
		}
		if st == "ffff:fff1" || st == "ingress" || st == "clsact" {
			return 0xFFFFFFF1, true
		}
		if idx := strings.IndexByte(st, ':'); idx >= 0 {
			majS, minS := st[:idx], st[idx+1:]
			var maj, min uint64
			var err error
			if majS != "" {
				maj, err = strconv.ParseUint(majS, 16, 16)
				if err != nil {
					return 0, false
				}
			}
			if minS != "" {
				min, err = strconv.ParseUint(minS, 16, 16)
				if err != nil {
					return 0, false
				}
			}
			return uint32((maj << 16) | min), true
		}
	}
	if i, ok := wire.AsInt(v); ok {
		return uint32(i), true
	}
	return 0, false
}

func asU64(v any) uint64 {
	if i, ok := wire.AsInt(v); ok && i > 0 {
		return uint64(i)
	}
	return 0
}

func parseSites(d map[string]any) map[int64]*Site {
	out := map[int64]*Site{}
	arr, _ := d["sites"].([]any)
	for _, a := range arr {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		idx, ok := wire.AsInt(m["site_idx"])
		if !ok {
			continue
		}
		s := &Site{
			SiteIdx:      idx,
			AdapterID:    jstr(m["adapter_id"]),
			Name:         jstr(m["name"]),
			Symbol:       jstr(m["symbol"]),
			QdiscKind:    strings.ToLower(strings.TrimSpace(jstr(m["qdisc_kind"]))),
			ProbeType:    jstr(m["probe_type"]),
			ProbeVersion: jstr(m["probe_version"]),
		}
		if _, present := m["probe_type"]; !present {
			s.ProbeType = ""
		}
		if v, ok := m["stage"]; ok && v != nil {
			s.Stage, s.HasStage = wire.AsInt(v)
		}
		s.EvidenceLevel, _ = wire.AsInt(m["evidence_level"])
		out[idx] = s
	}
	return out
}

func parseTopology(d map[string]any) []topoEpoch {
	var out []topoEpoch
	arr, _ := d["topology_epochs"].([]any)
	for _, a := range arr {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		ep := topoEpoch{}
		ep.EpochID, _ = wire.AsInt(m["epoch_id"])
		ep.TsNs, _ = wire.AsInt(m["ts_ns"])
		if v, ok := m["netns_inum"]; ok && v != nil {
			ep.NetnsInum, ep.HasNetns = wire.AsInt(v)
		}
		devs, _ := m["devices"].([]any)
		for _, dv := range devs {
			dm, ok := dv.(map[string]any)
			if !ok {
				continue
			}
			td := topoDevice{Name: jstr(dm["name"])}
			if v, ok := dm["ifindex"]; ok && v != nil {
				td.Ifindex, td.HasIfindex = wire.AsInt(v)
			}
			td.DevGen, _ = wire.AsInt(dm["dev_gen"])
			if v, ok := dm["linktype"]; ok && v != nil {
				td.Linktype, td.HasLinktype = wire.AsInt(v)
			}
			ep.Devices = append(ep.Devices, td)
		}
		qds, _ := m["qdiscs"].([]any)
		for _, qv := range qds {
			qm, ok := qv.(map[string]any)
			if !ok {
				continue
			}
			tq := topoQdisc{Kind: jstr(qm["kind"])}
			if v, ok := qm["ifindex"]; ok && v != nil {
				tq.Ifindex, tq.HasIfindex = wire.AsInt(v)
			}
			tq.DevGen, _ = wire.AsInt(qm["dev_gen"])
			if v, ok := qm["queue_gen"]; ok && v != nil {
				tq.QueueGen, tq.HasQueueGen = wire.AsInt(v)
			}
			if h, ok := parseTCHandleAny(qm["handle"]); ok {
				tq.Handle, tq.HasHandle = int64(h), true
			}
			if p, ok := parseTCHandleAny(qm["parent"]); ok {
				tq.Parent, tq.HasParent = int64(p), true
			}
			ep.Qdiscs = append(ep.Qdiscs, tq)
		}
		cls, _ := m["classes"].([]any)
		for _, cv := range cls {
			cm, ok := cv.(map[string]any)
			if !ok {
				continue
			}
			tc := ClassInfo{Kind: jstr(cm["kind"])}
			if v, ok := cm["ifindex"]; ok && v != nil {
				tc.Ifindex, tc.HasIfindex = wire.AsInt(v)
			}
			tc.DevGen, _ = wire.AsInt(cm["dev_gen"])
			if h, ok := parseTCHandleAny(cm["handle"]); ok {
				tc.Handle, tc.HasHandle = h, true
			} else if h, ok := parseTCHandleAny(cm["classid"]); ok {
				tc.Handle, tc.HasHandle = h, true
			}
			if p, ok := parseTCHandleAny(cm["parent"]); ok {
				tc.Parent, tc.HasParent = p, true
			}
			if lf, ok := parseTCHandleAny(cm["leaf"]); ok {
				tc.Leaf = lf
			}
			if v, ok := cm["prio"]; ok && v != nil {
				tc.Prio, tc.HasPrio = wire.AsInt(v)
			}
			tc.Quantum, _ = wire.AsInt(cm["quantum"])
			tc.RateBps = asU64(cm["rate_bps"])
			tc.CeilBps = asU64(cm["ceil_bps"])
			tc.Bytes = asU64(cm["bytes"])
			tc.Packets = asU64(cm["packets"])
			tc.Drops = asU64(cm["drops"])
			tc.Overlimits = asU64(cm["overlimits"])
			ep.Classes = append(ep.Classes, tc)
		}
		out = append(out, ep)
	}
	return out
}

func parseCalibrations(m map[string]any) []calibration {
	var out []calibration
	arr, _ := m["calibrations"].([]any)
	for _, a := range arr {
		cm, ok := a.(map[string]any)
		if !ok {
			continue
		}
		c := calibration{}
		c.BoottimeNs, _ = wire.AsInt(cm["boottime_ns"])
		if v, ok := cm["realtime_ns"]; ok && v != nil {
			c.RealtimeNs, _ = wire.AsInt(v)
		} else {
			c.RealtimeNs = c.BoottimeNs
		}
		if v, ok := cm["err_ns"]; ok {
			c.ErrNs, _ = wire.AsInt(v)
		} else {
			c.ErrNs, _ = wire.AsInt(cm["est_err_ns"])
		}
		out = append(out, c)
	}
	return out
}

// isParentTCClass reports whether parent is a TC class handle (non-zero and not root/clsact ffff:xxxx).
func isParentTCClass(parent uint64) bool {
	p := uint32(parent)
	return p != 0 && (p&0xFFFF0000) != 0xFFFF0000
}

// ResolveSite returns the dict.json site for a site index.
func (s *Session) ResolveSite(idx uint16) *Site { return s.sites[int64(idx)] }

// InferQdiscKind infers a qdisc kind name from dict.json sites[siteIdx] when a qdisc
// (such as an invisible default pfifo 0: under an HTB leaf class) is absent from qdiscs[].
func (s *Session) InferQdiscKind(siteIdx uint16) string {
	site := s.ResolveSite(siteIdx)
	if site == nil {
		return ""
	}
	if site.QdiscKind != "" {
		return site.QdiscKind
	}
	sym := strings.ToLower(site.Symbol + " " + site.Name)
	switch {
	case strings.Contains(sym, "pfifo_fast"):
		return "pfifo_fast"
	case strings.Contains(sym, "pfifo_tail") || strings.Contains(sym, "pfifo_head_drop") || strings.Contains(sym, "ptail"):
		return "pfifo_head_drop"
	case strings.Contains(sym, "bfifo"):
		return "bfifo"
	case strings.Contains(sym, "pfifo") || strings.Contains(sym, "qdisc_dequeue_head") || strings.Contains(sym, "fifo"):
		return "pfifo"
	case strings.Contains(sym, "sfq"):
		return "sfq"
	case strings.Contains(sym, "fq_codel"):
		return "fq_codel"
	case strings.Contains(sym, "htb"):
		return "htb"
	}
	return ""
}

func (s *Session) resolveVisitQdiscKind(v *QueueVisit) string {
	qi := s.ResolveQdiscInfo(v.Ifindex, Some(v.QueueGen), Some(v.QdiscHandle), Some(v.QdiscParent), Some(v.DevGen), OptU{})
	if qi != nil && qi.Kind != "" {
		return qi.Kind
	}
	if v.Entry != nil {
		if k := s.InferQdiscKind(v.Entry.SiteDictIdx); k != "" {
			return k
		}
	}
	if v.Exit != nil {
		if k := s.InferQdiscKind(v.Exit.SiteDictIdx); k != "" {
			return k
		}
	}
	return ""
}

// IsTopoDesyncedAt reports whether ts falls into a TOPO_DESYNC window.
func (s *Session) IsTopoDesyncedAt(ts uint64) bool {
	for _, w := range s.TopoDesyncWindows {
		if w[0] <= ts && ts <= w[1] {
			return true
		}
	}
	return false
}

func (s *Session) resolveDevInfo(ifindex uint64, devGen OptU, netns OptU) *topoDevice {
	var best *topoDevice
	for ei := range s.topo {
		ep := &s.topo[ei]
		if netns.OK && netns.V != 0 && ep.NetnsInum != 0 && uint64(ep.NetnsInum) != netns.V {
			continue
		}
		for di := range ep.Devices {
			d := &ep.Devices[di]
			if !d.HasIfindex || uint64(d.Ifindex) != ifindex {
				continue
			}
			if devGen.OK && devGen.V != 0 && d.DevGen != 0 && uint64(d.DevGen) != devGen.V {
				continue
			}
			best = d
		}
	}
	if best == nil {
		for ei := range s.topo {
			for di := range s.topo[ei].Devices {
				d := &s.topo[ei].Devices[di]
				if d.HasIfindex && uint64(d.Ifindex) == ifindex {
					return d
				}
			}
		}
	}
	return best
}

// ResolveDevName maps ifindex (+dev_gen/netns) to a device name (fallback "if<N>").
func (s *Session) ResolveDevName(ifindex uint64, devGen OptU, netns OptU) string {
	if ifindex == 0 {
		return "if0"
	}
	if d := s.resolveDevInfo(ifindex, devGen, netns); d != nil && d.Name != "" {
		return d.Name
	}
	return fmt.Sprintf("if%d", ifindex)
}

// ResolveDevLinktype maps ifindex to its pcap linktype (default ETHERNET).
func (s *Session) ResolveDevLinktype(ifindex uint64, devGen OptU) int {
	if d := s.resolveDevInfo(ifindex, devGen, OptU{}); d != nil && d.HasLinktype {
		return int(d.Linktype)
	}
	return wire.LinkTypeEthernet
}

// QdiscInfo is a resolved dict.json qdisc entry.
type QdiscInfo struct {
	Kind     string
	Handle   int64
	Parent   int64
	QueueGen int64
}

// ResolveQdiscInfo resolves a qdisc by (ifindex, queue_gen) then (ifindex, handle, parent),
// preferring the latest topology epoch at or before ts when ts is provided.
func (s *Session) ResolveQdiscInfo(ifindex uint64, queueGen, handle, parent OptU, devGen OptU, ts OptU) *QdiscInfo {
	if ts.OK && s.IsTopoDesyncedAt(ts.V) {
		return nil
	}
	if queueGen.OK && queueGen.V > 0 {
		var bestAtOrBefore, bestAny *QdiscInfo
		for _, ep := range s.topo {
			for _, q := range ep.Qdiscs {
				if q.HasIfindex && uint64(q.Ifindex) == ifindex && q.HasQueueGen && uint64(q.QueueGen) == queueGen.V {
					if devGen.OK && devGen.V != 0 && q.DevGen != 0 && uint64(q.DevGen) != devGen.V {
						continue
					}
					cand := &QdiscInfo{Kind: q.Kind, Handle: q.Handle, Parent: q.Parent, QueueGen: q.QueueGen}
					bestAny = cand
					if !ts.OK || ep.TsNs <= int64(ts.V) {
						bestAtOrBefore = cand
					}
				}
			}
		}
		if bestAtOrBefore != nil {
			return bestAtOrBefore
		}
		if bestAny != nil {
			return bestAny
		}
	}
	if handle.OK {
		h32 := uint32(handle.V)
		var bestAtOrBefore, bestAny *QdiscInfo
		for _, ep := range s.topo {
			for _, q := range ep.Qdiscs {
				if q.HasIfindex && uint64(q.Ifindex) == ifindex && q.HasHandle && uint32(q.Handle) == h32 {
					if parent.OK && parent.V != 0 && q.HasParent && uint32(q.Parent) != uint32(parent.V) {
						continue
					}
					if h32 == 0 && (!parent.OK || parent.V == 0) && q.HasParent && isParentTCClass(uint64(uint32(q.Parent))) {
						continue
					}
					cand := &QdiscInfo{Kind: q.Kind, Handle: q.Handle, Parent: q.Parent, QueueGen: q.QueueGen}
					bestAny = cand
					if !ts.OK || ep.TsNs <= int64(ts.V) {
						bestAtOrBefore = cand
					}
				}
			}
		}
		if bestAtOrBefore != nil {
			return bestAtOrBefore
		}
		if bestAny != nil {
			return bestAny
		}
	}
	return nil
}

// ResolveClassInfo resolves a TC class from dict.json topology_epochs[].classes[]
// by (ifindex, classid), preferring the latest epoch at or before ts.
func (s *Session) ResolveClassInfo(ifindex, classid uint64, devGen, ts OptU) *ClassInfo {
	c32 := uint32(classid)
	if c32 == 0 {
		return nil
	}
	if ts.OK && s.IsTopoDesyncedAt(ts.V) {
		return nil
	}
	var bestAtOrBefore, bestAny *ClassInfo
	for ei := range s.topo {
		ep := &s.topo[ei]
		for ci := range ep.Classes {
			c := &ep.Classes[ci]
			if !c.HasHandle || c.Handle != c32 {
				continue
			}
			if ifindex != 0 && c.HasIfindex && c.Ifindex != 0 && uint64(c.Ifindex) != ifindex {
				continue
			}
			if devGen.OK && devGen.V != 0 && c.DevGen != 0 && uint64(c.DevGen) != devGen.V {
				continue
			}
			cp := *c
			bestAny = &cp
			if !ts.OK || ep.TsNs <= int64(ts.V) {
				bestAtOrBefore = &cp
			}
		}
	}
	if bestAtOrBefore != nil {
		return bestAtOrBefore
	}
	return bestAny
}

// FormatBitrate renders bits/sec into compact human TC notation ("10M", "1.05G", "500K").
func FormatBitrate(bps uint64) string {
	if bps == 0 {
		return ""
	}
	trimFloat := func(v float64, unit string) string {
		s := fmt.Sprintf("%.2f", v)
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
		return s + unit
	}
	switch {
	case bps >= 1_000_000_000:
		if bps%1_000_000_000 == 0 {
			return fmt.Sprintf("%dG", bps/1_000_000_000)
		}
		return trimFloat(float64(bps)/1e9, "G")
	case bps >= 1_000_000:
		if bps%1_000_000 == 0 {
			return fmt.Sprintf("%dM", bps/1_000_000)
		}
		return trimFloat(float64(bps)/1e6, "M")
	case bps >= 1_000:
		if bps%1_000 == 0 {
			return fmt.Sprintf("%dK", bps/1_000)
		}
		return trimFloat(float64(bps)/1e3, "K")
	default:
		return fmt.Sprintf("%dbps", bps)
	}
}

// FormatClassRate formats (rate_bps, ceil_bps) into "10M→20M" or "100M".
func FormatClassRate(rateBps, ceilBps uint64) string {
	r := FormatBitrate(rateBps)
	c := FormatBitrate(ceilBps)
	if r != "" && c != "" && rateBps != ceilBps {
		return r + "→" + c
	}
	if r != "" {
		return r
	}
	return c
}

// FormatClassSummary formats human metadata for a TC class (kind, prio, rate→ceil).
func FormatClassSummary(ci *ClassInfo) string {
	if ci == nil {
		return ""
	}
	var parts []string
	if ci.Kind != "" {
		parts = append(parts, "class "+ci.Kind+" "+FormatTCHandle(Some(uint64(ci.Handle))))
	} else {
		parts = append(parts, "class "+FormatTCHandle(Some(uint64(ci.Handle))))
	}
	if ci.HasPrio && strings.EqualFold(ci.Kind, "htb") {
		parts = append(parts, fmt.Sprintf("prio %d", ci.Prio))
	} else if ci.HasPrio && ci.Prio != 0 {
		parts = append(parts, fmt.Sprintf("prio %d", ci.Prio))
	}
	if rate := FormatClassRate(ci.RateBps, ci.CeilBps); rate != "" {
		parts = append(parts, "rate "+rate)
	}
	return strings.Join(parts, " · ")
}

// CalibrateBoottimeToRealtime returns (realtime_ns, err_ns, calibrated).
func (s *Session) CalibrateBoottimeToRealtime(boottime uint64) (int64, int64, bool) {
	if len(s.calibs) == 0 {
		return int64(boottime), 0, false
	}
	bt := int64(boottime)
	best := 0
	bestD := int64(math.MaxInt64)
	for i, c := range s.calibs {
		d := c.BoottimeNs - bt
		if d < 0 {
			d = -d
		}
		if d < bestD {
			bestD = d
			best = i
		}
	}
	c := s.calibs[best]
	return c.RealtimeNs + (bt - c.BoottimeNs), c.ErrNs, true
}

// FormatTCHandle renders a tc handle like `tc` does ("1:", "14:", "1:10", "root").
func FormatTCHandle(h OptU) string {
	if !h.OK {
		return "0:"
	}
	v := uint32(h.V)
	switch v {
	case 0xFFFFFFFF:
		return "root"
	case 0xFFFFFFF1:
		return "ffff:fff1"
	case 0:
		return "0:"
	}
	major := (v >> 16) & 0xFFFF
	minor := v & 0xFFFF
	if minor == 0 {
		return fmt.Sprintf("%x:", major)
	}
	return fmt.Sprintf("%x:%x", major, minor)
}

func manifestStr(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	if v == nil {
		return "None"
	}
	return jstr(v)
}

func manifestStrOr(m map[string]any, key, def string) string {
	v := m[key]
	if !wire.Truthy(v) {
		return def
	}
	return jstr(v)
}

// adapterName maps an adapter_id to the manifest adapters[].name.
func (s *Session) adapterName(id string) string {
	arr, _ := s.Manifest["adapters"].([]any)
	for _, a := range arr {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if jstr(m["adapter_id"]) == id {
			if n := jstr(m["name"]); n != "" {
				return n
			}
		}
	}
	return id
}

func upper(s string) string { return strings.ToUpper(s) }
