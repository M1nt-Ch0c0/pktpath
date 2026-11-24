package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"pktpath/studio/pkg/adb"
)

var (
	reSerial = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,64}$`)
	reDev    = regexp.MustCompile(`^[A-Za-z0-9_.@:\-]{1,32}$`)
	scopes   = map[string]bool{"tc-egress": true, "ip-tx": true, "sock-tx": true, "rx-sock": true, "fwd": true}
)

// DeviceInfo is one entry of GET /api/devices.
type DeviceInfo struct {
	Serial     string `json:"serial"`
	Model      string `json:"model"`
	Product    string `json:"product"`
	State      string `json:"state"`
	AndroidVer string `json:"android_ver"`
	Kernel     string `json:"kernel"`
	RootMode   string `json:"root_mode"`
	AgentReady bool   `json:"agent_ready"`
}

func (s *Server) state(serial string) *deviceState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.devState[serial]
	if st == nil {
		st = &deviceState{}
		s.devState[serial] = st
	}
	return st
}

// ListDevices enumerates devices with cheap non-root probes in parallel.
func (s *Server) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	ents, err := s.adb.Devices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceInfo, len(ents))
	var wg sync.WaitGroup
	for i, e := range ents {
		out[i] = DeviceInfo{Serial: e.Serial, Model: e.Model, Product: e.Product, State: e.State}
		if e.State != "device" {
			s.adb.ForgetRoot(e.Serial)
			continue
		}
		wg.Add(1)
		go func(i int, serial string) {
			defer wg.Done()
			p, err := s.adb.Props(ctx, serial)
			if err != nil {
				return
			}
			d := &out[i]
			if p.Model != "" {
				d.Model = p.Model
			}
			if p.Product != "" {
				d.Product = p.Product
			}
			d.AndroidVer, d.Kernel = p.AndroidVer, p.Kernel
			st := s.state(serial)
			mode := s.adb.RootMode(serial)
			if mode == "" && p.ShellUID == "0" {
				mode = adb.RootAdbd
			}
			if mode == adb.RootAdbd && p.ShellUID != "" && p.ShellUID != "0" {
				// adbd restarted unrooted (reboot) -> re-probe on next prepare.
				s.adb.ForgetRoot(serial)
				mode = ""
			}
			d.RootMode = mode
			want := strings.ToLower(s.opts.Runtime.AgentSHA256)
			got := strings.ToLower(p.AgentSHA256)
			if got == "" && st.AgentSHA256 != "" && mode == adb.RootSu {
				got = st.AgentSHA256 // dir unreadable as shell; trust prepare result
			}
			d.AgentReady = want != "" && got == want
		}(i, e.Serial)
	}
	wg.Wait()
	return out, nil
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if s.opts.Runtime.AdbPath == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"devices":     []DeviceInfo{},
			"adb_path":    "",
			"adb_missing": true,
		})
		return
	}
	devs, err := s.ListDevices(r.Context())
	if err != nil {
		writeErrExtra(w, http.StatusInternalServerError, err.Error(), map[string]any{"devices": []DeviceInfo{}, "adb_missing": false})
		return
	}
	if devs == nil {
		devs = []DeviceInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs, "adb_path": s.opts.Runtime.AdbPath, "adb_missing": false})
}

// PrepareResult is returned by POST /api/device/prepare.
type PrepareResult struct {
	OK          bool   `json:"ok"`
	Serial      string `json:"serial"`
	RootMode    string `json:"root_mode"`
	Kernel      string `json:"kernel"`
	AndroidVer  string `json:"android_ver"`
	Model       string `json:"model"`
	AgentSHA256 string `json:"agent_sha256"`
	AgentPushed bool   `json:"agent_pushed"`
	AgentPath   string `json:"agent_path"`
	ElapsedMs   int64  `json:"elapsed_ms"`
	Error       string `json:"error,omitempty"`
}

// Prepare ensures root + injects the agent.
func (s *Server) Prepare(ctx context.Context, serial string) PrepareResult {
	t0 := time.Now()
	res := PrepareResult{Serial: serial, AgentPath: adb.RemoteAgent}
	defer func() { res.ElapsedMs = time.Since(t0).Milliseconds() }()
	mode, err := s.adb.EnsureRoot(ctx, serial)
	res.RootMode = mode
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if p, err := s.adb.Props(ctx, serial); err == nil {
		res.Kernel, res.AndroidVer, res.Model = p.Kernel, p.AndroidVer, p.Model
	}
	pushed, sha, err := s.adb.EnsureAgent(ctx, serial, s.opts.Runtime.AgentPath, s.opts.Runtime.AgentSHA256)
	res.AgentPushed, res.AgentSHA256 = pushed, sha
	st := s.state(serial)
	s.mu.Lock()
	st.RootMode, st.Kernel, st.PreparedAt = mode, res.Kernel, time.Now()
	if err == nil {
		st.AgentSHA256 = sha
	}
	s.mu.Unlock()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if mode == adb.RootNone {
		res.Error = "device is not rooted: neither adbd root, `adb root`, nor `su -c` granted uid 0 (eBPF capture requires root)"
		return res
	}
	res.OK = true
	return res
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	serial := b.str("serial")
	if serial == "" {
		serial = s.defaultSerial(r.Context())
	}
	if !reSerial.MatchString(serial) {
		writeErr(w, http.StatusBadRequest, "invalid or missing serial")
		return
	}
	res := s.Prepare(r.Context(), serial)
	code := http.StatusOK
	if !res.OK {
		code = http.StatusInternalServerError
	}
	writeJSON(w, code, res)
}

// defaultSerial picks the only/first online device when the UI omits serial.
func (s *Server) defaultSerial(ctx context.Context) string {
	ents, err := s.adb.Devices(ctx)
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if e.State == "device" {
			return e.Serial
		}
	}
	return ""
}

func (s *Server) serialFromQuery(r *http.Request) (string, bool) {
	serial := strings.TrimSpace(r.URL.Query().Get("serial"))
	if serial == "" {
		serial = s.defaultSerial(r.Context())
	}
	return serial, reSerial.MatchString(serial)
}

// ensureReady makes sure root mode is known and the agent is injected.
func (s *Server) ensureReady(ctx context.Context, serial string) error {
	st := s.state(serial)
	s.mu.Lock()
	ready := st.AgentSHA256 != "" && st.AgentSHA256 == s.opts.Runtime.AgentSHA256 && s.adb.RootMode(serial) != ""
	s.mu.Unlock()
	if ready {
		return nil
	}
	res := s.Prepare(ctx, serial)
	if !res.OK {
		return errString(res.Error)
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

// InspectResult is GET /api/device/inspect.
type InspectResult struct {
	OK         bool            `json:"ok"`
	Serial     string          `json:"serial"`
	Dev        string          `json:"dev"`
	Scope      string          `json:"scope"`
	Interfaces []adb.Iface     `json:"interfaces"`
	Inspect    json.RawMessage `json:"inspect"`
	Error      string          `json:"error,omitempty"`
}

// Inspect lists interfaces and runs `pktpath inspect --json`.
func (s *Server) Inspect(ctx context.Context, serial, dev, scope string, enablePlugins bool) InspectResult {
	res := InspectResult{Serial: serial, Dev: dev, Scope: scope, Interfaces: []adb.Iface{}, Inspect: json.RawMessage("null")}
	if r, err := s.adb.Shell(ctx, serial, "ip -br addr 2>/dev/null || ip -o addr", 10*time.Second); err == nil || r.Stdout != "" {
		res.Interfaces = adb.ParseIPBrAddr(r.Stdout)
	}
	if err := s.ensureReady(ctx, serial); err != nil {
		res.Error = err.Error()
		return res
	}
	cmd := adb.RemoteAgent + " inspect --dev " + adb.ShQuote(dev) + " --scope " + adb.ShQuote(scope)
	if enablePlugins && s.pluginsDir != "" {
		if n, perr := s.adb.SyncPlugins(ctx, serial, s.pluginsDir); perr == nil && n > 0 {
			cmd += " --plugin-dir " + adb.ShQuote(adb.RemotePluginsDir)
		}
	}
	cmd += " --json"
	r, err := s.adb.Priv(ctx, serial, cmd, 45*time.Second)
	raw := extractJSONObject(r.Stdout)
	if raw != nil {
		res.Inspect = raw
		res.OK = true
		return res
	}
	msg := strings.TrimSpace(r.Combined())
	if err != nil {
		msg = err.Error() + ": " + msg
	}
	res.Error = "pktpath inspect produced no JSON: " + truncate(msg, 2000)
	return res
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	serial, ok := s.serialFromQuery(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid or missing serial")
		return
	}
	dev := strings.TrimSpace(r.URL.Query().Get("dev"))
	if dev == "" {
		dev = "wlan0"
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "tc-egress"
	}
	if !reDev.MatchString(dev) {
		writeErr(w, http.StatusBadRequest, "invalid dev")
		return
	}
	if !scopes[scope] {
		writeErr(w, http.StatusBadRequest, "invalid scope (tc-egress|ip-tx|sock-tx|rx-sock|fwd)")
		return
	}
	enablePlugins := true
	if qp := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("plugins"))); qp == "0" || qp == "false" || qp == "off" {
		enablePlugins = false
	}
	res := s.Inspect(r.Context(), serial, dev, scope, enablePlugins)
	code := http.StatusOK
	if !res.OK && len(res.Interfaces) == 0 {
		code = http.StatusInternalServerError
	}
	writeJSON(w, code, res)
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	serial, ok := s.serialFromQuery(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid or missing serial")
		return
	}
	res, err := s.adb.Shell(r.Context(), serial, "cmd package list packages -U 2>/dev/null || pm list packages -U 2>/dev/null", 30*time.Second)
	apps := adb.ParsePackages(res.Stdout)
	if len(apps) == 0 {
		if r2, err2 := s.adb.Priv(r.Context(), serial, "cat /data/system/packages.list 2>/dev/null", 15*time.Second); err2 == nil || r2.Stdout != "" {
			apps = adb.ParsePackages(r2.Stdout)
			if len(apps) > 0 {
				err = nil
			}
		}
	}
	if len(apps) == 0 && err != nil {
		writeErrExtra(w, http.StatusInternalServerError, err.Error(), map[string]any{"apps": []adb.App{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "serial": serial, "apps": apps})
}

// extractJSONObject returns the outermost {...} object in s if valid JSON.
func extractJSONObject(s string) json.RawMessage {
	s = strings.TrimSpace(s)
	if json.Valid([]byte(s)) && strings.HasPrefix(s, "{") {
		return json.RawMessage(s)
	}
	i := strings.Index(s, "{")
	j := strings.LastIndex(s, "}")
	if i < 0 || j <= i {
		return nil
	}
	c := s[i : j+1]
	if json.Valid([]byte(c)) {
		return json.RawMessage(c)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
