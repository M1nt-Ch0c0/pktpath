package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"pktpath/studio/pkg/adb"
	"pktpath/studio/pkg/sshclient"
)

var (
	reSerial = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,96}$`)
	reDev    = regexp.MustCompile(`^[A-Za-z0-9_.@:\-]{1,32}$`)
	scopes   = map[string]bool{"tc-egress": true, "ip-tx": true, "sock-tx": true, "rx-sock": true, "fwd": true}
)

// DeviceInfo is one entry of GET /api/devices (Android ADB or Linux SSH).
type DeviceInfo struct {
	Serial     string `json:"serial"`
	Transport  string `json:"transport"` // "adb" | "ssh"
	Model      string `json:"model"`
	Product    string `json:"product"`
	State      string `json:"state"`
	AndroidVer string `json:"android_ver,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Kernel     string `json:"kernel"`
	RootMode   string `json:"root_mode"`
	AgentReady bool   `json:"agent_ready"`
	SSHHost    string `json:"ssh_host,omitempty"`
	SSHUser    string `json:"ssh_user,omitempty"`
	SSHPort    int    `json:"ssh_port,omitempty"`
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

// ListDevices enumerates Android ADB devices with cheap non-root probes in parallel.
func (s *Server) ListDevices(ctx context.Context) ([]DeviceInfo, error) {
	if s.opts.Runtime.AdbPath == "" {
		return []DeviceInfo{}, nil
	}
	ents, err := s.adb.Devices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceInfo, len(ents))
	var wg sync.WaitGroup
	for i, e := range ents {
		out[i] = DeviceInfo{Serial: e.Serial, Transport: "adb", Model: e.Model, Product: e.Product, State: e.State}
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
				s.adb.ForgetRoot(serial)
				mode = ""
			}
			d.RootMode = mode
			want := strings.ToLower(s.opts.Runtime.AgentSHA256)
			got := strings.ToLower(p.AgentSHA256)
			if got == "" && st.AgentSHA256 != "" && mode == adb.RootSu {
				got = st.AgentSHA256
			}
			d.AgentReady = want != "" && got == want
		}(i, e.Serial)
	}
	wg.Wait()
	return out, nil
}

func (s *Server) sshDevicesSnapshot() []DeviceInfo {
	targets := s.sshStore.List()
	out := make([]DeviceInfo, 0, len(targets))
	for _, t := range targets {
		serial := t.Serial()
		st := s.state(serial)
		s.mu.Lock()
		kernel, rm, sha := st.Kernel, st.RootMode, st.AgentSHA256
		s.mu.Unlock()
		out = append(out, DeviceInfo{
			Serial:     serial,
			Transport:  "ssh",
			Model:      t.Name,
			Product:    "Linux SSH",
			State:      "device",
			Kernel:     kernel,
			RootMode:   rm,
			AgentReady: sha != "",
			SSHHost:    t.Host,
			SSHUser:    t.User,
			SSHPort:    t.Port,
		})
	}
	return out
}

func (s *Server) availableAgentKeys() []string {
	var keys []string
	for k := range s.opts.Runtime.Agents {
		keys = append(keys, k)
	}
	return keys
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	adbEnabled := s.kernel == nil || s.kernel.HasTransportKind("adb")
	sshEnabled := s.kernel == nil || s.kernel.HasTransportKind("ssh")

	adbMissing := s.opts.Runtime.AdbPath == ""
	devs := []DeviceInfo{}
	var adbErr string
	if adbEnabled && !adbMissing {
		list, err := s.ListDevices(r.Context())
		if err != nil {
			adbErr = err.Error()
		} else if list != nil {
			devs = list
		}
	}
	sshTargets := []sshclient.Target{}
	sshDevs := []DeviceInfo{}
	if sshEnabled {
		sshTargets = s.sshStore.List()
		sshDevs = s.sshDevicesSnapshot()
	}
	all := append([]DeviceInfo{}, devs...)
	all = append(all, sshDevs...)

	writeJSON(w, http.StatusOK, map[string]any{
		"devices":          all,
		"adb_devices":      devs,
		"ssh_targets":      sshTargets,
		"adb_enabled":      adbEnabled,
		"ssh_enabled":      sshEnabled,
		"adb_path":         s.opts.Runtime.AdbPath,
		"adb_missing":      adbMissing,
		"adb_error":        adbErr,
		"ssh_available":    s.ssh != nil && s.ssh.Available(),
		"ssh_path":         s.ssh.SSHPath,
		"available_agents": s.availableAgentKeys(),
	})
}

// ---- SSH Target CRUD ----

func (s *Server) handleSSHTargetsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"ssh_available":    s.ssh != nil && s.ssh.Available(),
		"ssh_path":         s.ssh.SSHPath,
		"targets":          s.sshStore.List(),
		"available_agents": s.availableAgentKeys(),
	})
}

func (s *Server) handleSSHTargetsUpsert(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	port := 22
	if p, ok := b.int("port"); ok && p > 0 && p <= 65535 {
		port = int(p)
	}
	useSudo := true
	if _, present := b["use_sudo"]; present {
		useSudo = b.bool("use_sudo")
	}
	t := sshclient.Target{
		ID:           b.str("id"),
		Name:         b.str("name"),
		Host:         b.str("host"),
		Port:         port,
		User:         b.str("user"),
		IdentityFile: b.str("identity_file"),
		UseSudo:      useSudo,
		RemoteDir:    b.str("remote_dir"),
	}
	saved, err := s.sshStore.Upsert(t)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"target":  saved,
		"serial":  saved.Serial(),
		"targets": s.sshStore.List(),
	})
}

func (s *Server) handleSSHTargetsDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		if b, err := readBody(r); err == nil {
			id = b.str("id")
		}
	}
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	if err := s.sshStore.Delete(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"deleted": id,
		"targets": s.sshStore.List(),
	})
}

func (s *Server) handleSSHTest(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var t sshclient.Target
	if id := b.str("id"); id != "" && b.str("host") == "" {
		var ok bool
		t, ok = s.sshStore.Get(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "ssh target not found: "+id)
			return
		}
	} else {
		port := 22
		if p, ok := b.int("port"); ok && p > 0 && p <= 65535 {
			port = int(p)
		}
		t = sshclient.Target{
			Host:         b.str("host"),
			Port:         port,
			User:         b.str("user"),
			IdentityFile: b.str("identity_file"),
			UseSudo:      b.bool("use_sudo"),
		}
	}
	probe, err := s.ssh.Probe(r.Context(), t)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	_, agentKey := s.pickLinuxAgent(probe.Arch)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"probe":     probe,
		"agent_key": agentKey,
	})
}

func (s *Server) pickLinuxAgent(arch string) (adb.AgentBinary, string) {
	a := strings.ToLower(strings.TrimSpace(arch))
	switch a {
	case "x86_64", "amd64":
		if ab, ok := s.opts.Runtime.Agents["linux-x86_64"]; ok {
			return ab, "linux-x86_64"
		}
	case "aarch64", "arm64":
		if ab, ok := s.opts.Runtime.Agents["linux-arm64"]; ok {
			return ab, "linux-arm64"
		}
	}
	return adb.AgentBinary{}, ""
}

// PrepareResult is returned by POST /api/device/prepare.
type PrepareResult struct {
	OK          bool   `json:"ok"`
	Serial      string `json:"serial"`
	Transport   string `json:"transport"`
	Arch        string `json:"arch,omitempty"`
	RootMode    string `json:"root_mode"`
	Kernel      string `json:"kernel"`
	AndroidVer  string `json:"android_ver,omitempty"`
	Model       string `json:"model"`
	AgentSHA256 string `json:"agent_sha256"`
	AgentPushed bool   `json:"agent_pushed"`
	AgentPath   string `json:"agent_path"`
	ElapsedMs   int64  `json:"elapsed_ms"`
	Error       string `json:"error,omitempty"`
}

func (s *Server) prepareSSH(ctx context.Context, serial, targetID string) PrepareResult {
	t0 := time.Now()
	res := PrepareResult{Serial: serial, Transport: "ssh"}
	defer func() { res.ElapsedMs = time.Since(t0).Milliseconds() }()

	t, ok := s.sshStore.Get(targetID)
	if !ok {
		res.Error = "SSH target not found: " + targetID
		return res
	}
	res.Model = t.Name
	res.AgentPath = s.ssh.RemoteAgentPath(t)

	probe, err := s.ssh.Probe(ctx, t)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Arch = probe.Arch
	res.Kernel = probe.Kernel
	res.RootMode = probe.RootMode
	if probe.Hostname != "" {
		res.Model = t.Name + " (" + probe.Hostname + ")"
	}
	if probe.RootMode == "none" {
		res.Error = "remote Linux user lacks root/passwordless sudo (configure root SSH or `sudo -n` for eBPF capture)"
		return res
	}
	agent, key := s.pickLinuxAgent(probe.Arch)
	if agent.Path == "" {
		res.Error = fmt.Sprintf("no configured Linux collector for remote arch %q (package must include a matching target)", probe.Arch)
		return res
	}
	pushed, sha, err := s.ssh.EnsureAgent(ctx, t, agent.Path, agent.SHA256)
	res.AgentPushed, res.AgentSHA256 = pushed, sha
	if err != nil {
		res.Error = fmt.Sprintf("upload %s agent: %v", key, err)
		return res
	}
	st := s.state(serial)
	s.mu.Lock()
	st.RootMode, st.Kernel, st.AgentSHA256, st.PreparedAt = probe.RootMode, probe.Kernel, sha, time.Now()
	s.mu.Unlock()
	res.OK = true
	return res
}

// Prepare ensures root + injects the matching collector agent (ADB or SSH).
func (s *Server) Prepare(ctx context.Context, serial string) PrepareResult {
	if id, isSSH := sshclient.IsSSHSerial(serial); isSSH {
		return s.prepareSSH(ctx, serial, id)
	}
	t0 := time.Now()
	res := PrepareResult{Serial: serial, Transport: "adb", Arch: "arm64", AgentPath: adb.RemoteAgent}
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

func (s *Server) defaultSerial(ctx context.Context) string {
	if s.opts.Runtime.AdbPath != "" {
		ents, err := s.adb.Devices(ctx)
		if err == nil {
			for _, e := range ents {
				if e.State == "device" {
					return e.Serial
				}
			}
		}
	}
	if list := s.sshStore.List(); len(list) > 0 {
		return list[0].Serial()
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

func (s *Server) ensureReady(ctx context.Context, serial string) error {
	st := s.state(serial)
	s.mu.Lock()
	var ready bool
	if _, isSSH := sshclient.IsSSHSerial(serial); isSSH {
		ready = st.AgentSHA256 != "" && st.RootMode != "" && st.RootMode != "none"
	} else {
		ready = st.AgentSHA256 != "" && st.AgentSHA256 == s.opts.Runtime.AgentSHA256 && s.adb.RootMode(serial) != ""
	}
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

func pickDefaultIface(ifs []adb.Iface, fallback string) string {
	if fallback != "" {
		for _, it := range ifs {
			if it.Name == fallback {
				return fallback
			}
		}
	}
	for _, pref := range []string{"wlan0", "eth0", "ens33", "enp0s3"} {
		for _, it := range ifs {
			if it.Name == pref {
				return pref
			}
		}
	}
	for _, it := range ifs {
		if it.Name != "lo" && strings.EqualFold(it.State, "UP") {
			return it.Name
		}
	}
	if len(ifs) > 0 {
		return ifs[0].Name
	}
	if fallback != "" {
		return fallback
	}
	return "eth0"
}

// Inspect lists interfaces and runs `pktpath inspect --json` on ADB or SSH.
func (s *Server) Inspect(ctx context.Context, serial, dev, scope string, enablePlugins bool) InspectResult {
	res := InspectResult{Serial: serial, Dev: dev, Scope: scope, Interfaces: []adb.Iface{}, Inspect: json.RawMessage("null")}
	if targetID, isSSH := sshclient.IsSSHSerial(serial); isSSH {
		t, ok := s.sshStore.Get(targetID)
		if !ok {
			res.Error = "SSH target not found: " + targetID
			return res
		}
		if r, err := s.ssh.Exec(ctx, t, "ip -br addr 2>/dev/null || ip -o addr", false, 10*time.Second); err == nil || r.Stdout != "" {
			res.Interfaces = adb.ParseIPBrAddr(r.Stdout)
		}
		if dev == "" {
			dev = pickDefaultIface(res.Interfaces, "eth0")
			res.Dev = dev
		}
		if err := s.ensureReady(ctx, serial); err != nil {
			res.Error = err.Error()
			return res
		}
		cmd := adb.ShQuote(s.ssh.RemoteAgentPath(t)) + " inspect --dev " + adb.ShQuote(dev) + " --scope " + adb.ShQuote(scope)
		if enablePlugins {
			paths := s.activeKernelPluginFiles()
			if n, perr := s.ssh.SyncPluginFiles(ctx, t, paths); perr == nil && n > 0 {
				cmd += " --plugin-dir " + adb.ShQuote(s.ssh.RemotePluginsDir(t))
			}
		}
		cmd += " --json"
		r, err := s.ssh.Exec(ctx, t, cmd, true, 45*time.Second)
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

	if r, err := s.adb.Shell(ctx, serial, "ip -br addr 2>/dev/null || ip -o addr", 10*time.Second); err == nil || r.Stdout != "" {
		res.Interfaces = adb.ParseIPBrAddr(r.Stdout)
	}
	if dev == "" {
		dev = pickDefaultIface(res.Interfaces, "wlan0")
		res.Dev = dev
	}
	if err := s.ensureReady(ctx, serial); err != nil {
		res.Error = err.Error()
		return res
	}
	cmd := adb.RemoteAgent + " inspect --dev " + adb.ShQuote(dev) + " --scope " + adb.ShQuote(scope)
	if enablePlugins {
		paths := s.activeKernelPluginFiles()
		if n, perr := s.adb.SyncPluginFiles(ctx, serial, paths); perr == nil && n > 0 {
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
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "tc-egress"
	}
	if dev != "" && !reDev.MatchString(dev) {
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
	if targetID, isSSH := sshclient.IsSSHSerial(serial); isSSH {
		t, ok := s.sshStore.Get(targetID)
		if !ok {
			writeErr(w, http.StatusNotFound, "SSH target not found: "+targetID)
			return
		}
		apps, err := s.ssh.ListUsersAndProcs(r.Context(), t)
		if len(apps) == 0 && err != nil {
			writeErrExtra(w, http.StatusInternalServerError, err.Error(), map[string]any{"apps": []adb.App{}})
			return
		}
		if apps == nil {
			apps = []adb.App{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "serial": serial, "apps": apps})
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
