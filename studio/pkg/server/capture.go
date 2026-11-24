package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"pktpath/studio/pkg/adb"
)

// Capture phases.
const (
	phaseRunning  = "running"
	phaseStopping = "stopping"
	phasePulling  = "pulling"
	phaseParsing  = "reconstructing"
	phaseDone     = "done"
	phaseError    = "error"
)

// StopResult is returned by POST /api/capture/stop.
type StopResult struct {
	OK            bool     `json:"ok"`
	CaptureID     string   `json:"capture_id"`
	SessionID     string   `json:"session_id"`
	SessionPath   string   `json:"session_path"`
	Overview      any      `json:"overview"`
	RemoteCleaned bool     `json:"remote_cleaned"`
	CleanExit     bool     `json:"clean_exit"`
	SelfExited    bool     `json:"self_exited"`
	LogLines      []string `json:"log_lines,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type captureState struct {
	mu sync.Mutex

	ID          string
	Serial      string
	Mode        string
	Dev         string
	Scope       string
	DurationSec int64
	Args        []string
	Run         *adb.RemoteRun
	Started     time.Time
	Ended       time.Time
	Phase       string
	Logs        []string
	Err         string

	finalizeOnce sync.Once
	done         chan struct{}
	result       *StopResult
	stopMonitor  chan struct{}
}

func (c *captureState) active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Phase != phaseDone && c.Phase != phaseError
}

var (
	reIPCIDR   = regexp.MustCompile(`^[0-9A-Fa-f:.]+(/\d{1,3})?$`)
	reMark     = regexp.MustCompile(`^(0x[0-9A-Fa-f]+|\d+)(/(0x[0-9A-Fa-f]+|\d+))?$`)
	reSample   = regexp.MustCompile(`^(1/)?\d{1,7}$`)
	reTrigger  = regexp.MustCompile(`^[a-z_]+>\d+(,\s*[a-z_]+>\d+)*$`)
	reBudget   = regexp.MustCompile(`^\d+[KkMmGg]?[Bb]?$`)
	validProto = map[string]string{"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6", "icmp6": "icmpv6"}
)

// CaptureRequest is the normalised POST /api/capture/start body.
type CaptureRequest struct {
	Serial        string
	Mode          string
	Dev           string
	Scope         string
	Args          []string
	DurSec        int64
	EnablePlugins bool
}

// BuildRecordArgs validates the loosely-typed UI body and returns pktpath
// record CLI arguments (without --out).
func BuildRecordArgs(b body) (*CaptureRequest, error) {
	req := &CaptureRequest{Serial: b.str("serial"), Mode: strings.ToLower(b.str("mode")), Dev: b.str("dev"), Scope: b.str("scope")}
	if req.Mode == "" {
		req.Mode = "oneshot"
	}
	if req.Mode != "oneshot" && req.Mode != "daemon" {
		return nil, fmt.Errorf("invalid mode %q (oneshot|daemon)", req.Mode)
	}
	if req.Dev == "" {
		req.Dev = "wlan0"
	}
	if !reDev.MatchString(req.Dev) {
		return nil, fmt.Errorf("invalid dev %q", req.Dev)
	}
	if req.Scope == "" {
		req.Scope = "tc-egress"
	}
	if !scopes[req.Scope] {
		return nil, fmt.Errorf("invalid scope %q", req.Scope)
	}
	a := []string{"--mode", req.Mode, "--dev", req.Dev, "--scope", req.Scope}

	if uid, ok := b.int("uid"); ok && uid >= 0 && uid < 0xFFFFFFFF {
		a = append(a, "--uid", strconv.FormatInt(uid, 10))
	}
	if tg, ok := b.int("tgid"); ok && tg > 0 {
		a = append(a, "--tgid", strconv.FormatInt(tg, 10))
	}
	if p := strings.ToLower(b.str("proto")); p != "" && p != "all" && p != "any" && p != "*" {
		norm, ok := validProto[p]
		if !ok {
			return nil, fmt.Errorf("invalid proto %q", p)
		}
		a = append(a, "--proto", norm)
	}
	for _, k := range []string{"src_ip", "dst_ip"} {
		if v := b.str(k); v != "" && v != "any" {
			if !reIPCIDR.MatchString(v) {
				return nil, fmt.Errorf("invalid %s %q", k, v)
			}
			a = append(a, "--"+strings.ReplaceAll(k, "_", "-"), v)
		}
	}
	for _, k := range []string{"src_port", "dst_port"} {
		if v, ok := b.int(k); ok && v != 0 {
			if v < 0 || v > 65535 {
				return nil, fmt.Errorf("invalid %s %d", k, v)
			}
			a = append(a, "--"+strings.ReplaceAll(k, "_", "-"), strconv.FormatInt(v, 10))
		}
	}
	if v := b.str("mark"); v != "" {
		if !reMark.MatchString(v) {
			return nil, fmt.Errorf("invalid mark %q", v)
		}
		a = append(a, "--mark", v)
	}
	if v := b.str("sample"); v != "" {
		if !reSample.MatchString(v) {
			return nil, fmt.Errorf("invalid sample %q (expected 1/N)", v)
		}
		if !strings.HasPrefix(v, "1/") && v != "0" {
			v = "1/" + v
		}
		a = append(a, "--sample", v)
	}
	if v := strings.ToLower(b.str("sample_by")); v != "" {
		if v != "pkt" && v != "flow" {
			return nil, fmt.Errorf("invalid sample_by %q", v)
		}
		a = append(a, "--sample-by", v)
	}
	dur, hasDur := b.int("duration_sec")
	if req.Mode == "oneshot" {
		if !hasDur || dur <= 0 {
			dur = 10
		}
	}
	if dur > 0 {
		if dur > 24*3600 {
			return nil, fmt.Errorf("duration_sec too large")
		}
		a = append(a, "--duration", strconv.FormatInt(dur, 10)+"s")
		req.DurSec = dur
	}
	if v, ok := b.int("capture_hdr"); ok && v > 0 {
		if v > 128 {
			v = 128
		}
		a = append(a, "--capture-hdr", strconv.FormatInt(v, 10))
	}
	if b.bool("profile_sendmsg") {
		a = append(a, "--profile", "sendmsg")
	}
	req.EnablePlugins = true
	if _, present := b["enable_plugins"]; present {
		req.EnablePlugins = b.bool("enable_plugins")
	}
	if b.bool("allow_partial") {
		a = append(a, "--allow-partial")
	}
	if req.Mode == "daemon" {
		trig := b.str("trigger")
		if n, err := strconv.ParseInt(trig, 10, 64); err == nil && n > 0 {
			trig = "sojourn_us>" + strconv.FormatInt(n, 10)
		}
		trig = strings.ReplaceAll(trig, " ", "")
		if trig != "" {
			if !reTrigger.MatchString(trig) {
				return nil, fmt.Errorf("invalid trigger %q", trig)
			}
			a = append(a, "--trigger", trig)
		}
		if v, ok := b.int("pre_window_sec"); ok && v > 0 {
			a = append(a, "--pre-window", strconv.FormatInt(v, 10)+"s")
		}
		if v, ok := b.int("post_window_sec"); ok && v > 0 {
			a = append(a, "--post-window", strconv.FormatInt(v, 10)+"s")
		}
	}
	for _, k := range []string{"mem_budget", "disk_budget"} {
		if v := b.str(k); v != "" {
			if !reBudget.MatchString(v) {
				return nil, fmt.Errorf("invalid %s %q", k, v)
			}
			a = append(a, "--"+strings.ReplaceAll(k, "_", "-"), v)
		}
	}
	req.Args = a
	return req, nil
}

// StartCapture launches a background capture.
func (s *Server) StartCapture(ctx context.Context, req *CaptureRequest) (*captureState, error) {
	s.capMu.Lock()
	if s.cap != nil && s.cap.active() {
		cur := s.cap
		s.capMu.Unlock()
		return cur, fmt.Errorf("a capture is already active (%s on %s)", cur.ID, cur.Serial)
	}
	s.capMu.Unlock()

	if err := s.ensureReady(ctx, req.Serial); err != nil {
		return nil, err
	}
	args := append([]string(nil), req.Args...)
	if req.EnablePlugins && s.pluginsDir != "" {
		if n, perr := s.adb.SyncPlugins(ctx, req.Serial, s.pluginsDir); perr != nil {
			return nil, fmt.Errorf("sync plugins: %w", perr)
		} else if n > 0 {
			args = append(args, "--plugin-dir", adb.RemotePluginsDir)
		}
	}
	id := time.Now().Format("20060102_150405")
	run, err := s.adb.StartRecord(ctx, req.Serial, id, args)
	if err != nil {
		return nil, err
	}
	c := &captureState{
		ID: id, Serial: req.Serial, Mode: req.Mode, Dev: req.Dev, Scope: req.Scope,
		DurationSec: req.DurSec, Args: req.Args, Run: run, Started: time.Now(), Phase: phaseRunning,
		done: make(chan struct{}), stopMonitor: make(chan struct{}),
	}
	s.capMu.Lock()
	s.cap = c
	s.capMu.Unlock()
	s.log.Printf("capture %s started on %s pid=%d: %s", id, req.Serial, run.PID, run.Command)

	// Catch immediate failures (bad args, BPF load error) synchronously.
	time.Sleep(900 * time.Millisecond)
	alive, lines, _ := s.adb.Poll(ctx, req.Serial, run, 60)
	c.mu.Lock()
	if lines != nil {
		c.Logs = lines
	}
	c.mu.Unlock()
	if !alive && !s.adb.RemoteExists(ctx, req.Serial, run.OutDir+"/manifest.json") {
		msg := "pktpath record exited immediately"
		if len(lines) > 0 {
			msg += ": " + lines[len(lines)-1]
		}
		c.finalizeOnce.Do(func() {
			c.mu.Lock()
			c.Phase, c.Err, c.Ended = phaseError, msg, time.Now()
			c.result = &StopResult{CaptureID: id, Error: msg, LogLines: lines}
			c.mu.Unlock()
			close(c.done)
		})
		go s.adb.CleanupRun(context.Background(), req.Serial, run)
		return c, fmt.Errorf("%s", msg)
	}
	go s.monitor(c)
	return c, nil
}

func (s *Server) monitor(c *captureState) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stopMonitor:
			return
		case <-c.done:
			return
		case <-t.C:
		}
		c.mu.Lock()
		phase := c.Phase
		c.mu.Unlock()
		if phase != phaseRunning {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		alive, lines, err := s.adb.Poll(ctx, c.Serial, c.Run, 60)
		cancel()
		if err != nil {
			continue
		}
		c.mu.Lock()
		if lines != nil {
			c.Logs = lines
		}
		c.mu.Unlock()
		if !alive {
			// Recorder finished by itself (oneshot duration elapsed): auto-pull.
			go s.finalize(c, true)
			return
		}
	}
}

// finalize stops (if needed), pulls, cleans up and reconstructs exactly once.
func (s *Server) finalize(c *captureState, selfExit bool) {
	c.finalizeOnce.Do(func() {
		res := &StopResult{CaptureID: c.ID, SelfExited: selfExit}
		defer func() {
			c.mu.Lock()
			c.result = res
			c.Ended = time.Now()
			if res.OK {
				c.Phase = phaseDone
			} else {
				c.Phase = phaseError
				c.Err = res.Error
			}
			res.LogLines = append([]string(nil), c.Logs...)
			c.mu.Unlock()
			close(c.done)
			s.log.Printf("capture %s finalized ok=%v session=%s err=%s", c.ID, res.OK, res.SessionID, res.Error)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		setPhase := func(p string) { c.mu.Lock(); c.Phase = p; c.mu.Unlock() }

		setPhase(phaseStopping)
		res.CleanExit = true
		alive, lines, _ := s.adb.Poll(ctx, c.Serial, c.Run, 80)
		if alive {
			_ = s.adb.Signal(ctx, c.Serial, c.Run.PID, "INT")
			deadline := time.Now().Add(8 * time.Second)
			for alive && time.Now().Before(deadline) {
				time.Sleep(300 * time.Millisecond)
				alive, lines, _ = s.adb.Poll(ctx, c.Serial, c.Run, 80)
			}
			if alive {
				res.CleanExit = false
				_ = s.adb.Signal(ctx, c.Serial, c.Run.PID, "TERM")
				time.Sleep(2 * time.Second)
				if alive, _, _ = s.adb.Poll(ctx, c.Serial, c.Run, 10); alive {
					_ = s.adb.Signal(ctx, c.Serial, c.Run.PID, "KILL")
					time.Sleep(500 * time.Millisecond)
				}
			}
		}
		if lines != nil {
			c.mu.Lock()
			c.Logs = lines
			c.mu.Unlock()
		}

		setPhase(phasePulling)
		if !s.adb.RemoteExists(ctx, c.Serial, c.Run.OutDir) {
			res.Error = "remote run directory missing (record failed?): " + lastOf(lines)
			res.RemoteCleaned = s.adb.CleanupRun(ctx, c.Serial, c.Run)
			return
		}
		s.adb.PrepareForPull(ctx, c.Serial, c.Run)
		name := sanitizeName(fmt.Sprintf("%s_%s_%s", c.ID, c.Serial, c.Dev))
		dst := uniquePath(filepath.Join(s.sessionsRoot, name))
		tmpParent := filepath.Join(s.sessionsRoot, ".pulling_"+c.ID)
		_ = os.RemoveAll(tmpParent)
		if err := s.adb.Pull(ctx, c.Serial, c.Run.OutDir, tmpParent+string(os.PathSeparator), 10*time.Minute); err != nil {
			res.Error = err.Error()
			_ = os.RemoveAll(tmpParent)
			return
		}
		pulled := filepath.Join(tmpParent, filepath.Base(c.Run.OutDir))
		if st, err := os.Stat(pulled); err != nil || !st.IsDir() {
			pulled = tmpParent // some adb versions copy contents directly
		}
		if err := os.Rename(pulled, dst); err != nil {
			res.Error = "move pulled session: " + err.Error()
			return
		}
		_ = os.RemoveAll(tmpParent)
		_ = s.adb.Pull(ctx, c.Serial, c.Run.LogPath, filepath.Join(dst, "studio_record.log"), time.Minute)
		res.RemoteCleaned = s.adb.CleanupRun(ctx, c.Serial, c.Run)

		setPhase(phaseParsing)
		id := s.sess.register(dst)
		res.SessionID, res.SessionPath = id, dst
		ov, err := s.sess.overview(id)
		if err != nil {
			res.Error = "reconstruct: " + err.Error()
			return
		}
		res.Overview = ov
		res.OK = true
	})
}

func lastOf(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

var reUnsafe = regexp.MustCompile(`[^A-Za-z0-9._\-]+`)

func sanitizeName(s string) string { return strings.Trim(reUnsafe.ReplaceAllString(s, "-"), "-.") }

func uniquePath(p string) string {
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return p
	}
	for i := 2; i < 1000; i++ {
		q := fmt.Sprintf("%s_%d", p, i)
		if _, err := os.Stat(q); os.IsNotExist(err) {
			return q
		}
	}
	return fmt.Sprintf("%s_%d", p, time.Now().UnixNano())
}

// StopCapture stops the active capture (or returns the last result).
func (s *Server) StopCapture(ctx context.Context) (*StopResult, error) {
	s.capMu.Lock()
	c := s.cap
	s.capMu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("no capture has been started")
	}
	go s.finalize(c, false)
	select {
	case <-c.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.result, nil
}

// HasActiveCapture reports whether a device capture is currently running/finalizing.
func (s *Server) HasActiveCapture() bool {
	s.capMu.Lock()
	c := s.cap
	s.capMu.Unlock()
	return c != nil && c.active()
}

// StopActiveCapture is used on window close / shutdown.
func (s *Server) StopActiveCapture(ctx context.Context) {
	s.capMu.Lock()
	c := s.cap
	s.capMu.Unlock()
	if c == nil || !c.active() {
		return
	}
	s.log.Printf("shutdown: stopping active capture %s", c.ID)
	_, _ = s.StopCapture(ctx)
}

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req, err := BuildRecordArgs(b)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Serial == "" {
		req.Serial = s.defaultSerial(r.Context())
	}
	if !reSerial.MatchString(req.Serial) {
		writeErr(w, http.StatusBadRequest, "invalid or missing serial")
		return
	}
	c, err := s.StartCapture(r.Context(), req)
	if err != nil {
		extra := map[string]any{}
		if c != nil {
			c.mu.Lock()
			extra["capture_id"] = c.ID
			extra["log_lines"] = append([]string(nil), c.Logs...)
			c.mu.Unlock()
		}
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already active") {
			code = http.StatusConflict
		}
		writeErrExtra(w, code, err.Error(), extra)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "capture_id": c.ID, "status": phaseRunning, "remote_pid": c.Run.PID,
		"remote_dir": c.Run.OutDir, "command": c.Run.Command, "serial": c.Serial, "mode": c.Mode, "dev": c.Dev,
	})
}

func (s *Server) handleCaptureStatus(w http.ResponseWriter, r *http.Request) {
	s.capMu.Lock()
	c := s.cap
	s.capMu.Unlock()
	st := map[string]any{
		"active": false, "capture_id": "", "serial": "", "mode": "", "dev": "", "scope": "", "phase": "idle",
		"elapsed_sec": 0, "duration_sec": 0, "log_lines": []string{}, "last_session_id": "", "session_path": "", "error": "",
	}
	if c != nil {
		c.mu.Lock()
		end := time.Now()
		if !c.Ended.IsZero() {
			end = c.Ended
		}
		logs := append([]string{}, c.Logs...)
		st["active"] = c.Phase != phaseDone && c.Phase != phaseError
		st["capture_id"], st["serial"], st["mode"], st["dev"], st["scope"] = c.ID, c.Serial, c.Mode, c.Dev, c.Scope
		st["phase"] = c.Phase
		st["elapsed_sec"] = float64(end.Sub(c.Started).Milliseconds()) / 1000.0
		st["duration_sec"] = c.DurationSec
		st["log_lines"] = logs
		st["remote_pid"] = c.Run.PID
		st["command"] = c.Run.Command
		st["error"] = c.Err
		if c.result != nil {
			st["last_session_id"] = c.result.SessionID
			st["session_path"] = c.result.SessionPath
		}
		c.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleCaptureFlush(w http.ResponseWriter, r *http.Request) {
	drainBody(r)
	s.capMu.Lock()
	c := s.cap
	s.capMu.Unlock()
	if c == nil || !c.active() {
		writeErr(w, http.StatusConflict, "no active capture")
		return
	}
	if c.Mode != "daemon" {
		writeErr(w, http.StatusBadRequest, "flush (SIGUSR1) is only meaningful in daemon mode")
		return
	}
	if err := s.adb.Signal(r.Context(), c.Serial, c.Run.PID, "USR1"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "capture_id": c.ID, "signal": "SIGUSR1", "remote_pid": c.Run.PID})
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	drainBody(r)
	res, err := s.StopCapture(r.Context())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if res == nil {
		writeErr(w, http.StatusInternalServerError, "capture finalized without result")
		return
	}
	code := http.StatusOK
	if !res.OK {
		code = http.StatusInternalServerError
	}
	writeJSON(w, code, res)
}
