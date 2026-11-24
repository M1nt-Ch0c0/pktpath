package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"pktpath/studio/pkg/adb"
)

// SelftestOptions configures RunSelftest.
type SelftestOptions struct {
	Serial      string
	Dev         string
	KeepSession bool
}

// SelftestReport is the JSON summary emitted by `--selftest`.
type SelftestReport struct {
	OK              bool           `json:"ok"`
	StartedAt       string         `json:"started_at"`
	ElapsedMs       int64          `json:"elapsed_ms"`
	Runtime         *adb.Runtime   `json:"runtime"`
	HTTPBaseURL     string         `json:"http_base_url"`
	WebChecked      bool           `json:"web_checked"`
	DeviceConnected bool           `json:"device_connected"`
	Serial          string         `json:"serial,omitempty"`
	Model           string         `json:"model,omitempty"`
	Kernel          string         `json:"kernel,omitempty"`
	RootMode        string         `json:"root_mode,omitempty"`
	AgentSHA256     string         `json:"agent_sha256,omitempty"`
	InterfaceCount  int            `json:"interface_count,omitempty"`
	AppCount        int            `json:"app_count,omitempty"`
	CaptureID       string         `json:"capture_id,omitempty"`
	SessionID       string         `json:"session_id,omitempty"`
	SampleCount     int            `json:"sample_count,omitempty"`
	PcapngBytes     int            `json:"pcapng_bytes,omitempty"`
	PcapngMagicOK   bool           `json:"pcapng_magic_ok,omitempty"`
	RemoteCleaned   bool           `json:"remote_cleaned,omitempty"`
	Steps           []string       `json:"steps"`
	Extra           map[string]any `json:"extra,omitempty"`
	Error           string         `json:"error,omitempty"`
}

// RunSelftest runs an end-to-end automated self-test against the live HTTP
// server (and a connected Android device if available).
func (s *Server) RunSelftest(ctx context.Context, opts SelftestOptions) (rep SelftestReport) {
	t0 := time.Now()
	rep = SelftestReport{
		StartedAt: t0.Format(time.RFC3339),
		Runtime:   s.opts.Runtime,
		Steps:     []string{},
	}
	defer func() { rep.ElapsedMs = time.Since(t0).Milliseconds() }()

	step := func(msg string) {
		rep.Steps = append(rep.Steps, msg)
		s.log.Printf("[selftest] %s", msg)
	}
	fail := func(format string, args ...any) SelftestReport {
		rep.Error = fmt.Sprintf(format, args...)
		s.log.Printf("[selftest] FAIL: %s", rep.Error)
		return rep
	}

	if s.opts.Runtime == nil || s.opts.Runtime.AdbPath == "" {
		return fail("adb runtime missing")
	}
	if _, err := os.Stat(s.opts.Runtime.AdbPath); err != nil {
		return fail("adb binary missing at %s: %v", s.opts.Runtime.AdbPath, err)
	}
	step("runtime_ok: " + s.opts.Runtime.AdbPath)

	ln, err := s.Listen("127.0.0.1:0")
	if err != nil {
		return fail("listen: %v", err)
	}
	go func() { _ = s.Serve(ln) }()
	defer s.Shutdown(context.Background())

	base := "http://" + ln.Addr().String()
	rep.HTTPBaseURL = base
	hc := &http.Client{Timeout: 90 * time.Second}

	// 1. Static web UI check
	if status, raw, err := httpReq(ctx, hc, http.MethodGet, base+"/", nil); err != nil || status != 200 || len(raw) == 0 {
		return fail("GET / failed: status=%d err=%v", status, err)
	}
	rep.WebChecked = true
	step("web_index_ok")

	// 1b. Plugins endpoint check
	var plugResp struct {
		OK         bool   `json:"ok"`
		PluginsDir string `json:"plugins_dir"`
	}
	if err := httpJSON(ctx, hc, http.MethodGet, base+"/api/plugins", nil, &plugResp); err != nil || !plugResp.OK {
		return fail("GET /api/plugins failed: %v", err)
	}
	step("plugins_api_ok")

	// 2. Devices check
	var devResp struct {
		Devices []DeviceInfo `json:"devices"`
		Error   string       `json:"error"`
	}
	if err := httpJSON(ctx, hc, http.MethodGet, base+"/api/devices", nil, &devResp); err != nil {
		return fail("GET /api/devices: %v", err)
	}
	var chosen *DeviceInfo
	for i := range devResp.Devices {
		d := &devResp.Devices[i]
		if d.State != "device" {
			continue
		}
		if opts.Serial == "" || d.Serial == opts.Serial {
			chosen = d
			break
		}
	}
	if chosen == nil {
		if opts.Serial != "" {
			return fail("requested device %q not connected (found %d devices)", opts.Serial, len(devResp.Devices))
		}
		step("no_online_device: skipping live phone steps")
		rep.OK = true
		return rep
	}
	rep.DeviceConnected = true
	rep.Serial = chosen.Serial
	rep.Model = chosen.Model
	rep.Kernel = chosen.Kernel
	step("device_found: " + chosen.Serial + " (" + chosen.Model + ")")

	// 3. Prepare root + inject agent
	var prep PrepareResult
	if err := httpJSON(ctx, hc, http.MethodPost, base+"/api/device/prepare", map[string]any{"serial": chosen.Serial}, &prep); err != nil {
		return fail("POST /api/device/prepare: %v (%s)", err, prep.Error)
	}
	if !prep.OK {
		return fail("device prepare failed: %s", prep.Error)
	}
	rep.RootMode = prep.RootMode
	rep.AgentSHA256 = prep.AgentSHA256
	if prep.Kernel != "" {
		rep.Kernel = prep.Kernel
	}
	step("device_prepared: root=" + prep.RootMode + " sha=" + adb.ShortSHA(prep.AgentSHA256, 12))

	// 4. Inspect interfaces + tc topology
	dev := opts.Dev
	if dev == "" {
		dev = "wlan0"
	}
	var insp InspectResult
	inspURL := fmt.Sprintf("%s/api/device/inspect?serial=%s&dev=%s&scope=tc-egress", base, url.QueryEscape(chosen.Serial), url.QueryEscape(dev))
	if err := httpJSON(ctx, hc, http.MethodGet, inspURL, nil, &insp); err != nil {
		return fail("GET /api/device/inspect: %v (%s)", err, insp.Error)
	}
	if !insp.OK {
		return fail("inspect not ok: %s", insp.Error)
	}
	rep.InterfaceCount = len(insp.Interfaces)
	step(fmt.Sprintf("inspect_ok: %d interfaces", len(insp.Interfaces)))

	// 5. Apps list
	var appsResp struct {
		Apps []adb.App `json:"apps"`
	}
	if err := httpJSON(ctx, hc, http.MethodGet, base+"/api/device/apps?serial="+url.QueryEscape(chosen.Serial), nil, &appsResp); err != nil {
		return fail("GET /api/device/apps: %v", err)
	}
	rep.AppCount = len(appsResp.Apps)
	step(fmt.Sprintf("apps_ok: %d packages", len(appsResp.Apps)))

	// 6. Short 2s live capture while generating gentle egress traffic on dev
	gw := s.detectGateway(ctx, chosen.Serial, dev)
	var startResp struct {
		OK        bool   `json:"ok"`
		CaptureID string `json:"capture_id"`
		Error     string `json:"error"`
	}
	startBody := map[string]any{
		"serial":          chosen.Serial,
		"mode":            "oneshot",
		"dev":             dev,
		"scope":           "tc-egress",
		"uid":             -1,
		"sample":          "1/1",
		"sample_by":       "pkt",
		"duration_sec":    4,
		"capture_hdr":     96,
		"profile_sendmsg": false,
		"allow_partial":   true,
	}
	if err := httpJSON(ctx, hc, http.MethodPost, base+"/api/capture/start", startBody, &startResp); err != nil {
		return fail("POST /api/capture/start: %v (%s)", err, startResp.Error)
	}
	rep.CaptureID = startResp.CaptureID
	step("capture_started: " + startResp.CaptureID)

	if gw != "" {
		_, _ = s.adb.Shell(ctx, chosen.Serial, fmt.Sprintf("ping -I %s -c 5 -i 0.2 -W 1 %s >/dev/null 2>&1 || true", adb.ShQuote(dev), adb.ShQuote(gw)), 5*time.Second)
	} else {
		time.Sleep(1500 * time.Millisecond)
	}

	var statusResp map[string]any
	_ = httpJSON(ctx, hc, http.MethodGet, base+"/api/capture/status", nil, &statusResp)
	step("capture_status_polled")

	var stopResp StopResult
	if err := httpJSON(ctx, hc, http.MethodPost, base+"/api/capture/stop", map[string]any{}, &stopResp); err != nil {
		return fail("POST /api/capture/stop: %v (%s)", err, stopResp.Error)
	}
	if !stopResp.OK {
		return fail("capture stop failed: %s", stopResp.Error)
	}
	rep.SessionID = stopResp.SessionID
	rep.RemoteCleaned = stopResp.RemoteCleaned
	if !opts.KeepSession && stopResp.SessionPath != "" {
		defer func(p string) { _ = os.RemoveAll(p) }(stopResp.SessionPath)
	}
	step("capture_stopped_and_pulled: " + stopResp.SessionID)

	// 7. Overview + first sample + pcapng export
	var ov struct {
		Samples []struct {
			SampleID uint64 `json:"sample_id"`
		} `json:"samples"`
	}
	if err := httpJSON(ctx, hc, http.MethodGet, base+"/api/session/overview?id="+url.QueryEscape(stopResp.SessionID), nil, &ov); err != nil {
		return fail("GET /api/session/overview: %v", err)
	}
	rep.SampleCount = len(ov.Samples)
	step(fmt.Sprintf("overview_ok: %d samples", rep.SampleCount))

	if len(ov.Samples) > 0 {
		sid := ov.Samples[0].SampleID
		var detail map[string]any
		u := fmt.Sprintf("%s/api/session/sample?id=%s&sample_id=%d", base, url.QueryEscape(stopResp.SessionID), sid)
		if err := httpJSON(ctx, hc, http.MethodGet, u, nil, &detail); err != nil {
			return fail("GET /api/session/sample: %v", err)
		}
		step(fmt.Sprintf("sample_detail_ok: sample_id=%d", sid))
	}

	code, pcapBytes, err := httpReq(ctx, hc, http.MethodGet, base+"/api/session/export-pcapng?id="+url.QueryEscape(stopResp.SessionID), nil)
	if err != nil || code != 200 {
		return fail("GET /api/session/export-pcapng: status=%d err=%v", code, err)
	}
	rep.PcapngBytes = len(pcapBytes)
	if len(pcapBytes) >= 4 && binary.LittleEndian.Uint32(pcapBytes[:4]) == 0x0A0D0D0A {
		rep.PcapngMagicOK = true
	} else {
		return fail("invalid pcapng SHB magic (%d bytes)", len(pcapBytes))
	}
	step(fmt.Sprintf("pcapng_ok: %d bytes", len(pcapBytes)))

	rep.OK = true
	return rep
}

func (s *Server) detectGateway(ctx context.Context, serial, dev string) string {
	r, err := s.adb.Shell(ctx, serial, "ip -4 route show dev "+adb.ShQuote(dev)+" 2>/dev/null; ip -4 route show table all dev "+adb.ShQuote(dev)+" 2>/dev/null", 5*time.Second)
	if err != nil && r.Stdout == "" {
		return ""
	}
	for _, ln := range strings.Split(r.Stdout, "\n") {
		f := strings.Fields(ln)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "via" && strings.Count(f[i+1], ".") == 3 {
				return f[i+1]
			}
		}
	}
	return ""
}

func httpReq(ctx context.Context, hc *http.Client, method, u string, reqBody any) (int, []byte, error) {
	var rd io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

func httpJSON(ctx context.Context, hc *http.Client, method, u string, reqBody any, dst any) error {
	code, raw, err := httpReq(ctx, hc, method, u, reqBody)
	if len(raw) > 0 && dst != nil {
		_ = json.Unmarshal(raw, dst)
	}
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(raw)), 400))
	}
	return nil
}
