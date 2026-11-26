package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cordisPluginRuntimeProtocol = "pktpath.cordis3.plugin-runtime/1"

// CordisPluginRuntimeOptions names the Node executable and plugin-runtime.mjs module.
type CordisPluginRuntimeOptions struct {
	NodePath string
	HostPath string
}

// CordisPluginRuntime is the new-preview in-process JS/TS plugin host.
// It talks to plugin-runtime.mjs over a small control protocol; analyze/export
// payloads are written to sidecar JSON files so they are not capped by the
// 64KiB control line and are not forced through JS Number on the wire.
type CordisPluginRuntime struct {
	opts   CordisPluginRuntimeOptions
	mu     sync.Mutex
	w      *cordisWorker
	tmpDir string
	closed bool
	loaded map[string]struct{}
}

// NewCordisPluginRuntime stores options; the Node worker starts on first Load.
func NewCordisPluginRuntime(opts CordisPluginRuntimeOptions) *CordisPluginRuntime {
	return &CordisPluginRuntime{opts: opts, loaded: map[string]struct{}{}}
}

// ResolveDefaultPluginRuntime locates the bundled plugin-runtime.mjs and a Node >=22 executable.
// explicitHost / explicitNode, when non-empty, are used as-is (node may be a bare LookPath name).
func ResolveDefaultPluginRuntime(explicitHost, explicitNode string) (host, node string, err error) {
	host, err = resolvePluginRuntimeHost(explicitHost)
	if err != nil {
		return "", "", err
	}
	node, err = resolvePluginRuntimeNode(explicitNode)
	if err != nil {
		return "", "", err
	}
	return host, node, nil
}

func resolvePluginRuntimeHost(explicit string) (string, error) {
	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	return resolvePluginRuntimeHostWithExeDir(explicit, exeDir)
}

func resolvePluginRuntimeHostWithExeDir(explicit, exeDir string) (string, error) {
	if s := strings.TrimSpace(explicit); s != "" {
		return mustExistingFile(s, "cordis plugin runtime host")
	}
	if s := strings.TrimSpace(os.Getenv("PKTPATH_CORDIS_PLUGIN_RUNTIME")); s != "" {
		return mustExistingFile(s, "cordis plugin runtime host")
	}
	var candidates []string
	if exeDir != "" {
		candidates = append(candidates,
			filepath.Join(exeDir, "cordis-analyzer-host", "plugin-runtime.mjs"),
			filepath.Join(exeDir, "studio", "cordis-analyzer-host", "plugin-runtime.mjs"),
		)
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		dir := filepath.Dir(file)
		candidates = append(candidates, filepath.Clean(filepath.Join(dir, "..", "..", "cordis-analyzer-host", "plugin-runtime.mjs")))
	}
	if cwd, err := os.Getwd(); err == nil {
		for d := cwd; ; {
			candidates = append(candidates,
				filepath.Join(d, "studio", "cordis-analyzer-host", "plugin-runtime.mjs"),
				filepath.Join(d, "cordis-analyzer-host", "plugin-runtime.mjs"),
			)
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, err := filepath.Abs(c)
			if err != nil {
				return "", err
			}
			return abs, nil
		}
	}
	return "", errors.New("bundled studio/cordis-analyzer-host/plugin-runtime.mjs not found")
}

func resolvePluginRuntimeNode(explicit string) (string, error) {
	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	return resolvePluginRuntimeNodeWithExeDir(explicit, exeDir, runtime.GOOS)
}

func resolvePluginRuntimeNodeWithExeDir(explicit, exeDir, goos string) (string, error) {
	try := func(s string) (string, bool) {
		s = strings.TrimSpace(s)
		if s == "" {
			return "", false
		}
		if filepath.Base(s) == s {
			if p, err := exec.LookPath(s); err == nil {
				return p, true
			}
			return "", false
		}
		if st, err := os.Stat(s); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(s)
			return abs, true
		}
		return "", false
	}
	if s := strings.TrimSpace(explicit); s != "" {
		if p, ok := try(s); ok {
			return p, nil
		}
		return "", fmt.Errorf("node runtime not found: %s", s)
	}
	if p, ok := try(os.Getenv("PKTPATH_CORDIS_NODE")); ok {
		return p, nil
	}
	if exeDir != "" {
		for _, c := range bundledNodeCandidates(exeDir, goos) {
			if p, ok := try(c); ok {
				return p, nil
			}
		}
	}
	for _, s := range []string{
		os.Getenv("PKTPATH_TEST_CORDIS_NODE"),
		"node",
	} {
		if p, ok := try(s); ok {
			return p, nil
		}
	}
	return "", errors.New("Node >=22 executable not found for Cordis plugin runtime")
}

func bundledNodeCandidates(exeDir, goos string) []string {
	if goos == "windows" {
		return []string{
			filepath.Join(exeDir, "node", "node.exe"),
			filepath.Join(exeDir, "runtime", "node", "node.exe"),
			filepath.Join(exeDir, "node.exe"),
		}
	}
	return []string{
		filepath.Join(exeDir, "node", "bin", "node"),
		filepath.Join(exeDir, "runtime", "node", "bin", "node"),
		filepath.Join(exeDir, "node", "node"),
	}
}

func mustExistingFile(path, what string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		return "", fmt.Errorf("%s not found: %s", what, path)
	}
	return abs, nil
}

func (h *CordisPluginRuntime) ensureLocked() error {
	if h.closed {
		return errors.New("cordis plugin runtime closed")
	}
	if h.w != nil {
		return nil
	}
	if strings.TrimSpace(h.opts.HostPath) == "" {
		return errors.New("missing Cordis plugin runtime module path")
	}
	w, err := startCordisWorkerMode(CordisAnalyzerOptions{NodePath: h.opts.NodePath, HostPath: h.opts.HostPath}, cordisPluginRuntimeProtocol, nil)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "pktpath-plugin-runtime-")
	if err != nil {
		w.abort()
		return err
	}
	h.w = w
	h.tmpDir = dir
	return nil
}

func validateRelativeModule(mod string) error {
	s := strings.TrimSpace(mod)
	if s == "" {
		return errors.New("missing entrypoint.module")
	}
	if filepath.IsAbs(s) || filepath.VolumeName(s) != "" {
		return fmt.Errorf("entrypoint.module must be relative to the package directory: %s", s)
	}
	clean := strings.ReplaceAll(s, "\\", "/")
	for _, part := range strings.Split(clean, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("entrypoint.module must be a relative path inside the package directory: %s", s)
		}
	}
	return nil
}

// Load imports a package's entrypoint.module into the Cordis host and calls optional setup(ctx).
func (h *CordisPluginRuntime) Load(ctx context.Context, pluginID, packageDir, module string, analyzers, exporters []string) error {
	if err := validateRelativeModule(module); err != nil {
		return err
	}
	absDir, err := filepath.Abs(packageDir)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.ensureLocked(); err != nil {
		return err
	}
	if _, ok := h.loaded[pluginID]; ok {
		return fmt.Errorf("plugin already loaded: %s", pluginID)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err = h.w.controlWithTimeout(callCtx, "load", map[string]any{
		"plugin_id":   pluginID,
		"package_dir": absDir,
		"module":      module,
		"analyzers":   analyzers,
		"exporters":   exporters,
	}, nil)
	if err != nil {
		return err
	}
	h.loaded[pluginID] = struct{}{}
	return nil
}

// Unload disposes the plugin and waits until async cleanup has finished.
func (h *CordisPluginRuntime) Unload(pluginID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.w == nil {
		delete(h.loaded, pluginID)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := h.w.controlWithTimeout(ctx, "unload", map[string]any{"plugin_id": pluginID}, nil)
	delete(h.loaded, pluginID)
	return err
}

// Analyze calls the loaded plugin's analyze(input) and validates the returned JSON.
func (h *CordisPluginRuntime) Analyze(ctx context.Context, pluginID, analyzerID string, payload any) (*AnalyzeOutput, error) {
	raw, err := h.roundTrip(ctx, 15*time.Second, "analyze", map[string]any{
		"plugin_id":   pluginID,
		"analyzer_id": analyzerID,
	}, payload)
	if err != nil {
		return nil, err
	}
	out, err := unmarshalAnalyzeOutput(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid analyzer JSON output: %w", err)
	}
	if err := validateAnalyzeOutput(out); err != nil {
		return nil, err
	}
	return out, nil
}

// Export calls the loaded plugin's exportSession(input).
func (h *CordisPluginRuntime) Export(ctx context.Context, pluginID, exporterID string, payload any, fallbackOut string) (*ExportOutput, error) {
	raw, err := h.roundTrip(ctx, 60*time.Second, "export", map[string]any{
		"plugin_id":   pluginID,
		"exporter_id": exporterID,
	}, payload)
	if err != nil {
		return nil, err
	}
	var out ExportOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("invalid exporter JSON output: %w", err)
	}
	if out.OutPath == "" {
		out.OutPath = fallbackOut
	}
	if out.OK {
		if _, err := os.Stat(out.OutPath); err != nil {
			return nil, fmt.Errorf("export claimed ok but out_path is missing: %w", err)
		}
	}
	return &out, nil
}

func (h *CordisPluginRuntime) roundTrip(ctx context.Context, timeout time.Duration, op string, fields map[string]any, payload any) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.ensureLocked(); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	inFile, err := os.CreateTemp(h.tmpDir, op+"-in-*.json")
	if err != nil {
		return nil, err
	}
	inName := inFile.Name()
	enc, err := json.Marshal(payload)
	if err != nil {
		inFile.Close()
		os.Remove(inName)
		return nil, err
	}
	_, err = inFile.Write(enc)
	inFile.Close()
	if err != nil {
		os.Remove(inName)
		return nil, err
	}
	outFile, err := os.CreateTemp(h.tmpDir, op+"-out-*.json")
	if err != nil {
		os.Remove(inName)
		return nil, err
	}
	outName := outFile.Name()
	outFile.Close()
	defer func() {
		os.Remove(inName)
		os.Remove(outName)
	}()
	fields["input_path"] = inName
	fields["output_path"] = outName
	if err := h.w.controlWithTimeout(callCtx, op, fields, nil); err != nil {
		return nil, err
	}
	return os.ReadFile(outName)
}

// Close unloads remaining plugins, waits for cleanup, and stops the worker.
func (h *CordisPluginRuntime) Close(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.w == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := h.w.controlWithTimeout(callCtx, "shutdown", nil, nil)
	h.w.abort()
	select {
	case <-h.w.exited:
	case <-callCtx.Done():
	}
	h.w = nil
	h.loaded = map[string]struct{}{}
	if h.tmpDir != "" {
		_ = os.RemoveAll(h.tmpDir)
		h.tmpDir = ""
	}
	return err
}

var allowedInsightSeverity = map[string]bool{"ok": true, "info": true, "warn": true, "critical": true}
var allowedKPITone = map[string]bool{"": true, "default": true, "ok": true, "warn": true, "bad": true}

func validateAnalyzeOutput(out *AnalyzeOutput) error {
	if out == nil {
		return errors.New("analyzer returned no JSON object")
	}
	for i, ins := range out.Insights {
		if !allowedInsightSeverity[ins.Severity] {
			return fmt.Errorf("invalid insight severity %q at index %d (only ok|info|warn|critical)", ins.Severity, i)
		}
	}
	for i, kpi := range out.KPIs {
		if !allowedKPITone[kpi.Tone] {
			return fmt.Errorf("invalid kpi tone %q at index %d (only default|ok|warn|bad)", kpi.Tone, i)
		}
	}
	return nil
}

// ErrCommandEntrypoint is returned when a new-preview install would have used entrypoint.command.
var ErrCommandEntrypoint = errors.New("新 preview 不加载 entrypoint.command 外部进程包，也不回退到 Go stdio")

type flexUint64 uint64

func (u *flexUint64) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*u = flexUint64(v)
	return nil
}

type rawPluginInsight struct {
	ID         string       `json:"id"`
	PluginID   string       `json:"plugin_id"`
	PluginName string       `json:"plugin_name"`
	Severity   string       `json:"severity"`
	Title      string       `json:"title"`
	Summary    string       `json:"summary"`
	Metric     string       `json:"metric,omitempty"`
	SampleIDs  []flexUint64 `json:"sample_ids,omitempty"`
}

type rawAnalyzeOutput struct {
	Insights []rawPluginInsight `json:"insights,omitempty"`
	KPIs     []ExtraKPI         `json:"kpis,omitempty"`
	Notes    []string           `json:"notes,omitempty"`
}

func unmarshalAnalyzeOutput(raw []byte) (*AnalyzeOutput, error) {
	var parsed rawAnalyzeOutput
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	out := &AnalyzeOutput{
		KPIs:  parsed.KPIs,
		Notes: parsed.Notes,
	}
	if len(parsed.Insights) > 0 {
		out.Insights = make([]Insight, len(parsed.Insights))
		for i, ri := range parsed.Insights {
			var ids []uint64
			if len(ri.SampleIDs) > 0 {
				ids = make([]uint64, len(ri.SampleIDs))
				for j, v := range ri.SampleIDs {
					ids[j] = uint64(v)
				}
			}
			out.Insights[i] = Insight{
				ID:        ri.ID,
				PluginID:  ri.PluginID,
				Plugin:    ri.PluginName,
				Severity:  ri.Severity,
				Title:     ri.Title,
				Summary:   ri.Summary,
				Metric:    ri.Metric,
				SampleIDs: ids,
			}
		}
	}
	return out, nil
}
