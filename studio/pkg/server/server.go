// Package server implements the PktPath Studio localhost HTTP API.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pktpath/studio/pkg/adb"
	"pktpath/studio/pkg/kernel"
	"pktpath/studio/pkg/sshclient"
)

// Options configures the server.
type Options struct {
	Runtime    *adb.Runtime
	Web        fs.FS  // rooted at web/
	AppDir     string // %LOCALAPPDATA%\PktPathStudio
	PluginsDir string // %LOCALAPPDATA%\PktPathStudio\plugins
	Logger     *log.Logger
	Version    string
	// F01 development candidate; empty Host keeps the original Go path.
	CordisAnalyzerHost string
	CordisAnalyzerNode string
}

// Server is the Studio HTTP backend.
type Server struct {
	opts         Options
	adb          *adb.Client
	ssh          *sshclient.Client
	sshStore     *sshclient.Store
	kernel       *kernel.Kernel
	sessionsRoot string
	pluginsDir   string
	log          *log.Logger

	mu       sync.Mutex
	devState map[string]*deviceState
	port     int

	capMu sync.Mutex
	cap   *captureState

	activeClients atomic.Int64
	everHadClient atomic.Bool
	sseStopOnce   sync.Once
	sseStopCh     chan struct{}
	quitOnce      sync.Once
	quitReqCh     chan struct{}

	sess *sessionStore
	http *http.Server
}

type deviceState struct {
	RootMode    string
	AgentSHA256 string
	Kernel      string
	PreparedAt  time.Time
}

// New builds a server (does not listen yet).
func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	if opts.AppDir == "" {
		opts.AppDir = adb.DefaultAppDir()
	}
	if opts.Runtime == nil {
		opts.Runtime = &adb.Runtime{}
	}
	root := filepath.Join(opts.AppDir, "sessions")
	_ = os.MkdirAll(root, 0o755)
	pdir := strings.TrimSpace(opts.PluginsDir)
	if pdir == "" {
		pdir = filepath.Join(opts.AppDir, "plugins")
	}
	_ = os.MkdirAll(pdir, 0o755)
	s := &Server{
		opts:         opts,
		adb:          adb.NewClient(opts.Runtime.AdbPath),
		ssh:          sshclient.NewClient(),
		sshStore:     sshclient.NewStore(filepath.Join(opts.AppDir, "ssh_targets.json")),
		sessionsRoot: root,
		pluginsDir:   pdir,
		log:          opts.Logger,
		devState:     map[string]*deviceState{},
		sseStopCh:    make(chan struct{}),
		quitReqCh:    make(chan struct{}),
	}
	s.sess = newSessionStore(root, filepath.Join(opts.AppDir, "opened_sessions.json"))
	s.initKernel()
	return s
}

// ActiveClients returns the number of currently connected SSE browser tabs.
func (s *Server) ActiveClients() int64 { return s.activeClients.Load() }

// EverHadClient reports whether at least one SSE browser tab has connected.
func (s *Server) EverHadClient() bool { return s.everHadClient.Load() }

// QuitRequested returns a channel closed when POST /api/app/quit is called.
func (s *Server) QuitRequested() <-chan struct{} { return s.quitReqCh }

// Port returns the bound TCP port (0 before Listen).
func (s *Server) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// ADB exposes the underlying adb client (used by selftest).
func (s *Server) ADB() *adb.Client { return s.adb }

// SessionsRoot returns the local sessions directory.
func (s *Server) SessionsRoot() string { return s.sessionsRoot }

// Listen binds addr (e.g. "127.0.0.1:0") and returns the listener.
func (s *Server) Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		s.mu.Lock()
		s.port = ta.Port
		s.mu.Unlock()
	}
	return ln, nil
}

// Serve serves HTTP on ln until Shutdown.
func (s *Server) Serve(ln net.Listener) error {
	s.http = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	err := s.http.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops any active capture (gracefully, pulling data) then the HTTP server.
func (s *Server) Shutdown(ctx context.Context) {
	s.sseStopOnce.Do(func() { close(s.sseStopCh) })
	s.StopActiveCapture(ctx)
	if s.kernel != nil {
		s.kernel.Shutdown()
		if host := s.kernel.Host().AnalyzerHost; host != nil {
			if err := host.Close(ctx); err != nil {
				s.log.Printf("Cordis analyzer drain: %v", err)
			}
		}
	}
	if s.http != nil {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		_ = s.http.Shutdown(sctx)
	}
}

// Handler returns the full HTTP handler (API + embedded web UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/kernel/state", s.handleKernelState)
	mux.HandleFunc("POST /api/kernel/plugins/toggle", s.handleKernelPluginToggle)
	mux.HandleFunc("POST /api/kernel/plugins/config", s.handleKernelPluginConfig)
	mux.HandleFunc("POST /api/kernel/plugins/reset", s.handleKernelPluginReset)
	mux.HandleFunc("POST /api/kernel/plugins/reload", s.handleKernelPluginReload)
	mux.HandleFunc("POST /api/kernel/plugins/preview", s.handleKernelPluginPreview)
	mux.HandleFunc("POST /api/kernel/plugins/install", s.handleKernelPluginInstall)
	mux.HandleFunc("POST /api/kernel/plugins/uninstall", s.handleKernelPluginUninstall)
	mux.HandleFunc("POST /api/kernel/export", s.handleKernelExport)
	mux.HandleFunc("GET /api/kernel/plugin-asset/{id}/{path...}", s.handleKernelPluginAsset)
	mux.HandleFunc("GET /api/plugins", s.handlePlugins)
	mux.HandleFunc("POST /api/plugins/preview", s.handlePluginsPreview)
	mux.HandleFunc("POST /api/plugins/import", s.handlePluginsImport)
	mux.HandleFunc("POST /api/plugins/toggle", s.handlePluginsToggle)
	mux.HandleFunc("POST /api/plugins/delete", s.handlePluginsDelete)
	mux.HandleFunc("GET /api/ssh/targets", s.handleSSHTargetsList)
	mux.HandleFunc("POST /api/ssh/targets", s.handleSSHTargetsUpsert)
	mux.HandleFunc("DELETE /api/ssh/targets", s.handleSSHTargetsDelete)
	mux.HandleFunc("POST /api/ssh/test", s.handleSSHTest)
	mux.HandleFunc("GET /api/app/events", s.handleAppEvents)
	mux.HandleFunc("POST /api/app/quit", s.handleAppQuit)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("POST /api/device/prepare", s.handlePrepare)
	mux.HandleFunc("GET /api/device/inspect", s.handleInspect)
	mux.HandleFunc("GET /api/device/apps", s.handleApps)
	mux.HandleFunc("POST /api/capture/start", s.handleCaptureStart)
	mux.HandleFunc("GET /api/capture/status", s.handleCaptureStatus)
	mux.HandleFunc("POST /api/capture/flush", s.handleCaptureFlush)
	mux.HandleFunc("POST /api/capture/stop", s.handleCaptureStop)
	mux.HandleFunc("GET /api/sessions", s.handleSessions)
	mux.HandleFunc("POST /api/sessions/open", s.handleSessionsOpen)
	mux.HandleFunc("POST /api/dialog/pick-folder", s.handlePickFolder)
	mux.HandleFunc("POST /api/dialog/save-file", s.handleSaveFile)
	mux.HandleFunc("POST /api/dialog/open-file", s.handleOpenFile)
	mux.HandleFunc("POST /api/dialog/reveal", s.handleReveal)
	mux.HandleFunc("GET /api/session/overview", s.handleOverview)
	mux.HandleFunc("GET /api/session/sample", s.handleSample)
	mux.HandleFunc("GET /api/session/export-pcapng", s.handleExportGet)
	mux.HandleFunc("POST /api/session/export-pcapng", s.handleExportPost)
	mux.HandleFunc("POST /api/session/redact", s.handleRedact)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "unknown API endpoint: "+r.Method+" "+r.URL.Path)
	})
	mux.HandleFunc("/", s.handleStatic)
	return s.guard(mux)
}

// guard blocks DNS-rebinding / cross-origin access to the root-capable API and
// recovers handler panics.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always drain unread request body before ServeHTTP returns so Windows
		// Winsock never emits TCP RST (WSAECONNRESET 10054) on Connection: close.
		defer drainBody(r)
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Printf("panic in %s %s: %v", r.Method, r.URL.Path, rec)
				writeErr(w, http.StatusInternalServerError, fmt.Sprintf("internal error: %v", rec))
			}
		}()
		s.mu.Lock()
		port := s.port
		s.mu.Unlock()
		if port != 0 && r.Host != "" {
			h := strings.ToLower(r.Host)
			if hp, p, err := net.SplitHostPort(h); err == nil {
				if p != strconv.Itoa(port) {
					http.Error(w, "forbidden host port", http.StatusForbidden)
					return
				}
				h = hp
			}
			if h != "127.0.0.1" && h != "localhost" && h != "::1" && h != "[::1]" {
				http.Error(w, "forbidden host", http.StatusForbidden)
				return
			}
			if o := strings.ToLower(strings.TrimSpace(r.Header.Get("Origin"))); o != "" && o != "null" && r.Method != http.MethodGet {
				okOrigin := strings.HasPrefix(o, "http://127.0.0.1:") ||
					strings.HasPrefix(o, "http://localhost:") ||
					strings.HasPrefix(o, "http://[::1]:") ||
					o == "http://127.0.0.1" || o == "http://localhost"
				if !okOrigin {
					http.Error(w, "forbidden origin", http.StatusForbidden)
					return
				}
			}
		}
		start := time.Now()
		next.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/capture/status" {
			s.log.Printf("%s %s (%s)", r.Method, r.URL.RequestURI(), time.Since(start).Round(time.Millisecond))
		}
	})
}

var contentTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".ico":   "image/x-icon",
	".woff2": "font/woff2",
	".txt":   "text/plain; charset=utf-8",
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.opts.Web == nil {
		http.Error(w, "web UI not embedded", http.StatusNotFound)
		return
	}
	p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	b, err := fs.ReadFile(s.opts.Web, p)
	if err != nil {
		// SPA fallback for unknown non-asset paths.
		if path.Ext(p) == "" {
			if b2, err2 := fs.ReadFile(s.opts.Web, "index.html"); err2 == nil {
				p, b = "index.html", b2
				err = nil
			}
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	ct := contentTypes[strings.ToLower(path.Ext(p))]
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	snap := s.kernel.Snapshot(s.opts.Version)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                    true,
		"pid":                   os.Getpid(),
		"version":               s.opts.Version,
		"runtime":               s.opts.Runtime,
		"adb_missing":           s.opts.Runtime.AdbPath == "",
		"ssh_available":         s.ssh != nil && s.ssh.Available(),
		"sessions_root":         s.sessionsRoot,
		"plugins_dir":           s.pluginsDir,
		"active_clients":        s.activeClients.Load(),
		"kernel_plugins_active": snap.ActivePlugins,
		"kernel_plugins_total":  snap.TotalPlugins,
	})
}

func (s *Server) handleAppEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	s.everHadClient.Store(true)
	s.activeClients.Add(1)
	defer s.activeClients.Add(-1)

	if _, err := io.WriteString(w, ": connected\n\n"); err != nil {
		return
	}
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.sseStopCh:
			return
		case <-ticker.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleAppQuit(w http.ResponseWriter, r *http.Request) {
	drainBody(r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(60 * time.Millisecond)
		s.quitOnce.Do(func() { close(s.quitReqCh) })
	}()
}

// ---- JSON helpers ----

func drainBody(r *http.Request) {
	if r != nil && r.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func writeErrExtra(w http.ResponseWriter, code int, msg string, extra map[string]any) {
	m := map[string]any{"ok": false, "error": msg}
	for k, v := range extra {
		m[k] = v
	}
	writeJSON(w, code, m)
}

// body is a loosely-typed JSON object tolerant of string/number/bool mixes.
type body map[string]any

func readBody(r *http.Request) (body, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	m := body{}
	if strings.TrimSpace(string(b)) == "" {
		return m, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}
	return m, nil
}

func (b body) str(k string) string {
	v, ok := b[k]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// int returns (value, present). Empty strings / null count as absent.
func (b body) int(k string) (int64, bool) {
	v, ok := b[k]
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i, true
		}
		if f, err := t.Float64(); err == nil {
			return int64(f), true
		}
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, false
		}
		if i, err := strconv.ParseInt(s, 0, 64); err == nil {
			return i, true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return int64(f), true
		}
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func (b body) bool(k string) bool {
	v, ok := b[k]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case json.Number:
		return t.String() != "0"
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	}
	return false
}

func queryBool(r *http.Request, k string) bool {
	s := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(k)))
	return s == "1" || s == "true" || s == "yes" || s == "on"
}
