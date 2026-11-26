package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"pktpath/studio/pkg/adb"
	"pktpath/studio/pkg/kernel"
	"pktpath/studio/pkg/plugins"
)

func (s *Server) initKernel() {
	host := kernel.HostServices{
		AppDir:       s.opts.AppDir,
		PluginsDir:   s.pluginsDir,
		SessionsRoot: s.sessionsRoot,
	}
	if s.opts.CordisAnalyzerHost != "" {
		host.AnalyzerHost = kernel.NewCordisAnalyzerHost(kernel.CordisAnalyzerOptions{NodePath: s.opts.CordisAnalyzerNode, HostPath: s.opts.CordisAnalyzerHost})
	}
	if s.opts.CordisPluginRuntime != "-" {
		runtimeHost := strings.TrimSpace(s.opts.CordisPluginRuntime)
		runtimeNode := strings.TrimSpace(s.opts.CordisPluginRuntimeNode)
		if runtimeHost == "" {
			if h, n, err := kernel.ResolveDefaultPluginRuntime("", runtimeNode); err == nil {
				runtimeHost, runtimeNode = h, n
				s.opts.CordisPluginRuntime = runtimeHost
				if s.opts.CordisPluginRuntimeNode == "" {
					s.opts.CordisPluginRuntimeNode = runtimeNode
				}
			}
		}
		if runtimeHost != "" {
			if runtimeNode == "" {
				runtimeNode = s.opts.CordisAnalyzerNode
			}
			host.PluginRuntime = kernel.NewCordisPluginRuntime(kernel.CordisPluginRuntimeOptions{NodePath: runtimeNode, HostPath: runtimeHost})
		}
	}
	if s.opts.CordisPluginHost != "" {
		host.LifecycleHost = kernel.NewCordisLifecycleHost(kernel.CordisLifecycleOptions{NodePath: s.opts.CordisPluginNode, HostPath: s.opts.CordisPluginHost, ConfigTransactions: s.opts.CordisConfigTransactions})
	}
	s.kernel = kernel.New(host)
	plugins.RegisterAllBuiltins(s.kernel)
	s.kernel.OnChange(func() {
		s.applyKernelSideEffects()
	})
	_ = s.kernel.Start()
	s.applyKernelSideEffects()
}

// Kernel exposes the microkernel (used by selftest and API handlers).
func (s *Server) Kernel() *kernel.Kernel { return s.kernel }

func (s *Server) applyKernelSideEffects() {
	if s.kernel == nil {
		return
	}
	// Apply custom ADB path override if configured in builtin.transport.android-adb
	adbCfg := s.kernel.PluginConfig("builtin.transport.android-adb")
	customAdb := kernel.ConfigString(adbCfg, "adb_path", "")
	if customAdb != "" {
		if _, err := os.Stat(customAdb); err == nil {
			s.adb = adb.NewClient(customAdb)
		}
	} else if s.opts.Runtime != nil && s.opts.Runtime.AdbPath != "" {
		s.adb = adb.NewClient(s.opts.Runtime.AdbPath)
	}
}

// activeKernelPluginFiles materializes all active kernel.ext extensions (built-in
// visual builder + external bundles) into clean JSON files for device sync.
func (s *Server) activeKernelPluginFiles() []string {
	if s.kernel == nil {
		return s.enabledPluginPaths()
	}
	paths, err := s.kernel.MaterializeKernelPluginFiles()
	if err != nil {
		s.log.Printf("materialize kernel plugins failed: %v", err)
		return nil
	}
	return paths
}

// enrichOverview runs all active analyzer plugins (built-in + in-process Cordis modules)
// on the loaded session and attaches `plugin_insights`, `plugin_kpis`, and `plugin_notes`
// onto the returned overview JSON without mutating the cached base reconstruction.
func (s *Server) enrichOverview(ctx context.Context, id, dir string, ls *loadedSession) json.RawMessage {
	if ls == nil {
		return json.RawMessage("null")
	}
	if s.kernel == nil {
		return ls.overview
	}
	out := s.kernel.AnalyzeSession(ctx, &kernel.AnalyzeInput{
		SessionID:  id,
		SessionDir: dir,
		Session:    ls.sess,
		Overview:   ls.ovObj,
	})
	trimmed := bytes.TrimSpace(ls.overview)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return ls.overview
	}
	extra, err := json.Marshal(struct {
		Insights []kernel.Insight  `json:"plugin_insights"`
		KPIs     []kernel.ExtraKPI `json:"plugin_kpis"`
		Notes    []string          `json:"plugin_notes,omitempty"`
	}{
		Insights: out.Insights,
		KPIs:     out.KPIs,
		Notes:    out.Notes,
	})
	if err != nil || len(extra) < 2 {
		return ls.overview
	}
	var buf bytes.Buffer
	buf.Grow(len(trimmed) + len(extra) + 2)
	buf.Write(trimmed[:len(trimmed)-1])
	buf.WriteByte(',')
	buf.Write(extra[1:])
	return json.RawMessage(buf.Bytes())
}

// ---- Microkernel HTTP API Handlers ----

func (s *Server) handleKernelState(w http.ResponseWriter, r *http.Request) {
	snap := s.kernel.Snapshot(s.opts.Version)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"state": snap,
	})
}

func (s *Server) handleKernelPluginToggle(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := b.str("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing plugin id")
		return
	}
	en := b.bool("enabled")
	err = s.kernel.SetEnabled(id, en)
	snap := s.kernel.Snapshot(s.opts.Version)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
			"state": snap,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"id":      id,
		"enabled": en,
		"state":   snap,
	})
}

func (s *Server) handleKernelPluginConfig(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := b.str("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing plugin id")
		return
	}
	rawCfg, _ := b["config"].(map[string]any)
	if rawCfg == nil {
		rawCfg = map[string]any{}
	}
	norm, err := s.kernel.SetConfigContext(r.Context(), id, rawCfg)
	snap := s.kernel.Snapshot(s.opts.Version)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  err.Error(),
			"config": norm,
			"state":  snap,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"id":     id,
		"config": norm,
		"state":  snap,
	})
}

func (s *Server) handleKernelPluginReset(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := b.str("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing plugin id")
		return
	}
	norm, err := s.kernel.ResetConfigContext(r.Context(), id)
	snap := s.kernel.Snapshot(s.opts.Version)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error(), "config": norm, "state": snap})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"id":     id,
		"config": norm,
		"state":  snap,
	})
}

func (s *Server) handleKernelPluginReload(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := b.str("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing plugin id")
		return
	}
	err = s.kernel.Reload(id)
	snap := s.kernel.Snapshot(s.opts.Version)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
			"state": snap,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"id":    id,
		"state": snap,
	})
}

func (s *Server) handleKernelPluginPreview(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rawPath := b.str("path")
	content := b.str("content")
	fileName := b.str("filename")
	prev := s.kernel.PreviewExternal(rawPath, []byte(content), fileName)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      prev.OK,
		"preview": prev,
		"error":   prev.Error,
	})
}

func (s *Server) handleKernelPluginInstall(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rawPath := b.str("path")
	content := b.str("content")
	fileName := b.str("filename")
	meta, err := s.kernel.InstallExternal(rawPath, []byte(content), fileName)
	snap := s.kernel.Snapshot(s.opts.Version)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, kernel.ErrAnalyzerBundleBusy) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]any{
			"ok":    false,
			"error": err.Error(),
			"state": snap,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"plugin": meta,
		"state":  snap,
	})
}

func (s *Server) handleKernelPluginUninstall(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := b.str("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing plugin id")
		return
	}
	if err := s.kernel.UninstallExternal(id); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, kernel.ErrAnalyzerBundleBusy) {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"id":    id,
		"state": s.kernel.Snapshot(s.opts.Version),
	})
}

func (s *Server) handleKernelExport(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	exporterID := b.str("exporter_id")
	if exporterID == "" {
		writeErr(w, http.StatusBadRequest, "missing exporter_id")
		return
	}
	sessID := b.str("session_id")
	if sessID == "" {
		sessID = b.str("id")
	}
	if sessID == "" {
		writeErr(w, http.StatusBadRequest, "missing session_id")
		return
	}
	realID, dir, ls, err := s.sess.load(sessID)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}

	outPath := b.str("out_path")
	if outPath != "" {
		if abs, aerr := filepath.Abs(outPath); aerr == nil {
			outPath = abs
		}
	}
	params, _ := b["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	// Pass through common top-level params if provided.
	if _, has := b["redact"]; has {
		params["redact"] = b.bool("redact")
	}
	if k := b.str("key"); k != "" {
		params["key"] = k
	}

	// Ensure directory exporters don't overwrite the source directory itself.
	for _, ex := range s.kernel.Exporters() {
		if ex.ID == exporterID && ex.IsDirectory {
			if outPath == "" {
				outPath = uniquePath(filepath.Join(s.sessionsRoot, sanitizeName(realID)+"_"+sanitizeName(exporterID)))
			} else if normPathKey(outPath) == normPathKey(dir) {
				outPath = uniquePath(dir + "_" + sanitizeName(exporterID))
			} else if normPathKey(outPath) == normPathKey(s.sessionsRoot) {
				outPath = uniquePath(filepath.Join(s.sessionsRoot, sanitizeName(realID)+"_"+sanitizeName(exporterID)))
			}
		} else if ex.ID == exporterID && outPath == "" {
			ext := ex.DefaultExt
			if ext == "" {
				ext = ".out"
			}
			outPath = filepath.Join(s.sessionsRoot, fmt.Sprintf("%s_%s%s", sanitizeName(exporterID), sanitizeName(realID), ext))
		}
	}

	res, err := s.kernel.RunExporter(r.Context(), exporterID, &kernel.ExportInput{
		SessionID:  realID,
		SessionDir: dir,
		Session:    ls.sess,
		Overview:   ls.ovObj,
		OutPath:    outPath,
		Params:     params,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{
		"ok":           res.OK,
		"exporter_id":  exporterID,
		"session_id":   realID,
		"out_path":     res.OutPath,
		"is_directory": res.IsDirectory,
		"summary":      res.Summary,
		"details":      res.Details,
	}
	if res.IsDirectory && res.OutPath != "" && hasManifest(res.OutPath) {
		resp["new_session_id"] = s.sess.register(res.OutPath)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleKernelPluginAsset(w http.ResponseWriter, r *http.Request) {
	pluginID := strings.TrimSpace(r.PathValue("id"))
	relPath := strings.TrimSpace(r.PathValue("path"))
	if pluginID == "" || relPath == "" {
		http.NotFound(w, r)
		return
	}
	full, err := s.kernel.ResolvePluginAsset(pluginID, relPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := contentTypes[strings.ToLower(path.Ext(full))]
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
