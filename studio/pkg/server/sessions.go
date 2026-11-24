package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SessionMeta is one entry of GET /api/sessions.
type SessionMeta struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Path          string `json:"path"`
	CreatedAt     string `json:"created_at"`
	CreatedUnixMs int64  `json:"created_unix_ms"`
	Scope         string `json:"scope"`
	Dev           string `json:"dev"`
	Mode          string `json:"mode"`
	KernelRelease string `json:"kernel_release,omitempty"`
	SampleCount   int    `json:"sample_count"`
	External      bool   `json:"external,omitempty"`
}

type cachedEntry struct {
	dir   string
	stamp int64
	ls    *loadedSession
}

type sessionStore struct {
	root string

	mu       sync.Mutex
	external map[string]string // id -> clean dir (in-memory external sessions)
	byPath   map[string]string // clean lower path -> id
	cache    map[string]*cachedEntry
}

func newSessionStore(root, _ string) *sessionStore {
	return &sessionStore{
		root:     root,
		external: map[string]string{},
		byPath:   map[string]string{},
		cache:    map[string]*cachedEntry{},
	}
}

func normPathKey(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = filepath.Clean(p)
	}
	return strings.ToLower(filepath.Clean(abs))
}

func isInsideDir(child, parent string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// register assigns a stable session ID to dir and returns it.
func (ss *sessionStore) register(dir string) string {
	abs, err := filepath.Abs(dir)
	if err == nil {
		dir = abs
	}
	dir = filepath.Clean(dir)
	key := normPathKey(dir)

	ss.mu.Lock()
	defer ss.mu.Unlock()

	if id, ok := ss.byPath[key]; ok {
		return id
	}
	if isInsideDir(dir, ss.root) && filepath.Clean(filepath.Dir(dir)) == filepath.Clean(ss.root) {
		id := filepath.Base(dir)
		ss.byPath[key] = id
		return id
	}
	base := sanitizeName(filepath.Base(dir))
	if base == "" {
		base = "session"
	}
	h := sha256.Sum256([]byte(key))
	id := "ext_" + base + "_" + hex.EncodeToString(h[:])[:8]
	ss.external[id] = dir
	ss.byPath[key] = id
	return id
}

func (ss *sessionStore) resolveDir(id string) (string, string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", "", fmt.Errorf("missing session id")
	}
	ss.mu.Lock()
	if dir, ok := ss.external[id]; ok {
		ss.mu.Unlock()
		if hasManifest(dir) {
			return id, dir, nil
		}
		return "", "", fmt.Errorf("session folder no longer exists: %s", dir)
	}
	ss.mu.Unlock()

	// Local session inside sessionsRoot (disallow path traversal).
	if id == filepath.Base(id) && id != "." && id != ".." {
		cand := filepath.Join(ss.root, id)
		if hasManifest(cand) {
			return id, cand, nil
		}
	}

	// Allow passing an existing directory path directly if convenient.
	if filepath.IsAbs(id) && hasManifest(id) {
		regID := ss.register(id)
		return regID, filepath.Clean(id), nil
	}
	return "", "", fmt.Errorf("session %q not found", id)
}

func hasManifest(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "manifest.json"))
	return err == nil && !st.IsDir()
}

func dirStamp(dir string) int64 {
	var stamp int64
	if st, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
		stamp ^= st.ModTime().UnixNano() ^ (st.Size() << 16)
	}
	ents, err := os.ReadDir(dir)
	if err == nil {
		stamp ^= int64(len(ents)) << 32
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".pktb") {
				if fi, err := e.Info(); err == nil {
					stamp += fi.Size() + fi.ModTime().UnixNano()
				}
			}
		}
	}
	return stamp
}

func (ss *sessionStore) load(id string) (string, string, *loadedSession, error) {
	realID, dir, err := ss.resolveDir(id)
	if err != nil {
		return "", "", nil, err
	}
	st := dirStamp(dir)
	ss.mu.Lock()
	ce := ss.cache[realID]
	if ce != nil && ce.dir == dir && ce.stamp == st && ce.ls != nil {
		ls := ce.ls
		ss.mu.Unlock()
		return realID, dir, ls, nil
	}
	ss.mu.Unlock()

	ls, err := engineLoad(realID, dir)
	if err != nil {
		return realID, dir, nil, err
	}
	ss.mu.Lock()
	ss.cache[realID] = &cachedEntry{dir: dir, stamp: st, ls: ls}
	ss.mu.Unlock()
	return realID, dir, ls, nil
}

func (ss *sessionStore) overview(id string) (any, error) {
	_, _, ls, err := ss.load(id)
	if err != nil {
		return nil, err
	}
	return ls.overview, nil
}

func (ss *sessionStore) list() []SessionMeta {
	seen := map[string]bool{}
	var metas []SessionMeta

	// 1. Local sessions under %LOCALAPPDATA%\PktPathStudio\sessions\
	if ents, err := os.ReadDir(ss.root); err == nil {
		for _, e := range ents {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			dir := filepath.Join(ss.root, e.Name())
			if !hasManifest(dir) {
				continue
			}
			id := ss.register(dir)
			seen[id] = true
			metas = append(metas, ss.inspectMeta(id, dir, false))
		}
	}

	// 2. Manually opened external session folders in memory
	ss.mu.Lock()
	extCopy := make(map[string]string, len(ss.external))
	for k, v := range ss.external {
		extCopy[k] = v
	}
	ss.mu.Unlock()
	for id, dir := range extCopy {
		if seen[id] || !hasManifest(dir) {
			continue
		}
		seen[id] = true
		metas = append(metas, ss.inspectMeta(id, dir, true))
	}

	sort.Slice(metas, func(i, j int) bool {
		if metas[i].CreatedUnixMs != metas[j].CreatedUnixMs {
			return metas[i].CreatedUnixMs > metas[j].CreatedUnixMs
		}
		return metas[i].ID > metas[j].ID
	})
	if metas == nil {
		metas = []SessionMeta{}
	}
	return metas
}

type quickManifest struct {
	Dev           string `json:"dev"`
	Scope         string `json:"scope"`
	Mode          string `json:"mode"`
	KernelRelease string `json:"kernel_release"`
	Calibrations  []struct {
		RealtimeNs int64 `json:"realtime_ns"`
	} `json:"calibrations"`
	Admissions struct {
		Selected int `json:"selected"`
		Created  int `json:"created"`
	} `json:"admissions"`
}

func (ss *sessionStore) inspectMeta(id, dir string, external bool) SessionMeta {
	m := SessionMeta{
		ID:       id,
		Name:     filepath.Base(dir),
		Path:     dir,
		External: external,
	}
	mp := filepath.Join(dir, "manifest.json")
	if st, err := os.Stat(mp); err == nil {
		t := st.ModTime()
		m.CreatedUnixMs = t.UnixMilli()
		m.CreatedAt = t.Format("2006-01-02 15:04:05")
	}
	if b, err := os.ReadFile(mp); err == nil {
		var qm quickManifest
		if json.Unmarshal(b, &qm) == nil {
			m.Dev = qm.Dev
			m.Scope = qm.Scope
			m.Mode = qm.Mode
			m.KernelRelease = qm.KernelRelease
			if qm.Admissions.Created > 0 {
				m.SampleCount = qm.Admissions.Created
			} else if qm.Admissions.Selected > 0 {
				m.SampleCount = qm.Admissions.Selected
			}
			// Use calibration realtime_ns if within a sane epoch range (2020..2035).
			if len(qm.Calibrations) > 0 {
				rt := qm.Calibrations[0].RealtimeNs
				if rt > 1577836800_000000000 && rt < 2051222400_000000000 {
					t := time.Unix(0, rt).Local()
					m.CreatedUnixMs = t.UnixMilli()
					m.CreatedAt = t.Format("2006-01-02 15:04:05")
				}
			}
		}
	}
	ss.mu.Lock()
	if ce := ss.cache[id]; ce != nil && ce.ls != nil {
		m.SampleCount = ce.ls.samples
	}
	ss.mu.Unlock()
	return m
}

// ---- HTTP handlers ----

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"sessions_root": s.sessionsRoot,
		"sessions":      s.sess.list(),
	})
}

func (s *Server) handleSessionsOpen(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rawPath := b.str("path")
	if rawPath == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	p, err := filepath.Abs(rawPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	st, err := os.Stat(p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "path does not exist: "+p)
		return
	}
	if !st.IsDir() {
		p = filepath.Dir(p)
	}
	if !hasManifest(p) {
		writeErr(w, http.StatusBadRequest, "not a PktPath session folder (manifest.json missing): "+p)
		return
	}
	id := s.sess.register(p)
	_, _, ls, err := s.sess.load(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "reconstruct failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"session_id":   id,
		"id":           id,
		"session_path": p,
		"path":         p,
		"overview":     ls.overview,
	})
}

func (s *Server) handlePickFolder(w http.ResponseWriter, r *http.Request) {
	b, _ := readBody(r)
	initDir := ""
	if b != nil {
		initDir = b.str("initial_dir")
	}
	if initDir == "" {
		initDir = s.sessionsRoot
	}
	chosen, cancelled, err := pickFolderNative(r.Context(), initDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "folder dialog failed: "+err.Error())
		return
	}
	if cancelled || chosen == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "cancelled": true, "path": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": false, "path": chosen})
}

func (s *Server) handleSaveFile(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defName := b.str("default_name")
	initDir := b.str("initial_dir")
	filter := b.str("filter")
	chosen, cancelled, err := saveFileNative(r.Context(), defName, initDir, filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save-file dialog failed: "+err.Error())
		return
	}
	if cancelled || chosen == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "cancelled": true, "path": ""})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": false, "path": chosen})
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rawPath := b.str("path")
	if rawPath == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	abs, err := filepath.Abs(rawPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	st, err := os.Stat(abs)
	if err != nil {
		writeErr(w, http.StatusNotFound, "path does not exist: "+abs)
		return
	}
	if err := revealPathNative(abs, st.IsDir()); err != nil {
		writeErr(w, http.StatusInternalServerError, "explorer launch failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": abs})
}

func sessionIDFromQuery(r *http.Request) string {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		id = strings.TrimSpace(r.URL.Query().Get("session_id"))
	}
	return id
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	id := sessionIDFromQuery(r)
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id query parameter")
		return
	}
	ov, err := s.sess.overview(id)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleSample(w http.ResponseWriter, r *http.Request) {
	id := sessionIDFromQuery(r)
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id query parameter")
		return
	}
	sidStr := strings.TrimSpace(r.URL.Query().Get("sample_id"))
	sid, err := strconv.ParseUint(sidStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid sample_id")
		return
	}
	_, _, ls, err := s.sess.load(id)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	detail, err := engineSample(ls, sid)
	if err != nil {
		code := http.StatusNotFound
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleExportGet(w http.ResponseWriter, r *http.Request) {
	id := sessionIDFromQuery(r)
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id query parameter")
		return
	}
	redact := queryBool(r, "redact")
	key := strings.TrimSpace(r.URL.Query().Get("key"))

	realID, _, ls, err := s.sess.load(id)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	data, _, err := enginePcapngBytes(ls, redact, key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export pcapng: "+err.Error())
		return
	}
	safe := sanitizeName(realID)
	if safe == "" {
		safe = "session"
	}
	fname := "trace_" + safe + ".pcapng"
	if redact {
		fname = "trace_" + safe + "_redacted.pcapng"
	}
	w.Header().Set("Content-Type", "application/x-pcapng")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, fname))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleExportPost(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := b.str("id")
	if id == "" {
		id = b.str("session_id")
	}
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	redact := b.bool("redact")
	key := b.str("key")
	outPath := b.str("out_path")

	realID, dir, _, err := s.sess.load(id)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeErr(w, code, err.Error())
		return
	}
	if outPath == "" {
		safe := sanitizeName(realID)
		suffix := ".pcapng"
		if redact {
			suffix = "_redacted.pcapng"
		}
		outPath = filepath.Join(s.sessionsRoot, "trace_"+safe+suffix)
	}
	if abs, err := filepath.Abs(outPath); err == nil {
		outPath = abs
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdir out_path: "+err.Error())
		return
	}
	n, err := engineExportFile(dir, outPath, redact, key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export pcapng: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"id":               realID,
		"out_path":         outPath,
		"exported_packets": n,
		"redact":           redact,
	})
}

func (s *Server) handleRedact(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := b.str("id")
	if id == "" {
		id = b.str("session_id")
	}
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return
	}
	outDir := b.str("out_dir")
	key := b.str("key")

	realID, dir, err := s.sess.resolveDir(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if outDir == "" {
		safe := sanitizeName(realID)
		outDir = uniquePath(filepath.Join(s.sessionsRoot, safe+"_redacted"))
	}
	if abs, err := filepath.Abs(outDir); err == nil {
		outDir = abs
	}
	if normPathKey(outDir) == normPathKey(dir) {
		outDir = uniquePath(dir + "_redacted")
	} else if normPathKey(outDir) == normPathKey(s.sessionsRoot) {
		outDir = uniquePath(filepath.Join(s.sessionsRoot, sanitizeName(realID)+"_redacted"))
	}
	if err := engineRedact(dir, outDir, key); err != nil {
		writeErr(w, http.StatusInternalServerError, "redact session: "+err.Error())
		return
	}
	newID := s.sess.register(outDir)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"id":         realID,
		"out_dir":    outDir,
		"session_id": newID,
	})
}
