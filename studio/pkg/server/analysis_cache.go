package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pktpath/studio/pkg/kernel"
)

const (
	analysisCacheFileName     = ".pktpath_analysis_cache.json"
	analysisCacheSchemaVer    = 1
	analysisStorageSession    = "session_disk"
	analysisStorageAppCache   = "app_cache"
	openedSessionsSchemaVer   = 1
)

type analysisCacheEntry struct {
	sessionFP  string
	analyzerFP string
	storage    string
	out        *kernel.AnalyzeOutput
	enriched   json.RawMessage
}

type persistedAnalysisCache struct {
	SchemaVersion       int               `json:"schema_version"`
	SessionFingerprint  string            `json:"session_fingerprint"`
	AnalyzerFingerprint string            `json:"analyzer_fingerprint"`
	SavedAt             string            `json:"saved_at"`
	Storage             string            `json:"storage,omitempty"`
	Insights            []kernel.Insight  `json:"plugin_insights"`
	KPIs                []kernel.ExtraKPI `json:"plugin_kpis"`
	Notes               []string          `json:"plugin_notes,omitempty"`
}

type persistedOpenedSessions struct {
	SchemaVersion int      `json:"schema_version"`
	UpdatedAt     string   `json:"updated_at"`
	Dirs          []string `json:"dirs"`
}

// isSessionSourceFile returns true only for immutable session input files
// (manifest.json, dict.json, and *.pktb blocks). Cache files such as
// .pktpath_analysis_cache.json are intentionally excluded so persisting
// analysis outputs never invalidates the base session reconstruction cache.
func isSessionSourceFile(name string) bool {
	return name == "manifest.json" || name == "dict.json" || strings.HasSuffix(name, ".pktb")
}

// sessionSourceFingerprint hashes the metadata (name, size, mtime) of the
// session's source files so edits or new blocks invalidate persisted analysis.
func sessionSourceFingerprint(dir string) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if isSessionSourceFile(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(h, "%s|%d|%d\n", name, fi.Size(), fi.ModTime().UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeFileAtomic writes data to a sibling temp file, syncs and closes it
// before renaming onto target so readers never observe partial JSON and
// Windows rename semantics (no open handle on temp file) are respected.
func writeFileAtomic(target string, data []byte, perm os.FileMode) error {
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".pktpath-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmpPath, perm)
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (s *Server) appAnalysisCachePath(dir string) string {
	if s.opts.AppDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normPathKey(dir)))
	return filepath.Join(s.opts.AppDir, "analysis_cache", hex.EncodeToString(sum[:])[:24]+".json")
}

func readPersistedAnalysisFile(path, sessionFP, analyzerFP string) (*kernel.AnalyzeOutput, bool) {
	if path == "" {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var rec persistedAnalysisCache
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, false
	}
	if rec.SchemaVersion != analysisCacheSchemaVer ||
		rec.SessionFingerprint != sessionFP ||
		rec.AnalyzerFingerprint != analyzerFP {
		return nil, false
	}
	out := &kernel.AnalyzeOutput{
		Insights: rec.Insights,
		KPIs:     rec.KPIs,
		Notes:    rec.Notes,
	}
	if out.Insights == nil {
		out.Insights = []kernel.Insight{}
	}
	if out.KPIs == nil {
		out.KPIs = []kernel.ExtraKPI{}
	}
	if out.Notes == nil {
		out.Notes = []string{}
	}
	return out, true
}

func (s *Server) loadPersistedAnalysis(dir, sessionFP, analyzerFP string) (*kernel.AnalyzeOutput, string, bool) {
	if out, ok := readPersistedAnalysisFile(filepath.Join(dir, analysisCacheFileName), sessionFP, analyzerFP); ok {
		return out, analysisStorageSession, true
	}
	if appPath := s.appAnalysisCachePath(dir); appPath != "" {
		if out, ok := readPersistedAnalysisFile(appPath, sessionFP, analyzerFP); ok {
			return out, analysisStorageAppCache, true
		}
	}
	return nil, "", false
}

func (s *Server) savePersistedAnalysis(dir, sessionFP, analyzerFP string, out *kernel.AnalyzeOutput) string {
	if out == nil {
		return ""
	}
	rec := persistedAnalysisCache{
		SchemaVersion:       analysisCacheSchemaVer,
		SessionFingerprint:  sessionFP,
		AnalyzerFingerprint: analyzerFP,
		SavedAt:             time.Now().UTC().Format(time.RFC3339),
		Storage:             analysisStorageSession,
		Insights:            out.Insights,
		KPIs:                out.KPIs,
		Notes:               out.Notes,
	}
	if rec.Insights == nil {
		rec.Insights = []kernel.Insight{}
	}
	if rec.KPIs == nil {
		rec.KPIs = []kernel.ExtraKPI{}
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return ""
	}
	data = append(data, '\n')
	sessionCachePath := filepath.Join(dir, analysisCacheFileName)
	if err := writeFileAtomic(sessionCachePath, data, 0o644); err == nil {
		return analysisStorageSession
	}

	// Read-only session directory fallback: persist under AppDir/analysis_cache.
	appPath := s.appAnalysisCachePath(dir)
	if appPath == "" {
		return ""
	}
	rec.Storage = analysisStorageAppCache
	fallbackData, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return ""
	}
	fallbackData = append(fallbackData, '\n')
	if err := writeFileAtomic(appPath, fallbackData, 0o644); err == nil {
		return analysisStorageAppCache
	}
	return ""
}

func mergeOverviewWithAnalysis(base json.RawMessage, out *kernel.AnalyzeOutput) json.RawMessage {
	if out == nil {
		return base
	}
	trimmed := bytes.TrimSpace(base)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return base
	}
	insights := out.Insights
	if insights == nil {
		insights = []kernel.Insight{}
	}
	kpis := out.KPIs
	if kpis == nil {
		kpis = []kernel.ExtraKPI{}
	}
	extra, err := json.Marshal(struct {
		Insights []kernel.Insight  `json:"plugin_insights"`
		KPIs     []kernel.ExtraKPI `json:"plugin_kpis"`
		Notes    []string          `json:"plugin_notes,omitempty"`
	}{
		Insights: insights,
		KPIs:     kpis,
		Notes:    out.Notes,
	})
	if err != nil || len(extra) < 2 {
		return base
	}
	var buf bytes.Buffer
	buf.Grow(len(trimmed) + len(extra) + 2)
	buf.Write(trimmed[:len(trimmed)-1])
	buf.WriteByte(',')
	buf.Write(extra[1:])
	return json.RawMessage(buf.Bytes())
}

func (s *Server) enrichOverviewWithOptions(ctx context.Context, id, dir string, ls *loadedSession, refresh bool) json.RawMessage {
	if ls == nil {
		return json.RawMessage("null")
	}
	if s.kernel == nil {
		return ls.overview
	}

	sessionFP, fpErr := sessionSourceFingerprint(dir)
	analyzerFP := s.kernel.AnalyzerFingerprint()

	if !refresh && fpErr == nil && s.sess != nil {
		if ce, ok := s.sess.getAnalysisCache(id, dir, ls, sessionFP, analyzerFP); ok {
			return ce.enriched
		}
		if persisted, storage, ok := s.loadPersistedAnalysis(dir, sessionFP, analyzerFP); ok {
			enriched := mergeOverviewWithAnalysis(ls.overview, persisted)
			s.sess.putAnalysisCache(id, dir, ls, &analysisCacheEntry{
				sessionFP:  sessionFP,
				analyzerFP: analyzerFP,
				storage:    storage,
				out:        persisted,
				enriched:   enriched,
			})
			return enriched
		}
	}

	out, hasErrors := s.kernel.AnalyzeSessionReport(ctx, &kernel.AnalyzeInput{
		SessionID:  id,
		SessionDir: dir,
		Session:    ls.sess,
		Overview:   ls.ovObj,
	})
	enriched := mergeOverviewWithAnalysis(ls.overview, out)

	// Only persist clean analysis runs; transient analyzer errors are returned
	// in plugin_notes but not frozen into the cache so subsequent loads retry.
	if !hasErrors && fpErr == nil {
		storage := s.savePersistedAnalysis(dir, sessionFP, analyzerFP, out)
		if s.sess != nil {
			s.sess.putAnalysisCache(id, dir, ls, &analysisCacheEntry{
				sessionFP:  sessionFP,
				analyzerFP: analyzerFP,
				storage:    storage,
				out:        out,
				enriched:   enriched,
			})
		}
	}
	return enriched
}
