package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"pktpath/studio/pkg/export"
	"pktpath/studio/pkg/wire"
)

func testU8(v uint8) []byte   { return []byte{v} }
func testU16(v uint16) []byte { var b [2]byte; binary.LittleEndian.PutUint16(b[:], v); return b[:] }
func testU32(v uint32) []byte { var b [4]byte; binary.LittleEndian.PutUint32(b[:], v); return b[:] }
func testU64(v uint64) []byte { var b [8]byte; binary.LittleEndian.PutUint64(b[:], v); return b[:] }

func makeSyntheticSessionDir(t *testing.T, parent, folderName string) string {
	t.Helper()
	dir := filepath.Join(parent, folderName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir session dir: %v", err)
	}
	uuidStr := "12345678-1234-4123-8123-123456789abc"
	uuid, err := wire.ParseUUID(uuidStr)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "manifest.json"),
		[]byte(`{"session_uuid":"`+uuidStr+`","dev":"eth0","scope":"tc-egress"}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dict.json"),
		[]byte(`{"sites":[],"topology_epochs":[{"epoch_id":1,"devices":[{"ifindex":2,"name":"eth0","linktype":101}]}]}`), 0o644); err != nil {
		t.Fatalf("write dict: %v", err)
	}

	var pay []byte
	pay = append(pay, wire.EncodeEvent(&wire.Event{
		Kind: wire.KindObject, ObjectType: wire.ObjSKB, EvidenceLevel: wire.EvidenceDirect,
		CPU: 0, Seq: 1, TsNs: 1_000_000, ObjectID: 1,
	}, []wire.TLV{
		{Tag: wire.TLVObjSampleID, Val: testU64(9007199254740993)},
		{Tag: wire.TLVObjEndReason, Val: testU16(wire.EndTxOK)},
	})...)
	pay = append(pay, wire.EncodeEvent(&wire.Event{
		Kind: wire.KindSummary, ObjectType: wire.ObjSKB, EvidenceLevel: wire.EvidenceDirect,
		CPU: 0, Seq: 2, TsNs: 1_000_100, ObjectID: 1,
	}, []wire.TLV{
		{Tag: wire.TLVSumPktLen, Val: testU32(28)},
		{Tag: wire.TLVSumLinearLen, Val: testU32(28)},
		{Tag: wire.TLVSumIfindex, Val: testU32(2)},
		{Tag: wire.TLVSumDir, Val: testU8(wire.DirTX)},
		{Tag: wire.TLVSumIPVersion, Val: testU8(4)},
		{Tag: wire.TLVSumL4Proto, Val: testU8(1)},
		{Tag: wire.TLVSumSrcIP, Val: []byte{192, 168, 10, 5}},
		{Tag: wire.TLVSumDstIP, Val: []byte{198, 51, 100, 9}},
		{Tag: wire.TLVSumUID, Val: testU32(10234)},
		{Tag: wire.TLVSumComm, Val: []byte("ping\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")},
		{Tag: wire.TLVSumLinktype, Val: testU16(101)},
		{Tag: wire.TLVSumHdrBytes, Val: []byte{
			0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
			0x40, 0x01, 0x00, 0x00, 192, 168, 10, 5, 198, 51, 100, 9,
			0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
		}},
	})...)

	blk1, err := wire.EncodeBlock(wire.BlockHeader{
		Magic: wire.BlockMagic, Major: wire.WireMajor, Minor: wire.WireMinor,
		BlockType: wire.BlockEventBatch, ProducerType: wire.ProdKernelBPF,
		Epoch: 1, BlockNo: 1, SessionUUID: uuid, MinTsNs: 1_000_000, MaxTsNs: 1_000_100,
	}, pay)
	if err != nil {
		t.Fatalf("encode blk1: %v", err)
	}
	blkEnd, err := wire.EncodeBlock(wire.BlockHeader{
		Magic: wire.BlockMagic, Major: wire.WireMajor, Minor: wire.WireMinor,
		BlockType: wire.BlockEndMarker, ProducerType: wire.ProdController,
		Epoch: 1, BlockNo: 2, SessionUUID: uuid, MinTsNs: 1_000_100, MaxTsNs: 1_000_100,
	}, nil)
	if err != nil {
		t.Fatalf("encode blkEnd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "block_000001.pktb"), blk1, 0o644); err != nil {
		t.Fatalf("write blk1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "block_000002.pktb"), blkEnd, 0o644); err != nil {
		t.Fatalf("write blkEnd: %v", err)
	}
	return dir
}

func requireCordisNodeRuntime(t *testing.T) (string, string) {
	t.Helper()
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skipf("node binary not in PATH: %v", err)
	}
	_, thisFile, _, _ := runtime.Caller(0)
	hostDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "cordis-analyzer-host")
	runtimeScript := filepath.Join(hostDir, "plugin-runtime.mjs")
	if _, err := os.Stat(runtimeScript); err != nil {
		t.Skipf("plugin-runtime.mjs missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hostDir, "node_modules")); err != nil {
		t.Skipf("cordis-analyzer-host/node_modules missing: %v", err)
	}
	return nodeBin, runtimeScript
}

func installCountingCordisAnalyzer(t *testing.T, pluginsDir, counterPath string) string {
	t.Helper()
	pluginID := "shan-counting-analyzer"
	bundleDir := filepath.Join(pluginsDir, pluginID)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("mkdir plugin bundle: %v", err)
	}
	manifest := `{
  "id": "shan-counting-analyzer",
  "name": "Counting Cordis Analyzer",
  "version": "1.0.0",
  "category": "analyzer",
  "config_schema": {
    "fields": [
      {"key": "tag", "label": "Tag", "type": "string", "default": "v1"},
      {"key": "fail", "label": "Fail", "type": "boolean", "default": false}
    ]
  },
  "entrypoint": {
    "module": "plugin.mjs"
  },
  "analyzers": [
    {"id": "counting-main", "name": "Counting Main", "priority": 15}
  ]
}`
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write plugin manifest: %v", err)
	}
	counterJSON, _ := json.Marshal(counterPath)
	pluginJS := `import fs from "node:fs";

const COUNTER_PATH = ` + string(counterJSON) + `;

export const name = "shan-counting-analyzer";

export function apply(ctx, config) {
  ctx.on("dispose", async () => {
    await new Promise((r) => setTimeout(r, 15));
  });
}

export async function analyze(req) {
  fs.appendFileSync(COUNTER_PATH, "run\n", "utf8");
  const cfg = req.config || {};
  if (cfg.fail) {
    throw new Error("simulated analyzer failure");
  }
  const tag = String(cfg.tag || "v1");
  return {
    insights: [
      {
        id: "counting-insight",
        severity: "info",
        title: "Cordis analyzer tag=" + tag,
        summary: "session=" + req.session_id
      }
    ],
    kpis: [
      {
        id: "counting-kpi",
        label: "Analyzer Tag",
        value: tag
      }
    ],
    notes: ["cordis-run:" + tag]
  };
}
`
	if err := os.WriteFile(filepath.Join(bundleDir, "plugin.mjs"), []byte(pluginJS), 0o644); err != nil {
		t.Fatalf("write plugin.mjs: %v", err)
	}
	return pluginID
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("read counter %s: %v", path, err)
	}
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" {
		return 0
	}
	return len(strings.Split(trimmed, "\n"))
}

func fileSHA256Map(t *testing.T, dir string, names []string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(names))
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		sum := sha256.Sum256(b)
		out[n] = hex.EncodeToString(sum[:])
	}
	return out
}

func doJSONRequest(t *testing.T, h http.Handler, method, target string, payload any) (int, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	if payload != nil {
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, target, &body)
	req.Host = "127.0.0.1:8765"
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp map[string]any
	if len(rec.Body.Bytes()) > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s %s returned non-JSON (status=%d): %s", method, target, rec.Code, rec.Body.String())
		}
	}
	return rec.Code, resp
}

func findInsightTitle(ov map[string]any, wantPrefix string) (string, bool) {
	list, _ := ov["plugin_insights"].([]any)
	for _, raw := range list {
		m, _ := raw.(map[string]any)
		title, _ := m["title"].(string)
		if strings.HasPrefix(title, wantPrefix) {
			return title, true
		}
	}
	return "", false
}

func TestAnalysisPersistenceEndToEndCordisModule(t *testing.T) {
	nodeBin, runtimeScript := requireCordisNodeRuntime(t)

	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	pluginsDir := filepath.Join(appDir, "plugins")
	counterPath := filepath.Join(root, "runs.log")

	// Folder name intentionally includes CJK + space to verify cross-platform path handling.
	extSessionDir := makeSyntheticSessionDir(t, root, "合成会话 验收_01")
	sourceFiles := []string{"manifest.json", "dict.json", "block_000001.pktb", "block_000002.pktb"}
	beforeHashes := fileSHA256Map(t, extSessionDir, sourceFiles)

	pluginID := installCountingCordisAnalyzer(t, pluginsDir, counterPath)

	newSrv := func() *Server {
		return New(Options{
			AppDir:                  appDir,
			PluginsDir:              pluginsDir,
			CordisPluginRuntime:     runtimeScript,
			CordisPluginRuntimeNode: nodeBin,
			Version:                 "test-dev",
		})
	}

	// ---- Server #1: open external session -> runs Cordis analyzer once & persists ----
	s1 := newSrv()
	code, openResp := doJSONRequest(t, s1.Handler(), http.MethodPost, "/api/sessions/open", map[string]any{
		"path": extSessionDir,
	})
	if code != http.StatusOK {
		t.Fatalf("open session failed: status=%d resp=%v", code, openResp)
	}
	sessID, _ := openResp["session_id"].(string)
	if sessID == "" {
		t.Fatalf("missing session_id in open response: %v", openResp)
	}
	openOv, _ := openResp["overview"].(map[string]any)
	if title, ok := findInsightTitle(openOv, "Cordis analyzer tag="); !ok || title != "Cordis analyzer tag=v1" {
		t.Fatalf("unexpected open insight: ok=%v title=%q", ok, title)
	}
	if got := countLines(t, counterPath); got != 1 {
		t.Fatalf("expected 1 analyzer run after initial open, got %d", got)
	}

	// Verify session-disk cache written and immutable session source files untouched.
	cachePath := filepath.Join(extSessionDir, analysisCacheFileName)
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected session-disk analysis cache at %s: %v", cachePath, err)
	}
	afterHashes := fileSHA256Map(t, extSessionDir, sourceFiles)
	for _, f := range sourceFiles {
		if beforeHashes[f] != afterHashes[f] {
			t.Fatalf("session source file %s was modified!", f)
		}
	}

	// Second overview in same process hits memory base cache (0 extra Cordis runs).
	code, ovResp := doJSONRequest(t, s1.Handler(), http.MethodGet, "/api/session/overview?id="+sessID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview #2 failed: status=%d resp=%v", code, ovResp)
	}
	if got := countLines(t, counterPath); got != 1 {
		t.Fatalf("expected memory cache hit (still 1 run), got %d", got)
	}

	s1.kernel.Shutdown()

	// ---- Server #2 (simulated restart): restores opened_sessions.json & hits session-disk cache ----
	s2 := newSrv()
	defer s2.kernel.Shutdown()

	code, listResp := doJSONRequest(t, s2.Handler(), http.MethodGet, "/api/sessions", nil)
	if code != http.StatusOK {
		t.Fatalf("list sessions after restart failed: status=%d", code)
	}
	sessionsList, _ := listResp["sessions"].([]any)
	foundExternal := false
	for _, raw := range sessionsList {
		m, _ := raw.(map[string]any)
		if m["id"] == sessID && m["external"] == true {
			foundExternal = true
			break
		}
	}
	if !foundExternal {
		t.Fatalf("external session %s was not restored from opened_sessions.json: %v", sessID, listResp)
	}

	code, ovAfterRestart := doJSONRequest(t, s2.Handler(), http.MethodGet, "/api/session/overview?id="+sessID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview after restart failed: status=%d resp=%v", code, ovAfterRestart)
	}
	if title, ok := findInsightTitle(ovAfterRestart, "Cordis analyzer tag="); !ok || title != "Cordis analyzer tag=v1" {
		t.Fatalf("unexpected insight after restart: ok=%v title=%q", ok, title)
	}
	if got := countLines(t, counterPath); got != 1 {
		t.Fatalf("expected session-disk cache hit across restart (still 1 run), got %d", got)
	}

	// ---- Config change invalidates cache -> recomputes and persists v2 ----
	code, cfgResp := doJSONRequest(t, s2.Handler(), http.MethodPost, "/api/kernel/plugins/config", map[string]any{
		"id":     pluginID,
		"config": map[string]any{"tag": "v2", "fail": false},
	})
	if code != http.StatusOK {
		t.Fatalf("update plugin config failed: status=%d resp=%v", code, cfgResp)
	}
	code, ovV2 := doJSONRequest(t, s2.Handler(), http.MethodGet, "/api/session/overview?id="+sessID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview after config change failed: status=%d", code)
	}
	if title, ok := findInsightTitle(ovV2, "Cordis analyzer tag="); !ok || title != "Cordis analyzer tag=v2" {
		t.Fatalf("expected tag=v2 after config change, got ok=%v title=%q", ok, title)
	}
	if got := countLines(t, counterPath); got != 2 {
		t.Fatalf("expected 2 runs after config change, got %d", got)
	}

	// ---- Explicit ?refresh=1 forces recompute ----
	code, _ = doJSONRequest(t, s2.Handler(), http.MethodGet, "/api/session/overview?id="+sessID+"&refresh=1", nil)
	if code != http.StatusOK {
		t.Fatalf("overview refresh=1 failed: status=%d", code)
	}
	if got := countLines(t, counterPath); got != 3 {
		t.Fatalf("expected 3 runs after ?refresh=1, got %d", got)
	}

	// ---- Corrupted session-disk cache is safely ignored and rebuilt on next restart ----
	if err := os.WriteFile(cachePath, []byte("{corrupted json"), 0o644); err != nil {
		t.Fatalf("corrupt cache file: %v", err)
	}
	s2.kernel.Shutdown()
	s3 := newSrv()
	defer s3.kernel.Shutdown()

	code, ovRebuilt := doJSONRequest(t, s3.Handler(), http.MethodGet, "/api/session/overview?id="+sessID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview after corrupt cache failed: status=%d", code)
	}
	if title, ok := findInsightTitle(ovRebuilt, "Cordis analyzer tag="); !ok || title != "Cordis analyzer tag=v2" {
		t.Fatalf("expected rebuilt tag=v2, got ok=%v title=%q", ok, title)
	}
	if got := countLines(t, counterPath); got != 4 {
		t.Fatalf("expected 4 runs after corrupt cache rebuild, got %d", got)
	}

	// ---- Session source file mtime/size change invalidates cache ----
	manifestPath := filepath.Join(extSessionDir, "manifest.json")
	future := time.Now().Add(5 * time.Second)
	if err := os.Chtimes(manifestPath, future, future); err != nil {
		t.Fatalf("chtimes manifest: %v", err)
	}
	code, _ = doJSONRequest(t, s3.Handler(), http.MethodGet, "/api/session/overview?id="+sessID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview after source mtime change failed: status=%d", code)
	}
	if got := countLines(t, counterPath); got != 5 {
		t.Fatalf("expected 5 runs after session source mtime change, got %d", got)
	}

	// ---- Disabling analyzer plugin invalidates cache and removes its insight ----
	code, toggleResp := doJSONRequest(t, s3.Handler(), http.MethodPost, "/api/kernel/plugins/toggle", map[string]any{
		"id":      pluginID,
		"enabled": false,
	})
	if code != http.StatusOK {
		t.Fatalf("disable plugin failed: status=%d resp=%v", code, toggleResp)
	}
	code, ovDisabled := doJSONRequest(t, s3.Handler(), http.MethodGet, "/api/session/overview?id="+sessID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview after disable failed: status=%d", code)
	}
	if _, ok := findInsightTitle(ovDisabled, "Cordis analyzer tag="); ok {
		t.Fatalf("disabled analyzer insight should not remain in overview")
	}
	if got := countLines(t, counterPath); got != 5 {
		t.Fatalf("disabled analyzer should not have run again, got %d", got)
	}

	// ---- Redacted export must not leak .pktpath_analysis_cache.json ----
	redactedDir := filepath.Join(root, "redacted_out")
	if err := export.RedactSession(extSessionDir, redactedDir, "test-redact-key"); err != nil {
		t.Fatalf("RedactSession: %v", err)
	}
	if _, err := os.Stat(filepath.Join(redactedDir, analysisCacheFileName)); !os.IsNotExist(err) {
		t.Fatalf("redacted export should not contain %s", analysisCacheFileName)
	}
}

func TestAnalysisPersistenceReadOnlyFallbackAndErrorNotCached(t *testing.T) {
	nodeBin, runtimeScript := requireCordisNodeRuntime(t)

	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	pluginsDir := filepath.Join(appDir, "plugins")
	counterPath := filepath.Join(root, "runs.log")

	pluginID := installCountingCordisAnalyzer(t, pluginsDir, counterPath)

	newSrv := func() *Server {
		return New(Options{
			AppDir:                  appDir,
			PluginsDir:              pluginsDir,
			CordisPluginRuntime:     runtimeScript,
			CordisPluginRuntimeNode: nodeBin,
			Version:                 "test-dev",
		})
	}

	// ---- Part A: Analyzer error must NOT be persisted into cache ----
	errSessionDir := makeSyntheticSessionDir(t, root, "err_session")
	s1 := newSrv()
	code, _ := doJSONRequest(t, s1.Handler(), http.MethodPost, "/api/kernel/plugins/config", map[string]any{
		"id":     pluginID,
		"config": map[string]any{"tag": "bad", "fail": true},
	})
	if code != http.StatusOK {
		t.Fatalf("set fail=true failed: status=%d", code)
	}
	code, openErrResp := doJSONRequest(t, s1.Handler(), http.MethodPost, "/api/sessions/open", map[string]any{
		"path": errSessionDir,
	})
	if code != http.StatusOK {
		t.Fatalf("open err session failed: status=%d", code)
	}
	errSessID, _ := openErrResp["session_id"].(string)
	if _, err := os.Stat(filepath.Join(errSessionDir, analysisCacheFileName)); !os.IsNotExist(err) {
		t.Fatalf("errored analysis run must not write %s", analysisCacheFileName)
	}
	if got := countLines(t, counterPath); got != 1 {
		t.Fatalf("expected 1 run on first failing analysis, got %d", got)
	}
	// Calling overview again must retry (not serve cached failure).
	code, _ = doJSONRequest(t, s1.Handler(), http.MethodGet, "/api/session/overview?id="+errSessID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview retry failed: status=%d", code)
	}
	if got := countLines(t, counterPath); got != 2 {
		t.Fatalf("expected retry on failing analyzer (2 runs), got %d", got)
	}

	// Reset config to fail=false for Part B.
	code, _ = doJSONRequest(t, s1.Handler(), http.MethodPost, "/api/kernel/plugins/config", map[string]any{
		"id":     pluginID,
		"config": map[string]any{"tag": "ro-ok", "fail": false},
	})
	if code != http.StatusOK {
		t.Fatalf("set fail=false failed: status=%d", code)
	}

	// ---- Part B: Read-only session directory falls back to AppDir/analysis_cache ----
	if os.Geteuid() == 0 {
		s1.kernel.Shutdown()
		t.Skip("running as root; chmod 0555 does not block writes")
	}
	roSessionDir := makeSyntheticSessionDir(t, root, "readonly_session")
	if err := os.Chmod(roSessionDir, 0o555); err != nil {
		t.Fatalf("chmod 0555: %v", err)
	}
	defer func() { _ = os.Chmod(roSessionDir, 0o755) }()

	code, openRO := doJSONRequest(t, s1.Handler(), http.MethodPost, "/api/sessions/open", map[string]any{
		"path": roSessionDir,
	})
	if code != http.StatusOK {
		t.Fatalf("open ro session failed: status=%d resp=%v", code, openRO)
	}
	roID, _ := openRO["session_id"].(string)
	if got := countLines(t, counterPath); got != 3 {
		t.Fatalf("expected 3 runs after opening ro session, got %d", got)
	}
	if _, err := os.Stat(filepath.Join(roSessionDir, analysisCacheFileName)); !os.IsNotExist(err) {
		t.Fatalf("readonly session dir should not have local cache file")
	}
	appCachePath := s1.appAnalysisCachePath(roSessionDir)
	if _, err := os.Stat(appCachePath); err != nil {
		t.Fatalf("expected fallback cache under AppDir at %s: %v", appCachePath, err)
	}
	s1.kernel.Shutdown()

	// Restart server: read-only session hits AppDir fallback cache with 0 extra runs.
	s2 := newSrv()
	defer s2.kernel.Shutdown()
	code, ovRO := doJSONRequest(t, s2.Handler(), http.MethodGet, "/api/session/overview?id="+roID, nil)
	if code != http.StatusOK {
		t.Fatalf("overview ro session after restart failed: status=%d", code)
	}
	if title, ok := findInsightTitle(ovRO, "Cordis analyzer tag="); !ok || title != "Cordis analyzer tag=ro-ok" {
		t.Fatalf("expected ro-ok insight from app_cache fallback, got ok=%v title=%q", ok, title)
	}
	if got := countLines(t, counterPath); got != 3 {
		t.Fatalf("expected app_cache fallback hit across restart (still 3 runs), got %d", got)
	}
}
