package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Production Server + real selected metadata IDs; no listener/device starts.
func TestCordisF031AV2HTTPDuplicateManagedStartupBlocked(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"hidden-managed-unknown", `{"version":2,"plugins":{"builtin.collector.ebpf-tc":{"config":{"future":7}}},"plugins":{}}`},
		{"hidden-managed-schemaVersion", `{"version":2,"plugins":{"builtin.collector.ebpf-tc":{"schemaVersion":99}},"plugins":{}}`},
		{"managed-config-merge", `{"version":2,"plugins":{"builtin.collector.ebpf-tc":{"config":{"future":7},"config":{}}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "plugins_config.json")
			raw := []byte(tc.raw)
			os.WriteFile(path, raw, 0600)
			marker := filepath.Join(dir, "node-was-started")
			node := filepath.Join(dir, "node-sentinel")
			os.WriteFile(node, []byte("#!/bin/sh\nprintf started > '"+marker+"'\nexit 99\n"), 0700)
			s := New(Options{AppDir: dir, CordisPluginHost: "never-loaded.mjs", CordisPluginNode: node, CordisConfigTransactions: true})
			defer s.Shutdown(context.Background())
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/kernel/state", nil))
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"config_compatibility"`) || !strings.Contains(w.Body.String(), `"incompatible-config"`) {
				t.Fatalf("startup error was swallowed without API diagnostics: %d %s", w.Code, w.Body.String())
			}
			r := httptest.NewRequest("POST", "/api/kernel/plugins/reset", strings.NewReader(`{"id":"builtin.collector.ebpf-tc"}`))
			r.Header.Set("Content-Type", "application/json")
			w = httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var response map[string]json.RawMessage
			json.Unmarshal(w.Body.Bytes(), &response)
			if w.Code != 400 || string(response["ok"]) != "false" || response["state"] == nil {
				t.Fatalf("Reset hid incompatible startup: %d %s", w.Code, w.Body.String())
			}
			if s.kernel.Collector() != nil || len(s.kernel.Host().LifecycleHost.Snapshot().ConfigOperations) != 0 {
				t.Fatal("bad config still activated collector/admitted transaction")
			}
			b, _ := os.ReadFile(path)
			if !bytes.Equal(raw, b) {
				t.Fatal("HTTP error rewrote future file")
			}
			if _, e := os.Stat(marker); !os.IsNotExist(e) {
				t.Fatal("startup probed Node")
			}
			if s.cap != nil || s.http != nil {
				t.Fatal("capture/listener touched")
			}
		})
	}
}
