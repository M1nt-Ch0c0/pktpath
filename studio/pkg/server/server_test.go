package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func doJSON(t *testing.T, h http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Host = "127.0.0.1"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func TestKernelHTTPAPILifecycle(t *testing.T) {
	s := New(Options{AppDir: t.TempDir(), Version: "2.0.0-test"})
	h := s.Handler()

	// 1. Health check
	rr, health := doJSON(t, h, http.MethodGet, "/api/health", nil)
	if rr.Code != http.StatusOK || health["ok"] != true {
		t.Fatalf("health failed: code=%d body=%v", rr.Code, health)
	}

	// 2. Kernel state lists all 13 built-in plugins
	rr, stResp := doJSON(t, h, http.MethodGet, "/api/kernel/state", nil)
	if rr.Code != http.StatusOK || stResp["ok"] != true {
		t.Fatalf("kernel state failed: code=%d", rr.Code)
	}
	st := stResp["state"].(map[string]any)
	if int(st["total_plugins"].(float64)) != 13 || int(st["active_plugins"].(float64)) != 13 {
		t.Fatalf("expected 13/13 built-in plugins, got %v/%v", st["active_plugins"], st["total_plugins"])
	}

	// 3. Hot toggle transport plugin
	rr, tog := doJSON(t, h, http.MethodPost, "/api/kernel/plugins/toggle", map[string]any{
		"id": "builtin.transport.android-adb", "enabled": false,
	})
	if rr.Code != http.StatusOK || tog["ok"] != true {
		t.Fatalf("toggle failed: %v", tog)
	}
	_, devs := doJSON(t, h, http.MethodGet, "/api/devices", nil)
	if devs["adb_enabled"] != false {
		t.Fatalf("expected adb_enabled=false when plugin disabled, got %v", devs["adb_enabled"])
	}

	// 4. Schema config save + reset
	rr, cfgResp := doJSON(t, h, http.MethodPost, "/api/kernel/plugins/config", map[string]any{
		"id":     "builtin.ui.theme",
		"config": map[string]any{"mode": "dark", "accent": "emerald", "density": "compact", "font_scale": 105},
	})
	if rr.Code != http.StatusOK || cfgResp["ok"] != true {
		t.Fatalf("config update failed: %v", cfgResp)
	}
	rr, rstResp := doJSON(t, h, http.MethodPost, "/api/kernel/plugins/reset", map[string]any{"id": "builtin.ui.theme"})
	if rr.Code != http.StatusOK || rstResp["ok"] != true {
		t.Fatalf("reset failed: %v", rstResp)
	}

	// 5. External JSON plugin preview -> install -> uninstall
	manifest := `{"id":"http.test.ext","name":"HTTP Ext","sock_fields":[{"struct":"sock","field":"sk_mark","size":4,"role":"tag","label":"m"}]}`
	rr, pv := doJSON(t, h, http.MethodPost, "/api/kernel/plugins/preview", map[string]any{"content": manifest, "filename": "m.json"})
	if rr.Code != http.StatusOK || pv["ok"] != true {
		t.Fatalf("preview failed: %v", pv)
	}
	rr, inst := doJSON(t, h, http.MethodPost, "/api/kernel/plugins/install", map[string]any{"content": manifest, "filename": "m.json"})
	if rr.Code != http.StatusOK || inst["ok"] != true {
		t.Fatalf("install failed: %v", inst)
	}
	rr, uninst := doJSON(t, h, http.MethodPost, "/api/kernel/plugins/uninstall", map[string]any{"id": "http.test.ext"})
	if rr.Code != http.StatusOK || uninst["ok"] != true {
		t.Fatalf("uninstall failed: %v", uninst)
	}
}

func TestDNSRebindingGuard(t *testing.T) {
	s := New(Options{AppDir: t.TempDir(), Version: "2.0.0-test"})
	s.mu.Lock()
	s.port = 18080
	s.mu.Unlock()
	h := s.Handler()

	// Reject foreign Host header
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Host = "evil.example.com:18080"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for foreign Host, got %d", rr.Code)
	}

	// Reject cross-origin POST
	req2 := httptest.NewRequest(http.MethodPost, "/api/kernel/plugins/toggle", bytes.NewBufferString(`{}`))
	req2.Host = "127.0.0.1:18080"
	req2.Header.Set("Origin", "https://evil.example.com")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for foreign Origin, got %d", rr2.Code)
	}
}
