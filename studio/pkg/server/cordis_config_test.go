package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCordisF03HTTPConfigResetOperationFacts(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("explicit controlled host")
	}
	s := New(Options{AppDir: t.TempDir(), CordisPluginHost: host, CordisConfigTransactions: true})
	defer s.Shutdown(context.Background())
	h := s.kernel.Host().LifecycleHost
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e := h.WaitActive(ctx, "builtin.collector.ebpf-tc"); e != nil {
		t.Fatal(e)
	}
	post := func(route, body string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", route, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		s.Handler().ServeHTTP(w, r)
		var doc map[string]json.RawMessage
		json.Unmarshal(w.Body.Bytes(), &doc)
		if w.Code != want || doc["state"] == nil {
			t.Fatalf("HTTP missing facts: %d %s", w.Code, w.Body.String())
		}
	}
	post("/api/kernel/plugins/config", `{"id":"builtin.collector.ebpf-tc","config":{"capture_hdr_bytes":64}}`, 200)
	if s.kernel.Collector().CaptureHdrBytes != 64 || len(h.Snapshot().ConfigOperations) != 1 || h.Snapshot().ConfigOperations[0].Phase != "committed" {
		t.Fatal("HTTP successful config not really committed")
	}
	post("/api/kernel/plugins/reset", `{"id":"builtin.collector.ebpf-tc"}`, 200)
	if s.kernel.Collector().CaptureHdrBytes != 96 || len(h.Snapshot().ConfigOperations) != 2 {
		t.Fatal("HTTP Reset not schema defaults")
	}
	post("/api/kernel/plugins/config", `{"id":"builtin.collector.ebpf-tc","config":{"unknown_f03":true}}`, 400)
	if len(h.Snapshot().ConfigOperations) != 2 || s.kernel.Collector().CaptureHdrBytes != 96 {
		t.Fatal("invalid HTTP config had side effects")
	}
	if s.cap != nil || s.http != nil {
		t.Fatal("F03 changed capture owner/listener")
	}
}
