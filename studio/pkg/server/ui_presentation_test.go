package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	studioassets "pktpath/studio"
)

// Actual Go routing + embedded assets. No listener, Node, capture or device calls.
func TestStudioSprintPresentationWithRealGoHandler(t *testing.T) {
	web, err := studioassets.WebFS()
	if err != nil {
		t.Fatal(err)
	}
	s := New(Options{AppDir: t.TempDir(), Web: web, Version: "ui-sprint-test"})
	defer s.Shutdown(context.Background())
	for _, route := range []string{"/", "/studio-presentation.css", "/studio-presentation.js", "/workbench-layout.js", "/api/health"} {
		t.Run(route, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", route, nil)
			r.Host = "127.0.0.1"
			s.Handler().ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("%s: status %d %s", route, w.Code, w.Body.String())
			}
			if route == "/" {
				for _, expected := range []string{"studio-presentation.css", "studio-presentation.js", "studioDataSource", "panelFlow", "panelLatency", "panelSamples"} {
					if !strings.Contains(w.Body.String(), expected) {
						t.Fatalf("missing %s", expected)
					}
				}
			}
			if route == "/api/health" {
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body["ok"] != true || body["version"] != "ui-sprint-test" || body["pid"] == nil || body["sessions_root"] == nil || body["kernel_plugins_total"] == nil {
					t.Fatalf("health contract: %v", body)
				}
			}
		})
	}
	if s.opts.CordisPluginHost != "" || s.opts.CordisAnalyzerHost != "" || s.cap != nil {
		t.Fatal("presentation must not opt into host or capture")
	}
}
