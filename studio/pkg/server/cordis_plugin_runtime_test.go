package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pktpath/studio/pkg/kernel"
	"pktpath/studio/pkg/reconstruct"
)

func TestDefaultPluginRuntimeIsCordis(t *testing.T) {
	s := New(Options{AppDir: t.TempDir()})
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	host := s.Kernel().Host()
	if host.PluginRuntime == nil {
		t.Fatal("new preview should default to the bundled Cordis plugin runtime when it is present")
	}
	if host.LifecycleHost != nil {
		t.Fatal("F02 lifecycle should stay off unless explicitly requested")
	}
	if host.AnalyzerHost != nil {
		t.Fatal("legacy F01 analyzer host should stay off unless explicitly requested")
	}
}

func TestDashDisablesDefaultPluginRuntime(t *testing.T) {
	s := New(Options{AppDir: t.TempDir(), CordisPluginRuntime: "-"})
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	if s.Kernel().Host().PluginRuntime != nil {
		t.Fatal("CordisPluginRuntime=- should leave the runtime unset")
	}
}

func TestServerDefaultCordisModulePluginEndToEnd(t *testing.T) {
	s := New(Options{AppDir: t.TempDir()})
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	pkgDir, err := filepath.Abs(filepath.Join("..", "kernel", "testdata", "fixture-module-plugin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Kernel().InstallExternal(pkgDir, nil, ""); err != nil {
		t.Fatalf("install module plugin: %v", err)
	}

	ov := &reconstruct.SessionOverview{
		Manifest: map[string]any{"id": "offline-1"},
		Dict:     map[string]any{},
		Stats: &reconstruct.Stats{
			QualityAlerts: []reconstruct.QualityAlert{
				{Kind: "gap", Severity: "error", Count: 1, Message: "synthetic"},
			},
		},
		Samples: []reconstruct.SampleRow{{SampleID: 42, Comm: "demo", MaxSojournUs: 1}},
	}
	baseJSON, err := json.Marshal(ov)
	if err != nil {
		t.Fatal(err)
	}
	ls := &loadedSession{
		ovObj:    ov,
		overview: baseJSON,
	}

	enriched := s.enrichOverview(context.Background(), "offline-1", t.TempDir(), ls)
	var got struct {
		PluginInsights []kernel.Insight  `json:"plugin_insights"`
		PluginKPIs     []kernel.ExtraKPI `json:"plugin_kpis"`
		PluginNotes    []string          `json:"plugin_notes"`
	}
	if err := json.Unmarshal(enriched, &got); err != nil {
		t.Fatalf("unmarshal enriched overview: %v", err)
	}
	var foundCritical bool
	for _, ins := range got.PluginInsights {
		if ins.PluginID == "community.analyzer.fixture-module" && ins.Severity == "critical" {
			foundCritical = true
		}
	}
	if !foundCritical {
		t.Fatalf("expected mapped critical insight from module plugin, got %+v", got.PluginInsights)
	}
	if len(got.PluginKPIs) == 0 {
		t.Fatalf("expected module plugin KPI in enriched overview")
	}

	outPath := filepath.Join(t.TempDir(), "audit.json")
	res, err := s.Kernel().RunExporter(context.Background(), "community.analyzer.fixture-module.export", &kernel.ExportInput{
		SessionID:  "offline-1",
		SessionDir: t.TempDir(),
		Overview:   ov,
		OutPath:    outPath,
		Params:     map[string]any{},
	})
	if err != nil {
		t.Fatalf("RunExporter: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected export ok=true, got %+v", res)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected exported file %s: %v", outPath, err)
	}

	start := time.Now()
	if err := s.Kernel().SetEnabled("community.analyzer.fixture-module", false); err != nil {
		t.Fatalf("disable module plugin: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 70*time.Millisecond {
		t.Fatalf("disable returned too early (%v); async cleanup was not awaited", elapsed)
	}
}

func TestKernelStateExposesDefaultPluginRuntime(t *testing.T) {
	s := New(Options{AppDir: t.TempDir()})
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/kernel/state", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"plugin_runtime"`) {
		t.Fatalf("expected plugin_runtime in default kernel state, status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		State struct {
			PluginRuntime *struct {
				Enabled  bool   `json:"enabled"`
				Backend  string `json:"backend"`
				Protocol string `json:"protocol"`
				HostPath string `json:"host_path"`
				NodePath string `json:"node_path"`
			} `json:"plugin_runtime"`
		} `json:"state"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode kernel state: %v", err)
	}
	rt := got.State.PluginRuntime
	if rt == nil || !rt.Enabled {
		t.Fatal("default preview should report plugin_runtime.enabled=true")
	}
	if rt.Backend != "cordis-plugin-runtime" || rt.Protocol != "pktpath.cordis3.plugin-runtime/1" {
		t.Fatalf("unexpected runtime identity: %+v", rt)
	}
	if !strings.HasSuffix(rt.HostPath, "plugin-runtime.mjs") {
		t.Fatalf("expected resolved plugin-runtime.mjs, got %q", rt.HostPath)
	}
	if strings.TrimSpace(rt.NodePath) == "" {
		t.Fatal("expected resolved Node path for default plugin runtime")
	}

	off := New(Options{AppDir: t.TempDir(), CordisPluginRuntime: "-"})
	t.Cleanup(func() { off.Shutdown(context.Background()) })
	w = httptest.NewRecorder()
	off.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/kernel/state", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), `"plugin_runtime"`) {
		t.Fatalf("CordisPluginRuntime=- should omit plugin_runtime, status=%d body=%s", w.Code, w.Body.String())
	}
}
