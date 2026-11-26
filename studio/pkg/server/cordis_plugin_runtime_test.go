package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
