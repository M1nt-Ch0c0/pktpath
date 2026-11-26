package kernel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pktpath/studio/pkg/reconstruct"
)

func testPluginRuntime(t *testing.T) *CordisPluginRuntime {
	t.Helper()
	host, node, err := ResolveDefaultPluginRuntime("", "")
	if err != nil {
		t.Skip(err)
	}
	rt := NewCordisPluginRuntime(CordisPluginRuntimeOptions{NodePath: node, HostPath: host})
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	return rt
}

func testdataPlugin(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveDefaultPluginRuntimeFindsBundledHost(t *testing.T) {
	host, node, err := ResolveDefaultPluginRuntime("", "")
	if err != nil {
		t.Skip(err)
	}
	if !strings.HasSuffix(host, "plugin-runtime.mjs") {
		t.Fatalf("unexpected host path: %s", host)
	}
	if _, err := os.Stat(host); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(node); err != nil {
		t.Fatal(err)
	}
}

func TestCommandOnlyPluginRejectedOnPreviewAndInstall(t *testing.T) {
	k := New(HostServices{AppDir: t.TempDir()})
	src := testdataPlugin(t, "command-only-plugin")
	prev := k.PreviewExternal(src, nil, "")
	if prev.OK || !strings.Contains(prev.Error, "entrypoint.command") {
		t.Fatalf("preview should reject command-only plugin: %+v", prev)
	}
	if _, err := k.InstallExternal(src, nil, ""); !errors.Is(err, ErrCommandEntrypoint) && (err == nil || !strings.Contains(err.Error(), "entrypoint.command")) {
		t.Fatalf("install should reject command-only plugin: %v", err)
	}
}

func TestModulePluginAnalyzeExportWaitsForCleanup(t *testing.T) {
	rt := testPluginRuntime(t)
	dir := t.TempDir()
	k := New(HostServices{AppDir: dir, PluginRuntime: rt})
	meta, err := k.InstallExternal(testdataPlugin(t, "fixture-module-plugin"), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID != "community.analyzer.fixture-module" {
		t.Fatalf("unexpected id %s", meta.ID)
	}
	if !k.IsPluginActive(meta.ID) {
		t.Fatal("plugin should be active after install")
	}

	sessDir := t.TempDir()
	out := k.AnalyzeSession(context.Background(), &AnalyzeInput{
		SessionID:  "sess-offline-1",
		SessionDir: sessDir,
		Overview: &reconstruct.SessionOverview{
			Manifest: map[string]any{"id": "sess-offline-1"},
			Dict:     map[string]any{},
			Stats: &reconstruct.Stats{
				QualityAlerts: []reconstruct.QualityAlert{{Kind: "gap", Severity: "error", Count: 1, Message: "synthetic"}},
			},
			Samples: []reconstruct.SampleRow{{SampleID: 42, Comm: "demo", MaxSojournUs: 1}},
		},
	})
	if len(out.Insights) != 1 || out.Insights[0].Severity != "critical" || out.Insights[0].Summary != "1" {
		t.Fatalf("unexpected insights: %+v", out.Insights)
	}
	if len(out.KPIs) != 1 || out.KPIs[0].Tone != "ok" || out.KPIs[0].Value != "1" {
		t.Fatalf("unexpected kpis: %+v", out.KPIs)
	}
	if len(out.Notes) != 1 || out.Notes[0] != "fixture-analyze" {
		t.Fatalf("unexpected notes: %+v", out.Notes)
	}

	exportPath := filepath.Join(dir, "fixture-export.json")
	res, err := k.RunExporter(context.Background(), "community.analyzer.fixture-module.export", &ExportInput{
		SessionID:  "sess-offline-1",
		SessionDir: sessDir,
		OutPath:    exportPath,
		Params:     map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.OutPath != exportPath {
		t.Fatalf("unexpected export result: %+v", res)
	}
	raw, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "fixture-export") {
		t.Fatalf("export file missing payload: %s", raw)
	}

	start := time.Now()
	if err := k.SetEnabled(meta.ID, false); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 70*time.Millisecond {
		t.Fatalf("disable returned before cleanup finished: %s", elapsed)
	}
	if k.IsPluginActive(meta.ID) {
		t.Fatal("plugin still active after disable")
	}
}

func TestBadSeverityIsAnalyzeFailure(t *testing.T) {
	rt := testPluginRuntime(t)
	k := New(HostServices{AppDir: t.TempDir(), PluginRuntime: rt})
	if _, err := k.InstallExternal(testdataPlugin(t, "bad-severity-plugin"), nil, ""); err != nil {
		t.Fatal(err)
	}
	out := k.AnalyzeSession(context.Background(), &AnalyzeInput{
		SessionID:  "sess",
		SessionDir: t.TempDir(),
		Overview:   &reconstruct.SessionOverview{},
	})
	if len(out.Insights) != 0 {
		t.Fatalf("invalid severity must not be attached as success: %+v", out.Insights)
	}
	if len(out.Notes) == 0 || !strings.Contains(strings.Join(out.Notes, "\n"), "invalid insight severity") {
		t.Fatalf("expected failure note, got %+v", out.Notes)
	}
}

func TestMissingAnalyzeExportIsLoadFailure(t *testing.T) {
	rt := testPluginRuntime(t)
	k := New(HostServices{AppDir: t.TempDir(), PluginRuntime: rt})
	_, err := k.InstallExternal(testdataPlugin(t, "missing-analyze-plugin"), nil, "")
	if err == nil || !strings.Contains(err.Error(), "analyze()") {
		t.Fatalf("expected load failure for missing analyze(), got %v", err)
	}
}

func TestValidateRelativeModuleRejectsEscape(t *testing.T) {
	for _, mod := range []string{"../plugin.mjs", "/tmp/plugin.mjs", "foo/../../x.mjs", ""} {
		if err := validateRelativeModule(mod); err == nil {
			t.Fatalf("expected reject %q", mod)
		}
	}
	if err := validateRelativeModule("plugin.mjs"); err != nil {
		t.Fatal(err)
	}
	if err := validateRelativeModule("lib/plugin.mjs"); err != nil {
		t.Fatal(err)
	}
}
