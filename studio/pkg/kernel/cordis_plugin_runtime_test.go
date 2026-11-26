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

func TestBundledNodeCandidates(t *testing.T) {
	win := bundledNodeCandidates("/app", "windows")
	if len(win) < 3 || !strings.HasSuffix(win[0], filepath.Join("node", "node.exe")) {
		t.Fatalf("unexpected windows bundled node candidates: %v", win)
	}
	lin := bundledNodeCandidates("/app", "linux")
	if len(lin) < 3 || !strings.HasSuffix(lin[0], filepath.Join("node", "bin", "node")) {
		t.Fatalf("unexpected linux bundled node candidates: %v", lin)
	}
}

func TestResolvePluginRuntimeNodePrecedence(t *testing.T) {
	dir := t.TempDir()
	envNode := filepath.Join(dir, "env-node")
	explicitNode := filepath.Join(dir, "explicit-node")
	winBundled := filepath.Join(dir, "exe", "node", "node.exe")
	linBundled := filepath.Join(dir, "exe", "node", "bin", "node")
	for _, p := range []string{envNode, explicitNode, winBundled, linBundled} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("stub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PKTPATH_CORDIS_NODE", envNode)
	got, err := resolvePluginRuntimeNodeWithExeDir("", filepath.Join(dir, "exe"), "windows")
	if err != nil || got != envNode {
		t.Fatalf("empty explicit should pick PKTPATH_CORDIS_NODE (%s), got %q err=%v", envNode, got, err)
	}

	got, err = resolvePluginRuntimeNodeWithExeDir(explicitNode, filepath.Join(dir, "exe"), "windows")
	if err != nil || got != explicitNode {
		t.Fatalf("non-empty explicit should win (%s), got %q err=%v", explicitNode, got, err)
	}

	t.Setenv("PKTPATH_CORDIS_NODE", "")
	got, err = resolvePluginRuntimeNodeWithExeDir("", filepath.Join(dir, "exe"), "windows")
	if err != nil || got != winBundled {
		t.Fatalf("empty explicit + unset env should pick bundled windows node (%s), got %q err=%v", winBundled, got, err)
	}

	got, err = resolvePluginRuntimeNodeWithExeDir("", filepath.Join(dir, "exe"), "linux")
	if err != nil || got != linBundled {
		t.Fatalf("empty explicit + unset env should pick bundled linux node (%s), got %q err=%v", linBundled, got, err)
	}
}

func TestLargeSampleIDRoundTrip(t *testing.T) {
	rt := testPluginRuntime(t)
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "bigint-plugin")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest.json"), []byte(`{
		"id": "reg.bigint",
		"name": "BigInt",
		"version": "1.0.0",
		"entrypoint": {"module": "plugin.mjs"},
		"analyzers": [{"id": "reg.bigint.a", "name": "BigInt"}]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "plugin.mjs"), []byte(`
		export async function analyze(input) {
			const sid = input.overview.samples[0].sample_id;
			return {
				insights: [{
					id: "big-1",
					plugin_id: "reg.bigint",
					plugin_name: "BigInt",
					severity: "info",
					title: "big",
					summary: String(sid),
					sample_ids: [sid]
				}]
			};
		}
	`), 0o644); err != nil {
		t.Fatal(err)
	}

	k := New(HostServices{AppDir: filepath.Join(dir, "app"), PluginRuntime: rt})
	if _, err := k.InstallExternal(pkgDir, nil, ""); err != nil {
		t.Fatal(err)
	}
	const want uint64 = 9007199254740993
	out := k.AnalyzeSession(context.Background(), &AnalyzeInput{
		SessionID:  "s1",
		SessionDir: dir,
		Overview: &reconstruct.SessionOverview{
			Samples: []reconstruct.SampleRow{{SampleID: want, Comm: "demo"}},
		},
	})
	if len(out.Insights) != 1 || out.Insights[0].Summary != "9007199254740993" {
		t.Fatalf("unexpected insights: %+v (notes=%v)", out.Insights, out.Notes)
	}
	if len(out.Insights[0].SampleIDs) != 1 || out.Insights[0].SampleIDs[0] != want {
		t.Fatalf("expected lossless uint64 %d, got %+v", want, out.Insights[0].SampleIDs)
	}
}

func TestAsyncCleanupFailureReportedOnDisable(t *testing.T) {
	rt := testPluginRuntime(t)
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "failclean-plugin")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest.json"), []byte(`{
		"id": "reg.failclean",
		"name": "FailClean",
		"version": "1.0.0",
		"entrypoint": {"module": "plugin.mjs"},
		"analyzers": [{"id": "reg.failclean.a", "name": "FailClean"}]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "plugin.mjs"), []byte(`
		export async function setup(ctx) {
			ctx.effect(() => async () => {
				await new Promise(r => setTimeout(r, 20));
				throw new Error("cleanup_boom");
			});
		}
		export async function analyze() { return { insights: [], kpis: [], notes: [] }; }
	`), 0o644); err != nil {
		t.Fatal(err)
	}

	k := New(HostServices{AppDir: filepath.Join(dir, "app"), PluginRuntime: rt})
	if _, err := k.InstallExternal(pkgDir, nil, ""); err != nil {
		t.Fatal(err)
	}
	err := k.SetEnabled("reg.failclean", false)
	if err == nil || !strings.Contains(err.Error(), "cleanup_boom") {
		t.Fatalf("expected cleanup_boom error on disable, got %v", err)
	}
	snap := k.Snapshot("test")
	var foundErr string
	for _, p := range snap.Plugins {
		if p.Meta.ID == "reg.failclean" {
			foundErr = p.Error
		}
	}
	if !strings.Contains(foundErr, "cleanup_boom") {
		t.Fatalf("expected snapshot LastError to record cleanup_boom, got %q", foundErr)
	}
}

func TestReinstallSamePluginReloadsFreshModule(t *testing.T) {
	rt := testPluginRuntime(t)
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "reload-plugin")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{
		"id": "reg.reload",
		"name": "Reload",
		"version": "1.0.0",
		"entrypoint": {"module": "plugin.mjs"},
		"analyzers": [{"id": "reg.reload.a", "name": "Reload"}]
	}`
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "plugin.mjs"), []byte(`export async function analyze() { return { notes: ["v1"] }; }`), 0o644); err != nil {
		t.Fatal(err)
	}

	k := New(HostServices{AppDir: filepath.Join(dir, "app"), PluginRuntime: rt})
	if _, err := k.InstallExternal(pkgDir, nil, ""); err != nil {
		t.Fatal(err)
	}
	out1 := k.AnalyzeSession(context.Background(), &AnalyzeInput{SessionID: "s1", SessionDir: dir, Overview: &reconstruct.SessionOverview{}})
	if len(out1.Notes) != 1 || out1.Notes[0] != "v1" {
		t.Fatalf("expected v1 note, got %v", out1.Notes)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "plugin.mjs"), []byte(`export async function analyze() { return { notes: ["v2"] }; }`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := k.InstallExternal(pkgDir, nil, ""); err != nil {
		t.Fatal(err)
	}
	out2 := k.AnalyzeSession(context.Background(), &AnalyzeInput{SessionID: "s1", SessionDir: dir, Overview: &reconstruct.SessionOverview{}})
	if len(out2.Notes) != 1 || out2.Notes[0] != "v2" {
		t.Fatalf("expected v2 note after reinstall, got %v", out2.Notes)
	}
}

func TestResolvePluginRuntimeHostPrefersExeDir(t *testing.T) {
	t.Setenv("PKTPATH_CORDIS_PLUGIN_RUNTIME", "")
	exeDir := t.TempDir()
	want := filepath.Join(exeDir, "cordis-analyzer-host", "plugin-runtime.mjs")
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("// bundled stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolvePluginRuntimeHostWithExeDir("", exeDir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("expected exeDir host %s to win over source/cwd, got %s", want, got)
	}
}
