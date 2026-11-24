package kernel

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

type stubPlugin struct {
	meta   PluginMeta
	schema *ConfigSchema
	apply  func(ctx *PluginContext, cfg map[string]any) error
}

func (s *stubPlugin) Meta() PluginMeta      { return s.meta }
func (s *stubPlugin) Schema() *ConfigSchema { return s.schema }
func (s *stubPlugin) Apply(ctx *PluginContext, cfg map[string]any) error {
	if s.apply != nil {
		return s.apply(ctx, cfg)
	}
	return nil
}

func TestSchemaNormalizeAndValidate(t *testing.T) {
	sc := &ConfigSchema{
		Fields: []FieldSchema{
			{Key: "enabled", Label: "Enable", Type: FieldBoolean, Default: true},
			{Key: "timeout", Label: "Timeout", Type: FieldNumber, Default: float64(10), Min: FloatPtr(1), Max: FloatPtr(60)},
			{
				Key:     "mode",
				Label:   "Mode",
				Type:    FieldSelect,
				Default: "fast",
				Options: []FieldOption{{Value: "fast", Label: "Fast"}, {Value: "deep", Label: "Deep"}},
			},
			{
				Key:       "rules",
				Label:     "Rules",
				Type:      FieldList,
				ItemLabel: "Rule",
				ItemFields: []FieldSchema{
					{Key: "name", Label: "Name", Type: FieldString, Required: true},
					{Key: "limit", Label: "Limit", Type: FieldNumber, Default: float64(5), Min: FloatPtr(1)},
				},
			},
		},
	}

	// Default filling
	norm, err := NormalizeAndValidate(sc, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ConfigBool(norm, "enabled", false) || ConfigInt(norm, "timeout", 0) != 10 || ConfigString(norm, "mode", "") != "fast" {
		t.Fatalf("defaults not populated cleanly: %#v", norm)
	}

	// Out-of-range number rejected
	if _, err := NormalizeAndValidate(sc, map[string]any{"timeout": 999}); err == nil {
		t.Fatalf("expected error for timeout > max")
	}

	// Invalid select option rejected
	if _, err := NormalizeAndValidate(sc, map[string]any{"mode": "invalid"}); err == nil {
		t.Fatalf("expected error for invalid select option")
	}

	// Nested list object normalization & required check
	norm2, err := NormalizeAndValidate(sc, map[string]any{
		"rules": []any{map[string]any{"name": "r1"}},
	})
	if err != nil {
		t.Fatalf("nested list failed: %v", err)
	}
	rows := ConfigListMaps(norm2, "rules")
	if len(rows) != 1 || ConfigInt(rows[0], "limit", 0) != 5 {
		t.Fatalf("nested default missing: %#v", rows)
	}
	if _, err := NormalizeAndValidate(sc, map[string]any{"rules": []any{map[string]any{"name": ""}}}); err == nil {
		t.Fatalf("expected error for empty required nested field")
	}
}

func TestEffectScopeAndDependencyCascade(t *testing.T) {
	dir := t.TempDir()
	k := New(HostServices{AppDir: dir, PluginsDir: filepath.Join(dir, "plugins"), SessionsRoot: filepath.Join(dir, "sessions")})

	disposedParent := false
	disposedChild := false

	k.RegisterBuiltin(&stubPlugin{
		meta: PluginMeta{ID: "parent", Name: "Parent", Version: "1.0", Builtin: true, Category: CatCollector, Provides: []string{"svc.core"}},
		apply: func(ctx *PluginContext, _ map[string]any) error {
			ctx.Provide("svc.core", "ready")
			ctx.RegisterExtension(ExtCollector, CollectorSpec{ID: "core", PluginID: "parent", Name: "Core"})
			ctx.OnDispose(func() { disposedParent = true })
			return nil
		},
	}, true)

	k.RegisterBuiltin(&stubPlugin{
		meta: PluginMeta{ID: "child", Name: "Child", Version: "1.0", Builtin: true, Category: CatCollector, Requires: []string{"svc.core"}},
		apply: func(ctx *PluginContext, _ map[string]any) error {
			ctx.RegisterExtension(ExtCaptureMode, CaptureModeSpec{ID: "m1", PluginID: "child", Mode: "oneshot", Name: "Oneshot"})
			ctx.OnDispose(func() { disposedChild = true })
			return nil
		},
	}, true)

	if err := k.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !k.IsPluginActive("parent") || !k.IsPluginActive("child") || len(k.CaptureModes()) != 1 {
		t.Fatalf("expected both parent and child active")
	}

	// Disabling parent must dispose parent AND cascade-deactivate child
	if err := k.SetEnabled("parent", false); err != nil {
		t.Fatalf("SetEnabled(false) failed: %v", err)
	}
	if !disposedParent || !disposedChild {
		t.Fatalf("effect scopes not disposed: parent=%v child=%v", disposedParent, disposedChild)
	}
	if k.IsPluginActive("child") || len(k.CaptureModes()) != 0 {
		t.Fatalf("child should be suspended when dependency disabled")
	}

	// Re-enabling parent must automatically reactivate child
	if err := k.SetEnabled("parent", true); err != nil {
		t.Fatalf("SetEnabled(true) failed: %v", err)
	}
	if !k.IsPluginActive("child") || len(k.CaptureModes()) != 1 {
		t.Fatalf("child should auto-reactivate when dependency restored")
	}
}

func TestConfigPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	mk := func() *Kernel {
		k := New(HostServices{AppDir: dir, PluginsDir: filepath.Join(dir, "plugins"), SessionsRoot: filepath.Join(dir, "sessions")})
		k.RegisterBuiltin(&stubPlugin{
			meta: PluginMeta{ID: "demo.theme", Name: "Theme", Version: "1.0", Builtin: true, Category: CatUI},
			schema: &ConfigSchema{
				Fields: []FieldSchema{{Key: "accent", Label: "Accent", Type: FieldString, Default: "blue"}},
			},
			apply: func(ctx *PluginContext, cfg map[string]any) error {
				ctx.RegisterExtension(ExtTheme, ThemeSpec{PluginID: "demo.theme", Accent: ConfigString(cfg, "accent", "blue")})
				return nil
			},
		}, true)
		return k
	}

	k1 := mk()
	_ = k1.Start()
	if _, err := k1.SetConfig("demo.theme", map[string]any{"accent": "emerald"}); err != nil {
		t.Fatalf("SetConfig failed: %v", err)
	}
	k1.Shutdown()

	k2 := mk()
	_ = k2.Start()
	defer k2.Shutdown()
	if th := k2.Theme(); th == nil || th.Accent != "emerald" {
		t.Fatalf("persisted config not restored: %#v", th)
	}
}

func TestExternalZipBundleLifecycleAndSecurity(t *testing.T) {
	dir := t.TempDir()
	k := New(HostServices{AppDir: dir, PluginsDir: filepath.Join(dir, "plugins"), SessionsRoot: filepath.Join(dir, "sessions")})
	_ = k.Start()
	defer k.Shutdown()

	// 1. ZipSlip archive must be rejected
	evilZip := filepath.Join(dir, "evil.pktplugin")
	func() {
		f, _ := os.Create(evilZip)
		defer f.Close()
		zw := zip.NewWriter(f)
		w1, _ := zw.Create("manifest.json")
		_, _ = w1.Write([]byte(`{"id":"evil","name":"Evil","sock_fields":[{"struct":"sock","field":"sk_mark","size":4}]}`))
		w2, _ := zw.Create("../escape.txt")
		_, _ = w2.Write([]byte("pwn"))
		_ = zw.Close()
	}()
	if _, err := k.InstallExternal(evilZip, nil, ""); err == nil {
		t.Fatalf("expected ZipSlip archive to fail installation")
	}

	// 2. Valid external bundle with kernel_extensions + UI slot
	goodZip := filepath.Join(dir, "good.pktplugin")
	func() {
		f, _ := os.Create(goodZip)
		defer f.Close()
		zw := zip.NewWriter(f)
		w1, _ := zw.Create("manifest.json")
		_, _ = w1.Write([]byte(`{
			"id": "test.ext",
			"name": "Test Ext",
			"version": "1.0.0",
			"kernel_extensions": {
				"sock_fields": [{"struct": "sock", "field": "sk_mark", "size": 4, "role": "tag", "label": "mark"}],
				"qdiscs": [{"id": "q1", "name": "Netem", "kind": "netem", "mode": "leaf", "enqueue_sym": "netem_enqueue", "dequeue_sym": "netem_dequeue"}]
			},
			"ui_slots": [{"id": "test.ext.slot", "slot": "canvas.banner", "title": "Banner", "script": "ui/w.js"}]
		}`))
		w2, _ := zw.Create("ui/w.js")
		_, _ = w2.Write([]byte("console.log('ok');"))
		_ = zw.Close()
	}()

	pv := k.PreviewExternal(goodZip, nil, "")
	if !pv.OK || pv.ID != "test.ext" || len(pv.SockFields) != 1 || len(pv.Qdiscs) != 1 || pv.UISlotCnt != 1 {
		t.Fatalf("unexpected preview: %#v", pv)
	}

	meta, err := k.InstallExternal(goodZip, nil, "")
	if err != nil || meta.ID != "test.ext" {
		t.Fatalf("install failed: meta=%#v err=%v", meta, err)
	}
	files, err := k.MaterializeKernelPluginFiles()
	if err != nil || len(files) != 1 {
		t.Fatalf("expected 1 materialized kernel ext file, got %v err=%v", files, err)
	}

	// Asset resolution works inside bundle and blocks traversal
	if _, err := k.ResolvePluginAsset("test.ext", "ui/w.js"); err != nil {
		t.Fatalf("valid asset failed: %v", err)
	}
	if _, err := k.ResolvePluginAsset("test.ext", "../../outside.txt"); err == nil {
		t.Fatalf("expected path traversal rejection")
	}

	// Uninstall cleans extensions & bundle dir
	if err := k.UninstallExternal("test.ext"); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}
	if len(k.UISlots()) != 0 || len(k.CollectKernelExtensions()) != 0 {
		t.Fatalf("extensions remained after uninstall")
	}
	if _, err := k.RunExporter(context.Background(), "nonexistent", &ExportInput{}); err == nil {
		t.Fatalf("expected error on missing exporter")
	}
}
