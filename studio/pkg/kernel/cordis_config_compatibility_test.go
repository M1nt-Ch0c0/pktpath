package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func compatSchema() *ConfigSchema {
	return &ConfigSchema{Fields: []FieldSchema{{Key: "mode", Type: FieldString, Default: "default"}, {Key: "amount", Type: FieldNumber, Default: 1}, {Key: "items", Type: FieldList, ItemFields: []FieldSchema{{Key: "known", Type: FieldString, Default: "ok"}}}}}
}
func compatKernel(t *testing.T, raw string, exists bool, options CordisLifecycleOptions, calls *atomic.Int32) (*Kernel, *CordisLifecycleHost, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plugins_config.json")
	if exists {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	options.PluginIDs = []string{"txn"}
	h := NewCordisLifecycleHost(options)
	k := New(HostServices{AppDir: dir, LifecycleHost: h})
	k.RegisterBuiltin(&stubPlugin{meta: PluginMeta{ID: "txn"}, schema: compatSchema(), apply: func(c *PluginContext, cfg map[string]any) error {
		calls.Add(1)
		c.Provide("compat.svc", ConfigString(cfg, "mode", ""))
		return nil
	}}, true)
	t.Cleanup(k.Shutdown)
	return k, h, path
}
func TestCordisF031AIncompatibleStartupNoApplyNoNode(t *testing.T) {
	cases := map[string]string{
		"alias-root-version":        `{"Version":99,"plugins":{}}`,
		"alias-root-plugins":        `{"version":2,"Plugins":{"txn":{"config":{"future":99}}}}`,
		"alias-entry-config":        `{"version":2,"plugins":{"txn":{"Config":{"mode":"user-A","future":99}}}}`,
		"future-file-version":       `{"version":99,"plugins":{"txn":{"config":{"mode":"user-A"}}}}`,
		"string-file-version":       `{"version":"2","plugins":{}}`,
		"plugin-schemaVersion-1":    `{"version":2,"plugins":{"txn":{"schemaVersion":1,"config":{"mode":"user-A"}}}}`,
		"plugin-schemaVersion-null": `{"version":2,"plugins":{"txn":{"schemaVersion":null}}}`,
		"unknown-field":             `{"version":2,"plugins":{"txn":{"config":{"mode":"user-A","future":99}}}}`,
		"unknown-nested-field":      `{"version":2,"plugins":{"txn":{"config":{"items":[{"known":"x","future":"y"}]}}}}`,
		"invalid-declared-type":     `{"version":2,"plugins":{"txn":{"config":{"amount":"not-a-number"}}}}`,
		"invalid-enabled":           `{"version":2,"plugins":{"txn":{"enabled":"true"}}}`,
		"config-array":              `{"version":2,"plugins":{"txn":{"config":[]}}}`,
		"null-entry":                `{"version":2,"plugins":{"txn":null}}`,
		"null-plugins":              `{"version":2,"plugins":null}`,
		"null-root":                 `null`,
		"bad-json":                  "{bad-json\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "node-started")
			node := filepath.Join(dir, "node-sentinel")
			script := "#!/bin/sh\nprintf started > '" + marker + "'\nexit 99\n"
			if err := os.WriteFile(node, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			k, h, path := compatKernel(t, raw, true, CordisLifecycleOptions{NodePath: node, HostPath: "not-loaded.mjs", ConfigTransactions: true}, &calls)
			if err := k.Start(); err == nil {
				t.Fatal("incompatible file silently defaulted/activated")
			}
			v := h.Snapshot().ConfigCompatibility
			if v == nil || !v.Blocked || v.State != "incompatible-config" || v.Source != "startup" || v.Reason == "" || v.ObservedAt == "" {
				t.Fatalf("no observable admission diagnosis: %+v", v)
			}
			for _, action := range []func() error{func() error { return k.SetEnabled("txn", true) }, func() error { _, e := k.SetConfig("txn", map[string]any{"mode": "C"}); return e }, func() error { _, e := k.ResetConfig("txn"); return e }, func() error { return k.Reload("txn") }, k.savePersistedConfig} {
				if e := action(); e == nil {
					t.Fatal("ordinary action cleared compatibility quarantine")
				}
			}
			if calls.Load() != 0 || h.worker != nil || len(h.Snapshot().ConfigOperations) != 0 || k.IsPluginActive("txn") {
				t.Fatal("blocked config still executed")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("Node executable was probed/started", err)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, []byte(raw)) {
				t.Fatal("incompatible source bytes modified")
			}
		})
	}
}
func TestCordisF031ACompatibleFormatsPositive(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Fatal("explicit controlled host")
	}
	for _, tc := range []struct {
		name, raw, want string
		exists          bool
	}{
		{"v2-user-A", `{"version":2,"opaque":{"preserve":true},"plugins":{"txn":{"opaqueEntry":7,"config":{"mode":"user-A"}}}}`, "user-A", true},
		{"missing-version-legacy", `{"plugins":{"txn":{"config":{"mode":"legacy-A"}}}}`, "legacy-A", true},
		{"missing-file", "", "default", false},
		{"null-config-enabled-legacy", `{"version":2,"plugins":{"txn":{"enabled":null,"config":null}}}`, "default", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			k, h, path := compatKernel(t, tc.raw, tc.exists, CordisLifecycleOptions{HostPath: host, ConfigTransactions: true}, &calls)
			if e := k.Start(); e != nil {
				t.Fatal(e)
			}
			waitLifecycle(t, h, "txn")
			if got, ok := k.Service("compat.svc"); !ok || got != tc.want || calls.Load() != 1 {
				t.Fatal("valid input over-rejected/default changed", got)
			}
			v := h.Snapshot().ConfigCompatibility
			if v == nil || v.Blocked || v.State != "compatible" {
				t.Fatalf("valid file marked blocked: %+v", v)
			}
			if tc.exists {
				after, _ := os.ReadFile(path)
				if string(after) != tc.raw {
					t.Fatal("startup rewrote valid source")
				}
			} else {
				if _, e := os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("missing file materialized at startup")
				}
			}
			if _, e := k.SetConfig("txn", map[string]any{"mode": "new-B"}); e != nil {
				t.Fatal(e)
			}
			if got, _ := k.Service("compat.svc"); got != "new-B" {
				t.Fatal("valid transaction stopped working")
			}
			for _, op := range h.Snapshot().ConfigOperations {
				if op.Phase != "committed" || !op.RunningLive {
					t.Fatalf("valid transaction fake success: %+v", op)
				}
			}
		})
	}
}
func TestCordisF031ARuntimeBadFileBlocksControlAndWriter(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Fatal("explicit controlled host")
	}
	for _, first := range []string{"control", "writer"} {
		t.Run(first, func(t *testing.T) {
			var calls atomic.Int32
			k, h, path := compatKernel(t, `{"version":2,"plugins":{"txn":{"config":{"mode":"user-A"}}}}`, true, CordisLifecycleOptions{HostPath: host, ConfigTransactions: true}, &calls)
			if e := k.Start(); e != nil {
				t.Fatal(e)
			}
			waitLifecycle(t, h, "txn")
			generation := generationOf(h, "txn")
			future := []byte("{ \"version\":99,\"plugins\":{\"txn\":{\"config\":{\"mode\":\"future-C\"}}}}\n")
			if e := os.WriteFile(path, future, 0600); e != nil {
				t.Fatal(e)
			}
			var e error
			if first == "control" {
				e = k.SetEnabled("txn", false)
			} else {
				e = k.savePersistedConfig()
			}
			if e == nil {
				t.Fatal("incompatible runtime source was overwritten")
			}
			if _, e = k.ResetConfig("txn"); e == nil {
				t.Fatal("Reset cleared quarantine")
			}
			if e = k.Reload("txn"); e == nil {
				t.Fatal("Reload cleared quarantine")
			}
			now, _ := os.ReadFile(path)
			if !bytes.Equal(now, future) || generationOf(h, "txn") != generation || calls.Load() != 1 {
				t.Fatal("rejection mutated bytes/generation")
			}
			if got, ok := k.Service("compat.svc"); !ok || got != "user-A" {
				t.Fatal("runtime guard unexpectedly claimed/stopped live A")
			}
			before := *h.Snapshot().ConfigCompatibility
			// Editing the file is not an implicit in-process reset of a latched guard.
			good := []byte(`{"version":2,"plugins":{}}`)
			os.WriteFile(path, good, 0600)
			if _, e = k.SetConfig("txn", map[string]any{"mode": "D"}); e == nil {
				t.Fatal("file edit silently unlatched quarantine")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, good) || h.Snapshot().ConfigCompatibility.LastObservedHash != before.LastObservedHash {
				t.Fatal("sticky diagnosis rewritten/false real-time disk claim")
			}
		})
	}
}
func TestCordisF031ALegacyDefaultAndF02RemainUnchanged(t *testing.T) {
	raw := `{"version":99,"plugins":{"txn":{"config":{"mode":"user-A","future":7}}}}`
	for _, mode := range []string{"old-Go", "F02-without-transaction-flag"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			var k *Kernel
			var h *CordisLifecycleHost
			if mode == "old-Go" {
				dir := t.TempDir()
				os.WriteFile(filepath.Join(dir, "plugins_config.json"), []byte(raw), 0600)
				k = New(HostServices{AppDir: dir})
				k.RegisterBuiltin(&stubPlugin{meta: PluginMeta{ID: "txn"}, schema: compatSchema(), apply: func(c *PluginContext, cfg map[string]any) error { calls.Add(1); return nil }}, true)
				t.Cleanup(k.Shutdown)
			} else {
				host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
				if host == "" {
					t.Fatal("explicit host")
				}
				k, h, _ = compatKernel(t, raw, true, CordisLifecycleOptions{HostPath: host}, &calls)
			}
			if e := k.Start(); e != nil {
				t.Fatal("default/F02 semantics unexpectedly changed", e)
			}
			if h != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if e := h.WaitActive(ctx, "txn"); e != nil {
					t.Fatal(e)
				}
				if h.Snapshot().ConfigCompatibility != nil {
					t.Fatal("flag-off still ran admission policy")
				}
			}
			if calls.Load() != 1 {
				t.Fatal("legacy behavior not retained")
			}
			b, _ := os.ReadFile(k.configPath)
			var doc map[string]json.RawMessage
			if json.Unmarshal(b, &doc) != nil || string(doc["version"]) != "99" {
				t.Fatal("legacy startup file changed")
			}
		})
	}
}
func TestCordisF031AExactTransactionImageAlsoValidated(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Fatal("explicit host")
	}
	var calls atomic.Int32
	k, h, path := compatKernel(t, `{"version":2,"plugins":{"txn":{"config":{"mode":"user-A"}}}}`, true, CordisLifecycleOptions{HostPath: host, ConfigTransactions: true}, &calls)
	if e := k.Start(); e != nil {
		t.Fatal(e)
	}
	waitLifecycle(t, h, "txn")
	gen := generationOf(h, "txn")
	future := []byte(`{"version":2,"plugins":{"txn":{"schemaVersion":1,"config":{"mode":"future-A"}}}}`)
	os.WriteFile(path, future, 0600)
	// Production configure is called directly here to bypass the PUBLIC early check;
	// its own captured image, not a separate earlier read, must still be validated.
	if e := h.configure(context.Background(), "txn", map[string]any{"mode": "B"}); e == nil {
		t.Fatal("transaction captured unsupported schemaVersion after public check")
	}
	b, _ := os.ReadFile(path)
	if !bytes.Equal(b, future) || generationOf(h, "txn") != gen || calls.Load() != 1 || len(h.Snapshot().ConfigOperations) != 0 {
		t.Fatal("exact image compatibility check followed side effects")
	}
	if v := h.Snapshot().ConfigCompatibility; v == nil || !v.Blocked || v.Source != "transaction-admission" {
		t.Fatalf("wrong admission diagnostic: %+v", v)
	}
}
