package kernel

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type duplicateConfigCase struct{ name, raw string }

func duplicateManagedImages() []duplicateConfigCase {
	return []duplicateConfigCase{
		{"root-hidden-unknown", `{"version":2,"plugins":{"txn":{"config":{"mode":"hidden-A","future":7}}},"plugins":{}}`},
		{"config-hidden-unknown", `{"version":2,"plugins":{"txn":{"config":{"mode":"hidden-A","future":7},"config":{}}}}`},
		{"root-hidden-schema", `{"version":2,"plugins":{"txn":{"schemaVersion":99,"config":{"mode":"hidden-A"}}},"plugins":{}}`},
		{"config-hidden-bad-type", `{"version":2,"plugins":{"txn":{"config":{"mode":"hidden-A","amount":"not-a-number"},"config":{}}}}`},
		{"escaped-root", `{"version":2,"plu\u0067ins":{"txn":{"config":{"future":7}}},"plugins":{}}`},
		{"escaped-config", `{"version":2,"plugins":{"txn":{"con\u0066ig":{"future":7},"config":{}}}}`},
		{"nested-list-hidden", `{"version":2,"plugins":{"txn":{"config":{"items":[{"known":"x","future":7}]},"config":{}}}}`},
		{"root-three-occurrences", `{"version":2,"plugins":{},"plugins":{"txn":{"config":{"future":7}}},"plugins":{}}`},
		{"reverse-root", `{"version":2,"plugins":{},"plugins":{"txn":{"config":{"future":7}}}}`},
		{"reverse-config", `{"version":2,"plugins":{"txn":{"config":{},"config":{"amount":"not-a-number"}}}}`},
		{"root-ending-unmanaged", `{"version":2,"plugins":{"txn":{"config":{"future":7}}},"plugins":{"custom":{"config":{}}}}`},
		{"casefold-in-hidden-entry", `{"version":2,"plugins":{"txn":{"Config":{"future":7}}},"plugins":{}}`},
		{"casefold-config-combination", `{"version":2,"plugins":{"txn":{"Config":{"future":7},"config":{}}}}`},
		{"unicode-root-alias-combination", `{"version":2,"plugin\u017f":{"txn":{"config":{"future":7}}},"plugins":{}}`},
		{"null-between-roots", `{"version":2,"plugins":{"txn":{"config":{"future":7}}},"plugins":null,"plugins":{}}`},
		{"identical-valid-protected-root", `{"version":2,"plugins":{"txn":{"config":{"mode":"A"}}},"plugins":{"txn":{"config":{"mode":"A"}}}}`},
		{"identical-valid-protected-config", `{"version":2,"plugins":{"txn":{"config":{"mode":"A"},"config":{"mode":"A"}}}}`},
		{"null-config-then-object", `{"version":2,"plugins":{"txn":{"config":null,"config":{"mode":"A"}}}}`},
	}
}

func TestCordisF031AV2ProtectedDuplicateStartupZeroEffects(t *testing.T) {
	for _, tc := range duplicateManagedImages() {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			marker := filepath.Join(d, "node-was-executed")
			node := filepath.Join(d, "node-sentinel")
			if e := os.WriteFile(node, []byte("#!/bin/sh\nprintf started > '"+marker+"'\nexit 99\n"), 0700); e != nil {
				t.Fatal(e)
			}
			var calls atomic.Int32
			k, h, path := compatKernel(t, tc.raw, true, CordisLifecycleOptions{NodePath: node, HostPath: "must-not-load.mjs", ConfigTransactions: true}, &calls)
			err := k.Start()
			v := h.Snapshot().ConfigCompatibility
			if err == nil || v == nil || !v.Blocked || !strings.Contains(err.Error(), "incompatible-config") {
				t.Fatalf("not rejected before host: err=%v view=%+v", err, v)
			}
			if calls.Load() != 0 || h.worker != nil || k.IsPluginActive("txn") || len(h.Snapshot().ConfigOperations) != 0 {
				t.Fatal("startup activated/created operation")
			}
			if _, e := os.Stat(marker); !os.IsNotExist(e) {
				t.Fatal("Node was executed on rejected image")
			}
			for _, action := range []func() error{
				func() error { return k.SetEnabled("txn", false) },
				func() error { _, e := k.SetConfig("txn", map[string]any{"mode": "B"}); return e },
				func() error { _, e := k.ResetConfig("txn"); return e },
				func() error { return k.Reload("txn") }, k.savePersistedConfig,
			} {
				if e := action(); e == nil {
					t.Fatal("control/writer cleared startup quarantine")
				}
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, []byte(tc.raw)) {
				t.Fatal("original rejected bytes changed")
			}
		})
	}
}

func TestCordisF031AV2DuplicateRuntimeAllAdmissions(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Fatal("actual host required")
	}
	// Each operation independently encounters a newly bad image, not an already
	// latched quarantine. configure bypasses the public check after a good check.
	for _, tc := range duplicateManagedImages()[:8] {
		for _, entry := range []string{"disable", "enable", "SetConfig", "Reset", "Reload", "writer", "captured-configure"} {
			t.Run(tc.name+"/"+entry, func(t *testing.T) {
				var calls atomic.Int32
				k, h, path := compatKernel(t, `{"version":2,"plugins":{"txn":{"config":{"mode":"user-A"}}}}`, true, CordisLifecycleOptions{HostPath: host, ConfigTransactions: true}, &calls)
				if e := k.Start(); e != nil {
					t.Fatal(e)
				}
				waitLifecycle(t, h, "txn")
				gen := generationOf(h, "txn")
				h.mu.Lock()
				worker := h.worker
				h.mu.Unlock()
				if e := k.checkConfigCompatibility("v2-good-public-before-swap"); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, []byte(tc.raw), 0600); e != nil {
					t.Fatal(e)
				}
				var err error
				switch entry {
				case "disable":
					err = k.SetEnabled("txn", false)
				case "enable":
					err = k.SetEnabled("txn", true)
				case "SetConfig":
					_, err = k.SetConfig("txn", map[string]any{"mode": "B"})
				case "Reset":
					_, err = k.ResetConfig("txn")
				case "Reload":
					err = k.Reload("txn")
				case "writer":
					err = k.savePersistedConfig()
				case "captured-configure":
					err = h.configure(context.Background(), "txn", map[string]any{"mode": "B"})
				}
				v := h.Snapshot().ConfigCompatibility
				if err == nil || !strings.Contains(err.Error(), "incompatible-config") || v == nil || !v.Blocked {
					t.Fatalf("runtime admission bypassed %s: err=%v view=%+v", entry, err, v)
				}
				actual, live := k.Service("compat.svc")
				h.mu.Lock()
				sameWorker := h.worker == worker
				h.mu.Unlock()
				if !live || actual != "user-A" || !sameWorker || calls.Load() != 1 || generationOf(h, "txn") != gen || len(h.Snapshot().ConfigOperations) != 0 {
					t.Fatalf("rejected image changed active A: actual=%v live=%v apply=%d", actual, live, calls.Load())
				}
				after, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(after, []byte(tc.raw)) {
					t.Fatal("runtime rejection overwrote original bytes")
				}
			})
		}
	}
}

func TestCordisF031AV2LegalDuplicatesAndOpaqueNotGlobalBan(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Fatal("actual host required")
	}
	for _, tc := range []struct{ name, raw, want string }{
		{"opaque-root-and-deep", `{"version":2,"opaque":{"plugins":{"x":1},"plugins":{},"config":{"amount":"bad"},"config":{}},"opaque":{"nested":[{"config":1,"config":2}]},"plugins":{"txn":{"config":{"mode":"opaque-A"}}}}`, "opaque-A"},
		{"opaque-entry", `{"version":2,"plugins":{"txn":{"opaque":{"config":{"future":1},"config":{}},"opaque":{"plugins":1,"plugins":2},"config":{"mode":"entry-A"}}}}`, "entry-A"},
		{"ordinary-config-scalar-last-value", `{"version":2,"plugins":{"txn":{"config":{"mode":"early","mode":"last-A","amount":4,"amount":5}}}}`, "last-A"},
		{"nested-list-item-last-value", `{"version":2,"plugins":{"txn":{"config":{"mode":"nested-A","items":[{"known":"early","known":"late"}]}}}}`, "nested-A"},
		{"plugin-map-id-replacement", `{"version":2,"plugins":{"txn":{"schemaVersion":99,"config":{"mode":"discarded","future":7}},"t\u0078n":{"config":{"mode":"replacement-A"}}}}`, "replacement-A"},
		{"unmanaged-config-repeat", `{"version":2,"plugins":{"txn":{"config":{"mode":"managed-A"}},"custom":{"schemaVersion":99,"config":{"future":1},"config":{"opaque":2}}}}`, "managed-A"},
		{"root-repeat-no-managed-entry", `{"version":2,"plugins":{"custom":{"schemaVersion":99,"config":{"future":1}}},"plugins":{"other":{"config":{}}}}`, "default"},
		{"scalar-version-repeat", `{"version":2,"version":2,"plugins":{"txn":{"config":{"mode":"version-A"}}}}`, "version-A"},
		{"scalar-enabled-repeat", `{"version":2,"plugins":{"txn":{"enabled":false,"enabled":true,"config":{"mode":"enabled-A"}}}}`, "enabled-A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			k, h, path := compatKernel(t, tc.raw, true, CordisLifecycleOptions{HostPath: host, ConfigTransactions: true}, &calls)
			if e := k.Start(); e != nil {
				t.Fatalf("legal/opaque over-rejected: %v", e)
			}
			waitLifecycle(t, h, "txn")
			actual, live := k.Service("compat.svc")
			if !live || actual != tc.want || calls.Load() != 1 {
				t.Fatalf("validation-consumption diverged: got=%v want=%v live=%v apply=%d", actual, tc.want, live, calls.Load())
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, []byte(tc.raw)) {
				t.Fatal("startup changed valid original bytes")
			}
			if tc.name == "nested-list-item-last-value" {
				items := k.PluginConfig("txn")["items"].([]any)
				if items[0].(map[string]any)["known"] != "late" {
					t.Fatal("nested last-value consumer changed")
				}
			}
			if tc.name == "plugin-map-id-replacement" && k.PluginConfig("txn")["amount"] != float64(1) {
				t.Fatal("map-value replacement unexpectedly merged prior entry")
			}
			if _, e := k.SetConfig("txn", map[string]any{"mode": "new-B"}); e != nil {
				t.Fatalf("valid transaction rejected: %v", e)
			}
			if actual, live = k.Service("compat.svc"); !live || actual != "new-B" {
				t.Fatal("valid transaction not actually live")
			}
		})
	}
}
