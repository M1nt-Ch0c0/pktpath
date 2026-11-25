//go:build collector_inputs

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"pktpath/studio/pkg/adb"
	"testing"
)

// Real local ELF inputs only; no Probe, Prepare, EnsureAgent, transport or
// collector execution. This checks the actual deployment selector's map.
func TestExplicitCollectorTransportRoutesWithoutDevice(t *testing.T) {
	root := os.Getenv("PKTPATH_COLLECTOR_TEST_INPUTS")
	if root == "" {
		t.Fatal("controlled collector inputs required")
	}
	dir := t.TempDir()
	m := adb.CollectorManifest{SchemaVersion: 1, SourceCommit: "0a26519323e095ba804f54494c55f20aeea9a7c2", Collectors: map[string]adb.CollectorFile{}}
	for target, name := range map[string]string{"linux-x86_64": adb.FileAgentLinuxX64, "android-arm64": adb.FileAgent} {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0755); e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(b)
		m.Collectors[target] = adb.CollectorFile{File: name, SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))}
	}
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "collectors.json")
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	rt, e := adb.LoadCollectorRuntime(p)
	if e != nil {
		t.Fatal(e)
	}
	s := New(Options{AppDir: t.TempDir(), Runtime: rt})
	for _, arch := range []string{"x86_64", "amd64", " AMD64 "} {
		got, key := s.pickLinuxAgent(arch)
		if key != "linux-x86_64" || got.Path != filepath.Join(dir, adb.FileAgentLinuxX64) {
			t.Fatalf("SSH target route %q: %q %+v", arch, key, got)
		}
	}
	for _, arch := range []string{"aarch64", "arm64", "riscv64", ""} {
		got, key := s.pickLinuxAgent(arch)
		if got.Path != "" || key != "" {
			t.Fatalf("unprovided target %q selected %+v", arch, got)
		}
	}
	// Existing ADB Prepare passes these exact legacy Runtime fields to EnsureAgent.
	if s.opts.Runtime.AgentPath != filepath.Join(dir, adb.FileAgent) || s.opts.Runtime.AgentSHA256 != m.Collectors["android-arm64"].SHA256 {
		t.Fatal("ADB must use Android payload, never host Linux x86_64")
	}
	if s.cap != nil {
		t.Fatal("selector test must not create capture")
	}
}
