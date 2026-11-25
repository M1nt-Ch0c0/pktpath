//go:build collector_inputs

package adb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Controlled real build inputs, read/copied only. Tests never execute either ELF.
func collectorFixture(t *testing.T) (string, CollectorManifest) {
	t.Helper()
	root := os.Getenv("PKTPATH_COLLECTOR_TEST_INPUTS")
	if root == "" {
		t.Fatal("explicit real collector input directory required; no device substitutes")
	}
	dir := t.TempDir()
	m := CollectorManifest{SchemaVersion: 1, SourceCommit: "0a26519323e095ba804f54494c55f20aeea9a7c2", Collectors: map[string]CollectorFile{}}
	for target, name := range map[string]string{"linux-x86_64": FileAgentLinuxX64, "android-arm64": FileAgent} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err = os.WriteFile(p, b, 0755); err != nil {
			t.Fatal(err)
		}
		sum, n, err := fileSHA256(p)
		if err != nil {
			t.Fatal(err)
		}
		m.Collectors[target] = CollectorFile{File: name, SHA256: sum, Size: n}
	}
	return filepath.Join(dir, "manifest.json"), m
}
func writeCollectorManifest(t *testing.T, p string, m CollectorManifest) {
	t.Helper()
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestExplicitCollectorRuntimeRealTargetsNoExecution(t *testing.T) {
	p, m := collectorFixture(t)
	writeCollectorManifest(t, p, m)
	r, e := LoadCollectorRuntime(p)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Agents) != 2 || r.AgentPath != filepath.Join(filepath.Dir(p), FileAgent) || r.Agents["linux-x86_64"].Path != filepath.Join(filepath.Dir(p), FileAgentLinuxX64) {
		t.Fatalf("routes: %+v", r)
	}
	if r.AdbPath != "" || r.Agents["linux-arm64"].Path != "" {
		t.Fatal("must not discover adb or invent Linux arm64")
	}
}
func TestExplicitCollectorManifestRejectsMissingCorruptTargetAndFallback(t *testing.T) {
	for _, name := range []string{"missing-manifest", "missing-file", "size", "hash", "target", "filename", "swapped-ELF", "symlink", "relative", "trailing-json"} {
		t.Run(name, func(t *testing.T) {
			p, m := collectorFixture(t)
			w := m.Collectors["linux-x86_64"]
			switch name {
			case "missing-file":
				os.Remove(filepath.Join(filepath.Dir(p), w.File))
			case "size":
				w.Size++
				m.Collectors["linux-x86_64"] = w
			case "hash":
				w.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
				m.Collectors["linux-x86_64"] = w
			case "target":
				m.Collectors["linux-arm64"] = w
			case "filename":
				w.File = "../" + w.File
				m.Collectors["linux-x86_64"] = w
			case "swapped-ELF":
				b, e := os.ReadFile(filepath.Join(filepath.Dir(p), FileAgent))
				if e != nil {
					t.Fatal(e)
				}
				os.WriteFile(filepath.Join(filepath.Dir(p), w.File), b, 0755)
				w.SHA256, w.Size, _ = fileSHA256(filepath.Join(filepath.Dir(p), w.File))
				m.Collectors["linux-x86_64"] = w
			case "symlink":
				target := filepath.Join(filepath.Dir(p), w.File)
				os.Rename(target, target+".real")
				os.Symlink(target+".real", target)
			}
			writeCollectorManifest(t, p, m)
			if name == "missing-manifest" {
				os.Remove(p)
			}
			if name == "relative" {
				p = "manifest.json"
			}
			if name == "trailing-json" {
				f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
				f.WriteString(" {}")
				f.Close()
			}
			if _, e := LoadCollectorRuntime(p); e == nil {
				t.Fatal("must reject without fallback")
			}
		})
	}
}
