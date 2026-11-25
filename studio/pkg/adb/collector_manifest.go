package adb

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// CollectorManifest is explicit, local deployment input. It never discovers
// binaries in cwd, PATH, lin-ci, SDK directories or the host architecture.
type CollectorManifest struct {
	SchemaVersion int                      `json:"schema_version"`
	SourceCommit  string                   `json:"source_commit"`
	Collectors    map[string]CollectorFile `json:"collectors"`
}
type CollectorFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// LoadCollectorRuntime verifies bytes/ELF target, but does not execute a
// collector, discover adb/ssh, contact a device or claim deployment readiness.
// An empty CLI flag does not call this function and preserves the old runtime.
func LoadCollectorRuntime(manifestPath string) (*Runtime, error) {
	if !filepath.IsAbs(manifestPath) {
		return nil, fmt.Errorf("collector manifest must be an explicit absolute path")
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("collector manifest: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, fmt.Errorf("collector manifest must be a regular file at most 1 MiB")
	}
	var m CollectorManifest
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&m); err != nil {
		return nil, fmt.Errorf("collector manifest: %w", err)
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("collector manifest must contain one JSON object")
	}
	commit, err := hex.DecodeString(m.SourceCommit)
	if m.SchemaVersion != 1 || err != nil || len(commit) != 20 || len(m.Collectors) == 0 {
		return nil, fmt.Errorf("collector manifest: unsupported version, source commit or empty targets")
	}
	rt := &Runtime{Dir: filepath.Dir(manifestPath), Agents: map[string]AgentBinary{}, Notes: []string{"Explicit collector manifest verified at startup; path/bytes/ELF target only. No device preparation, upload, kernel load or capture was performed."}}
	for target, want := range m.Collectors {
		expected := ""
		var machine elf.Machine
		switch target {
		case "linux-x86_64":
			expected = FileAgentLinuxX64
			machine = elf.EM_X86_64
		case "android-arm64":
			expected = FileAgent
			machine = elf.EM_AARCH64
		default:
			return nil, fmt.Errorf("collector manifest: unsupported target %q (no fallback)", target)
		}
		if want.File != expected || want.Size <= 0 {
			return nil, fmt.Errorf("collector %s: expected file %s and positive size", target, expected)
		}
		digest, err := hex.DecodeString(want.SHA256)
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("collector %s: invalid SHA256", target)
		}
		path := filepath.Join(rt.Dir, want.File)
		st, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("collector %s: %w (explicit manifest only, no fallback)", target, err)
		}
		if !st.Mode().IsRegular() || st.Size() != want.Size {
			return nil, fmt.Errorf("collector %s: file type or size mismatch", target)
		}
		sum, _, err := fileSHA256(path)
		if err != nil {
			return nil, fmt.Errorf("collector %s: %w", target, err)
		}
		if sum != strings.ToLower(want.SHA256) {
			return nil, fmt.Errorf("collector %s: SHA256 mismatch (no fallback)", target)
		}
		ef, err := elf.Open(path)
		if err != nil {
			return nil, fmt.Errorf("collector %s: invalid ELF: %w", target, err)
		}
		valid := ef.Class == elf.ELFCLASS64 && ef.Data == elf.ELFDATA2LSB && ef.Machine == machine
		interp := ""
		for _, p := range ef.Progs {
			if p.Type == elf.PT_INTERP {
				b, e := io.ReadAll(io.LimitReader(p.Open(), 4096))
				if e != nil {
					ef.Close()
					return nil, e
				}
				interp = strings.TrimRight(string(b), "\x00")
			}
		}
		ef.Close()
		if !valid || (target == "android-arm64" && interp != "/system/bin/linker64") {
			return nil, fmt.Errorf("collector %s: ELF machine/class or Android interpreter mismatch", target)
		}
		ab := AgentBinary{Path: path, SHA256: sum, Size: want.Size}
		rt.Agents[target] = ab
		if target == "android-arm64" {
			rt.AgentPath, rt.AgentSHA256, rt.AgentSize = ab.Path, ab.SHA256, ab.Size
		}
	}
	return rt, nil
}
