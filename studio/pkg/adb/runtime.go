package adb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Embedded runtime file names (as staged by scripts/build_studio.py into
// studio/assets_stage/).
const (
	FileAdb           = "adb.exe"
	FileAdbWinApi     = "AdbWinApi.dll"
	FileAdbWinUsb     = "AdbWinUsbApi.dll"
	FileAgent         = "pktpath-android-arm64"
	FileAgentLinuxX64 = "pktpath-linux-x86_64"
	FileAgentLinuxArm = "pktpath-linux-arm64"
	FileManifest      = "manifest.json"
	stampName         = ".extracted.json"
)

// RuntimeFiles lists embedded collector binaries staged by build_studio.py.
// Note: adb.exe is NOT embedded; system adb/ssh are discovered and invoked
// strictly with HideWindow + CREATE_NO_WINDOW (zero console window flash).
var RuntimeFiles = []string{FileAgent, FileAgentLinuxX64, FileAgentLinuxArm}

// AgentBinary describes one extracted target collector binary.
type AgentBinary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// AssetEntry describes one staged binary (written by build_studio.py).
type AssetEntry struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// AssetManifest is assets_stage/manifest.json.
type AssetManifest struct {
	BuiltAt string                `json:"built_at,omitempty"`
	Files   map[string]AssetEntry `json:"files"`
}

type stampEntry struct {
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	ModNano int64  `json:"mod_nano"`
}

// Runtime is the resolved local toolchain (system adb/ssh + multi-arch collectors).
type Runtime struct {
	Dir         string                 `json:"dir"`
	AdbPath     string                 `json:"adb_path"`
	AgentPath   string                 `json:"agent_path"`
	AgentSHA256 string                 `json:"agent_sha256"`
	AgentSize   int64                  `json:"agent_size"`
	Agents      map[string]AgentBinary `json:"agents,omitempty"`
	AdbEmbedded bool                   `json:"adb_embedded"`
	Extracted   []string               `json:"extracted"` // files (re)written during this startup
	ExtractMs   float64                `json:"extract_ms"`
	Notes       []string               `json:"notes,omitempty"`
}

// DefaultAppDir returns %LOCALAPPDATA%\PktPathStudio (or a sane fallback).
func DefaultAppDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		if d, err := os.UserCacheDir(); err == nil {
			base = d
		} else {
			base = os.TempDir()
		}
	}
	return filepath.Join(base, "PktPathStudio")
}

// ExtractRuntime materialises the embedded adb.exe + DLLs + Android agent into
// dir. assets must be rooted at assets_stage (may be nil or partially empty in
// dev builds, in which case system adb / on-disk agent are used as fallback).
//
// Fast path: a stamp file records size/sha/mtime of what was written last time;
// if all files still match (os.Stat only) nothing is hashed or written (<5 ms).
func ExtractRuntime(assets fs.FS, dir string) (*Runtime, error) {
	t0 := time.Now()
	rt := &Runtime{Dir: dir}
	defer func() { rt.ExtractMs = float64(time.Since(t0).Microseconds()) / 1000.0 }()

	man := loadAssetManifest(assets)
	have := map[string]bool{}
	for _, name := range RuntimeFiles {
		if _, ok := man.Files[name]; ok {
			have[name] = true
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return rt, fmt.Errorf("create runtime dir: %w", err)
	}

	adbSet := []string{FileAdb, FileAdbWinApi, FileAdbWinUsb}
	adbEmbedded := have[FileAdb] && have[FileAdbWinApi] && have[FileAdbWinUsb]

	if adbEmbedded {
		target := dir
		written, err := extractSet(assets, man, target, adbSet)
		if errors.Is(err, errLocked) {
			// A *different* adb.exe from an older Studio build is running out of
			// our runtime dir. Ask it to stop, then retry once; if still locked,
			// extract into a versioned side directory (DLLs must sit next to adb).
			_ = killServer(filepath.Join(dir, FileAdb))
			time.Sleep(400 * time.Millisecond)
			written, err = extractSet(assets, man, target, adbSet)
			if errors.Is(err, errLocked) {
				short := man.Files[FileAdb].SHA256
				if len(short) > 12 {
					short = short[:12]
				}
				target = filepath.Join(dir, "adb-"+short)
				rt.Notes = append(rt.Notes, "runtime adb.exe locked by running process; using "+target)
				written, err = extractSet(assets, man, target, adbSet)
			}
		}
		if err != nil {
			return rt, err
		}
		rt.Extracted = append(rt.Extracted, written...)
		rt.AdbPath = filepath.Join(target, FileAdb)
		rt.AdbEmbedded = true
	} else {
		p := findSystemAdb()
		if p == "" {
			rt.Notes = append(rt.Notes, "no embedded adb.exe and no system adb found")
		} else {
			rt.Notes = append(rt.Notes, "using system adb: "+p)
		}
		rt.AdbPath = p
	}

	rt.Agents = map[string]AgentBinary{}
	agentSpecs := []struct {
		key  string
		file string
	}{
		{"android-arm64", FileAgent},
		{"linux-x86_64", FileAgentLinuxX64},
		{"linux-arm64", FileAgentLinuxArm},
	}
	for _, spec := range agentSpecs {
		if have[spec.file] {
			written, err := extractSet(assets, man, dir, []string{spec.file})
			if err != nil {
				return rt, err
			}
			rt.Extracted = append(rt.Extracted, written...)
			ab := AgentBinary{
				Path:   filepath.Join(dir, spec.file),
				SHA256: man.Files[spec.file].SHA256,
				Size:   man.Files[spec.file].Size,
			}
			rt.Agents[spec.key] = ab
		} else if p := findDiskAgentFile(spec.file); p != "" {
			if sum, size, err := fileSHA256(p); err == nil {
				rt.Agents[spec.key] = AgentBinary{Path: p, SHA256: sum, Size: size}
				rt.Notes = append(rt.Notes, fmt.Sprintf("using on-disk %s: %s", spec.key, p))
			}
		}
	}
	if ab, ok := rt.Agents["android-arm64"]; ok {
		rt.AgentPath, rt.AgentSHA256, rt.AgentSize = ab.Path, ab.SHA256, ab.Size
	} else {
		rt.Notes = append(rt.Notes, "no embedded pktpath-android-arm64 agent found")
	}
	return rt, nil
}

var errLocked = errors.New("runtime file locked")

func loadAssetManifest(assets fs.FS) AssetManifest {
	man := AssetManifest{Files: map[string]AssetEntry{}}
	if assets == nil {
		return man
	}
	if b, err := fs.ReadFile(assets, FileManifest); err == nil {
		_ = json.Unmarshal(b, &man)
		if man.Files == nil {
			man.Files = map[string]AssetEntry{}
		}
	}
	// Slow path for builds without a manifest: hash embedded files directly.
	for _, name := range RuntimeFiles {
		if _, ok := man.Files[name]; ok {
			continue
		}
		b, err := fs.ReadFile(assets, name)
		if err != nil || len(b) == 0 {
			continue
		}
		s := sha256.Sum256(b)
		man.Files[name] = AssetEntry{Size: int64(len(b)), SHA256: hex.EncodeToString(s[:])}
	}
	// Drop manifest entries whose blob is not actually embedded.
	for name := range man.Files {
		if f, err := assets.Open(name); err != nil {
			delete(man.Files, name)
		} else {
			f.Close()
		}
	}
	return man
}

func readStamp(dir string) map[string]stampEntry {
	m := map[string]stampEntry{}
	if b, err := os.ReadFile(filepath.Join(dir, stampName)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeStamp(dir string, m map[string]stampEntry) {
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := filepath.Join(dir, fmt.Sprintf("%s.%d.tmp", stampName, os.Getpid()))
	if os.WriteFile(tmp, b, 0o644) == nil {
		if os.Rename(tmp, filepath.Join(dir, stampName)) != nil {
			os.Remove(tmp)
		}
	}
}

// extractSet ensures every file in names exists in dir with the expected hash.
func extractSet(assets fs.FS, man AssetManifest, dir string, names []string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	stamp := readStamp(dir)
	var written []string
	changed := false
	for _, name := range names {
		want := man.Files[name]
		dst := filepath.Join(dir, name)
		st, statErr := os.Stat(dst)
		if statErr == nil && st.Size() == want.Size {
			if se, ok := stamp[name]; ok && se.SHA256 == want.SHA256 && se.Size == want.Size && se.ModNano == st.ModTime().UnixNano() {
				continue // fast path
			}
			if sum, _, err := fileSHA256(dst); err == nil && sum == want.SHA256 {
				stamp[name] = stampEntry{Size: want.Size, SHA256: want.SHA256, ModNano: st.ModTime().UnixNano()}
				changed = true
				continue
			}
		}
		data, err := fs.ReadFile(assets, name)
		if err != nil {
			return written, fmt.Errorf("read embedded %s: %w", name, err)
		}
		tmp := filepath.Join(dir, fmt.Sprintf(".%s.%d.tmp", name, os.Getpid()))
		if err := os.WriteFile(tmp, data, 0o755); err != nil {
			return written, fmt.Errorf("write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			if statErr == nil {
				return written, fmt.Errorf("%w: %s: %v", errLocked, dst, err)
			}
			return written, fmt.Errorf("install %s: %w", dst, err)
		}
		if st2, err := os.Stat(dst); err == nil {
			stamp[name] = stampEntry{Size: want.Size, SHA256: want.SHA256, ModNano: st2.ModTime().UnixNano()}
			changed = true
		}
		written = append(written, name)
	}
	if changed {
		writeStamp(dir, stamp)
	}
	return written, nil
}

func fileSHA256(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func killServer(adbPath string) error {
	if _, err := os.Stat(adbPath); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := HideConsole(exec.CommandContext(ctx, adbPath, "kill-server"))
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

func findSystemAdb() string {
	name := "adb"
	if runtime.GOOS == "windows" {
		name = "adb.exe"
	}
	if env := strings.TrimSpace(os.Getenv("PKTPATH_ADB")); env != "" {
		if st, err := os.Stat(env); err == nil && !st.IsDir() {
			return env
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	cands := []string{}
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(exe), name))
	}
	for _, env := range []string{"ANDROID_SDK_ROOT", "ANDROID_HOME"} {
		if v := os.Getenv(env); v != "" {
			cands = append(cands, filepath.Join(v, "platform-tools", name))
		}
	}
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			cands = append(cands, filepath.Join(la, "Android", "Sdk", "platform-tools", name))
		}
		cands = append(cands, `C:\platform-tools\adb.exe`)
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func findDiskAgentFile(fileName string) string {
	if fileName == FileAgent {
		if v := os.Getenv("PKTPATH_AGENT"); v != "" {
			if st, err := os.Stat(v); err == nil && !st.IsDir() {
				return v
			}
		}
	}
	var roots []string
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		roots = append(roots, wd)
	}
	for _, r := range roots {
		for _, rel := range []string{fileName, filepath.Join("bin", fileName), filepath.Join("..", "bin", fileName), filepath.Join("..", "..", "bin", fileName)} {
			p := filepath.Join(r, rel)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
				return p
			}
		}
	}
	return ""
}

// ShortSHA returns the first n hex chars of a digest for display.
func ShortSHA(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
