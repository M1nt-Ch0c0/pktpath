package kernel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type cordisDiskImage struct {
	bytes  []byte
	exists bool
	mode   os.FileMode
}

// Local fault seams only, not supplied by plugins or decoded from configuration.
// Real temporary files are always used, including under injected short writes.
type cordisConfigIO struct {
	write   func(*os.File, []byte, string) (int, error)
	sync    func(*os.File, string) error
	rename  func(string, string, string) error
	syncDir func(string, string) error
}

func readCordisDisk(path string) (cordisDiskImage, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return cordisDiskImage{mode: 0600}, nil
	}
	if err != nil {
		return cordisDiskImage{}, err
	}
	if !info.Mode().IsRegular() {
		return cordisDiskImage{}, errors.New("F03 requires a regular non-symlink config file")
	}
	b, err := os.ReadFile(path)
	return cordisDiskImage{b, true, info.Mode().Perm()}, err
}
func diskImageHash(d cordisDiskImage) string {
	if !d.exists {
		return "absent"
	}
	s := sha256.Sum256(d.bytes)
	return hex.EncodeToString(s[:])
}
func sameDiskImage(a, b cordisDiskImage) bool {
	return a.exists == b.exists && bytes.Equal(a.bytes, b.bytes)
}

// Modify just one entry, retaining raw unknown envelope/other-plugin fields.
// It is NOT schema migration. Exact pre-operation bytes are retained separately.
func cordisConfigDocument(old cordisDiskImage, id string, cfg map[string]any) ([]byte, error) {
	doc := map[string]json.RawMessage{}
	if old.exists {
		if err := json.Unmarshal(old.bytes, &doc); err != nil || doc == nil {
			return nil, errors.New("invalid Studio config envelope")
		}
	}
	if v, ok := doc["version"]; ok {
		var version int
		if json.Unmarshal(v, &version) != nil || version != 2 {
			return nil, errors.New("unsupported Studio config version; migration not implemented")
		}
	}
	doc["version"] = json.RawMessage("2")
	plugins := map[string]json.RawMessage{}
	if raw, ok := doc["plugins"]; ok {
		if err := json.Unmarshal(raw, &plugins); err != nil || plugins == nil {
			return nil, errors.New("invalid Studio plugins envelope")
		}
	}
	entry := map[string]json.RawMessage{}
	if raw, ok := plugins[id]; ok {
		if err := json.Unmarshal(raw, &entry); err != nil || entry == nil {
			return nil, errors.New("invalid Studio plugin entry")
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	entry["config"] = raw
	entry["enabled"] = json.RawMessage("true")
	plugins[id], err = json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	doc["plugins"], err = json.Marshal(plugins)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}
func (h *CordisLifecycleHost) writeConfigImage(d cordisDiskImage, phase string) error {
	path := h.kernel.configPath
	if !d.exists {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pktpath-config-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err = f.Chmod(d.mode); err != nil {
		return err
	}
	n := 0
	if h.configIO != nil && h.configIO.write != nil {
		n, err = h.configIO.write(f, d.bytes, phase)
	} else {
		n, err = f.Write(d.bytes)
	}
	if err != nil {
		return fmt.Errorf("%s write: %w", phase, err)
	}
	if n != len(d.bytes) {
		return fmt.Errorf("%s write: %w", phase, io.ErrShortWrite)
	}
	if h.configIO != nil && h.configIO.sync != nil {
		err = h.configIO.sync(f, phase)
	} else {
		err = f.Sync()
	}
	if err != nil {
		return fmt.Errorf("%s sync: %w", phase, err)
	}
	if err = f.Close(); err != nil {
		return err
	}
	if h.configIO != nil && h.configIO.rename != nil {
		err = h.configIO.rename(name, path, phase)
	} else {
		err = os.Rename(name, path)
	}
	if err != nil {
		return fmt.Errorf("%s rename (outcome must be observed): %w", phase, err)
	}
	if h.configIO != nil && h.configIO.syncDir != nil {
		return h.configIO.syncDir(filepath.Dir(path), phase)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
