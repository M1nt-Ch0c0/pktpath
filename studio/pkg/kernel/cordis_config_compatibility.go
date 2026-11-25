package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// This is format admission, NOT a migration, backup, journal or transaction
// recovery record. Version 2 is the existing Studio FILE format, not Cordis3.
// ConfigSchema has no version API, so no plugin schemaVersion value is invented.
type CordisConfigCompatibilityView struct {
	Scope            string `json:"scope"`
	State            string `json:"state"`
	Blocked          bool   `json:"blocked"`
	Source           string `json:"source"`
	ObservedAt       string `json:"observed_at"`
	FileVersion      string `json:"file_version"`
	LastObservedHash string `json:"last_observed_hash"`
	Reason           string `json:"reason,omitempty"`
}

func (k *Kernel) checkConfigCompatibility(source string) error {
	h := k.host.LifecycleHost
	if h == nil || !h.opts.ConfigTransactions {
		return nil
	}
	k.persistMu.Lock()
	defer k.persistMu.Unlock()
	return k.checkConfigCompatibilityLocked(source)
}

// persistMu must be held. No owner lock while reading or validating the file.
// The sticky quarantine never auto-clears through Reset or a newer disk file.
func (k *Kernel) checkConfigCompatibilityLocked(source string) error {
	h := k.host.LifecycleHost
	if h == nil || !h.opts.ConfigTransactions {
		return nil
	}
	h.mu.Lock()
	if v := h.configCompatibility; v != nil && v.Blocked {
		err := fmt.Errorf("incompatible-config: %s", v.Reason)
		h.mu.Unlock()
		return err
	}
	h.mu.Unlock()
	image, err := readCordisDisk(k.configPath)
	return k.checkConfigImageCompatibilityLocked(source, image, err)
}
func (k *Kernel) checkConfigImageCompatibilityLocked(source string, image cordisDiskImage, err error) error {
	h := k.host.LifecycleHost
	if h == nil || !h.opts.ConfigTransactions {
		return nil
	}
	h.mu.Lock()
	if old := h.configCompatibility; old != nil && old.Blocked {
		e := fmt.Errorf("incompatible-config: %s", old.Reason)
		h.mu.Unlock()
		return e
	}
	h.mu.Unlock()
	v := CordisConfigCompatibilityView{Scope: "known-managed-schema-and-studio-file-version", State: "compatible", Source: source, ObservedAt: time.Now().Format(time.RFC3339Nano), FileVersion: "absent", LastObservedHash: diskImageHash(image)}
	if err == nil {
		err = k.validateKnownConfigImage(image, &v)
	} else {
		v.FileVersion = "unreadable"
		v.LastObservedHash = "unavailable"
	}
	if err != nil {
		v.State = "incompatible-config"
		v.Blocked = true
		v.Reason = err.Error()
	}
	h.mu.Lock()
	// A concurrent caller may already have latched incompatibility. Never erase it.
	if old := h.configCompatibility; old != nil && old.Blocked {
		v = *old
	} else {
		h.configCompatibility = &v
		h.eventLocked("", "config-compatibility", "", v.State+":"+source)
	}
	h.mu.Unlock()
	if v.Blocked {
		return fmt.Errorf("incompatible-config: %s", v.Reason)
	}
	return nil
}
func (k *Kernel) validateKnownConfigImage(image cordisDiskImage, v *CordisConfigCompatibilityView) error {
	if !image.exists {
		return nil
	}
	v.FileVersion = "uninterpretable"
	doc := map[string]json.RawMessage{}
	if err := json.Unmarshal(image.bytes, &doc); err != nil || doc == nil {
		return errors.New("Studio config must be a JSON object")
	}
	if err := rejectReservedConfigAliases(doc, []string{"version", "plugins"}); err != nil {
		return err
	}
	v.FileVersion = "legacy-without-version"
	if raw, ok := doc["version"]; ok {
		var version int
		if json.Unmarshal(raw, &version) != nil || version != 2 {
			v.FileVersion = "unsupported"
			return errors.New("unsupported Studio file version; expected existing 2 or legacy missing version")
		}
		v.FileVersion = "2"
	}
	plugins := map[string]json.RawMessage{}
	if raw, ok := doc["plugins"]; ok {
		if json.Unmarshal(raw, &plugins) != nil || plugins == nil {
			return errors.New("Studio plugins must be an object")
		}
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	for id, rec := range k.records {
		if !k.host.LifecycleHost.manages(id) {
			continue
		}
		raw, ok := plugins[id]
		if !ok {
			continue
		}
		entry := map[string]json.RawMessage{}
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			return fmt.Errorf("%s: plugin entry must be an object", id)
		}
		if err := rejectReservedConfigAliases(entry, []string{"config", "enabled", "schemaVersion"}); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		if _, present := entry["schemaVersion"]; present {
			return fmt.Errorf("%s: plugin schemaVersion unsupported; current schema API is unversioned", id)
		}
		if raw, ok := entry["enabled"]; ok {
			var enabled *bool
			if json.Unmarshal(raw, &enabled) != nil {
				return fmt.Errorf("%s: enabled must be boolean or legacy null", id)
			}
		}
		var cfg map[string]any
		if raw, ok := entry["config"]; ok {
			if json.Unmarshal(raw, &cfg) != nil {
				return fmt.Errorf("%s: config must be object or legacy null", id)
			}
		}
		schema := rec.plugin.Schema()
		if err := rejectCordisUnknownFields(schema, cfg); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		if _, err := NormalizeAndValidate(schema, cfg); err != nil {
			return fmt.Errorf("%s: invalid declared config: %w", id, err)
		}
	}
	return nil
}

// encoding/json maps are case-sensitive, but the legacy struct reader accepts
// case-insensitive tags. Reject aliases rather than validate a different image.
func rejectReservedConfigAliases(object map[string]json.RawMessage, keys []string) error {
	for key := range object {
		for _, canonical := range keys {
			if key != canonical && strings.EqualFold(key, canonical) {
				return fmt.Errorf("noncanonical reserved config key %q; expected %q", key, canonical)
			}
		}
	}
	return nil
}

// Parse exactly the checked startup image; do not validate one file read then
// normalize a second potentially different read. External file locking remains
// out of scope: subsequent external changes are not made into a crash journal.
func (k *Kernel) readCandidateStartupConfig() (persistedConfigFile, error) {
	h := k.host.LifecycleHost
	if h == nil || !h.opts.ConfigTransactions {
		return k.readPersistedConfig(), nil
	}
	k.persistMu.Lock()
	defer k.persistMu.Unlock()
	out := persistedConfigFile{Version: 2, Plugins: map[string]persistedPluginEntry{}}
	image, err := readCordisDisk(k.configPath)
	if e := k.checkConfigImageCompatibilityLocked("startup", image, err); e != nil {
		return out, e
	}
	if image.exists {
		_ = json.Unmarshal(image.bytes, &out)
	} // foreign plugin semantics stay legacy/out of scope
	if out.Plugins == nil {
		out.Plugins = map[string]persistedPluginEntry{}
	}
	return out, nil
}
