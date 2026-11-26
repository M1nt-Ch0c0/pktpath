package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AnalyzeSessionReport runs all active analyzer plugins (built-in + in-process Cordis modules),
// aggregates insights/KPIs/notes, and reports whether any analyzer returned an error.
func (k *Kernel) AnalyzeSessionReport(ctx context.Context, in *AnalyzeInput) (*AnalyzeOutput, bool) {
	agg := &AnalyzeOutput{
		Insights: []Insight{},
		KPIs:     []ExtraKPI{},
		Notes:    []string{},
	}
	hasErrors := false
	for _, an := range k.Analyzers() {
		if an.Run == nil {
			continue
		}
		out, err := an.Run(ctx, in)
		if err != nil {
			hasErrors = true
			agg.Notes = append(agg.Notes, fmt.Sprintf("[%s] %v", an.Name, err))
			continue
		}
		if out == nil {
			continue
		}
		for _, ins := range out.Insights {
			if ins.PluginID == "" {
				ins.PluginID = an.PluginID
			}
			if ins.Plugin == "" {
				ins.Plugin = an.Name
			}
			agg.Insights = append(agg.Insights, ins)
		}
		for _, kpi := range out.KPIs {
			if kpi.PluginID == "" {
				kpi.PluginID = an.PluginID
			}
			agg.KPIs = append(agg.KPIs, kpi)
		}
		agg.Notes = append(agg.Notes, out.Notes...)
	}
	return agg, hasErrors
}

type analyzerFingerprintItem struct {
	PluginID       string         `json:"plugin_id"`
	AnalyzerID     string         `json:"analyzer_id"`
	Name           string         `json:"name"`
	Priority       int            `json:"priority"`
	Version        string         `json:"version,omitempty"`
	BuiltIn        bool           `json:"built_in"`
	Config         map[string]any `json:"config,omitempty"`
	Module         string         `json:"module,omitempty"`
	ManifestSHA256 string         `json:"manifest_sha256,omitempty"`
	ModuleSHA256   string         `json:"module_sha256,omitempty"`
}

func sha256FileHex(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "err:" + err.Error()
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AnalyzerFingerprint returns a deterministic SHA-256 digest representing the ordered set
// of currently active analyzers, their active configs, and external module/manifest bytes.
// Any enable/disable, config change, or external module update produces a distinct digest.
func (k *Kernel) AnalyzerFingerprint() string {
	analyzers := k.Analyzers()
	items := make([]analyzerFingerprintItem, 0, len(analyzers))

	k.mu.RLock()
	for _, an := range analyzers {
		item := analyzerFingerprintItem{
			PluginID:   an.PluginID,
			AnalyzerID: an.ID,
			Name:       an.Name,
			Priority:   an.Priority,
		}
		if rec, ok := k.records[an.PluginID]; ok && rec != nil {
			meta := rec.plugin.Meta()
			item.Version = meta.Version
			item.BuiltIn = meta.Builtin
			if rec.config != nil {
				if cloned, ok := DeepCloneValue(rec.config).(map[string]any); ok {
					item.Config = cloned
				}
			}
			if ep, ok := rec.plugin.(*externalPlugin); ok && ep != nil {
				if ep.bundleDir != "" {
					item.ManifestSHA256 = sha256FileHex(filepath.Join(ep.bundleDir, "manifest.json"))
				}
				if ep.manifest.Entrypoint != nil {
					mod := strings.TrimSpace(ep.manifest.Entrypoint.Module)
					if mod != "" {
						item.Module = mod
						if ep.bundleDir != "" {
							item.ModuleSHA256 = sha256FileHex(filepath.Join(ep.bundleDir, filepath.FromSlash(mod)))
						}
					}
				}
			}
		}
		items = append(items, item)
	}
	k.mu.RUnlock()

	raw, err := json.Marshal(items)
	if err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("marshal-err:%v", err)))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
