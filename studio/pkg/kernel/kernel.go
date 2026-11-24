package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HostServices exposes safe host primitives that built-in plugins can inject.
type HostServices struct {
	AppDir       string
	PluginsDir   string
	SessionsRoot string
	Extra        map[string]any
}

// RegisteredExtension binds an extension payload to the plugin that registered it.
type RegisteredExtension struct {
	PluginID string
	Point    string
	Value    any
}

// PluginContext is a Cordis-inspired effect scope for a single plugin activation.
// Every service, extension, and cleanup hook registered through this context is
// automatically disposed when the plugin is disabled, reloaded, or uninstalled.
type PluginContext struct {
	kernel   *Kernel
	pluginID string

	mu          sync.Mutex
	disposers   []func()
	extPoints   []string
	services    []string
	disposed    bool
}

// PluginID returns the owning plugin ID.
func (c *PluginContext) PluginID() string { return c.pluginID }

// Host returns the shared host paths/services struct.
func (c *PluginContext) Host() HostServices { return c.kernel.host }

// Provide registers a named service in the microkernel and auto-removes it on dispose.
func (c *PluginContext) Provide(name string, impl any) {
	c.kernel.mu.Lock()
	c.kernel.services[name] = serviceEntry{pluginID: c.pluginID, impl: impl}
	c.kernel.mu.Unlock()

	c.mu.Lock()
	c.services = append(c.services, name)
	c.disposers = append(c.disposers, func() {
		c.kernel.mu.Lock()
		if cur, ok := c.kernel.services[name]; ok && cur.pluginID == c.pluginID {
			delete(c.kernel.services, name)
		}
		c.kernel.mu.Unlock()
	})
	c.mu.Unlock()
}

// Inject resolves a service provided by another plugin or host.
func (c *PluginContext) Inject(name string) (any, bool) {
	return c.kernel.Service(name)
}

// RegisterExtension contributes an extension to any open-ended extension point.
// Automatically rolled back when the plugin scope is disposed.
func (c *PluginContext) RegisterExtension(point string, value any) {
	c.kernel.mu.Lock()
	c.kernel.extensions[point] = append(c.kernel.extensions[point], RegisteredExtension{
		PluginID: c.pluginID,
		Point:    point,
		Value:    value,
	})
	c.kernel.mu.Unlock()

	c.mu.Lock()
	c.extPoints = append(c.extPoints, point)
	c.disposers = append(c.disposers, func() {
		c.kernel.mu.Lock()
		list := c.kernel.extensions[point]
		kept := list[:0]
		for _, item := range list {
			if item.PluginID != c.pluginID {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(c.kernel.extensions, point)
		} else {
			c.kernel.extensions[point] = kept
		}
		c.kernel.mu.Unlock()
	})
	c.mu.Unlock()
}

// OnDispose registers a custom cleanup callback invoked in LIFO order on dispose.
func (c *PluginContext) OnDispose(fn func()) {
	if fn == nil {
		return
	}
	c.mu.Lock()
	c.disposers = append(c.disposers, fn)
	c.mu.Unlock()
}

func (c *PluginContext) dispose() {
	c.mu.Lock()
	if c.disposed {
		c.mu.Unlock()
		return
	}
	c.disposed = true
	fns := make([]func(), len(c.disposers))
	copy(fns, c.disposers)
	c.disposers = nil
	c.extPoints = nil
	c.services = nil
	c.mu.Unlock()

	for i := len(fns) - 1; i >= 0; i-- {
		func() {
			defer func() { _ = recover() }()
			fns[i]()
		}()
	}
}

func (c *PluginContext) summary() (points []string, services []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seenP := map[string]bool{}
	for _, p := range c.extPoints {
		if !seenP[p] {
			seenP[p] = true
			points = append(points, p)
		}
	}
	sort.Strings(points)
	services = append([]string(nil), c.services...)
	sort.Strings(services)
	return points, services
}

type serviceEntry struct {
	pluginID string
	impl     any
}

type pluginRecord struct {
	plugin         Plugin
	defaultEnabled bool
	enabled        bool
	active         bool
	config         map[string]any
	scope          *PluginContext
	lastError      string
	activatedAt    time.Time
	order          int
}

type persistedPluginEntry struct {
	Enabled *bool          `json:"enabled,omitempty"`
	Config  map[string]any `json:"config,omitempty"`
}

type persistedConfigFile struct {
	Version int                             `json:"version"`
	Plugins map[string]persistedPluginEntry `json:"plugins"`
}

// PluginStatusView is the rich JSON representation returned by GET /api/kernel/state.
type PluginStatusView struct {
	Meta         PluginMeta     `json:"meta"`
	Schema       *ConfigSchema  `json:"schema"`
	Config       map[string]any `json:"config"`
	Enabled      bool           `json:"enabled"`
	Active       bool           `json:"active"`
	Status       string         `json:"status"` // active | disabled | error
	Error        string         `json:"error,omitempty"`
	ExtPoints    []string       `json:"extension_points"`
	Services     []string       `json:"provided_services"`
	ActivatedAt  string         `json:"activated_at,omitempty"`
	CanUninstall bool           `json:"can_uninstall"`
}

// KernelSnapshot is the complete live state of the microkernel for the GUI.
type KernelSnapshot struct {
	Version         string             `json:"version"`
	PluginsDir      string             `json:"plugins_dir"`
	ConfigPath      string             `json:"config_path"`
	TotalPlugins    int                `json:"total_plugins"`
	ActivePlugins   int                `json:"active_plugins"`
	BuiltinCount    int                `json:"builtin_count"`
	ExternalCount   int                `json:"external_count"`
	Plugins         []PluginStatusView `json:"plugins"`
	Transports      []TransportSpec    `json:"transports"`
	Collector       *CollectorSpec     `json:"collector,omitempty"`
	CaptureModes    []CaptureModeSpec  `json:"capture_modes"`
	Exporters       []ExporterSpec     `json:"exporters"`
	Analyzers       []AnalyzerSpec     `json:"analyzers"`
	UISlots         []UISlotSpec       `json:"ui_slots"`
	Theme           *ThemeSpec         `json:"theme,omitempty"`
	KernelExtSummary struct {
		SockFields int `json:"sock_fields"`
		SockMax    int `json:"sock_max"`
		Qdiscs     int `json:"qdiscs"`
		QdiscsMax  int `json:"qdiscs_max"`
	} `json:"kernel_ext_summary"`
	ExtensionCounts map[string]int `json:"extension_counts"`
}

// Kernel is the central Cordis-style microkernel for PktPath Studio.
type Kernel struct {
	mu         sync.RWMutex
	host       HostServices
	configPath string
	records    map[string]*pluginRecord
	orderSeq   int
	services   map[string]serviceEntry
	extensions map[string][]RegisteredExtension
	onChange   []func()
}

// New creates a new microkernel instance.
func New(host HostServices) *Kernel {
	if host.PluginsDir == "" && host.AppDir != "" {
		host.PluginsDir = filepath.Join(host.AppDir, "plugins")
	}
	if host.PluginsDir != "" {
		_ = os.MkdirAll(host.PluginsDir, 0o755)
	}
	cfgPath := filepath.Join(host.AppDir, "plugins_config.json")
	return &Kernel{
		host:       host,
		configPath: cfgPath,
		records:    map[string]*pluginRecord{},
		services:   map[string]serviceEntry{},
		extensions: map[string][]RegisteredExtension{},
	}
}

// Host returns the kernel host services.
func (k *Kernel) Host() HostServices { return k.host }

// OnChange registers a listener notified whenever plugin states/configs change.
func (k *Kernel) OnChange(fn func()) {
	k.mu.Lock()
	k.onChange = append(k.onChange, fn)
	k.mu.Unlock()
}

func (k *Kernel) notifyChange() {
	k.mu.RLock()
	fns := append([]func(){}, k.onChange...)
	k.mu.RUnlock()
	for _, fn := range fns {
		func() {
			defer func() { _ = recover() }()
			fn()
		}()
	}
}

// Service resolves a service provided by an active plugin or host.
func (k *Kernel) Service(name string) (any, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if ent, ok := k.services[name]; ok {
		return ent.impl, true
	}
	if k.host.Extra != nil {
		if v, ok := k.host.Extra[name]; ok {
			return v, true
		}
	}
	return nil, false
}

// RegisterBuiltin registers a first-class built-in plugin before Start().
func (k *Kernel) RegisterBuiltin(p Plugin, defaultEnabled bool) {
	meta := p.Meta()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.orderSeq++
	k.records[meta.ID] = &pluginRecord{
		plugin:         p,
		defaultEnabled: defaultEnabled,
		enabled:        defaultEnabled,
		config:         DefaultConfig(p.Schema()),
		order:          k.orderSeq,
	}
}

// Start loads persisted configuration, discovers external plugin bundles, and
// activates all enabled plugins in deterministic order.
func (k *Kernel) Start() error {
	persisted := k.readPersistedConfig()

	// Discover external plugins in PluginsDir (folders with manifest.json + legacy *.json).
	_ = k.discoverExternalPlugins()

	k.mu.Lock()
	for id, rec := range k.records {
		if p, ok := persisted.Plugins[id]; ok {
			if p.Enabled != nil {
				rec.enabled = *p.Enabled
			}
			if p.Config != nil {
				if norm, err := NormalizeAndValidate(rec.plugin.Schema(), p.Config); err == nil {
					rec.config = norm
				} else {
					rec.config = DefaultConfig(rec.plugin.Schema())
				}
			}
		} else {
			rec.config = DefaultConfig(rec.plugin.Schema())
		}
	}
	ordered := k.sortedIDsLocked()
	k.mu.Unlock()

	for _, id := range ordered {
		k.mu.RLock()
		en := k.records[id].enabled
		k.mu.RUnlock()
		if en {
			_ = k.activatePlugin(id)
		}
	}
	return nil
}

// Shutdown cleanly disposes every active plugin scope.
func (k *Kernel) Shutdown() {
	k.mu.RLock()
	ids := k.sortedIDsLocked()
	k.mu.RUnlock()
	for i := len(ids) - 1; i >= 0; i-- {
		k.deactivatePlugin(ids[i])
	}
}

func (k *Kernel) sortedIDsLocked() []string {
	type pair struct {
		id    string
		order int
	}
	arr := make([]pair, 0, len(k.records))
	for id, r := range k.records {
		arr = append(arr, pair{id: id, order: r.order})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].order != arr[j].order {
			return arr[i].order < arr[j].order
		}
		return arr[i].id < arr[j].id
	})
	out := make([]string, len(arr))
	for i, p := range arr {
		out[i] = p.id
	}
	return out
}

func (k *Kernel) activatePlugin(id string) error {
	k.mu.Lock()
	rec, ok := k.records[id]
	if !ok {
		k.mu.Unlock()
		return fmt.Errorf("plugin not found: %s", id)
	}
	oldScope := rec.scope
	rec.scope = nil
	rec.active = false
	rec.lastError = ""
	cfgCopy, _ := NormalizeAndValidate(rec.plugin.Schema(), rec.config)
	meta := rec.plugin.Meta()
	p := rec.plugin
	k.mu.Unlock()

	if oldScope != nil {
		oldScope.dispose()
	}

	// Verify required services/plugins if declared.
	for _, req := range meta.Requires {
		if _, hasSvc := k.Service(req); hasSvc {
			continue
		}
		if !k.IsPluginActive(req) {
			err := fmt.Errorf("依赖未满足: 需要启用 %s", req)
			k.mu.Lock()
			rec.lastError = err.Error()
			rec.active = false
			k.mu.Unlock()
			return err
		}
	}

	scope := &PluginContext{kernel: k, pluginID: id}
	if err := p.Apply(scope, cfgCopy); err != nil {
		scope.dispose()
		k.mu.Lock()
		rec.lastError = err.Error()
		rec.active = false
		k.mu.Unlock()
		return err
	}

	k.mu.Lock()
	rec.scope = scope
	rec.active = true
	rec.lastError = ""
	rec.activatedAt = time.Now()
	k.mu.Unlock()
	return nil
}

func (k *Kernel) deactivatePlugin(id string) {
	k.mu.Lock()
	rec, ok := k.records[id]
	if !ok {
		k.mu.Unlock()
		return
	}
	scope := rec.scope
	rec.scope = nil
	rec.active = false
	rec.lastError = ""
	k.mu.Unlock()

	if scope != nil {
		scope.dispose()
	}
}

// SetEnabled toggles a plugin on/off at runtime with full effect-scope rollback
// and automatic dependent cascade (Cordis-style dependency lifecycle).
func (k *Kernel) SetEnabled(id string, enabled bool) error {
	k.mu.Lock()
	rec, ok := k.records[id]
	if !ok {
		k.mu.Unlock()
		return fmt.Errorf("plugin not found: %s", id)
	}
	rec.enabled = enabled
	k.mu.Unlock()

	var err error
	if enabled {
		err = k.activatePlugin(id)
		k.reconcileDependents()
	} else {
		k.deactivatePlugin(id)
		k.reconcileDependents()
	}
	_ = k.savePersistedConfig()
	k.notifyChange()
	return err
}

func (k *Kernel) reconcileDependents() {
	k.mu.RLock()
	ids := k.sortedIDsLocked()
	k.mu.RUnlock()

	for _, id := range ids {
		k.mu.RLock()
		rec := k.records[id]
		if !rec.enabled {
			k.mu.RUnlock()
			continue
		}
		reqs := rec.plugin.Meta().Requires
		wasActive := rec.active
		k.mu.RUnlock()
		if len(reqs) == 0 {
			continue
		}
		missing := ""
		for _, req := range reqs {
			if _, ok := k.Service(req); ok {
				continue
			}
			if k.IsPluginActive(req) {
				continue
			}
			missing = req
			break
		}
		if missing != "" && wasActive {
			k.deactivatePlugin(id)
			k.mu.Lock()
			if r := k.records[id]; r != nil {
				r.lastError = fmt.Sprintf("依赖未启用: %s", missing)
			}
			k.mu.Unlock()
		} else if missing == "" && !wasActive {
			_ = k.activatePlugin(id)
		}
	}
}

// SetConfig validates, persists, and hot-reloads a plugin's configuration.
func (k *Kernel) SetConfig(id string, raw map[string]any) (map[string]any, error) {
	k.mu.RLock()
	rec, ok := k.records[id]
	if !ok {
		k.mu.RUnlock()
		return nil, fmt.Errorf("plugin not found: %s", id)
	}
	schema := rec.plugin.Schema()
	wasEnabled := rec.enabled
	k.mu.RUnlock()

	norm, err := NormalizeAndValidate(schema, raw)
	if err != nil {
		return nil, err
	}

	k.mu.Lock()
	rec.config = norm
	k.mu.Unlock()

	if wasEnabled {
		if err := k.activatePlugin(id); err != nil {
			_ = k.savePersistedConfig()
			k.notifyChange()
			return norm, err
		}
	}
	if err := k.savePersistedConfig(); err != nil {
		return norm, err
	}
	k.notifyChange()
	return norm, nil
}

// ResetConfig resets a plugin to its schema defaults and hot-reloads it.
func (k *Kernel) ResetConfig(id string) (map[string]any, error) {
	k.mu.RLock()
	rec, ok := k.records[id]
	if !ok {
		k.mu.RUnlock()
		return nil, fmt.Errorf("plugin not found: %s", id)
	}
	defs := DefaultConfig(rec.plugin.Schema())
	k.mu.RUnlock()
	return k.SetConfig(id, defs)
}

// Reload disposes and re-applies a plugin's current configuration.
func (k *Kernel) Reload(id string) error {
	k.mu.RLock()
	rec, ok := k.records[id]
	if !ok {
		k.mu.RUnlock()
		return fmt.Errorf("plugin not found: %s", id)
	}
	en := rec.enabled
	k.mu.RUnlock()
	if !en {
		k.deactivatePlugin(id)
		return nil
	}
	err := k.activatePlugin(id)
	k.notifyChange()
	return err
}

// IsPluginActive reports whether a plugin is currently enabled and active.
func (k *Kernel) IsPluginActive(id string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	rec, ok := k.records[id]
	return ok && rec.enabled && rec.active
}

// PluginConfig returns a deep-cloned copy of a plugin's active config.
func (k *Kernel) PluginConfig(id string) map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	rec, ok := k.records[id]
	if !ok || rec.config == nil {
		return map[string]any{}
	}
	c, _ := DeepCloneValue(rec.config).(map[string]any)
	if c == nil {
		return map[string]any{}
	}
	return c
}

// Extensions returns all active extensions registered at an open-ended point.
func (k *Kernel) Extensions(point string) []RegisteredExtension {
	k.mu.RLock()
	defer k.mu.RUnlock()
	list := k.extensions[point]
	out := make([]RegisteredExtension, len(list))
	copy(out, list)
	return out
}

// Transports returns all active transport plugins ordered by Priority.
func (k *Kernel) Transports() []TransportSpec {
	exts := k.Extensions(ExtTransport)
	out := make([]TransportSpec, 0, len(exts))
	for _, e := range exts {
		if sp, ok := e.Value.(TransportSpec); ok {
			out = append(out, sp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// HasTransportKind reports whether any active transport plugin provides kind (adb|ssh|offline).
func (k *Kernel) HasTransportKind(kind string) bool {
	for _, t := range k.Transports() {
		if strings.EqualFold(t.Kind, kind) {
			return true
		}
	}
	return false
}

// Collector returns the active eBPF collector configuration spec (if enabled).
func (k *Kernel) Collector() *CollectorSpec {
	exts := k.Extensions(ExtCollector)
	for _, e := range exts {
		if sp, ok := e.Value.(CollectorSpec); ok {
			cp := sp
			return &cp
		}
	}
	return nil
}

// CaptureModes returns all active capture mode plugins ordered by Priority.
func (k *Kernel) CaptureModes() []CaptureModeSpec {
	exts := k.Extensions(ExtCaptureMode)
	out := make([]CaptureModeSpec, 0, len(exts))
	for _, e := range exts {
		if sp, ok := e.Value.(CaptureModeSpec); ok {
			out = append(out, sp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// Exporters returns all active exporter extensions ordered by Priority.
func (k *Kernel) Exporters() []ExporterSpec {
	exts := k.Extensions(ExtExporter)
	out := make([]ExporterSpec, 0, len(exts))
	for _, e := range exts {
		if sp, ok := e.Value.(ExporterSpec); ok {
			out = append(out, sp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// Analyzers returns all active analyzer extensions ordered by Priority.
func (k *Kernel) Analyzers() []AnalyzerSpec {
	exts := k.Extensions(ExtAnalyzer)
	out := make([]AnalyzerSpec, 0, len(exts))
	for _, e := range exts {
		if sp, ok := e.Value.(AnalyzerSpec); ok {
			out = append(out, sp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// UISlots returns all active UI slot widgets ordered by Order.
func (k *Kernel) UISlots() []UISlotSpec {
	exts := k.Extensions(ExtUISlot)
	out := make([]UISlotSpec, 0, len(exts))
	for _, e := range exts {
		if sp, ok := e.Value.(UISlotSpec); ok {
			out = append(out, sp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

// Theme returns the active UI theme spec (if any).
func (k *Kernel) Theme() *ThemeSpec {
	exts := k.Extensions(ExtTheme)
	if len(exts) == 0 {
		return nil
	}
	if sp, ok := exts[len(exts)-1].Value.(ThemeSpec); ok {
		cp := sp
		return &cp
	}
	return nil
}

// CollectKernelExtensions gathers all active BTF sock_fields & TC qdiscs from every plugin.
func (k *Kernel) CollectKernelExtensions() []KernelExtSpec {
	exts := k.Extensions(ExtKernelExt)
	out := make([]KernelExtSpec, 0, len(exts))
	for _, e := range exts {
		if sp, ok := e.Value.(KernelExtSpec); ok {
			if len(sp.SockFields) > 0 || len(sp.Qdiscs) > 0 {
				out = append(out, sp)
			}
		}
	}
	return out
}

// MaterializeKernelPluginFiles renders all active kernel.ext specs into device-ready
// JSON manifest files inside a temporary staging directory under AppDir.
func (k *Kernel) MaterializeKernelPluginFiles() ([]string, error) {
	specs := k.CollectKernelExtensions()
	stageDir := filepath.Join(k.host.AppDir, ".staged_kernel_plugins")
	_ = os.RemoveAll(stageDir)
	if len(specs) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return nil, err
	}
	var paths []string
	for idx, sp := range specs {
		safe := sanitizeID(sp.ID)
		if safe == "" {
			safe = fmt.Sprintf("ext_%d", idx)
		}
		fileName := fmt.Sprintf("%02d_%s.json", idx, safe)
		doc := map[string]any{
			"id":          sp.ID,
			"name":        sp.Name,
			"description": sp.Description,
			"sock_fields": sp.SockFields,
			"qdiscs":      sp.Qdiscs,
		}
		b, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			continue
		}
		fp := filepath.Join(stageDir, fileName)
		if err := os.WriteFile(fp, b, 0o644); err != nil {
			return nil, err
		}
		paths = append(paths, fp)
	}
	return paths, nil
}

// AnalyzeSession runs all active analyzer plugins (built-in + external) and aggregates insights.
func (k *Kernel) AnalyzeSession(ctx context.Context, in *AnalyzeInput) *AnalyzeOutput {
	agg := &AnalyzeOutput{
		Insights: []Insight{},
		KPIs:     []ExtraKPI{},
		Notes:    []string{},
	}
	for _, an := range k.Analyzers() {
		if an.Run == nil {
			continue
		}
		out, err := an.Run(ctx, in)
		if err != nil {
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
	return agg
}

// RunExporter invokes any active exporter extension by ID (built-in or external).
func (k *Kernel) RunExporter(ctx context.Context, exporterID string, in *ExportInput) (*ExportOutput, error) {
	for _, ex := range k.Exporters() {
		if ex.ID == exporterID {
			if ex.Run == nil {
				return nil, fmt.Errorf("exporter %q has no runner", exporterID)
			}
			return ex.Run(ctx, in)
		}
	}
	return nil, fmt.Errorf("exporter %q not found or disabled", exporterID)
}

// Snapshot returns the full state of the microkernel for GET /api/kernel/state.
func (k *Kernel) Snapshot(version string) KernelSnapshot {
	k.mu.RLock()
	ids := k.sortedIDsLocked()
	plugins := make([]PluginStatusView, 0, len(ids))
	activeCnt, builtinCnt, extCnt := 0, 0, 0

	for _, id := range ids {
		rec := k.records[id]
		meta := rec.plugin.Meta()
		if meta.Capabilities == nil {
			meta.Capabilities = []string{}
		}
		if meta.Builtin {
			builtinCnt++
		} else {
			extCnt++
		}
		status := "disabled"
		if rec.enabled {
			if rec.active && rec.lastError == "" {
				status = "active"
				activeCnt++
			} else {
				status = "error"
			}
		}
		var pts, svcs []string
		if rec.scope != nil {
			pts, svcs = rec.scope.summary()
		}
		if pts == nil {
			pts = []string{}
		}
		if svcs == nil {
			svcs = []string{}
		}
		actStr := ""
		if !rec.activatedAt.IsZero() && rec.active {
			actStr = rec.activatedAt.Format(time.RFC3339)
		}
		cfgClone, _ := DeepCloneValue(rec.config).(map[string]any)
		if cfgClone == nil {
			cfgClone = map[string]any{}
		}
		plugins = append(plugins, PluginStatusView{
			Meta:         meta,
			Schema:       rec.plugin.Schema(),
			Config:       cfgClone,
			Enabled:      rec.enabled,
			Active:       rec.active,
			Status:       status,
			Error:        rec.lastError,
			ExtPoints:    pts,
			Services:     svcs,
			ActivatedAt:  actStr,
			CanUninstall: !meta.Builtin,
		})
	}
	extCounts := map[string]int{}
	for pt, list := range k.extensions {
		extCounts[pt] = len(list)
	}
	k.mu.RUnlock()

	snap := KernelSnapshot{
		Version:         version,
		PluginsDir:      k.host.PluginsDir,
		ConfigPath:      k.configPath,
		TotalPlugins:    len(plugins),
		ActivePlugins:   activeCnt,
		BuiltinCount:    builtinCnt,
		ExternalCount:   extCnt,
		Plugins:         plugins,
		Transports:      k.Transports(),
		Collector:       k.Collector(),
		CaptureModes:    k.CaptureModes(),
		Exporters:       k.Exporters(),
		Analyzers:       k.Analyzers(),
		UISlots:         k.UISlots(),
		Theme:           k.Theme(),
		ExtensionCounts: extCounts,
	}
	snap.KernelExtSummary.SockMax = 16
	snap.KernelExtSummary.QdiscsMax = 32
	for _, ke := range k.CollectKernelExtensions() {
		snap.KernelExtSummary.SockFields += len(ke.SockFields)
		snap.KernelExtSummary.Qdiscs += len(ke.Qdiscs)
	}
	return snap
}

func (k *Kernel) readPersistedConfig() persistedConfigFile {
	out := persistedConfigFile{Version: 2, Plugins: map[string]persistedPluginEntry{}}
	if k.configPath == "" {
		return out
	}
	b, err := os.ReadFile(k.configPath)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	if out.Plugins == nil {
		out.Plugins = map[string]persistedPluginEntry{}
	}
	return out
}

func (k *Kernel) savePersistedConfig() error {
	if k.configPath == "" {
		return nil
	}
	k.mu.RLock()
	doc := persistedConfigFile{
		Version: 2,
		Plugins: make(map[string]persistedPluginEntry, len(k.records)),
	}
	for id, rec := range k.records {
		en := rec.enabled
		cfgClone, _ := DeepCloneValue(rec.config).(map[string]any)
		doc.Plugins[id] = persistedPluginEntry{
			Enabled: &en,
			Config:  cfgClone,
		}
	}
	k.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(k.configPath), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", k.configPath, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, k.configPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func sanitizeID(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else if r == ' ' {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), ".-_")
}
