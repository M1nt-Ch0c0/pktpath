package kernel

import (
	"context"

	"pktpath/studio/pkg/reconstruct"
)

// Open-ended standard extension points (plugins may also register custom points).
const (
	ExtTransport   = "transport"
	ExtCollector   = "collector"
	ExtCaptureMode = "capture.mode"
	ExtKernelExt   = "kernel.ext"
	ExtAnalyzer    = "analyzer"
	ExtExporter    = "exporter"
	ExtUISlot      = "ui.slot"
	ExtTheme       = "theme"
)

// PluginCategory groups plugins in the Plugin Center UI.
type PluginCategory string

const (
	CatTransport PluginCategory = "transport"
	CatCollector PluginCategory = "collector"
	CatAnalyzer  PluginCategory = "analyzer"
	CatExporter  PluginCategory = "exporter"
	CatUI        PluginCategory = "ui"
	CatExternal  PluginCategory = "external"
)

// PluginMeta describes a plugin's identity, provenance, and declared capabilities.
type PluginMeta struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Author       string         `json:"author,omitempty"`
	Description  string         `json:"description"`
	Category     PluginCategory `json:"category"`
	Icon         string         `json:"icon,omitempty"`
	Builtin      bool           `json:"builtin"`
	SourcePath   string         `json:"source_path,omitempty"`
	Capabilities []string       `json:"capabilities"`
	Provides     []string       `json:"provides,omitempty"`
	Requires     []string       `json:"requires,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
}

// Plugin is the universal DSH/Cordis-style plugin contract.
// Everything in PktPath Studio implements this interface.
type Plugin interface {
	Meta() PluginMeta
	Schema() *ConfigSchema
	Apply(ctx *PluginContext, cfg map[string]any) error
}

// ---- Standard Extension Payloads ----

// TransportSpec registers a target device / session source transport in the GUI.
type TransportSpec struct {
	ID                  string `json:"id"`
	PluginID            string `json:"plugin_id"`
	Name                string `json:"name"`
	ShortLabel          string `json:"short_label"`
	Icon                string `json:"icon"`
	Kind                string `json:"kind"` // adb | ssh | offline | custom
	Description         string `json:"description"`
	Priority            int    `json:"priority"`
	SupportsLiveCapture bool   `json:"supports_live_capture"`
	SupportsOffline     bool   `json:"supports_offline"`
	ConfigSummary       string `json:"config_summary,omitempty"`
}

// CollectorSpec registers eBPF/device collector defaults & behavior.
type CollectorSpec struct {
	ID               string `json:"id"`
	PluginID         string `json:"plugin_id"`
	Name             string `json:"name"`
	DefaultScope     string `json:"default_scope"`
	DefaultDuration  int    `json:"default_duration_sec"`
	DefaultSample    string `json:"default_sample"`
	CaptureHdrBytes  int    `json:"capture_hdr_bytes"`
	ProfileSendmsg   bool   `json:"profile_sendmsg"`
	AllowPartial     bool   `json:"allow_partial"`
	EnableKernelExts bool   `json:"enable_kernel_exts"`
}

// CaptureModeSpec registers a capture mode tab (e.g. oneshot, daemon) in the Workbench.
type CaptureModeSpec struct {
	ID          string `json:"id"`
	PluginID    string `json:"plugin_id"`
	Mode        string `json:"mode"` // oneshot | daemon | custom
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Priority    int    `json:"priority"`
}

// KernelSockField declares one dynamic BTF-resolved struct sock field.
type KernelSockField struct {
	Struct string `json:"struct"`
	Field  string `json:"field"`
	Size   int    `json:"size"`
	Role   string `json:"role"` // tag | tgid_fallback
	Label  string `json:"label"`
}

// KernelQdisc declares one dynamically cloned BPF TC qdisc probe.
type KernelQdisc struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Mode       string `json:"mode"` // classful | leaf
	EnqueueSym string `json:"enqueue_sym"`
	DequeueSym string `json:"dequeue_sym,omitempty"`
}

// KernelExtSpec contributes dynamic eBPF kernel extensions (no artificial 2-slot cap).
type KernelExtSpec struct {
	ID          string            `json:"id"`
	PluginID    string            `json:"plugin_id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	SockFields  []KernelSockField `json:"sock_fields,omitempty"`
	Qdiscs      []KernelQdisc     `json:"qdiscs,omitempty"`
}

// Insight is one structured diagnostic card produced by an analyzer plugin.
type Insight struct {
	ID        string   `json:"id"`
	PluginID  string   `json:"plugin_id"`
	Plugin    string   `json:"plugin_name"`
	Severity  string   `json:"severity"` // ok | info | warn | critical
	Title     string   `json:"title"`
	Summary   string   `json:"summary"`
	Metric    string   `json:"metric,omitempty"`
	SampleIDs []uint64 `json:"sample_ids,omitempty"`
}

// ExtraKPI is an additional metric card contributed by an analyzer plugin.
type ExtraKPI struct {
	PluginID string `json:"plugin_id"`
	Label    string `json:"label"`
	Value    string `json:"value"`
	Sub      string `json:"sub,omitempty"`
	Tone     string `json:"tone,omitempty"` // default | ok | warn | bad
}

// AnalyzeInput is passed to every active analyzer plugin when opening a session.
type AnalyzeInput struct {
	SessionID   string
	SessionDir  string
	Session     *reconstruct.Session
	Overview    *reconstruct.SessionOverview
	OverviewMap map[string]any
}

// AnalyzeOutput is returned by an analyzer plugin.
type AnalyzeOutput struct {
	Insights []Insight  `json:"insights,omitempty"`
	KPIs     []ExtraKPI `json:"kpis,omitempty"`
	Notes    []string   `json:"notes,omitempty"`
}

// AnalyzerSpec registers a post-analysis hook (built-in Go or external out-of-process).
type AnalyzerSpec struct {
	ID          string `json:"id"`
	PluginID    string `json:"plugin_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	Run         func(ctx context.Context, in *AnalyzeInput) (*AnalyzeOutput, error) `json:"-"`
}

// ExportInput is passed to an exporter plugin on user action.
type ExportInput struct {
	SessionID  string
	SessionDir string
	Session    *reconstruct.Session
	Overview   *reconstruct.SessionOverview
	OutPath    string
	Params     map[string]any
}

// ExportOutput describes the artifact produced by an exporter plugin.
type ExportOutput struct {
	OK          bool           `json:"ok"`
	OutPath     string         `json:"out_path"`
	IsDirectory bool           `json:"is_directory,omitempty"`
	Summary     string         `json:"summary"`
	Details     map[string]any `json:"details,omitempty"`
}

// ExporterSpec registers a session exporter button in the Workbench GUI.
type ExporterSpec struct {
	ID          string `json:"id"`
	PluginID    string `json:"plugin_id"`
	Name        string `json:"name"`
	ButtonLabel string `json:"button_label"`
	Icon        string `json:"icon"`
	Description string `json:"description"`
	DefaultExt  string `json:"default_ext,omitempty"`
	FileFilter  string `json:"file_filter,omitempty"`
	IsDirectory bool   `json:"is_directory,omitempty"`
	Priority    int    `json:"priority"`
	Run         func(ctx context.Context, in *ExportInput) (*ExportOutput, error) `json:"-"`
}

// UISlotSpec mounts a plugin UI widget into a named Workbench slot.
type UISlotSpec struct {
	ID        string `json:"id"`
	PluginID  string `json:"plugin_id"`
	Slot      string `json:"slot"` // canvas.banner | workbench.toolbar | sample.extra | sidebar.extra
	Title     string `json:"title"`
	ScriptURL string `json:"script_url,omitempty"`
	StyleURL  string `json:"style_url,omitempty"`
	Order     int    `json:"order"`
}

// ThemeSpec controls the Studio visual theme dynamically from a UI plugin.
type ThemeSpec struct {
	PluginID  string `json:"plugin_id"`
	Mode      string `json:"mode"`    // light | dark | system
	Accent    string `json:"accent"`  // blue | emerald | violet | amber | rose
	Density   string `json:"density"` // comfortable | compact
	FontScale int    `json:"font_scale"`
}
