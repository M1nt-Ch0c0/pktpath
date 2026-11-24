package kernel

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pktpath/studio/pkg/adb"
)

// ExternalManifest is the v2.0 bundle manifest.json format (also backwards-compatible
// with legacy single-file kernel extension JSONs that declare top-level sock_fields/qdiscs).
type ExternalManifest struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Version     string         `json:"version,omitempty"`
	Author      string         `json:"author,omitempty"`
	Description string         `json:"description,omitempty"`
	Category    PluginCategory `json:"category,omitempty"`
	Icon        string         `json:"icon,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Requires    []string       `json:"requires,omitempty"`

	// Optional typed configuration schema rendered automatically in Plugin Center.
	ConfigSchema *ConfigSchema `json:"config_schema,omitempty"`

	// Mode 1: Dynamic Linux eBPF kernel extensions (BTF sock fields + cloned TC qdiscs).
	KernelExtensions *struct {
		SockFields []KernelSockField `json:"sock_fields,omitempty"`
		Qdiscs     []KernelQdisc     `json:"qdiscs,omitempty"`
	} `json:"kernel_extensions,omitempty"`
	// Legacy top-level compatibility fields:
	LegacySockFields []KernelSockField `json:"sock_fields,omitempty"`
	LegacyQdiscs     []KernelQdisc     `json:"qdiscs,omitempty"`

	// Mode 2: Out-of-process JSON-over-stdio hook entrypoint (invoked via HideConsole).
	Entrypoint *struct {
		Command []string `json:"command"`
	} `json:"entrypoint,omitempty"`
	Analyzers []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Priority    int    `json:"priority,omitempty"`
	} `json:"analyzers,omitempty"`
	Exporters []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		ButtonLabel string `json:"button_label,omitempty"`
		Icon        string `json:"icon,omitempty"`
		Description string `json:"description,omitempty"`
		DefaultExt  string `json:"default_ext,omitempty"`
		FileFilter  string `json:"file_filter,omitempty"`
		IsDirectory bool   `json:"is_directory,omitempty"`
		Priority    int    `json:"priority,omitempty"`
	} `json:"exporters,omitempty"`

	// Mode 3: Frontend UI Slot widgets served from bundle directory.
	UISlots []struct {
		ID     string `json:"id,omitempty"`
		Slot   string `json:"slot"`
		Title  string `json:"title"`
		Script string `json:"script,omitempty"`
		Style  string `json:"style,omitempty"`
		Order  int    `json:"order,omitempty"`
	} `json:"ui_slots,omitempty"`
}

// ExternalPreview summarizes an external plugin package before installation.
type ExternalPreview struct {
	OK           bool              `json:"ok"`
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version,omitempty"`
	Author       string            `json:"author,omitempty"`
	Description  string            `json:"description,omitempty"`
	Category     PluginCategory    `json:"category"`
	Icon         string            `json:"icon"`
	SourceType   string            `json:"source_type"` // zip | folder | json
	Capabilities []string          `json:"capabilities"`
	SockFields   []KernelSockField `json:"sock_fields,omitempty"`
	Qdiscs       []KernelQdisc     `json:"qdiscs,omitempty"`
	HasEntry     bool              `json:"has_entrypoint"`
	AnalyzerCnt  int               `json:"analyzer_count"`
	ExporterCnt  int               `json:"exporter_count"`
	UISlotCnt    int               `json:"ui_slot_count"`
	SchemaFields int               `json:"schema_fields"`
	Warnings     []string          `json:"warnings,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type externalPlugin struct {
	bundleDir string
	manifest  ExternalManifest
	meta      PluginMeta
	isFlat    bool
	flatFile  string
}

func (ep *externalPlugin) Meta() PluginMeta      { return ep.meta }
func (ep *externalPlugin) Schema() *ConfigSchema { return ep.manifest.ConfigSchema }

func (ep *externalPlugin) normalizedKernelExts() ([]KernelSockField, []KernelQdisc) {
	var sfs []KernelSockField
	var qds []KernelQdisc
	if ep.manifest.KernelExtensions != nil {
		sfs = append(sfs, ep.manifest.KernelExtensions.SockFields...)
		qds = append(qds, ep.manifest.KernelExtensions.Qdiscs...)
	}
	sfs = append(sfs, ep.manifest.LegacySockFields...)
	qds = append(qds, ep.manifest.LegacyQdiscs...)
	return sfs, qds
}

func (ep *externalPlugin) Apply(ctx *PluginContext, cfg map[string]any) error {
	// 1. Register kernel extensions (BTF sock fields + dynamically cloned TC qdiscs)
	sfs, qds := ep.normalizedKernelExts()
	if len(sfs) > 0 || len(qds) > 0 {
		ctx.RegisterExtension(ExtKernelExt, KernelExtSpec{
			ID:          ep.meta.ID,
			PluginID:    ep.meta.ID,
			Name:        ep.meta.Name,
			Description: ep.meta.Description,
			SockFields:  sfs,
			Qdiscs:      qds,
		})
	}

	// 2. Register UI slot widgets served from /api/kernel/plugin-asset/<id>/<rel>
	for i, u := range ep.manifest.UISlots {
		slotID := strings.TrimSpace(u.ID)
		if slotID == "" {
			slotID = fmt.Sprintf("%s.slot.%d", ep.meta.ID, i)
		}
		var scriptURL, styleURL string
		if s := strings.TrimSpace(u.Script); s != "" {
			scriptURL = fmt.Sprintf("/api/kernel/plugin-asset/%s/%s", ep.meta.ID, strings.TrimPrefix(filepath.ToSlash(s), "/"))
		}
		if s := strings.TrimSpace(u.Style); s != "" {
			styleURL = fmt.Sprintf("/api/kernel/plugin-asset/%s/%s", ep.meta.ID, strings.TrimPrefix(filepath.ToSlash(s), "/"))
		}
		ctx.RegisterExtension(ExtUISlot, UISlotSpec{
			ID:        slotID,
			PluginID:  ep.meta.ID,
			Slot:      u.Slot,
			Title:     u.Title,
			ScriptURL: scriptURL,
			StyleURL:  styleURL,
			Order:     u.Order,
		})
	}

	// 3. Register out-of-process analyzers & exporters if entrypoint is defined
	if ep.manifest.Entrypoint != nil && len(ep.manifest.Entrypoint.Command) > 0 {
		cmdSpec := append([]string(nil), ep.manifest.Entrypoint.Command...)
		cfgCopy, _ := DeepCloneValue(cfg).(map[string]any)

		for _, an := range ep.manifest.Analyzers {
			anID := strings.TrimSpace(an.ID)
			if anID == "" {
				anID = ep.meta.ID + ".analyzer"
			}
			anName := strings.TrimSpace(an.Name)
			if anName == "" {
				anName = ep.meta.Name
			}
			prio := an.Priority
			if prio == 0 {
				prio = 100
			}
			localID, localName := anID, anName
			ctx.RegisterExtension(ExtAnalyzer, AnalyzerSpec{
				ID:          localID,
				PluginID:    ep.meta.ID,
				Name:        localName,
				Description: an.Description,
				Priority:    prio,
				Run: func(rctx context.Context, in *AnalyzeInput) (*AnalyzeOutput, error) {
					return ep.invokeExternalAnalyzer(rctx, cmdSpec, cfgCopy, localID, in)
				},
			})
		}

		for _, ex := range ep.manifest.Exporters {
			exID := strings.TrimSpace(ex.ID)
			if exID == "" {
				exID = ep.meta.ID + ".exporter"
			}
			exName := strings.TrimSpace(ex.Name)
			if exName == "" {
				exName = ep.meta.Name
			}
			btn := strings.TrimSpace(ex.ButtonLabel)
			if btn == "" {
				btn = exName
			}
			icon := strings.TrimSpace(ex.Icon)
			if icon == "" {
				icon = "📤"
			}
			prio := ex.Priority
			if prio == 0 {
				prio = 100
			}
			localID := exID
			ctx.RegisterExtension(ExtExporter, ExporterSpec{
				ID:          localID,
				PluginID:    ep.meta.ID,
				Name:        exName,
				ButtonLabel: btn,
				Icon:        icon,
				Description: ex.Description,
				DefaultExt:  ex.DefaultExt,
				FileFilter:  ex.FileFilter,
				IsDirectory: ex.IsDirectory,
				Priority:    prio,
				Run: func(rctx context.Context, in *ExportInput) (*ExportOutput, error) {
					return ep.invokeExternalExporter(rctx, cmdSpec, cfgCopy, localID, in)
				},
			})
		}
	}
	return nil
}

func (ep *externalPlugin) runEntrypointJSON(ctx context.Context, cmdSpec []string, payload any, timeout time.Duration) ([]byte, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	exe := cmdSpec[0]
	args := append([]string(nil), cmdSpec[1:]...)
	// Resolve relative executable inside bundleDir if present.
	if !filepath.IsAbs(exe) {
		cand := filepath.Join(ep.bundleDir, exe)
		if _, err := os.Stat(cand); err == nil {
			exe = cand
		}
	}
	for i, a := range args {
		if !filepath.IsAbs(a) && !strings.HasPrefix(a, "-") {
			cand := filepath.Join(ep.bundleDir, a)
			if _, err := os.Stat(cand); err == nil {
				args[i] = cand
			}
		}
	}

	reqBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(tctx, exe, args...)
	cmd.Dir = ep.bundleDir
	cmd.Stdin = bytes.NewReader(reqBytes)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	adb.HideConsole(cmd)

	if err := cmd.Run(); err != nil {
		errTxt := strings.TrimSpace(stderr.String())
		if errTxt == "" {
			errTxt = strings.TrimSpace(stdout.String())
		}
		if errTxt != "" {
			return nil, fmt.Errorf("external hook failed (%v): %s", err, errTxt)
		}
		return nil, fmt.Errorf("external hook failed: %w", err)
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}

func (ep *externalPlugin) invokeExternalAnalyzer(ctx context.Context, cmdSpec []string, cfg map[string]any, analyzerID string, in *AnalyzeInput) (*AnalyzeOutput, error) {
	payload := map[string]any{
		"action":      "analyze",
		"plugin_id":   ep.meta.ID,
		"analyzer_id": analyzerID,
		"config":      cfg,
		"session_id":  in.SessionID,
		"session_dir": in.SessionDir,
		"overview":    in.Overview,
	}
	outBytes, err := ep.runEntrypointJSON(ctx, cmdSpec, payload, 15*time.Second)
	if err != nil {
		return nil, err
	}
	var out AnalyzeOutput
	if err := json.Unmarshal(outBytes, &out); err != nil {
		return nil, fmt.Errorf("invalid analyzer JSON output: %w", err)
	}
	return &out, nil
}

func (ep *externalPlugin) invokeExternalExporter(ctx context.Context, cmdSpec []string, cfg map[string]any, exporterID string, in *ExportInput) (*ExportOutput, error) {
	payload := map[string]any{
		"action":      "export",
		"plugin_id":   ep.meta.ID,
		"exporter_id": exporterID,
		"config":      cfg,
		"session_id":  in.SessionID,
		"session_dir": in.SessionDir,
		"out_path":    in.OutPath,
		"params":      in.Params,
		"overview":    in.Overview,
	}
	outBytes, err := ep.runEntrypointJSON(ctx, cmdSpec, payload, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var out ExportOutput
	if err := json.Unmarshal(outBytes, &out); err != nil {
		return nil, fmt.Errorf("invalid exporter JSON output: %w", err)
	}
	if out.OutPath == "" {
		out.OutPath = in.OutPath
	}
	return &out, nil
}

func parseExternalManifest(fallbackID string, raw []byte, sourcePath string) (ExternalManifest, PluginMeta, []string, error) {
	var m ExternalManifest
	var warnings []string
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, PluginMeta{}, nil, fmt.Errorf("manifest JSON 解析失败: %w", err)
	}
	id := sanitizeID(m.ID)
	if id == "" {
		id = sanitizeID(fallbackID)
	}
	if id == "" {
		id = "ext-plugin"
	}
	if strings.HasPrefix(id, "builtin.") {
		id = "ext." + strings.TrimPrefix(id, "builtin.")
	}
	m.ID = id
	if strings.TrimSpace(m.Name) == "" {
		m.Name = id
	}
	if strings.TrimSpace(m.Version) == "" {
		m.Version = "1.0.0"
	}
	if m.Category == "" {
		m.Category = CatExternal
	}
	if strings.TrimSpace(m.Icon) == "" {
		m.Icon = "🧩"
	}

	var sfs []KernelSockField
	var qds []KernelQdisc
	if m.KernelExtensions != nil {
		sfs = append(sfs, m.KernelExtensions.SockFields...)
		qds = append(qds, m.KernelExtensions.Qdiscs...)
	}
	sfs = append(sfs, m.LegacySockFields...)
	qds = append(qds, m.LegacyQdiscs...)

	caps := []string{}
	for _, sf := range sfs {
		st := sf.Struct
		if st == "" {
			st = "sock"
		}
		if sf.Field == "" {
			warnings = append(warnings, "存在空的 sock_fields.field，已忽略")
			continue
		}
		if sf.Size != 1 && sf.Size != 2 && sf.Size != 4 && sf.Size != 8 {
			warnings = append(warnings, fmt.Sprintf("字段 %s.%s size=%d 无效（仅支持 1/2/4/8）", st, sf.Field, sf.Size))
			continue
		}
		if sf.Role == "tgid_fallback" {
			caps = append(caps, fmt.Sprintf("内核 BTF 动态读取 struct %s.%s (%dB) 作为 PID/TGID 归属兜底", st, sf.Field, sf.Size))
		} else {
			lbl := sf.Label
			if lbl == "" {
				lbl = sf.Field
			}
			caps = append(caps, fmt.Sprintf("内核 BTF 动态读取 struct %s.%s (%dB) 附加扩展标签 [%s]", st, sf.Field, sf.Size, lbl))
		}
	}
	for _, q := range qds {
		if q.Mode == "classful" {
			caps = append(caps, fmt.Sprintf("动态克隆 BPF 探针追踪分层队列 %s (%s)", strings.ToUpper(q.Kind), q.EnqueueSym))
		} else if q.Mode == "leaf" {
			caps = append(caps, fmt.Sprintf("动态克隆 BPF 探针追踪叶子队列 %s (%s / %s) 并计算驻留耗时", strings.ToUpper(q.Kind), q.EnqueueSym, q.DequeueSym))
		} else {
			warnings = append(warnings, fmt.Sprintf("qdisc %q mode=%q 非法（应为 classful 或 leaf）", q.Kind, q.Mode))
		}
	}
	for _, an := range m.Analyzers {
		caps = append(caps, fmt.Sprintf("后分析扩展「%s」：会话加载时自动产出诊断洞察与指标", an.Name))
	}
	for _, ex := range m.Exporters {
		caps = append(caps, fmt.Sprintf("导出器扩展「%s」：在工作台导出栏注册自定义导出按钮", ex.Name))
	}
	for _, u := range m.UISlots {
		caps = append(caps, fmt.Sprintf("界面插槽扩展「%s」：挂载到工作台 [%s] 区域", u.Title, u.Slot))
	}
	if m.ConfigSchema != nil && len(m.ConfigSchema.Fields) > 0 {
		caps = append(caps, fmt.Sprintf("可视化配置表单：提供 %d 个图形化可调参数", len(m.ConfigSchema.Fields)))
	}
	if len(caps) == 0 {
		warnings = append(warnings, "该插件清单未声明任何内核扩展、分析器、导出器或 UI 插槽能力")
	}

	meta := PluginMeta{
		ID:           m.ID,
		Name:         m.Name,
		Version:      m.Version,
		Author:       m.Author,
		Description:  m.Description,
		Category:     m.Category,
		Icon:         m.Icon,
		Builtin:      false,
		SourcePath:   sourcePath,
		Capabilities: caps,
		Requires:     m.Requires,
		Tags:         m.Tags,
	}
	return m, meta, warnings, nil
}

func (k *Kernel) discoverExternalPlugins() error {
	if k.host.PluginsDir == "" {
		return nil
	}
	ents, err := os.ReadDir(k.host.PluginsDir)
	if err != nil {
		return err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		full := filepath.Join(k.host.PluginsDir, name)
		if e.IsDir() {
			mfPath := filepath.Join(full, "manifest.json")
			raw, rerr := os.ReadFile(mfPath)
			if rerr != nil {
				continue
			}
			m, meta, _, perr := parseExternalManifest(name, raw, full)
			if perr != nil {
				continue
			}
			ep := &externalPlugin{bundleDir: full, manifest: m, meta: meta}
			k.registerExternalLocked(ep)
		} else if strings.HasSuffix(strings.ToLower(name), ".json") {
			raw, rerr := os.ReadFile(full)
			if rerr != nil {
				continue
			}
			base := strings.TrimSuffix(name, filepath.Ext(name))
			m, meta, _, perr := parseExternalManifest(base, raw, full)
			if perr != nil {
				continue
			}
			ep := &externalPlugin{bundleDir: k.host.PluginsDir, manifest: m, meta: meta, isFlat: true, flatFile: full}
			k.registerExternalLocked(ep)
		}
	}
	return nil
}

func (k *Kernel) registerExternalLocked(ep *externalPlugin) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if cur, exists := k.records[ep.meta.ID]; exists && cur.plugin.Meta().Builtin {
		return // never allow external bundle to shadow a built-in ID
	}
	k.orderSeq++
	k.records[ep.meta.ID] = &pluginRecord{
		plugin:         ep,
		defaultEnabled: true,
		enabled:        true,
		config:         DefaultConfig(ep.Schema()),
		order:          k.orderSeq,
	}
}

// PreviewExternal inspects a .zip/.pktplugin, folder, or .json plugin before installation.
func (k *Kernel) PreviewExternal(srcPath string, rawContent []byte, fileName string) ExternalPreview {
	prev := ExternalPreview{Capabilities: []string{}, Icon: "🧩", Category: CatExternal}
	var raw []byte
	var fallbackID string

	if len(rawContent) > 0 {
		prev.SourceType = "json"
		raw = rawContent
		fallbackID = strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))
	} else {
		if strings.TrimSpace(srcPath) == "" {
			prev.Error = "未指定插件路径或内容"
			return prev
		}
		st, err := os.Stat(srcPath)
		if err != nil {
			prev.Error = "无法读取插件路径: " + err.Error()
			return prev
		}
		if st.IsDir() {
			prev.SourceType = "folder"
			fallbackID = filepath.Base(srcPath)
			b, rerr := os.ReadFile(filepath.Join(srcPath, "manifest.json"))
			if rerr != nil {
				prev.Error = "插件目录缺少 manifest.json"
				return prev
			}
			raw = b
		} else {
			ext := strings.ToLower(filepath.Ext(srcPath))
			fallbackID = strings.TrimSuffix(filepath.Base(srcPath), ext)
			if ext == ".zip" || ext == ".pktplugin" {
				prev.SourceType = "zip"
				b, zerr := readManifestFromZip(srcPath)
				if zerr != nil {
					prev.Error = zerr.Error()
					return prev
				}
				raw = b
			} else {
				prev.SourceType = "json"
				b, rerr := os.ReadFile(srcPath)
				if rerr != nil {
					prev.Error = "读取插件文件失败: " + rerr.Error()
					return prev
				}
				raw = b
			}
		}
	}

	m, meta, warnings, err := parseExternalManifest(fallbackID, raw, srcPath)
	if err != nil {
		prev.Error = err.Error()
		return prev
	}
	ep := &externalPlugin{manifest: m, meta: meta}
	sfs, qds := ep.normalizedKernelExts()

	prev.OK = true
	prev.ID = meta.ID
	prev.Name = meta.Name
	prev.Version = meta.Version
	prev.Author = meta.Author
	prev.Description = meta.Description
	prev.Category = meta.Category
	prev.Icon = meta.Icon
	prev.Capabilities = meta.Capabilities
	prev.SockFields = sfs
	prev.Qdiscs = qds
	prev.HasEntry = m.Entrypoint != nil && len(m.Entrypoint.Command) > 0
	prev.AnalyzerCnt = len(m.Analyzers)
	prev.ExporterCnt = len(m.Exporters)
	prev.UISlotCnt = len(m.UISlots)
	if m.ConfigSchema != nil {
		prev.SchemaFields = len(m.ConfigSchema.Fields)
	}
	prev.Warnings = warnings
	return prev
}

// InstallExternal installs a .zip/.pktplugin bundle, folder bundle, or single .json into
// PluginsDir, registers it in the live microkernel, and activates it immediately.
func (k *Kernel) InstallExternal(srcPath string, rawContent []byte, fileName string) (PluginMeta, error) {
	prev := k.PreviewExternal(srcPath, rawContent, fileName)
	if !prev.OK {
		return PluginMeta{}, fmt.Errorf("%s", prev.Error)
	}
	destDir := filepath.Join(k.host.PluginsDir, prev.ID)
	// Deactivate prior version if reinstalling.
	if k.IsPluginActive(prev.ID) {
		k.deactivatePlugin(prev.ID)
	}
	_ = os.RemoveAll(destDir)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return PluginMeta{}, err
	}

	switch prev.SourceType {
	case "zip":
		if err := extractZipBundle(srcPath, destDir); err != nil {
			_ = os.RemoveAll(destDir)
			return PluginMeta{}, err
		}
	case "folder":
		if err := copyDirRecursive(srcPath, destDir); err != nil {
			_ = os.RemoveAll(destDir)
			return PluginMeta{}, err
		}
	default: // json
		var raw []byte
		if len(rawContent) > 0 {
			raw = rawContent
		} else {
			var err error
			raw, err = os.ReadFile(srcPath)
			if err != nil {
				_ = os.RemoveAll(destDir)
				return PluginMeta{}, err
			}
		}
		if err := os.WriteFile(filepath.Join(destDir, "manifest.json"), raw, 0o644); err != nil {
			_ = os.RemoveAll(destDir)
			return PluginMeta{}, err
		}
	}

	mfBytes, err := os.ReadFile(filepath.Join(destDir, "manifest.json"))
	if err != nil {
		_ = os.RemoveAll(destDir)
		return PluginMeta{}, fmt.Errorf("安装后缺少 manifest.json: %w", err)
	}
	m, meta, _, err := parseExternalManifest(prev.ID, mfBytes, destDir)
	if err != nil {
		_ = os.RemoveAll(destDir)
		return PluginMeta{}, err
	}
	ep := &externalPlugin{bundleDir: destDir, manifest: m, meta: meta}
	k.registerExternalLocked(ep)
	if err := k.activatePlugin(meta.ID); err != nil {
		_ = k.savePersistedConfig()
		k.notifyChange()
		return meta, err
	}
	_ = k.savePersistedConfig()
	k.notifyChange()
	return meta, nil
}

// UninstallExternal disposes and permanently removes an external plugin.
func (k *Kernel) UninstallExternal(id string) error {
	k.mu.Lock()
	rec, ok := k.records[id]
	if !ok {
		k.mu.Unlock()
		return fmt.Errorf("plugin not found: %s", id)
	}
	if rec.plugin.Meta().Builtin {
		k.mu.Unlock()
		return fmt.Errorf("内置插件不可卸载（可在插件中心随时关闭）")
	}
	ep, _ := rec.plugin.(*externalPlugin)
	k.mu.Unlock()

	k.deactivatePlugin(id)

	k.mu.Lock()
	delete(k.records, id)
	k.mu.Unlock()

	if ep != nil {
		if ep.isFlat && ep.flatFile != "" {
			_ = os.Remove(ep.flatFile)
		} else if ep.bundleDir != "" {
			_ = os.RemoveAll(ep.bundleDir)
		}
	}
	_ = k.savePersistedConfig()
	k.notifyChange()
	return nil
}

// ResolvePluginAsset safely resolves a static asset inside an external plugin bundle.
func (k *Kernel) ResolvePluginAsset(pluginID, relPath string) (string, error) {
	k.mu.RLock()
	rec, ok := k.records[pluginID]
	k.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("plugin not found")
	}
	ep, ok := rec.plugin.(*externalPlugin)
	if !ok || ep.bundleDir == "" {
		return "", fmt.Errorf("plugin has no bundle directory")
	}
	cleanRel := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(relPath, "/")))
	if cleanRel == "." || strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
		return "", fmt.Errorf("invalid asset path")
	}
	full := filepath.Join(ep.bundleDir, cleanRel)
	relCheck, err := filepath.Rel(ep.bundleDir, full)
	if err != nil || strings.HasPrefix(relCheck, "..") {
		return "", fmt.Errorf("path escapes bundle directory")
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		return "", fmt.Errorf("asset not found")
	}
	return full, nil
}

func readManifestFromZip(zipPath string) ([]byte, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("无法打开插件压缩包: %w", err)
	}
	defer zr.Close()

	// Find manifest.json at root or one level deep.
	var best *zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		norm := strings.TrimPrefix(filepath.ToSlash(f.Name), "./")
		parts := strings.Split(norm, "/")
		if norm == "manifest.json" {
			best = f
			break
		}
		if len(parts) == 2 && parts[1] == "manifest.json" && best == nil {
			best = f
		}
	}
	if best == nil {
		return nil, fmt.Errorf("压缩包中未找到 manifest.json")
	}
	rc, err := best.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, 2*1024*1024))
}

func extractZipBundle(zipPath, destDir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	// Detect optional single top-level wrapper folder.
	stripPrefix := ""
	for _, f := range zr.File {
		norm := strings.TrimPrefix(filepath.ToSlash(f.Name), "./")
		if norm == "manifest.json" {
			stripPrefix = ""
			break
		}
		parts := strings.Split(norm, "/")
		if len(parts) == 2 && parts[1] == "manifest.json" {
			stripPrefix = parts[0] + "/"
		}
	}

	cleanDest := filepath.Clean(destDir)
	for _, f := range zr.File {
		norm := strings.TrimPrefix(filepath.ToSlash(f.Name), "./")
		if stripPrefix != "" {
			if !strings.HasPrefix(norm, stripPrefix) {
				continue
			}
			norm = strings.TrimPrefix(norm, stripPrefix)
		}
		if norm == "" {
			continue
		}
		target := filepath.Join(cleanDest, filepath.FromSlash(norm))
		rel, rerr := filepath.Rel(cleanDest, target)
		if rerr != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("unsafe zip entry path: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(rc, 32*1024*1024))
		rc.Close()
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func copyDirRecursive(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}
