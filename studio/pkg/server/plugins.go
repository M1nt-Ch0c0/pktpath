package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const pluginStateFile = ".plugins_state.json"

// PluginSockField describes one BTF-resolved struct sock field declared in a plugin JSON.
type PluginSockField struct {
	Struct  string `json:"struct"`
	Field   string `json:"field"`
	Size    int    `json:"size"`
	Role    string `json:"role"`
	Label   string `json:"label"`
	Summary string `json:"summary"`
}

// PluginQdisc describes one custom TC qdisc hook declared in a plugin JSON.
type PluginQdisc struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Mode       string `json:"mode"` // classful | leaf
	EnqueueSym string `json:"enqueue_sym"`
	DequeueSym string `json:"dequeue_sym,omitempty"`
	Summary    string `json:"summary"`
}

// PluginDetail is the rich capability summary of one installed or previewed plugin.
type PluginDetail struct {
	ID             string            `json:"id"`
	File           string            `json:"file"`
	Name           string            `json:"name"`
	Version        string            `json:"version,omitempty"`
	Description    string            `json:"description,omitempty"`
	Enabled        bool              `json:"enabled"`
	SockFields     int               `json:"sock_fields"`
	Qdiscs         int               `json:"qdiscs"`
	SockFieldSpecs []PluginSockField `json:"sock_field_specs"`
	QdiscSpecs     []PluginQdisc     `json:"qdisc_specs"`
	Capabilities   []string          `json:"capabilities"`
	Warnings       []string          `json:"warnings,omitempty"`
	Error          string            `json:"error,omitempty"`
}

// PluginSlots reports current BPF runtime slot consumption across enabled plugins.
type PluginSlots struct {
	SockUsed     int `json:"sock_used"`
	SockMax      int `json:"sock_max"`
	ClassfulUsed int `json:"classful_used"`
	ClassfulMax  int `json:"classful_max"`
	LeafUsed     int `json:"leaf_used"`
	LeafMax      int `json:"leaf_max"`
	EnabledCount int `json:"enabled_count"`
	TotalCount   int `json:"total_count"`
}

type pluginState struct {
	Disabled map[string]bool `json:"disabled"`
}

func (s *Server) readPluginState() pluginState {
	st := pluginState{Disabled: map[string]bool{}}
	b, err := os.ReadFile(filepath.Join(s.pluginsDir, pluginStateFile))
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	if st.Disabled == nil {
		st.Disabled = map[string]bool{}
	}
	return st
}

func (s *Server) writePluginState(st pluginState) error {
	if st.Disabled == nil {
		st.Disabled = map[string]bool{}
	}
	_ = os.MkdirAll(s.pluginsDir, 0o755)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(s.pluginsDir, pluginStateFile)
	tmp := fmt.Sprintf("%s.%d.tmp", p, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// parsePluginManifest validates raw JSON and generates human-readable capability summaries.
func parsePluginManifest(fileName string, rawBytes []byte, enabled bool) PluginDetail {
	baseID := strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))
	pd := PluginDetail{
		ID:             baseID,
		File:           filepath.Base(fileName),
		Name:           baseID,
		Enabled:        enabled,
		SockFieldSpecs: []PluginSockField{},
		QdiscSpecs:     []PluginQdisc{},
		Capabilities:   []string{},
	}

	var doc struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
		SockFields  []struct {
			Struct string `json:"struct"`
			Field  string `json:"field"`
			Size   int    `json:"size"`
			Role   string `json:"role"`
			Label  string `json:"label"`
		} `json:"sock_fields"`
		Qdiscs []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Kind       string `json:"kind"`
			Mode       string `json:"mode"`
			EnqueueSym string `json:"enqueue_sym"`
			DequeueSym string `json:"dequeue_sym"`
		} `json:"qdiscs"`
	}
	if err := json.Unmarshal(rawBytes, &doc); err != nil {
		pd.Error = "JSON 解析失败: " + err.Error()
		return pd
	}
	if strings.TrimSpace(doc.ID) != "" {
		pd.ID = strings.TrimSpace(doc.ID)
	}
	if strings.TrimSpace(doc.Name) != "" {
		pd.Name = strings.TrimSpace(doc.Name)
	}
	pd.Version = strings.TrimSpace(doc.Version)
	pd.Description = strings.TrimSpace(doc.Description)

	for _, sf := range doc.SockFields {
		stName := strings.TrimSpace(sf.Struct)
		if stName == "" {
			stName = "sock"
		}
		fld := strings.TrimSpace(sf.Field)
		if fld == "" {
			pd.Warnings = append(pd.Warnings, "存在空的 sock_fields.field，加载时将被跳过")
			continue
		}
		sz := sf.Size
		if sz != 1 && sz != 2 && sz != 4 && sz != 8 {
			pd.Warnings = append(pd.Warnings, fmt.Sprintf("字段 %s.%s 的 size=%d 非法（仅支持 1/2/4/8）", stName, fld, sz))
			continue
		}
		role := strings.ToLower(strings.TrimSpace(sf.Role))
		if role == "" {
			role = "tag"
		}
		lbl := strings.TrimSpace(sf.Label)
		if lbl == "" {
			lbl = fld
		}
		var sum string
		if role == "tgid_fallback" {
			sum = fmt.Sprintf("通过内核 BTF 动态读取 struct %s.%s (%dB)，当标准归属缺失时作为进程 PID/TGID 兜底来源", stName, fld, sz)
		} else {
			role = "tag"
			sum = fmt.Sprintf("通过内核 BTF 动态读取 struct %s.%s (%dB)，为每个样本附加扩展标签 [%s]", stName, fld, sz, lbl)
		}
		pd.SockFieldSpecs = append(pd.SockFieldSpecs, PluginSockField{
			Struct:  stName,
			Field:   fld,
			Size:    sz,
			Role:    role,
			Label:   lbl,
			Summary: sum,
		})
		pd.Capabilities = append(pd.Capabilities, sum)
	}

	for _, q := range doc.Qdiscs {
		id := strings.TrimSpace(q.ID)
		kind := strings.TrimSpace(q.Kind)
		mode := strings.ToLower(strings.TrimSpace(q.Mode))
		enq := strings.TrimSpace(q.EnqueueSym)
		deq := strings.TrimSpace(q.DequeueSym)
		name := strings.TrimSpace(q.Name)
		if kind == "" {
			kind = id
		}
		if id == "" {
			id = kind
		}
		if name == "" {
			name = strings.ToUpper(kind) + " Custom Qdisc"
		}
		if mode != "classful" && mode != "leaf" {
			pd.Warnings = append(pd.Warnings, fmt.Sprintf("队列 %s 的 mode=%q 非法（应为 classful 或 leaf）", id, q.Mode))
			continue
		}
		if enq == "" {
			pd.Warnings = append(pd.Warnings, fmt.Sprintf("队列 %s 缺少 enqueue_sym", id))
			continue
		}
		if mode == "leaf" && deq == "" {
			pd.Warnings = append(pd.Warnings, fmt.Sprintf("叶子队列 %s 缺少 dequeue_sym（无法计算驻留耗时）", id))
			continue
		}
		var sum string
		if mode == "classful" {
			sum = fmt.Sprintf("追踪自定义分层队列 %s (classful)：挂钩 %s，记录入队分类路径", strings.ToUpper(kind), enq)
		} else {
			sum = fmt.Sprintf("追踪自定义叶子队列 %s (leaf)：挂钩 %s / %s，精确测量单包排队驻留耗时", strings.ToUpper(kind), enq, deq)
		}
		pd.QdiscSpecs = append(pd.QdiscSpecs, PluginQdisc{
			ID:         id,
			Name:       name,
			Kind:       kind,
			Mode:       mode,
			EnqueueSym: enq,
			DequeueSym: deq,
			Summary:    sum,
		})
		pd.Capabilities = append(pd.Capabilities, sum)
	}

	pd.SockFields = len(pd.SockFieldSpecs)
	pd.Qdiscs = len(pd.QdiscSpecs)
	if pd.SockFields == 0 && pd.Qdiscs == 0 && pd.Error == "" {
		pd.Warnings = append(pd.Warnings, "该 JSON 未声明任何有效的 sock_fields 或 qdiscs 能力")
	}
	return pd
}

func (s *Server) listPluginsDetailed() ([]PluginDetail, PluginSlots) {
	st := s.readPluginState()
	list := []PluginDetail{}
	slots := PluginSlots{SockMax: 16, ClassfulMax: 32, LeafMax: 32}

	ents, err := os.ReadDir(s.pluginsDir)
	if err != nil {
		return list, slots
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		enabled := !st.Disabled[name]
		b, rerr := os.ReadFile(filepath.Join(s.pluginsDir, name))
		var pd PluginDetail
		if rerr != nil {
			pd = PluginDetail{
				ID:             strings.TrimSuffix(name, filepath.Ext(name)),
				File:           name,
				Name:           name,
				Enabled:        enabled,
				SockFieldSpecs: []PluginSockField{},
				QdiscSpecs:     []PluginQdisc{},
				Capabilities:   []string{},
				Error:          rerr.Error(),
			}
		} else {
			pd = parsePluginManifest(name, b, enabled)
		}
		slots.TotalCount++
		if enabled && pd.Error == "" {
			slots.EnabledCount++
			slots.SockUsed += len(pd.SockFieldSpecs)
			for _, q := range pd.QdiscSpecs {
				if q.Mode == "classful" {
					slots.ClassfulUsed++
				} else if q.Mode == "leaf" {
					slots.LeafUsed++
				}
			}
		}
		list = append(list, pd)
	}
	return list, slots
}

// enabledPluginPaths returns absolute paths of all valid enabled *.json plugins.
func (s *Server) enabledPluginPaths() []string {
	list, _ := s.listPluginsDetailed()
	var out []string
	for _, p := range list {
		if p.Enabled && p.Error == "" {
			out = append(out, filepath.Join(s.pluginsDir, p.File))
		}
	}
	return out
}

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	list, slots := s.listPluginsDetailed()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"plugins_dir": s.pluginsDir,
		"plugins":     list,
		"slots":       slots,
	})
}

func (s *Server) handlePluginsPreview(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rawPath := b.str("path")
	content := b.str("content")
	fileName := b.str("filename")

	var raw []byte
	if rawPath != "" {
		raw, err = os.ReadFile(rawPath)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "读取插件文件失败: "+err.Error())
			return
		}
		if fileName == "" {
			fileName = filepath.Base(rawPath)
		}
	} else if content != "" {
		raw = []byte(content)
		if fileName == "" {
			fileName = "custom_plugin.json"
		}
	} else {
		writeErr(w, http.StatusBadRequest, "missing path or content")
		return
	}

	pd := parsePluginManifest(fileName, raw, true)
	_, curSlots := s.listPluginsDetailed()
	if curSlots.SockUsed+len(pd.SockFieldSpecs) > curSlots.SockMax {
		pd.Warnings = append(pd.Warnings, fmt.Sprintf("导入后 Socket 字段槽位将超出上限 (%d+%d > %d)", curSlots.SockUsed, len(pd.SockFieldSpecs), curSlots.SockMax))
	}
	clsAdd, leafAdd := 0, 0
	for _, q := range pd.QdiscSpecs {
		if q.Mode == "classful" {
			clsAdd++
		} else {
			leafAdd++
		}
	}
	if curSlots.ClassfulUsed+clsAdd > curSlots.ClassfulMax {
		pd.Warnings = append(pd.Warnings, fmt.Sprintf("导入后 Classful 队列槽位将超出上限 (%d+%d > %d)", curSlots.ClassfulUsed, clsAdd, curSlots.ClassfulMax))
	}
	if curSlots.LeafUsed+leafAdd > curSlots.LeafMax {
		pd.Warnings = append(pd.Warnings, fmt.Sprintf("导入后 Leaf 队列槽位将超出上限 (%d+%d > %d)", curSlots.LeafUsed, leafAdd, curSlots.LeafMax))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     pd.Error == "",
		"plugin": pd,
		"slots":  curSlots,
		"error":  pd.Error,
	})
}

func (s *Server) handlePluginsImport(w http.ResponseWriter, r *http.Request) {
	// Legacy APIs must not bypass a candidate task's package lease.
	if s.kernel != nil && s.kernel.Host().AnalyzerHost != nil {
		release, err := s.kernel.Host().AnalyzerHost.ProtectPackageMutation()
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		defer release()
	}

	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rawPath := b.str("path")
	content := b.str("content")
	fileName := b.str("filename")

	var raw []byte
	if rawPath != "" {
		raw, err = os.ReadFile(rawPath)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "读取插件文件失败: "+err.Error())
			return
		}
		if fileName == "" {
			fileName = filepath.Base(rawPath)
		}
	} else if content != "" {
		raw = []byte(content)
		if fileName == "" {
			fileName = "custom_plugin.json"
		}
	} else {
		writeErr(w, http.StatusBadRequest, "missing path or content")
		return
	}

	safeName := sanitizeName(filepath.Base(fileName))
	if safeName == "" {
		safeName = "plugin.json"
	}
	if !strings.HasSuffix(strings.ToLower(safeName), ".json") {
		safeName += ".json"
	}

	pd := parsePluginManifest(safeName, raw, true)
	if pd.Error != "" {
		writeErr(w, http.StatusBadRequest, pd.Error)
		return
	}
	if err := os.MkdirAll(s.pluginsDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建插件目录失败: "+err.Error())
		return
	}
	dst := filepath.Join(s.pluginsDir, safeName)
	if err := os.WriteFile(dst, raw, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存插件失败: "+err.Error())
		return
	}
	// Ensure newly imported plugin is enabled.
	st := s.readPluginState()
	delete(st.Disabled, safeName)
	_ = s.writePluginState(st)

	list, slots := s.listPluginsDetailed()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"imported":    pd,
		"plugins_dir": s.pluginsDir,
		"plugins":     list,
		"slots":       slots,
	})
}

func (s *Server) handlePluginsToggle(w http.ResponseWriter, r *http.Request) {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	file := filepath.Base(b.str("file"))
	if file == "" || file == "." || file == ".." || !strings.HasSuffix(strings.ToLower(file), ".json") {
		writeErr(w, http.StatusBadRequest, "invalid plugin file")
		return
	}
	if _, err := os.Stat(filepath.Join(s.pluginsDir, file)); err != nil {
		writeErr(w, http.StatusNotFound, "plugin not found: "+file)
		return
	}
	enabled := b.bool("enabled")
	st := s.readPluginState()
	if enabled {
		delete(st.Disabled, file)
	} else {
		st.Disabled[file] = true
	}
	if err := s.writePluginState(st); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	list, slots := s.listPluginsDetailed()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"file":    file,
		"enabled": enabled,
		"plugins": list,
		"slots":   slots,
	})
}

func (s *Server) handlePluginsDelete(w http.ResponseWriter, r *http.Request) {
	// Legacy APIs must not bypass a candidate task's package lease.
	if s.kernel != nil && s.kernel.Host().AnalyzerHost != nil {
		release, err := s.kernel.Host().AnalyzerHost.ProtectPackageMutation()
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		defer release()
	}

	b, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	file := filepath.Base(b.str("file"))
	if file == "" || file == "." || file == ".." || !strings.HasSuffix(strings.ToLower(file), ".json") {
		writeErr(w, http.StatusBadRequest, "invalid plugin file")
		return
	}
	p := filepath.Join(s.pluginsDir, file)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st := s.readPluginState()
	delete(st.Disabled, file)
	_ = s.writePluginState(st)

	list, slots := s.listPluginsDetailed()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"deleted": file,
		"plugins": list,
		"slots":   slots,
	})
}
