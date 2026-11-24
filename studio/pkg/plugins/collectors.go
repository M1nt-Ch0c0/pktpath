package plugins

import (
	"fmt"
	"strings"

	"pktpath/studio/pkg/kernel"
)

// ---- 4. Linux eBPF TC/Qdisc Collector ----

type ebpfTCCollector struct{}

func (p *ebpfTCCollector) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.collector.ebpf-tc",
		Name:        "eBPF 队列采集",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "采集网卡 TC/Qdisc 队列路径、驻留耗时与发包结果。",
		Category:    kernel.CatCollector,
		Icon:        "⚡",
		Builtin:     true,
		Capabilities: []string{
			"探测网卡与 TC qdisc/class 队列拓扑",
			"提供应用/协议/端口/IP 过滤与内核 eBPF 采集",
		},
		Provides: []string{"collector.ebpf"},
		Tags:     []string{"ebpf", "btf", "tc", "qdisc"},
	}
}

func (p *ebpfTCCollector) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "default_scope",
				Label:   "默认观测范围",
				Type:    kernel.FieldSelect,
				Default: "tc-egress",
				Options: []kernel.FieldOption{
					{Value: "tc-egress", Label: "tc-egress（TC 出口队列）"},
					{Value: "ip-tx", Label: "ip-tx（IP 发包）"},
					{Value: "sock-tx", Label: "sock-tx（Socket 发包）"},
					{Value: "fwd", Label: "fwd（路由转发）"},
				},
			},
			{
				Key:     "capture_hdr_bytes",
				Label:   "包头截取长度",
				Type:    kernel.FieldNumber,
				Default: float64(96),
				Min:     kernel.FloatPtr(0),
				Max:     kernel.FloatPtr(128),
				Step:    kernel.FloatPtr(8),
				Unit:    "B",
			},
			{
				Key:     "profile_sendmsg",
				Label:   "启用 sendmsg 线程与创建时间追踪",
				Type:    kernel.FieldBoolean,
				Default: false,
			},
			{
				Key:     "allow_partial",
				Label:   "部分符号缺失时允许降级采集",
				Type:    kernel.FieldBoolean,
				Default: true,
			},
			{
				Key:     "enable_kernel_exts",
				Label:   "采集时启用自定义内核扩展",
				Type:    kernel.FieldBoolean,
				Default: true,
			},
		},
	}
}

func (p *ebpfTCCollector) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	spec := kernel.CollectorSpec{
		ID:               "ebpf-tc",
		PluginID:         p.Meta().ID,
		Name:             p.Meta().Name,
		DefaultScope:     kernel.ConfigString(cfg, "default_scope", "tc-egress"),
		DefaultDuration:  10,
		DefaultSample:    "1/1",
		CaptureHdrBytes:  kernel.ConfigInt(cfg, "capture_hdr_bytes", 96),
		ProfileSendmsg:   kernel.ConfigBool(cfg, "profile_sendmsg", false),
		AllowPartial:     kernel.ConfigBool(cfg, "allow_partial", true),
		EnableKernelExts: kernel.ConfigBool(cfg, "enable_kernel_exts", true),
	}
	ctx.Provide("collector.ebpf", spec)
	ctx.RegisterExtension(kernel.ExtCollector, spec)
	return nil
}

// ---- 5. Dynamic Kernel Extensions (BTF sock fields + custom TC qdiscs) ----

type kernelExtBuilder struct{}

func (p *kernelExtBuilder) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.collector.kernel-ext",
		Name:        "自定义内核扩展",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "添加额外 struct sock BTF 字段或自定义 TC 队列探针。",
		Category:    kernel.CatCollector,
		Icon:        "🧬",
		Builtin:     true,
		Capabilities: []string{
			"按 BTF 动态读取最多 16 个 struct sock 字段",
			"按符号名动态克隆最多 32 个自定义 TC qdisc 探针",
		},
		Requires: []string{"collector.ebpf"},
		Provides: []string{"kernel.ext.builder"},
		Tags:     []string{"btf", "sock", "qdisc"},
	}
}

func (p *kernelExtBuilder) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:       "sock_fields",
				Label:     "Socket 字段 (BTF)",
				Type:      kernel.FieldList,
				ItemLabel: "字段",
				ItemFields: []kernel.FieldSchema{
					{Key: "struct", Label: "结构体", Type: kernel.FieldString, Default: "sock", Placeholder: "sock", Required: true},
					{Key: "field", Label: "字段路径", Type: kernel.FieldString, Placeholder: "sk_mark", Required: true},
					{
						Key:     "size",
						Label:   "宽度",
						Type:    kernel.FieldSelect,
						Default: "4",
						Options: []kernel.FieldOption{
							{Value: "1", Label: "1 B"},
							{Value: "2", Label: "2 B"},
							{Value: "4", Label: "4 B"},
							{Value: "8", Label: "8 B"},
						},
					},
					{
						Key:     "role",
						Label:   "用途",
						Type:    kernel.FieldSelect,
						Default: "tag",
						Options: []kernel.FieldOption{
							{Value: "tag", Label: "样本标签"},
							{Value: "tgid_fallback", Label: "PID 兜底"},
						},
					},
					{Key: "label", Label: "显示名", Type: kernel.FieldString, Placeholder: "sock_mark"},
				},
			},
			{
				Key:       "qdiscs",
				Label:     "自定义 TC 队列",
				Type:      kernel.FieldList,
				ItemLabel: "队列",
				ItemFields: []kernel.FieldSchema{
					{Key: "kind", Label: "队列 kind", Type: kernel.FieldString, Placeholder: "netem / tbf / fq", Required: true},
					{Key: "name", Label: "显示名", Type: kernel.FieldString, Placeholder: "NetEm"},
					{
						Key:     "mode",
						Label:   "类型",
						Type:    kernel.FieldSelect,
						Default: "leaf",
						Options: []kernel.FieldOption{
							{Value: "leaf", Label: "叶子队列 (leaf)"},
							{Value: "classful", Label: "分类队列 (classful)"},
						},
					},
					{Key: "enqueue_sym", Label: "入队符号", Type: kernel.FieldString, Placeholder: "netem_enqueue", Required: true},
					{Key: "dequeue_sym", Label: "出队符号", Type: kernel.FieldString, Placeholder: "netem_dequeue"},
				},
			},
		},
	}
}

func (p *kernelExtBuilder) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	var sfs []kernel.KernelSockField
	for _, row := range kernel.ConfigListMaps(cfg, "sock_fields") {
		fld := kernel.ConfigString(row, "field", "")
		if fld == "" {
			continue
		}
		sz := kernel.ConfigInt(row, "size", 4)
		if sz != 1 && sz != 2 && sz != 4 && sz != 8 {
			return fmt.Errorf("字段 %s 宽度 %d 无效（仅支持 1/2/4/8）", fld, sz)
		}
		sfs = append(sfs, kernel.KernelSockField{
			Struct: kernel.ConfigString(row, "struct", "sock"),
			Field:  fld,
			Size:   sz,
			Role:   kernel.ConfigString(row, "role", "tag"),
			Label:  kernel.ConfigString(row, "label", fld),
		})
	}

	var qds []kernel.KernelQdisc
	for idx, row := range kernel.ConfigListMaps(cfg, "qdiscs") {
		kind := strings.ToLower(kernel.ConfigString(row, "kind", ""))
		enq := kernel.ConfigString(row, "enqueue_sym", "")
		deq := kernel.ConfigString(row, "dequeue_sym", "")
		mode := strings.ToLower(kernel.ConfigString(row, "mode", "leaf"))
		if kind == "" || enq == "" {
			continue
		}
		if mode == "leaf" && deq == "" {
			return fmt.Errorf("叶子队列 %s 缺少出队符号", kind)
		}
		qds = append(qds, kernel.KernelQdisc{
			ID:         fmt.Sprintf("gui_%s_%d", kind, idx),
			Name:       kernel.ConfigString(row, "name", strings.ToUpper(kind)),
			Kind:       kind,
			Mode:       mode,
			EnqueueSym: enq,
			DequeueSym: deq,
		})
	}

	ctx.Provide("kernel.ext.builder", map[string]int{"sock_fields": len(sfs), "qdiscs": len(qds)})
	if len(sfs) > 0 || len(qds) > 0 {
		ctx.RegisterExtension(kernel.ExtKernelExt, kernel.KernelExtSpec{
			ID:         p.Meta().ID,
			PluginID:   p.Meta().ID,
			Name:       p.Meta().Name,
			SockFields: sfs,
			Qdiscs:     qds,
		})
	}
	return nil
}
