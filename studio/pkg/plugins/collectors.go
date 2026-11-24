package plugins

import (
	"fmt"
	"strings"

	"pktpath/studio/pkg/kernel"
)

// ---- 4. Linux eBPF TC / Qdisc Core Collector Plugin ----

type ebpfTCCollector struct{}

func (p *ebpfTCCollector) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.collector.ebpf-tc",
		Name:        "Linux eBPF TC/Qdisc 核心采集引擎",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "内置零私有依赖的上游 Linux eBPF 采集核心：利用内核 BTF 自动解析结构体偏移，追踪 HTB / fq_codel / pfifo / bfifo / SFQ、SKB 克隆派生与 TXQ 背压。",
		Category:    kernel.CatCollector,
		Icon:        "⚡",
		Builtin:     true,
		Capabilities: []string{
			"内核 BTF 自动解析，跨内核版本免编译运行（支持 arm64 与 x86_64）",
			"原生追踪 TC/Qdisc 入出队耗时、驱动 TXQ 阻塞背压与 SKB Clone/Expand 血缘",
			"支持短时复现（oneshot）与异常触发环形缓存（daemon）两种采集模式",
			"所有采集默认参数可在此处图形化统一配置并立即同步到工作台",
		},
		Provides: []string{"collector.ebpf"},
		Tags:     []string{"ebpf", "btf", "tc", "qdisc", "core"},
	}
}

func (p *ebpfTCCollector) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "eBPF 采集默认参数",
		Description: "配置工作台采集表单的默认值，避免每次采集重复勾选。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "default_scope",
				Label:       "默认采集观测范围 (Scope)",
				Type:        kernel.FieldSelect,
				Default:     "tc-egress",
				Description: "tc-egress 为最推荐的零开销队列路径追踪范围。",
				Options: []kernel.FieldOption{
					{Value: "tc-egress", Label: "tc-egress（TC 队列到驱动发包，推荐）"},
					{Value: "ip-tx", Label: "ip-tx（IP 发包到驱动）"},
					{Value: "sock-tx", Label: "sock-tx（Socket 发送到驱动）"},
					{Value: "fwd", Label: "fwd（路由转发路径）"},
				},
			},
			{
				Key:         "default_duration_sec",
				Label:       "短时复现默认采集时长",
				Type:        kernel.FieldNumber,
				Default:     float64(10),
				Min:         kernel.FloatPtr(1),
				Max:         kernel.FloatPtr(600),
				Step:        kernel.FloatPtr(1),
				Unit:        "秒",
			},
			{
				Key:         "default_sample",
				Label:       "默认抽样比例",
				Type:        kernel.FieldSelect,
				Default:     "1/1",
				Options: []kernel.FieldOption{
					{Value: "1/1", Label: "全量 1/1（精确复现）"},
					{Value: "1/10", Label: "抽样 1/10（高吞吐场景）"},
					{Value: "1/100", Label: "抽样 1/100（超高速压测）"},
				},
			},
			{
				Key:         "capture_hdr_bytes",
				Label:       "抓包包头截取长度（用于导出 Wireshark .pcapng）",
				Type:        kernel.FieldNumber,
				Default:     float64(96),
				Min:         kernel.FloatPtr(0),
				Max:         kernel.FloatPtr(128),
				Step:        kernel.FloatPtr(8),
				Unit:        "字节",
			},
			{
				Key:         "profile_sendmsg",
				Label:       "默认启用 sendmsg 精确线程 TID 剖析",
				Description: "开启后增加 tcp_sendmsg / udp_sendmsg kprobe，略增 CPU 开销。",
				Type:        kernel.FieldBoolean,
				Default:     false,
			},
			{
				Key:         "allow_partial",
				Label:       "符号缺失时允许降级采集（allow-partial）",
				Description: "当目标内核裁剪或内联了部分可选符号时仍继续采集。",
				Type:        kernel.FieldBoolean,
				Default:     true,
			},
			{
				Key:         "enable_kernel_exts",
				Label:       "采集时自动注入所有已启用的内核扩展插件",
				Description: "自动将动态 BTF 字段与自定义 qdisc 探针下发至采集器。",
				Type:        kernel.FieldBoolean,
				Default:     true,
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
		DefaultDuration:  kernel.ConfigInt(cfg, "default_duration_sec", 10),
		DefaultSample:    kernel.ConfigString(cfg, "default_sample", "1/1"),
		CaptureHdrBytes:  kernel.ConfigInt(cfg, "capture_hdr_bytes", 96),
		ProfileSendmsg:   kernel.ConfigBool(cfg, "profile_sendmsg", false),
		AllowPartial:     kernel.ConfigBool(cfg, "allow_partial", true),
		EnableKernelExts: kernel.ConfigBool(cfg, "enable_kernel_exts", true),
	}
	ctx.Provide("collector.ebpf", spec)
	ctx.RegisterExtension(kernel.ExtCollector, spec)
	return nil
}

// ---- 5. Visual Dynamic Kernel Extension Builder Plugin (Zero JSON!) ----

type kernelExtBuilder struct{}

func (p *kernelExtBuilder) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.collector.kernel-ext",
		Name:        "内核 BTF 与自定义队列可视化构建器",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "无需手写 JSON！直接在下方图形化卡片中添加任意 `struct sock` BTF 字段（最多 16 个）或任意自定义 TC qdisc 队列探针（动态克隆，最多 32 个并发），保存即刻生效。",
		Category:    kernel.CatCollector,
		Icon:        "🧬",
		Builtin:     true,
		Capabilities: []string{
			"图形化配置任意 struct sock 内核字段（支持点号嵌套，运行时通过 /sys/kernel/btf/vmlinux 自动求偏移）",
			"图形化配置任意自定义 TC qdisc 探针（classful 分层队列或 leaf 叶子队列，自动动态克隆 BPF 字节码模板）",
			"零手写 JSON、零重新编译：保存后下一次设备检测或采集立即生效",
		},
		Requires: []string{"collector.ebpf"},
		Provides: []string{"kernel.ext.builder"},
		Tags:     []string{"btf", "sock", "qdisc", "dynamic", "no-code"},
	}
}

func (p *kernelExtBuilder) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "可视化内核扩展规则（零 JSON）",
		Description: "点击「＋ 新增」即可添加任意内核结构体字段或自定义 TC 队列挂钩，保存后自动合成并下发给采集器。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "sock_fields",
				Label:       "自定义 Socket (BTF) 观测字段",
				Description: "通过内核 BTF 动态读取 struct sock 任意字段（如 sk_mark、sk_priority 或私有扩展字段），单次采集最多同时生效 16 个。",
				Type:        kernel.FieldList,
				ItemLabel:   "Socket 字段",
				ItemFields: []kernel.FieldSchema{
					{
						Key:         "struct",
						Label:       "结构体名",
						Type:        kernel.FieldString,
						Default:     "sock",
						Placeholder: "sock",
						Required:    true,
					},
					{
						Key:         "field",
						Label:       "字段路径（支持嵌套）",
						Type:        kernel.FieldString,
						Placeholder: "例如 sk_mark 或 __sk_common.skc_bound_dev_if",
						Required:    true,
					},
					{
						Key:     "size",
						Label:   "字节宽度",
						Type:    kernel.FieldSelect,
						Default: "4",
						Options: []kernel.FieldOption{
							{Value: "1", Label: "1 字节 (u8)"},
							{Value: "2", Label: "2 字节 (u16)"},
							{Value: "4", Label: "4 字节 (u32)"},
							{Value: "8", Label: "8 字节 (u64)"},
						},
					},
					{
						Key:     "role",
						Label:   "字段用途",
						Type:    kernel.FieldSelect,
						Default: "tag",
						Options: []kernel.FieldOption{
							{Value: "tag", Label: "附加到样本扩展标签 (tag)"},
							{Value: "tgid_fallback", Label: "标准归属缺失时作 PID/TGID 兜底"},
						},
					},
					{
						Key:         "label",
						Label:       "界面展示标签名",
						Type:        kernel.FieldString,
						Placeholder: "例如 sock_mark",
					},
				},
			},
			{
				Key:         "qdiscs",
				Label:       "自定义 TC Qdisc 队列探针（动态克隆，突破固定槽位）",
				Description: "填写目标队列的内核 enqueue / dequeue 符号名，采集器运行时自动动态克隆 BPF 模板并补丁 site_id（支持最多 32 个并发自定义队列）。",
				Type:        kernel.FieldList,
				ItemLabel:   "自定义队列",
				ItemFields: []kernel.FieldSchema{
					{
						Key:         "kind",
						Label:       "TC 队列类型 (kind)",
						Type:        kernel.FieldString,
						Placeholder: "例如 netem / tbf / fq / prio",
						Required:    true,
					},
					{
						Key:         "name",
						Label:       "显示名称",
						Type:        kernel.FieldString,
						Placeholder: "例如 NetEm Delay Emulator",
					},
					{
						Key:     "mode",
						Label:   "队列角色",
						Type:    kernel.FieldSelect,
						Default: "leaf",
						Options: []kernel.FieldOption{
							{Value: "leaf", Label: "叶子队列 (leaf)：追踪入队/出队并计算排队驻留耗时"},
							{Value: "classful", Label: "分层分类队列 (classful)：追踪入队分类路径"},
						},
					},
					{
						Key:         "enqueue_sym",
						Label:       "入队内核符号 (enqueue_sym)",
						Type:        kernel.FieldString,
						Placeholder: "例如 netem_enqueue / tbf_enqueue",
						Required:    true,
					},
					{
						Key:         "dequeue_sym",
						Label:       "出队内核符号 (leaf 必填)",
						Type:        kernel.FieldString,
						Placeholder: "例如 netem_dequeue / tbf_dequeue",
					},
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
			return fmt.Errorf("Socket 字段 %s 的字节宽度 %d 非法（仅支持 1/2/4/8）", fld, sz)
		}
		lbl := kernel.ConfigString(row, "label", fld)
		sfs = append(sfs, kernel.KernelSockField{
			Struct: kernel.ConfigString(row, "struct", "sock"),
			Field:  fld,
			Size:   sz,
			Role:   kernel.ConfigString(row, "role", "tag"),
			Label:  lbl,
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
			return fmt.Errorf("自定义叶子队列 %s 必须填写出队符号 (dequeue_sym)", kind)
		}
		name := kernel.ConfigString(row, "name", strings.ToUpper(kind)+" Custom Qdisc")
		qds = append(qds, kernel.KernelQdisc{
			ID:         fmt.Sprintf("gui_%s_%d", kind, idx),
			Name:       name,
			Kind:       kind,
			Mode:       mode,
			EnqueueSym: enq,
			DequeueSym: deq,
		})
	}

	ctx.Provide("kernel.ext.builder", map[string]int{
		"sock_fields": len(sfs),
		"qdiscs":      len(qds),
	})
	if len(sfs) > 0 || len(qds) > 0 {
		ctx.RegisterExtension(kernel.ExtKernelExt, kernel.KernelExtSpec{
			ID:          p.Meta().ID,
			PluginID:    p.Meta().ID,
			Name:        p.Meta().Name,
			Description: "通过插件中心可视化配置生成的动态内核扩展",
			SockFields:  sfs,
			Qdiscs:      qds,
		})
	}
	return nil
}
