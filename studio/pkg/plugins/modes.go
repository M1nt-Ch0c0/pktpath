package plugins

import "pktpath/studio/pkg/kernel"

// ---- 6. Oneshot Capture Mode Plugin ----

type oneshotModePlugin struct{}

func (p *oneshotModePlugin) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.mode.oneshot",
		Name:        "短时复现抓包",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "按固定时长抓取全量或抽样数据包。",
		Category:    kernel.CatCollector,
		Icon:        "⏱",
		Builtin:     true,
		Capabilities: []string{
			"注册「复现抓包（短时）」采集模式",
			"支持自定义默认抽样率与采集时长",
		},
		Requires: []string{"collector.ebpf"},
		Provides: []string{"capture.mode.oneshot"},
		Tags:     []string{"oneshot", "capture", "mode"},
	}
}

func (p *oneshotModePlugin) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "default_duration_sec",
				Label:   "默认时长",
				Type:    kernel.FieldNumber,
				Default: float64(10),
				Min:     kernel.FloatPtr(1),
				Max:     kernel.FloatPtr(600),
				Step:    kernel.FloatPtr(1),
				Unit:    "秒",
			},
			{
				Key:     "default_sample",
				Label:   "默认抽样",
				Type:    kernel.FieldSelect,
				Default: "1/1",
				Options: []kernel.FieldOption{
					{Value: "1/1", Label: "全选 1/1"},
					{Value: "1/10", Label: "1/10"},
					{Value: "1/100", Label: "1/100"},
				},
			},
		},
	}
}

func (p *oneshotModePlugin) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	ctx.Provide("capture.mode.oneshot", cfg)
	ctx.RegisterExtension(kernel.ExtCaptureMode, kernel.CaptureModeSpec{
		ID:          "oneshot",
		PluginID:    p.Meta().ID,
		Mode:        "oneshot",
		Name:        "复现抓包（短时）",
		Description: "按固定时长采集",
		Priority:    10,
	})
	return nil
}

// ---- 7. Daemon Flight-Recorder Mode Plugin ----

type daemonModePlugin struct{}

func (p *daemonModePlugin) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.mode.daemon",
		Name:        "后台异常蹲守",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "常驻内存环形缓冲，排队超时或手动触发时落盘。",
		Category:    kernel.CatCollector,
		Icon:        "🛡",
		Builtin:     true,
		Capabilities: []string{
			"注册「后台蹲守（偶发卡顿）」采集模式",
			"支持排队时延阈值自动触发与 SIGUSR1 手动落盘",
		},
		Requires: []string{"collector.ebpf"},
		Provides: []string{"capture.mode.daemon"},
		Tags:     []string{"daemon", "trigger", "mode"},
	}
}

func (p *daemonModePlugin) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "default_threshold_ms",
				Label:   "默认触发阈值",
				Type:    kernel.FieldNumber,
				Default: float64(20),
				Min:     kernel.FloatPtr(1),
				Max:     kernel.FloatPtr(500),
				Step:    kernel.FloatPtr(1),
				Unit:    "ms",
			},
			{
				Key:     "default_pre_sec",
				Label:   "触发前窗口",
				Type:    kernel.FieldNumber,
				Default: float64(5),
				Min:     kernel.FloatPtr(0),
				Max:     kernel.FloatPtr(60),
				Step:    kernel.FloatPtr(1),
				Unit:    "秒",
			},
			{
				Key:     "default_post_sec",
				Label:   "触发后窗口",
				Type:    kernel.FieldNumber,
				Default: float64(2),
				Min:     kernel.FloatPtr(0),
				Max:     kernel.FloatPtr(60),
				Step:    kernel.FloatPtr(1),
				Unit:    "秒",
			},
		},
	}
}

func (p *daemonModePlugin) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	ctx.Provide("capture.mode.daemon", cfg)
	ctx.RegisterExtension(kernel.ExtCaptureMode, kernel.CaptureModeSpec{
		ID:          "daemon",
		PluginID:    p.Meta().ID,
		Mode:        "daemon",
		Name:        "后台蹲守（偶发卡顿）",
		Description: "内存环缓，超阈值落盘",
		Priority:    20,
	})
	return nil
}
