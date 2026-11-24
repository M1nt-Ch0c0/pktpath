package plugins

import "pktpath/studio/pkg/kernel"

// ---- 11. UI Appearance & Layout Theme Plugin ----

type uiThemePlugin struct{}

func (p *uiThemePlugin) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.ui.theme",
		Name:        "界面外观与布局主题插件",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "自定义 PktPath Studio 的明暗模式、品牌强调色、信息密度与字号缩放，修改后无需重启即时热更新生效。",
		Category:    kernel.CatUI,
		Icon:        "🎨",
		Builtin:     true,
		Capabilities: []string{
			"支持浅色/深色主题与 5 种品牌强调色即时热切换",
			"支持舒适/紧凑信息密度与 90%~115% 字号缩放",
			"所有外观偏好自动持久化保存，跨重启生效",
		},
		Provides: []string{"ui.theme"},
		Tags:     []string{"ui", "theme", "appearance", "dark-mode"},
	}
}

func (p *uiThemePlugin) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "界面外观配置",
		Description: "点击保存后立即实时更新工作台与插件中心配色和排版。",
		Fields: []kernel.FieldSchema{
			{
				Key:     "mode",
				Label:   "色彩模式",
				Type:    kernel.FieldSelect,
				Default: "light",
				Options: []kernel.FieldOption{
					{Value: "light", Label: "明亮模式 (Light)"},
					{Value: "dark", Label: "深邃暗色 (Dark)"},
				},
			},
			{
				Key:     "accent",
				Label:   "主题强调色",
				Type:    kernel.FieldSelect,
				Default: "blue",
				Options: []kernel.FieldOption{
					{Value: "blue", Label: "科技蓝 (Blue)"},
					{Value: "emerald", Label: "翡翠绿 (Emerald)"},
					{Value: "violet", Label: "极光紫 (Violet)"},
					{Value: "amber", Label: "琥珀金 (Amber)"},
					{Value: "rose", Label: "绯红玫瑰 (Rose)"},
				},
			},
			{
				Key:     "density",
				Label:   "信息密度",
				Type:    kernel.FieldSelect,
				Default: "comfortable",
				Options: []kernel.FieldOption{
					{Value: "comfortable", Label: "舒适标准"},
					{Value: "compact", Label: "紧凑高密度（适合大屏多样本）"},
				},
			},
			{
				Key:     "font_scale",
				Label:   "全局字号缩放",
				Type:    kernel.FieldNumber,
				Default: float64(100),
				Min:     kernel.FloatPtr(90),
				Max:     kernel.FloatPtr(115),
				Step:    kernel.FloatPtr(5),
				Unit:    "%",
			},
		},
	}
}

func (p *uiThemePlugin) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	spec := kernel.ThemeSpec{
		PluginID:  p.Meta().ID,
		Mode:      kernel.ConfigString(cfg, "mode", "light"),
		Accent:    kernel.ConfigString(cfg, "accent", "blue"),
		Density:   kernel.ConfigString(cfg, "density", "comfortable"),
		FontScale: kernel.ConfigInt(cfg, "font_scale", 100),
	}
	ctx.Provide("ui.theme", spec)
	ctx.RegisterExtension(kernel.ExtTheme, spec)
	return nil
}
