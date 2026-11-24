package plugins

import "pktpath/studio/pkg/kernel"

// ---- 13. UI Theme ----

type uiThemePlugin struct{}

func (p *uiThemePlugin) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.ui.theme",
		Name:        "外观主题",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "切换明暗模式、配色与界面密度。",
		Category:    kernel.CatUI,
		Icon:        "🎨",
		Builtin:     true,
		Capabilities: []string{
			"明暗模式与 5 套强调色",
			"排版密度与字号缩放",
		},
		Provides: []string{"ui.theme"},
		Tags:     []string{"ui", "theme"},
	}
}

func (p *uiThemePlugin) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "mode",
				Label:   "模式",
				Type:    kernel.FieldSelect,
				Default: "light",
				Options: []kernel.FieldOption{
					{Value: "light", Label: "浅色"},
					{Value: "dark", Label: "深色"},
				},
			},
			{
				Key:     "accent",
				Label:   "强调色",
				Type:    kernel.FieldSelect,
				Default: "blue",
				Options: []kernel.FieldOption{
					{Value: "blue", Label: "蓝"},
					{Value: "emerald", Label: "绿"},
					{Value: "violet", Label: "紫"},
					{Value: "amber", Label: "橙"},
					{Value: "rose", Label: "红"},
				},
			},
			{
				Key:     "density",
				Label:   "密度",
				Type:    kernel.FieldSelect,
				Default: "comfortable",
				Options: []kernel.FieldOption{
					{Value: "comfortable", Label: "标准"},
					{Value: "compact", Label: "紧凑"},
				},
			},
			{
				Key:     "font_scale",
				Label:   "字号缩放",
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
