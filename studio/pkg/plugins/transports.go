package plugins

import (
	"fmt"

	"pktpath/studio/pkg/kernel"
)

// ---- 1. Android ADB Transport ----

type androidADBTransport struct{}

func (p *androidADBTransport) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.transport.android-adb",
		Name:        "Android ADB",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "通过本机 adb 连接 Android 设备。",
		Category:    kernel.CatTransport,
		Icon:        "📱",
		Builtin:     true,
		Capabilities: []string{
			"发现 USB / 无线 ADB 设备并检查 root 权限",
			"推送 arm64 采集器并解析应用包名与 UID",
		},
		Provides: []string{"transport.adb"},
		Tags:     []string{"android", "adb", "arm64"},
	}
}

func (p *androidADBTransport) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:         "adb_path",
				Label:       "ADB 路径",
				Description: "留空自动从系统 PATH 查找。",
				Type:        kernel.FieldFile,
				Placeholder: "自动查找 adb.exe",
				FileFilter:  "ADB (adb.exe)|adb.exe|All Files (*.*)|*.*",
			},
			{
				Key:     "auto_prepare",
				Label:   "选中设备时自动检查并推送采集器",
				Type:    kernel.FieldBoolean,
				Default: true,
			},
			{
				Key:         "poll_interval_sec",
				Label:       "自动刷新间隔",
				Description: "0 表示仅手动刷新。",
				Type:        kernel.FieldNumber,
				Default:     float64(0),
				Min:         kernel.FloatPtr(0),
				Max:         kernel.FloatPtr(60),
				Step:        kernel.FloatPtr(1),
				Unit:        "秒",
			},
		},
	}
}

func (p *androidADBTransport) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	adbPath := kernel.ConfigString(cfg, "adb_path", "")
	summary := "系统 PATH"
	if adbPath != "" {
		summary = adbPath
	}
	ctx.Provide("transport.adb", cfg)
	ctx.RegisterExtension(kernel.ExtTransport, kernel.TransportSpec{
		ID:                  "adb",
		PluginID:            p.Meta().ID,
		Name:                "Android (ADB)",
		ShortLabel:          "Android",
		Icon:                "📱",
		Kind:                "adb",
		Description:         "连接 Android 设备",
		Priority:            10,
		SupportsLiveCapture: true,
		ConfigSummary:       summary,
	})
	return nil
}

// ---- 2. Linux SSH Transport ----

type linuxSSHTransport struct{}

func (p *linuxSSHTransport) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.transport.linux-ssh",
		Name:        "Linux SSH",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "通过 SSH 连接 Linux 主机或开发板。",
		Category:    kernel.CatTransport,
		Icon:        "🐧",
		Builtin:     true,
		Capabilities: []string{
			"通过 OpenSSH 管理远程 Linux 主机",
			"按架构自动上传 x86_64 / arm64 静态采集器",
		},
		Provides: []string{"transport.ssh"},
		Tags:     []string{"linux", "ssh", "x86_64", "arm64"},
	}
}

func (p *linuxSSHTransport) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "default_use_sudo",
				Label:   "非 root 登录时默认使用 sudo -n",
				Type:    kernel.FieldBoolean,
				Default: true,
			},
			{
				Key:     "connect_timeout_sec",
				Label:   "连接超时",
				Type:    kernel.FieldNumber,
				Default: float64(10),
				Min:     kernel.FloatPtr(3),
				Max:     kernel.FloatPtr(60),
				Step:    kernel.FloatPtr(1),
				Unit:    "秒",
			},
			{
				Key:         "default_remote_dir",
				Label:       "远端临时目录",
				Type:        kernel.FieldString,
				Default:     "/tmp",
				Placeholder: "/tmp",
			},
		},
	}
}

func (p *linuxSSHTransport) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	timeout := kernel.ConfigInt(cfg, "connect_timeout_sec", 10)
	sudo := kernel.ConfigBool(cfg, "default_use_sudo", true)
	ctx.Provide("transport.ssh", cfg)
	ctx.RegisterExtension(kernel.ExtTransport, kernel.TransportSpec{
		ID:                  "ssh",
		PluginID:            p.Meta().ID,
		Name:                "Linux (SSH)",
		ShortLabel:          "Linux SSH",
		Icon:                "🐧",
		Kind:                "ssh",
		Description:         "连接 Linux 远程主机",
		Priority:            20,
		SupportsLiveCapture: true,
		ConfigSummary:       fmt.Sprintf("超时 %ds · sudo=%v", timeout, sudo),
	})
	return nil
}

// ---- 3. Offline Session Store ----

type offlineSessionTransport struct{}

func (p *offlineSessionTransport) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.transport.offline",
		Name:        "本地会话",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "打开和浏览本机历史会话目录。",
		Category:    kernel.CatTransport,
		Icon:        "📂",
		Builtin:     true,
		Capabilities: []string{
			"列出本机已保存的采集历史",
			"从文件夹打开离线或脱敏会话",
		},
		Provides: []string{"transport.offline"},
		Tags:     []string{"offline", "history", "local"},
	}
}

func (p *offlineSessionTransport) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "auto_open_latest",
				Label:   "启动时自动载入最近一次会话",
				Type:    kernel.FieldBoolean,
				Default: false,
			},
			{
				Key:     "max_history_items",
				Label:   "历史列表展示上限",
				Type:    kernel.FieldNumber,
				Default: float64(50),
				Min:     kernel.FloatPtr(10),
				Max:     kernel.FloatPtr(500),
				Step:    kernel.FloatPtr(10),
				Unit:    "条",
			},
		},
	}
}

func (p *offlineSessionTransport) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	ctx.Provide("transport.offline", cfg)
	ctx.RegisterExtension(kernel.ExtTransport, kernel.TransportSpec{
		ID:              "offline",
		PluginID:        p.Meta().ID,
		Name:            "本地会话",
		ShortLabel:      "离线",
		Icon:            "📂",
		Kind:            "offline",
		Description:     "打开本地或他人分享的会话目录",
		Priority:        30,
		SupportsOffline: true,
		ConfigSummary:   ctx.Host().SessionsRoot,
	})
	return nil
}
