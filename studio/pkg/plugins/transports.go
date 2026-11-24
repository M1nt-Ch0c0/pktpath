package plugins

import (
	"fmt"

	"pktpath/studio/pkg/kernel"
)

// ---- 1. Android ADB Transport Plugin ----

type androidADBTransport struct{}

func (p *androidADBTransport) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.transport.android-adb",
		Name:        "Android ADB 采集连接器",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "通过本机系统 ADB 发现已连接的 Android 设备，支持自动提权（adbd-root / su）、注入 ARM64 eBPF 采集器、查询包名 UID 及在线采集。",
		Category:    kernel.CatTransport,
		Icon:        "📱",
		Builtin:     true,
		Capabilities: []string{
			"枚举 USB/无线 ADB Android 真机与模拟器",
			"自动识别 adbd-root / su 权限并按需推送 pktpath-android-arm64",
			"自动解析应用包名与 UID（支持 packages.list 降级兜底）",
			"关闭本插件后，工作台将自动隐藏 Android 目标页签并停止 ADB 轮询",
		},
		Provides: []string{"transport.adb"},
		Tags:     []string{"android", "adb", "arm64", "live"},
	}
}

func (p *androidADBTransport) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "Android ADB 连接配置",
		Description: "无需内置 ADB，自动复用系统 PATH 中的 adb.exe（全静默无黑框执行）。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "adb_path",
				Label:       "自定义 ADB 路径（留空自动探测）",
				Description: "默认从系统 PATH 或 ANDROID_HOME 自动探测 adb 可执行文件。",
				Type:        kernel.FieldFile,
				Placeholder: "留空使用系统 PATH 中的 adb",
				FileFilter:  "ADB Executable (adb.exe)|adb.exe|All Files (*.*)|*.*",
			},
			{
				Key:         "auto_prepare",
				Label:       "切换设备时自动检查并注入采集器",
				Description: "选中设备后自动校验采集器 SHA256 与 root 权限。",
				Type:        kernel.FieldBoolean,
				Default:     true,
			},
			{
				Key:         "poll_interval_sec",
				Label:       "设备列表自动刷新间隔",
				Description: "0 表示仅手动点击刷新按钮。",
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
	summary := "系统 PATH 自动探测"
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
		Description:         "通过本机 ADB 连接已 root 的 Android 设备",
		Priority:            10,
		SupportsLiveCapture: true,
		SupportsOffline:     false,
		ConfigSummary:       summary,
	})
	return nil
}

// ---- 2. Linux SSH Transport Plugin ----

type linuxSSHTransport struct{}

func (p *linuxSSHTransport) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.transport.linux-ssh",
		Name:        "Linux SSH 采集连接器",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "通过 OpenSSH 连接任意 Linux 服务器、容器宿主机、开发板或 WSL2，自动探测 CPU 架构并上传对应的静态 Linux eBPF 采集器。",
		Category:    kernel.CatTransport,
		Icon:        "🐧",
		Builtin:     true,
		Capabilities: []string{
			"支持通过 OpenSSH (BatchMode + 私钥 / ssh config) 管理多台 Linux 远程主机",
			"自动探测 x86_64 / arm64 架构并自动注入静态 pktpath-linux-* 采集器",
			"自动枚举远端 /etc/passwd 用户与活跃进程，无需手动查 UID",
			"关闭本插件后，工作台将隐藏 Linux SSH 页签",
		},
		Provides: []string{"transport.ssh"},
		Tags:     []string{"linux", "ssh", "x86_64", "arm64", "server"},
	}
}

func (p *linuxSSHTransport) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "Linux SSH 连接器默认配置",
		Description: "控制新建 SSH 主机时的默认行为；主机列表也可直接在工作台或下方快速维护。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "default_use_sudo",
				Label:       "默认使用 sudo -n 提权执行 eBPF 采集",
				Description: "以非 root 账号登录 Linux 时自动前置 `sudo -n`（需远端免密 sudo）。",
				Type:        kernel.FieldBoolean,
				Default:     true,
			},
			{
				Key:         "connect_timeout_sec",
				Label:       "SSH 连接超时时间",
				Type:        kernel.FieldNumber,
				Default:     float64(10),
				Min:         kernel.FloatPtr(3),
				Max:         kernel.FloatPtr(60),
				Step:        kernel.FloatPtr(1),
				Unit:        "秒",
			},
			{
				Key:         "default_remote_dir",
				Label:       "远端临时工作目录",
				Description: "存放远端采集器与临时会话块的目录，采集结束自动清理。",
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
	summary := fmt.Sprintf("超时 %ds · sudo=%v", timeout, sudo)
	ctx.Provide("transport.ssh", cfg)
	ctx.RegisterExtension(kernel.ExtTransport, kernel.TransportSpec{
		ID:                  "ssh",
		PluginID:            p.Meta().ID,
		Name:                "Linux (SSH)",
		ShortLabel:          "Linux SSH",
		Icon:                "🐧",
		Kind:                "ssh",
		Description:         "通过 OpenSSH 连接任意 Linux 服务器 / 开发板 / WSL2",
		Priority:            20,
		SupportsLiveCapture: true,
		SupportsOffline:     false,
		ConfigSummary:       summary,
	})
	return nil
}

// ---- 3. Offline Session Store Transport Plugin ----

type offlineSessionTransport struct{}

func (p *offlineSessionTransport) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.transport.offline",
		Name:        "本地会话与离线浏览",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "无需连接任何真机即可打开历史采集会话目录、离线分享包或脱敏后的会话，进行完整的单包路径重建与诊断。",
		Category:    kernel.CatTransport,
		Icon:        "📂",
		Builtin:     true,
		Capabilities: []string{
			"管理本机自动保存的历史会话列表（支持一键定位资源管理器目录）",
			"支持通过原生文件夹选择器打开任意外部会话目录",
			"零设备依赖：纯离线也可加载后分析插件与导出插件",
		},
		Provides: []string{"transport.offline"},
		Tags:     []string{"offline", "history", "local"},
	}
}

func (p *offlineSessionTransport) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "离线会话与历史记录设置",
		Description: "控制历史会话浏览和打开行为。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "auto_open_latest",
				Label:       "启动时在离线模式下自动载入最近一次会话",
				Type:        kernel.FieldBoolean,
				Default:     false,
			},
			{
				Key:         "max_history_items",
				Label:       "历史下拉菜单最多展示条数",
				Type:        kernel.FieldNumber,
				Default:     float64(50),
				Min:         kernel.FloatPtr(10),
				Max:         kernel.FloatPtr(500),
				Step:        kernel.FloatPtr(10),
				Unit:        "条",
			},
		},
	}
}

func (p *offlineSessionTransport) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	ctx.Provide("transport.offline", cfg)
	ctx.RegisterExtension(kernel.ExtTransport, kernel.TransportSpec{
		ID:                  "offline",
		PluginID:            p.Meta().ID,
		Name:                "本地离线会话",
		ShortLabel:          "离线会话",
		Icon:                "📂",
		Kind:                "offline",
		Description:         "不依赖设备，直接打开本地或他人分享的会话目录",
		Priority:            30,
		SupportsLiveCapture: false,
		SupportsOffline:     true,
		ConfigSummary:       ctx.Host().SessionsRoot,
	})
	return nil
}
