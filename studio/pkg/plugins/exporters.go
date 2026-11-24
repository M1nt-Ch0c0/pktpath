package plugins

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"pktpath/studio/pkg/export"
	"pktpath/studio/pkg/kernel"
)

// ---- 8. Wireshark .pcapng Exporter Plugin ----

type pcapngExporter struct{}

func (p *pcapngExporter) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.exporter.pcapng",
		Name:        "Wireshark .pcapng 导出插件",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "将采集到的单包路径和包头字节导出为标准 .pcapng 文件，并在每个帧的 pcapng 注释（opt_comment）中嵌入队列驻留与路径元数据，支持一键在 Wireshark 中关联分析。",
		Category:    kernel.CatExporter,
		Icon:        "🦈",
		Builtin:     true,
		Capabilities: []string{
			"导出带单包路径注释的 Wireshark 兼容 .pcapng 文件",
			"支持开启默认 IP/敏感字段哈希脱敏后再导出",
			"在工作台会话导出栏注册「导出 Wireshark」按钮",
		},
		Provides: []string{"exporter.pcapng"},
		Tags:     []string{"pcapng", "wireshark", "export"},
	}
}

func (p *pcapngExporter) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "Wireshark 导出选项",
		Description: "设置默认导出行为。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "redact_by_default",
				Label:       "导出 .pcapng 时默认脱敏 IP 地址与进程名",
				Type:        kernel.FieldBoolean,
				Default:     false,
			},
			{
				Key:         "default_key",
				Label:       "默认脱敏盐值 Key（留空自动随机）",
				Type:        kernel.FieldString,
				Placeholder: "留空每次生成随机盐",
			},
		},
	}
}

func (p *pcapngExporter) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	defRedact := kernel.ConfigBool(cfg, "redact_by_default", false)
	defKey := kernel.ConfigString(cfg, "default_key", "")
	ctx.Provide("exporter.pcapng", cfg)
	ctx.RegisterExtension(kernel.ExtExporter, kernel.ExporterSpec{
		ID:          "pcapng",
		PluginID:    p.Meta().ID,
		Name:        p.Meta().Name,
		ButtonLabel: "导出 Wireshark",
		Icon:        "🦈",
		Description: "导出带队列驻留注释的标准 .pcapng 文件",
		DefaultExt:  ".pcapng",
		FileFilter:  "Wireshark Capture (*.pcapng)|*.pcapng|All Files (*.*)|*.*",
		Priority:    10,
		Run: func(_ context.Context, in *kernel.ExportInput) (*kernel.ExportOutput, error) {
			redact := defRedact
			if v, ok := in.Params["redact"].(bool); ok {
				redact = v
			}
			key := defKey
			if v, ok := in.Params["key"].(string); ok && strings.TrimSpace(v) != "" {
				key = strings.TrimSpace(v)
			}
			outPath := in.OutPath
			if outPath == "" {
				outPath = filepath.Join(ctx.Host().SessionsRoot, fmt.Sprintf("trace_%s.pcapng", in.SessionID))
			}
			if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
				return nil, err
			}
			n, err := export.ExportPcapng(in.SessionDir, outPath, redact, key)
			if err != nil {
				return nil, err
			}
			return &kernel.ExportOutput{
				OK:      true,
				OutPath: outPath,
				Summary: fmt.Sprintf("已导出 %d 个数据包至 Wireshark .pcapng", n),
				Details: map[string]any{"exported_packets": n, "redact": redact},
			}, nil
		},
	})
	return nil
}

// ---- 9. Deterministic Privacy Redactor Plugin ----

type redactExporter struct{}

func (p *redactExporter) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.exporter.redact",
		Name:        "会话确定性隐私脱敏导出插件",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "使用带密钥的确定性 SHA-256 对会话中的 IP 地址、进程名与包头负载进行脱敏，保留完整流关联性与队列耗时结构，方便安全分享排障。",
		Category:    kernel.CatExporter,
		Icon:        "🛡️",
		Builtin:     true,
		Capabilities: []string{
			"保留完整 TCP/UDP 流关联与队列耗时，隐藏真实 IP 与敏感进程信息",
			"输出独立可打开的新会话目录，脱敏后可直接在 Studio 中浏览",
			"在工作台会话导出栏注册「脱敏导出」按钮",
		},
		Provides: []string{"exporter.redact"},
		Tags:     []string{"privacy", "redact", "sha256", "share"},
	}
}

func (p *redactExporter) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "隐私脱敏设置",
		Description: "配置脱敏使用的确定性盐值（相同 Key 对同一 IP 始终映射为相同的匿名 IP）。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "default_key",
				Label:       "默认脱敏 Key（留空自动生成）",
				Type:        kernel.FieldString,
				Placeholder: "例如 team-share-key",
			},
		},
	}
}

func (p *redactExporter) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	defKey := kernel.ConfigString(cfg, "default_key", "")
	ctx.Provide("exporter.redact", cfg)
	ctx.RegisterExtension(kernel.ExtExporter, kernel.ExporterSpec{
		ID:          "redact",
		PluginID:    p.Meta().ID,
		Name:        p.Meta().Name,
		ButtonLabel: "脱敏分享包",
		Icon:        "🛡️",
		Description: "生成隐藏真实 IP/进程名的安全离线会话目录",
		IsDirectory: true,
		Priority:    20,
		Run: func(_ context.Context, in *kernel.ExportInput) (*kernel.ExportOutput, error) {
			key := defKey
			if v, ok := in.Params["key"].(string); ok && strings.TrimSpace(v) != "" {
				key = strings.TrimSpace(v)
			}
			outDir := in.OutPath
			if outDir == "" {
				outDir = filepath.Join(ctx.Host().SessionsRoot, in.SessionID+"_redacted")
			}
			if err := export.RedactSession(in.SessionDir, outDir, key); err != nil {
				return nil, err
			}
			return &kernel.ExportOutput{
				OK:          true,
				OutPath:     outDir,
				IsDirectory: true,
				Summary:     "已生成确定性脱敏会话目录",
			}, nil
		},
	})
	return nil
}

// ---- 10. CSV & Markdown Diagnostic Report Exporter Plugin ----

type csvReportExporter struct{}

func (p *csvReportExporter) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.exporter.csv-report",
		Name:        "CSV / Markdown 诊断报告导出插件",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "一键将重建后的样本清单、队列分位统计导出为 Excel 友好的 UTF-8 CSV 表格或结构化 Markdown 诊断报告，便于归档与贴入缺陷单。",
		Category:    kernel.CatExporter,
		Icon:        "📑",
		Builtin:     true,
		Capabilities: []string{
			"导出带 UTF-8 BOM 的 Excel 兼容 CSV 样本明细表",
			"支持切换为 Markdown 诊断报告模式（含队列 P50/P95/P99 与热点样本）",
			"在工作台会话导出栏注册一键导出按钮",
		},
		Provides: []string{"exporter.csv-report"},
		Tags:     []string{"csv", "markdown", "excel", "report"},
	}
}

func (p *csvReportExporter) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "报告导出格式设置",
		Description: "选择导出为 CSV 表格或 Markdown 诊断报告。",
		Fields: []kernel.FieldSchema{
			{
				Key:     "format",
				Label:   "导出格式",
				Type:    kernel.FieldSelect,
				Default: "csv",
				Options: []kernel.FieldOption{
					{Value: "csv", Label: "CSV 样本明细表 (.csv, Excel 直开)"},
					{Value: "markdown", Label: "Markdown 诊断摘要报告 (.md)"},
				},
			},
			{
				Key:         "max_rows",
				Label:       "最多导出样本行数（0 = 全部）",
				Type:        kernel.FieldNumber,
				Default:     float64(0),
				Min:         kernel.FloatPtr(0),
				Max:         kernel.FloatPtr(100000),
				Step:        kernel.FloatPtr(100),
				Unit:        "行",
			},
		},
	}
}

func (p *csvReportExporter) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	format := kernel.ConfigString(cfg, "format", "csv")
	maxRows := kernel.ConfigInt(cfg, "max_rows", 0)
	ext := ".csv"
	filter := "CSV Table (*.csv)|*.csv|All Files (*.*)|*.*"
	btn := "导出 CSV 表"
	if format == "markdown" {
		ext = ".md"
		filter = "Markdown Report (*.md)|*.md|All Files (*.*)|*.*"
		btn = "导出 MD 报告"
	}
	ctx.Provide("exporter.csv-report", cfg)
	ctx.RegisterExtension(kernel.ExtExporter, kernel.ExporterSpec{
		ID:          "csv-report",
		PluginID:    p.Meta().ID,
		Name:        p.Meta().Name,
		ButtonLabel: btn,
		Icon:        "📑",
		Description: "导出结构化 CSV 表格或 Markdown 诊断报告",
		DefaultExt:  ext,
		FileFilter:  filter,
		Priority:    30,
		Run: func(_ context.Context, in *kernel.ExportInput) (*kernel.ExportOutput, error) {
			if in.Overview == nil {
				return nil, fmt.Errorf("会话数据尚未加载")
			}
			outPath := in.OutPath
			if outPath == "" {
				outPath = filepath.Join(ctx.Host().SessionsRoot, fmt.Sprintf("report_%s%s", in.SessionID, ext))
			}
			if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
				return nil, err
			}
			samples := in.Overview.Samples
			if maxRows > 0 && len(samples) > maxRows {
				samples = samples[:maxRows]
			}
			if format == "markdown" {
				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("# PktPath 诊断报告 — %s\n\n", in.SessionID))
				if st := in.Overview.Stats; st != nil {
					sb.WriteString("## 概览统计\n\n")
					sb.WriteString(fmt.Sprintf("- 观测范围: `%s` · 模式: `%s` · 抽样率: `%s`\n", st.Scope, st.Mode, st.SampleRate))
					sb.WriteString(fmt.Sprintf("- 样本总数: **%d** · 分支总数: **%d** (完整 %d / 缺失 %d)\n", st.SampleCounts.Total, st.Branches.Total, st.Branches.Complete, st.Branches.Incomplete))
					sb.WriteString(fmt.Sprintf("- 丢包 (DROP): **%d** · 驱动重排 (Requeue): **%d**\n\n", st.Endpoints["DROP"], st.RequeueCount))
					if len(st.Queues) > 0 {
						sb.WriteString("## 队列驻留分位\n\n")
						sb.WriteString("| 队列 | 类型 | 次数 | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) |\n|---|---|---:|---:|---:|---:|---:|\n")
						for _, q := range st.Queues {
							sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s | %s |\n",
								q.Label, q.Kind, q.PairedN, fmtUsMs(q.P50Us), fmtUsMs(q.P95Us), fmtUsMs(q.P99Us), fmtUsMs(q.MaxUs)))
						}
						sb.WriteString("\n")
					}
				}
				sb.WriteString(fmt.Sprintf("## 样本明细 (共 %d 条)\n\n", len(samples)))
				sb.WriteString("| SampleID | 进程 | 协议 | 源 -> 目的 | 长度 | 最大驻留(ms) | 终点 | 路径 |\n|---:|---|---|---|---:|---:|---|---|\n")
				for _, s := range samples {
					sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s -> %s | %d | %.3f | %s | `%s` |\n",
						s.SampleID, s.Comm, s.Proto, s.Src, s.Dst, s.PktLen, s.MaxSojournUs/1000.0, s.Endpoint, s.PathSig))
				}
				if err := os.WriteFile(outPath, []byte(sb.String()), 0o644); err != nil {
					return nil, err
				}
				return &kernel.ExportOutput{
					OK:      true,
					OutPath: outPath,
					Summary: fmt.Sprintf("已导出 Markdown 诊断报告（%d 个样本）", len(samples)),
					Details: map[string]any{"rows": len(samples), "format": "markdown"},
				}, nil
			}

			// Default: UTF-8 BOM CSV for Excel
			f, err := os.Create(outPath)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			_, _ = f.Write([]byte{0xEF, 0xBB, 0xBF})
			cw := csv.NewWriter(f)
			_ = cw.Write([]string{
				"sample_id", "uid", "tgid", "comm", "proto", "src", "dst",
				"pkt_len", "max_sojourn_ms", "total_ms", "endpoint", "completeness", "branches", "requeued", "path_sig",
			})
			for _, s := range samples {
				uidStr, tgidStr := "", ""
				if s.UID != nil {
					uidStr = strconv.FormatUint(*s.UID, 10)
				}
				if s.Tgid != nil {
					tgidStr = strconv.FormatUint(*s.Tgid, 10)
				}
				_ = cw.Write([]string{
					strconv.FormatUint(s.SampleID, 10),
					uidStr,
					tgidStr,
					s.Comm,
					s.Proto,
					s.Src,
					s.Dst,
					strconv.FormatUint(s.PktLen, 10),
					fmt.Sprintf("%.3f", s.MaxSojournUs/1000.0),
					fmt.Sprintf("%.3f", s.TotalUs/1000.0),
					s.Endpoint,
					s.Completeness,
					strconv.Itoa(s.BranchCount),
					strconv.FormatBool(s.Requeued),
					s.PathSig,
				})
			}
			cw.Flush()
			if err := cw.Error(); err != nil {
				return nil, err
			}
			return &kernel.ExportOutput{
				OK:      true,
				OutPath: outPath,
				Summary: fmt.Sprintf("已导出 %d 条样本明细至 CSV", len(samples)),
				Details: map[string]any{"rows": len(samples), "format": "csv"},
			}, nil
		},
	})
	return nil
}

func fmtUsMs(us *float64) string {
	if us == nil {
		return "—"
	}
	return fmt.Sprintf("%.3f", *us/1000.0)
}
