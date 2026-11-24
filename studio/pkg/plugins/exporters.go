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

// ---- 10. Wireshark .pcapng Exporter ----

type pcapngExporter struct{}

func (p *pcapngExporter) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.exporter.pcapng",
		Name:        "Wireshark 导出",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "导出带队列路径注释的 .pcapng 文件。",
		Category:    kernel.CatExporter,
		Icon:        "🦈",
		Builtin:     true,
		Capabilities: []string{
			"导出 Wireshark 可直接打开的 .pcapng",
			"支持导出前对 IP 与进程名脱敏",
		},
		Provides: []string{"exporter.pcapng"},
		Tags:     []string{"pcapng", "wireshark"},
	}
}

func (p *pcapngExporter) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "redact_by_default",
				Label:   "导出时默认脱敏 IP 与进程名",
				Type:    kernel.FieldBoolean,
				Default: false,
			},
			{
				Key:         "default_key",
				Label:       "默认脱敏 Key",
				Type:        kernel.FieldString,
				Placeholder: "留空自动随机",
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
		ButtonLabel: "导出 .pcapng",
		Icon:        "🦈",
		Description: "导出 Wireshark .pcapng",
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
				Summary: fmt.Sprintf("已导出 %d 个包 (.pcapng)", n),
				Details: map[string]any{"exported_packets": n, "redact": redact},
			}, nil
		},
	})
	return nil
}

// ---- 11. Deterministic Privacy Redactor ----

type redactExporter struct{}

func (p *redactExporter) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.exporter.redact",
		Name:        "隐私脱敏",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "匿名化 IP、进程名和包头后另存会话。",
		Category:    kernel.CatExporter,
		Icon:        "🛡️",
		Builtin:     true,
		Capabilities: []string{
			"保留流关联与队列耗时，替换真实 IP 与进程名",
			"另存为可独立打开的脱敏会话目录",
		},
		Provides: []string{"exporter.redact"},
		Tags:     []string{"privacy", "redact"},
	}
}

func (p *redactExporter) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:         "default_key",
				Label:       "脱敏盐值 Key",
				Description: "相同 Key 对同一 IP 始终生成一致的匿名地址。",
				Type:        kernel.FieldString,
				Placeholder: "留空自动随机",
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
		ButtonLabel: "脱敏另存",
		Icon:        "🛡️",
		Description: "生成脱敏会话目录",
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
				Summary:     "已生成脱敏会话目录",
			}, nil
		},
	})
	return nil
}

// ---- 12. CSV / Markdown Report Exporter ----

type csvReportExporter struct{}

func (p *csvReportExporter) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.exporter.csv-report",
		Name:        "表格 / 报告导出",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "导出 CSV 样本明细表或 Markdown 摘要。",
		Category:    kernel.CatExporter,
		Icon:        "📑",
		Builtin:     true,
		Capabilities: []string{
			"导出 UTF-8 BOM CSV（Excel 可直接打开）",
			"支持切换为 Markdown 诊断摘要",
		},
		Provides: []string{"exporter.csv-report"},
		Tags:     []string{"csv", "markdown", "report"},
	}
}

func (p *csvReportExporter) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "format",
				Label:   "导出格式",
				Type:    kernel.FieldSelect,
				Default: "csv",
				Options: []kernel.FieldOption{
					{Value: "csv", Label: "CSV 表格 (.csv)"},
					{Value: "markdown", Label: "Markdown 报告 (.md)"},
				},
			},
			{
				Key:     "max_rows",
				Label:   "最多导出行数（0 为全部）",
				Type:    kernel.FieldNumber,
				Default: float64(0),
				Min:     kernel.FloatPtr(0),
				Max:     kernel.FloatPtr(100000),
				Step:    kernel.FloatPtr(100),
				Unit:    "行",
			},
		},
	}
}

func (p *csvReportExporter) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	format := kernel.ConfigString(cfg, "format", "csv")
	maxRows := kernel.ConfigInt(cfg, "max_rows", 0)
	ext := ".csv"
	filter := "CSV Table (*.csv)|*.csv|All Files (*.*)|*.*"
	btn := "导出 CSV"
	if format == "markdown" {
		ext = ".md"
		filter = "Markdown Report (*.md)|*.md|All Files (*.*)|*.*"
		btn = "导出 MD"
	}
	ctx.Provide("exporter.csv-report", cfg)
	ctx.RegisterExtension(kernel.ExtExporter, kernel.ExporterSpec{
		ID:          "csv-report",
		PluginID:    p.Meta().ID,
		Name:        p.Meta().Name,
		ButtonLabel: btn,
		Icon:        "📑",
		Description: "导出样本明细或摘要报告",
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
					sb.WriteString(fmt.Sprintf("- Scope: `%s` · 模式: `%s` · 抽样: `%s`\n", st.Scope, st.Mode, st.SampleRate))
					sb.WriteString(fmt.Sprintf("- 样本: **%d** · 分支: **%d**（完整 %d / 缺失 %d）\n", st.SampleCounts.Total, st.Branches.Total, st.Branches.Complete, st.Branches.Incomplete))
					sb.WriteString(fmt.Sprintf("- 丢包: **%d** · 重排: **%d**\n\n", st.Endpoints["DROP"], st.RequeueCount))
					if len(st.Queues) > 0 {
						sb.WriteString("## 队列分位\n\n| 队列 | 类型 | 次数 | P50(ms) | P95(ms) | P99(ms) | Max(ms) |\n|---|---|---:|---:|---:|---:|---:|\n")
						for _, q := range st.Queues {
							sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s | %s |\n",
								q.Label, q.Kind, q.PairedN, fmtUsMs(q.P50Us), fmtUsMs(q.P95Us), fmtUsMs(q.P99Us), fmtUsMs(q.MaxUs)))
						}
						sb.WriteString("\n")
					}
				}
				sb.WriteString(fmt.Sprintf("## 样本明细 (%d)\n\n| # | 进程 | 协议 | 源 -> 目的 | 长度 | 最大驻留(ms) | 终点 | 路径 |\n|---:|---|---|---|---:|---:|---|---|\n", len(samples)))
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
					Summary: fmt.Sprintf("已导出 Markdown 报告（%d 条）", len(samples)),
					Details: map[string]any{"rows": len(samples), "format": "markdown"},
				}, nil
			}

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
					uidStr, tgidStr, s.Comm, s.Proto, s.Src, s.Dst,
					strconv.FormatUint(s.PktLen, 10),
					fmt.Sprintf("%.3f", s.MaxSojournUs/1000.0),
					fmt.Sprintf("%.3f", s.TotalUs/1000.0),
					s.Endpoint, s.Completeness,
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
				Summary: fmt.Sprintf("已导出 CSV（%d 条）", len(samples)),
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
