package plugins

import (
	"context"
	"fmt"
	"sort"

	"pktpath/studio/pkg/kernel"
)

// ---- 8. DAG Reconstructor ----

type dagReconstructAnalyzer struct{}

func (p *dagReconstructAnalyzer) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.analyzer.dag-reconstruct",
		Name:        "路径 DAG 重建",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "配对队列入出队事件，重建多分支路径与血缘。",
		Category:    kernel.CatAnalyzer,
		Icon:        "🕸️",
		Builtin:     true,
		Capabilities: []string{
			"计算队列 P50 / P95 / P99 驻留耗时",
			"识别 SKB Clone / Copy / Expand 多分支流转",
		},
		Provides: []string{"analyzer.dag"},
		Tags:     []string{"dag", "sojourn", "clone"},
	}
}

func (p *dagReconstructAnalyzer) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "highlight_multi_branch",
				Label:   "在会话顶部汇总多分支派生样本",
				Type:    kernel.FieldBoolean,
				Default: true,
			},
		},
	}
}

func (p *dagReconstructAnalyzer) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	highlight := kernel.ConfigBool(cfg, "highlight_multi_branch", true)
	ctx.Provide("analyzer.dag", cfg)
	ctx.RegisterExtension(kernel.ExtAnalyzer, kernel.AnalyzerSpec{
		ID:          "dag-reconstruct",
		PluginID:    p.Meta().ID,
		Name:        p.Meta().Name,
		Description: p.Meta().Description,
		Priority:    10,
		Run: func(_ context.Context, in *kernel.AnalyzeInput) (*kernel.AnalyzeOutput, error) {
			out := &kernel.AnalyzeOutput{}
			if !highlight || in == nil || in.Overview == nil {
				return out, nil
			}
			multiIDs := []uint64{}
			for _, s := range in.Overview.Samples {
				if s.BranchCount > 1 {
					multiIDs = append(multiIDs, s.SampleID)
				}
			}
			if len(multiIDs) > 0 {
				if len(multiIDs) > 10 {
					multiIDs = multiIDs[:10]
				}
				out.Insights = append(out.Insights, kernel.Insight{
					ID:        "dag.multi_branch",
					Severity:  "info",
					Title:     "存在 SKB 多分支派生",
					Summary:   fmt.Sprintf("共 %d 个样本发生 Clone / Copy / Expand 派生。", len(multiIDs)),
					Metric:    fmt.Sprintf("%d 样本", len(multiIDs)),
					SampleIDs: multiIDs,
				})
			}
			return out, nil
		},
	})
	return nil
}

// ---- 9. Anomaly Radar ----

type anomalyRadarAnalyzer struct{}

func (p *anomalyRadarAnalyzer) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.analyzer.anomaly-radar",
		Name:        "异常雷达",
		Version:     "2.0.0",
		Author:      "PktPath",
		Description: "标出高排队时延、丢包和驱动重排样本。",
		Category:    kernel.CatAnalyzer,
		Icon:        "📡",
		Builtin:     true,
		Capabilities: []string{
			"按阈值检测慢队列与长尾样本",
			"汇总丢包（DROP）与驱动 BUSY 重排（Requeue）",
		},
		Provides: []string{"analyzer.anomaly-radar"},
		Tags:     []string{"diagnostics", "anomaly", "radar"},
	}
}

func (p *anomalyRadarAnalyzer) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Fields: []kernel.FieldSchema{
			{
				Key:     "sojourn_warn_ms",
				Label:   "驻留警告阈值",
				Type:    kernel.FieldNumber,
				Default: float64(5),
				Min:     kernel.FloatPtr(0.1),
				Max:     kernel.FloatPtr(5000),
				Step:    kernel.FloatPtr(0.5),
				Unit:    "ms",
			},
			{
				Key:     "sojourn_crit_ms",
				Label:   "驻留严重阈值",
				Type:    kernel.FieldNumber,
				Default: float64(25),
				Min:     kernel.FloatPtr(0.5),
				Max:     kernel.FloatPtr(10000),
				Step:    kernel.FloatPtr(1),
				Unit:    "ms",
			},
			{
				Key:     "drop_warn_count",
				Label:   "丢包告警条数",
				Type:    kernel.FieldNumber,
				Default: float64(1),
				Min:     kernel.FloatPtr(1),
				Max:     kernel.FloatPtr(10000),
				Step:    kernel.FloatPtr(1),
				Unit:    "包",
			},
			{
				Key:     "requeue_warn_count",
				Label:   "重排告警次数",
				Type:    kernel.FieldNumber,
				Default: float64(1),
				Min:     kernel.FloatPtr(1),
				Max:     kernel.FloatPtr(10000),
				Step:    kernel.FloatPtr(1),
				Unit:    "次",
			},
		},
	}
}

func (p *anomalyRadarAnalyzer) Apply(ctx *kernel.PluginContext, cfg map[string]any) error {
	warnMs := kernel.ConfigFloat(cfg, "sojourn_warn_ms", 5)
	critMs := kernel.ConfigFloat(cfg, "sojourn_crit_ms", 25)
	if critMs < warnMs {
		critMs = warnMs
	}
	dropThresh := kernel.ConfigInt(cfg, "drop_warn_count", 1)
	reqThresh := kernel.ConfigInt(cfg, "requeue_warn_count", 1)

	ctx.Provide("analyzer.anomaly-radar", cfg)
	ctx.RegisterExtension(kernel.ExtAnalyzer, kernel.AnalyzerSpec{
		ID:          "anomaly-radar",
		PluginID:    p.Meta().ID,
		Name:        p.Meta().Name,
		Description: p.Meta().Description,
		Priority:    20,
		Run: func(_ context.Context, in *kernel.AnalyzeInput) (*kernel.AnalyzeOutput, error) {
			out := &kernel.AnalyzeOutput{}
			if in == nil || in.Overview == nil || in.Overview.Stats == nil {
				return out, nil
			}
			st := in.Overview.Stats
			samples := in.Overview.Samples

			type slowSamp struct {
				id uint64
				ms float64
			}
			var slow []slowSamp
			maxMs := 0.0
			for _, s := range samples {
				ms := s.MaxSojournUs / 1000.0
				if ms > maxMs {
					maxMs = ms
				}
				if ms >= warnMs {
					slow = append(slow, slowSamp{id: s.SampleID, ms: ms})
				}
			}
			sort.Slice(slow, func(i, j int) bool { return slow[i].ms > slow[j].ms })

			hotQueue := ""
			hotP95Ms := 0.0
			for _, q := range st.Queues {
				if q.P95Us != nil && *q.P95Us/1000.0 > hotP95Ms {
					hotP95Ms = *q.P95Us / 1000.0
					hotQueue = q.Label
				}
			}

			if len(slow) > 0 {
				sev := "warn"
				if maxMs >= critMs {
					sev = "critical"
				}
				topIDs := make([]uint64, 0, minInt(len(slow), 8))
				for i := 0; i < len(slow) && i < 8; i++ {
					topIDs = append(topIDs, slow[i].id)
				}
				qHint := ""
				if hotQueue != "" {
					qHint = fmt.Sprintf("，最慢队列 %s (P95=%.2f ms)", hotQueue, hotP95Ms)
				}
				out.Insights = append(out.Insights, kernel.Insight{
					ID:        "radar.high_sojourn",
					Severity:  sev,
					Title:     "队列排队时延偏高",
					Summary:   fmt.Sprintf("%d 个样本驻留 ≥ %.1f ms（峰值 %.2f ms%s）。", len(slow), warnMs, maxMs, qHint),
					Metric:    fmt.Sprintf("峰值 %.2f ms", maxMs),
					SampleIDs: topIDs,
				})
			}

			drops := st.Endpoints["DROP"]
			if drops >= dropThresh {
				dropIDs := []uint64{}
				for _, s := range samples {
					if s.Endpoint == "DROP" && len(dropIDs) < 8 {
						dropIDs = append(dropIDs, s.SampleID)
					}
				}
				out.Insights = append(out.Insights, kernel.Insight{
					ID:        "radar.drops",
					Severity:  "critical",
					Title:     "发现内核丢包 (DROP)",
					Summary:   fmt.Sprintf("共 %d 条分支在协议栈或队列中丢弃。", drops),
					Metric:    fmt.Sprintf("%d 丢包", drops),
					SampleIDs: dropIDs,
				})
			}

			if st.RequeueCount >= reqThresh {
				reqIDs := []uint64{}
				for _, s := range samples {
					if s.Requeued && len(reqIDs) < 8 {
						reqIDs = append(reqIDs, s.SampleID)
					}
				}
				out.Insights = append(out.Insights, kernel.Insight{
					ID:        "radar.requeue",
					Severity:  "warn",
					Title:     "驱动发包重排 (Requeue)",
					Summary:   fmt.Sprintf("共 %d 次 NETDEV_TX_BUSY 重排（GSO=%d / BadTXQ=%d）。", st.RequeueCount, st.RequeueGSOCount, st.RequeueBadTxqCount),
					Metric:    fmt.Sprintf("%d 次", st.RequeueCount),
					SampleIDs: reqIDs,
				})
			}

			if len(out.Insights) == 0 && len(samples) > 0 {
				out.Insights = append(out.Insights, kernel.Insight{
					ID:       "radar.healthy",
					Severity: "ok",
					Title:    "未触发异常阈值",
					Summary:  fmt.Sprintf("共 %d 个样本，最大驻留 %.2f ms（阈值 %.1f ms），无丢包与重排。", len(samples), maxMs, warnMs),
					Metric:   fmt.Sprintf("峰值 %.2f ms", maxMs),
				})
			}

			tone := "ok"
			statusLabel := "正常"
			if drops >= dropThresh || maxMs >= critMs {
				tone = "bad"
				statusLabel = "存在瓶颈/丢包"
			} else if len(slow) > 0 || st.RequeueCount >= reqThresh {
				tone = "warn"
				statusLabel = "时延波动"
			}
			out.KPIs = append(out.KPIs, kernel.ExtraKPI{
				Label: "异常雷达评估",
				Value: statusLabel,
				Sub:   fmt.Sprintf("峰值 %.2f ms · 丢包 %d · 重排 %d", maxMs, drops, st.RequeueCount),
				Tone:  tone,
			})
			return out, nil
		},
	})
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
