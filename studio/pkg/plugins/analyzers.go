package plugins

import (
	"context"
	"fmt"
	"sort"

	"pktpath/studio/pkg/kernel"
)

// ---- 6. DAG Multi-Branch Reconstructor Plugin ----

type dagReconstructAnalyzer struct{}

func (p *dagReconstructAnalyzer) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.analyzer.dag-reconstruct",
		Name:        "多分支 SKB 血缘 DAG 重建引擎",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "基于严格契约证据与 (object_id, queue_gen, visit_id) 配对，重建每个数据包的完整内核流转 DAG、Clone/Expand 派生关系与队列驻留分位数。",
		Category:    kernel.CatAnalyzer,
		Icon:        "🕸️",
		Builtin:     true,
		Capabilities: []string{
			"精确配对队列入队/出队事件并计算 P50 / P95 / P99 排队驻留耗时",
			"追踪 SKB CLONE / COPY / EXPAND 对象血缘派生并构建多分支路径图",
			"自动评估每条分支的数据完备性（完整 / 缺失 / 未知）与质量窗口交集",
		},
		Provides: []string{"analyzer.dag"},
		Tags:     []string{"dag", "reconstruct", "sojourn", "clone"},
	}
}

func (p *dagReconstructAnalyzer) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "DAG 重建展示配置",
		Description: "控制多分支血缘与队列统计摘要行为。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "highlight_multi_branch",
				Label:       "在诊断栏汇总多分支派生（SKB Clone/Expand）统计",
				Type:        kernel.FieldBoolean,
				Default:     true,
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
					Title:     "检测到 SKB 派生/多分支流转",
					Summary:   fmt.Sprintf("本次会话共有 %d 个样本发生了 SKB Clone/Copy/Expand 多分支派生，可点击样本在右侧查看父子血缘关系。", len(multiIDs)),
					Metric:    fmt.Sprintf("%d 个多分支样本", len(multiIDs)),
					SampleIDs: multiIDs,
				})
			}
			return out, nil
		},
	})
	return nil
}

// ---- 7. Automated Bottleneck & Anomaly Radar Plugin ----

type anomalyRadarAnalyzer struct{}

func (p *anomalyRadarAnalyzer) Meta() kernel.PluginMeta {
	return kernel.PluginMeta{
		ID:          "builtin.analyzer.anomaly-radar",
		Name:        "瓶颈与异常雷达诊断插件",
		Version:     "2.0.0",
		Author:      "PktPath Core",
		Description: "自动扫描每条样本与队列，识别高排队驻留瓶颈、丢包、驱动 BUSY 重排（Requeue）、乱序以及采集质量缺口，并在工作台画布顶部生成可一键定位样本的诊断卡片。",
		Category:    kernel.CatAnalyzer,
		Icon:        "📡",
		Builtin:     true,
		Capabilities: []string{
			"自动识别超过阈值的队列排队抖动（可自定义警告/严重毫秒阈值）",
			"自动聚合丢包（DROP）、重排（Requeue）与乱序异常并关联对应样本 ID",
			"向工作台画布顶部插槽输出实时诊断卡片与健康评分 KPI",
			"关闭本插件后，工作台将自动移除异常雷达卡片",
		},
		Provides: []string{"analyzer.anomaly-radar"},
		Tags:     []string{"diagnostics", "anomaly", "bottleneck", "radar"},
	}
}

func (p *anomalyRadarAnalyzer) Schema() *kernel.ConfigSchema {
	return &kernel.ConfigSchema{
		Title:       "异常雷达阈值配置",
		Description: "调整触发告警的排队驻留与异常计数阈值，保存后立即生效。",
		Fields: []kernel.FieldSchema{
			{
				Key:         "sojourn_warn_ms",
				Label:       "队列驻留警告阈值",
				Description: "单包在队列内驻留超过该时间将触发黄色警告。",
				Type:        kernel.FieldNumber,
				Default:     float64(5),
				Min:         kernel.FloatPtr(0.1),
				Max:         kernel.FloatPtr(5000),
				Step:        kernel.FloatPtr(0.5),
				Unit:        "ms",
			},
			{
				Key:         "sojourn_crit_ms",
				Label:       "队列驻留严重告警阈值",
				Description: "单包在队列内驻留超过该时间将触发红色严重告警。",
				Type:        kernel.FieldNumber,
				Default:     float64(25),
				Min:         kernel.FloatPtr(0.5),
				Max:         kernel.FloatPtr(10000),
				Step:        kernel.FloatPtr(1),
				Unit:        "ms",
			},
			{
				Key:         "drop_warn_count",
				Label:       "丢包触发告警条数",
				Type:        kernel.FieldNumber,
				Default:     float64(1),
				Min:         kernel.FloatPtr(1),
				Max:         kernel.FloatPtr(10000),
				Step:        kernel.FloatPtr(1),
				Unit:        "包",
			},
			{
				Key:         "requeue_warn_count",
				Label:       "驱动 BUSY 重排触发告警条数",
				Type:        kernel.FieldNumber,
				Default:     float64(1),
				Min:         kernel.FloatPtr(1),
				Max:         kernel.FloatPtr(10000),
				Step:        kernel.FloatPtr(1),
				Unit:        "次",
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

			// 1. High sojourn detection
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

			// Find hottest queue
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
					qHint = fmt.Sprintf("；最慢队列为 %s (P95=%.2f ms)", hotQueue, hotP95Ms)
				}
				out.Insights = append(out.Insights, kernel.Insight{
					ID:        "radar.high_sojourn",
					Severity:  sev,
					Title:     "检测到队列排队高时延瓶颈",
					Summary:   fmt.Sprintf("共 %d 个样本单队列驻留 ≥ %.1f ms，峰值 %.2f ms%s。", len(slow), warnMs, maxMs, qHint),
					Metric:    fmt.Sprintf("峰值 %.2f ms", maxMs),
					SampleIDs: topIDs,
				})
			}

			// 2. Drops
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
					Summary:   fmt.Sprintf("共观测到 %d 条分支在协议栈或队列中丢弃，点击下方样本可查看精确丢包点与 drop_reason。", drops),
					Metric:    fmt.Sprintf("%d 丢包", drops),
					SampleIDs: dropIDs,
				})
			}

			// 3. Requeues / driver backpressure
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
					Title:     "驱动发包背压与重排 (Requeue)",
					Summary:   fmt.Sprintf("发生 %d 次驱动返回 NETDEV_TX_BUSY 重排（GSO=%d / BadTXQ=%d），表明网卡发送队列或驱动环短暂饱和。", st.RequeueCount, st.RequeueGSOCount, st.RequeueBadTxqCount),
					Metric:    fmt.Sprintf("%d 次重排", st.RequeueCount),
					SampleIDs: reqIDs,
				})
			}

			// 4. Healthy summary when clean
			if len(out.Insights) == 0 && len(samples) > 0 {
				out.Insights = append(out.Insights, kernel.Insight{
					ID:       "radar.healthy",
					Severity: "ok",
					Title:    "队列路径通畅，未触发异常阈值",
					Summary:  fmt.Sprintf("已扫描 %d 个样本，最大队列驻留 %.2f ms（告警阈值 %.1f ms），无丢包与驱动重排。", len(samples), maxMs, warnMs),
					Metric:   fmt.Sprintf("峰值 %.2f ms", maxMs),
				})
			}

			// Health KPI card
			tone := "ok"
			statusLabel := "健康"
			if drops >= dropThresh || maxMs >= critMs {
				tone = "bad"
				statusLabel = "存在瓶颈/丢包"
			} else if len(slow) > 0 || st.RequeueCount >= reqThresh {
				tone = "warn"
				statusLabel = "轻度波动"
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
