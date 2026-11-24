package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pktpath/studio/pkg/kernel"
	"pktpath/studio/pkg/reconstruct"
)

func TestRegisterAllBuiltinsAndCascade(t *testing.T) {
	dir := t.TempDir()
	k := kernel.New(kernel.HostServices{
		AppDir:       dir,
		PluginsDir:   filepath.Join(dir, "plugins"),
		SessionsRoot: filepath.Join(dir, "sessions"),
	})
	RegisterAllBuiltins(k)
	if err := k.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer k.Shutdown()

	snap := k.Snapshot("2.0.0")
	if snap.TotalPlugins != 13 || snap.ActivePlugins != 13 {
		t.Fatalf("expected 13/13 active built-in plugins, got %d/%d", snap.ActivePlugins, snap.TotalPlugins)
	}
	if len(snap.Transports) != 3 || len(snap.CaptureModes) != 2 || len(snap.Exporters) != 3 || len(snap.Analyzers) != 2 {
		t.Fatalf("unexpected extension counts: transports=%d modes=%d exporters=%d analyzers=%d",
			len(snap.Transports), len(snap.CaptureModes), len(snap.Exporters), len(snap.Analyzers))
	}

	// Disabling eBPF collector cascades to capture modes & kernel-ext builder
	if err := k.SetEnabled("builtin.collector.ebpf-tc", false); err != nil {
		t.Fatalf("disable collector failed: %v", err)
	}
	if len(k.CaptureModes()) != 0 || k.Collector() != nil {
		t.Fatalf("dependent capture modes did not deactivate")
	}
	if err := k.SetEnabled("builtin.collector.ebpf-tc", true); err != nil {
		t.Fatalf("re-enable collector failed: %v", err)
	}
	if len(k.CaptureModes()) != 2 {
		t.Fatalf("dependent capture modes did not reactivate")
	}
}

func TestKernelExtBuilderMultiQdisc(t *testing.T) {
	dir := t.TempDir()
	k := kernel.New(kernel.HostServices{AppDir: dir, PluginsDir: filepath.Join(dir, "plugins"), SessionsRoot: filepath.Join(dir, "sessions")})
	RegisterAllBuiltins(k)
	_ = k.Start()
	defer k.Shutdown()

	_, err := k.SetConfig("builtin.collector.kernel-ext", map[string]any{
		"sock_fields": []any{
			map[string]any{"struct": "sock", "field": "sk_mark", "size": "4", "role": "tag", "label": "mark"},
			map[string]any{"struct": "sock", "field": "sk_priority", "size": "4", "role": "tag", "label": "prio"},
		},
		"qdiscs": []any{
			map[string]any{"kind": "netem", "mode": "leaf", "enqueue_sym": "netem_enqueue", "dequeue_sym": "netem_dequeue"},
			map[string]any{"kind": "tbf", "mode": "leaf", "enqueue_sym": "tbf_enqueue", "dequeue_sym": "tbf_dequeue"},
			map[string]any{"kind": "fq", "mode": "leaf", "enqueue_sym": "fq_enqueue", "dequeue_sym": "fq_dequeue"},
		},
	})
	if err != nil {
		t.Fatalf("SetConfig kernel-ext failed: %v", err)
	}
	snap := k.Snapshot("2.0.0")
	if snap.KernelExtSummary.SockFields != 2 || snap.KernelExtSummary.Qdiscs != 3 {
		t.Fatalf("unexpected kernel_ext_summary: %+v", snap.KernelExtSummary)
	}
	files, err := k.MaterializeKernelPluginFiles()
	if err != nil || len(files) != 1 {
		t.Fatalf("MaterializeKernelPluginFiles failed: %v %v", files, err)
	}
}

func TestAnomalyRadarAndCSVReportExporter(t *testing.T) {
	dir := t.TempDir()
	k := kernel.New(kernel.HostServices{AppDir: dir, PluginsDir: filepath.Join(dir, "plugins"), SessionsRoot: filepath.Join(dir, "sessions")})
	RegisterAllBuiltins(k)
	_ = k.Start()
	defer k.Shutdown()

	p95 := 12500.0
	ov := &reconstruct.SessionOverview{
		Stats: &reconstruct.Stats{
			Scope:        "tc-egress",
			Mode:         "oneshot",
			SampleRate:   "1/1",
			SampleCounts: reconstruct.SampleCounts{Total: 2},
			Branches:     reconstruct.BranchCounts{Total: 3, Complete: 3},
			Endpoints:    map[string]int{"TX_OK": 1, "DROP": 1},
			RequeueCount: 1,
			Queues: []reconstruct.QueueStat{
				{Label: "eth0 NETEM 20:", Kind: "netem", PairedN: 2, P95Us: &p95},
			},
		},
		Samples: []reconstruct.SampleRow{
			{SampleID: 1, Comm: "ping", Proto: "icmp", Src: "192.0.2.1", Dst: "198.51.100.2", PktLen: 98, MaxSojournUs: 12500, TotalUs: 12800, Endpoint: "TX_OK", Completeness: "complete", BranchCount: 2, Requeued: true, PathSig: "ENTRY -> NETEM -> TX_OK"},
			{SampleID: 2, Comm: "iperf3", Proto: "tcp", Src: "192.0.2.1:5000", Dst: "198.51.100.2:443", PktLen: 1500, MaxSojournUs: 300, TotalUs: 450, Endpoint: "DROP", Completeness: "complete", BranchCount: 1, PathSig: "ENTRY -> DROP"},
		},
	}

	anOut := k.AnalyzeSession(context.Background(), &kernel.AnalyzeInput{SessionID: "s1", SessionDir: dir, Overview: ov})
	ids := map[string]bool{}
	for _, ins := range anOut.Insights {
		ids[ins.ID] = true
	}
	for _, want := range []string{"dag.multi_branch", "radar.high_sojourn", "radar.drops", "radar.requeue"} {
		if !ids[want] {
			t.Fatalf("missing expected insight %q in %+v", want, anOut.Insights)
		}
	}

	// CSV export
	csvPath := filepath.Join(dir, "out.csv")
	res, err := k.RunExporter(context.Background(), "csv-report", &kernel.ExportInput{SessionID: "s1", SessionDir: dir, Overview: ov, OutPath: csvPath})
	if err != nil || !res.OK {
		t.Fatalf("csv export failed: %v %+v", err, res)
	}
	b, _ := os.ReadFile(csvPath)
	if !strings.Contains(string(b), "sample_id,uid") || !strings.Contains(string(b), "iperf3") {
		t.Fatalf("unexpected CSV content: %s", string(b))
	}

	// Switch exporter to Markdown mode and verify
	if _, err := k.SetConfig("builtin.exporter.csv-report", map[string]any{"format": "markdown"}); err != nil {
		t.Fatalf("switch csv-report to markdown failed: %v", err)
	}
	mdPath := filepath.Join(dir, "out.md")
	res2, err := k.RunExporter(context.Background(), "csv-report", &kernel.ExportInput{SessionID: "s1", SessionDir: dir, Overview: ov, OutPath: mdPath})
	if err != nil || !res2.OK {
		t.Fatalf("markdown export failed: %v %+v", err, res2)
	}
	mb, _ := os.ReadFile(mdPath)
	if !strings.Contains(string(mb), "# PktPath 诊断报告") || !strings.Contains(string(mb), "eth0 NETEM 20:") {
		t.Fatalf("unexpected Markdown content: %s", string(mb))
	}
}
