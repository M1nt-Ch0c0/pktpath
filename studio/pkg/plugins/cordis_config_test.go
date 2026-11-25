package plugins

import (
	"context"
	"os"
	"pktpath/studio/pkg/kernel"
	"testing"
	"time"
)

func TestCordisF03ActualFourMetadataConfigOperations(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("explicit controlled host")
	}
	h := kernel.NewCordisLifecycleHost(kernel.CordisLifecycleOptions{HostPath: host, ConfigTransactions: true})
	k := kernel.New(kernel.HostServices{AppDir: t.TempDir(), LifecycleHost: h})
	RegisterAllBuiltins(k)
	if e := k.Start(); e != nil {
		t.Fatal(e)
	}
	defer k.Shutdown()
	ids := []string{"builtin.collector.ebpf-tc", "builtin.collector.kernel-ext", "builtin.mode.oneshot", "builtin.mode.daemon"}
	wait := func() {
		t.Helper()
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			all := true
			for _, id := range ids {
				all = all && k.IsPluginActive(id)
			}
			if all {
				return
			}
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Fatalf("real metadata fanout not active: %+v", h.Snapshot())
			}
		}
	}
	wait()
	for _, id := range ids {
		if _, e := k.SetConfigContext(context.Background(), id, map[string]any{}); e != nil {
			t.Fatalf("%s: %v", id, e)
		}
		wait()
	}
	snapshot := h.Snapshot()
	if len(snapshot.ConfigOperations) != 4 {
		t.Fatalf("not all four operations recorded: %+v", snapshot)
	}
	for _, op := range snapshot.ConfigOperations {
		if op.Phase != "committed" || !op.RunningLive || op.ActivatedGeneration == op.OriginalGeneration {
			t.Fatalf("metadata labels without new live generation: %+v", op)
		}
	}
	for _, name := range []string{"collector.ebpf", "kernel.ext.builder", "capture.mode.oneshot", "capture.mode.daemon"} {
		if _, ok := k.Service(name); !ok {
			t.Fatal("actual Go service lost", name)
		}
	}
	// Metadata only. Never calls Materialize, capture hooks, C, devices or transport.
}
