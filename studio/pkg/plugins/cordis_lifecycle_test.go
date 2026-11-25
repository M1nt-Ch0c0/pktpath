package plugins

import (
	"context"
	"encoding/json"
	"os"
	"pktpath/studio/pkg/kernel"
	"reflect"
	"testing"
	"time"
)

func TestCordisF02ActualCollectorFanoutMetadataOnly(t *testing.T) {
	host := os.Getenv("PKTPATH_TEST_CORDIS_HOST")
	if host == "" {
		t.Skip("explicit Node host required")
	}
	h := kernel.NewCordisLifecycleHost(kernel.CordisLifecycleOptions{HostPath: host})
	k := kernel.New(kernel.HostServices{AppDir: t.TempDir(), LifecycleHost: h})
	RegisterAllBuiltins(k)
	if err := k.Start(); err != nil {
		t.Fatal(err)
	}
	defer k.Shutdown()
	ids := []string{"builtin.collector.ebpf-tc", "builtin.collector.kernel-ext", "builtin.mode.oneshot", "builtin.mode.daemon"}
	wait := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.WaitActive(ctx, ids...); err != nil {
			node, _ := h.NodeState()
			t.Fatalf("%v Node=%s Go=%+v", err, node, h.Snapshot())
		}
	}
	wait()
	// Controlled independent old/new invocations, never run one task twice.
	old := kernel.New(kernel.HostServices{AppDir: t.TempDir()})
	RegisterAllBuiltins(old)
	old.Start()
	defer old.Shutdown()
	if !reflect.DeepEqual(old.Collector(), k.Collector()) || !reflect.DeepEqual(old.CaptureModes(), k.CaptureModes()) || !reflect.DeepEqual(old.CollectKernelExtensions(), k.CollectKernelExtensions()) {
		t.Fatal("metadata old/new difference")
	}
	if err := k.SetEnabled(ids[0], false); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if k.IsPluginActive(id) {
			t.Fatalf("%s retained active dependency", id)
		}
	}
	if len(k.CaptureModes()) != 0 || k.Collector() != nil || len(k.CollectKernelExtensions()) != 0 {
		t.Fatal("fanout registrations survived")
	}
	if err := k.SetEnabled(ids[0], true); err != nil {
		t.Fatal(err)
	}
	wait()
	for _, name := range []string{"collector.ebpf", "kernel.ext.builder", "capture.mode.oneshot", "capture.mode.daemon"} {
		if _, ok := k.Service(name); !ok {
			t.Fatalf("actual service %s absent", name)
		}
	}
	state, _ := json.Marshal(h.Snapshot())
	t.Logf("actual metadata-only graph=%s", state)
	// NO MaterializeKernelPluginFiles, analyzer/exporter execution, capture or ADB/SSH.
}
