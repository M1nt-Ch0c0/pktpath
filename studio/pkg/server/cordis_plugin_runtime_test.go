package server

import (
	"context"
	"testing"
)

func TestDefaultPluginRuntimeIsCordis(t *testing.T) {
	s := New(Options{AppDir: t.TempDir()})
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	host := s.Kernel().Host()
	if host.PluginRuntime == nil {
		t.Fatal("new preview should default to the bundled Cordis plugin runtime when it is present")
	}
	if host.LifecycleHost != nil {
		t.Fatal("F02 lifecycle should stay off unless explicitly requested")
	}
	if host.AnalyzerHost != nil {
		t.Fatal("legacy F01 analyzer host should stay off unless explicitly requested")
	}
}

func TestDashDisablesDefaultPluginRuntime(t *testing.T) {
	s := New(Options{AppDir: t.TempDir(), CordisPluginRuntime: "-"})
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	if s.Kernel().Host().PluginRuntime != nil {
		t.Fatal("CordisPluginRuntime=- should leave the runtime unset")
	}
}
