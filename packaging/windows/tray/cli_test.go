package main

import "testing"

func TestParseTrayArgs(t *testing.T) {
	env := func(k string) string {
		if k == AppDirEnv {
			return ""
		}
		return ""
	}
	opt := ParseTrayArgs([]string{"--app-dir", `/tmp/my data`, "--install-dir", `/opt/PktPath Studio`, "--no-open"}, env, `C:\ignored\PktPathStudio.exe`)
	if opt.AppDir != `/tmp/my data` || opt.InstallDir != `/opt/PktPath Studio` || !opt.NoOpen {
		t.Fatalf("%+v", opt)
	}
	opt = ParseTrayArgs(nil, env, `/opt/PktPath Studio/PktPathStudio.exe`)
	if opt.InstallDir != `/opt/PktPath Studio` {
		t.Fatalf("install dir from exe: %q", opt.InstallDir)
	}
}
