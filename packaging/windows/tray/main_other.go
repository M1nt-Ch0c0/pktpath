//go:build !windows

package main

import (
	"fmt"
	"os"
)

// main is a stub so `go test ./...` and a Linux `go build` succeed.
// The tray host is a Windows GUI application and is not used on Linux.
func main() {
	fmt.Fprintln(os.Stderr, "PktPathStudio 托盘宿主仅支持 Windows。请使用 CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build 交叉编译 PktPathStudio.exe。")
	os.Exit(2)
}
