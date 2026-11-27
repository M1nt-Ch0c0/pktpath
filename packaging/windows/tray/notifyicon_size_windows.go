//go:build windows && (amd64 || arm64)

package main

import "unsafe"

// Compile-time assertion: NOTIFYICONDATAW on 64-bit Windows (Vista+) must be
// exactly 976 bytes; any drift breaks Shell_NotifyIconW callbacks/tooltips.
var _ [976]byte = [unsafe.Sizeof(notifyIconDataW{})]byte{}
