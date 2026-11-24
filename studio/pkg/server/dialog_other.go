//go:build !windows

package server

import (
	"context"
	"errors"
)

func pickFolderNative(_ context.Context, _ string) (string, bool, error) {
	return "", false, errors.New("native folder picker is only supported on Windows")
}

func saveFileNative(_ context.Context, _, _, _ string) (string, bool, error) {
	return "", false, errors.New("native save-file dialog is only supported on Windows")
}

func openFileNative(_ context.Context, _, _, _ string) (string, bool, error) {
	return "", false, errors.New("native open-file dialog is only supported on Windows")
}

func revealPathNative(_ string, _ bool) error {
	return errors.New("explorer reveal is only supported on Windows")
}
