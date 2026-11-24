package studio

import (
	"embed"
	"io/fs"
)

//go:embed web/*
var embeddedWeb embed.FS

//go:embed assets_stage/*
var embeddedAssetsStage embed.FS

// WebFS returns the embedded frontend workbench rooted at studio/web/.
func WebFS() (fs.FS, error) {
	return fs.Sub(embeddedWeb, "web")
}

// AssetsStageFS returns the embedded runtime toolchain rooted at studio/assets_stage/.
func AssetsStageFS() (fs.FS, error) {
	return fs.Sub(embeddedAssetsStage, "assets_stage")
}
