// Package web embeds the built React UI. Run `make ui` to populate dist before
// building the binary; without it the server explains that the UI is missing.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Files returns the built UI rooted at dist.
func Files() fs.FS {
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return files
}
