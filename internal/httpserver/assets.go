package httpserver

import (
	"embed"
	"io/fs"
)

//go:embed assets/*
var embeddedAssets embed.FS

// Assets returns the embedded UI filesystem rooted at the assets directory.
func Assets() fs.FS {
	sub, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}
