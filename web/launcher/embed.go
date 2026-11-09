// Package launcher embeds the Windows app's own screens (server list and
// setup), built from web/launcher.html into web/launcher/dist.
package launcher

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS is the built launcher, rooted at its index (launcher.html).
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
