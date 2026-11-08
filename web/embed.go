// Package web embeds the built user interface (web/dist).
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
