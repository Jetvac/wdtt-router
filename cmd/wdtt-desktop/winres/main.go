// Command winres writes the Windows resources of the app (icon, manifest,
// version information) as .syso files that the Go linker picks up:
//
//	go run ./cmd/wdtt-desktop/winres -version v1.2.1
//
// The release build runs it; without it the app still builds, just without
// an icon in Explorer.
package main

import (
	"flag"
	"image"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Jetvac/wdtt-router/internal/desktop"
	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func main() {
	ver := flag.String("version", "0.0.0", "release version (v1.2.3 or 1.2.3-dev)")
	out := flag.String("out", "cmd/wdtt-desktop", "folder of the app's main package")
	flag.Parse()
	var imgs []image.Image
	for _, size := range []int{16, 20, 24, 32, 40, 48, 64, 256} {
		imgs = append(imgs, desktop.Icon(size, ""))
	}
	icon, err := winres.NewIconFromImages(imgs)
	if err != nil {
		log.Fatal(err)
	}
	var rs winres.ResourceSet
	if err := rs.SetIcon(winres.ID(1), icon); err != nil {
		log.Fatal(err)
	}
	rs.SetManifest(winres.AppManifest{
		Description:         "WDTT Router",
		DPIAwareness:        winres.DPIPerMonitorV2,
		UseCommonControlsV6: true,
	})
	num := regexp.MustCompile(`\d+(\.\d+){0,3}`).FindString(*ver)
	if num == "" {
		num = "0.0.0"
	}
	var vi version.Info
	vi.SetFileVersion(num)
	vi.SetProductVersion(num)
	for k, v := range map[string]string{
		version.ProductName:      "WDTT Router",
		version.FileDescription:  "WDTT Router",
		version.ProductVersion:   *ver,
		version.FileVersion:      *ver,
		version.CompanyName:      "WDTT Router contributors",
		version.LegalCopyright:   "MIT License",
		version.OriginalFilename: "wdtt-router.exe",
	} {
		if err := vi.Set(0x409, k, v); err != nil {
			log.Fatal(err)
		}
	}
	rs.SetVersionInfo(vi)
	for name, arch := range map[string]winres.Arch{"amd64": winres.ArchAMD64, "arm64": winres.ArchARM64} {
		f, err := os.Create(filepath.Join(*out, "rsrc_windows_"+name+".syso"))
		if err != nil {
			log.Fatal(err)
		}
		if err := rs.WriteObject(f, arch); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}
