// Command wdtt-desktop is the WDTT Router app for Windows: a window with the
// panel, opened through an SSH tunnel to the panel server, and a tray icon
// with the servers' state and notifications. The panel keeps running on
// the server; the app only connects to it.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Jetvac/wdtt-router/internal/desktop"
	"github.com/Jetvac/wdtt-router/web/launcher"
)

var version = "dev"

func main() {
	minimized := flag.Bool("minimized", false, "start in the tray (used by autostart)")
	browser := flag.Bool("browser", false, "no window: print the address to open in a browser (development)")
	data := flag.String("data", "", `state folder (default: %APPDATA%\WDTT Router)`)
	flag.Parse()
	if !singleInstance() {
		return
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		fatal(err.Error())
		return
	}
	dir = filepath.Join(dir, "WDTT Router")
	if *data != "" {
		dir = *data
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		fatal(err.Error())
		return
	}
	logTo(filepath.Join(dir, "app.log"))
	app, err := desktop.New(dir, launcher.FS(), version)
	if err != nil {
		fatal("Не удалось запустить WDTT Router: " + err.Error())
		return
	}
	l, startURL, err := app.Listen()
	if err != nil {
		fatal("Не удалось запустить WDTT Router: " + err.Error())
		return
	}
	srv := &http.Server{Handler: app, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() { log.Println(srv.Serve(l)) }()
	log.Printf("WDTT Router app %s started", version)
	go app.AutoConnect()
	runUI(app, startURL, *minimized, *browser)
}

// logTo keeps a small log next to the app's state, for troubleshooting.
func logTo(path string) {
	if st, err := os.Stat(path); err == nil && st.Size() > 1<<20 {
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	log.SetOutput(f)
	fmt.Fprintln(f)
}
