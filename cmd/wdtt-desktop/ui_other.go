//go:build !windows

package main

import (
	"fmt"

	"github.com/Jetvac/wdtt-router/internal/desktop"
)

// Outside Windows the app runs headless for development: open the printed
// address in a browser.
func singleInstance() bool { return true }

func fatal(msg string) { fmt.Println(msg) }

func runUI(app *desktop.App, startURL string, _, _ bool) {
	app.Status = func(level, text string) { fmt.Printf("[%s] %s\n", level, text) }
	app.Notify = func(title, text string) { fmt.Printf("notification: %s: %s\n", title, text) }
	fmt.Println("Open", startURL)
	select {}
}
