package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync/atomic"

	"github.com/Jetvac/wdtt-router/internal/desktop"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// winUI is the app window (WebView2) and its tray icon. Closing the window
// hides it to the tray, so notifications keep coming; "Выход" in the tray
// menu quits.
type winUI struct {
	app      *desktop.App
	w        webview2.WebView
	hwnd     uintptr
	base     string
	oldProc  uintptr
	hintShow atomic.Bool
}

var theUI *winUI

func singleInstance() bool { return firstInstance() }

func fatal(msg string) { messageBox(msg) }

func runUI(app *desktop.App, startURL string, minimized, browser bool) {
	runtime.LockOSThread()
	// Sharp text on high-DPI screens (per-monitor v2).
	pSetProcessDpiAwarenessCx.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
	if browser {
		// Development: no window or tray, the address goes to stdout.
		app.Status = func(level, text string) { fmt.Printf("[%s] %s\n", level, text) }
		app.Notify = func(title, text string) { fmt.Printf("notification: %s: %s\n", title, text) }
		fmt.Println("Open", startURL)
		select {}
	}
	scale := 1.0
	if dpi, _, _ := pGetDpiForSystem.Call(); dpi > 0 {
		scale = float64(dpi) / 96
	}
	width := min(uint(1280*scale), uint(float64(sysMetric(0))*0.9))
	height := min(uint(840*scale), uint(float64(sysMetric(1))*0.88))
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(app.Store().Dir(), "webview"),
		WindowOptions: webview2.WindowOptions{
			Title: appTitle, Width: width, Height: height, Center: true,
		},
	})
	if w == nil {
		messageBox("Для работы WDTT Router нужен компонент Microsoft Edge WebView2 Runtime. Сейчас откроется страница загрузки: установите его и запустите приложение снова.")
		openURL("https://go.microsoft.com/fwlink/p/?LinkId=2124703")
		return
	}
	ui := &winUI{app: app, w: w, hwnd: uintptr(w.Window()), base: app.Base()}
	theUI = ui
	if minimized {
		pShowWindow.Call(ui.hwnd, swHide)
	}
	ui.setIcons()
	ui.subclass()
	t := newTray(ui)
	app.Status = func(level, text string) { t.setState(level, text) }
	app.Notify = func(title, text string) { t.balloon(title, text, false) }
	w.Navigate(startURL)
	w.Run()
	t.remove()
}

// show brings the window to the front (any thread).
func (u *winUI) show() {
	if r, _, _ := pIsIconic.Call(u.hwnd); r != 0 {
		pShowWindow.Call(u.hwnd, swRestore)
	} else {
		pShowWindow.Call(u.hwnd, swShow)
	}
	pSetForegroundWindow.Call(u.hwnd)
}

func (u *winUI) navigate(path string) {
	u.w.Dispatch(func() { u.w.Navigate(u.base + path) })
}

func (u *winUI) setIcons() {
	big := int(sysMetric(11)) // SM_CXICON
	small := int(sysMetric(49))
	pSendMessageW.Call(u.hwnd, wmSetIcon, 1, makeIcon(desktop.Icon(max(big, 32), "")))
	pSendMessageW.Call(u.hwnd, wmSetIcon, 0, makeIcon(desktop.Icon(max(small, 16), "")))
}

// subclass makes the close button hide the window instead of quitting.
func (u *winUI) subclass() {
	const gwlpWndProc = ^uintptr(3) // -4
	u.oldProc, _, _ = pSetWindowLongPtrW.Call(u.hwnd, gwlpWndProc, windows.NewCallback(mainProc))
}

func mainProc(hwnd, msg, wp, lp uintptr) uintptr {
	u := theUI
	if msg == wmClose {
		pShowWindow.Call(hwnd, swHide)
		if !u.hintShow.Swap(true) && theTray != nil {
			theTray.balloon(appTitle, "Приложение продолжает работать в трее и пришлёт уведомление, если что-то случится. Выход — в меню значка.", false)
		}
		return 0
	}
	r, _, _ := pCallWindowProcW.Call(u.oldProc, hwnd, msg, wp, lp)
	return r
}
