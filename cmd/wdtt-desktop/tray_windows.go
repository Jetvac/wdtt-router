package main

import (
	"image"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/Jetvac/wdtt-router/internal/desktop"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")
	gdi32   = windows.NewLazySystemDLL("gdi32.dll")

	pRegisterClassExW         = user32.NewProc("RegisterClassExW")
	pCreateWindowExW          = user32.NewProc("CreateWindowExW")
	pDefWindowProcW           = user32.NewProc("DefWindowProcW")
	pCallWindowProcW          = user32.NewProc("CallWindowProcW")
	pSetWindowLongPtrW        = user32.NewProc("SetWindowLongPtrW")
	pShowWindow               = user32.NewProc("ShowWindow")
	pIsIconic                 = user32.NewProc("IsIconic")
	pIsWindowVisible          = user32.NewProc("IsWindowVisible")
	pSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	pPostMessageW             = user32.NewProc("PostMessageW")
	pSendMessageW             = user32.NewProc("SendMessageW")
	pFindWindowW              = user32.NewProc("FindWindowW")
	pCreatePopupMenu          = user32.NewProc("CreatePopupMenu")
	pAppendMenuW              = user32.NewProc("AppendMenuW")
	pSetMenuDefaultItem       = user32.NewProc("SetMenuDefaultItem")
	pTrackPopupMenu           = user32.NewProc("TrackPopupMenu")
	pDestroyMenu              = user32.NewProc("DestroyMenu")
	pGetCursorPos             = user32.NewProc("GetCursorPos")
	pRegisterWindowMessageW   = user32.NewProc("RegisterWindowMessageW")
	pCreateIconIndirect       = user32.NewProc("CreateIconIndirect")
	pDestroyIcon              = user32.NewProc("DestroyIcon")
	pGetSystemMetrics         = user32.NewProc("GetSystemMetrics")
	pGetDpiForSystem          = user32.NewProc("GetDpiForSystem")
	pSetProcessDpiAwarenessCx = user32.NewProc("SetProcessDpiAwarenessContext")
	pMessageBoxW              = user32.NewProc("MessageBoxW")
	pShellNotifyIconW         = shell32.NewProc("Shell_NotifyIconW")
	pShellExecuteW            = shell32.NewProc("ShellExecuteW")
	pCreateDIBSection         = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap             = gdi32.NewProc("CreateBitmap")
	pDeleteObject             = gdi32.NewProc("DeleteObject")
)

const (
	wmNull        = 0x0000
	wmClose       = 0x0010
	wmSetIcon     = 0x0080
	wmContextMenu = 0x007B
	wmCommand     = 0x0111
	wmApp         = 0x8000
	wmTray        = wmApp + 10 // tray icon callback
	wmShowMain    = wmApp + 11 // a second copy of the app asks to show the window

	ninSelect           = 0x400
	ninKeySelect        = 0x401
	ninBalloonUserClick = 0x405

	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4
	nifMessage    = 0x1
	nifIcon       = 0x2
	nifTip        = 0x4
	nifInfo       = 0x10
	nifShowTip    = 0x80
	niifInfo      = 0x1
	niifWarning   = 0x2

	swHide    = 0
	swShow    = 5
	swRestore = 9

	mfString    = 0x0
	mfGrayed    = 0x1
	mfChecked   = 0x8
	mfSeparator = 0x800
	tpmRightBtn = 0x2
	tpmBottom   = 0x20

	appTitle   = "WDTT Router"
	trayClass  = "WDTTRouterTray"
	runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
)

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

// Menu commands.
const (
	cmdOpen = iota + 1
	cmdServers
	cmdDisconnect
	cmdAutostart
	cmdExit
)

// tray is the notification-area icon: its colour shows the state of the
// servers, its menu opens the window, and balloons carry panel events.
type tray struct {
	ui   *winUI
	hwnd uintptr

	mu       sync.Mutex
	nid      notifyIconData
	icons    map[string]uintptr
	level    string
	text     string
	taskbarC uintptr
}

var theTray *tray

func newTray(ui *winUI) *tray {
	t := &tray{ui: ui, icons: map[string]uintptr{}, level: "off", text: "Не подключено"}
	theTray = t
	cls, _ := windows.UTF16PtrFromString(trayClass)
	var hinst windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &hinst)
	wc := wndClassEx{LpfnWndProc: windows.NewCallback(trayProc), HInstance: uintptr(hinst), LpszClassName: cls}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	title, _ := windows.UTF16PtrFromString(appTitle)
	t.hwnd, _, _ = pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)), 0, 0, 0, 0, 0, 0, 0, uintptr(hinst), 0)
	tc, _ := windows.UTF16PtrFromString("TaskbarCreated")
	t.taskbarC, _, _ = pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tc)))
	t.nid.CbSize = uint32(unsafe.Sizeof(t.nid))
	t.nid.HWnd = t.hwnd
	t.nid.UID = 1
	t.nid.UCallbackMessage = wmTray
	t.add()
	return t
}

func (t *tray) icon(level string) uintptr {
	if h, ok := t.icons[level]; ok {
		return h
	}
	size := int(sysMetric(49)) // SM_CXSMICON, already scaled for the DPI
	if size < 16 {
		size = 16
	}
	h := makeIcon(desktop.Icon(size, level))
	t.icons[level] = h
	return h
}

func (t *tray) add() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nid.UFlags = nifMessage | nifIcon | nifTip | nifShowTip
	t.nid.HIcon = t.icon(t.level)
	copyUTF16(t.nid.SzTip[:], tipText(t.text))
	pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))
	t.nid.UVersion = 4 // NOTIFYICON_VERSION_4
	pShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&t.nid)))
}

// setState changes the icon colour and tooltip (any goroutine).
func (t *tray) setState(level, text string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.level, t.text = level, text
	t.nid.UFlags = nifIcon | nifTip | nifShowTip
	t.nid.HIcon = t.icon(level)
	copyUTF16(t.nid.SzTip[:], tipText(text))
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
}

// balloon shows a notification (a toast on Windows 10 and 11).
func (t *tray) balloon(title, text string, warn bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nid.UFlags = nifInfo
	copyUTF16(t.nid.SzInfoTitle[:], title)
	copyUTF16(t.nid.SzInfo[:], text)
	t.nid.DwInfoFlags = niifInfo
	if warn {
		t.nid.DwInfoFlags = niifWarning
	}
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
}

func (t *tray) remove() {
	t.mu.Lock()
	defer t.mu.Unlock()
	pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
}

func tipText(s string) string {
	// The tooltip holds 127 characters; the first lines matter most.
	return appTitle + " — " + strings.ReplaceAll(s, "\n\n", "\n")
}

func trayProc(hwnd, msg, wp, lp uintptr) uintptr {
	t := theTray
	switch {
	case t != nil && msg == t.taskbarC && msg != 0:
		t.add() // Explorer restarted
		return 0
	case msg == wmShowMain:
		t.ui.show()
		return 0
	case msg == wmTray:
		switch lp & 0xffff {
		case ninSelect, ninKeySelect, ninBalloonUserClick:
			t.ui.show()
		case wmContextMenu:
			t.menu()
		}
		return 0
	case msg == wmCommand:
		t.command(int(wp & 0xffff))
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wp, lp)
	return r
}

func (t *tray) menu() {
	m, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(m)
	t.mu.Lock()
	state := strings.SplitN(t.text, "\n", 2)[0]
	t.mu.Unlock()
	appendMenu(m, mfString|mfGrayed, 0, state)
	appendMenu(m, mfSeparator, 0, "")
	appendMenu(m, mfString, cmdOpen, "Открыть панель")
	appendMenu(m, mfString, cmdServers, "Серверы…")
	if t.ui.app.Active() != "" {
		appendMenu(m, mfString, cmdDisconnect, "Отключиться")
	}
	appendMenu(m, mfSeparator, 0, "")
	flags := uintptr(mfString)
	if autostartEnabled() {
		flags |= mfChecked
	}
	appendMenu(m, flags, cmdAutostart, "Запускать вместе с Windows")
	appendMenu(m, mfSeparator, 0, "")
	appendMenu(m, mfString, cmdExit, "Выход")
	pSetMenuDefaultItem.Call(m, cmdOpen, 0)
	var pt struct{ X, Y int32 }
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// The usual dance so the menu closes when clicking elsewhere.
	pSetForegroundWindow.Call(t.hwnd)
	pTrackPopupMenu.Call(m, tpmRightBtn|tpmBottom, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	pPostMessageW.Call(t.hwnd, wmNull, 0, 0)
}

func (t *tray) command(id int) {
	switch id {
	case cmdOpen:
		t.ui.show()
	case cmdServers:
		t.ui.navigate("/_app/")
		t.ui.show()
	case cmdDisconnect:
		t.ui.app.Disconnect()
		t.ui.navigate("/_app/")
	case cmdAutostart:
		setAutostart(!autostartEnabled())
	case cmdExit:
		t.remove()
		t.ui.w.Terminate()
	}
}

func appendMenu(m uintptr, flags uintptr, id int, text string) {
	p, _ := windows.UTF16PtrFromString(text)
	pAppendMenuW.Call(m, flags, uintptr(id), uintptr(unsafe.Pointer(p)))
}

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	clear(dst)
	copy(dst, u)
}

// ---- icons -------------------------------------------------------------------------

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

// makeIcon turns an image into an HICON with alpha.
func makeIcon(img *image.NRGBA) uintptr {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	bi := bitmapInfoHeader{Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}
	bi.Size = uint32(unsafe.Sizeof(bi))
	var bits unsafe.Pointer
	color, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if color == 0 {
		return 0
	}
	px := unsafe.Slice((*byte)(bits), w*h*4)
	for i := 0; i < w*h; i++ {
		px[i*4+0] = img.Pix[i*4+2]
		px[i*4+1] = img.Pix[i*4+1]
		px[i*4+2] = img.Pix[i*4+0]
		px[i*4+3] = img.Pix[i*4+3]
	}
	mask, _, _ := pCreateBitmap.Call(uintptr(w), uintptr(h), 1, 1, 0)
	ii := iconInfo{FIcon: 1, HbmMask: mask, HbmColor: color}
	hicon, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	pDeleteObject.Call(color)
	pDeleteObject.Call(mask)
	return hicon
}

func sysMetric(i int) uintptr {
	r, _, _ := pGetSystemMetrics.Call(uintptr(i))
	return r
}

// ---- autostart, single instance, message box ----------------------------------------

func autostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(appTitle)
	exe, _ := os.Executable()
	return err == nil && strings.Contains(strings.ToLower(v), strings.ToLower(exe))
}

func setAutostart(on bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if !on {
		_ = k.DeleteValue(appTitle)
		return
	}
	exe, _ := os.Executable()
	_ = k.SetStringValue(appTitle, `"`+exe+`" --minimized`)
}

// firstInstance reports whether no other copy runs; otherwise it asks the
// running copy to show its window.
func firstInstance() bool {
	name, _ := windows.UTF16PtrFromString(`Local\WDTTRouterDesktop`)
	_, err := windows.CreateMutex(nil, false, name)
	if err != windows.ERROR_ALREADY_EXISTS {
		return true
	}
	cls, _ := windows.UTF16PtrFromString(trayClass)
	if h, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0); h != 0 {
		pPostMessageW.Call(h, wmShowMain, 0, 0)
	}
	return false
}

func messageBox(text string) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(appTitle)
	pMessageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), 0x10)
}

func openURL(u string) {
	op, _ := windows.UTF16PtrFromString("open")
	p, _ := windows.UTF16PtrFromString(u)
	pShellExecuteW.Call(0, uintptr(unsafe.Pointer(op)), uintptr(unsafe.Pointer(p)), 0, 0, swShow)
}
