package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/spec"
	"github.com/Jetvac/wdtt-router/internal/store"
)

const (
	maxWDTTKeys = 200
	// maxKeyDevices is the most devices one key can have (a server has 249
	// client addresses).
	maxKeyDevices = 249
	// unbindKeep is how long a removed device stays in the key's unbind
	// list; the server applies it within seconds.
	unbindKeep = 30 * 24 * time.Hour
)

var (
	reVKHash   = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	rePassword = regexp.MustCompile(`^[A-Za-z0-9._-]{16,128}$`)
)

// normalizeVKHashes accepts call links or bare hashes, comma separated,
// and returns the hashes the way a wdtt:// link carries them.
func normalizeVKHashes(in string) (string, error) {
	var out []string
	for _, h := range strings.Split(in, ",") {
		h = strings.TrimSpace(h)
		if i := strings.LastIndex(h, "/"); i >= 0 {
			h = h[i+1:]
		}
		if i := strings.IndexAny(h, "?#"); i >= 0 {
			h = h[:i]
		}
		if h == "" {
			continue
		}
		if !reVKHash.MatchString(h) {
			return "", fmt.Errorf("хеш звонка %q имеет неверный формат", h)
		}
		out = append(out, h)
	}
	if len(out) > 8 {
		return "", errors.New("не больше 8 хешей звонков")
	}
	return strings.Join(out, ","), nil
}

// readWDTTRuntime returns what a running WDTT server reports. The panel
// runs on the entry server, so it reads the file the server rewrites every
// few seconds; the node status is the fallback.
func (a *App) readWDTTRuntime(kind string) *spec.WDTTRuntime {
	b, err := os.ReadFile(agent.WDTTServerOf(kind).Status)
	if err == nil {
		var r spec.WDTTRuntime
		if json.Unmarshal(b, &r) == nil && time.Since(time.Unix(r.UpdatedAt, 0)) < time.Minute {
			return &r
		}
	}
	n, _ := a.localNode()
	if kind == spec.WDTTTurnVK {
		if n.Status.TurnVK != nil {
			return n.Status.TurnVK.Runtime
		}
		return nil
	}
	return n.Status.WDTT
}

// wdttKeySpecs converts the stored keys of one server into its configuration.
func (a *App) wdttKeySpecs(kind string) ([]spec.WDTTKey, error) {
	keys, err := a.Store.WDTTKeys()
	if err != nil {
		return nil, err
	}
	out := []spec.WDTTKey{}
	for _, k := range keys {
		if k.Kind != kind {
			continue
		}
		sk := spec.WDTTKey{ID: k.ID, Password: k.Password, ExpiresAt: k.ExpiresAt, Disabled: k.Disabled, DeviceEpoch: k.DeviceEpoch, MaxDevices: k.MaxDevices}
		for _, u := range k.Unbind {
			sk.Unbind = append(sk.Unbind, spec.WDTTUnbind{Device: u.Device, At: u.At})
		}
		out = append(out, sk)
	}
	return out, nil
}

type wdttKeyView struct {
	store.WDTTKey
	State    string                   `json:"state"` // active, disabled, expired
	DeviceID string                   `json:"device_id"`
	DeviceIP string                   `json:"device_ip"`
	Sessions int                      `json:"sessions"`
	Up       int64                    `json:"up_bytes"`
	Down     int64                    `json:"down_bytes"`
	LastSeen int64                    `json:"last_seen"`
	Devices  []spec.WDTTDeviceRuntime `json:"devices"`
}

// wdttDeviceView is one row of the list of all devices.
type wdttDeviceView struct {
	spec.WDTTDeviceRuntime
	Kind    string `json:"kind"`
	KeyID   string `json:"key_id"`
	KeyName string `json:"key_name"`
}

type wdttServerView struct {
	Kind       string               `json:"kind"`
	Label      string               `json:"label"`
	Enabled    bool                 `json:"enabled"`
	DTLSPort   int                  `json:"dtls_port"`
	MainVKHash string               `json:"main_vk_hash"`
	Runtime    map[string]any       `json:"runtime,omitempty"`
	Main       *spec.WDTTKeyRuntime `json:"main,omitempty"`
}

func runtimeView(rt *spec.WDTTRuntime) map[string]any {
	if rt == nil {
		return nil
	}
	return map[string]any{"sessions": rt.Sessions, "devices": rt.Devices, "version": rt.Version,
		"started_at": rt.StartedAt, "updated_at": rt.UpdatedAt, "auth_failures": rt.AuthFailures,
		"handshake_failures": rt.HandshakeFailures, "main": rt.Keys["main"]}
}

func (a *App) listWDTTKeys(w http.ResponseWriter, r *http.Request, s auth.Session) {
	keys, err := a.Store.WDTTKeys()
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	runtimes := map[string]*spec.WDTTRuntime{}
	servers := map[string]wdttServerView{}
	devices := []wdttDeviceView{}
	for _, k := range wdttKinds {
		ws := a.wdttSettings(k)
		rt := a.readWDTTRuntime(k.ID)
		if !ws.Enabled {
			rt = nil
		}
		runtimes[k.ID] = rt
		sv := wdttServerView{Kind: k.ID, Label: k.Label, Enabled: ws.Enabled, DTLSPort: ws.DTLSPort,
			MainVKHash: a.Store.Setting(k.prefix+"vk_hash", ""), Runtime: runtimeView(rt)}
		if rt != nil {
			if m, ok := rt.Keys["main"]; ok {
				sv.Main = &m
				for _, d := range m.Devices {
					devices = append(devices, wdttDeviceView{WDTTDeviceRuntime: d, Kind: k.ID, KeyID: "main", KeyName: "Пароль владельца"})
				}
			}
		}
		servers[k.ID] = sv
	}
	now := time.Now().Unix()
	views := make([]wdttKeyView, 0, len(keys))
	for _, k := range keys {
		v := wdttKeyView{WDTTKey: k, State: "active", Devices: []spec.WDTTDeviceRuntime{}}
		switch {
		case k.Disabled:
			v.State = "disabled"
		case k.ExpiresAt != 0 && now >= k.ExpiresAt:
			v.State = "expired"
		}
		if rt := runtimes[k.Kind]; rt != nil {
			if kr, ok := rt.Keys[k.ID]; ok {
				v.DeviceID, v.DeviceIP, v.Sessions, v.Up, v.Down, v.LastSeen = kr.DeviceID, kr.DeviceIP, kr.Sessions, kr.Up, kr.Down, kr.LastSeen
				if kr.Devices != nil {
					v.Devices = kr.Devices
				}
				for _, d := range kr.Devices {
					devices = append(devices, wdttDeviceView{WDTTDeviceRuntime: d, Kind: k.Kind, KeyID: k.ID, KeyName: k.Name})
				}
			}
		}
		views = append(views, v)
	}
	sort.SliceStable(devices, func(i, j int) bool {
		if (devices[i].Sessions > 0) != (devices[j].Sessions > 0) {
			return devices[i].Sessions > 0
		}
		return devices[i].LastSeen > devices[j].LastSeen
	})
	out := map[string]any{"keys": views, "limit": maxWDTTKeys, "max_devices": maxKeyDevices,
		"servers": servers, "devices": devices,
		// Earlier fields, about the standard server.
		"main_vk_hash": servers[spec.WDTTStandard].MainVKHash}
	if rt := runtimes[spec.WDTTStandard]; rt != nil {
		out["runtime"] = runtimeView(rt)
	}
	writeJSON(w, 200, out)
}

func validMaxDevices(n int) error {
	if n < 0 || n > maxKeyDevices {
		return fmt.Errorf("число устройств: 0 (без ограничения) – %d", maxKeyDevices)
	}
	return nil
}

func (a *App) createWDTTKey(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Name       string `json:"name"`
		Days       int    `json:"days"`
		VKHash     string `json:"vk_hash"`
		Kind       string `json:"kind"`
		MaxDevices int    `json:"max_devices"`
	}
	if !decode(w, r, &body) {
		return
	}
	kind, ok := wdttKindOf(body.Kind)
	if !ok {
		apiError(w, 400, "неизвестный тип клиента")
		return
	}
	if !a.wdttSettings(kind).Enabled {
		apiError(w, 400, "сначала включите сервер WDTT для этого клиента ("+kind.Label+")")
		return
	}
	keys, err := a.Store.WDTTKeys()
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	if len(keys) >= maxWDTTKeys {
		apiError(w, 400, fmt.Sprintf("не больше %d ключей", maxWDTTKeys))
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || utf8.RuneCountInString(body.Name) > 64 {
		apiError(w, 400, "укажите название ключа (до 64 символов)")
		return
	}
	if body.Days < 0 || body.Days > 3650 {
		apiError(w, 400, "срок действия: 0 (бессрочно) – 3650 дней")
		return
	}
	if err := validMaxDevices(body.MaxDevices); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	hash, err := normalizeVKHashes(body.VKHash)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	k := store.WDTTKey{ID: "k" + strings.ToLower(spec.NewPassword(10)), Name: body.Name, Password: spec.NewPassword(20), VKHash: hash,
		Kind: kind.ID, MaxDevices: body.MaxDevices}
	k.ID = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return 'x'
	}, k.ID)
	if body.Days > 0 {
		k.ExpiresAt = time.Now().Add(time.Duration(body.Days) * 24 * time.Hour).Unix()
	}
	if err := a.Store.PutWDTTKey(k); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	a.queueEntryWith(w, r, s, "wdtt.key.create", fmt.Sprintf("%s %s kind=%s max_devices=%d", k.ID, k.Name, k.Kind, k.MaxDevices), map[string]any{"id": k.ID})
}

func (a *App) patchWDTTKey(w http.ResponseWriter, r *http.Request, s auth.Session) {
	k, err := a.Store.WDTTKey(r.PathValue("id"))
	if err != nil {
		apiError(w, 404, "ключ не найден")
		return
	}
	var body struct {
		Name        *string `json:"name"`
		Disabled    *bool   `json:"disabled"`
		ResetDevice bool    `json:"reset_device"` // unbind every device
		Days        *int    `json:"days"`         // new term from now; 0 = never expires
		VKHash      *string `json:"vk_hash"`
		MaxDevices  *int    `json:"max_devices"`
		// UnbindDevice frees one device; it may connect again if a slot is free.
		UnbindDevice *string `json:"unbind_device"`
	}
	if !decode(w, r, &body) {
		return
	}
	var what []string
	if body.Name != nil {
		n := strings.TrimSpace(*body.Name)
		if n == "" || utf8.RuneCountInString(n) > 64 {
			apiError(w, 400, "укажите название ключа (до 64 символов)")
			return
		}
		k.Name = n
		what = append(what, "name")
	}
	if body.VKHash != nil {
		h, err := normalizeVKHashes(*body.VKHash)
		if err != nil {
			apiError(w, 400, err.Error())
			return
		}
		k.VKHash = h
		what = append(what, "vk_hash")
	}
	if body.Days != nil {
		if *body.Days < 0 || *body.Days > 3650 {
			apiError(w, 400, "срок действия: 0 (бессрочно) – 3650 дней")
			return
		}
		k.ExpiresAt = 0
		if *body.Days > 0 {
			k.ExpiresAt = time.Now().Add(time.Duration(*body.Days) * 24 * time.Hour).Unix()
		}
		what = append(what, "days="+strconv.Itoa(*body.Days))
	}
	if body.Disabled != nil {
		k.Disabled = *body.Disabled
		what = append(what, fmt.Sprintf("disabled=%v", k.Disabled))
	}
	if body.ResetDevice {
		k.DeviceEpoch++
		what = append(what, "reset_device")
	}
	if body.MaxDevices != nil && *body.MaxDevices != k.MaxDevices {
		if err := validMaxDevices(*body.MaxDevices); err != nil {
			apiError(w, 400, err.Error())
			return
		}
		k.MaxDevices = *body.MaxDevices
		what = append(what, "max_devices="+strconv.Itoa(k.MaxDevices))
	}
	if body.UnbindDevice != nil {
		dev := strings.TrimSpace(*body.UnbindDevice)
		if dev == "" || len(dev) > 128 {
			apiError(w, 400, "не указано устройство")
			return
		}
		now := time.Now()
		keep := []store.WDTTUnbind{}
		for _, u := range k.Unbind {
			if u.Device != dev && now.Sub(time.Unix(u.At, 0)) < unbindKeep {
				keep = append(keep, u)
			}
		}
		if len(keep) > 63 {
			keep = keep[len(keep)-63:]
		}
		k.Unbind = append(keep, store.WDTTUnbind{Device: dev, At: now.Unix()})
		what = append(what, "unbind="+dev)
	}
	if err := a.Store.PutWDTTKey(k); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	// Only the name or the call hash changed: nothing to apply on the server.
	if body.Days == nil && body.Disabled == nil && !body.ResetDevice && body.UnbindDevice == nil && !strings.Contains(strings.Join(what, ","), "max_devices") {
		a.audit(r, s, "wdtt.key.update", k.ID+" "+strings.Join(what, ","))
		writeJSON(w, 200, map[string]any{})
		return
	}
	a.queueEntry(w, r, s, "wdtt.key.update", k.ID+" "+strings.Join(what, ","))
}

func (a *App) deleteWDTTKey(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id := r.PathValue("id")
	if err := a.Store.DeleteWDTTKey(id); err != nil {
		apiError(w, 404, "ключ не найден")
		return
	}
	a.queueEntry(w, r, s, "wdtt.key.delete", id)
}

// wdttLink returns the password and the wdtt:// link of a key ("main" is
// the owner password of the server given by ?kind=):
// wdtt://HOST:DTLS:WG:LOCAL:PASSWORD:HASHES.
func (a *App) wdttLink(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id := r.PathValue("id")
	var password, hash string
	var kind wdttKind
	if id == "main" {
		var ok bool
		if kind, ok = wdttKindOf(r.URL.Query().Get("kind")); !ok {
			apiError(w, 400, "неизвестный тип клиента")
			return
		}
		p, err := a.Store.Secret(kind.secret)
		if err != nil {
			apiError(w, 404, "сервер WDTT ("+kind.Label+") ещё не настроен")
			return
		}
		password, hash = p, a.Store.Setting(kind.prefix+"vk_hash", "")
	} else {
		k, err := a.Store.WDTTKey(id)
		if err != nil {
			apiError(w, 404, "ключ не найден")
			return
		}
		password, hash = k.Password, k.VKHash
		kind, _ = wdttKindOf(k.Kind)
	}
	n, _ := a.localNode()
	ws := a.wdttSettings(kind)
	out := map[string]string{"password": password, "host": n.Host, "port": strconv.Itoa(ws.DTLSPort), "kind": kind.ID, "client": kind.Label}
	if hash != "" && !strings.Contains(n.Host, ":") {
		out["link"] = fmt.Sprintf("wdtt://%s:%d:%d:9000:%s:%s", n.Host, ws.DTLSPort, ws.WGPort, password, hash)
	}
	a.audit(r, s, "secret.view", "wdtt "+kind.ID+" "+id)
	writeJSON(w, 200, out)
}

// putWDTT changes the settings of one WDTT server (kind "standard", the
// default, or "turnvk").
func (a *App) putWDTT(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Kind     string `json:"kind"`
		Enabled  bool   `json:"enabled"`
		DTLSPort int    `json:"dtls_port"`
		DNS      string `json:"dns"`
		Rotate   bool   `json:"rotate_password"`
		// Password sets a chosen owner password, e.g. the one existing
		// clients of an earlier WDTT server already use.
		Password *string `json:"password"`
		VKHash   *string `json:"vk_hash"`
		MTU      int     `json:"mtu"`
	}
	if !decode(w, r, &body) {
		return
	}
	kind, ok := wdttKindOf(body.Kind)
	if !ok {
		apiError(w, 400, "неизвестный тип клиента")
		return
	}
	if body.DTLSPort == 0 {
		body.DTLSPort = kind.defPort
	}
	if body.MTU == 0 {
		body.MTU = 1280
	}
	if body.MTU < 1200 || body.MTU > 1340 {
		apiError(w, 400, "MTU туннеля: от 1200 до 1340")
		return
	}
	if body.DTLSPort < 1024 || body.DTLSPort > 65534 || body.DTLSPort == a.PanelPort {
		apiError(w, 400, "порт DTLS должен быть в диапазоне 1024–65534 и не совпадать с портом панели")
		return
	}
	if body.Enabled {
		for _, other := range wdttKinds {
			if other.ID == kind.ID {
				continue
			}
			if ot := a.wdttSettings(other); ot.Enabled && ot.DTLSPort == body.DTLSPort {
				apiError(w, 400, fmt.Sprintf("порт %d уже занят сервером WDTT (%s)", body.DTLSPort, other.Label))
				return
			}
		}
	}
	if body.DNS == "" {
		body.DNS = "1.1.1.1"
	}
	for _, d := range strings.Split(body.DNS, ",") {
		if net.ParseIP(strings.TrimSpace(d)) == nil {
			apiError(w, 400, "DNS: укажите IP-адреса через запятую")
			return
		}
	}
	var hash string
	if body.VKHash != nil {
		h, err := normalizeVKHashes(*body.VKHash)
		if err != nil {
			apiError(w, 400, err.Error())
			return
		}
		hash = h
	}
	if body.Password != nil && *body.Password != "" {
		if !rePassword.MatchString(*body.Password) {
			apiError(w, 400, "пароль владельца: 16–128 символов A–Z, a–z, 0–9, точка, дефис, подчёркивание")
			return
		}
		keys, _ := a.Store.WDTTKeys()
		for _, k := range keys {
			if k.Password == *body.Password && k.Kind == kind.ID {
				apiError(w, 400, "этот пароль уже выдан как ключ доступа")
				return
			}
		}
		_ = a.Store.PutSecret(kind.secret, *body.Password)
	}
	if body.VKHash != nil {
		_ = a.Store.SetSetting(kind.prefix+"vk_hash", hash)
	}
	_ = a.Store.SetSetting(kind.prefix+"enabled", map[bool]string{true: "1", false: "0"}[body.Enabled])
	_ = a.Store.SetSetting(kind.prefix+"dtls_port", strconv.Itoa(body.DTLSPort))
	_ = a.Store.SetSetting(kind.prefix+"wg_port", strconv.Itoa(body.DTLSPort+1))
	_ = a.Store.SetSetting(kind.prefix+"dns", strings.ReplaceAll(body.DNS, " ", ""))
	_ = a.Store.SetSetting(kind.prefix+"mtu", strconv.Itoa(body.MTU))
	if body.Rotate {
		_ = a.Store.PutSecret(kind.secret, spec.NewPassword(20))
	}
	a.queueEntry(w, r, s, "wdtt.update", fmt.Sprintf("kind=%s enabled=%v port=%d", kind.ID, body.Enabled, body.DTLSPort))
}
