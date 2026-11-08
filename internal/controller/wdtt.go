package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Jetvac/wdtt-router/internal/agent"
	"github.com/Jetvac/wdtt-router/internal/auth"
	"github.com/Jetvac/wdtt-router/internal/spec"
	"github.com/Jetvac/wdtt-router/internal/store"
)

const maxWDTTKeys = 200

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

func readWDTTRuntime() *spec.WDTTRuntime {
	b, err := os.ReadFile(agent.WDTTStatusPath)
	if err != nil {
		return nil
	}
	var r spec.WDTTRuntime
	if json.Unmarshal(b, &r) != nil || time.Since(time.Unix(r.UpdatedAt, 0)) > time.Minute {
		return nil
	}
	return &r
}

// wdttKeySpecs converts stored keys into the server configuration.
func (a *App) wdttKeySpecs() ([]spec.WDTTKey, error) {
	keys, err := a.Store.WDTTKeys()
	if err != nil {
		return nil, err
	}
	out := make([]spec.WDTTKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, spec.WDTTKey{ID: k.ID, Password: k.Password, ExpiresAt: k.ExpiresAt, Disabled: k.Disabled, DeviceEpoch: k.DeviceEpoch})
	}
	return out, nil
}

type wdttKeyView struct {
	store.WDTTKey
	State    string `json:"state"` // active, disabled, expired
	DeviceID string `json:"device_id"`
	DeviceIP string `json:"device_ip"`
	Sessions int    `json:"sessions"`
	Up       int64  `json:"up_bytes"`
	Down     int64  `json:"down_bytes"`
	LastSeen int64  `json:"last_seen"`
}

func (a *App) listWDTTKeys(w http.ResponseWriter, r *http.Request, s auth.Session) {
	keys, err := a.Store.WDTTKeys()
	if err != nil {
		apiError(w, 500, err.Error())
		return
	}
	// The panel runs on the entry server: read the live status the WDTT
	// server publishes every few seconds rather than the cached node status.
	rt := readWDTTRuntime()
	if rt == nil {
		n, _ := a.localNode()
		rt = n.Status.WDTT
	}
	now := time.Now().Unix()
	views := make([]wdttKeyView, 0, len(keys))
	for _, k := range keys {
		v := wdttKeyView{WDTTKey: k, State: "active"}
		switch {
		case k.Disabled:
			v.State = "disabled"
		case k.ExpiresAt != 0 && now >= k.ExpiresAt:
			v.State = "expired"
		}
		if rt != nil {
			if kr, ok := rt.Keys[k.ID]; ok {
				v.DeviceID, v.DeviceIP, v.Sessions, v.Up, v.Down, v.LastSeen = kr.DeviceID, kr.DeviceIP, kr.Sessions, kr.Up, kr.Down, kr.LastSeen
			}
		}
		views = append(views, v)
	}
	out := map[string]any{"keys": views, "limit": maxWDTTKeys, "main_vk_hash": a.Store.Setting("wdtt_vk_hash", "")}
	if rt != nil {
		out["runtime"] = map[string]any{"sessions": rt.Sessions, "devices": rt.Devices, "version": rt.Version,
			"started_at": rt.StartedAt, "updated_at": rt.UpdatedAt, "auth_failures": rt.AuthFailures,
			"handshake_failures": rt.HandshakeFailures, "main": rt.Keys["main"]}
	}
	writeJSON(w, 200, out)
}

func (a *App) createWDTTKey(w http.ResponseWriter, r *http.Request, s auth.Session) {
	var body struct {
		Name   string `json:"name"`
		Days   int    `json:"days"`
		VKHash string `json:"vk_hash"`
	}
	if !decode(w, r, &body) {
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
	hash, err := normalizeVKHashes(body.VKHash)
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	k := store.WDTTKey{ID: "k" + strings.ToLower(spec.NewPassword(10)), Name: body.Name, Password: spec.NewPassword(20), VKHash: hash}
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
	a.queueEntryWith(w, r, s, "wdtt.key.create", k.ID+" "+k.Name, map[string]any{"id": k.ID})
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
		ResetDevice bool    `json:"reset_device"`
		Days        *int    `json:"days"` // new term from now; 0 = never expires
		VKHash      *string `json:"vk_hash"`
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
	if err := a.Store.PutWDTTKey(k); err != nil {
		apiError(w, 500, err.Error())
		return
	}
	// Only the name or the call hash changed: nothing to apply on the server.
	if body.Days == nil && body.Disabled == nil && !body.ResetDevice {
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
// the owner password): wdtt://HOST:DTLS:WG:LOCAL:PASSWORD:HASHES.
func (a *App) wdttLink(w http.ResponseWriter, r *http.Request, s auth.Session) {
	id := r.PathValue("id")
	var password, hash string
	if id == "main" {
		p, err := a.Store.Secret("wdtt_password")
		if err != nil {
			apiError(w, 404, "WDTT ещё не настроен")
			return
		}
		password, hash = p, a.Store.Setting("wdtt_vk_hash", "")
	} else {
		k, err := a.Store.WDTTKey(id)
		if err != nil {
			apiError(w, 404, "ключ не найден")
			return
		}
		password, hash = k.Password, k.VKHash
	}
	n, _ := a.localNode()
	es := a.entrySettings()
	out := map[string]string{"password": password, "host": n.Host, "port": strconv.Itoa(es.WDTTDTLSPort)}
	if hash != "" && !strings.Contains(n.Host, ":") {
		out["link"] = fmt.Sprintf("wdtt://%s:%d:%d:9000:%s:%s", n.Host, es.WDTTDTLSPort, es.WDTTWGPort, password, hash)
	}
	a.audit(r, s, "secret.view", "wdtt "+id)
	writeJSON(w, 200, out)
}
