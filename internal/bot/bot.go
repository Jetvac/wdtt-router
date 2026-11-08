// Package bot is the panel's Telegram bot. It runs on a server chosen in
// the panel (usually one where Telegram is reachable) and needs no open
// port: it long-polls Telegram, and it polls the panel's bot API over Mesh
// for events to forward and for the /status summary.
//
// Only chats paired with a one-time code from the panel get answers; other
// chats are told how to pair and nothing else. The bot holds no server
// credentials: its API key only reads events and the status summary.
package bot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jetvac/wdtt-router/internal/spec"
)

// Config is the bot's configuration file (written by the agent).
type Config struct {
	spec.BotSpec
	StateDir string `json:"state_dir"`
}

// Event is something the panel wants the paired chats to know.
type Event struct {
	ID   int64  `json:"id"`
	Text string `json:"text"`
}

// SyncReply is the panel's answer to /api/bot/sync.
type SyncReply struct {
	Chats  []int64 `json:"chats"`
	Events []Event `json:"events"`
	Last   int64   `json:"last"`
}

const apiBase = "https://api.telegram.org/bot"

// Bot is a running bot.
type Bot struct {
	cfg   Config
	tg    *http.Client
	panel *http.Client

	mu     sync.Mutex
	tgErr  string // last Telegram error, "" when it works
	chats  map[int64]bool
	last   int64
	synced bool // false until the first sync of a fresh install
}

// LoadConfig reads the configuration file.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if !spec.ValidBotToken(c.Token) || c.PanelURL == "" || c.APIToken == "" {
		return c, errors.New("incomplete bot configuration")
	}
	return c, nil
}

// New prepares the bot.
func New(c Config) *Bot {
	want := strings.ReplaceAll(strings.ToLower(c.PanelFingerprint), ":", "")
	pinned := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The panel has a self-signed certificate; it is pinned instead.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no panel certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("panel certificate does not match the pinned fingerprint")
			}
			return nil
		},
	}
	return &Bot{
		cfg:   c,
		tg:    &http.Client{Timeout: 70 * time.Second, Transport: &http.Transport{DialContext: dialTelegram, TLSHandshakeTimeout: 15 * time.Second}},
		panel: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: pinned}},
		chats: map[int64]bool{},
	}
}

// Run serves until ctx ends.
func (b *Bot) Run(ctx context.Context) error {
	b.last, b.synced = b.loadLast()
	_ = b.tgCall(ctx, "setMyCommands", map[string]any{"commands": []map[string]string{
		{"command": "status", "description": "Состояние серверов"},
		{"command": "help", "description": "Что умеет бот"},
	}}, nil)
	go b.syncLoop(ctx)
	log.Printf("Telegram bot started, panel %s", b.cfg.PanelURL)
	offset := int64(0)
	for ctx.Err() == nil {
		var ups []update
		err := b.tgCall(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 50, "allowed_updates": []string{"message"}}, &ups)
		b.mu.Lock()
		b.tgErr = ""
		if err != nil {
			b.tgErr = err.Error()
		}
		b.mu.Unlock()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("Telegram: %v", err)
				sleep(ctx, 10*time.Second)
			}
			continue
		}
		for _, u := range ups {
			offset = u.ID + 1
			if u.Message != nil {
				b.handle(ctx, u.Message)
			}
		}
	}
	return nil
}

type update struct {
	ID      int64    `json:"update_id"`
	Message *message `json:"message"`
}

type message struct {
	Chat struct {
		ID        int64  `json:"id"`
		Type      string `json:"type"`
		Title     string `json:"title"`
		FirstName string `json:"first_name"`
		Username  string `json:"username"`
	} `json:"chat"`
	Text string `json:"text"`
}

func (b *Bot) paired(id int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.chats[id]
}

func (b *Bot) handle(ctx context.Context, m *message) {
	text := strings.TrimSpace(m.Text)
	cmd, arg, _ := strings.Cut(text, " ")
	cmd, _, _ = strings.Cut(cmd, "@") // "/status@my_bot" in groups
	chat := m.Chat.ID
	switch cmd {
	case "/start":
		if code := strings.TrimSpace(arg); code != "" {
			name := m.Chat.Title
			if name == "" {
				name = strings.TrimSpace(m.Chat.FirstName + " @" + m.Chat.Username)
			}
			if err := b.pair(ctx, chat, name, code); err != nil {
				b.send(ctx, chat, "Не получилось привязать чат: "+err.Error())
				return
			}
			b.mu.Lock()
			b.chats[chat] = true
			b.mu.Unlock()
			b.send(ctx, chat, "Чат привязан к панели WDTT Router. Сюда будут приходить уведомления.\n\n/status — состояние серверов")
			return
		}
		if b.paired(chat) {
			b.send(ctx, chat, "Чат уже привязан.\n\n/status — состояние серверов")
			return
		}
		b.send(ctx, chat, "Это бот панели WDTT Router. Чтобы получать уведомления, возьмите код привязки в панели («Настройки» → «Telegram-бот») и отправьте сюда:\n/start КОД")
	case "/status":
		if !b.paired(chat) {
			return
		}
		var st struct {
			Text string `json:"text"`
		}
		if err := b.panelCall(ctx, http.MethodGet, "/api/bot/status", nil, &st); err != nil {
			b.send(ctx, chat, "Панель не отвечает: "+err.Error())
			return
		}
		b.send(ctx, chat, st.Text)
	case "/help":
		if !b.paired(chat) {
			return
		}
		b.send(ctx, chat, "/status — состояние серверов, цепочки и WDTT\n\nУведомления приходят сами: сервер недоступен или снова на связи, цепочка не работает, WDTT остановился, вход в панель с нового адреса, перебор паролей, ошибки задач.")
	}
}

func (b *Bot) pair(ctx context.Context, chat int64, name, code string) error {
	var r struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	err := b.panelCall(ctx, http.MethodPost, "/api/bot/pair", map[string]any{"chat_id": chat, "name": name, "code": code}, &r)
	if err != nil {
		return err
	}
	if !r.OK {
		return errors.New(r.Error)
	}
	return nil
}

// syncLoop picks up new events and the list of paired chats.
func (b *Bot) syncLoop(ctx context.Context) {
	for ctx.Err() == nil {
		var r SyncReply
		err := b.panelCall(ctx, http.MethodGet, "/api/bot/sync?after="+strconv.FormatInt(b.last, 10), nil, &r)
		if err != nil {
			log.Printf("panel: %v", err)
			sleep(ctx, 30*time.Second)
			continue
		}
		b.mu.Lock()
		b.chats = map[int64]bool{}
		for _, c := range r.Chats {
			b.chats[c] = true
		}
		b.mu.Unlock()
		if !b.synced {
			// First start: do not replay history.
			b.last, b.synced = r.Last, true
		} else {
			for _, e := range r.Events {
				for _, c := range r.Chats {
					b.send(ctx, c, e.Text)
				}
				b.last = e.ID
			}
			if r.Last < b.last {
				b.last = r.Last // the panel was restored from a backup
			}
		}
		b.saveLast()
		sleep(ctx, 10*time.Second)
	}
}

func (b *Bot) send(ctx context.Context, chat int64, text string) {
	if len(text) > 4000 {
		text = text[:4000] + "…"
	}
	if err := b.tgCall(ctx, "sendMessage", map[string]any{"chat_id": chat, "text": text, "disable_web_page_preview": true}, nil); err != nil {
		log.Printf("Telegram sendMessage to %d: %v", chat, err)
	}
}

func (b *Bot) tgCall(ctx context.Context, method string, body any, out any) error {
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+b.cfg.Token+"/"+method, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.tg.Do(req)
	if err != nil {
		// The URL holds the token; never log it.
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	if !r.OK {
		return fmt.Errorf("%s: %s", method, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (b *Bot) panelCall(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(b.cfg.PanelURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.cfg.APIToken)
	// Tell the panel whether Telegram works from here.
	b.mu.Lock()
	tg := b.tgErr
	b.mu.Unlock()
	if tg == "" {
		tg = "ok"
	}
	req.Header.Set("X-Bot-Telegram", short(tg, 200))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.panel.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (b *Bot) statePath() string { return filepath.Join(b.cfg.StateDir, "last_event") }

func (b *Bot) loadLast() (int64, bool) {
	data, err := os.ReadFile(b.statePath())
	if err != nil {
		return 0, false
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return v, true
}

func (b *Bot) saveLast() {
	if b.cfg.StateDir != "" {
		_ = os.WriteFile(b.statePath(), []byte(strconv.FormatInt(b.last, 10)), 0600)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
