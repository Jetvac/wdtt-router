package wdtt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// Peers is the WireGuard side of the server. The Linux implementation is a
// userspace WireGuard device on the wdtt0 TUN interface.
type Peers interface {
	Set(peers map[string]string) error // public key (base64) -> client IP
	// Kick starts a WireGuard handshake with a peer through the given
	// endpoint (a session address), unless the peer has a fresh one.
	// retry also clears the peer's handshake state first, which WireGuard
	// otherwise keeps for 5 s before it sends another initiation.
	Kick(public, endpoint string, retry bool) error
	// Fresh reports whether the peer completed a handshake recently.
	Fresh(public string) bool
	SetMTU(mtu int) error
	Close() error
}

// PeersFactory creates the WireGuard device on top of the bind.
type PeersFactory func(b *bind, serverPrivate string, mtu int) (Peers, error)

const (
	handshakeTimeout = 20 * time.Second
	firstMsgTimeout  = 30 * time.Second
	idleTimeout      = 3 * time.Minute // clients send a keepalive every 15 s
	maxHandshakes    = 64
	keepaliveByte    = 0xFF
	deviceTTL        = 180 * 24 * time.Hour
	kickInterval     = 20 * time.Second
	kickTries        = 3
)

// Server is a WDTT server.
type Server struct {
	cfgPath  string
	newPeers PeersFactory
	Version  string

	mu     sync.Mutex
	cfg    *Config
	byPass map[string]Key
	byID   map[string]Key
	st     *state
	dirty  bool
	peers  Peers

	mux     *mux
	bind    *bind
	traffic sync.Map // key id -> *counter
	started time.Time

	handshakeFailed atomic.Int64
	sem             chan struct{}
	serving         sync.WaitGroup

	kmu    sync.Mutex
	kicked map[string]time.Time // device -> last server-initiated handshake
	kicks  atomic.Int64
}

type counter struct{ up, down atomic.Int64 }

// NewServer prepares a server from its configuration file.
func NewServer(cfgPath string, peers PeersFactory) *Server {
	return &Server{cfgPath: cfgPath, newPeers: peers, sem: make(chan struct{}, maxHandshakes)}
}

func (s *Server) counter(id string) *counter {
	c, _ := s.traffic.LoadOrStore(id, &counter{})
	return c.(*counter)
}

func (s *Server) buildKeys(cfg *Config) (keyring, map[string]Key, map[string]Key, error) {
	byPass, byID := map[string]Key{}, map[string]Key{}
	var ring keyring
	add := func(k Key) error {
		a, err := newAEAD(k.Password)
		if err != nil {
			return err
		}
		byPass[k.Password], byID[k.ID] = k, k
		ring = append(ring, keyEntry{id: k.ID, aead: a})
		return nil
	}
	if cfg.MainPassword != "" {
		if err := add(Key{ID: MainKeyID, Password: cfg.MainPassword}); err != nil {
			return nil, nil, nil, err
		}
	}
	now := time.Now()
	for _, k := range cfg.Keys {
		if !k.active(now) {
			byID[k.ID] = k // known but not accepted on the wire
			continue
		}
		if err := add(k); err != nil {
			return nil, nil, nil, err
		}
	}
	return ring, byPass, byID, nil
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	cfg, err := LoadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return err
	}
	st, migrated, err := loadState(cfg.DataDir)
	if err != nil {
		return err
	}
	if migrated {
		log.Printf("state initialised (%d devices taken over)", len(st.Devices))
		if err := saveState(cfg.DataDir, st); err != nil {
			return err
		}
	}
	ring, byPass, byID, err := s.buildKeys(cfg)
	if err != nil {
		return err
	}
	s.cfg, s.st, s.byPass, s.byID, s.started = cfg, st, byPass, byID, time.Now()
	s.bind = newBind()
	if s.peers, err = s.newPeers(s.bind, st.ServerPrivate, cfg.MTU); err != nil {
		return fmt.Errorf("WireGuard: %w", err)
	}
	defer s.peers.Close()
	s.mu.Lock()
	s.applyKeysLocked()
	err = s.syncPeersLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}

	if s.mux, err = listenMux(ctx, cfg.Listen, ring); err != nil {
		return err
	}
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return err
	}
	l, err := dtls.NewListenerWithOptions(&acceptor{m: s.mux, done: make(chan struct{})},
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	)
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, func() { _ = l.Close() })
	log.Printf("WDTT server %s listening on udp %s, %d passwords, %d devices", s.Version, cfg.Listen, len(ring), len(st.Devices))
	logResets(s.mux.resetPrevious(sessionsFile(cfg.StatusFile)))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.housekeeping(ctx) }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}
		s.serving.Add(1)
		go func() { defer s.serving.Done(); s.serve(ctx, c.(*dtls.Conn)) }()
	}
	// Tell every client the session is over (DTLS close_notify) so they
	// reconnect as soon as the server is back, then close the sockets.
	s.closeSessions(func(*session) bool { return true })
	done := make(chan struct{})
	go func() { s.serving.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	_ = s.mux.Close()
	wg.Wait()
	// A planned stop has told every client already.
	_ = os.Remove(sessionsFile(cfg.StatusFile))
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()
	return nil
}

// closeSessions closes matching DTLS sessions with a close_notify, which
// makes the client open new ones right away.
func (s *Server) closeSessions(match func(*session) bool) {
	s.bind.mu.Lock()
	var list []*session
	for ss := range s.bind.sessions {
		if match(ss) {
			list = append(list, ss)
		}
	}
	s.bind.mu.Unlock()
	var wg sync.WaitGroup
	for _, ss := range list {
		wg.Add(1)
		go func() { defer wg.Done(); _ = ss.c.Close() }()
	}
	wg.Wait()
}

// dropKey ends every session and pending handshake of a password.
func (s *Server) dropKey(id string) {
	if s.mux == nil {
		return
	}
	s.closeSessions(func(ss *session) bool { return ss.keyID == id })
	s.mux.closeKey(id)
}

// Reload re-reads the configuration (SIGHUP).
func (s *Server) Reload() error {
	cfg, err := LoadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	ring, byPass, byID, err := s.buildKeys(cfg)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Listen != s.cfg.Listen || cfg.DataDir != s.cfg.DataDir {
		return errors.New("listen address and data directory need a restart")
	}
	old := s.byPass
	if cfg.MTU != s.cfg.MTU {
		// Clients get the new MTU with their next GETCONF (reconnect).
		if err := s.peers.SetMTU(cfg.MTU); err != nil {
			return err
		}
		log.Printf("tunnel MTU %d -> %d", s.cfg.MTU, cfg.MTU)
	}
	s.cfg, s.byPass, s.byID = cfg, byPass, byID
	s.mux.setKeys(ring)
	// Close sessions whose password is gone, changed or no longer active.
	for pass, k := range old {
		if nk, ok := byPass[pass]; !ok || nk.ID != k.ID {
			s.dropKey(k.ID)
		}
	}
	s.applyKeysLocked()
	log.Printf("configuration reloaded: %d passwords", len(ring))
	return s.syncPeersLocked()
}

// applyKeysLocked reconciles device bindings with the configured keys.
func (s *Server) applyKeysLocked() {
	for id, ks := range s.st.Keys {
		if id == MainKeyID {
			continue
		}
		k, ok := s.byID[id]
		if !ok {
			s.dropDeviceLocked(ks.DeviceID)
			delete(s.st.Keys, id)
			s.dirty = true
			continue
		}
		if k.DeviceEpoch != ks.DeviceEpoch {
			if ks.DeviceID != "" {
				log.Printf("key %s: device %s unbound", id, ks.DeviceID)
				s.dropDeviceLocked(ks.DeviceID)
				s.dropKey(id)
			}
			ks.DeviceID, ks.DeviceEpoch = "", k.DeviceEpoch
			s.dirty = true
		}
	}
}

func (s *Server) dropDeviceLocked(id string) {
	if id != "" {
		delete(s.st.Devices, id)
		s.dirty = true
	}
}

// syncPeersLocked makes the WireGuard peer list match the devices that may
// connect: devices bound to an active key, and devices of the owner password.
func (s *Server) syncPeersLocked() error {
	now := time.Now()
	bound := map[string]bool{}
	allowed := map[string]bool{}
	for id, ks := range s.st.Keys {
		if ks.DeviceID == "" || id == MainKeyID {
			continue
		}
		bound[ks.DeviceID] = true
		if k, ok := s.byID[id]; ok && k.active(now) {
			allowed[ks.DeviceID] = true
		}
	}
	peers := map[string]string{}
	for id, d := range s.st.Devices {
		if allowed[id] || (!bound[id] && s.cfg.MainPassword != "") {
			peers[d.Public] = d.IP
		}
	}
	return s.peers.Set(peers)
}

func (s *Server) serve(ctx context.Context, c *dtls.Conn) {
	defer c.Close()
	raddr, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	raddr = netip.AddrPortFrom(raddr.Addr().Unmap(), raddr.Port())
	s.mux.mu.Lock()
	vc := s.mux.conns[raddr]
	s.mux.mu.Unlock()
	if vc == nil {
		return
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	err := c.HandshakeContext(hctx)
	cancel()
	<-s.sem
	if err != nil {
		s.handshakeFailed.Add(1)
		return
	}
	sess := &session{c: c, keyID: vc.keyID, cnt: s.counter(vc.keyID), opened: time.Now().UnixNano()}
	sess.ep = &endpoint{s: sess, addr: raddr}
	sess.lastRx.Store(time.Now().UnixNano())
	s.bind.add(sess)
	defer func() {
		sess.dead.Store(true)
		s.bind.remove(sess)
	}()
	// On shutdown Run closes the session (with a close_notify) and waits for
	// this goroutine before closing the sockets.

	buf := make([]byte, maxDatagram)
	_ = c.SetReadDeadline(time.Now().Add(firstMsgTimeout))
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	msg := buf[:n]
	if body, ok := strings.CutPrefix(string(msg), "GETCONF:"); ok {
		reply, dev, ok := s.getconf(sess.keyID, body)
		if _, err := c.Write([]byte(reply)); err != nil || !ok {
			return
		}
		sess.dev = dev
		msg = nil
	} else if string(msg) == "READY" {
		if _, err := c.Write([]byte("READY_OK")); err != nil {
			return
		}
		msg = nil
	}
	var lastDeadline time.Time
	for {
		if len(msg) > 0 && !(len(msg) == 1 && msg[0] == keepaliveByte) {
			sess.cnt.up.Add(int64(len(msg)))
			// WireGuard data (type 4) on a new session: the client holds
			// keys. If the server has no fresh handshake with it, those
			// keys are from before a restart; start a new one at once.
			if msg[0] == 4 && sess.dev != "" && !sess.checked.Swap(true) {
				go s.kick(sess.dev, raddr.String())
			}
			s.bind.deliver(sess, msg)
		}
		if now := time.Now(); now.Sub(lastDeadline) > 10*time.Second {
			_ = c.SetReadDeadline(now.Add(idleTimeout))
			lastDeadline = now
			sess.lastRx.Store(now.UnixNano())
		}
		n, err = c.Read(buf)
		if err != nil {
			return
		}
		msg = buf[:n]
	}
}

func cleanDeviceID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 128 || strings.IndexFunc(id, func(r rune) bool { return !unicode.IsPrint(r) || r == '|' }) >= 0 {
		return "unknown"
	}
	return id
}

// kick has the server start the WireGuard handshake with a device whose
// client still sends data with keys the server does not have (the server
// restarted). On its own the client's WireGuard notices only after about
// 15 s. Every client sends GETCONF on each new session, so the server
// knows which device the session belongs to and where to reach it. A
// client that starts afresh sends a handshake first, not data, and is left
// alone so that two handshakes do not cross.
func (s *Server) kick(dev, endpoint string) {
	s.kmu.Lock()
	if s.kicked == nil {
		s.kicked = map[string]time.Time{}
	}
	if time.Since(s.kicked[dev]) < kickInterval {
		s.kmu.Unlock()
		return
	}
	s.kicked[dev] = time.Now()
	s.kmu.Unlock()
	s.mu.Lock()
	d := s.st.Devices[dev]
	peers := s.peers
	s.mu.Unlock()
	if d == nil || peers == nil {
		return
	}
	// The handshake answer may go out on one of the client's sessions
	// that is itself still stale; try again through the newest session.
	for try := 0; try < kickTries; try++ {
		if try > 0 {
			if ep := s.bind.newestFor(dev); ep != "" {
				endpoint = ep
			}
		}
		if err := peers.Kick(d.Public, endpoint, try > 0); err != nil {
			log.Printf("WireGuard handshake with %q: %v", dev, err)
			return
		}
		time.Sleep(time.Second)
		fresh := peers.Fresh(d.Public)
		if os.Getenv("WDTT_DEBUG_KICK") != "" {
			log.Printf("kick %q try %d via %s: fresh=%v", dev, try, endpoint, fresh)
		}
		if fresh {
			break
		}
	}
	s.kicks.Add(1)
	if s.kicks.Load() <= 50 || s.kicks.Load()%100 == 0 {
		log.Printf("device %q is back: WireGuard handshake checked (%d so far)", dev, s.kicks.Load())
	}
}

// getconf answers "GETCONF:<local port>|<device id>|<password>" and
// returns the device on success.
func (s *Server) getconf(sessionKey, body string) (string, string, bool) {
	// Like the original server: split on every "|" and use the first three
	// fields, so clients that append more fields keep working.
	parts := strings.Split(strings.TrimSpace(body), "|")
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	port := "9000"
	if p, err := strconv.Atoi(parts[0]); err == nil && p > 0 && p < 65536 {
		port = parts[0]
	}
	devID, password := cleanDeviceID(parts[1]), parts[2]

	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byPass[password]
	if !ok || password == "" || k.ID != sessionKey {
		if old, known := s.knownInactiveLocked(password); known {
			if old.Disabled {
				return "DENIED:deactivated", "", false
			}
			return "DENIED:expired", "", false
		}
		owner := "none"
		if ok {
			owner = k.ID
		}
		log.Printf("GETCONF from %q: wrong password (fields=%d, password length %d, matches key %s, session key %s)",
			devID, len(parts), len(password), owner, sessionKey)
		return "DENIED:wrong_password", "", false
	}
	now := time.Now()
	ks := s.st.Keys[k.ID]
	if ks == nil {
		ks = &keyState{DeviceEpoch: k.DeviceEpoch}
		s.st.Keys[k.ID] = ks
	}
	if k.ID != MainKeyID {
		if ks.DeviceID != "" && ks.DeviceID != devID {
			log.Printf("GETCONF key %s: bound to another device, request from %q", k.ID, devID)
			return "DENIED:device_mismatch", "", false
		}
		if ks.DeviceID == "" {
			ks.DeviceID = devID
			log.Printf("key %s bound to device %q", k.ID, devID)
		}
	}
	ks.LastSeen = now.Unix()
	d := s.st.Devices[devID]
	if d == nil {
		ip := s.st.freeIP()
		priv, pub, err := newKeyPair()
		if ip == "" || err != nil {
			log.Printf("GETCONF %q: no free client address", devID)
			return "NOCONF", "", true
		}
		d = &deviceState{IP: ip, Private: priv, Public: pub}
		s.st.Devices[devID] = d
		log.Printf("new device %q -> %s", devID, ip)
	}
	d.LastSeen = now.Unix()
	s.dirty = true
	if err := s.syncPeersLocked(); err != nil {
		log.Printf("WireGuard peers: %v", err)
		return "NOCONF", "", true
	}
	return clientConfig(s.st.ServerPublic, d.Private, d.IP, s.cfg.DNS, port, s.cfg.MTU), devID, true
}

func (s *Server) knownInactiveLocked(password string) (Key, bool) {
	if password == "" {
		return Key{}, false
	}
	for _, k := range s.cfg.Keys {
		if k.Password == password && !k.active(time.Now()) {
			return k, true
		}
	}
	return Key{}, false
}

// housekeeping expires keys, forgets stale devices, saves state and writes
// the status file.
func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		if i%6 == 0 {
			s.expireLocked()
		}
		if i%6 == 0 || s.dirty {
			s.flushLocked()
		}
		st := s.statusLocked()
		path := s.cfg.StatusFile
		s.mu.Unlock()
		writeStatus(path, st)
		writeSessions(sessionsFile(path), s.mux.live())
	}
}

func (s *Server) expireLocked() {
	now := time.Now()
	changed := false
	for _, k := range s.cfg.Keys {
		if k.ExpiresAt != 0 && now.Unix() >= k.ExpiresAt {
			if _, live := s.byPass[k.Password]; live {
				log.Printf("key %s expired", k.ID)
				delete(s.byPass, k.Password)
				s.dropKey(k.ID)
				changed = true
			}
		}
	}
	if changed {
		ring, _, _, err := s.buildKeys(s.cfg)
		if err == nil {
			s.mux.setKeys(ring)
		}
	}
	bound := map[string]bool{}
	for _, ks := range s.st.Keys {
		bound[ks.DeviceID] = true
	}
	for id, d := range s.st.Devices {
		if !bound[id] && d.LastSeen != 0 && now.Sub(time.Unix(d.LastSeen, 0)) > deviceTTL {
			delete(s.st.Devices, id)
			changed = true
		}
	}
	if changed {
		s.dirty = true
		if err := s.syncPeersLocked(); err != nil {
			log.Printf("WireGuard peers: %v", err)
		}
	}
}

// flushLocked moves live traffic counters into the state and saves it.
func (s *Server) flushLocked() {
	s.traffic.Range(func(k, v any) bool {
		c := v.(*counter)
		up, down := c.up.Swap(0), c.down.Swap(0)
		if up == 0 && down == 0 {
			return true
		}
		ks := s.st.Keys[k.(string)]
		if ks == nil {
			if _, ok := s.byID[k.(string)]; !ok {
				return true
			}
			ks = &keyState{}
			s.st.Keys[k.(string)] = ks
		}
		ks.Up += up
		ks.Down += down
		s.dirty = true
		return true
	})
	if !s.dirty {
		return
	}
	if err := saveState(s.cfg.DataDir, s.st); err != nil {
		log.Printf("save state: %v", err)
		return
	}
	s.dirty = false
}

// Status is published for the agent and the panel.
type Status struct {
	Version           string               `json:"version"`
	StartedAt         int64                `json:"started_at"`
	UpdatedAt         int64                `json:"updated_at"`
	Sessions          int                  `json:"sessions"`
	Devices           int                  `json:"devices"`
	HandshakeFailures int64                `json:"handshake_failures"`
	AuthFailures      int64                `json:"auth_failures"`
	StaleResets       int64                `json:"stale_resets"`
	Keys              map[string]KeyStatus `json:"keys"`
}

// KeyStatus describes one password.
type KeyStatus struct {
	Sessions int    `json:"sessions"`
	DeviceID string `json:"device_id,omitempty"`
	DeviceIP string `json:"device_ip,omitempty"`
	Up       int64  `json:"up_bytes"`
	Down     int64  `json:"down_bytes"`
	LastSeen int64  `json:"last_seen,omitempty"`
}

func (s *Server) statusLocked() Status {
	total, byKey := s.bind.count()
	st := Status{Version: s.Version, StartedAt: s.started.Unix(), UpdatedAt: time.Now().Unix(), Sessions: total,
		Devices: len(s.st.Devices), HandshakeFailures: s.handshakeFailed.Load(), AuthFailures: s.mux.authFailed.Load(),
		StaleResets: s.mux.resetsSent.Load(), Keys: map[string]KeyStatus{}}
	for id := range s.byID {
		ks := KeyStatus{Sessions: byKey[id]}
		if k := s.st.Keys[id]; k != nil {
			ks.DeviceID, ks.Up, ks.Down, ks.LastSeen = k.DeviceID, k.Up, k.Down, k.LastSeen
			if d := s.st.Devices[k.DeviceID]; d != nil {
				ks.DeviceIP = d.IP
			}
		}
		if v, ok := s.traffic.Load(id); ok {
			ks.Up += v.(*counter).up.Load()
			ks.Down += v.(*counter).down.Load()
		}
		st.Keys[id] = ks
	}
	return st
}

func writeStatus(path string, st Status) {
	if path == "" {
		return
	}
	b, _ := json.Marshal(st)
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, path)
	}
}

// ReadStatus reads the status file written by a running server.
func ReadStatus(path string) (*Status, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st Status
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// session is one DTLS connection of a client. A client keeps many of them
// in parallel, each through its own TURN allocation.
type session struct {
	c       *dtls.Conn
	keyID   string
	cnt     *counter
	ep      *endpoint
	dead    atomic.Bool
	lastIdx atomic.Uint32
	lastRx  atomic.Int64
	dev     string      // device that sent GETCONF on this session
	opened  int64       // unix nanoseconds
	checked atomic.Bool // the device's WireGuard state was checked
	wmu     sync.Mutex
	wdl     time.Time // last write-deadline refresh, guarded by wmu
}

func (s *session) writeData(p []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.dead.Load() {
		return net.ErrClosed
	}
	// Refreshing the deadline per packet costs a timer reset; once a
	// second is plenty for a 5-second limit.
	if now := time.Now(); now.Sub(s.wdl) > time.Second {
		_ = s.c.SetWriteDeadline(now.Add(5 * time.Second))
		s.wdl = now
	}
	if _, err := s.c.Write(p); err != nil {
		s.dead.Store(true)
		return err
	}
	s.cnt.down.Add(int64(len(p)))
	return nil
}
