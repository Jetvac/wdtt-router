package link

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// MinDatagram is the smallest datagram the link assumes any path carries
// (an IPv4 MTU of 576).
const MinDatagram = 576 - 28

// Bind is WireGuard's transport for the link: one UDP socket, masked
// datagrams, messages cut into parts when they do not fit the path, and
// probes answered on the spot.
type Bind struct {
	keys   keys
	listen netip.AddrPort
	// pathDatagram returns the largest UDP payload the path's interface
	// takes (its MTU less 28); nil: unlimited (tests use a fixed limit).
	pathDatagram func() int
	// OnReply gets the answers to this side's probes.
	OnReply func(Reply)
	// run identifies this run of the service in probe answers.
	run uint64

	conn   atomic.Pointer[net.UDPConn]
	mu     sync.Mutex
	limit  atomic.Int32 // a smaller datagram found by probing (0: none)
	fragID atomic.Uint32
	reasm  reassembler
	// last: where WireGuard last sent to, or a probe came from (status).
	last atomic.Pointer[netip.AddrPort]

	TxBytes, RxBytes   atomic.Uint64
	Split, Joined, Bad atomic.Uint64
}

// Reply is the answer to a probe.
type Reply struct {
	Seq  uint32
	Sent int64  // unix ns, as the probe carried it
	Size int    // the probe datagram's size as it arrived
	Run  uint64 // the answering service's run
	At   time.Time
}

// NewBind returns a bind that listens on listen (the zero value: any
// address, the port WireGuard asks for).
func NewBind(psk []byte, listen netip.AddrPort, pathDatagram func() int) *Bind {
	var r [8]byte
	_, _ = rand.Read(r[:])
	return &Bind{keys: deriveKeys(psk), listen: listen, pathDatagram: pathDatagram, run: binary.BigEndian.Uint64(r[:]) | 1}
}

// Datagram is the largest datagram the link sends now.
func (b *Bind) Datagram() int {
	d := 65507
	if b.pathDatagram != nil {
		d = b.pathDatagram()
	}
	if l := int(b.limit.Load()); l > 0 && l < d {
		d = l
	}
	return max(d, MinDatagram)
}

// Limit caps datagrams below what the interface allows (0: no cap).
func (b *Bind) Limit(n int) {
	if n > 0 {
		n = max(n, MinDatagram)
	}
	b.limit.Store(int32(n))
}

// Limited reports the cap set by Limit (0: none).
func (b *Bind) Limited() int { return int(b.limit.Load()) }

// Peer is where the other side was last seen or sent to.
func (b *Bind) Peer() netip.AddrPort {
	if p := b.last.Load(); p != nil {
		return *p
	}
	return netip.AddrPort{}
}

// Waiting: messages waiting for their parts; Expired: given up.
func (b *Bind) Waiting() int         { return b.reasm.waiting() }
func (b *Bind) Expired() uint64      { b.reasm.mu.Lock(); defer b.reasm.mu.Unlock(); return b.reasm.Expired }
func (b *Bind) BatchSize() int       { return 16 }
func (b *Bind) SetMark(uint32) error { return nil }

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn.Load() != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	la := b.listen
	if !la.IsValid() {
		la = netip.AddrPortFrom(netip.IPv4Unspecified(), port)
	}
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(la))
	if err != nil {
		return nil, 0, err
	}
	setDontFragment(c)
	_ = c.SetReadBuffer(4 << 20)
	_ = c.SetWriteBuffer(4 << 20)
	b.conn.Store(c)
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receiver(c)}, actual, nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.conn.Swap(nil); c != nil {
		return c.Close()
	}
	return nil
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{AP: ap}, nil
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// write sends one datagram: header and payload behind a fresh nonce.
func (b *Bind) write(c *net.UDPConn, to netip.AddrPort, hdr [hdrLen]byte, payload []byte) (int, error) {
	bp := bufPool.Get().(*[]byte)
	dg := append((*bp)[:nonceLen], hdr[:]...)
	dg = append(dg, payload...)
	b.keys.seal(dg)
	n, err := c.WriteToUDPAddrPort(dg, to)
	*bp = dg
	bufPool.Put(bp)
	if err == nil {
		b.TxBytes.Add(uint64(n))
	}
	return len(dg), err
}

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	c := b.conn.Load()
	if c == nil {
		return net.ErrClosed
	}
	to := e.AP
	if p := b.last.Load(); p == nil || *p != to {
		b.last.Store(&to)
	}
	for _, msg := range bufs {
		if err := b.sendMsg(c, to, msg, false); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bind) sendMsg(c *net.UDPConn, to netip.AddrPort, msg []byte, retry bool) error {
	room := b.Datagram()
	if len(msg)+Overhead <= room {
		n, err := b.write(c, to, [hdrLen]byte{kindWhole}, msg)
		if err != nil && isMsgSize(err) && !retry {
			// The interface took less than we thought (its MTU went down
			// since we read it): cap and send in parts.
			b.Limit(n - 64)
			return b.sendMsg(c, to, msg, true)
		}
		return err
	}
	parts := split(msg, room-Overhead)
	if parts == nil {
		return errors.New("link: message too large for the path")
	}
	id := uint16(b.fragID.Add(1))
	b.Split.Add(1)
	for i, p := range parts {
		h := [hdrLen]byte{kindFrag, byte(i<<4 | len(parts))}
		binary.BigEndian.PutUint16(h[2:], id)
		n, err := b.write(c, to, h, p)
		if err != nil {
			if isMsgSize(err) && !retry {
				b.Limit(n - 64)
				return b.sendMsg(c, to, msg, true)
			}
			return err
		}
	}
	return nil
}

// Probe sends a probe of size bytes (at least ProbeSize) to the peer.
func (b *Bind) Probe(to netip.AddrPort, seq uint32, sent time.Time, size int) error {
	c := b.conn.Load()
	if c == nil {
		return net.ErrClosed
	}
	dg := b.keys.probeDatagram(seq, sent.UnixNano(), size)
	n, err := c.WriteToUDPAddrPort(dg, to)
	if err == nil {
		b.TxBytes.Add(uint64(n))
	}
	return err
}

func (b *Bind) receiver(c *net.UDPConn) conn.ReceiveFunc {
	buf := make([]byte, 65536)
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, src, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return 0, err
			}
			b.RxBytes.Add(uint64(n))
			src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
			hdr, payload, err := b.keys.open(buf[:n])
			if err != nil {
				b.Bad.Add(1)
				continue
			}
			var msg []byte
			switch hdr[0] {
			case kindWhole:
				msg = payload
			case kindFrag:
				msg = b.reasm.add(src, binary.BigEndian.Uint16(hdr[2:]), int(hdr[1]>>4), int(hdr[1]&15), payload, time.Now())
				if msg != nil {
					b.Joined.Add(1)
				}
			case kindProbe:
				if !b.keys.checkMAC(hdr, payload, probeBody) {
					b.Bad.Add(1)
					continue
				}
				seq, sent := probeFields(payload)
				if p := b.last.Load(); p == nil || *p != src {
					b.last.Store(&src)
				}
				r := b.keys.replyDatagram(seq, sent, n, b.run)
				if m, err := c.WriteToUDPAddrPort(r, src); err == nil {
					b.TxBytes.Add(uint64(m))
				}
				continue
			case kindReply:
				if !b.keys.checkMAC(hdr, payload, replyBody) {
					b.Bad.Add(1)
					continue
				}
				seq, sent := probeFields(payload)
				if f := b.OnReply; f != nil {
					f(Reply{Seq: seq, Sent: sent, Size: int(binary.BigEndian.Uint16(payload[12:])), Run: binary.BigEndian.Uint64(payload[14:]), At: time.Now()})
				}
				continue
			default:
				b.Bad.Add(1)
				continue
			}
			if msg == nil {
				continue
			}
			if len(msg) > len(packets[0]) {
				b.Bad.Add(1)
				continue
			}
			sizes[0] = copy(packets[0], msg)
			eps[0] = &Endpoint{AP: src}
			return 1, nil
		}
	}
}

// Endpoint is a peer address.
type Endpoint struct{ AP netip.AddrPort }

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) DstToString() string { return e.AP.String() }
func (e *Endpoint) DstToBytes() []byte  { b, _ := e.AP.MarshalBinary(); return b }
func (e *Endpoint) DstIP() netip.Addr   { return e.AP.Addr() }
func (e *Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
