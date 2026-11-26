package link

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Relay runs on an intermediate server of the chain: it passes the
// tunnel's datagrams between the previous hop and the next one without
// reading them (it holds no keys). Each server still knows only the next
// hop's Mesh address.
type Relay struct {
	Listen netip.AddrPort
	Next   netip.AddrPort
	Log    func(format string, args ...any)

	in    *net.UDPConn
	mu    sync.Mutex
	flows map[netip.AddrPort]*relayFlow
	last  atomic.Pointer[netip.AddrPort]

	Bytes atomic.Uint64
}

type relayFlow struct {
	up   *net.UDPConn
	seen atomic.Int64
}

const (
	relayIdle     = 3 * time.Minute
	relayMaxFlows = 16 // only the entry (or the hop before) talks to a relay
)

// Run forwards until ctx ends.
func (r *Relay) Run(ctx context.Context) error {
	if r.Log == nil {
		r.Log = func(string, ...any) {}
	}
	in, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(r.Listen))
	if err != nil {
		return err
	}
	_ = in.SetReadBuffer(4 << 20)
	r.in = in
	r.flows = map[netip.AddrPort]*relayFlow{}
	go func() {
		<-ctx.Done()
		in.Close()
		r.mu.Lock()
		for _, f := range r.flows {
			f.up.Close()
		}
		r.mu.Unlock()
	}()
	go r.sweep(ctx)
	buf := make([]byte, 65536)
	for {
		n, src, err := in.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		f := r.flow(src)
		if f == nil {
			continue
		}
		f.seen.Store(time.Now().UnixNano())
		if _, err := f.up.Write(buf[:n]); err == nil {
			r.Bytes.Add(uint64(n))
		}
	}
}

func (r *Relay) flow(src netip.AddrPort) *relayFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f := r.flows[src]; f != nil {
		return f
	}
	if len(r.flows) >= relayMaxFlows {
		return nil
	}
	up, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(r.Next))
	if err != nil {
		r.Log("relay: %v", err)
		return nil
	}
	setDontFragment(up)
	f := &relayFlow{up: up}
	r.flows[src] = f
	r.last.Store(&src)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			f.seen.Store(time.Now().UnixNano())
			if _, err := r.in.WriteToUDPAddrPort(buf[:n], src); err == nil {
				r.Bytes.Add(uint64(n))
			}
		}
	}()
	return f
}

func (r *Relay) sweep(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cut := time.Now().Add(-relayIdle).UnixNano()
		r.mu.Lock()
		for k, f := range r.flows {
			if f.seen.Load() < cut {
				f.up.Close()
				delete(r.flows, k)
			}
		}
		r.mu.Unlock()
	}
}

// Prev is the hop the relay last heard from.
func (r *Relay) Prev() netip.AddrPort {
	if p := r.last.Load(); p != nil {
		return *p
	}
	return netip.AddrPort{}
}
