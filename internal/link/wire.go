// Package link is the chain tunnel (docs/chain-link.md): a userspace
// WireGuard device between the entry and the exit that runs inside
// Cloudflare Mesh next to the Xray chain. This file is its datagram format.
//
// Every datagram on the wire is
//
//	nonce (8 random bytes) || mask(header (4 bytes) || payload)
//
// where mask XORs the first maskLen bytes with a ChaCha20 keystream keyed
// by the link's mask key and the nonce. WireGuard's message headers (type,
// receiver index, counter) and whole handshakes are therefore hidden:
// Cloudflare sees random bytes, as with the "random" mode of VLESS
// Encryption. Masking is not authentication; WireGuard authenticates its
// own messages, and probes carry a MAC of their own.
//
// The header's first byte is the kind:
//
//	kindWhole  a whole WireGuard message
//	kindFrag   a part of one: [1] = index<<4 | count, [2:4] = message id
//	kindProbe  a probe: seq (4), sent (8, unix ns), padding, MAC (16)
//	kindReply  the answer: seq, sent, size of the probe datagram (2), the
//	           answering run's id (8: it changes when that service restarts
//	           and has lost WireGuard's keys), MAC
package link

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

const (
	nonceLen = 8
	hdrLen   = 4
	// Overhead is what every datagram adds to its payload.
	Overhead = nonceLen + hdrLen
	maskLen  = 64
	macLen   = 16

	kindWhole = 0
	kindFrag  = 1
	kindProbe = 2
	kindReply = 3

	// maxParts: a WireGuard message is cut into at most this many parts.
	maxParts = 15

	probeBody = 4 + 8 // seq, sent
	replyBody = 4 + 8 + 2 + 8
	// ProbeSize is the size of a plain probe datagram.
	ProbeSize = Overhead + probeBody + macLen
)

var errShort = errors.New("short datagram")

// keys are derived from the link's preshared key, so the panel hands out
// one secret per link.
type keys struct {
	mask [32]byte
	mac  [32]byte
}

func deriveKeys(psk []byte) keys {
	var k keys
	d := func(label string, out *[32]byte) {
		h := hmac.New(sha256.New, psk)
		h.Write([]byte(label))
		copy(out[:], h.Sum(nil))
	}
	d("wdtt-router link mask v1", &k.mask)
	d("wdtt-router link probe v1", &k.mac)
	return k
}

// xorMask masks or unmasks b (everything after the nonce) in place.
func (k *keys) xorMask(nonce []byte, b []byte) {
	var n12 [12]byte
	copy(n12[:], nonce[:nonceLen])
	c, err := chacha20.NewUnauthenticatedCipher(k.mask[:], n12[:])
	if err != nil {
		panic(err) // key and nonce sizes are fixed
	}
	m := min(len(b), maskLen)
	c.XORKeyStream(b[:m], b[:m])
}

func (k *keys) sum(b []byte) []byte {
	h := hmac.New(sha256.New, k.mac[:])
	h.Write(b)
	return h.Sum(nil)[:macLen]
}

// seal fills in the nonce of dg (whose header and payload are in place
// after it) and masks it.
func (k *keys) seal(dg []byte) {
	_, _ = rand.Read(dg[:nonceLen])
	k.xorMask(dg[:nonceLen], dg[nonceLen:])
}

// open unmasks dg in place and returns its header and payload.
func (k *keys) open(dg []byte) (hdr, payload []byte, err error) {
	if len(dg) < Overhead {
		return nil, nil, errShort
	}
	k.xorMask(dg[:nonceLen], dg[nonceLen:])
	return dg[nonceLen:Overhead], dg[Overhead:], nil
}

// probeDatagram builds a probe of total size size (at least ProbeSize).
func (k *keys) probeDatagram(seq uint32, sent int64, size int) []byte {
	size = max(size, ProbeSize)
	dg := make([]byte, size)
	h := dg[nonceLen:]
	h[0] = kindProbe
	binary.BigEndian.PutUint32(h[hdrLen:], seq)
	binary.BigEndian.PutUint64(h[hdrLen+4:], uint64(sent))
	// Padding (MTU probes) is random, not zeros.
	_, _ = rand.Read(h[hdrLen+probeBody : len(h)-macLen])
	copy(h[len(h)-macLen:], k.sum(h[:len(h)-macLen]))
	k.seal(dg)
	return dg
}

// replyDatagram answers a probe that arrived in a datagram of size size.
func (k *keys) replyDatagram(seq uint32, sent int64, size int, run uint64) []byte {
	dg := make([]byte, Overhead+replyBody+macLen)
	h := dg[nonceLen:]
	h[0] = kindReply
	binary.BigEndian.PutUint32(h[hdrLen:], seq)
	binary.BigEndian.PutUint64(h[hdrLen+4:], uint64(sent))
	binary.BigEndian.PutUint16(h[hdrLen+12:], uint16(min(size, 65535)))
	binary.BigEndian.PutUint64(h[hdrLen+14:], run)
	copy(h[len(h)-macLen:], k.sum(h[:len(h)-macLen]))
	k.seal(dg)
	return dg
}

// checkMAC verifies the MAC at the end of an unmasked probe or reply
// (header and payload, as returned by open).
func (k *keys) checkMAC(hdr, payload []byte, body int) bool {
	if len(payload) < body+macLen {
		return false
	}
	b := make([]byte, 0, hdrLen+len(payload)-macLen)
	b = append(append(b, hdr...), payload[:len(payload)-macLen]...)
	return hmac.Equal(k.sum(b), payload[len(payload)-macLen:])
}

// probeFields reads seq and sent from a probe or reply payload.
func probeFields(payload []byte) (seq uint32, sent int64) {
	return binary.BigEndian.Uint32(payload), int64(binary.BigEndian.Uint64(payload[4:]))
}
