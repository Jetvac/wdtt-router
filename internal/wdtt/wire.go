// Package wdtt is a server for WDTT clients: WireGuard carried over DTLS,
// with every datagram disguised as an encrypted RTP media packet so it can be
// relayed through the TURN servers of a video-calling service.
//
// The wire protocol (RTP wrap, DTLS parameters, the GETCONF exchange and the
// wdtt:// link) follows the original WDTT project so that its standard
// clients work unchanged. The implementation here is independent.
package wdtt

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// RTP wrap: a 12-byte RTP v2 header with the padding bit set, the payload
// sealed with ChaCha20-Poly1305 (header as additional data), then 1..N
// padding bytes whose count is stored in the last byte.
//
//	nonce = SSRC(4) | seq(2) | 0x0000 | timestamp(4)
//	key   = HKDF-SHA256(password, salt "WDTT-WRAP-v1", info "rtp-obfs/chacha20poly1305")
const (
	rtpHeaderLen = 12
	tagLen       = chacha20poly1305.Overhead
	minWireLen   = rtpHeaderLen + 1
	ptAudio      = 111
	ptVideo      = 96
	// MaxWireOverhead is the most the wrap adds to a datagram.
	MaxWireOverhead = rtpHeaderLen + tagLen + 64
)

// DeriveKey returns the wrap key for a connection password.
func DeriveKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("empty password")
	}
	key := make([]byte, chacha20poly1305.KeySize)
	r := hkdf.New(sha256.New, []byte(password), []byte("WDTT-WRAP-v1"), []byte("rtp-obfs/chacha20poly1305"))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func newAEAD(password string) (cipher.AEAD, error) {
	k, err := DeriveKey(password)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(k)
}

// looksLikeRTP is the cheap check done before any decryption attempt.
func looksLikeRTP(b []byte) bool {
	if len(b) < minWireLen+tagLen || b[0]>>6 != 2 {
		return false
	}
	pt := b[1] & 0x7f
	return pt == ptAudio || pt == ptVideo
}

func nonceFor(hdr []byte) [12]byte {
	var n [12]byte
	copy(n[0:4], hdr[8:12]) // SSRC
	copy(n[4:6], hdr[2:4])  // sequence
	copy(n[8:12], hdr[4:8]) // timestamp
	return n
}

// open authenticates and decrypts one wrapped datagram into dst.
func open(aead cipher.AEAD, wire, dst []byte) (int, error) {
	if len(wire) < minWireLen || wire[0]>>6 != 2 {
		return 0, errors.New("not an RTP packet")
	}
	end := len(wire)
	if wire[0]&0x20 != 0 {
		pad := int(wire[end-1])
		if pad == 0 || pad > end-rtpHeaderLen {
			return 0, errors.New("bad RTP padding")
		}
		end -= pad
	}
	ct := wire[rtpHeaderLen:end]
	if len(ct) <= tagLen || len(ct)-tagLen > len(dst) {
		return 0, errors.New("bad payload length")
	}
	n := nonceFor(wire)
	out, err := aead.Open(dst[:0], n[:], ct, wire[:rtpHeaderLen])
	if err != nil {
		return 0, err
	}
	return len(out), nil
}

// sealer wraps outgoing datagrams of one stream. Sequence and timestamp
// advance like a 48 kHz Opus stream with 20 ms frames; the (seq, ts) pair
// stays unique for 2^48 packets, which keeps nonces unique per key.
type sealer struct {
	aead   cipher.AEAD
	ssrc   uint32
	pt     byte
	padMax int
	seq0   uint16
	ts0    uint32
	n      atomic.Uint64
}

func newSealer(aead cipher.AEAD, pt byte) *sealer {
	s := &sealer{aead: aead, pt: pt & 0x7f, padMax: 24, ssrc: rand.Uint32(), seq0: uint16(rand.Uint32()), ts0: rand.Uint32()}
	if s.pt == ptVideo {
		s.padMax = 60
	}
	return s
}

// sealedLen is the largest size seal can produce for a payload.
func (s *sealer) sealedLen(payload int) int { return rtpHeaderLen + payload + tagLen + s.padMax }

// seal writes the wrapped form of payload into dst and returns its length.
func (s *sealer) seal(dst, payload []byte) int {
	c := s.n.Add(1) - 1
	seq := s.seq0 + uint16(c)
	ts := s.ts0 + uint32(c)*960 + uint32(c>>16)
	dst[0] = 0x80 | 0x20
	dst[1] = s.pt
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	binary.BigEndian.PutUint32(dst[8:12], s.ssrc)
	n := nonceFor(dst)
	out := s.aead.Seal(dst[rtpHeaderLen:rtpHeaderLen], n[:], payload, dst[:rtpHeaderLen])
	end := rtpHeaderLen + len(out)
	pad := 1 + rand.IntN(s.padMax)
	r := rand.Uint64()
	for i := 0; i < pad-1; i++ {
		if i%8 == 0 && i > 0 {
			r = rand.Uint64()
		}
		dst[end+i] = byte(r >> (8 * (i % 8)))
	}
	dst[end+pad-1] = byte(pad)
	return end + pad
}
