package spec

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

// HopKeys is a VLESS Encryption key pair (ML-KEM-768 + X25519 handshake,
// X25519 authentication). Decryption stays on the hop, Encryption is given
// only to the entry.
type HopKeys struct {
	Decryption string
	Encryption string
}

// NewHopKeys generates keys in the format produced by "xray vlessenc".
// "random" makes the stream indistinguishable from random bytes, so even
// Cloudflare's proxy sees no recognisable protocol inside the Mesh.
func NewHopKeys() (HopKeys, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return HopKeys{}, err
	}
	enc := base64.RawURLEncoding
	return HopKeys{
		Decryption: "mlkem768x25519plus.random.600s." + enc.EncodeToString(priv.Bytes()),
		Encryption: "mlkem768x25519plus.random.0rtt." + enc.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// NewUUID returns a random RFC 4122 version 4 UUID.
func NewUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

const safeChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"

// NewPassword returns a random password of n safe characters.
func NewPassword(n int) string {
	out := make([]byte, n)
	for i := range out {
		v, _ := rand.Int(rand.Reader, big.NewInt(int64(len(safeChars))))
		out[i] = safeChars[v.Int64()]
	}
	return string(out)
}

// RandomPort returns a port in [20000, 60000).
func RandomPort() int {
	v, _ := rand.Int(rand.Reader, big.NewInt(40000))
	return 20000 + int(v.Int64())
}

// ValidAuthorizedKey accepts one plain public key line ("type base64
// [comment]") without authorized_keys options.
func ValidAuthorizedKey(line string) bool {
	if strings.ContainsAny(line, "\r\n") || len(line) > 16384 {
		return false
	}
	pub, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(opts) > 0 || len(rest) > 0 {
		return false
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return true
	case ssh.KeyAlgoRSA:
		if k, ok := pub.(ssh.CryptoPublicKey); ok {
			if r, ok := k.CryptoPublicKey().(*rsa.PublicKey); ok {
				return r.N.BitLen() >= 2048
			}
		}
	}
	return false
}
