package impl

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const npvSentinelPrefix = "npvs1:"

const npvSentinelAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"

//go:embed assets/npvs/tboxes_last.bin
var npvsTlastBin []byte

//go:embed assets/npvs/tyboxes.bin
var npvsTyBin []byte

//go:embed assets/npvs/mbl.bin
var npvsMblBin []byte

//go:embed assets/npvs/xor.bin
var npvsXorBin []byte

var wbShiftRows = [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}

var wbKdfPrefix = []byte("npvtunnel/appkey/v1 ")

var (
	wbTy    [16][256]uint32
	wbMbl   [16][256]uint32
	wbTlast [16][256]byte

	wbOnce sync.Once
	wbErr  error
)

func loadWB() error {
	wbOnce.Do(func() {
		if len(npvsTlastBin) != 4096 || len(npvsTyBin) != 16384 ||
			len(npvsMblBin) != 16384 || len(npvsXorBin) != 24576 {
			wbErr = errors.New("npvs: embedded whitebox blob has wrong size")
			return
		}
		for i := 0; i < 16; i++ {
			copy(wbTlast[i][:], npvsTlastBin[i*256:(i+1)*256])
			for j := 0; j < 256; j++ {
				wbTy[i][j] = binary.BigEndian.Uint32(npvsTyBin[(i*256+j)*4:])
				wbMbl[i][j] = binary.BigEndian.Uint32(npvsMblBin[(i*256+j)*4:])
			}
		}
	})
	return wbErr
}

func wbShift(s *[16]byte) {
	var t [16]byte
	for i := 0; i < 16; i++ {
		t[i] = s[wbShiftRows[i]]
	}
	*s = t
}

func wbXor(t, a, b int) byte {
	return npvsXorBin[(t<<8)+(a<<4)+b]
}

func wbBlock(in *[16]byte) (out [16]byte) {
	s := *in

	wbShift(&s)

	for grp := 0; grp < 4; grp++ {
		base := grp * 4

		i1 := wbTy[base+0][s[base+0]]
		i2 := wbTy[base+1][s[base+1]]
		i3 := wbTy[base+2][s[base+2]]
		i4 := wbTy[base+3][s[base+3]]
		for k := 0; k < 4; k++ {
			tb := grp*24 + k*6
			hi := uint(28 - 8*k)
			lo := uint(24 - 8*k)

			b10 := wbXor(tb, int(i1>>hi)&15, int(i2>>hi)&15)
			b11 := wbXor(tb+1, int(i3>>hi)&15, int(i4>>hi)&15)
			b2a := wbXor(tb+2, int(i1>>lo)&15, int(i2>>lo)&15)
			b3a := wbXor(tb+3, int(i3>>lo)&15, int(i4>>lo)&15)

			vhi := wbXor(tb+4, int(b10), int(b11))
			vlo := wbXor(tb+5, int(b2a), int(b3a))
			s[base+k] = vlo | vhi<<4
		}

		i5 := wbMbl[base+0][s[base+0]]
		i6 := wbMbl[base+1][s[base+1]]
		i7 := wbMbl[base+2][s[base+2]]
		i8 := wbMbl[base+3][s[base+3]]
		for k := 0; k < 4; k++ {
			tb := grp*24 + k*6
			hi := uint(28 - 8*k)
			lo := uint(24 - 8*k)

			a := wbXor(tb, int(i5>>hi)&15, int(i6>>hi)&15)
			b := wbXor(tb+1, int(i7>>hi)&15, int(i8>>hi)&15)
			c := wbXor(tb+2, int(i5>>lo)&15, int(i6>>lo)&15)
			d := wbXor(tb+3, int(i7>>lo)&15, int(i8>>lo)&15)

			vhi := wbXor(tb+4, int(a), int(b))
			vlo := wbXor(tb+5, int(c), int(d))
			s[base+k] = vhi<<4 | vlo
		}
	}

	wbShift(&s)

	for i := 0; i < 16; i++ {
		out[i] = wbTlast[i][s[i]]
	}
	return out
}

func wbCTR(nonce, ct []byte) []byte {
	var counter [16]byte
	copy(counter[:], nonce[:16])

	out := make([]byte, len(ct))
	for i := 0; i < len(ct); i += 16 {
		ks := wbBlock(&counter)

		n := len(ct) - i
		if n > 16 {
			n = 16
		}
		for j := 0; j < n; j++ {
			out[i+j] = ct[i+j] ^ ks[j]
		}

		for p := 15; p >= 0; p-- {
			counter[p]++
			if counter[p] != 0 {
				break
			}
		}
	}
	return out
}

func custodianKDK(salt []byte) []byte {
	if loadWB() != nil {
		return nil
	}
	material := make([]byte, 32)
	copy(material, salt[:16])
	stream := wbCTR(material[:16], material[16:])
	sum := sha256.Sum256(append(append([]byte{}, wbKdfPrefix...), stream...))
	return sum[:]
}

func chachaOpen(key, nonce, ctTag, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ctTag, aad)
}

func b64UrlNoPad(s string) ([]byte, error) {
	if r, err := base64.URLEncoding.DecodeString(s); err == nil {
		return r, nil
	}
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func decodeNpvSentinels(s string) string {
	var sb strings.Builder
	for {
		i := strings.Index(s, npvSentinelPrefix)
		if i < 0 {
			sb.WriteString(s)
			return sb.String()
		}
		sb.WriteString(s[:i])
		s = s[i+len(npvSentinelPrefix):]

		j := 0
		for j < len(s) && strings.IndexByte(npvSentinelAlphabet, s[j]) >= 0 {
			j++
		}
		tok := s[:j]
		s = s[j:]

		dec, ok := decodeSentinelToken(tok)
		if !ok {
			sb.WriteString(npvSentinelPrefix)
			sb.WriteString(tok)
			continue
		}
		sb.Write(dec)
	}
}

func decodeSentinelToken(tok string) ([]byte, bool) {
	if dec, err := base64.StdEncoding.DecodeString(tok); err == nil {
		return dec, true
	}
	if dec, err := base64.URLEncoding.DecodeString(tok); err == nil {
		return dec, true
	}
	if m := len(tok) % 4; m != 0 {
		if dec, err := base64.URLEncoding.DecodeString(tok + strings.Repeat("=", 4-m)); err == nil {
			return dec, true
		}
	}
	return nil, false
}
