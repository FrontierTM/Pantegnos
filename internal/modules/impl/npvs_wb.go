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

//go:embed assets/npvs/tboxes_last_v2.bin
var npvsTlastBinV2 []byte

//go:embed assets/npvs/tyboxes.bin
var npvsTyBin []byte

//go:embed assets/npvs/mbl.bin
var npvsMblBin []byte

//go:embed assets/npvs/xor.bin
var npvsXorBin []byte

var wbShiftRows = [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}

var wbKdfPrefix = []byte("npvtunnel/appkey/v1 ")

const (
	wbTlastSize  = 4096
	wbTableSize = 16384
	wbXorSize   = 24576
)

var (
	wbTy      [16][256]uint32
	wbMbl     [16][256]uint32
	wbTlastV1 [16][256]byte
	wbTlastV2 [16][256]byte

	wbOnce sync.Once
	wbErr  error
)

func loadWB() error {
	wbOnce.Do(func() {
		if len(npvsTlastBin) != wbTlastSize || len(npvsTlastBinV2) != wbTlastSize ||
			len(npvsTyBin) != wbTableSize || len(npvsMblBin) != wbTableSize ||
			len(npvsXorBin) != wbXorSize {
			wbErr = errors.New("npvs: embedded whitebox blob has wrong size")
			return
		}
		for i := 0; i < 16; i++ {
			copy(wbTlastV1[i][:], npvsTlastBin[i*256:(i+1)*256])
			copy(wbTlastV2[i][:], npvsTlastBinV2[i*256:(i+1)*256])
			for j := 0; j < 256; j++ {
				k := (i*256 + j) * 4
				wbTy[i][j] = binary.BigEndian.Uint32(npvsTyBin[k:])
				wbMbl[i][j] = binary.BigEndian.Uint32(npvsMblBin[k:])
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

func wbMix(grp, k int, a, b, c, d uint32) byte {
	t := grp*24 + k*6
	hi := uint(28 - 8*k)
	lo := uint(24 - 8*k)
	p1 := wbXor(t, int(a>>hi)&15, int(b>>hi)&15)
	p2 := wbXor(t+1, int(c>>hi)&15, int(d>>hi)&15)
	p3 := wbXor(t+2, int(a>>lo)&15, int(b>>lo)&15)
	p4 := wbXor(t+3, int(c>>lo)&15, int(d>>lo)&15)
	return wbXor(t+4, int(p1), int(p2))<<4 | wbXor(t+5, int(p3), int(p4))
}

func wbApplyRow(s *[16]byte, base int, tab [16][256]uint32, grp int) {
	a := tab[base+0][s[base+0]]
	b := tab[base+1][s[base+1]]
	c := tab[base+2][s[base+2]]
	d := tab[base+3][s[base+3]]
	for k := 0; k < 4; k++ {
		s[base+k] = wbMix(grp, k, a, b, c, d)
	}
}

func wbBlock(in *[16]byte, tlast *[16][256]byte) (out [16]byte) {
	s := *in

	wbShift(&s)

	for grp := 0; grp < 4; grp++ {
		base := grp * 4

		wbApplyRow(&s, base, wbTy, grp)
		wbApplyRow(&s, base, wbMbl, grp)
	}

	wbShift(&s)

	for i := 0; i < 16; i++ {
		out[i] = tlast[i][s[i]]
	}
	return out
}

func wbCTR(nonce, ct []byte, tlast *[16][256]byte) []byte {
	var counter [16]byte
	copy(counter[:], nonce[:16])

	out := make([]byte, len(ct))
	for i := 0; i < len(ct); i += 16 {
		ks := wbBlock(&counter, tlast)

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

func custodianKDKs(salt []byte) [][]byte {
	if loadWB() != nil {
		return nil
	}

	material := make([]byte, 32)
	copy(material, salt[:16])

	var kdks [][]byte
	for _, tlast := range wbVariants() {
		stream := wbCTR(material[:16], material[16:], tlast)
		sum := sha256.Sum256(append(append([]byte{}, wbKdfPrefix...), stream...))
		kdks = append(kdks, sum[:])
	}
	return kdks
}

func wbVariants() []*[16][256]byte {
	return []*[16][256]byte{&wbTlastV1, &wbTlastV2}
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
