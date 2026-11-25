package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
)

func sipTestJavaStream() []byte {
	out := []byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x0a}
	out = append(out, []byte("SerSocksIP")...)
	out = append(out, make([]byte, 8)...)
	out = append(out, 0x02, 0x00, 0x01, 'I', 0x00, 0x04)
	out = append(out, []byte("port")...)
	out = append(out, 0x78, 0x70, 0x00, 0x00, 0x01, 0xbb)
	return out
}

func sipTestWrap(payload []byte) []byte {
	pad := aes.BlockSize - len(payload)%aes.BlockSize
	padded := append(append([]byte(nil), payload...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, err := aes.NewCipher(sipOuterKey)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return []byte(base64.StdEncoding.EncodeToString(out))
}

func sipTestAESCFBEncrypt(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	cipher.NewCFBEncrypter(block, sipIV).XORKeyStream(out, data)
	return out
}

func sipTestCASTCFBEncrypt(data, key []byte) []byte {
	block, err := cast5.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	cipher.NewCFBEncrypter(block, sipIV[:cast5.BlockSize]).XORKeyStream(out, data)
	return out
}

func sipTestVER8(stream []byte) []byte {
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	block, err := aes.NewCipher(sipVER8Key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	payload := append([]byte("VER8"), nonce...)
	payload = append(payload, gcm.Seal(nil, nonce, stream, nil)...)
	return sipTestWrap(payload)
}

func sipTestLayered(stream []byte, version string, tailSize int) []byte {
	n := len(stream) + 65
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	stored := append([]byte(nil), key...)
	stored[0], stored[31] = stored[31], stored[0]

	encrypted := sipTestAESCFBEncrypt(stream, key)
	rebuilt := make([]byte, 0, len(stream)+58)
	for i := 0; i < 16; i++ {
		rebuilt = append(rebuilt, byte(i))
	}
	rebuilt = append(rebuilt, sipReverseCopy(encrypted[10:])...)
	rebuilt = append(rebuilt, encrypted[:10]...)
	rebuilt = append(rebuilt, stored...)

	xor := pbkdf2.Key(rebuilt[:16], sipSalt, 32, 1500, sha1.New)
	for i := 0; i < min(1500, len(rebuilt)-16); i++ {
		rebuilt[16+i] ^= xor[i]
	}

	half := (n - 17) / 2
	castPlain := append([]byte{1}, rebuilt[len(rebuilt)-half:]...)
	castPlain = append(castPlain, sipReverseCopy(rebuilt[:len(rebuilt)-half])...)
	castKey := make([]byte, 16)
	for i := range castKey {
		castKey[i] = byte(i)
	}
	castEncrypted := sipTestCASTCFBEncrypt(castPlain, castKey)

	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	record := append([]byte(nil), nonce...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(n))
	record = append(record, length[:]...)
	record = append(record, make([]byte, n)...)
	record = append(record, castEncrypted...)
	record = append(record, castKey...)

	var salsaKey [32]byte
	for i := range salsaKey {
		salsaKey[i] = byte(i)
	}
	salsaPlain := make([]byte, len(record)-8)
	salsa20.XORKeyStream(salsaPlain, record[8:], nonce, &salsaKey)
	record = append(append([]byte(nil), nonce...), salsaPlain...)

	prefix := append([]byte(nil), salsaKey[:]...)
	prefix = append(prefix, sipReverseCopy(record)...)
	prefix = append(prefix, make([]byte, 32)...)
	outerKey := make([]byte, 32)
	for i := range outerKey {
		outerKey[i] = byte(i)
	}
	payload := append([]byte(version), sipTestAESCFBEncrypt(prefix, outerKey)...)
	for i := 0; i < 16; i++ {
		payload = append(payload, byte(i))
	}
	payload = append(payload, make([]byte, tailSize-32)...)
	for i := 31; i >= 16; i-- {
		payload = append(payload, byte(i))
	}
	return sipTestWrap(payload)
}

func TestDecryptSIP(t *testing.T) {
	stream := sipTestJavaStream()
	tests := []struct {
		name      string
		container string
		data      []byte
	}{
		{"legacy", "legacy", sipTestWrap(stream)},
		{"ver8", "VER8", sipTestVER8(stream)},
		{"ver2", "VER2", sipTestLayered(stream, "VER2", 32)},
		{"ver5", "VER5", sipTestLayered(stream, "VER5", 52)},
		{"ver7", "VER7", sipTestLayered(stream, "VER7", 47)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := DecryptSIP(tt.data)
			if err != nil {
				t.Fatalf("DecryptSIP: %v", err)
			}
			if !strings.Contains(out, "// container: "+tt.container) {
				t.Fatalf("missing container %s in output", tt.container)
			}
			if !strings.Contains(out, `"port": 443`) {
				t.Fatalf("missing port field in output:\n%s", out)
			}
		})
	}
}

func TestDecryptSIPRejectsGarbage(t *testing.T) {
	if _, err := DecryptSIP([]byte("not a config")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSIPModifiedUTF8(t *testing.T) {
	raw := []byte{'a', 0xc3, 0xb1, 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80}
	if got := sipModifiedUTF8(raw); got != "añ\x00😀" {
		t.Fatalf("got %q", got)
	}
}

func TestSIPLayeredFixtureShape(t *testing.T) {
	data := sipTestLayered(sipTestJavaStream(), "VER7", 47)
	out, err := DecryptSIP(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "// class: SerSocksIP") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestSIPOpenSSLField(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	var material, previous []byte
	for len(material) < 48 {
		h := md5.New()
		h.Write(previous)
		h.Write(sipFieldKey)
		h.Write(salt)
		previous = h.Sum(nil)
		material = append(material, previous...)
	}
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("secret-password")
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, material[32:48]).CryptBlocks(encrypted, plain)
	record := append([]byte("Salted__"), salt...)
	record = append(record, encrypted...)
	blob := base64.StdEncoding.EncodeToString(record)
	got, ok := sipOpenSSLField(blob)
	if !ok || got != "secret-password" {
		t.Fatalf("got %q, %v", got, ok)
	}
}
