package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"Pantegnos/internal/modules"
)

func hcTestAESECBEncrypt(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	n := block.BlockSize() - len(data)%block.BlockSize()
	padded := append(bytes.Clone(data), bytes.Repeat([]byte{byte(n)}, n)...)
	out := make([]byte, len(padded))
	for i := range len(padded) / block.BlockSize() {
		off := i * block.BlockSize()
		block.Encrypt(out[off:off+block.BlockSize()], padded[off:off+block.BlockSize()])
	}
	return out
}

func TestHCLegacyRoundTrip(t *testing.T) {
	plain := "PAYLOAD[splitConfig]PROXY[splitConfig]false[splitConfig]false"
	key := "hc_reborn_4"
	sum := sha1.Sum([]byte(key))
	blob := hcTestAESECBEncrypt(sum[:16], []byte(plain))
	b64 := base64.StdEncoding.EncodeToString(blob)
	runes := make([]rune, len(b64))
	for i := range b64 {
		runes[i] = rune(b64[i]) ^ hcLegacyXor[i%len(hcLegacyXor)]
	}
	text, ok := hcDecodeLegacy([]byte(string(runes)))
	if !ok {
		t.Fatal("legacy decode failed")
	}
	if !strings.Contains(text, "payload: PAYLOAD") || !strings.Contains(text, "payloadProxyURL: PROXY") {
		t.Fatalf("unexpected output:\n%s", text)
	}
}

func hcWriteInt(buf *bytes.Buffer, v int) {
	buf.Write(binary.BigEndian.AppendUint32(nil, uint32(v)))
}

func hcWriteStr(buf *bytes.Buffer, s string) {
	hcWriteInt(buf, len(s))
	buf.WriteString(s)
}

func TestHCParseHPC1(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("HPC1")
	hcWriteInt(&buf, 11)
	hcWriteStr(&buf, "name1")
	hcWriteStr(&buf, "SSH")
	hcWriteStr(&buf, "1.2.3.4")
	hcWriteInt(&buf, 2222)
	hcWriteStr(&buf, "user")
	hcWriteStr(&buf, "pass")
	hcWriteStr(&buf, "payload")
	hcWriteStr(&buf, `{"a":1}`)
	text := hcParseHPC1("s0", buf.Bytes())
	for _, want := range []string{"protocol: SSH", "host: 1.2.3.4", "port: 2222", "username: user", "password: pass", "payload: payload"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestHCHCCFGRoundTrip(t *testing.T) {
	gkey := bytes.Repeat([]byte{0x42}, 32)
	fields := []string{"ssh"}
	version := "test"
	header := bytes.Join([][]byte{
		[]byte("HCCFG"), {0}, []byte(hcAppID), {0}, []byte("1"), {0},
		[]byte("ssh"), {0}, []byte(version), {0}, gkey,
	}, nil)
	headerKey := hcHMAC(hcSealKey, bytes.Join([][]byte{{0xd3}, hcSealInfo[:32], header}, nil))
	appCfg := "app-config|n7|" + hcAppID + "|1|ssh|" + version
	g, err := hkdf.Key(sha256.New, headerKey, gkey, appCfg, 32)
	if err != nil {
		t.Fatal(err)
	}

	meta := []byte(`{"g":{"v":"hello"}}`)
	metaSalt := bytes.Repeat([]byte{0x11}, 24)
	metaCT, _ := hcXChaCha(g, metaSalt, meta)
	metaCT = append(metaCT, make([]byte, 16)...)

	var sec bytes.Buffer
	sec.WriteString("HPC1")
	hcWriteInt(&sec, 11)
	hcWriteStr(&sec, "name")
	hcWriteStr(&sec, "SSH")
	hcWriteStr(&sec, "1.2.3.4")
	hcWriteInt(&sec, 22)
	hcWriteStr(&sec, "u")
	hcWriteStr(&sec, "p")
	hcWriteStr(&sec, "")
	hcWriteStr(&sec, "{}")
	secSalt := bytes.Repeat([]byte{0x22}, 24)
	secCT, _ := hcXChaCha(g, secSalt, sec.Bytes())
	secCT = append(secCT, make([]byte, 16)...)

	env := hcEnvelope{
		Magic:     "HCCFG",
		Schema:    7,
		Cipher:    "s1",
		KDF:       "h1",
		Schedule:  "n7",
		Fields:    fields,
		Key:       hex.EncodeToString(gkey),
		Protected: json.RawMessage("0"),
		Version:   hcVersion(version),
		Main:      new(hcItem{Label: "m", Salt: hex.EncodeToString(metaSalt), Ciphertext: hex.EncodeToString(metaCT)}),
		Sections:  []hcItem{{Label: "s0", Salt: hex.EncodeToString(secSalt), Ciphertext: hex.EncodeToString(secCT)}},
	}
	plain, _ := json.Marshal(env)
	outerSalt := bytes.Repeat([]byte{0x33}, 24)
	outerCT, _ := hcXChaCha(hcStaticKey, outerSalt, plain)
	file := bytes.Join([][]byte{outerSalt, outerCT, make([]byte, 16)}, nil)

	res, err := decryptHTTPCustom(modules.Request{FileName: "x.hc", Data: file})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Text, `"v": "hello"`) || !strings.Contains(res.Text, "host: 1.2.3.4") {
		t.Fatalf("unexpected output:\n%s", res.Text)
	}
}
