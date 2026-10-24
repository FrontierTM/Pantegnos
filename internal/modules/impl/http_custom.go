package impl

import (
	"bytes"
	"cmp"
	"crypto/aes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20"

	"Pantegnos/internal/modules"
)

const (
	hcAppID          = "xyz.easypro.httpcustom"
	hcOuterXorKeyHex = "e382e4b8adc386f09f9293"
	hcStaticKeyHex   = "88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f"
	hcSealKeyHex     = "9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3"
	hcSealInfoHex    = "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc18138cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92"
	hcChaChaKey1Hex  = "3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"
	hcChaChaKey5Hex  = "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"
	hcChaChaKey7Hex  = "3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"
	hcFieldMarker    = "88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d"
)

var (
	hcStaticKey   = hcMustHex(hcStaticKeyHex)
	hcSealKey     = hcMustHex(hcSealKeyHex)
	hcSealInfo    = hcMustHex(hcSealInfoHex)
	hcOuterXorKey = hcMustHex(hcOuterXorKeyHex)
)

var (
	hcChaChaKey1 = hcMustHex(hcChaChaKey1Hex)
	hcChaChaKey5 = hcMustHex(hcChaChaKey5Hex)
	hcChaChaKey7 = hcMustHex(hcChaChaKey7Hex)
)

var hcRstKeys = []string{
	"JN1k3YHc2.6_v235",
	"JN1k3YHc_2.7_v71",
	"JN1k3YHc2.7.ps69",
	"JN1k3YHc2.7.6950",
	"Jn1K3yHc2.8.ps08",
	"Jn1K3yHc2.9.ps6c",
	"Zk:L7>WKaiK*s9>D",
	"!<f!&WIlM**R.B0X",
	"b4a5opinx2uloec6",
}

var hcLegacyXor = []rune{'。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕'}

var hcLegacyFields = []string{
	"payload", "payloadProxyURL", "shouldNotWorkWithRoot", "lockPayloadAndServers",
	"expiryDate", "hasNotes", "noteField2", "sshAddress", "onlyAllowOnMobileData",
	"unlockRemoteProxy", "unknown", "vpnAddress", "sslSni", "shouldConnectUsingSSH",
	"udpgwPort", "lockPayload", "hasHWID", "hwid", "noteField1",
	"unlockUserAndPassword", "sslAndPayloadMode", "enablePassword", "password",
}

var hcLegacyKeys = []string{
	"hc_reborn___7", "hc_reborn_tester", "hc_reborn_tester_5", "hc_reborn_7",
	"hc_reborn_6", "hc_reborn_5", "hc_reborn_4", "hc_reborn_3", "hc_reborn_2",
	"hc_reborn_1", "hc_reborn10", "hc_reborn9", "hc_reborn8", "hc_reborn7",
	"keY_secReaT_hc", "keY_secReaT_hc1", "keY_secReaT_hc2", "keY_secReaT_hc_reborn",
	"keY_secReaT_hc_reborn1", "keY_secReaT_hc_2", "keY_secReaT_hc_reborn3",
	"keY_secReaT_hc_reborn4", "keY_secReaT_hc_reborn5", "keY_secReaT_hc_reborn6",
	"keY_secReaT_te4Z9", "keY_secReaT_te4Z10", "keY_secReaT_te4Z11", "keY_secReaT_e",
}

func init() {
	modules.Register(modules.Module{
		Name:      "HTTP Custom config export (.hc)",
		ApkAuthor: "xyz.easypro.httpcustom",
		Proto:     []string{"HCCFG", "HCX1"},
		Extension: ".hc",
		Decrypt:   decryptHTTPCustom,
	})
}

var (
	errHCPassword = errors.New("http custom: this .hc file is password-protected")
	errHCHWID     = errors.New("http custom: this .hc file is HWID-locked")
)

func decryptHTTPCustom(req modules.Request) (modules.Result, error) {
	if text, ok := hcDecodeLegacy(req.Data); ok {
		return hcResult(req, text), nil
	}
	if text, ok := hcDecodeOrdinary(req.Data); ok {
		return hcResult(req, text), nil
	}
	if text, err := hcDecodeHCCFG(req.Data); err == nil {
		return hcResult(req, text), nil
	} else if errors.Is(err, errHCPassword) || errors.Is(err, errHCHWID) {
		return modules.Result{}, err
	}
	return modules.Result{}, errors.New("http custom: unsupported or corrupt .hc file")
}

func hcResult(req modules.Request, text string) modules.Result {
	return modules.Result{
		Text:     text,
		FileName: modules.OutputName(req.FileName, ".hc"),
		Echo:     true,
	}
}

func hcLatin1(data []byte) []byte {
	if !utf8.Valid(data) {
		return bytes.Clone(data)
	}
	out := make([]byte, 0, len(data))
	for _, r := range string(data) {
		if r > 0xff {
			out = append(out, '?')
			continue
		}
		out = append(out, byte(r))
	}
	return out
}

func hcXor(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func hcXChaCha(key, nonce, data []byte) ([]byte, error) {
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	c.SetCounter(1)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

func hcChaCha8(key, nonce8, data []byte) ([]byte, error) {
	var nonce [12]byte
	copy(nonce[4:], nonce8)
	return hcXChaCha(key, nonce[:], data)
}

func hcAESECBDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of %d", len(data), block.BlockSize())
	}
	out := make([]byte, len(data))
	for i := range len(data) / block.BlockSize() {
		off := i * block.BlockSize()
		block.Decrypt(out[off:off+block.BlockSize()], data[off:off+block.BlockSize()])
	}
	return out, nil
}

func hcUnpadPKCS7(data []byte, blockSize int) []byte {
	if len(data) == 0 {
		return data
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		return data
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return data
		}
	}
	return data[:len(data)-n]
}

func hcDecodeLegacy(data []byte) (string, bool) {
	if !utf8.Valid(data) {
		return "", false
	}
	runes := []rune(string(data))
	if len(runes) < 16 {
		return "", false
	}
	raw := make([]byte, len(runes))
	for i, r := range runes {
		raw[i] = byte(r ^ hcLegacyXor[i%len(hcLegacyXor)])
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		blob, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return "", false
		}
	}
	for _, key := range hcLegacyKeys {
		sum := sha1.Sum([]byte(key))
		pt, err := hcAESECBDecrypt(sum[:16], blob)
		if err != nil {
			continue
		}
		if text := hcFormatSplitConfig(string(hcUnpadPKCS7(pt, aes.BlockSize))); text != "" {
			return text, true
		}
	}
	return "", false
}

func hcFormatSplitConfig(text string) string {
	if !strings.Contains(text, "[splitConfig]") {
		return ""
	}
	var sb strings.Builder
	i := 0
	for part := range strings.SplitSeq(text, "[splitConfig]") {
		if i >= len(hcLegacyFields) {
			break
		}
		part = strings.TrimSpace(part)
		if part != "" {
			fmt.Fprintf(&sb, "%s: %s\n", hcLegacyFields[i], part)
		}
		i++
	}
	return strings.TrimSpace(sb.String())
}

func hcDecodeOrdinary(data []byte) (string, bool) {
	b := hcXor(hcLatin1(data), hcOuterXorKey)
	if !utf8.Valid(b) {
		return "", false
	}
	hx := hcOnlyHex(string(b))
	if len(hx) <= 32 {
		return "", false
	}
	enc, err := hex.DecodeString(hx)
	if err != nil || len(enc) <= 16 {
		return "", false
	}
	pt, err := hcChaCha8(hcChaChaKey5, bytes.Repeat([]byte{0xdb}, 8), enc[:len(enc)-16])
	if err != nil {
		return "", false
	}
	var root hcOrdinary
	if json.Unmarshal(pt, &root) != nil {
		return "", false
	}
	if text := root.text(); text != "" {
		return text, true
	}
	return "", false
}

func hcOnlyHex(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			return r
		}
		return -1
	}, s)
}

func hcBase64Loose(s string) ([]byte, error) {
	t := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/', r == '=':
			return r
		}
		return -1
	}, s)
	t = strings.TrimRight(t, "=")
	for len(t)%4 != 0 {
		t += "="
	}
	return base64.StdEncoding.DecodeString(t)
}

type hcOrdinary struct {
	Cfg *struct {
		Content string `json:"content"`
		XY      string `json:"xy"`
		UV      string `json:"uv"`
	} `json:"cfg"`
	A      *hcOrdinaryA `json:"a"`
	Mode   string       `json:"uv"`
	Config string       `json:"xy"`
}

type hcOrdinaryA struct {
	XY       string `json:"xy"`
	UV       string `json:"uv"`
	HWID     string `json:"bb"`
	Password string `json:"e"`
	Area     string `json:"fe"`
	Provider string `json:"ed"`
}

var hcConfigFields = []string{
	"payload", "proxy", "lockAllConfig", "blockedByRoot", "expiryTime",
	"noteEnabled", "notes", "sshField", "mobileDataAndLockProvider",
	"unlockUserAndPass", "ovpnConfig", "ovpnUserAndPass", "sni",
	"unlockUserAndPass2", "unknown14", "blockedByHwid", "cloudconfig",
	"psiphon", "name", "blockArea", "connectionMode", "blockedByPassword",
	"unknown22", "extraSniffer", "psiphon2", "v2rayEnabled", "v2rayConfig",
	"version", "slowdnsEnabled", "slowdnsServer", "slowdnsPublickey", "dnsResolver",
}

func (o *hcOrdinary) text() string {
	var xy, uv string
	if cfg := o.Cfg; cfg != nil {
		if cfg.Content != "" {
			b := []byte(cfg.Content)
			for i := range b {
				b[i] ^= byte(i%20 + 2)
			}
			if raw, err := hcBase64Loose(string(b)); err == nil {
				for _, key := range hcRstKeys {
					pt, err := hcAESECBDecrypt([]byte(key), raw)
					if err != nil {
						continue
					}
					if text := hcFormatSplitConfig(string(hcUnpadPKCS7(pt, aes.BlockSize))); text != "" {
						return text
					}
				}
			}
		}
		xy, uv = cfg.XY, cfg.UV
	}
	if a := o.A; a != nil {
		if xy == "" {
			xy = a.XY
		}
		if uv == "" {
			uv = a.UV
		}
		if xy != "" && uv != "" {
			if text := hcOrdinaryConfig(xy, uv, a); text != "" {
				return text
			}
		}
	}
	if xy == "" {
		xy = o.Config
	}
	if uv == "" {
		uv = o.Mode
	}
	if xy != "" && uv != "" {
		if text := hcOrdinaryConfig(xy, uv, o.A); text != "" {
			return text
		}
	}
	if a := o.A; a != nil {
		var sb strings.Builder
		for _, f := range []struct{ name, value string }{
			{"hwid", a.HWID},
			{"password", a.Password},
			{"area", a.Area},
			{"provider", a.Provider},
		} {
			if f.value != "" {
				fmt.Fprintf(&sb, "%s: %s\n", f.name, f.value)
			}
		}
		if sb.Len() > 0 {
			return strings.TrimSpace(sb.String())
		}
	}
	return ""
}

func hcOrdinaryConfig(xy, uv string, a *hcOrdinaryA) string {
	plain, err := hcOpenField(xy, hcChaChaKey1)
	if err != nil {
		return ""
	}
	parts := strings.Split(string(plain), uv)
	if len(parts) == 0 {
		return ""
	}
	protections := make(map[string]string)
	if a != nil {
		for _, f := range []struct{ name, value string }{
			{"hwid", a.HWID},
			{"password", a.Password},
			{"area", a.Area},
			{"provider", a.Provider},
		} {
			if f.value == "" {
				continue
			}
			out, err := hcOpenField(f.value, hcChaChaKey7)
			if err == nil && len(out) > 0 {
				protections[f.name] = string(out)
			}
		}
	}
	config := make(map[string]string)
	for i, part := range parts {
		if i == 22 || i == 24 || i >= len(hcConfigFields) {
			continue
		}
		value := strings.ReplaceAll(part, hcFieldMarker, "")
		if value == "" || hcLooksHex(value) {
			continue
		}
		config[hcConfigFields[i]] = value
	}
	if len(config) == 0 {
		return ""
	}
	out := struct {
		Protections map[string]string `json:"Protections"`
		Config      map[string]string `json:"Config"`
	}{protections, config}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

func hcOpenField(value string, key []byte) ([]byte, error) {
	raw, err := hex.DecodeString(hcOnlyHex(value))
	if err != nil {
		return nil, err
	}
	if len(raw) <= 16 {
		return nil, errors.New("http custom: field is too short")
	}
	return hcChaCha8(key, bytes.Repeat([]byte{0xdb}, 8), raw[:len(raw)-16])
}

func hcLooksHex(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

type hcEnvelope struct {
	Magic     string          `json:"a"`
	Schema    int             `json:"b"`
	Cipher    string          `json:"c"`
	KDF       string          `json:"d"`
	Schedule  string          `json:"e"`
	Fields    []string        `json:"f"`
	Key       string          `json:"g"`
	Protected json.RawMessage `json:"h"`
	Main      *hcItem         `json:"i"`
	Sections  []hcItem        `json:"j"`
	Version   hcVersion       `json:"n"`
}

type hcItem struct {
	Label      string `json:"a"`
	Salt       string `json:"b"`
	Ciphertext string `json:"c"`
}

type hcVersion string

func (v *hcVersion) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*v = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*v = hcVersion(s)
		return nil
	}
	*v = hcVersion(b)
	return nil
}

func (e *hcEnvelope) passwordProtected() bool {
	switch string(e.Protected) {
	case "1", "true":
		return true
	}
	return false
}

func hcDecodeHCCFG(data []byte) (string, error) {
	candidates := [][]byte{data}
	if latin := hcLatin1(data); !bytes.Equal(latin, data) {
		candidates = append(candidates, latin)
	}
	for _, b := range candidates {
		if len(b) < 40 {
			continue
		}
		pt, err := hcXChaCha(hcStaticKey, b[:24], b[24:len(b)-16])
		if err != nil {
			continue
		}
		var env hcEnvelope
		if json.Unmarshal(pt, &env) == nil && env.Magic == "HCCFG" {
			return hcOpenHCCFG(&env)
		}
	}
	var env hcEnvelope
	if json.Unmarshal(data, &env) == nil && env.Magic == "HCCFG" {
		return hcOpenHCCFG(&env)
	}
	return "", errors.New("http custom: no HCCFG envelope")
}

func hcOpenHCCFG(env *hcEnvelope) (string, error) {
	schema, schedule := env.Schema, env.Schedule
	if schema == 1 {
		return "", errors.New("http custom: HCCFG schema 1 (XChaCha20/HKDF) is not implemented")
	}
	if schema != 2 && schema != 5 && schema != 7 {
		return "", fmt.Errorf("http custom: unsupported HCCFG schema %d", schema)
	}
	if env.passwordProtected() {
		return "", fmt.Errorf("%w (schema %d, schedule %s)", errHCPassword, schema, schedule)
	}
	if schedule == "n2" || schedule == "n8" {
		return "", fmt.Errorf("%w (schedule %s)", errHCHWID, schedule)
	}
	if schedule != "n7" {
		return "", fmt.Errorf("http custom: unsupported HCCFG schedule %q", schedule)
	}
	gkey, err := hex.DecodeString(env.Key)
	if err != nil || len(gkey) != 32 {
		return "", errors.New("http custom: bad HCCFG key")
	}
	version := string(env.Version)
	fieldCSV := strings.Join(env.Fields, ",")
	sep := []byte{0}
	header := bytes.Join([][]byte{
		[]byte("HCCFG"), sep, []byte(hcAppID), sep, []byte("1"), sep,
		[]byte(fieldCSV), sep, []byte(version), sep, gkey,
	}, nil)
	headerKey := hcHMAC(hcSealKey, bytes.Join([][]byte{{0xd3}, hcSealInfo[:32], header}, nil))
	appCfg := "app-config|" + schedule + "|" + hcAppID + "|1|" + fieldCSV
	if version != "" {
		appCfg += "|" + version
	}
	g, err := hkdf.Key(sha256.New, headerKey, gkey, appCfg, 32)
	if err != nil {
		return "", fmt.Errorf("http custom: HCCFG key derivation: %w", err)
	}

	var parts []string
	if env.Main != nil {
		meta, err := hcOpenItem(*env.Main, g)
		if err != nil {
			return "", fmt.Errorf("http custom: main config: %w", err)
		}
		parts = append(parts, hcFormatSection("main config", meta))
	}
	for _, item := range env.Sections {
		plain, err := hcOpenItem(item, g)
		if err != nil {
			parts = append(parts, fmt.Sprintf("// section %s: %v", item.Label, err))
			continue
		}
		parts = append(parts, hcFormatSection("section "+cmp.Or(item.Label, "?"), plain))
	}
	if len(parts) == 0 {
		return "", errors.New("http custom: no HCCFG sections")
	}
	return strings.Join(parts, "\n\n"), nil
}

func hcOpenItem(item hcItem, key []byte) ([]byte, error) {
	salt, err := hex.DecodeString(item.Salt)
	if err != nil || len(salt) != 24 {
		return nil, errors.New("bad section salt")
	}
	ct, err := hex.DecodeString(item.Ciphertext)
	if err != nil || len(ct) < 16 {
		return nil, errors.New("bad section ciphertext")
	}
	plain, err := hcXChaCha(key, salt, ct[:len(ct)-16])
	if err != nil {
		return nil, err
	}
	if rest, ok := bytes.CutPrefix(plain, []byte("HPR1")); ok && len(rest) >= 40 {
		return hcXChaCha(key, rest[:24], rest[24:len(rest)-16])
	}
	return plain, nil
}

func hcFormatSection(label string, plain []byte) string {
	if text := hcParseHPC1(label, plain); text != "" {
		return text
	}
	if utf8.Valid(plain) {
		if pretty, ok := hcIndentJSON(plain); ok {
			return fmt.Sprintf("// %s\n%s", label, pretty)
		}
		return fmt.Sprintf("// %s\n%s", label, plain)
	}
	return fmt.Sprintf("// %s\n%s", label, hex.EncodeToString(plain))
}

func hcIndentJSON(data []byte) ([]byte, bool) {
	var buf bytes.Buffer
	if json.Indent(&buf, data, "", "  ") != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

func hcParseHPC1(label string, data []byte) string {
	rest, ok := bytes.CutPrefix(data, []byte("HPC1"))
	if !ok {
		return ""
	}
	r := bytes.NewReader(rest)
	readUint32 := func() (uint32, bool) {
		var v uint32
		if binary.Read(r, binary.BigEndian, &v) != nil {
			return 0, false
		}
		return v, true
	}
	readString := func() (string, bool) {
		n, ok := readUint32()
		if !ok || uint64(n) > uint64(r.Len()) {
			return "", false
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", false
		}
		return string(b), true
	}
	if _, ok := readUint32(); !ok {
		return ""
	}
	name, ok := readString()
	if !ok {
		return ""
	}
	protocol, ok := readString()
	if !ok {
		return ""
	}
	host, ok := readString()
	if !ok {
		return ""
	}
	port, ok := readUint32()
	if !ok {
		return ""
	}
	user, ok := readString()
	if !ok {
		return ""
	}
	pass, ok := readString()
	if !ok {
		return ""
	}
	payload, ok := readString()
	if !ok {
		return ""
	}
	options, ok := readString()
	if !ok {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "// %s\n", label)
	fmt.Fprintf(&sb, "name: %s\n", name)
	fmt.Fprintf(&sb, "protocol: %s\n", protocol)
	fmt.Fprintf(&sb, "host: %s\n", host)
	fmt.Fprintf(&sb, "port: %d\n", port)
	fmt.Fprintf(&sb, "username: %s\n", user)
	fmt.Fprintf(&sb, "password: %s\n", pass)
	if payload != "" {
		fmt.Fprintf(&sb, "payload: %s\n", payload)
	}
	if options != "" && options != "{}" {
		fmt.Fprintf(&sb, "options: %s\n", options)
	}
	return strings.TrimSpace(sb.String())
}

func hcHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hcMustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("http custom: invalid hex constant: " + err.Error())
	}
	return b
}
