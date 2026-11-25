package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"Pantegnos/internal/modules"
)

const (
	tlsBlobPrefix   = 12
	tlsIVSize       = 36
	tlsIVPart       = tlsIVSize / 2
	tlsBlobSuffix   = 84
	tlsBlobOverhead = tlsBlobPrefix + tlsIVSize + tlsBlobSuffix
	tlsGCMTagSize   = 16
	tlsMinCipher    = 2 * tlsGCMTagSize

	tlsLabelWidth = 30
)

const TLSConfigTrailer = ":::::"

const (
	tlsTagV4 = 506
	tlsTagV5 = 507
)

const tlsBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var tlsConfigKeyLiterals = [...]string{
	"0Vtx%\u0431\u043d\u043ea\u06363nh\u01b0nV5\u1ea1\u03c4\u03b7\u03c23",
	"%\u0431\u043d\u043ea\u063623nh\u01b0ng5\u1ea1\u03c4\u03b7\u03c2\u4f1a#",
	"4%\u0431\u043d\u043ea\u063623nh\u01b0ng5B\u1ea1F\u6162\u4f1a#",
	"\u00cbG(FG2e3df|@4%a\u063623\\5FB\u1ea1nHsF#",
	"VxF\u00b03DgKa$\u00a8%\u00b7\u00b0s$5!\u00b2\u00b9\u00ach00k",
}

type tlsFieldKind uint8

const (
	tlsFieldRaw tlsFieldKind = iota
	tlsFieldText
	tlsFieldBool
	tlsFieldPort
)

var tlsPortSelections = [...]string{"AUTO", "T 80", "T 443", "CUSTOM"}

type tlsFieldSpec struct {
	name  string
	label string
	kind  tlsFieldKind
}

var tlsConfigFields = [...]tlsFieldSpec{
	{"tag", "Config tag", tlsFieldRaw},
	{"server", "Server index", tlsFieldRaw},
	{"port", "Port", tlsFieldPort},
	{"sshServer", "Private Server", tlsFieldBool},
	{"sshUser", "SSH user", tlsFieldText},
	{"sshPassword", "SSH password", tlsFieldText},
	{"sshHost", "SSH host", tlsFieldText},
	{"portSpec", "Port text", tlsFieldText},
	{"customPort", "Custom port", tlsFieldText},
	{"sshPort", "SSH port", tlsFieldText},
	{"reserved10", "Field 10", tlsFieldRaw},
	{"usePayload", "Use Payload", tlsFieldBool},
	{"payload", "Payload", tlsFieldText},
	{"useSni", "Use SNI Host", tlsFieldBool},
	{"sniHost", "SNI Host", tlsFieldText},
	{"usePayloadAt", "Use Payload after TLS", tlsFieldBool},
	{"payloadAt", "Payload after TLS", tlsFieldText},
	{"useProxy", "Use Proxy", tlsFieldBool},
	{"proxyHost", "Proxy Host", tlsFieldText},
	{"proxyPort", "Proxy Port", tlsFieldText},
	{"ipv6", "IPv6", tlsFieldBool},
	{"tcpFastOpen", "TCP Fast Open", tlsFieldBool},
	{"tlsChannelOff", "Obfuscated TLSCH", tlsFieldBool},
	{"tcpProto", "TCP Method", tlsFieldBool},
	{"reserved24", "Field 24", tlsFieldRaw},
	{"blockMethod", "Block Method", tlsFieldBool},
	{"blockTorrent", "Block Torrent", tlsFieldBool},
	{"message", "Message", tlsFieldText},
	{"blockRootDevice", "Block Root and DevMode", tlsFieldBool},
}

type TLSConfig struct {
	Tag    int
	Fields []string

	values map[string]string
}

func init() {
	modules.Register(modules.Module{
		Name:      "TLS Tunnel (SSH/proxy payload profiles)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.tlsvpn.tlstunnel",
		Proto:     []string{},
		Extension: ".tls",
		Decrypt: func(req modules.Request) (modules.Result, error) {
			data := req.Data
			if len(data) == 0 {
				data = []byte(req.Payload)
			}

			plaintext, keyIndex, err := DecryptTLSConfig(data)
			if err != nil {
				return modules.Result{}, err
			}
			cfg, err := ParseTLSConfig(plaintext)
			if err != nil {
				return modules.Result{}, err
			}

			return modules.Result{
				Text:     cfg.Format(keyIndex),
				FileName: modules.OutputName(req.FileName, ".tls"),
			}, nil
		},
	})
}

func tlsConfigKeys() [][]byte {
	keys := make([][]byte, len(tlsConfigKeyLiterals))
	for i, literal := range tlsConfigKeyLiterals {
		runes := []rune(literal)
		slices.Reverse(runes)
		keys[i] = []byte(string(runes))
	}
	return keys
}

func tlsReverse(data []byte) []byte {
	out := bytes.Clone(data)
	slices.Reverse(out)
	return out
}

func tlsNewGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, tlsIVSize)
}

func tlsDecodePayload(raw []byte) ([]byte, error) {
	clean := make([]byte, 0, len(raw))
	for _, b := range tlsReverse(raw) {
		if strings.IndexByte(tlsBase64Alphabet, b) >= 0 {
			clean = append(clean, b)
		}
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("no base64 payload found")
	}
	blob, err := base64.RawStdEncoding.DecodeString(string(clean))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %v", err)
	}
	return blob, nil
}

func DecryptTLSConfig(raw []byte) ([]byte, int, error) {
	blob, err := tlsDecodePayload(raw)
	if err != nil {
		return nil, -1, err
	}
	if len(blob) < tlsBlobOverhead+tlsMinCipher {
		return nil, -1, fmt.Errorf("payload too short: %d bytes, want at least %d",
			len(blob), tlsBlobOverhead+tlsMinCipher)
	}

	half := (len(blob) - tlsBlobOverhead) / 2
	iv := slices.Concat(
		tlsReverse(blob[half+tlsBlobPrefix:half+tlsBlobPrefix+tlsIVPart]),
		tlsReverse(blob[len(blob)-102:len(blob)-84]),
	)
	ciphertext := slices.Concat(
		tlsReverse(blob[tlsBlobPrefix:half+tlsBlobPrefix]),
		tlsReverse(blob[half+tlsIVPart+tlsBlobPrefix:len(blob)-102]),
	)

	for index, key := range tlsConfigKeys() {
		gcm, err := tlsNewGCM(key)
		if err != nil {
			return nil, -1, err
		}
		plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
		if err == nil {
			return plaintext, index, nil
		}
	}
	return nil, -1, fmt.Errorf("no TLS Tunnel key authenticated this config")
}

func EncryptTLSConfig(plaintext []byte, keyIndex int) ([]byte, error) {
	keys := tlsConfigKeys()
	if keyIndex < 0 || keyIndex >= len(keys) {
		return nil, fmt.Errorf("key index %d out of range", keyIndex)
	}
	gcm, err := tlsNewGCM(keys[keyIndex])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, tlsIVSize)
	prefix := make([]byte, tlsBlobPrefix)
	suffix := make([]byte, tlsBlobSuffix)
	for _, buf := range [][]byte{iv, prefix, suffix} {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("random: %v", err)
		}
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	half := len(ciphertext) / 2
	blob := bytes.Join([][]byte{
		prefix,
		tlsReverse(ciphertext[:half]),
		tlsReverse(iv[:tlsIVPart]),
		tlsReverse(ciphertext[half:]),
		tlsReverse(iv[tlsIVPart:]),
		suffix,
	}, nil)

	text := strings.ReplaceAll(base64.StdEncoding.EncodeToString(blob), "=", "")
	return append(tlsReverse([]byte(text)), TLSConfigTrailer...), nil
}

func (c *TLSConfig) Value(name string) string {
	if c == nil {
		return ""
	}
	return c.values[name]
}

func (c *TLSConfig) Bool(name string) bool {
	return strings.EqualFold(strings.TrimSpace(c.Value(name)), "true")
}

func ParseTLSConfig(plaintext []byte) (*TLSConfig, error) {
	text := strings.TrimRight(strings.TrimPrefix(string(plaintext), "\ufeff"), "\x00")
	fields := strings.Split(text, ":")
	if len(fields) < len(tlsConfigFields) {
		return nil, fmt.Errorf("expected at least %d fields, got %d", len(tlsConfigFields), len(fields))
	}

	cfg := &TLSConfig{
		Fields: fields,
		values: make(map[string]string, len(tlsConfigFields)),
	}
	for i, spec := range tlsConfigFields {
		cfg.values[spec.name] = tlsDecodeField(spec, fields[i])
	}
	if tag, err := strconv.Atoi(strings.TrimSpace(fields[0])); err == nil {
		cfg.Tag = tag
	}
	return cfg, nil
}

func tlsDecodeField(spec tlsFieldSpec, stored string) string {
	stored = strings.TrimSpace(stored)
	if stored == "" || spec.kind != tlsFieldText {
		return stored
	}
	decoded, err := base64.RawStdEncoding.DecodeString(stored)
	if err != nil {
		return stored
	}
	return string(decoded)
}

func (c *TLSConfig) Format(keyIndex int) string {
	rows := c.rows()

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n[+] TLS Tunnel profile (tag %d, key #%d of %d)\n",
		c.Tag, keyIndex, len(tlsConfigKeyLiterals))
	fmt.Fprintf(&sb, "%-*s | %s\n%s\n", tlsLabelWidth, "FIELD", "VALUE", strings.Repeat("-", 80))
	for _, row := range rows {
		fmt.Fprintf(&sb, "%-*s | %s\n", tlsLabelWidth, row.label, tlsValueLines(row.value))
	}
	return sb.String()
}

type tlsRow struct {
	label string
	value string
}

func (c *TLSConfig) rows() []tlsRow {
	documented := c.Tag == tlsTagV4 || c.Tag == tlsTagV5

	rows := make([]tlsRow, 0, len(tlsConfigFields))
	if documented {
		rows = append(rows, tlsRow{"Connection", tlsConnectionMode(c)})
	}

	for i, stored := range c.Fields[:len(tlsConfigFields)] {
		spec := tlsConfigFields[i]
		label, value := fmt.Sprintf("Field %d", i), strings.TrimSpace(stored)
		if documented {
			if spec.name == "sshServer" {
				continue
			}
			label = spec.label
			value = tlsRenderValue(spec, stored)
		}
		if value == "" || value == "❌ FALSE" {
			continue
		}
		rows = append(rows, tlsRow{label, value})
	}
	return rows
}

func tlsRenderValue(spec tlsFieldSpec, stored string) string {
	value := tlsDecodeField(spec, stored)
	switch spec.kind {
	case tlsFieldBool:
		switch {
		case strings.EqualFold(value, "true"):
			return "✅ TRUE"
		case strings.EqualFold(value, "false"):
			return "❌ FALSE"
		default:
			return value
		}
	case tlsFieldPort:
		return tlsPortSelection(value)
	default:
		return value
	}
}

func tlsPortSelection(stored string) string {
	index, err := strconv.Atoi(stored)
	if err != nil || index < 0 || index >= len(tlsPortSelections) {
		return stored
	}
	return fmt.Sprintf("%s (%d)", tlsPortSelections[index], index)
}

func tlsConnectionMode(cfg *TLSConfig) string {
	if cfg.Bool("sshServer") {
		return "Private Server (SSH)"
	}
	return "Official servers"
}

func tlsValueLines(value string) string {
	lines := strings.Split(value, "\n")
	indent := strings.Repeat(" ", tlsLabelWidth+3)
	for i := 1; i < len(lines); i++ {
		lines[i] = indent + strings.TrimSpace(lines[i])
	}
	return strings.Join(lines, "\n")
}
