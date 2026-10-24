package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"Pantegnos/internal/modules"
)

const (
	v2boxMagic       = "v2box_export"
	v2boxExtension   = ".v2box"
	v2boxStaticKey   = "V2BoxEncryptionKey2026_Secret!#%"
	v2boxNonceSize   = 12
	v2boxTagSize     = 16
	v2boxLinkScheme  = "v2box://"
	v2boxLockedLabel = "locked="
)

type v2boxExport struct {
	Version             int      `json:"version"`
	Magic               string   `json:"magic"`
	IsPasswordProtected bool     `json:"isPasswordProtected"`
	ExpirationTimestamp *float64 `json:"expirationTimestamp"`
	AllowedDeviceIDs    []string `json:"allowedDeviceIDs"`
	Ciphertext          string   `json:"ciphertext"`
	Nonce               string   `json:"nonce"`
	Tag                 string   `json:"tag"`
}

type v2boxPayload struct {
	Configs []json.RawMessage `json:"configs"`
	Raws    map[string]string `json:"raws"`
	A       []json.RawMessage `json:"a"`
	B       map[string]string `json:"b"`
}

type v2boxProfile struct {
	ConfigType          string   `json:"configType"`
	Remarks             string   `json:"remarks"`
	Server              string   `json:"server"`
	ServerPort          string   `json:"serverPort"`
	Network             string   `json:"network"`
	Security            string   `json:"security"`
	DeviceID            string   `json:"deviceID"`
	IsLocked            bool     `json:"isLocked"`
	ExpirationTimestamp *float64 `json:"expirationTimestamp"`
}

func init() {
	modules.Register(modules.Module{
		Name:      "V2Box export / locked profile (.v2box, v2box://)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box",
		Proto:     []string{"v2box"},
		Extension: v2boxExtension,
		NeedsPassword: func(_, payload string) bool {
			exp, err := parseV2BoxExport([]byte(payload))
			return err == nil && exp.IsPasswordProtected
		},
		Decrypt: decryptV2Box,
	})
}

func decryptV2Box(req modules.Request) (modules.Result, error) {
	data := req.Data
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte(req.Payload)
	}

	plain, isLink, err := decodeV2BoxLockedLink(data)
	if err != nil {
		return modules.Result{}, err
	}
	if isLink {
		return modules.Result{
			Text:     formatV2BoxLockedLink(plain),
			FileName: v2boxOutputName(req.FileName),
			Echo:     true,
		}, nil
	}

	exp, err := parseV2BoxExport(data)
	if err != nil {
		return modules.Result{}, err
	}
	payload, err := openV2BoxExport(exp, req.Password)
	if err != nil {
		return modules.Result{}, err
	}

	return modules.Result{
		Text:     formatV2BoxExport(exp, payload),
		FileName: v2boxOutputName(req.FileName),
		Echo:     true,
	}, nil
}

func parseV2BoxExport(data []byte) (*v2boxExport, error) {
	var exp v2boxExport
	if err := json.Unmarshal(data, &exp); err != nil {
		return nil, fmt.Errorf("v2box: not a .v2box export: %w", err)
	}
	if exp.Magic != v2boxMagic {
		return nil, fmt.Errorf("v2box: bad magic %q, want %q", exp.Magic, v2boxMagic)
	}
	if exp.Ciphertext == "" || exp.Nonce == "" || exp.Tag == "" {
		return nil, fmt.Errorf("v2box: export is missing ciphertext, nonce or tag")
	}
	return &exp, nil
}

func openV2BoxExport(exp *v2boxExport, password string) ([]byte, error) {
	key := []byte(v2boxStaticKey)
	if exp.IsPasswordProtected {
		if password == "" {
			return nil, fmt.Errorf("v2box: this export is password protected")
		}
		digest := sha256.Sum256([]byte(password))
		key = digest[:]
	}

	nonce, err := v2boxBase64(exp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("v2box: nonce: %w", err)
	}
	tag, err := v2boxBase64(exp.Tag)
	if err != nil {
		return nil, fmt.Errorf("v2box: tag: %w", err)
	}
	ciphertext, err := v2boxBase64(exp.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("v2box: ciphertext: %w", err)
	}
	if len(nonce) != v2boxNonceSize {
		return nil, fmt.Errorf("v2box: nonce is %d bytes, want %d", len(nonce), v2boxNonceSize)
	}
	if len(tag) != v2boxTagSize {
		return nil, fmt.Errorf("v2box: tag is %d bytes, want %d", len(tag), v2boxTagSize)
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("v2box: ciphertext is empty")
	}

	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("v2box: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("v2box: %w", err)
	}
	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		if exp.IsPasswordProtected {
			return nil, fmt.Errorf("v2box: incorrect password or corrupted export")
		}
		return nil, fmt.Errorf("v2box: decryption failed (corrupted export)")
	}
	return plain, nil
}

func decodeV2BoxLockedLink(data []byte) (string, bool, error) {
	text := strings.TrimSpace(string(data))
	if !strings.HasPrefix(strings.ToLower(text), v2boxLinkScheme) {
		return "", false, nil
	}
	body := text[len(v2boxLinkScheme):]
	if !strings.HasPrefix(body, v2boxLockedLabel) {
		return "", true, fmt.Errorf("v2box: %s is an install link, not a profile export; download the file it points to and open it", text)
	}
	body = strings.TrimSpace(body[len(v2boxLockedLabel):])
	plain, err := v2boxBase64(body)
	if err != nil {
		return "", true, fmt.Errorf("v2box: locked link: %w", err)
	}
	return string(plain), true, nil
}

func formatV2BoxExport(exp *v2boxExport, payload []byte) string {
	var sb strings.Builder
	sb.WriteString("// ---- V2Box export ----\n")
	fmt.Fprintf(&sb, "// version: %d\n", exp.Version)
	if exp.IsPasswordProtected {
		sb.WriteString("// password: required\n")
	} else {
		sb.WriteString("// password: not set (fixed app key)\n")
	}
	if exp.ExpirationTimestamp != nil {
		sb.WriteString("// expires: " + v2boxTime(*exp.ExpirationTimestamp) + "\n")
	} else {
		sb.WriteString("// expires: not set\n")
	}
	if len(exp.AllowedDeviceIDs) > 0 {
		sb.WriteString("// device lock: " + strings.Join(exp.AllowedDeviceIDs, ", ") + "\n")
	} else {
		sb.WriteString("// device lock: not set\n")
	}

	var packageData v2boxPayload
	if err := json.Unmarshal(payload, &packageData); err != nil {
		sb.WriteString("// payload: not JSON\n\n")
		sb.Write(payload)
		if !strings.HasSuffix(sb.String(), "\n") {
			sb.WriteString("\n")
		}
		return sb.String()
	}

	configs := packageData.Configs
	if len(configs) == 0 {
		configs = packageData.A
	}
	raws := packageData.Raws
	if len(raws) == 0 {
		raws = packageData.B
	}
	fmt.Fprintf(&sb, "// configs: %d\n", len(configs))
	fmt.Fprintf(&sb, "// raw configs: %d\n", len(raws))

	importLocked := exp.IsPasswordProtected || exp.ExpirationTimestamp != nil || len(exp.AllowedDeviceIDs) > 0
	for i, raw := range configs {
		var profile v2boxProfile
		if err := json.Unmarshal(raw, &profile); err != nil {
			continue
		}
		fmt.Fprintf(&sb, "// config %d: %s\n", i+1, v2boxProfileSummary(profile, importLocked))
	}

	sb.WriteString("\n")
	var out bytes.Buffer
	if err := json.Indent(&out, payload, "", "  "); err != nil {
		sb.Write(payload)
	} else {
		sb.Write(out.Bytes())
	}
	if !strings.HasSuffix(sb.String(), "\n") {
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatV2BoxLockedLink(plain string) string {
	var lines []string
	for line := range strings.SplitSeq(strings.ReplaceAll(plain, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}

	var sb strings.Builder
	sb.WriteString("// ---- V2Box locked profile link ----\n")
	sb.WriteString("// cipher: none (base64 only)\n")
	fmt.Fprintf(&sb, "// profiles: %d\n", len(lines))
	sb.WriteString("// note: V2Box imports these only when this device matches a profile's deviceID\n")
	sb.WriteString("\n")
	if len(lines) == 0 {
		sb.WriteString("// (the link carries no profiles)\n")
		return sb.String()
	}
	sb.WriteString(strings.Join(lines, "\n"))
	sb.WriteString("\n")
	return sb.String()
}

func v2boxProfileSummary(p v2boxProfile, importLocked bool) string {
	var parts []string
	kind := p.ConfigType
	if kind == "" {
		kind = "unknown"
	}
	parts = append(parts, kind)
	if p.Remarks != "" {
		parts = append(parts, fmt.Sprintf("%q", v2boxOneLine(p.Remarks)))
	}
	if p.Server != "" {
		target := p.Server
		if p.ServerPort != "" {
			target += ":" + p.ServerPort
		}
		parts = append(parts, "at "+target)
	}
	if transport := strings.Trim(p.Network+"/"+p.Security, "/"); transport != "" {
		parts = append(parts, "("+transport+")")
	}
	if p.IsLocked {
		parts = append(parts, "[locked]")
	} else if importLocked {
		parts = append(parts, "[locked on import]")
	}
	if p.DeviceID != "" {
		parts = append(parts, "device "+p.DeviceID)
	}
	if p.ExpirationTimestamp != nil {
		parts = append(parts, "expires "+v2boxTime(*p.ExpirationTimestamp))
	}
	return strings.Join(parts, " ")
}

func v2boxOneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	runes := []rune(s)
	if len(runes) > 80 {
		return string(runes[:77]) + "..."
	}
	return s
}

func v2boxTime(seconds float64) string {
	millis := int64(math.Round(seconds * 1000))
	when := time.UnixMilli(millis).UTC()
	out := when.Format(time.RFC3339)
	if time.Now().After(when) {
		out += " (expired)"
	}
	return out
}

func v2boxBase64(value string) ([]byte, error) {
	clean := strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "=")); err == nil {
		return decoded, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(clean, "="))
}

func v2boxOutputName(fileName string) string {
	if strings.EqualFold(filepath.Ext(fileName), ".txt") {
		return fileName
	}
	return modules.OutputName(fileName, v2boxExtension)
}
