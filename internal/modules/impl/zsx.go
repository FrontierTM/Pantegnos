package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"Pantegnos/internal/modules"

	"golang.org/x/crypto/argon2"
)

const (
	zsxMagic            = "ZSX1"
	zsxVersionLegacy    = 1
	zsxVersion          = 2
	zsxNonceSize        = 12
	zsxTagSize          = 16
	zsxCfgAAD           = "zsx-cfg-v1"
	zsxKeySize          = 32
	zsxArgonMemKiB      = 65536
	zsxArgonIterations  = 3
	zsxArgonParallelism = 1
)

var zsxOpenKey = func() [zsxKeySize]byte {
	return sha256.Sum256([]byte("ZedSecure .zsx v2"))
}()

type zsxKdf struct {
	Salt string `json:"salt"`
}

type zsxInner struct {
	Mode      int     `json:"mode"`
	NameEn    string  `json:"nameEn"`
	NameFa    string  `json:"nameFa"`
	Note      string  `json:"note"`
	CreatedAt int64   `json:"createdAt"`
	ExpiresAt *int64  `json:"expiresAt"`
	Kdf       *zsxKdf `json:"kdf"`
	CfgNonce  string  `json:"cfgNonce"`
	CfgCipher string  `json:"cfgCipher"`
}

type zedLinkPayload struct {
	Version int             `json:"v"`
	Name    string          `json:"n"`
	Source  json.RawMessage `json:"s"`
	Members []string        `json:"m"`
}

type zedLinkSource struct {
	Kind string `json:"kind"`
}

func init() {
	modules.Register(modules.Module{
		Name:      "ZedSecure vault / shared profile (.zsx, zedsecure://)",
		ApkAuthor: "https://github.com/CluvexStudio/ZedSecure",
		Proto:     []string{"zedsecure"},
		Extension: ".zsx",
		NeedsPassword: func(_, payload string) bool {
			inner, err := parseZsxOuter([]byte(payload))
			return err == nil && inner.Mode == 1
		},
		Decrypt: decryptZSX,
	})
}

func decryptZSX(req modules.Request) (modules.Result, error) {
	data := req.Data
	if len(data) == 0 {
		data = []byte(req.Payload)
	}
	if isZedLink(data) {
		text, err := formatZedLink(data)
		if err != nil {
			return modules.Result{}, fmt.Errorf("zsx: %w", err)
		}
		return modules.Result{
			Text:     text,
			FileName: zsxLinkOutputName(req.FileName),
			Echo:     true,
		}, nil
	}

	inner, err := parseZsxOuter(data)
	if err != nil {
		return modules.Result{}, fmt.Errorf("zsx: %w", err)
	}
	payload, err := openZsxPayload(inner, req.Password)
	if err != nil {
		return modules.Result{}, fmt.Errorf("zsx: %w", err)
	}

	return modules.Result{
		Text:     formatZsxVault(inner, payload),
		FileName: modules.OutputName(req.FileName, ".zsx"),
		Echo:     true,
	}, nil
}

func zsxLinkOutputName(fileName string) string {
	if strings.EqualFold(filepath.Ext(fileName), ".txt") {
		fileName = modules.Stem(fileName, ".txt")
	}
	return modules.OutputName(fileName, ".zsx")
}

func isZedLink(data []byte) bool {
	_, ok := zedLinkBody(string(data))
	return ok
}

func parseZsxOuter(data []byte) (*zsxInner, error) {
	if len(data) < len(zsxMagic)+1+zsxNonceSize+zsxTagSize {
		return nil, fmt.Errorf("file is too short to be a .zsx vault")
	}
	if string(data[:len(zsxMagic)]) != zsxMagic {
		return nil, fmt.Errorf("bad magic")
	}
	switch data[len(zsxMagic)] {
	case zsxVersion:
	case zsxVersionLegacy:
		return nil, fmt.Errorf("this vault was made by an older ZedSecure version (ZSX1 v1 is not supported)")
	default:
		return nil, fmt.Errorf("unsupported .zsx version %d", data[len(zsxMagic)])
	}

	header := len(zsxMagic) + 1
	nonce := data[header : header+zsxNonceSize]
	plain, err := zsxAESGCMOpen(zsxOpenKey[:], nonce, data[:header], data[header+zsxNonceSize:])
	if err != nil {
		return nil, fmt.Errorf("outer layer failed to authenticate: %w", err)
	}

	var inner zsxInner
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, fmt.Errorf("metadata parse: %w", err)
	}
	if inner.Mode != 0 && inner.Mode != 1 {
		return nil, fmt.Errorf("unsupported unlock mode %d", inner.Mode)
	}
	return &inner, nil
}

func openZsxPayload(inner *zsxInner, password string) (string, error) {
	key := zsxOpenKey[:]
	if inner.Mode == 1 {
		if password == "" {
			return "", fmt.Errorf("this vault is password protected")
		}
		derived, err := zsxArgon2Key(inner, password)
		if err != nil {
			return "", err
		}
		key = derived
	}

	nonce, err := zsxBase64(inner.CfgNonce)
	if err != nil {
		return "", fmt.Errorf("config nonce: %w", err)
	}
	if len(nonce) != zsxNonceSize {
		return "", fmt.Errorf("config nonce is %d bytes, want %d", len(nonce), zsxNonceSize)
	}
	cipherText, err := zsxBase64(inner.CfgCipher)
	if err != nil {
		return "", fmt.Errorf("config cipher: %w", err)
	}
	plain, err := zsxAESGCMOpen(key, nonce, []byte(zsxCfgAAD), cipherText)
	if err != nil {
		if inner.Mode == 1 {
			return "", fmt.Errorf("incorrect password: %w", err)
		}
		return "", fmt.Errorf("config failed to authenticate: %w", err)
	}
	return string(plain), nil
}

func zsxArgon2Key(inner *zsxInner, password string) ([]byte, error) {
	if inner.Kdf == nil {
		return nil, fmt.Errorf("password vault has no KDF parameters")
	}
	salt, err := zsxBase64(inner.Kdf.Salt)
	if err != nil {
		return nil, fmt.Errorf("kdf salt: %w", err)
	}
	if len(salt) < 8 {
		return nil, fmt.Errorf("kdf salt is only %d bytes", len(salt))
	}

	return argon2.IDKey(
		[]byte(password),
		salt,
		zsxArgonIterations,
		zsxArgonMemKiB,
		zsxArgonParallelism,
		zsxKeySize,
	), nil
}

func zsxAESGCMOpen(key, nonce, aad, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, cipherText, aad)
}

func zsxBase64(value string) ([]byte, error) {
	clean := strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "="))
}

func formatZsxVault(inner *zsxInner, payload string) string {
	var sb strings.Builder
	sb.WriteString("// ---- ZedSecure vault profile ----\n")
	if inner.NameEn != "" {
		zsxComment(&sb, "name", inner.NameEn)
	}
	if inner.NameFa != "" && inner.NameFa != inner.NameEn {
		zsxComment(&sb, "name (fa)", inner.NameFa)
	}
	if inner.Note != "" {
		zsxComment(&sb, "note", inner.Note)
	}
	if inner.CreatedAt > 0 {
		zsxComment(&sb, "created", time.UnixMilli(inner.CreatedAt).UTC().Format(time.RFC3339))
	}
	if inner.ExpiresAt != nil && *inner.ExpiresAt > 0 {
		expires := time.UnixMilli(*inner.ExpiresAt).UTC().Format(time.RFC3339)
		if time.Until(time.UnixMilli(*inner.ExpiresAt)) < 0 {
			expires += " (expired)"
		}
		zsxComment(&sb, "expires", expires)
	} else {
		zsxComment(&sb, "expires", "not set")
	}
	if inner.Mode == 1 {
		zsxComment(&sb, "password", "required")
	} else {
		zsxComment(&sb, "password", "not set")
	}

	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		zsxComment(&sb, "payload", "empty")
		return sb.String()
	}
	switch {
	case isZedLink([]byte(trimmed)):
		kind := zedLinkKind(trimmed)
		label := "ZedSecure link"
		if kind != "" {
			label += " (" + kind + ")"
		}
		zsxComment(&sb, "payload", label)
		sb.WriteString("\n")
		rendered, err := formatZedLink([]byte(trimmed))
		if err != nil {
			sb.WriteString(trimmed)
			sb.WriteString("\n")
		} else {
			sb.WriteString(strings.TrimPrefix(rendered, "// ---- ZedSecure shared profile ----\n"))
		}
	case json.Valid([]byte(trimmed)):
		zsxComment(&sb, "payload", "JSON config")
		sb.WriteString("\n")
		var out bytes.Buffer
		if err := json.Indent(&out, []byte(trimmed), "", "  "); err == nil {
			sb.WriteString(out.String())
		} else {
			sb.WriteString(trimmed)
		}
		sb.WriteString("\n")
	default:
		zsxComment(&sb, "payload", "share link")
		sb.WriteString("\n")
		sb.WriteString(trimmed)
		sb.WriteString("\n")
	}
	return sb.String()
}

func zsxComment(sb *strings.Builder, key, value string) {
	first := true
	for line := range strings.SplitSeq(strings.TrimRight(value, "\r\n"), "\n") {
		if first {
			fmt.Fprintf(sb, "// %s: %s\n", key, line)
			first = false
		} else {
			fmt.Fprintf(sb, "// %s   %s\n", strings.Repeat(" ", len(key)), line)
		}
	}
}

func zedLinkBody(text string) (string, bool) {
	trimmed := strings.TrimSpace(text)
	const scheme = "zedsecure://"
	if len(trimmed) < len(scheme) || !strings.EqualFold(trimmed[:len(scheme)], scheme) {
		return "", false
	}
	body, _, _ := strings.Cut(trimmed[len(scheme):], "#")
	return strings.TrimSpace(body), true
}

func formatZedLink(data []byte) (string, error) {
	body, ok := zedLinkBody(string(data))
	if !ok {
		return "", fmt.Errorf("not a zedsecure:// link")
	}
	raw, err := b64DecodeUrlSafe(body)
	if err != nil {
		return "", fmt.Errorf("link base64: %w", err)
	}

	var payload zedLinkPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("link JSON: %w", err)
	}
	var source zedLinkSource
	if len(payload.Source) > 0 {
		_ = json.Unmarshal(payload.Source, &source)
	}

	var sb strings.Builder
	sb.WriteString("// ---- ZedSecure shared profile ----\n")
	zsxComment(&sb, "version", strconv.Itoa(payload.Version))
	zsxComment(&sb, "name", payload.Name)
	kind := source.Kind
	if kind == "" {
		kind = "unknown"
	}
	zsxComment(&sb, "source", kind)
	if len(payload.Members) > 0 {
		zsxComment(&sb, "members", strconv.Itoa(len(payload.Members)))
	}
	sb.WriteString("\n")

	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return "", fmt.Errorf("link JSON: %w", err)
	}
	sb.Write(out.Bytes())
	sb.WriteString("\n")
	return sb.String(), nil
}

func zedLinkKind(data string) string {
	body, ok := zedLinkBody(data)
	if !ok {
		return ""
	}
	raw, err := b64DecodeUrlSafe(body)
	if err != nil {
		return ""
	}
	var payload zedLinkPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return ""
	}
	var source zedLinkSource
	if err := json.Unmarshal(payload.Source, &source); err != nil {
		return ""
	}
	return source.Kind
}
