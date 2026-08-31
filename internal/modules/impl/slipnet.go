package impl

import (
	"Pantegnos/internal/modules"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	KEY_HEX           = "214F052025B2F949605A5429EC3D5FA80C2022C168AD946E68852D447214DBD3"
	FORMAT_VERSION    = 0x01
	SALT_LENGTH       = 16
	IV_LENGTH         = 12
	PBKDF2_ITERATIONS = 600000
	KEY_SIZE_BYTES    = 32 // 256 bits
)

var (
	v1  = []string{"Version", "Tunnel Type/Mode", "Name", "Domain", "Resolvers", "AuthMode", "KeepAlive", "CC", "Port", "Host", "GSO"}
	v20 = append(v1,
		"DNSTT Public Key", "SOCKS Username", "SOCKS Password", "SSH Enabled", "SSH Username",
		"SSH Password", "SSH Port", "Forward DNS thru SSH", "SSH Host", "Use Server DNS",
		"DoH URL", "DNS Transport", "SSH Auth Type", "SSH Private Key (B64)", "SSH Key Passphrase (B64)",
		"Tor Bridge Lines (B64)", "DNSTT Authoritative", "Naive Port", "Naive Username", "Naive Password (B64)",
		"Is Locked", "Lock Password Hash", "Expiration Date", "Allow Sharing", "Bound Device ID",
		"Resolvers Hidden", "Hidden Resolvers", "NoizDNS Stealth", "DNS Payload Size", "SOCKS5 Server Port",
		"VayDNS DNSTT Compat", "VayDNS Record Type", "VayDNS Max Qname Len", "VayDNS RPS", "VayDNS Idle Timeout",
		"VayDNS Keepalive", "VayDNS UDP Timeout", "VayDNS Max Num Labels", "VayDNS Client Id Size",
	)
	v21 = append(v20,
		"SSH TLS Enabled", "SSH TLS SNI", "SSH HTTP Proxy Host", "SSH HTTP Proxy Port", "SSH HTTP Proxy Custom Host",
		"SSH WS Enabled", "SSH WS Path", "SSH WS Use TLS", "SSH WS Custom Host",
	)
	v22 = append(v21, "SSH Payload (B64)")
	v24 = append(v22, "Resolver Mode", "RR Spread Count")
	v25 = append(v24,
		"VLESS UUID", "VLESS Security", "VLESS Transport", "VLESS WS Path", "CDN IP",
		"CDN Port", "SNI Fragment Enabled", "SNI Fragment Strategy", "SNI Fragment Delay MS", "Legacy SNI (Empty)",
	)
	v27 = append(v25,
		"CH Padding Enabled", "WS Header Obfuscation", "WS Padding Enabled",
		"SNI Spoof TTL", "Fake Decoy Host", "TCP Max Seg",
	)
	v28     = append(v27, "VLESS SNI")
	SCHEMAS = map[string][]string{
		"1": v1, "20": v20, "21": v21, "22": v22, "23": v24, "24": v24,
		"25": v25, "26": v27, "27": v27, "28": v28,
	}
)

func init() {
	modules.Register(modules.Module{
		Name:      "SlipNet Android VPN client (Updated v28)",
		ApkAuthor: "https://github.com/anonvector/SlipNet/releases/",
		Proto:     []string{"slipnet-enc", "slipnet", "slipnet-bundle-enc"},
		Extension: ".slip",
		NeedsPassword: func(proto, _ string) bool {
			return proto == "slipnet-bundle-enc"
		},
		Decrypt: decryptSlipNet,
	})
}

func decryptSlipNet(req modules.Request) (modules.Result, error) {
	switch req.Proto {
	case "slipnet-bundle-enc":
		decrypted, err := decryptBundleBlob(req.Payload, req.Password)
		if err != nil {
			return modules.Result{}, err
		}
		return modules.Result{
			Text:     decrypted,
			FileName: modules.Stem(req.FileName, ".slip") + "_bundle.txt",
		}, nil

	case "slipnet":
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Payload))
		if err != nil {
			return modules.Result{}, fmt.Errorf("base64 decode: %v", err)
		}
		return modules.Result{Text: parseProfile(string(data)), Echo: true}, nil

	default:
		decrypted, err := decryptBlob(slipnetGCM, strings.TrimSpace(req.Payload))
		if err != nil {
			return modules.Result{}, err
		}
		return modules.Result{
			Text:     parseProfile(decrypted),
			FileName: modules.OutputName(req.FileName, ".slip"),
		}, nil
	}
}

func parseProfile(decryptedText string) string {
	decryptedText = strings.TrimSuffix(decryptedText, "|")
	parts := strings.Split(decryptedText, "|")
	if len(parts) == 0 || parts[0] == "" {
		return "[!] Empty decrypted text"
	}

	verStr := parts[0]
	schema, exists := SCHEMAS[verStr]

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n[+] Detected Profile Version: %s\n%-30s | %s\n%s\n",
		verStr, "FIELD", "VALUE", strings.Repeat("-", 80))

	for i, value := range parts {
		label := ""
		if exists && i < len(schema) {
			label = schema[i]
		}
		if label == "" {
			label = fmt.Sprintf("Field %d", i)
		}

		displayValue := value
		if displayValue == "" {
			displayValue = "(empty)"
		}

		if _, hit := lockedLabels[label]; hit {
			if value == "1" {
				displayValue = "🔒 YES / ✅ TRUE"
			} else {
				displayValue = "🔓 NO / ❌ FALSE"
			}
		} else if value != "" && isTrueFalseLabel(label) {
			if value == "1" {
				displayValue = "✅ TRUE"
			} else {
				displayValue = "❌ FALSE"
			}
		}
		fmt.Fprintf(&sb, "%-30s | %s\n", label, displayValue)
	}
	return sb.String()
}

var lockedLabels = map[string]struct{}{
	"Is Locked": {}, "SSH TLS Enabled": {}, "SSH WS Enabled": {}, "SSH WS Use TLS": {},
	"SNI Fragment Enabled": {}, "CH Padding Enabled": {}, "WS Header Obfuscation": {}, "WS Padding Enabled": {},
}

var trueFalseLabels = map[string]struct{}{
	"VayDNS DNSTT Compat": {}, "Resolvers Hidden": {}, "GSO": {}, "DNSTT Authoritative": {},
	"SSH Enabled": {}, "Forward DNS thru SSH": {}, "Use Server DNS": {}, "Allow Sharing": {}, "NoizDNS Stealth": {},
}

func isTrueFalseLabel(label string) bool {
	_, ok := trueFalseLabels[label]
	return ok
}

var slipnetGCM = mustGCM(KEY_HEX)

func mustGCM(keyHex string) cipher.AEAD {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		panic("slipnet: bad key hex: " + err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("slipnet: cipher init: " + err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("slipnet: gcm init: " + err.Error())
	}
	return aesgcm
}

func decryptBlob(aesgcm cipher.AEAD, blobStr string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(blobStr)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %v", err)
	}
	if len(data) < 13 {
		return "", fmt.Errorf("blob too short")
	}

	nonce := data[1:13]
	ciphertext := data[13:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (check key/iv): %v", err)
	}
	return string(plaintext), nil
}

func decryptBundleBlob(blobStr string, password string) (string, error) {
	cleaned := make([]byte, 0, len(blobStr))
	for i := 0; i < len(blobStr); i++ {
		c := blobStr[i]
		if c != '\n' && c != '\r' && c != ' ' {
			cleaned = append(cleaned, c)
		}
	}

	data := make([]byte, base64.StdEncoding.DecodedLen(len(cleaned)))
	n, err := base64.StdEncoding.Decode(data, cleaned)
	if err != nil {
		return "", fmt.Errorf("bundle base64 decode: %v", err)
	}
	data = data[:n]

	// Version(1) + Salt(16) + IV(12) + Tag overhead (16)
	minRequiredLength := 1 + SALT_LENGTH + IV_LENGTH + 16
	if len(data) < minRequiredLength {
		return "", fmt.Errorf("encrypted bundle is truncated or invalid")
	}

	if data[0] != FORMAT_VERSION {
		return "", fmt.Errorf("unsupported encrypted bundle format version: 0x%02x", data[0])
	}

	saltStart := 1
	ivStart := saltStart + SALT_LENGTH
	ciphertextStart := ivStart + IV_LENGTH

	salt := data[saltStart:ivStart]
	iv := data[ivStart:ciphertextStart]
	ciphertextWithTag := data[ciphertextStart:]

	derivedKey := pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, KEY_SIZE_BYTES, sha256.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("cipher initialization block failure: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm block failure: %v", err)
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return "", fmt.Errorf("wrong password or corrupted bundle data payload")
	}

	return string(plaintext), nil
}
