package impl

import (
	"Pantegnos/modules"
	"Pantegnos/utils"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mazznoer/colorgrad"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
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
		Exec: func(proto, payload, extension, file, outputDir string) {

			if proto == "slipnet-bundle-enc" {
				fmt.Printf("[*] Processing SlipNet Password Bundle configuration: %s\n", file)

				//Take a look at this gay ahh setup lol xd
				fmt.Print(utils.ColorizeGradientText("Enter bundle password: ", colorgrad.Rainbow()))
				passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					fmt.Printf("[!] Failed to read password: %v\n", err)
					return
				}
				password := strings.TrimSpace(string(passwordBytes))

				if password == "" {
					fmt.Println("[!] Password cannot be empty")
					return
				}

				decrypted, err := decryptBundleBlob(payload, password)
				if err != nil {
					fmt.Printf("[!] Failed to decrypt bundle %s: %v\n", file, err)
					return
				}

				outputFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(file), ".slip")+"_bundle.txt")
				if err := os.WriteFile(outputFile, []byte(decrypted), 0644); err != nil {
					fmt.Printf("Error writing %s: %v\n", outputFile, err)
					return
				}
				fmt.Printf("[+] Successfully decrypted bundle and saved to: %s\n", outputFile)
				return
			}

			if proto == "slipnet" {
				data, err := base64.StdEncoding.DecodeString(payload)
				if err != nil {
					log.Println("Error decoding base64 payload:", err)
				}
				formattedProfile := parseProfile(string(data))
				fmt.Println(formattedProfile)
				return
			}

			fmt.Printf("[*] Processing SlipNet configuration: %s\n", file)
			decrypted, err := decryptBlob(KEY_HEX, payload)
			if err != nil {
				fmt.Printf("[!] Failed to decrypt %s: %v\n", file, err)
				return
			}

			formattedProfile := parseProfile(decrypted)
			outputFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(file), ".slip")+".txt")
			if err := os.WriteFile(outputFile, []byte(formattedProfile), 0644); err != nil {
				fmt.Printf("Error writing %s: %v\n", outputFile, err)
				return
			}
			fmt.Printf("[+] Successfully decrypted and saved to: %s\n", outputFile)
		},
	})
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
	sb.WriteString(fmt.Sprintf("\n[+] Detected Profile Version: %s\n", verStr))
	sb.WriteString(fmt.Sprintf("%-30s | %s\n", "FIELD", "VALUE"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for i, value := range parts {
		label := ""
		if exists && i < len(schema) {
			label = schema[i]
		} else {
			label = fmt.Sprintf("Field %d", i)
		}

		displayValue := value
		if displayValue == "" {
			displayValue = "(empty)"
		}

		switch label {
		case "Is Locked", "SSH TLS Enabled", "SSH WS Enabled", "SSH WS Use TLS",
			"SNI Fragment Enabled", "CH Padding Enabled", "WS Header Obfuscation", "WS Padding Enabled":
			if value == "1" {
				displayValue = "🔒 YES / ✅ TRUE"
			} else {
				displayValue = "🔓 NO / ❌ FALSE"
			}
		case "VayDNS DNSTT Compat", "Resolvers Hidden", "GSO", "DNSTT Authoritative",
			"SSH Enabled", "Forward DNS thru SSH", "Use Server DNS", "Allow Sharing", "NoizDNS Stealth":
			if value == "1" {
				displayValue = "✅ TRUE"
			} else {
				displayValue = "❌ FALSE"
			}
		}
		sb.WriteString(fmt.Sprintf("%-30s | %s\n", label, displayValue))
	}
	return sb.String()
}

func decryptBlob(keyHex, blobStr string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(blobStr)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %v", err)
	}
	if len(data) < 13 {
		return "", fmt.Errorf("blob too short")
	}

	key, _ := hex.DecodeString(keyHex)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
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
	cleanedBlob := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(blobStr)

	data, err := base64.StdEncoding.DecodeString(cleanedBlob)
	if err != nil {
		return "", fmt.Errorf("bundle base64 decode: %v", err)
	}

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
