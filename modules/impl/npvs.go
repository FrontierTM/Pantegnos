package impl

import (
	"Pantegnos/modules"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

type PassphraseConfig struct {
	Iters int    `json:"iters"`
	Kdf   string `json:"kdf"`
	Salt  string `json:"salt"`
	Wrap  string `json:"wrap"`
}

type NPVSConfig struct {
	ConfigID   string           `json:"configId"`
	Passphrase PassphraseConfig `json:"passphrase"`
	V          int              `json:"v"`
}

func init() {
	modules.Register(modules.Module{
		Name:      "Npv Tunnel V2ray/SSH (.npvs)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv",
		Proto:     []string{"NPVS"},
		Extension: ".npvs",
		Exec: func(proto, payload, extension, file, outputDir string) {
			fileBytes, err := os.ReadFile(file)
			if err != nil {
				fmt.Println("error loading file:", err)
				os.Exit(1)
			}

			outputFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(file), ".npvs")+".txt")

			pt, err := decryptNPVS(fileBytes)
			if err != nil {
				fmt.Println("  decrypt error:", err)
				return
			}

			re := regexp.MustCompile(`npvs1:([A-Za-z0-9+/=]+)`)
			processedContent := re.ReplaceAllStringFunc(string(pt), func(match string) string {
				sub := re.FindStringSubmatch(match)
				if len(sub) < 2 {
					return match
				}
				b64 := sub[1]
				if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
					return string(decoded)
				}
				if decoded, err := base64.URLEncoding.DecodeString(b64); err == nil {
					return string(decoded)
				}
				return match
			})

			if err := os.WriteFile(outputFile, []byte(processedContent), 0644); err != nil {
				fmt.Printf("Error writing to %s: %v\n", outputFile, err)
				return
			}

			fmt.Println(processedContent)
		},
	})
}

func promptForPassword() ([]byte, error) {
	if term.IsTerminal(int(syscall.Stdin)) {
		fmt.Print("Enter .npvs password: ")
		if pw, err := term.ReadPassword(int(syscall.Stdin)); err == nil {
			fmt.Println()
			password := strings.TrimSpace(string(pw))
			if password != "" {
				return []byte(password), nil
			}
		}
	}

	fmt.Print("Enter .npvs password (visible): ")
	var input string
	_, _ = fmt.Scanln(&input)
	password := strings.TrimSpace(input)
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}
	return []byte(password), nil
}

func base64URLDecode(input string) ([]byte, error) {
	switch len(input) % 4 {
	case 2:
		input += "=="
	case 3:
		input += "="
	}
	return base64.URLEncoding.DecodeString(input)
}

func customPBKDF2HmacSha256(passphraseBytes, salt []byte, iterations, dkLen int) []byte {
	blocks := (dkLen + 31) / 32
	out := make([]byte, dkLen)
	counter := make([]byte, 4)

	for i, written := 1, 0; i <= blocks; i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))

		mac := hmac.New(sha256.New, passphraseBytes)
		mac.Write(salt)
		mac.Write(counter)
		digest := mac.Sum(nil)

		blockXor := make([]byte, len(digest))
		copy(blockXor, digest)

		for j := 2; j <= iterations; j++ {
			mac.Reset()
			mac.Write(digest)
			digest = mac.Sum(nil)
			for idx := range blockXor {
				blockXor[idx] ^= digest[idx]
			}
		}

		n := 32
		if dkLen-written < n {
			n = dkLen - written
		}
		copy(out[written:written+n], blockXor[:n])
		written += n
	}

	return out
}

func unwrapDEK(wrapKey, wrapBytes, saltBytes []byte) ([]byte, error) {
	if len(wrapBytes) < 12 {
		return nil, fmt.Errorf("wrap bytes too short")
	}
	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, wrapBytes[:12], wrapBytes[12:], saltBytes)
}

func decryptNPVS(fileBytes []byte) ([]byte, error) {
	if len(fileBytes) < 89 || fileBytes[4] != 1 {
		return nil, fmt.Errorf("invalid file format or unsupported version")
	}

	headerLen := int(binary.BigEndian.Uint32(fileBytes[5:9]))
	headerEnd := 9 + headerLen

	bArrR := fileBytes[9:headerEnd]
	var config NPVSConfig
	if err := json.Unmarshal(bArrR, &config); err != nil {
		return nil, err
	}

	if len(fileBytes) < headerEnd+16 {
		return nil, fmt.Errorf("file too short for payload envelope")
	}

	nonce := fileBytes[headerEnd : headerEnd+12]
	bodyLen := int(binary.BigEndian.Uint32(fileBytes[headerEnd+12 : headerEnd+16]))
	cipherEnd := headerEnd + 16 + bodyLen

	if len(fileBytes) < cipherEnd {
		return nil, fmt.Errorf("malformed file: payload exceeds file size")
	}
	ciphertext := fileBytes[headerEnd+16 : cipherEnd]

	salt, err := base64URLDecode(config.Passphrase.Salt)
	if err != nil {
		return nil, err
	}
	wrapBytes, err := base64URLDecode(config.Passphrase.Wrap)
	if err != nil {
		return nil, err
	}

	pw, err := promptForPassword()
	if err != nil {
		return nil, err
	}

	derived := customPBKDF2HmacSha256(pw, salt, config.Passphrase.Iters, 32)
	dek, err := unwrapDEK(derived, wrapBytes, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK. Check if the passphrase is correct")
	}

	aead, err := chacha20poly1305.New(dek)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, bArrR)
}
