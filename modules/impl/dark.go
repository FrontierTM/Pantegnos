package impl

import (
	"Pantegnos/modules"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vmihailenco/msgpack/v5"
)

var DTConstants = struct {
	KEY_256 []byte
	KEY_192 []byte
	IV      []byte
}{
	KEY_256: []byte("$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"),
	KEY_192: []byte("F)J@NcRfUjXn2r4u7x!A%D*G"),
	IV:      mustHexDecode("232e39185523184a5723586242200e05"),
}

func init() {
	modules.Register(modules.Module{
		Name:      "DarkTunnel - SSH DNSTT V2Ray",
		ApkAuthor: "https://play.google.com/store/apps/details?id=net.darktunnel.app",
		Proto:     []string{"darktunnel"},
		Extension: ".dark",
		Exec: func(proto, payload, extension, file, outputDir string) {

			decryptedDump, err := DecryptDark(payload)
			if err != nil {
				fmt.Printf("[!] Decryption failed for %s: %v\n", file, err)
				return
			}

			outputFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(file), ".dark")+".txt")
			if err := os.WriteFile(outputFile, []byte(decryptedDump), 0644); err != nil {
				fmt.Printf("[!] Error writing final dump to %s: %v\n", outputFile, err)
				return
			}

			fmt.Printf("[+] Successfully decrypted and saved to: %s\n", outputFile)
		},
	})
}

func DecryptDark(payload string) (string, error) {
	outerBytes, err := base64DecodeSafe(payload)
	if err != nil {
		return "", err
	}

	var outer map[string]interface{}
	if err := json.Unmarshal(outerBytes, &outer); err != nil {
		return "", err
	}

	encLockedConfigStr, ok := outer["encryptedLockedConfig"].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid encryptedLockedConfig key")
	}

	encryptedLockedConfig, err := base64DecodeSafe(encLockedConfigStr)
	if err != nil {
		return "", err
	}

	decryptedOuter, err := aesCFBDecrypt(encryptedLockedConfig, DTConstants.KEY_256, DTConstants.IV)
	if err != nil {
		return "", err
	}

	var unpackedOuter map[string]interface{}
	if err := msgpack.Unmarshal(decryptedOuter, &unpackedOuter); err != nil {
		return "", err
	}

	if encInnerVal, found := unpackedOuter["EncryptedLockedConfig"]; found {
		if encInnerBytes, ok := encInnerVal.([]byte); ok {
			decryptedInner, err := aesCFBDecrypt(encInnerBytes, DTConstants.KEY_192, DTConstants.IV)
			if err == nil {
				var unpackedInner interface{}
				if err := msgpack.Unmarshal(decryptedInner, &unpackedInner); err == nil {
					unpackedOuter["EncryptedLockedConfig"] = cleanEncrypted(unpackedInner, DTConstants.KEY_192, DTConstants.IV)
				}
			}
		}
	}

	outer["encryptedLockedConfig"] = unpackedOuter
	normalized := normalizeForJSON(outer)

	jsonOut, err := json.MarshalIndent(normalized, "", "    ")
	if err != nil {
		return "", err
	}

	return string(jsonOut), nil
}

func cleanEncrypted(value interface{}, key, iv []byte) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		cleaned := make(map[string]interface{})
		for k, val := range v {
			if strings.HasPrefix(k, "Encrypted") {
				if byteData, ok := val.([]byte); ok && len(byteData) > 0 {
					if dec, err := aesCFBDecrypt(byteData, key, iv); err == nil {
						cleaned[k] = dec
						continue
					}
				}
			}
			cleaned[k] = cleanEncrypted(val, key, iv)
		}
		return cleaned

	case []interface{}:
		cleaned := make([]interface{}, len(v))
		for i, val := range v {
			cleaned[i] = cleanEncrypted(val, key, iv)
		}
		return cleaned
	}

	return value
}

func mustHexDecode(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func base64DecodeSafe(data string) ([]byte, error) {
	cleanData := strings.ReplaceAll(data, "-", "+")
	cleanData = strings.ReplaceAll(cleanData, "_", "/")
	if pad := len(cleanData) % 4; pad != 0 {
		cleanData += strings.Repeat("=", 4-pad)
	}
	return base64.StdEncoding.DecodeString(cleanData)
}

func aesCFBDecrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(data))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decrypted, data)
	return decrypted, nil
}

func isUTF8Printable(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	re := regexp.MustCompile(`^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$`)
	return re.Match(value)
}

func tryParseJSONString(value string) interface{} {
	trimmed := strings.TrimSpace(value)
	if !((strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"))) {
		return value
	}

	re := regexp.MustCompile(`(:\s*)(\$[A-Za-z0-9_]+)`)
	fixedJSON := re.ReplaceAllString(trimmed, `${1}"${2}"`)

	var parsed interface{}
	if err := json.Unmarshal([]byte(fixedJSON), &parsed); err == nil {
		return normalizeForJSON(parsed)
	}
	return value
}

func normalizeForJSON(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		cleaned := make(map[string]interface{})
		for key, val := range v {
			if key != "Password" {
				cleaned[key] = normalizeForJSON(val)
			}
		}
		return cleaned

	case []interface{}:
		cleaned := make([]interface{}, len(v))
		for i, val := range v {
			cleaned[i] = normalizeForJSON(val)
		}
		return cleaned

	case []byte:
		if isUTF8Printable(v) {
			return tryParseJSONString(string(v))
		}
		ints := make([]int, len(v))
		for i, b := range v {
			ints[i] = int(b)
		}
		return ints

	case string:
		return tryParseJSONString(v)
	}

	return value
}
