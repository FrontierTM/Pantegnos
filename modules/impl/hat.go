package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"Pantegnos/modules"
)

const HatImportKey = "8515D40BD04D8C97"

func init() {
	modules.Register(modules.Module{
		Name:      "HA Tunnel Plus (HAT)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.hatunnel.plusl",
		Proto:     []string{""},
		Extension: ".hat",
		Exec: func(proto, payload, extension, file, outputDir string) {
			ciphertext, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				fmt.Printf("Base64 decode error for %s: %v\n", file, err)
				return
			}

			hasher := sha1.New()
			hasher.Write([]byte(HatImportKey))
			derivedKey := hasher.Sum(nil)[:16]

			plaintext, err := decryptAESECB(ciphertext, derivedKey)
			if err != nil {
				fmt.Printf("Decrypt error for %s: %v\n", file, err)
				return
			}

			unpaddedPlaintext, err := pkcs7Unpad(plaintext, aes.BlockSize)
			if err != nil {
				fmt.Printf("Unpadding error for %s: %v\n", file, err)
				return
			}

			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, unpaddedPlaintext, "", "    "); err == nil {
				unpaddedPlaintext = prettyJSON.Bytes()
			}

			outputFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(file), ".hat")+".txt")
			if err := os.WriteFile(outputFile, unpaddedPlaintext, 0644); err != nil {
				fmt.Printf("Error writing %s: %v\n", outputFile, err)
				return
			}
			fmt.Printf("Successfully decrypted: %s\n", outputFile)
		},
	})
}

func decryptAESECB(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext length not multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	bs := block.BlockSize()
	for start := 0; start < len(ciphertext); start += bs {
		block.Decrypt(plaintext[start:start+bs], ciphertext[start:start+bs])
	}
	return plaintext, nil
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty padding data")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data length is not a multiple of block size")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen >= 1 && paddingLen <= blockSize {
		valid := true
		for i := len(data) - paddingLen; i < len(data); i++ {
			if int(data[i]) != paddingLen {
				valid = false
				break
			}
		}
		if valid {
			return data[:len(data)-paddingLen], nil
		}
	}

	//TODO: Soft trim fallback if layout calculations mismatch slightly
	result := data
	for len(result) > 0 {
		lastByte := result[len(result)-1]
		if lastByte < 32 || lastByte == ' ' {
			result = result[:len(result)-1]
		} else {
			break
		}
	}
	return result, nil
}
