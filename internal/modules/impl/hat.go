package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"Pantegnos/internal/modules"
)

const HatImportKey = "8515D40BD04D8C97"

func init() {
	modules.Register(modules.Module{
		Name:      "HA Tunnel Plus (HAT)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.hatunnel.plusl",
		Proto:     []string{""},
		Extension: ".hat",
		Decrypt: func(req modules.Request) (modules.Result, error) {
			ciphertext, err := base64.StdEncoding.DecodeString(req.Payload)
			if err != nil {
				return modules.Result{}, fmt.Errorf("base64 decode: %v", err)
			}

			hasher := sha1.New()
			hasher.Write([]byte(HatImportKey))
			derivedKey := hasher.Sum(nil)[:16]

			plaintext, err := decryptAESECB(ciphertext, derivedKey)
			if err != nil {
				return modules.Result{}, err
			}

			unpaddedPlaintext, err := pkcs7Unpad(plaintext, aes.BlockSize)
			if err != nil {
				return modules.Result{}, err
			}

			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, unpaddedPlaintext, "", "    "); err == nil {
				unpaddedPlaintext = prettyJSON.Bytes()
			}

			return modules.Result{
				Text:     string(unpaddedPlaintext),
				FileName: modules.OutputName(req.FileName, ".hat"),
			}, nil
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
