package impl

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"Pantegnos/internal/modules"
)

var NetModKeys = []string{
	"<n3t5yn4^n3tm0d>",
	"_netsyna_netmod_",
	"nicetrybuddygoon",
}

func init() {
	modules.Register(modules.Module{
		Name:      "NetMod VPN Client (V2Ray/SSH)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.netmod.syna",
		Proto:     []string{"nm-*"},
		Extension: ".nm",
		Decrypt: func(req modules.Request) (modules.Result, error) {
			payload := strings.Map(func(r rune) rune {
				if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
					return -1
				}
				return r
			}, req.Payload)

			ciphertext, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return modules.Result{}, fmt.Errorf("base64 decode: %v", err)
			}

			plaintext, _, err := decryptNetMod(ciphertext)
			if err != nil {
				return modules.Result{}, err
			}

			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, plaintext, "", "    "); err == nil {
				plaintext = prettyJSON.Bytes()
			}

			text := string(plaintext)
			if req.Proto != "" {
				text = req.Proto + "://" + text
			}

			return modules.Result{
				Text:     text,
				FileName: modules.OutputName(req.FileName, ".nm"),
			}, nil
		},
	})
}

func decryptNetMod(ciphertext []byte) ([]byte, string, error) {
	var lastErr error
	for _, key := range NetModKeys {
		if len(key) != 16 {
			continue
		}
		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			lastErr = err
			continue
		}
		if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
			lastErr = fmt.Errorf("ciphertext length not multiple of block size")
			continue
		}

		plaintext := make([]byte, len(ciphertext))
		for start := 0; start < len(ciphertext); start += block.BlockSize() {
			block.Decrypt(plaintext[start:start+block.BlockSize()], ciphertext[start:start+block.BlockSize()])
		}

		unpadded, err := strictPKCS7Unpad(plaintext, block.BlockSize())
		if err != nil {
			lastErr = fmt.Errorf("key %q: %v", key, err)
			continue
		}
		return unpadded, key, nil
	}
	return nil, "", fmt.Errorf("no netmod key matched: %v", lastErr)
}

func strictPKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data length is not a multiple of block size")
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen < 1 || paddingLen > blockSize {
		return nil, fmt.Errorf("invalid padding length %d", paddingLen)
	}
	for i := len(data) - paddingLen; i < len(data); i++ {
		if int(data[i]) != paddingLen {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:len(data)-paddingLen], nil
}
