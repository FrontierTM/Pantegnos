package impl

import (
	"Pantegnos/modules"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const AesKey = "_netsyna_netmod_"

func init() {
	modules.Register(modules.Module{
		Name:      "NetMod VPN Client (V2Ray/SSH)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.netmod.syna",
		Proto:     []string{"nm-*"},
		Extension: ".nm",
		Exec: func(proto, payload, extension, file, outputDir string) {
			ciphertext, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				fmt.Printf("Base64 decode error for %s: %v\n", file, err)
				return
			}

			plaintext, err := decryptAESECB(ciphertext, []byte(AesKey))
			if err != nil {
				fmt.Printf("Decrypt error for %s: %v\n", file, err)
				return
			}

			outputFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(file), ".nm")+".txt")
			decryptedString := proto + "://" + string(trimNullBytes(plaintext))
			if err := os.WriteFile(outputFile, []byte(decryptedString), 0644); err != nil {
				fmt.Printf("Error writing %s: %v\n", outputFile, err)
				return
			}

		},
	})
}

func trimNullBytes(data []byte) []byte {
	return []byte(strings.TrimRight(string(data), "\x00"))
}
