package impl

import (
	"Pantegnos/internal/modules"
	"encoding/base64"
	"strings"
)

const AesKey = "_netsyna_netmod_"

func init() {
	modules.Register(modules.Module{
		Name:      "NetMod VPN Client (V2Ray/SSH)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.netmod.syna",
		Proto:     []string{"nm-*"},
		Extension: ".nm",
		Decrypt: func(req modules.Request) (modules.Result, error) {
			ciphertext, err := base64.StdEncoding.DecodeString(req.Payload)
			if err != nil {
				return modules.Result{}, err
			}

			plaintext, err := decryptAESECB(ciphertext, []byte(AesKey))
			if err != nil {
				return modules.Result{}, err
			}

			return modules.Result{
				Text:     req.Proto + "://" + string(trimNullBytes(plaintext)),
				FileName: modules.OutputName(req.FileName, ".nm"),
			}, nil
		},
	})
}

func trimNullBytes(data []byte) []byte {
	return []byte(strings.TrimRight(string(data), "\x00"))
}
