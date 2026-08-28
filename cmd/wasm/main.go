//go:build js && wasm

// Command wasm exposes the Pantegnos decryption core to JavaScript.
//
// Exports on the JS global object:
//
//	pantegnosDecrypt(fileName, data, password) → {ok, text, fileName} | {ok, error}
//	pantegnosNeedsPassword(fileName, data) → boolean
//
// where data is a Uint8Array of the raw file bytes.
package main

import (
	"errors"
	"syscall/js"

	"Pantegnos/internal/modules"

	_ "Pantegnos/internal/modules/impl"
)

var errBadCall = errors.New("usage: pantegnosDecrypt(fileName, data (Uint8Array), password)")

var errNoModule = errors.New("no module supports this file type")

func main() {
	js.Global().Set("pantegnosDecrypt", js.FuncOf(wsDecrypt))
	js.Global().Set("pantegnosNeedsPassword", js.FuncOf(wsNeedsPassword))

	select {}
}

func wsDecrypt(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return errorResult(errBadCall)
	}

	fileName := args[0].String()
	data := copyBytes(args[1])
	password := args[2].String()

	mod, proto, payload := modules.Lookup(fileName, data)
	if mod == nil {
		return errorResult(errNoModule)
	}

	result, err := mod.Decrypt(modules.Request{
		FileName: fileName,
		Data:     data,
		Proto:    proto,
		Payload:  payload,
		Password: password,
	})
	if err != nil {
		return errorResult(err)
	}

	return map[string]any{
		"ok":       true,
		"text":     result.Text,
		"fileName": result.FileName,
	}
}

func wsNeedsPassword(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return false
	}

	fileName := args[0].String()
	data := copyBytes(args[1])

	mod, proto, payload := modules.Lookup(fileName, data)
	if mod == nil || mod.NeedsPassword == nil {
		return false
	}

	return mod.NeedsPassword(proto, payload)
}

func copyBytes(v js.Value) []byte {
	if v.Type() != js.TypeObject {
		return nil
	}
	data := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(data, v)
	return data
}

func errorResult(err error) map[string]any {
	return map[string]any{"ok": false, "error": err.Error()}
}
