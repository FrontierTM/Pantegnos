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

var (
	errBadCall  = errors.New("usage: pantegnosDecrypt(fileName, data (Uint8Array), password)")
	errNoModule = errors.New("no module supports this file type")
)

func main() {
	g := js.Global()
	g.Set("pantegnosDecrypt", js.FuncOf(wsDecrypt))
	g.Set("pantegnosNeedsPassword", js.FuncOf(wsNeedsPassword))
	select {}
}

func wsDecrypt(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return fail(errBadCall)
	}

	fileName := args[0].String()
	data := copyBytes(args[1])
	password := args[2].String()

	mod, proto, payload := modules.Lookup(fileName, data)
	if mod == nil {
		return fail(errNoModule)
	}

	result, err := mod.Decrypt(modules.Request{
		FileName: fileName,
		Data:     data,
		Proto:    proto,
		Payload:  payload,
		Password: password,
	})
	if err != nil {
		return fail(err)
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

	mod, proto, payload := modules.Lookup(args[0].String(), copyBytes(args[1]))
	if mod == nil || mod.NeedsPassword == nil {
		return false
	}
	return mod.NeedsPassword(proto, payload)
}

func copyBytes(v js.Value) []byte {
	if v.Type() != js.TypeObject || v.Get("constructor").Get("name").String() != "Uint8Array" {
		return nil
	}
	data := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(data, v)
	return data
}

func fail(err error) map[string]any {
	return map[string]any{"ok": false, "error": err.Error()}
}
