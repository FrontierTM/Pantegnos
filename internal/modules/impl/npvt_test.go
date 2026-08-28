package impl

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeOne(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("hello-wasm"))
	b64NoPad := strings.TrimRight(b64, "=")
	b64URL := base64.URLEncoding.EncodeToString([]byte("hello-wasm"))

	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{"hex", "68656c6c6f", []byte("hello"), false},
		{"base64 std padded", b64, []byte("hello-wasm"), false},
		{"base64 std unpadded", b64NoPad, []byte("hello-wasm"), false},
		{"base64 url-safe", b64URL, []byte("hello-wasm"), false},
		{"empty", "", nil, true},
		{"junk", "not valid !!!", nil, true},
	}

	for _, tt := range tests {
		got, err := decodeOne(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%s: decodeOne(%q) = %v, want error", tt.name, tt.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: decodeOne(%q) error: %v", tt.name, tt.input, err)
			continue
		}
		if !bytes.Equal(got, tt.want) {
			t.Errorf("%s: decodeOne(%q) = %v, want %v", tt.name, tt.input, got, tt.want)
		}
	}
}
