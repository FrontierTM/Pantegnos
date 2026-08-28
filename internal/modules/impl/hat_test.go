package impl

import (
	"bytes"
	"strings"
	"testing"
)

func TestPkcs7Unpad(t *testing.T) {
	spacePad := []byte("content" + strings.Repeat(" ", 9)) // 16 bytes, trailing spaces

	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
		wantErr   bool
	}{
		{"valid padding", append([]byte("payload-data!!"), 2, 2), 16, []byte("payload-data!!"), false},
		{"empty data", nil, 16, nil, true},
		{"not block aligned", []byte("abc"), 16, nil, true},
		{"invalid padding soft-trims", spacePad, 16, []byte("content"), false},
	}

	for _, tt := range tests {
		got, err := pkcs7Unpad(tt.data, tt.blockSize)
		if tt.wantErr {
			if err == nil {
				t.Errorf("%s: pkcs7Unpad = %q, want error", tt.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: pkcs7Unpad error: %v", tt.name, err)
			continue
		}
		if !bytes.Equal(got, tt.want) {
			t.Errorf("%s: pkcs7Unpad = %q, want %q", tt.name, got, tt.want)
		}
	}
}
