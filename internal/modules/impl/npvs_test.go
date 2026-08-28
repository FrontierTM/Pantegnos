package impl

import (
	"bytes"
	"testing"

	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

func TestCustomPBKDF2MatchesStdlib(t *testing.T) {
	tests := []struct {
		name  string
		pass  string
		salt  []byte
		iters int
		dkLen int
	}{
		{"one block", "hunter2", []byte("fixed-salt-value"), 2, 32},
		{"two blocks", "hunter2", []byte("fixed-salt-value"), 3, 64},
		{"short key", "x", []byte{0, 1, 2, 3}, 5, 16},
	}

	for _, tt := range tests {
		got := customPBKDF2HmacSha256([]byte(tt.pass), tt.salt, tt.iters, tt.dkLen)
		want := pbkdf2.Key([]byte(tt.pass), tt.salt, tt.iters, tt.dkLen, sha256.New)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: customPBKDF2HmacSha256 mismatch", tt.name)
		}
	}
}
