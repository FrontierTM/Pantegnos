package impl

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"Pantegnos/internal/modules"
)

func buildNpvsEnvelope(t *testing.T, header map[string]any, body []byte) []byte {
	t.Helper()

	hdr, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 0, 9+len(hdr)+16+len(body)+64)
	buf = append(buf, 'N', 'P', 'V', 'S', 1)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(hdr)))
	buf = append(buf, hdr...)
	buf = append(buf, make([]byte, 12)...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(body)+16))
	buf = append(buf, body...)
	buf = append(buf, make([]byte, 80)...)
	return buf
}

func npvsModule(t *testing.T) *modules.Module {
	t.Helper()

	for i := range modules.Registry {
		if modules.Registry[i].Extension == ".npvs" {
			return &modules.Registry[i]
		}
	}
	t.Fatal("npvs module not registered")
	return nil
}

func npvsTestHeader(extra map[string]any) map[string]any {
	header := map[string]any{
		"configId":   "abcdefghijklmnop",
		"policy":     map[string]any{},
		"recipients": []any{},
		"v":          1,
	}
	for k, v := range extra {
		header[k] = v
	}
	return header
}

func TestNpvsNeedsPassword(t *testing.T) {
	mod := npvsModule(t)
	if mod.NeedsPassword == nil {
		t.Fatal("npvs module has no NeedsPassword")
	}

	displayMessage := map[string]any{
		"attestationLevel":    "NONE",
		"configVersion":       1,
		"customServerMessage": "",
		"displayMessage":      "join https://t.me/somechannel for the passphrase",
		"expiresAt":           nil,
		"onlyMobileNetwork":   false,
	}

	tests := []struct {
		name   string
		header map[string]any
		want   bool
	}{
		{
			name: "passphrase wrap with embedded https url",
			header: npvsTestHeader(map[string]any{
				"passphrase": map[string]any{
					"iters": 600000,
					"kdf":   "pbkdf2-hmac-sha256",
					"salt":  "T8OEWfugJxIaP6OsqZEq2A",
					"wrap":  "Q6U_ziFuHdctJWfqQ3imfJmocb8YAfvEiSjwbjIOIAdJz39aVMfgjmKeXO2ocSV9x0qXgxJQ9sKsXWIz",
				},
				"policy": displayMessage,
			}),
			want: true,
		},
		{
			name: "appkey wrap with embedded https url",
			header: npvsTestHeader(map[string]any{
				"appKey": map[string]any{
					"kdf":   "wbaes-ctr-sha256",
					"keyId": 1,
					"salt":  "b8rRzxKKxDl5LON5CfzU3w",
					"wrap":  "_dpErPduK5g6ZTLnceWjWCQuge16l5yypQFAI71aYHAidoKQVEDQEti8VVdyWhFi-_qNORDkaVqkiBzb",
				},
				"policy": displayMessage,
			}),
			want: false,
		},
	}

	for _, tt := range tests {
		data := buildNpvsEnvelope(t, tt.header, []byte("placeholder-body-plaintext"))

		proto, payload := modules.SplitContent(string(data))
		if proto != "" || payload != string(data) {
			t.Fatalf("%s: SplitContent corrupted binary envelope: proto=%q", tt.name, proto)
		}

		if got := mod.NeedsPassword(proto, payload); got != tt.want {
			t.Errorf("%s: NeedsPassword = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestNpvsPolicyExtraction(t *testing.T) {
	header := npvsTestHeader(map[string]any{
		"policy": map[string]any{
			"attestationLevel":    "NONE",
			"configVersion":       2,
			"customServerMessage": "server message here",
			"displayMessage":      "join https://t.me/somechannel",
			"expiresAt":           nil,
			"onlyMobileNetwork":   true,
		},
	})
	data := buildNpvsEnvelope(t, header, []byte("x"))

	env, err := parseNpvVEnvelope(data)
	if err != nil {
		t.Fatalf("parseNpvVEnvelope: %v", err)
	}

	if got := env.hdr.Policy.DisplayMessage; got != "join https://t.me/somechannel" {
		t.Errorf("displayMessage = %q, want policy parsed", got)
	}
	if got := env.hdr.Policy.CustomServerMessage; got != "server message here" {
		t.Errorf("customServerMessage = %q", got)
	}
	if !env.hdr.Policy.OnlyMobileNetwork {
		t.Error("onlyMobileNetwork not parsed")
	}
}

func TestNpvsCreatorMessage(t *testing.T) {
	tests := []struct {
		name   string
		policy map[string]any
		want   string
	}{
		{
			name: "both messages joined",
			policy: map[string]any{
				"customServerMessage": "server notice",
				"displayMessage":      "hello https://t.me/x",
			},
			want: "hello https://t.me/x\nserver notice",
		},
		{
			name:   "empty messages",
			policy: map[string]any{},
			want:   "",
		},
		{
			name: "crlf normalized and trimmed",
			policy: map[string]any{
				"displayMessage": " line1\r\nline2 \r\n",
			},
			want: "line1\nline2",
		},
	}

	for _, tt := range tests {
		data := buildNpvsEnvelope(t, npvsTestHeader(map[string]any{"policy": tt.policy}), []byte("x"))

		env, err := parseNpvVEnvelope(data)
		if err != nil {
			t.Fatalf("%s: parseNpvVEnvelope: %v", tt.name, err)
		}
		if got := env.creatorMessage(); got != tt.want {
			t.Errorf("%s: creatorMessage() = %q, want %q", tt.name, got, tt.want)
		}
	}
}
