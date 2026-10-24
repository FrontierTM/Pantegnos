package mobile

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseClipboardAcceptsKnownSchemes(t *testing.T) {
	cases := map[string]string{
		"slipnet://abc.def":        "clipboard.slip",
		"slipnet-enc://abc":        "clipboard.slip",
		"slipnet-bundle-enc://abc": "clipboard.slip",
		"darktunnel://host:443":    "clipboard.dark",
		"happ://crypt1/abc":        "clipboard.happ",
		"nm-v3://abc":              "clipboard.nm",
		"npvs://abc":               "clipboard.npvs",
		"npvt://abc":               "clipboard.npvt",
		"v2box://locked=abc":       "clipboard.v2box",
		"zedsecure://abc":          "clipboard.zsx",
	}
	for uri, want := range cases {
		got, ok := ParseClipboard(uri)
		if !ok {
			t.Errorf("expected %q to be accepted", uri)
			continue
		}
		if got.Name != want {
			t.Errorf("%q: name = %q, want %q", uri, got.Name, want)
		}
		if string(decode(t, got.B64)) != uri {
			t.Errorf("%q: payload round trip failed: %q", uri, string(decode(t, got.B64)))
		}
	}
}

func TestParseClipboardTrimsWhitespace(t *testing.T) {
	got, ok := ParseClipboard("  \n slipnet://abc \n ")
	if !ok {
		t.Fatal("expected the trimmed URI to be accepted")
	}
	if got.Name != "clipboard.slip" {
		t.Errorf("name = %q", got.Name)
	}
	if string(decode(t, got.B64)) != "slipnet://abc" {
		t.Errorf("payload = %q", string(decode(t, got.B64)))
	}
}

func TestParseClipboardRejects(t *testing.T) {
	for _, input := range []string{
		"",
		"   \n  ",
		"just some text",
		"https://example.com/config.slip",
		"gopher://example.com",
		"://slipnet",
	} {
		if _, ok := ParseClipboard(input); ok {
			t.Errorf("expected %q to be rejected", input)
		}
	}
}

func decode(t *testing.T, b64 string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("bad base64: %v", err)
	}
	return data
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"config.npvs":                     "config.npvs",
		"/storage/emulated/0/config.npvs": "config.npvs",
		`C:\Users\x\config.npvs`:          "config.npvs",
		"":                                "config",
		"   ":                             "config",
		"/":                               "config",
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}

	long := SanitizeName(strings.Repeat("a", 400) + ".npvs")
	if len(long) != 120 {
		t.Errorf("long name length = %d, want a 120 byte cap", len(long))
	}
}

func TestOutputFileName(t *testing.T) {
	if got := OutputFileName("payload.npvs", "profile.txt"); got != "profile.txt" {
		t.Errorf("core name should win, got %q", got)
	}
	if got := OutputFileName("payload.npvs", ""); got != "payload.txt" {
		t.Errorf("got %q", got)
	}
	if got := OutputFileName("archive", ""); got != "archive.txt" {
		t.Errorf("got %q", got)
	}
}
