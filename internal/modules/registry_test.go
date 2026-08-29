package modules

import "testing"

func resetRegistry(t *testing.T) {
	t.Helper()

	saved := Registry
	Registry = nil
	t.Cleanup(func() { Registry = saved })
}

func TestFindPrefersExtension(t *testing.T) {
	resetRegistry(t)

	Register(Module{Extension: ".npvt", Proto: []string{"NPVT1"}})
	Register(Module{Extension: ".slip", Proto: []string{"slipnet-enc"}})

	got := Find(".slip", "NPVT1")
	if got == nil || got.Extension != ".slip" {
		t.Fatalf("Find(.slip, NPVT1) = %v, want the .slip module", got)
	}
}

func TestFindProtocolWildcard(t *testing.T) {
	resetRegistry(t)

	Register(Module{Extension: ".nm", Proto: []string{"nm-*"}})

	if got := Find(".zzz", "nm-3"); got == nil || got.Extension != ".nm" {
		t.Fatalf("Find(.zzz, nm-3) = %v, want the .nm module", got)
	}
	if got := Find(".zzz", "other"); got != nil {
		t.Fatalf("Find(.zzz, other) = %v, want nil", got)
	}
}

func TestFindMiss(t *testing.T) {
	resetRegistry(t)

	if got := Find(".zzz", "unknown"); got != nil {
		t.Fatalf("Find(.zzz, unknown) = %v, want nil", got)
	}
}

func TestSplitContentSchemeAware(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantProto   string
		wantPayload string
	}{
		{
			"binary npvs with https url embedded in header",
			"NPVS\x01\x00\x00\x02\xf4" + `{"policy":{"displayMessage":"join https://t.me/foo"}}` + "\x00\x01\x02",
			"",
			"NPVS\x01\x00\x00\x02\xf4" + `{"policy":{"displayMessage":"join https://t.me/foo"}}` + "\x00\x01\x02",
		},
		{
			"scheme payload containing https url",
			`slipnet://{"doh":"https://dns.google/dns-query","x":1}`,
			"slipnet",
			`{"doh":"https://dns.google/dns-query","x":1}`,
		},
		{
			"scheme separator is not first",
			`{"url":"https://example.com/x"} happproxy://crypt2/eyJ`,
			"",
			`{"url":"https://example.com/x"} happproxy://crypt2/eyJ`,
		},
		{
			"plain uri still splits",
			"happ://crypt/SGVsbG8=",
			"happ",
			"crypt/SGVsbG8=",
		},
		{
			"uppercase scheme still splits",
			"NPVT1://414243",
			"NPVT1",
			"414243",
		},
		{
			"colon without slashes does not split",
			"note: this is not a uri",
			"",
			"note: this is not a uri",
		},
		{
			"scheme must be non-empty",
			"://payload",
			"",
			"://payload",
		},
	}
	for _, tt := range tests {
		proto, payload := SplitContent(tt.content)
		if proto != tt.wantProto || payload != tt.wantPayload {
			t.Errorf("%s: SplitContent(%q) = (%q, %q), want (%q, %q)",
				tt.name, tt.content, proto, payload, tt.wantProto, tt.wantPayload)
		}
	}
}

func TestLookupDoesNotCorruptBinary(t *testing.T) {
	resetRegistry(t)

	Register(Module{Extension: ".npvs", Proto: []string{"NPVS"}})

	raw := "NPVS\x01\x00\x00\x00\x10" + `{"policy":{"displayMessage":"join https://t.me/foo"}}` + "\x00\x01\x02"
	mod, proto, payload := Lookup("config.npvs", []byte(raw))
	if mod == nil || mod.Extension != ".npvs" {
		t.Fatalf("Lookup module = %v, want .npvs module", mod)
	}
	if proto != "" {
		t.Errorf("Lookup proto = %q, want empty", proto)
	}
	if payload != raw {
		t.Errorf("Lookup payload = %q, want the full raw content %q", payload, raw)
	}
}

func TestLookupPreservesTrailingWhitespaceBytes(t *testing.T) {
	resetRegistry(t)

	Register(Module{Extension: ".npvs", Proto: []string{"NPVS"}})

	raw := []byte("NPVS\x01\x00\x00\x00\x04{} \n")
	_, _, payload := Lookup("config.npvs", raw)
	if payload != string(raw) {
		t.Errorf("Lookup payload = %q, want %q (no trimming)", payload, string(raw))
	}
}

func TestStemAndOutputName(t *testing.T) {
	if got, want := Stem("dir/config.npvt", ".npvt"), "config"; got != want {
		t.Errorf("Stem = %q, want %q", got, want)
	}
	if got, want := OutputName("dir/config.npvt", ".npvt"), "config.txt"; got != want {
		t.Errorf("OutputName = %q, want %q", got, want)
	}
}
