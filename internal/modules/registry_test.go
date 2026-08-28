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

func TestSplitContent(t *testing.T) {
	tests := []struct {
		content     string
		wantProto   string
		wantPayload string
	}{
		{"slipnet-enc://AAAA", "slipnet-enc", "AAAA"},
		{"plaincontent", "", "plaincontent"},
		{"", "", ""},
	}

	for _, tt := range tests {
		proto, payload := SplitContent(tt.content)
		if proto != tt.wantProto || payload != tt.wantPayload {
			t.Errorf("SplitContent(%q) = (%q, %q), want (%q, %q)",
				tt.content, proto, payload, tt.wantProto, tt.wantPayload)
		}
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
