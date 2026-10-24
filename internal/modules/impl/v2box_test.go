package impl

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"Pantegnos/internal/modules"
)

// v2boxFixtureOpen is a real 6.1.4 export with isPasswordProtected=false. The
// app encrypted it with the fixed key, so it is the compatibility fixture for
// the static-key path.
const v2boxFixtureOpen = "eyJub25jZSI6IjJGZ0ZsYTZIblFBbEd2bmEiLCJtYWdpYyI6InYyYm94X2V4cG9ydCIsInRhZyI6Ik40YWJjNm1OZzJmSklScFM3TGw3Tmc9PSIsImNpcGhlcnRleHQiOiJxdFFrZFwvM2VpczYzcXhSR0ZwZDhUdTZ2WjdSNWtXN1FYNWl0UXpBdGxIblp6YjBsNGdVT3Eya2hpcGJtb3o2NmZEWG5NTmtlWlorWUNCb3FRclpvdjRFbUF6SXVyeG9ROXhPeVRHXC9NWXVXVTlYZ1wvd3lkWXNjVXJSYmc0MlhPRkRCVmswbUNGUlVvMmx5dGpMUjlcLzBscnpuQ0JVcmhQeDUzd0tDU0xET3EyMkgyS1RxNlJvOUlaNlVyUytpSFpJTmV3a0tWWlwvbUhxa3ZRWllqNTNtUFdYRXEzXC96dDdRMnk4ZEgwMUZKcHdpSGl0SElKcFIxdXBjS0FKU0tyeER5V3VYdzRzdDR0VTV1bjF5MlwvWm00ZUowekRRSmErbjFESTdjeE51TUtzZEp5TUpkczNCQjUxeHZocmtZNGtSN3RIVlZzN2RkTmVDNUJnNE82WTVUM0o5cGhlbkpcL3pveEphc1ZcL2RITUNpUW55UWw2VCsyYnFGc0RcL21EQktBMjY4QTF6MHhxY09YWlJrUkRENFRrWmFvYjdieVY1dDlvc3pTNlZrSmJyMVUrZHZhNUJQcjVEd0ZjNkoyYVpka0lmQVQ2Vmpzd3JhTzhEYlUyY2JDcHRPUHhrcWZWclBSVE1keGNvclE4MEt3R1laNFh1TFB1WjdWQm9UN3dwZjZ5QUJcL2ZnXC9GV2haMUFGZ2pTYnNcL0ZVTGE5alJ0azVRTEgyQVRyVlFWVXJjNlZqcDVyZkoyV0hHeEVEbEFYXC9XaTdjbXkxcFMyeWx5TThjQ01BRjlDZzBkdzIwdmlzNWpWTTY5cXd3SEJtdWsrckNnS1ZSQkZzZUU0cDRvYmVLQW9idFdoRHZJMmpIdnFQZ3VQb2RhTHVpN2Y2SEFRWjlRRjZwRW9Nc0ZXV3BQSTFOY1ZYNWJJSDhSVDhaZVZWT1EyZz09IiwidmVyc2lvbiI6MSwiaXNQYXNzd29yZFByb3RlY3RlZCI6ZmFsc2V9"

// v2boxFixtureProtected is a synthetic export with a known password. It carries
// two configs, one raw config, an expiry and a device allow-list, and it also
// repeats the payload as a/b like 6.1.4 does.
const v2boxFixtureProtected = "eyJ2ZXJzaW9uIjoxLCJtYWdpYyI6InYyYm94X2V4cG9ydCIsImlzUGFzc3dvcmRQcm90ZWN0ZWQiOnRydWUsImV4cGlyYXRpb25UaW1lc3RhbXAiOjQxMDI0NDQ4MDAuMCwiYWxsb3dlZERldmljZUlEcyI6WyIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiXSwiY2lwaGVydGV4dCI6ImJPKy9QQUxMaTQyNHRvS0RQb2ozMGdnVWlkV2xPR2NmbXRVQVUyUm0rQWt3b2NKZjlFY3IrblpqYjR6bGswbXVxVkhTT3FUNnpzZnhTYWNoc1h1YW9tOEhWQ0Rzc2tRUWxhd2k5M0VMUWVqeDBWQkVsVlozQzM4MGFtdzJsL0RNTnYzTkU3Q0N5cjgxYVJGWHkyendYRmErRVR3NldYRjkxYWRHb1FxZ0ZiVzh6SVV0NHVqUnRNdnhnNTNQeW16VUxyNmlBVm5nVzdjVTJsTS94d09kVkNxTUVoandFZjg5Qk9XdDlaRGp1Z1VnWGl3Z1h2NXdHUkY5aEt4V2FMcFVHdWdLejJBQ3ZtRWVIKzZ3a0h2cVRySkg5WlM4WmNXTUFNS0djOHhSblZya2dkSEFuWlZRTHppUXQwUEw1UVNsbFB6UGZhV1JyK0x4NzNoVWJxT2l6a1JNeEhCb0RmT2d4U3ppWnI5VEpZSkJtY1BhQTJOZGhkNndHQStXOGJOM0FZMzYzVmtxakt4SDZlRnpDczZ5TzJaUnhZMEEwZ0Vad0s5R3JIREV6Q1VOY1FqM0RaRTlvK21SSXVnQWZaNVNFWHRGTU1BSjBKQmxpcGMwU2U2bVBkVVF0RDZiWHo4Q1dSL3Nta0svT0dQMDVLcTI4Vm01R0VVYnJDN2MrNGo4MFA4Q244NVZOMFN5NEx6VXJEZUYwL1FxZTBhZW1MUElEMlB2WklLdGZNL3VZK3BWd2Y0dDVkRjhsdUY3b1l4cWVuaXh3NitJVHZXeExQY3ZJa0FMeXNlRkdGZkNESWdwZTFCWHU2dGtxU1RVcGJDN0tQcWk5MTVpUmUrNmJWRnFlWlNZTnNoTnh4S2l0REl0Q2VzdXJxNkJaeFpMQ2tPeTUrL0pvQkh2aisyT3hOVzZYampwZDJpK04yQ1Y3dEpqb3BadWVyU0hwL3F0ak41Rm9qWWZiV2dndmpwc0tIQnhWWGpMYXl6d2ZTV1RoYnQyZWE0MjFvWXRXVFc2NW5wVXE2ZVllcUp5Rkx5TGx4clJRQ3J0NnZueWRqbXBLa25PS0M0MnBTR1BUWktQR0lPdFZSSlJZeG1BUzc1YWxnVG1pOUlLYW9zWWJjK3lzNDlHbzBKZzVtQzVFWkR2NWN0bCsrODFBN3VRYys3RERoWHF5cU5mZ253QVYzNTNmaTVpQm43ZTdRZ2lVdTY5SEVWcUw3WmpiMDloUlg3R1lURWhlWlpsMytGRFFKbHQ4cXNJcGwyQ1hKSDloVzhBV0E1aVQ2MndrMS82aVpYVmtkRnBHR2NiRE9SVnY2RUV2U1AyZzdBWVFoQyt1Zkp2bGNLQWVQcEtlRlcrNXp5NVczdTdYWEZZeFdMcisvamlJMWN5clRwbjNTOUVHOHNHOG8rYU5Yams5aG1PbFBkR044VTVlZGNWQ2ptMWNqSDdvY0Z4aUJkb0RObzZRUFRxQ25lNXp4azIzbjViZkMrVkpHY1pteW81dG8xQWEvU0E3S1dsd242NXBNUUswU3BzeDY3aVcrRklsZHdYVFNFNEJNazU5cWhmdjh6d0o3VlIyaStwYzY0dnMvTWNlTHYyQWxTNU5YTnQ0N013L2lXekN0MXMvOU5aSmkzSFJQZlpFOTNiYzN6d25hV0Y1Zm96TWpIY0VWVGlQN2hkTDg2Q3lscGRGWkdPcTVVUy95d2pDNEtRSyswUUVoaGhtTGNUak1mdjgyRlZZTkxjMTVjWFNSV1EybmhCYnJiMERhemt2T3RTZWVOMFl1QjBwUnh0TE5NSXRLclFQbDZCL21mWnU3R2wvTGt4SlpjRGQzREMxcUVlWnBMbXpFeXJGWWNSaXBiTjNTbStiVzBDWE81Q3B2MXZGZy9oc2NtZjQ3RkMveWE3cmhRS1VEcFlwRVN4c0VGbjBvQ0hzNXpXRjd2b3dneDNQTXVEWjd3cmI1alliWlBWb1BRb204S2hERTFVbFBIQUJVUXl3TzA2QWsyUFBjWTBhKzFqQUx6QzdYN0NQNmpONjU5N3pWV3RnbmdxQ1dGSFdxM09VeTc1STIzMG4wbWFWSURyenY2T3dVbGhJbU1RcXQwZjNyaW4yUUhHaTI1WVRwM1Z3OTFpTVRMTFhUVkRZWGdJdUpEelR0MHhObTJiMGlXV2hzSU9wbWp5NFVGd3dGWVlMSnpKQTFpWnB0UEJvSnd4NnM0MUNya0liNkNaeUMxL2xzMVNpZXZML1VoN3BRWTRpNDN2S05zQk5pVjVheGN5UldBeUgxN1RQNUdjaE56NkVYMzJTV1A2TFFjbForRGh3M1piYks2dlJZYlVnN1BMc0IxTU5WajBLdlFkWGVwZHkyQ2dHWS9NWmV0Wkl4TkF4M09WeGNldTBPcm9mOEc5Zlp6R0VXVXVxRmhObWlZZlJCdEUxMFNkUTZieFV5amViS1R3QVdJQy8yMmthYWVTRXFTRWUxUmUzaVBPVTRBYncyTlZQSDIwVnVKNDhQcmh6Z0t3NHRSNHlzaW1SaytzV1V4eTNyRlVLeTh6OVZtSXFFMk5pVTRKRXBMY3Q0MzRWaHU1U3JnY1FYTmpYZ09NdW1xSU1iM1k4Q2FnSkk4djBzSmtvNTVUT0ZqQ0liNWl3d0QxRlR6eVc0aGxqendTQThyek00eHdJbzhRVXhpWWpYWmhWUjgrMzFhRU14U3Iwb0VqcTBVUzNpMXVLZDY1dEVCTmpJaVdHUFZVOUdnUUdyQVpCL3BpOWRRdTZNMTIzWGlnREpmOXpVbCs5d2duMnE4WmtNTlVUSWZPaU5YcXgvUmFETldIQ0swODZOOWdFbVhmM2tIZnNONCtBek9LbEFJNjV4ZmdMbnE3dUpWWVI0dTREQ2Q4VzAwaVNoRGJhUVp1ckUrYloxdWEzdDhoWmlYY08rcnU0U0tWbFB1UmlBMlZBOWFJUW92QlUyODczUWJDYVFWeWRJQmxKTzBzL2RvMG14ZmhoZlFaRkZWTThld0RPeVh6R1RycmRscHl6TUduNU9XSGxuUUx5MExVTkNDc0wvVnNuR25maWNraWV1dnloVXg0ZUZ5Ny9kQ0x0SE9JanJCM2JTVEU5Qlprb2g0T2lHVE50RTBjODNmWGwyVXl4dzc3MmM5cTRWVXRBUzMydmhyQ0FPVTBkK3Jvc1hLdDZzMExHTjlGSU4zS0Nhak5QVDhXU1p0QllkV2ZsR3dWNnFhUnpIbE5sWVlEMUo5VHBHMktneXhZTjJzTktuS1lIVEZIWjJtWWlxL2xFNlBtT3dNaHZHaHFMUjRyS2FYNmp0b2czVjZkRnFzSkczTlZHb3VxY2NlOFY1alNBbFkzNXJsd1ZWdSswUVJzS0JpQVRRV0hvVlByZGI2TEpFejFqMlIwbHBvazloU0dRTXM2VlFoZVQvNjA0UFduVE52Q3daK0MrbkJhdkwvakswdDVpQnlLV091cXVDVTZ1WXlmejhpemxXNmVkakdVTzk3MnNDOE9VWVBvaGdOTFk2bUYxQmYzTk9KWW51ZlV0UnRFIiwibm9uY2UiOiJBQUVDQXdRRkJnY0lDUW9MIiwidGFnIjoiQk56UkZMRnlWbFRSKzJSTzAwdEFJQT09In0="

const v2boxFixturePassword = "correct horse battery staple"

func v2boxTestModule(t *testing.T) *modules.Module {
	t.Helper()
	mod := modules.Find(".v2box", "")
	if mod == nil {
		t.Fatal("no module registered for .v2box")
	}
	return mod
}

func v2boxFixture(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("fixture base64: %v", err)
	}
	return raw
}

func v2boxDecryptFixture(t *testing.T, raw []byte, name, password string) string {
	t.Helper()
	mod := v2boxTestModule(t)
	res, err := mod.Decrypt(modules.Request{
		FileName: name,
		Data:     raw,
		Proto:    "",
		Payload:  string(raw),
		Password: password,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !res.Echo {
		t.Error("output must be echoed")
	}
	return res.Text
}

func TestV2BoxOpenExport(t *testing.T) {
	raw := v2boxFixture(t, v2boxFixtureOpen)
	text := v2boxDecryptFixture(t, raw, "sample.v2box", "")
	for _, want := range []string{
		"// ---- V2Box export ----",
		"// version: 1",
		"// password: not set (fixed app key)",
		"// configs: 1",
		"// config 1: VLESS",
		"tiktok.edns.space:443",
		"(ws/tls)",
		"[locked]",
		`"configType": "VLESS"`,
		`"server": "tiktok.edns.space"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
	if strings.Contains(text, "// device lock: 1111") {
		t.Error("an export without allowedDeviceIDs must not report a device lock")
	}
}

func TestV2BoxPasswordProtectedExport(t *testing.T) {
	raw := v2boxFixture(t, v2boxFixtureProtected)
	text := v2boxDecryptFixture(t, raw, "sample.v2box", v2boxFixturePassword)
	for _, want := range []string{
		"// password: required",
		"// expires: 2100-01-01T00:00:00Z",
		"// device lock: 11111111-2222-3333-4444-555555555555",
		"// configs: 2",
		"// raw configs: 1",
		"// config 1: VMESS \"Pantegnos VMess\" at 203.0.113.10:8443 (ws/tls) [locked] device AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
		"// config 2: VLESS \"Pantegnos VLESS\" at 198.51.100.7:443 (tcp/reality) [locked on import]",
		`"configs": [`,
		`"raws": {`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestV2BoxWrongPassword(t *testing.T) {
	raw := v2boxFixture(t, v2boxFixtureProtected)
	mod := v2boxTestModule(t)
	_, err := mod.Decrypt(modules.Request{FileName: "sample.v2box", Data: raw, Payload: string(raw), Password: "wrong"})
	if err == nil || !strings.Contains(err.Error(), "incorrect password") {
		t.Fatalf("wrong password error = %v", err)
	}
}

func TestV2BoxPasswordRequired(t *testing.T) {
	raw := v2boxFixture(t, v2boxFixtureProtected)
	mod := v2boxTestModule(t)
	_, err := mod.Decrypt(modules.Request{FileName: "sample.v2box", Data: raw, Payload: string(raw)})
	if err == nil || !strings.Contains(err.Error(), "password protected") {
		t.Fatalf("missing password error = %v", err)
	}
}

func TestV2BoxNeedsPassword(t *testing.T) {
	mod := v2boxTestModule(t)
	if mod.NeedsPassword == nil {
		t.Fatal("v2box module has no NeedsPassword")
	}
	open := string(v2boxFixture(t, v2boxFixtureOpen))
	protected := string(v2boxFixture(t, v2boxFixtureProtected))
	if mod.NeedsPassword("", open) {
		t.Error("open export reported as password protected")
	}
	if !mod.NeedsPassword("", protected) {
		t.Error("protected export not reported as password protected")
	}
	if mod.NeedsPassword("", "v2box://locked=AAAA") {
		t.Error("locked link reported as password protected")
	}
	if mod.NeedsPassword("", "not an export") {
		t.Error("garbage reported as password protected")
	}
}

func TestV2BoxTamperRejected(t *testing.T) {
	raw := v2boxFixture(t, v2boxFixtureProtected)

	var outer map[string]any
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(outer["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0xff
	outer["ciphertext"] = base64.StdEncoding.EncodeToString(ciphertext)
	tampered, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}

	mod := v2boxTestModule(t)
	_, err = mod.Decrypt(modules.Request{FileName: "sample.v2box", Data: tampered, Payload: string(tampered), Password: v2boxFixturePassword})
	if err == nil || !strings.Contains(err.Error(), "corrupted export") {
		t.Fatalf("tampered export error = %v", err)
	}
}

func TestV2BoxBadMagic(t *testing.T) {
	raw := []byte(`{"magic":"something_else","ciphertext":"AAAA","nonce":"AAAA","tag":"AAAA"}`)
	mod := v2boxTestModule(t)
	_, err := mod.Decrypt(modules.Request{FileName: "sample.v2box", Data: raw, Payload: string(raw)})
	if err == nil || !strings.Contains(err.Error(), "bad magic") {
		t.Fatalf("bad magic error = %v", err)
	}
}

func TestV2BoxLockedLink(t *testing.T) {
	uris := "vless://bbbbbbbb-cccc-dddd-eeee-ffffffffffff@198.51.100.7:443?security=tls&deviceID=AAAA#One\n" +
		"trojan://secret@203.0.113.9:8443?security=tls&deviceID=BBBB#Two"
	link := "v2box://locked=" + base64.StdEncoding.EncodeToString([]byte(uris))

	mod, proto, payload := modules.Lookup("clipboard.v2box", []byte(link))
	if mod == nil || mod.Extension != ".v2box" {
		t.Fatalf("Lookup module = %v, want the V2Box module", mod)
	}
	if proto != "v2box" {
		t.Errorf("proto = %q, want v2box", proto)
	}
	res, err := mod.Decrypt(modules.Request{FileName: "clipboard.v2box", Data: []byte(link), Proto: proto, Payload: payload})
	if err != nil {
		t.Fatalf("decrypt link: %v", err)
	}
	if res.FileName != "clipboard.txt" {
		t.Errorf("output name = %q, want clipboard.txt", res.FileName)
	}
	for _, want := range []string{
		"// ---- V2Box locked profile link ----",
		"// cipher: none (base64 only)",
		"// profiles: 2",
		"vless://bbbbbbbb-cccc-dddd-eeee-ffffffffffff@198.51.100.7:443",
		"trojan://secret@203.0.113.9:8443",
	} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestV2BoxInstallLinkRejected(t *testing.T) {
	link := []byte("v2box://install-sub?url=https%3A%2F%2Fexample.com%2Fsub")
	mod := v2boxTestModule(t)
	_, err := mod.Decrypt(modules.Request{FileName: "clipboard.v2box", Data: link, Payload: string(link)})
	if err == nil || !strings.Contains(err.Error(), "install link") {
		t.Fatalf("install link error = %v", err)
	}
}

func TestV2BoxAliasPayload(t *testing.T) {
	exp := &v2boxExport{Version: 1, Magic: v2boxMagic}
	payload := []byte(`{"a":[{"configType":"TROJAN","remarks":"Alias only","server":"203.0.113.9","serverPort":"443"}],"b":{"id":"raw"}}`)
	text := formatV2BoxExport(exp, payload)
	for _, want := range []string{
		"// configs: 1",
		"// raw configs: 1",
		"// config 1: TROJAN \"Alias only\" at 203.0.113.9:443",
		`"a": [`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("alias payload output is missing %q", want)
		}
	}
}

func TestV2BoxLookupByExtensionAndProto(t *testing.T) {
	mod, proto, _ := modules.Lookup("profile.v2box", v2boxFixture(t, v2boxFixtureOpen))
	if mod == nil || mod.Extension != ".v2box" {
		t.Fatalf("Lookup(.v2box) module = %v", mod)
	}
	if proto != "" {
		t.Errorf("proto = %q, want empty for a JSON file", proto)
	}

	mod, proto, _ = modules.Lookup("profile.txt", []byte("v2box://locked=AAAA"))
	if mod == nil || mod.Extension != ".v2box" {
		t.Fatalf("Lookup(v2box://) module = %v", mod)
	}
	if proto != "v2box" {
		t.Errorf("proto = %q, want v2box", proto)
	}
}
