package impl

import (
	"encoding/base64"
	"strings"
	"testing"

	"Pantegnos/internal/modules"
)

const (
	zsxFixtureOpen    = "WlNYMQI9Va+1Hmfbrqn3UZYuB9D6wQFbgatNuICIv1TpTOkBn4UaxfwfxfA9Kifte4v6e+U4HnIwAgCsRFhkOcbOtAHyIEVIwyb6SAF97NVvxdzM3cOg5ahVHbptQuN1fYA/VuUjaiohO2SFYX3tbqMQwZ9udr/t4Vn+Kdg3K1TQ/40dA5TGoNc57hUmCxXAPK6fuOSs9WP8GFmReXFaECm2LcfoVPqlb9rLPj6N128U8BvE9Z1gGCN8rIjNafT/ju0IQd8n2eO7DX0xsas+bw0FceAz/Q2jm+/7WX1iDtoGv9GjKUxD+KLsBanOT6Ul6TqaFs8HPEEXqfbqbxXsx6ubvvvkXp1xILpO74iwmhjFu/SSdHVLCxhBj6O8oYH6yAt8vwoOPBbuR7T3TwUmz/ft1rAONaT9Fsb6NxYSAqW2WSMlmmY2z6HJ1EhAuVObPmp3A5XwU2A/rYWNNjKfHDysxc8ULxvHaepDSSupczkrLb92oQ=="
	zsxFixtureLocked  = "WlNYMQJEj2itlWu+Yxtlqh7nciz1568WN8IGDOM2l7be07daxlwT+LzN0tWsJ3vN9XmnCiZY50fMw5QGwg8EGMzI22kbYUGeUBhmHLRkAySI0sx3r7GxBE70Bcq/EoaYVJRGwSzPm2KjY+Qj/4iY4TZ/QfmNQl8RrpryYNLYumwTqyAfYue7ZkcGOrcPOO+PdTYHdu/zDnKYj3Uq7oHwxSlqELf2prb1sKdLBzI2l0/QvCZbNbOmEpRuFdwhB6FT7NKgjOM8PRqbtL5DLdi0i1ObGaJkMo7GFCckWvaefMXQV/xdvsddH4+zWKBxWG9Cp7wEm+nAJeEFEsXMbpd8v1aNML5E542KUJ8tRmb5D4fcY8oytak1d4oZbXeNi0oUY1Qu8RYZzYrlj/zG4TtGGVz4prjFVo2UHGW7Bcm3H7KtCiIdpPVxH6PGRV2oDasgjja3/XV4/mybJzBEDQBeYK+DlKQbUTzMMaLEMmkKGKpxyYOx4vs6KYg9NxNArnhyBzRQo6JmZpowD/n7qCuK7Ss8KmmD4L7nwyYBt6Zvm/o+ZCv/FsnGm0+nC4WFipBNhuGx5Y9hcVgWTPT5xQlruP2xGhQM0wX2yhzrpXK/ybM8vW3tffIce1Js"
	zsxFixtureZedLink = "WlNYMQJiZ8WBZ6/QL4EWB0hF/eVyepBCaWSieVowMIJw9COJU5z7iq+vLXB+7YOp6uqBIoGOuOd/XrWXdGLFZyqirW6HlBImCrSgLfxinnjmsOGQzR0Bz9NqkDFbiyD58Hrn/MFucOjoe1djBHzbDIdfwMakmYUT3BBpwpHsk2lb1Ghxtgy62YRUyh2K2BtbmI0OEqsxkuO5smg6TiykVLxgCmq+kaYVyhSH4509gX7e2NWpcD2Tfqk0GfHz7Yj8vzyZCFrams0wz1YqSGQPA1ENR6jrzfB3zTlwdWnCF1NIttn4s4lQQuRl5FNUGT5U+X3lgIhFyleRs54iMsfqxbT1JysbA/HZduTjaVJvvj3dVAGBYMA+Fw5wrjHZ2x1v+JW1YVrbln8QZHp25CeaF9ZAVrcsHoQyVi6btOALbzk3brWPqHYUEa9rO2T+ZEfPSDHQt0PuWrADjOhmxNOAOlievVnrCxoHApgWhBaTiraW2EoedqTW3drtJwqqtHFa37Q="
	zsxFixtureExpired = "WlNYMQLyUhepKekmokjKuNOG+MYroc2g6ASDU9XMC6gYxGAJ408FLOV4nA+DmlKt+BSljPVDNa53aCi0ikjwi1lj4Hxq6YsP06f99vK8NAccPcYWtQosPmyTrTfD5+aATKngRyXVUTMdz4A1qgXi6KKcU0umN1VKFsJ0BAhU6oxlv7WyGjXlwLaYbWRhvrYvOQBSAxLghZoT5BI1obWtfA0BN9pk5zMJnMnkwdwl6/0QS4pdXOT/Kk3gYCWXbsUWdjztC/1lJRxnCqwOAIgX8PgkRBCDKVPzTeSOdp4utA9rLUzKRFqXJLmtzQyLZhxXWIeGJem3sHmsBMXKBObzD2CmVZOYliaZqZQy8gYWlNgCcFSeaKELt3K5PQuTtgzAyns="
)

func zsxTestModule(t *testing.T) *modules.Module {
	t.Helper()
	mod := modules.Find(".zsx", "")
	if mod == nil {
		t.Fatal("no module registered for .zsx")
	}
	return mod
}

func zsxTestDecrypt(t *testing.T, encoded, password string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("fixture base64: %v", err)
	}
	mod := zsxTestModule(t)
	res, err := mod.Decrypt(modules.Request{
		FileName: "vault.zsx",
		Data:     raw,
		Proto:    "",
		Payload:  string(raw),
		Password: password,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if res.FileName != "vault.txt" {
		t.Errorf("output name = %q, want vault.txt", res.FileName)
	}
	if !res.Echo {
		t.Error("vault output must be echoed")
	}
	return res.Text
}

func TestZsxOpenVault(t *testing.T) {
	text := zsxTestDecrypt(t, zsxFixtureOpen, "")
	for _, want := range []string{
		"// ---- ZedSecure vault profile ----",
		"// name: Open Vault",
		"// note: hello world",
		"// expires: not set",
		"// password: not set",
		"// payload: share link",
		"vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@198.51.100.7:443",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestZsxLockedVault(t *testing.T) {
	text := zsxTestDecrypt(t, zsxFixtureLocked, "hunter2")
	for _, want := range []string{
		"// name: Locked Vault",
		"// name (fa): گاوصندوق",
		"// password: required",
		"// payload: JSON config",
		"\"server\": \"198.51.100.7\"",
		"\"server_port\": 443",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestZsxWrongPassword(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(zsxFixtureLocked)
	if err != nil {
		t.Fatal(err)
	}
	mod := zsxTestModule(t)
	_, err = mod.Decrypt(modules.Request{
		FileName: "vault.zsx",
		Data:     raw,
		Payload:  string(raw),
		Password: "not-the-password",
	})
	if err == nil || !strings.Contains(err.Error(), "incorrect password") {
		t.Fatalf("wrong password error = %v", err)
	}
}

func TestZsxPasswordRequired(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(zsxFixtureLocked)
	if err != nil {
		t.Fatal(err)
	}
	mod := zsxTestModule(t)
	_, err = mod.Decrypt(modules.Request{
		FileName: "vault.zsx",
		Data:     raw,
		Payload:  string(raw),
	})
	if err == nil || !strings.Contains(err.Error(), "password protected") {
		t.Fatalf("missing password error = %v", err)
	}
}

func TestZsxNeedsPassword(t *testing.T) {
	mod := zsxTestModule(t)
	if mod.NeedsPassword == nil {
		t.Fatal("zsx module has no NeedsPassword")
	}
	for name, tc := range map[string]struct {
		fixture string
		want    bool
	}{
		"open":    {zsxFixtureOpen, false},
		"locked":  {zsxFixtureLocked, true},
		"expired": {zsxFixtureExpired, false},
	} {
		raw, err := base64.StdEncoding.DecodeString(tc.fixture)
		if err != nil {
			t.Fatal(err)
		}
		if got := mod.NeedsPassword("", string(raw)); got != tc.want {
			t.Errorf("%s: NeedsPassword = %v, want %v", name, got, tc.want)
		}
		if got := mod.NeedsPassword("", "not a vault"); got {
			t.Errorf("%s: NeedsPassword on garbage = true", name)
		}
	}
}

func TestZsxExpiredVaultStillDecrypts(t *testing.T) {
	text := zsxTestDecrypt(t, zsxFixtureExpired, "")
	if !strings.Contains(text, "// expires: 2020-09-13T12:26:40Z (expired)") {
		t.Errorf("expired marker missing from output: %s", text)
	}
	if !strings.Contains(text, "ss://YWVzLTI1Ni1nY206cGFzcw@198.51.100.8:8388#Expired") {
		t.Error("expired vault payload was not decrypted")
	}
}

func TestZsxTamperRejected(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(zsxFixtureOpen)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	mod := zsxTestModule(t)
	_, err = mod.Decrypt(modules.Request{
		FileName: "vault.zsx",
		Data:     raw,
		Payload:  string(raw),
	})
	if err == nil || !strings.Contains(err.Error(), "outer layer") {
		t.Fatalf("tampered vault error = %v", err)
	}
}

func TestZsxVersionGates(t *testing.T) {
	mod := zsxTestModule(t)
	for name, raw := range map[string][]byte{
		"legacy": append([]byte("ZSX1\x01"), make([]byte, 28)...),
		"future": append([]byte("ZSX1\x03"), make([]byte, 28)...),
		"bad":    append([]byte("NOPE\x02"), make([]byte, 28)...),
		"short":  []byte("ZSX1\x02"),
	} {
		_, err := mod.Decrypt(modules.Request{FileName: "vault.zsx", Data: raw, Payload: string(raw)})
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestZsxZedLink(t *testing.T) {
	text := zsxTestDecrypt(t, zsxFixtureZedLink, "pässwörd-秘密")
	for _, want := range []string{
		"// payload: ZedSecure link (tor)",
		"// version: 1",
		"// name: Mini",
		"// source: tor",
		`"kind": "tor"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestZsxZedLinkInput(t *testing.T) {
	link := "zedsecure://eyJ2IjoxLCJuIjoiTWluaSIsInMiOnsia2luZCI6InRvciJ9LCJtIjpbXX0"
	mod, proto, payload := modules.Lookup("profile.txt", []byte(link+"\n"))
	if mod == nil || mod.Extension != ".zsx" {
		t.Fatalf("Lookup module = %v, want the ZedSecure module", mod)
	}
	if proto != "zedsecure" {
		t.Errorf("proto = %q, want zedsecure", proto)
	}
	res, err := mod.Decrypt(modules.Request{
		FileName: "profile.txt",
		Data:     []byte(link + "\n"),
		Proto:    proto,
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("decrypt link: %v", err)
	}
	if res.FileName != "profile.txt" {
		t.Errorf("output name = %q, want profile.txt", res.FileName)
	}
	for _, want := range []string{"// source: tor", "// name: Mini", `"v": 1`} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestZsxZedLinkRejectsBadBase64(t *testing.T) {
	mod := zsxTestModule(t)
	raw := []byte("zedsecure://!!!not-base64!!!")
	_, err := mod.Decrypt(modules.Request{FileName: "link.txt", Data: raw, Proto: "zedsecure", Payload: string(raw)})
	if err == nil {
		t.Fatal("expected an error for invalid link base64")
	}
}
