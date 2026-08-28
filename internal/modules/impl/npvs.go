package impl

import (
	"Pantegnos/internal/modules"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	npvsWrapSize  = 60
	npvsSaltSize  = 16
	npvsKdfAppKey = "wbaes-ctr-sha256"
	npvsKdfPass   = "pbkdf2-hmac-sha256"
	npvsKeyGen    = 1
	npvsMinIters  = 1
	npvsMaxIters  = 10000000
)

type npvsPassphraseWrap struct {
	Iters int    `json:"iters"`
	Kdf   string `json:"kdf"`
	Salt  string `json:"salt"`
	Wrap  string `json:"wrap"`
}

type npvsAppKeyWrap struct {
	Kdf   string `json:"kdf"`
	KeyID int    `json:"keyId"`
	Salt  string `json:"salt"`
	Wrap  string `json:"wrap"`
}

type npvsHeader struct {
	V        int    `json:"v"`
	ConfigID string `json:"configId"`
	IssuedAt string `json:"issuedAt"`
	Creator  struct {
		Fp string `json:"fp"`
		Pk string `json:"pk"`
	} `json:"creator"`
	AppKey     *npvsAppKeyWrap     `json:"appKey"`
	Passphrase *npvsPassphraseWrap `json:"passphrase"`
	Recipients []json.RawMessage   `json:"recipients"`
}

type npvsEnvelope struct {
	headerRaw []byte
	hdr       npvsHeader
	nonce     []byte
	body      []byte
	sig       []byte
}

func parseNpvVEnvelope(b []byte) (*npvsEnvelope, error) {
	if len(b) < 89 {
		return nil, fmt.Errorf("too short: %d bytes", len(b))
	}
	if b[0] != 'N' || b[1] != 'P' || b[2] != 'V' || b[3] != 'S' {
		return nil, fmt.Errorf("bad magic")
	}
	if b[4] > 1 {
		return nil, fmt.Errorf("unsupported version %d", b[4])
	}

	hdrLen := int(binary.BigEndian.Uint32(b[5:9]))
	if hdrLen < 0 || 9+hdrLen > len(b) {
		return nil, fmt.Errorf("invalid header length: %d", hdrLen)
	}

	e := &npvsEnvelope{headerRaw: b[9 : 9+hdrLen]}
	if err := json.Unmarshal(e.headerRaw, &e.hdr); err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}

	off := 9 + hdrLen
	if off+12+4 > len(b) {
		return nil, fmt.Errorf("truncated body nonce/length")
	}
	e.nonce = b[off : off+12]
	bodyLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
	off += 16

	if bodyLen < 16 || off+bodyLen+64 > len(b) {
		return nil, fmt.Errorf("invalid body length: %d", bodyLen)
	}
	e.body = b[off : off+bodyLen]
	e.sig = b[off+bodyLen : off+bodyLen+64]

	return e, nil
}

func init() {
	modules.Register(modules.Module{
		Name:      "NPV Tunnel v2ray/ssh config export (.npvs)",
		ApkAuthor: "com.vonmatrix.npvtunnel",
		Proto:     []string{"NPVS"},
		Extension: ".npvs",
		NeedsPassword: func(_, payload string) bool {
			env, err := parseNpvVEnvelope([]byte(payload))
			return err == nil && env.hdr.Passphrase != nil
		},
		Decrypt: decryptNPVS,
	})
}

func decryptNPVS(req modules.Request) (modules.Result, error) {
	pt, keys, err := decryptNPVSFull(req.Data, req.Password)
	if err != nil {
		return modules.Result{}, err
	}

	var sb strings.Builder
	sb.WriteString(decodeNpvSentinels(string(pt)))
	sb.WriteString("\n\n// ---- recovered key material ----\n")
	for _, kv := range keys {
		fmt.Fprintf(&sb, "// %s: %s\n", kv[0], kv[1])
	}

	return modules.Result{
		Text:     sb.String(),
		FileName: modules.OutputName(req.FileName, ".npvs"),
		Echo:     true,
	}, nil
}

func decryptNPVSFull(raw []byte, password string) (pt []byte, keys [][2]string, err error) {
	env, err := parseNpvVEnvelope(raw)
	if err != nil {
		return nil, nil, err
	}

	keys = append(keys,
		[2]string{"configId", env.hdr.ConfigID},
		[2]string{"creator.fp", env.hdr.Creator.Fp},
		[2]string{"creator.pk", env.hdr.Creator.Pk},
	)

	var dek []byte
	switch {
	case env.hdr.AppKey != nil:
		dek, err = unwrapAppKey(env.hdr.AppKey)
	case env.hdr.Passphrase != nil:
		dek, err = unwrapPassphrase(env.hdr.Passphrase, password)
	case len(env.hdr.Recipients) > 0:
		err = fmt.Errorf("envelope uses recipient ECDH wraps; recipient private key required")
	default:
		err = fmt.Errorf("no supported unwrap target (no appKey, no passphrase)")
	}
	if err != nil {
		return nil, keys, err
	}
	keys = append(keys, [2]string{"DEK/CEK (hex)", hex.EncodeToString(dek)})

	body, err := chachaOpen(dek, env.nonce, env.body, env.headerRaw)
	if err != nil {
		return nil, keys, fmt.Errorf("payload decrypt failed: %w", err)
	}

	return body, keys, nil
}

func unwrapAppKey(a *npvsAppKeyWrap) ([]byte, error) {
	if a.Kdf != npvsKdfAppKey {
		return nil, fmt.Errorf("unsupported appkey kdf %q", a.Kdf)
	}
	if a.KeyID != npvsKeyGen {
		return nil, fmt.Errorf("no custodian for generation %d", a.KeyID)
	}

	salt, err := b64UrlNoPad(a.Salt)
	if err != nil {
		return nil, err
	}
	if len(salt) != npvsSaltSize {
		return nil, fmt.Errorf("salt must be %d bytes", npvsSaltSize)
	}

	wrap, err := b64UrlNoPad(a.Wrap)
	if err != nil {
		return nil, err
	}
	if len(wrap) != npvsWrapSize {
		return nil, fmt.Errorf("wrap must be %d bytes", npvsWrapSize)
	}

	kdks := custodianKDKs(salt)
	if len(kdks) == 0 {
		return nil, fmt.Errorf("whitebox KDK derivation failed")
	}
	for _, kdk := range kdks {
		if dek, err := chachaOpen(kdk, wrap[:12], wrap[12:], salt); err == nil {
			return dek, nil
		}
	}
	return nil, fmt.Errorf("no custodian key matched (tried %d)", len(kdks))
}

func unwrapPassphrase(p *npvsPassphraseWrap, password string) ([]byte, error) {
	if p.Kdf != npvsKdfPass {
		return nil, fmt.Errorf("unsupported passphrase kdf %q", p.Kdf)
	}
	if p.Iters < npvsMinIters || p.Iters > npvsMaxIters {
		return nil, fmt.Errorf("bad iteration count %d", p.Iters)
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	salt, err := b64UrlNoPad(p.Salt)
	if err != nil {
		return nil, err
	}

	wrap, err := b64UrlNoPad(p.Wrap)
	if err != nil {
		return nil, err
	}
	if len(wrap) != npvsWrapSize {
		return nil, fmt.Errorf("wrap must be %d bytes", npvsWrapSize)
	}

	derived := customPBKDF2HmacSha256([]byte(password), salt, p.Iters, 32)
	return chachaOpen(derived, wrap[:12], wrap[12:], salt)
}

func customPBKDF2HmacSha256(passphraseBytes, salt []byte, iterations, dkLen int) []byte {
	blocks := (dkLen + 31) / 32
	out := make([]byte, dkLen)
	counter := make([]byte, 4)

	for i, written := 1, 0; i <= blocks; i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))

		mac := hmac.New(sha256.New, passphraseBytes)
		mac.Write(salt)
		mac.Write(counter)
		digest := mac.Sum(nil)

		blockXor := make([]byte, len(digest))
		copy(blockXor, digest)

		for j := 2; j <= iterations; j++ {
			mac.Reset()
			mac.Write(digest)
			digest = mac.Sum(nil)
			for idx := range blockXor {
				blockXor[idx] ^= digest[idx]
			}
		}

		n := 32
		if dkLen-written < n {
			n = dkLen - written
		}
		copy(out[written:written+n], blockXor[:n])
		written += n
	}

	return out
}
