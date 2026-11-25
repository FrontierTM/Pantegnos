package impl

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"Pantegnos/internal/modules"

	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
)

var (
	sipOuterKey  = []byte{0x19, 0x2e, 0x04, 0x08, 0x08, 0x04, 0x04, 0x09, 0x05, 0x59, 0x29, 0x59, 0x38, 0x5f, 0x54, 0x17}
	sipIV        = []byte{0xa7, 0x73, 0x4f, 0x9c, 0x12, 0xac, 0x1b, 0x01, 0xa4, 0x15, 0xf2, 0xc1, 0xfc, 0x78, 0xe6, 0x6b}
	sipSalt      = []byte("sH3CIVoF#rWLtJo6")
	sipVER8Key   = []byte("cambia_esto_por_tu_llave_de_32_b")
	sipFieldKey  = []byte("$%23489/**")
	sipJavaMagic = []byte{0xac, 0xed, 0x00, 0x05}
	sipTailSizes = map[string]int{"VER2": 32, "VER5": 52, "VER7": 47}
	sipCleaner   = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "\v", "", "\f", "", "-", "+", "_", "/")
)

type sipError string

func (e sipError) Error() string { return string(e) }

func sipFail(format string, args ...any) { panic(sipError(fmt.Sprintf(format, args...))) }

func sipMust(err error) {
	if err != nil {
		panic(sipError(err.Error()))
	}
}

func sipRequire(ok bool, format string, args ...any) {
	if !ok {
		sipFail(format, args...)
	}
}

func init() {
	modules.Register(modules.Module{
		Name:      "SocksIP / SocksTunnel (.sip)",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.newtoolsworks.sockstunnel",
		Proto:     []string{""},
		Extension: ".sip",
		Decrypt: func(req modules.Request) (modules.Result, error) {
			data := req.Data
			if len(data) == 0 {
				data = []byte(req.Payload)
			}
			text, err := DecryptSIP(data)
			if err != nil {
				return modules.Result{}, err
			}
			return modules.Result{Text: text, FileName: modules.OutputName(req.FileName, ".sip")}, nil
		},
	})
}

func DecryptSIP(data []byte) (text string, err error) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(sipError); ok {
				err = fmt.Errorf("sip: %s", e)
				return
			}
			panic(p)
		}
	}()

	outer := sipUnpad(sipAESECB(sipBase64(data), sipOuterKey))
	container, inner := "legacy", outer
	switch {
	case bytes.HasPrefix(outer, []byte("VER8")):
		container, inner = "VER8", sipVER8(outer)
	case sipVersion(outer) != 0:
		container = string(outer[:4])
		inner = sipLayered(outer[4:], sipTailSizes[container])
	case !bytes.HasPrefix(outer, sipJavaMagic):
		head := outer
		if len(head) > 8 {
			head = head[:8]
		}
		sipFail("unknown container prefix %s", hex.EncodeToString(head))
	}

	fields, class := sipParseJava(inner)
	if value, ok := fields["Fpassword"].(string); ok {
		if decoded, ok := sipOpenSSLField(value); ok {
			fields["FpasswordDecrypted"] = decoded
		}
	}
	return sipFormat(fields, class, container), nil
}

func sipBase64(data []byte) []byte {
	text := strings.TrimPrefix(strings.TrimSpace(string(data)), "\ufeff")
	if len(text) >= 6 && strings.EqualFold(text[:6], "sip://") {
		text = text[6:]
	}
	text = sipCleaner.Replace(text)
	if rem := len(text) % 4; rem != 0 {
		text += strings.Repeat("=", 4-rem)
	}
	out, err := base64.StdEncoding.DecodeString(text)
	sipMust(err)
	sipRequire(len(out) > 0 && len(out)%aes.BlockSize == 0, "not a SocksIP .sip container")
	return out
}

func sipAESECB(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	sipMust(err)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += block.BlockSize() {
		block.Decrypt(out[i:i+block.BlockSize()], data[i:i+block.BlockSize()])
	}
	return out
}

func sipUnpad(data []byte) []byte {
	sipRequire(len(data) > 0 && len(data)%aes.BlockSize == 0, "invalid padding")
	n := int(data[len(data)-1])
	sipRequire(n >= 1 && n <= aes.BlockSize && n <= len(data), "invalid padding")
	for _, b := range data[len(data)-n:] {
		sipRequire(int(b) == n, "invalid padding")
	}
	return data[:len(data)-n]
}

func sipVersion(payload []byte) byte {
	if len(payload) < 4 || payload[0] != 'V' || payload[1] != 'E' || payload[2] != 'R' {
		return 0
	}
	if payload[3] == '2' || payload[3] == '5' || payload[3] == '7' {
		return payload[3]
	}
	return 0
}

func sipVER8(payload []byte) []byte {
	sipRequire(len(payload) >= 32, "truncated VER8 payload")
	block, err := aes.NewCipher(sipVER8Key)
	sipMust(err)
	gcm, err := cipher.NewGCM(block)
	sipMust(err)
	plain, err := gcm.Open(nil, payload[4:16], payload[16:], nil)
	sipRequire(err == nil, "VER8 authentication failed")
	return plain
}

func sipLayered(payload []byte, tailSize int) []byte {
	sipRequire(tailSize > 0 && len(payload) >= tailSize+96, "truncated layered record")
	tail := append([]byte(nil), payload[len(payload)-tailSize:]...)
	sipReverse(tail[16:])
	decrypted := sipAESCFB(payload, tail[:32])
	record := sipReverseCopy(decrypted[32 : len(payload)-tailSize-32])
	sipRequire(len(record) >= 12, "truncated salsa record")
	copy(record[8:], sipSalsa20(record[:8], record[8:], decrypted[:32]))
	n := int(binary.BigEndian.Uint32(record[8:12]))
	end := 12 + 2*n - 16
	sipRequire(n >= 60 && end+16 <= len(record), "invalid cast record length")
	castPlain := sipCASTCFB(record[12+n:end], record[end:end+16])
	half := (n - 17) / 2
	var rebuilt []byte
	if castPlain[0] == 1 {
		rebuilt = append(sipReverseCopy(castPlain[1+half:n-16]), castPlain[1:1+half]...)
	} else {
		rebuilt = append(append([]byte(nil), castPlain[1:]...), record[end:]...)
	}
	v := n - 17
	sipRequire(len(rebuilt) >= v && v >= 58, "truncated reconstructed record")
	key := pbkdf2.Key(rebuilt[:16], sipSalt, 32, 1500, sha1.New)
	for i := 0; i < min(1500, len(rebuilt)-16); i++ {
		rebuilt[16+i] ^= key[i]
	}
	aesKey := append([]byte(nil), rebuilt[v-32:v]...)
	aesKey[0], aesKey[31] = aesKey[31], aesKey[0]
	encrypted := append(append([]byte(nil), rebuilt[v-42:v-32]...), sipReverseCopy(rebuilt[16:v-42])...)
	return sipAESCFB(encrypted, aesKey)
}

func sipAESCFB(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	sipMust(err)
	out := make([]byte, len(data))
	cipher.NewCFBDecrypter(block, sipIV).XORKeyStream(out, data)
	return out
}

func sipCASTCFB(data, key []byte) []byte {
	block, err := cast5.NewCipher(key)
	sipMust(err)
	out := make([]byte, len(data))
	cipher.NewCFBDecrypter(block, sipIV[:cast5.BlockSize]).XORKeyStream(out, data)
	return out
}

func sipSalsa20(nonce, data, key []byte) []byte {
	sipRequire(len(key) == 32 && len(nonce) == 8, "invalid salsa parameters")
	var salsaKey [32]byte
	copy(salsaKey[:], key)
	out := make([]byte, len(data))
	salsa20.XORKeyStream(out, data, nonce, &salsaKey)
	return out
}

func sipReverse(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

func sipReverseCopy(data []byte) []byte {
	out := append([]byte(nil), data...)
	sipReverse(out)
	return out
}

func sipOpenSSLField(value string) (string, bool) {
	record, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(record) < 32 || string(record[:8]) != "Salted__" {
		return "", false
	}
	var material, previous []byte
	for len(material) < 48 {
		h := md5.New()
		h.Write(previous)
		h.Write(sipFieldKey)
		h.Write(record[8:16])
		previous = h.Sum(nil)
		material = append(material, previous...)
	}
	block, err := aes.NewCipher(material[:32])
	if err != nil || len(record[16:])%aes.BlockSize != 0 {
		return "", false
	}
	plain := make([]byte, len(record)-16)
	cipher.NewCBCDecrypter(block, material[32:48]).CryptBlocks(plain, record[16:])
	n := int(plain[len(plain)-1])
	if n < 1 || n > aes.BlockSize || n > len(plain) {
		return "", false
	}
	for _, b := range plain[len(plain)-n:] {
		if int(b) != n {
			return "", false
		}
	}
	plain = plain[:len(plain)-n]
	if !utf8.Valid(plain) {
		return "", false
	}
	return string(plain), true
}

func sipFormat(fields map[string]any, class, container string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "// ---- SocksIP .sip profile ----\n// container: %s\n// class: %s\n// fields: %d\n", container, class, len(fields))
	if ms, ok := sipInt64(fields["expireFile"]); ok && ms > 0 {
		fmt.Fprintf(&sb, "// expires: %s (%d)\n", time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05 UTC"), ms)
	}
	if locked, ok := fields["LockwithHWID"].(bool); ok && locked {
		if hwid, ok := fields["HWID"].(string); ok && hwid != "" {
			fmt.Fprintf(&sb, "// device lock: %s\n", hwid)
		}
	}
	encoded, err := json.MarshalIndent(fields, "", "  ")
	if err == nil {
		sb.Write(encoded)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func sipInt64(value any) (int64, bool) {
	switch v := value.(type) {
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint16:
		return int64(v), true
	case uint32:
		return int64(v), true
	}
	return 0, false
}

type sipField struct {
	name string
	kind byte
	typ  string
}

type sipDesc struct {
	name   string
	fields []sipField
	super  *sipDesc
}

type sipObject struct {
	class  string
	fields map[string]any
}

type sipReader struct {
	data    []byte
	pos     int
	handles []any
}

func sipParseJava(data []byte) (map[string]any, string) {
	sipRequire(bytes.HasPrefix(data, sipJavaMagic), "not a Java serialization stream")
	r := &sipReader{data: data[4:]}
	obj, ok := r.content().(*sipObject)
	sipRequire(ok, "top-level value is not a serializable object")
	fields := make(map[string]any, len(obj.fields))
	for key, value := range obj.fields {
		fields[key] = sipUnwrap(value)
	}
	return fields, obj.class
}

func sipUnwrap(value any) any {
	obj, ok := value.(*sipObject)
	if !ok {
		return value
	}
	switch obj.class {
	case "java.lang.Long", "java.lang.Integer", "java.lang.Short", "java.lang.Byte", "java.lang.Boolean", "java.lang.String":
		if inner, ok := obj.fields["value"]; ok {
			return inner
		}
	}
	return value
}

func (r *sipReader) take(n int) []byte {
	sipRequire(n >= 0 && r.pos+n <= len(r.data), "unexpected end of Java stream")
	out := r.data[r.pos : r.pos+n]
	r.pos += n
	return out
}

func (r *sipReader) u1() byte    { return r.take(1)[0] }
func (r *sipReader) u2() uint16  { return binary.BigEndian.Uint16(r.take(2)) }
func (r *sipReader) u4() uint32  { return binary.BigEndian.Uint32(r.take(4)) }
func (r *sipReader) u8() uint64  { return binary.BigEndian.Uint64(r.take(8)) }
func (r *sipReader) str() string { return sipModifiedUTF8(r.take(int(r.u2()))) }
func (r *sipReader) peek() byte {
	sipRequire(r.pos < len(r.data), "unexpected end of Java stream")
	return r.data[r.pos]
}
func (r *sipReader) add(v any) any { r.handles = append(r.handles, v); return v }

func (r *sipReader) longStr() string {
	n := r.u8()
	sipRequire(n <= uint64(len(r.data)), "Java string too long")
	return sipModifiedUTF8(r.take(int(n)))
}

func (r *sipReader) ref() any {
	index := int(r.u4()) - 0x7e0000
	sipRequire(index >= 0 && index < len(r.handles), "invalid Java reference")
	return r.handles[index]
}

func (r *sipReader) content() any {
	switch tag := r.u1(); tag {
	case 0x70:
		return nil
	case 0x71:
		return r.ref()
	case 0x73:
		desc := r.desc()
		sipRequire(desc != nil, "null object class")
		obj := &sipObject{class: desc.name, fields: make(map[string]any, len(desc.fields))}
		r.add(obj)
		r.classData(desc, obj)
		return obj
	case 0x74:
		return r.add(r.str())
	case 0x7c:
		return r.add(r.longStr())
	case 0x75:
		desc := r.desc()
		sipRequire(desc != nil && len(desc.name) >= 2, "invalid Java array")
		count := int(r.u4())
		sipRequire(count >= 0 && count <= len(r.data), "invalid Java array")
		array := make([]any, count)
		r.add(array)
		kind := desc.name[1]
		primitive := kind == 'B' || kind == 'Z' || kind == 'C' || kind == 'S' || kind == 'I' || kind == 'J' || kind == 'F' || kind == 'D'
		for i := range array {
			if primitive {
				array[i] = r.value(kind)
			} else {
				array[i] = r.content()
			}
		}
		return array
	case 0x77:
		return append([]byte(nil), r.take(int(r.u1()))...)
	case 0x7a:
		return append([]byte(nil), r.take(int(r.u4()))...)
	case 0x78:
		return nil
	case 0x79:
		r.handles = nil
		return r.content()
	case 0x7e:
		desc := r.desc()
		sipRequire(desc != nil, "null enum class")
		index := len(r.handles)
		r.handles = append(r.handles, nil)
		enum := map[string]any{"class": desc.name, "enum": r.content()}
		r.handles[index] = enum
		return enum
	default:
		sipFail("unsupported Java token 0x%02x", tag)
		return nil
	}
}

func (r *sipReader) desc() *sipDesc {
	switch tag := r.u1(); tag {
	case 0x70:
		return nil
	case 0x71:
		desc, ok := r.ref().(*sipDesc)
		sipRequire(ok, "invalid Java class reference")
		return desc
	case 0x72:
	default:
		sipFail("expected Java class descriptor, got 0x%02x", tag)
	}
	desc := &sipDesc{name: r.str()}
	r.take(8)
	r.add(desc)
	r.u1()
	count := int(r.u2())
	desc.fields = make([]sipField, 0, count)
	for range count {
		kind := r.u1()
		field := sipField{name: r.str(), kind: kind}
		if kind == 'L' || kind == '[' {
			value, ok := r.content().(string)
			sipRequire(ok, "invalid Java field type")
			field.typ = value
		}
		desc.fields = append(desc.fields, field)
	}
	for r.peek() != 0x78 {
		r.content()
	}
	r.pos++
	desc.super = r.desc()
	return desc
}

func (r *sipReader) classData(desc *sipDesc, obj *sipObject) {
	if desc == nil {
		return
	}
	r.classData(desc.super, obj)
	for _, field := range desc.fields {
		obj.fields[field.name] = r.value(field.kind)
	}
}

func (r *sipReader) value(kind byte) any {
	switch kind {
	case 'B':
		return int8(r.u1())
	case 'Z':
		return r.u1() != 0
	case 'C':
		return r.u2()
	case 'S':
		return int16(r.u2())
	case 'I':
		return int32(r.u4())
	case 'J':
		return int64(r.u8())
	case 'F':
		return math.Float32frombits(r.u4())
	case 'D':
		return math.Float64frombits(r.u8())
	case 'L', '[':
		return r.content()
	}
	sipFail("unsupported Java field type %q", kind)
	return nil
}

func sipModifiedUTF8(data []byte) string {
	runes := make([]rune, 0, len(data))
	for i := 0; i < len(data); {
		switch c := data[i]; {
		case c < 0x80:
			runes = append(runes, rune(c))
			i++
		case c&0xe0 == 0xc0 && i+1 < len(data):
			runes = append(runes, rune(c&0x1f)<<6|rune(data[i+1]&0x3f))
			i += 2
		case c&0xf0 == 0xe0 && i+2 < len(data):
			runes = append(runes, rune(c&0x0f)<<12|rune(data[i+1]&0x3f)<<6|rune(data[i+2]&0x3f))
			i += 3
		case c&0xf8 == 0xf0 && i+3 < len(data):
			runes = append(runes, rune(c&0x07)<<18|rune(data[i+1]&0x3f)<<12|rune(data[i+2]&0x3f)<<6|rune(data[i+3]&0x3f))
			i += 4
		default:
			runes = append(runes, utf8.RuneError)
			i++
		}
	}
	out := runes[:0]
	for i := 0; i < len(runes); i++ {
		if utf16.IsSurrogate(runes[i]) && i+1 < len(runes) {
			if decoded := utf16.DecodeRune(runes[i], runes[i+1]); decoded != utf8.RuneError {
				out = append(out, decoded)
				i++
				continue
			}
		}
		out = append(out, runes[i])
	}
	return string(out)
}
