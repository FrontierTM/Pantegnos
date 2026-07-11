package impl

import (
	"Pantegnos/modules"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	L1Key        = []byte{0x7e, 0x12, 0x10, 0xf7, 0xaa, 0xb9, 0x56, 0xf7, 0xa6, 0x68, 0xbd, 0xa6, 0xe5, 0x7f, 0xed, 0xdb, 0x7f, 0x84, 0xad, 0x84, 0x0a, 0xef, 0x8d, 0x27, 0xb1, 0xb9, 0x69, 0x95, 0x9b, 0xe3, 0xab, 0x6c}
	L2KeyStatic  = []byte{0xb2, 0xbc, 0x61, 0x7c, 0x32, 0xd8, 0xb9, 0xeb, 0x19, 0x43, 0xa5, 0xff, 0xa8, 0x05, 0x1e, 0xea}
	EooMasterKey = []byte("null=V5kU5+FFrY\x00")

	SideIvs = [][]byte{
		{0x22, 0x1d, 0x57, 0x23, 0x49, 0x55, 0x5f, 0x1d, 0x11, 0x21, 0x33, 0x23, 0x6b, 0x1f, 0x4a, 0x3f},
		{0x55, 0x43, 0x49, 0x4c, 0x53, 0x44, 0x3e, 0x3f, 0x4a, 0x6a, 0x45, 0x39, 0x38, 0x4e, 0x77, 0x6a},
		{0x37, 0x4c, 0x25, 0x41, 0x57, 0x5e, 0x4d, 0x53, 0x1a, 0x3c, 0x32, 0x7b, 0x75, 0x43, 0x1e, 0x5f},
	}

	StandardIvs = [][]byte{
		{0x2c, 0x5d, 0x11, 0x47, 0xbb, 0xad, 0x42, 0x2b, 0x3b, 0x33, 0x4d, 0x4d, 0x23, 0x5f, 0x1a, 0x53},
		{0x52, 0x2b, 0x01, 0x43, 0x3a, 0x5e, 0x8b, 0x2f, 0xc7, 0x54, 0x9e, 0x1a, 0xd3, 0x68, 0xe5, 0x41},
		{0x33, 0x7a, 0x10, 0x35, 0xaa, 0xed, 0xf3, 0x45, 0x8c, 0xa1, 0x67, 0xe9, 0x2d, 0x74, 0xb8, 0x39},
	}

	allIVs         = append(append([][]byte{}, SideIvs...), StandardIvs...)
	CustomAlphabet = "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
	customEncoding = base64.NewEncoding(CustomAlphabet)
)

func init() {
	modules.Register(modules.Module{
		Name:      "HTTP Injector (SSH/V2ray) - Native",
		ApkAuthor: "https://play.google.com/store/apps/details?id=com.evozi.injector",
		Proto:     []string{""},
		Extension: ".ehi",
		Exec: func(proto, payload, extension, file, outputDir string) {
			decryptedString, err := DecryptEHI([]byte(payload))
			if err != nil {
				fmt.Printf("[!] Decryption error for %s: %v\n", file, err)
				return
			}

			outputFile := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(file), ".ehi")+".txt")

			if err := os.WriteFile(outputFile, []byte(decryptedString), 0644); err != nil {
				fmt.Printf("[!] Error writing final dump to %s: %v\n", outputFile, err)
				return
			}
		},
	})
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func customB64Decode(encodedStr string) ([]byte, error) {
	cleanStr := strings.ReplaceAll(encodedStr, "?", "")
	if rem := len(cleanStr) % 4; rem != 0 {
		cleanStr += strings.Repeat("=", 4-rem)
	}
	return customEncoding.DecodeString(cleanStr)
}

func decryptXorLayer(ciphertextStr string, key string) (string, error) {
	if strings.TrimSpace(ciphertextStr) == "" {
		return ciphertextStr, nil
	}

	reversed := reverseString(ciphertextStr)
	hexBytesRaw, err := customB64Decode(reversed)
	if err != nil {
		return "", err
	}

	hexStr := string(hexBytesRaw)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	rawBytes, err := hexToBytes(hexStr)
	if err != nil {
		return "", err
	}

	keyLen := len(key)
	decryptedBytes := make([]byte, 0, len(rawBytes))
	for i, b := range rawBytes {
		xorVal := b ^ key[i%keyLen]
		if xorVal != 0 {
			decryptedBytes = append(decryptedBytes, xorVal)
		}
	}

	plaintext := string(decryptedBytes)
	if len(plaintext) > 0 {
		badChars := 0
		for _, c := range plaintext {
			if c < 32 && c != 9 && c != 10 && c != 13 {
				badChars++
			}
		}
		if float64(badChars)/float64(len(plaintext)) > 0.5 {
			return "", errors.New("entropy check failed")
		}
	}

	return plaintext, nil
}

func decodeConfigMessage(ciphertextStr string) string {
	if strings.TrimSpace(ciphertextStr) == "" {
		return ciphertextStr
	}

	paddedStr := ciphertextStr
	if rem := len(paddedStr) % 4; rem != 0 {
		paddedStr += strings.Repeat("=", 4-rem)
	}

	rawBytes, err := base64.StdEncoding.DecodeString(paddedStr)
	if err != nil {
		return ciphertextStr
	}

	utf16Runes := utf16.Encode([]rune(string(rawBytes)))

	keyChars := []uint16{'E', 'H', 'I', 'M', 'S', 'G'}
	keyLen := len(keyChars)

	xoredChars := make([]uint16, len(utf16Runes))
	for i, jc := range utf16Runes {
		xoredChars[i] = jc ^ keyChars[i%keyLen]
	}

	return string(utf16.Decode(xoredChars))
}

func nativeXxteaDecrypt(data []byte, key []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}

	if rem := len(data) % 4; rem != 0 {
		padded := make([]byte, len(data)+(4-rem))
		copy(padded, data)
		data = padded
	}

	k := make([]uint32, 4)
	paddedKey := make([]byte, 16)
	copy(paddedKey, key)
	for i := 0; i < 4; i++ {
		k[i] = binary.LittleEndian.Uint32(paddedKey[i*4 : (i+1)*4])
	}

	n := len(data) / 4
	v := make([]uint32, n)
	for i := 0; i < n; i++ {
		v[i] = binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
	}

	const delta uint32 = 0x9e3779b9
	rounds := 6 + 52/uint32(n)
	sumVal := (rounds * delta) & 0xffffffff
	y := v[0]

	for sumVal != 0 {
		e := (sumVal >> 2) & 3
		for p := n - 1; p > 0; p-- {
			z := v[p-1]
			mx := (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sumVal ^ y) + (k[(uint32(p)&3)^e] ^ z))
			v[p] = (v[p] - mx) & 0xffffffff
			y = v[p]
		}
		z := v[n-1]
		mx := (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sumVal ^ y) + (k[(0&3)^e] ^ z))
		v[0] = (v[0] - mx) & 0xffffffff
		y = v[0]
		sumVal = (sumVal - delta) & 0xffffffff
	}

	decrypted := make([]byte, n*4)
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(decrypted[i*4:(i+1)*4], v[i])
	}

	length := v[n-1]
	if length > 0 && int(length) <= n*4 {
		return decrypted[:length]
	}
	return bytes.TrimRight(decrypted, "\x00")
}

func parseEhiBytes(fileBytes []byte) ([]byte, error) {
	r := bytes.NewReader(fileBytes)

	readUTF := func() (string, error) {
		var l uint16
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return "", err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}

	if _, err := readUTF(); err != nil {
		return nil, err
	}
	r.Seek(8, io.SeekCurrent)
	if _, err := readUTF(); err != nil {
		return nil, err
	}
	r.Seek(8, io.SeekCurrent)

	var pLen uint32
	if err := binary.Read(r, binary.BigEndian, &pLen); err != nil {
		return nil, err
	}
	r.Seek(8, io.SeekCurrent)

	payload := make([]byte, pLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func pyStr(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func pyTruthy(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		return t != 0
	default:
		return true
	}
}

var masterKeyFields = []struct {
	key          string
	alwaysString bool
}{
	{"configAesKey", false},
	{"configIdentifier", false},
	{"configSalt", false},
	{"configTimestamp", true},
	{"configExpiryTimestamp", true},
	{"lockModes", false},
	{"lockModesHash", false},
	{"configHwid", false},
	{"configLockMobileOperatorId", false},
}

func generateMasterKey(config map[string]interface{}) []byte {
	var sb strings.Builder
	for _, f := range masterKeyFields {
		val, exists := config[f.key]

		if f.alwaysString {
			if !exists {
				val = float64(0)
			}
			sb.WriteString(pyStr(val))
			continue
		}

		if !exists {
			val = ""
		}
		if pyTruthy(val) {
			sb.WriteString(pyStr(val))
		}
	}

	sum := sha256.Sum256([]byte(sb.String()))
	return sum[:]
}

func pkcs7Unpadd(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padding length")
	}
	padLen := int(data[len(data)-1])
	if padLen < 1 || padLen > blockSize {
		return nil, errors.New("invalid padding char")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("invalid padding sequence")
		}
	}
	return data[:len(data)-padLen], nil
}

func aesCbcDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext block error")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpadd(plaintext, aes.BlockSize)
}

func hexToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func cleanInnerFields(config map[string]interface{}, saltKey string) map[string]interface{} {
	cleaned := make(map[string]interface{}, len(config))
	vitalKeys := map[string]bool{"overwriteServerData": true}

	for k, v := range config {
		valStr, ok := v.(string)
		if !ok || strings.TrimSpace(valStr) == "" {
			cleaned[k] = v
			continue
		}

		var decryptedVal string
		var err error
		if k == "configMessage" {
			decryptedVal = decodeConfigMessage(valStr)
		} else {
			decryptedVal, err = decryptXorLayer(valStr, saltKey)
		}

		if err == nil && decryptedVal != "" {
			cleaned[k] = decryptedVal
		} else if vitalKeys[k] {
			cleaned[k] = v
		}
	}
	return cleaned
}

func tryNestedJsonParse(rawStr string) (interface{}, bool) {
	startIdx := strings.Index(rawStr, "{")
	endIdx := strings.LastIndex(rawStr, "}")
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return nil, false
	}

	var parsedObj interface{}
	if err := json.Unmarshal([]byte(rawStr[startIdx:endIdx+1]), &parsedObj); err != nil {
		return nil, false
	}

	if strVal, ok := parsedObj.(string); ok {
		var innerObj interface{}
		if err := json.Unmarshal([]byte(strVal), &innerObj); err == nil {
			return innerObj, true
		}
	}
	return parsedObj, true
}

func DecryptEHI(fileBytes []byte) (string, error) {
	payload, err := parseEhiBytes(fileBytes)
	if err != nil || len(payload) == 0 {
		return "", errors.New("failed parsing EHI structure")
	}

	var config map[string]interface{}
	isBypass := false

	for idx, iv := range allIVs {
		l1Dec, err := aesCbcDecrypt(payload, L1Key, iv)
		if err != nil {
			continue
		}

		parts := strings.Split(string(l1Dec), ":")
		if len(parts) < 3 {
			continue
		}

		iv2, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}

		garbageRaw, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			continue
		}

		garbage, err := aesCbcDecrypt(garbageRaw, L2KeyStatic, iv2)
		if err != nil {
			continue
		}

		finalRaw := nativeXxteaDecrypt(garbage, EooMasterKey)
		startIdx := bytes.IndexByte(finalRaw, '{')
		if startIdx == -1 {
			continue
		}

		if err := json.Unmarshal(finalRaw[startIdx:], &config); err == nil {
			isBypass = idx < len(SideIvs)
			break
		}
	}

	if config == nil {
		return "", errors.New("decryption signature mismatch across standard matrix maps")
	}

	targetSalt := "EVZJNI"
	if s, ok := config["configSalt"].(string); ok && s != "" {
		targetSalt = s
	}

	var parsedFinal map[string]interface{}

	if isBypass {
		parsedFinal = config
	} else {
		targetData, _ := config["configData"].(string)
		aaaResult, err := decryptXorLayer(targetData, targetSalt)
		if err != nil {
			return "", fmt.Errorf("xor layer decryption failure: %w", err)
		}

		rawPayload, err := base64.StdEncoding.DecodeString(aaaResult)
		if err != nil || len(rawPayload) <= 50 {
			return "", errors.New("malformed secondary raw payload length parameters")
		}

		timeCost := binary.LittleEndian.Uint32(rawPayload[1:5])
		memoryCost := binary.LittleEndian.Uint32(rawPayload[5:9])
		parallelism := rawPayload[9]

		salt := rawPayload[0x0a:0x1a]
		nonce := rawPayload[0x1a:0x32]
		aad := rawPayload[:0x1a]

		masterKey := generateMasterKey(config)
		argonKey := argon2.IDKey(masterKey, salt, timeCost, memoryCost, parallelism, 32)

		aead, err := chacha20poly1305.NewX(argonKey)
		if err != nil {
			return "", err
		}

		decryptedJsonBytes, err := aead.Open(nil, nonce, rawPayload[0x32:], aad)
		if err != nil {
			return "", err
		}

		if err := json.Unmarshal(decryptedJsonBytes, &parsedFinal); err != nil {
			return "", err
		}
	}

	cleanedFinalJson := cleanInnerFields(parsedFinal, targetSalt)

	for _, jsonField := range []string{"v2rRawJson", "overwriteServerData"} {
		if rawStr, ok := cleanedFinalJson[jsonField].(string); ok {
			if parsedObj, success := tryNestedJsonParse(rawStr); success {
				cleanedFinalJson[jsonField] = parsedObj
			}
		}
	}

	prettyJSON, err := json.MarshalIndent(cleanedFinalJson, "", "    ")
	if err != nil {
		return "", err
	}

	return string(prettyJSON), nil
}
