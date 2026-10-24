package mobile

import "strings"

// PickedFile is one file the user chose, already read into memory by the host.
type PickedFile struct {
	Name string `json:"name"`
	B64  string `json:"b64"`
}

// knownPrefixes maps a URI scheme prefix to the extension the core understands,
// so a pasted config is named the way the file picker would have named it.
var knownPrefixes = []struct {
	prefix string
	ext    string
}{
	{"slipnet", ".slip"},
	{"darktunnel", ".dark"},
	{"happ", ".happ"},
	{"nm", ".nm"},
	{"npvs", ".npvs"},
	{"npvt", ".npvt"},
	{"v2box", ".v2box"},
	{"zedsecure", ".zsx"},
}

const schemeSeparator = "://"

// schemeChars matches the scheme shapes the core actually produces, including
// the `happ/crypt1` variant.
func validScheme(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '+' || r == '.' || r == '-' || r == '_' || r == '/':
		default:
			return false
		}
	}
	return true
}

// ParseClipboard turns pasted text into a virtual config file. It returns false
// when the clipboard does not hold a config URI, which is the common case and
// must stay quiet rather than enqueueing junk.
func ParseClipboard(raw string) (PickedFile, bool) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return PickedFile{}, false
	}
	scheme, _, ok := strings.Cut(text, schemeSeparator)
	if !ok || scheme == "" {
		return PickedFile{}, false
	}
	if !validScheme(scheme) {
		return PickedFile{}, false
	}
	ext := ""
	for _, known := range knownPrefixes {
		if strings.HasPrefix(strings.ToLower(scheme), known.prefix) {
			ext = known.ext
			break
		}
	}
	if ext == "" {
		return PickedFile{}, false
	}
	return PickedFile{Name: "clipboard" + ext, B64: encodeBase64([]byte(text))}, true
}
