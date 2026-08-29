package modules

import (
	"path/filepath"
	"strings"
)

type Request struct {
	FileName string
	Data     []byte
	Proto    string
	Payload  string
	Password string
}

type Result struct {
	Text     string
	FileName string
	Echo     bool
}

type Module struct {
	Name          string
	ApkAuthor     string
	Proto         []string
	Extension     string
	NeedsPassword func(proto, payload string) bool
	Decrypt       func(req Request) (Result, error)
}

var Registry []Module

func Register(m Module) {
	Registry = append(Registry, m)
}

func Find(extension, proto string) *Module {
	for i := range Registry {
		if Registry[i].Extension == extension {
			return &Registry[i]
		}
	}

	for i := range Registry {
		if matchProto(Registry[i].Proto, proto) {
			return &Registry[i]
		}
	}
	return nil
}

func Lookup(fileName string, content []byte) (mod *Module, proto, payload string) {
	proto, payload = SplitContent(string(content))
	return Find(filepath.Ext(fileName), proto), proto, payload
}

func SplitContent(content string) (proto, payload string) {
	start := 0
	for start < len(content) && isSpaceByte(content[start]) {
		start++
	}
	for i := start; i < len(content); i++ {
		c := content[i]
		if c == ':' {
			if i > start && strings.HasPrefix(content[i:], "://") {
				return content[start:i], content[i+3:]
			}
			return "", content
		}
		if !isSchemeChar(c) {
			return "", content
		}
	}
	return "", content
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

func Stem(fileName, ext string) string {
	return strings.TrimSuffix(filepath.Base(fileName), ext)
}

func OutputName(fileName, ext string) string {
	return Stem(fileName, ext) + ".txt"
}

func matchProto(patterns []string, proto string) bool {
	for _, pattern := range patterns {
		if prefix, wild := strings.CutSuffix(pattern, "*"); wild {
			if strings.HasPrefix(proto, prefix) {
				return true
			}
			continue
		}
		if pattern == proto {
			return true
		}
	}
	return false
}
