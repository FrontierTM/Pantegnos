// Package modules hosts the decryptor registry shared by the CLI and the
// browser (WASM) frontend. Modules register pure decrypt functions; the
// frontends own all input, output, and prompting.
package modules

import (
	"path/filepath"
	"strings"
)

// Request carries everything a module needs to process one file.
type Request struct {
	FileName string // original file name, used for output naming
	Data     []byte // raw file bytes
	Proto    string // scheme before "://", or "" when absent
	Payload  string // content after "://", or the full content when absent
	Password string // empty unless NeedsPassword reported true
}

// Result is the outcome of a successful decrypt.
type Result struct {
	Text     string // decrypted, formatted content
	FileName string // suggested output file name; "" means display only
	Echo     bool   // the CLI should also print Text to stdout
}

// Module describes one supported config format.
type Module struct {
	Name          string
	ApkAuthor     string
	Proto         []string
	Extension     string
	NeedsPassword func(proto, payload string) bool
	Decrypt       func(req Request) (Result, error)
}

// Registry holds every registered module.
var Registry []Module

// Register adds a module to the registry.
func Register(m Module) {
	Registry = append(Registry, m)
}

// Find returns the module handling the given extension or protocol.
// Extension matches win; protocol matches support a trailing * wildcard.
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

// Lookup splits file content and finds the module for it in one step.
func Lookup(fileName string, content []byte) (mod *Module, proto, payload string) {
	proto, payload = SplitContent(strings.TrimSpace(string(content)))
	return Find(filepath.Ext(fileName), proto), proto, payload
}

// SplitContent separates a "scheme://payload" config into scheme and payload.
// Content without a separator yields an empty scheme and the full content.
func SplitContent(content string) (proto, payload string) {
	proto, payload, found := strings.Cut(content, "://")
	if !found {
		return "", content
	}
	return proto, payload
}

// Stem returns the base file name without its literal extension.
func Stem(fileName, ext string) string {
	return strings.TrimSuffix(filepath.Base(fileName), ext)
}

// OutputName derives the default output file name for an input file.
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
