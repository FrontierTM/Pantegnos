package modules

var Registry []Module

type Module struct {
	Name      string
	ApkAuthor string
	Proto     []string
	Extension string
	Exec      func(proto, payload, extension, file, outputDir string)
}

func Register(m Module) {
	Registry = append(Registry, m)
}
