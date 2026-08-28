package main

import (
	"Pantegnos/internal/modules"
	"Pantegnos/internal/utils"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mazznoer/colorgrad"
	"github.com/muesli/termenv"
	"golang.org/x/term"

	_ "Pantegnos/internal/modules/impl"
)

var (
	InputDir  string
	OutputDir string
	terminal  = termenv.NewOutput(os.Stdout)

	// version is set by goreleaser via -ldflags "-X main.version=...".
	version = "dev"
)

const banner = `
░█████████                           ░██
░██     ░██                          ░██
░██     ░██  ░██████   ░████████  ░████████  ░███████   ░████████ ░████████   ░███████   ░███████
░█████████        ░██  ░██    ░██    ░██    ░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██ ░██
░██          ░███████  ░██    ░██    ░██    ░█████████ ░██    ░██ ░██    ░██ ░██    ░██  ░███████
░██         ░██   ░██  ░██    ░██    ░██    ░██        ░██   ░███ ░██    ░██ ░██    ░██        ░██
░██          ░█████░██ ░██    ░██     ░████  ░███████   ░█████░██ ░██    ░██  ░███████   ░███████
                                                              ░██
                                                        ░███████
																	(c) 2026 | KernelDotDLL
`
const disclaimer = `
		┌─────────────────────────── [    T\[T]/T    ] ───────────────────────────┐
		│ PANTEGNOS :: Multi-Config Decryptor v%s                                  │           
		├─────────────────────────────────────────────────────────────────────────┤
		│ SUPPORTED: .nm, .slip (v28), any many more soon..                       │             
		├─────────────────────────────────────────────────────────────────────────┤
		│ [!] LEGAL NOTICE & LIABILITY WAIVER                                     │
		│                                                                         │
		│ The user of this software assumes all responsibility and risk for its   │
		│ application. This tool is provided "as-is" without any warranties.      │
		│                                                                         │
		│ The author (KernelDotDLL) shall not be held liable for any damages,     │
		│ legal consequences, or misuse arising from the operation of this        │
		│ software. It is the user's sole obligation to ensure that all actions   │
		│ comply with local, state, and international regulations.                │
		└─────────────────────────────────────────────────────────────────────────┘`

func init() {
	terminal.ClearScreen()
	terminal.DisableMouse()

	fmt.Println(utils.ColorizeGradientText(banner, colorgrad.Oranges()))
	fmt.Println(utils.ColorizeGradientText(fmt.Sprintf(disclaimer, version), colorgrad.Reds()))

	flag.StringVar(&InputDir, "input", "configs", "Input directory containing .nm files")
	flag.StringVar(&OutputDir, "output", "output", "Directory to save decrypted files")
	flag.Parse()
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	if err := os.MkdirAll("configs", 0755); err != nil {
		panic(err)
	}
	if err := os.MkdirAll("output", 0755); err != nil {
		panic(err)
	}

	entries, err := os.ReadDir(InputDir)
	if err != nil {
		fmt.Printf("Error reading directory %s: %v\n", InputDir, err)
		return
	}

	if err := os.MkdirAll(OutputDir, os.ModePerm); err != nil {
		fmt.Println("Error creating output directory:", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		processFile(filepath.Join(InputDir, entry.Name()))
	}

	fmt.Println("All files processed.")
	time.Sleep(time.Second * 5)
}

func processFile(path string) {
	fmt.Println("Decrypting:", path)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", path, err)
		return
	}

	mod, proto, payload := modules.Lookup(path, data)
	if mod == nil {
		if proto == "" {
			fmt.Printf("Invalid format in %s: missing protocol separator '://'\n", path)
		} else {
			fmt.Printf("No matching module found for file: %s\n", path)
		}
		return
	}

	password := ""
	if mod.NeedsPassword != nil && mod.NeedsPassword(proto, payload) {
		fmt.Print(utils.ColorizeGradientText("Enter password: ", colorgrad.Oranges()))
		password = promptPassword()
		fmt.Println()
		if password == "" {
			fmt.Println("[!] Password cannot be empty")
			return
		}
	}

	fmt.Printf("[Success] Module '%s' handling file: %s\n", mod.Name, path)

	result, err := mod.Decrypt(modules.Request{
		FileName: path,
		Data:     data,
		Proto:    proto,
		Payload:  payload,
		Password: password,
	})
	if err != nil {
		fmt.Printf("[!] Error decrypting %s: %v\n", path, err)
		return
	}

	if result.Echo {
		fmt.Println(result.Text)
	}

	if result.FileName == "" {
		return
	}

	outputFile := filepath.Join(OutputDir, result.FileName)
	if err := os.WriteFile(outputFile, []byte(result.Text), 0644); err != nil {
		fmt.Printf("Error writing %s: %v\n", outputFile, err)
		return
	}
	fmt.Printf("[+] Saved to: %s\n", outputFile)
}

func promptPassword() string {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err == nil {
			return strings.TrimSpace(string(pw))
		}
	}

	var input string
	_, _ = fmt.Scanln(&input)
	return strings.TrimSpace(input)
}
