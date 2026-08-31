package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mazznoer/colorgrad"
	"github.com/muesli/termenv"
	"golang.org/x/term"

	"Pantegnos/internal/modules"
	"Pantegnos/internal/utils"

	_ "Pantegnos/internal/modules/impl"
)

// version is set by goreleaser via -ldflags "-X main.version=...".
var version = "dev"

var (
	inputDir  = flag.String("input", "configs", "input directory containing config files")
	outputDir = flag.String("output", "output", "directory to save decrypted files")
)

const banner = `
██████╗  █████╗ ███╗   ██╗████████╗███████╗ ██████╗ ███╗   ██╗ ██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝██╔════╝██╔════╝ ████╗  ██║██╔═══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║   ██║   █████╗  ██║  ███╗██╔██╗ ██║██║   ██║███████╗
██╔═══╝ ██╔══██║██║╚██╗██║   ██║   ██╔══╝  ██║   ██║██║╚██╗██║██║   ██║╚════██║
██║     ██║  ██║██║ ╚████║   ██║   ███████╗╚██████╔╝██║ ╚████║╚██████╔╝███████║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
                                                              (c) 2026 KernelDotDLL`

const disclaimer = `
  ┌───────────────────────────────────────────────────────────────────────┐
  │ PANTEGNOS :: Multi-Config Decryptor v%-32s                            │
  ├───────────────────────────────────────────────────────────────────────┤
  │ SUPPORTED: .slip  .ehi  .dark  .hat  .npvt  .npvs  .nm  .happ         │
  ├───────────────────────────────────────────────────────────────────────┤
  │ LEGAL NOTICE & LIABILITY WAIVER                                       │
  │                                                                       │
  │ The user of this software assumes all responsibility and risk for its │
  │ application. This tool is provided "as-is" without any warranties.    │
  │                                                                       │
  │ The author (KernelDotDLL) shall not be held liable for any damages,   │
  │ legal consequences, or misuse arising from the operation of this      │
  │ software. It is the user's sole obligation to ensure that all actions │
  │ comply with local, state, and international regulations.              │
  └───────────────────────────────────────────────────────────────────────┘`

func main() {
	printBanner()

	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if err := os.MkdirAll(*inputDir, 0o755); err != nil {
		fatal("Error with input directory %s: %v", *inputDir, err)
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fatal("Error creating output directory %s: %v", *outputDir, err)
	}

	entries, err := os.ReadDir(*inputDir)
	if err != nil {
		fatal("Error reading directory %s: %v", *inputDir, err)
	}

	succeeded := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if processFile(filepath.Join(*inputDir, entry.Name())) {
			succeeded++
		}
	}

	fmt.Printf("All files processed. (%d succeeded)\n", succeeded)
	time.Sleep(5 * time.Second)
}

func printBanner() {
	terminal := termenv.NewOutput(os.Stdout)
	terminal.ClearScreen()
	terminal.DisableMouse()
	fmt.Println(utils.ColorizeGradientText(banner, colorgrad.Oranges()))
	fmt.Println(utils.ColorizeGradientText(fmt.Sprintf(disclaimer, version), colorgrad.Reds()))
}

func fatal(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
	os.Exit(1)
}

func processFile(path string) bool {
	fmt.Println("Decrypting:", path)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", path, err)
		return false
	}

	mod, proto, payload := modules.Lookup(path, data)
	if mod == nil {
		if proto == "" {
			fmt.Printf("Invalid format in %s: missing protocol separator '://'\n", path)
		} else {
			fmt.Printf("No matching module found for file: %s\n", path)
		}
		return false
	}

	password := ""
	if mod.NeedsPassword != nil && mod.NeedsPassword(proto, payload) {
		fmt.Print(utils.ColorizeGradientText("Enter password: ", colorgrad.Oranges()))
		password = promptPassword()
		fmt.Println()
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
		return false
	}

	if result.Echo {
		fmt.Println(result.Text)
	}

	if result.FileName == "" {
		return true
	}

	outPath := filepath.Join(*outputDir, result.FileName)
	if err := os.WriteFile(outPath, []byte(result.Text), 0o644); err != nil {
		fmt.Printf("Error writing %s: %v\n", outPath, err)
		return false
	}
	fmt.Printf("[+] Saved to: %s\n", outPath)
	return true
}

func promptPassword() string {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		if err == nil {
			return strings.TrimSpace(string(pw))
		}
	}

	var input string
	_, _ = fmt.Scanln(&input)
	return strings.TrimSpace(input)
}
