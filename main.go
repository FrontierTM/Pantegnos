package main

import (
	"Pantegnos/modules"
	"Pantegnos/utils"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mazznoer/colorgrad"
	"github.com/muesli/termenv"

	_ "Pantegnos/modules/impl"
)

var (
	InputDir  string
	OutputDir string
	terminal  = termenv.NewOutput(os.Stdout)
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
																	(c) 2026 | v2.8.5 | KernelDotDLL
`
const disclaimer = `
		┌─────────────────────────── [    T\[T]/T    ] ───────────────────────────┐
		│ PANTEGNOS :: Multi-Config Decryptor v2.8.5                              │           
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
	fmt.Println(utils.ColorizeGradientText(disclaimer, colorgrad.Reds()))

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

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(InputDir, entry.Name()))
		}
	}

	if err := os.MkdirAll(OutputDir, os.ModePerm); err != nil {
		fmt.Println("Error creating output directory:", err)
		return
	}

	for _, file := range files {
		fmt.Println("Decrypting:", file)

		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", file, err)
			continue
		}

		content := strings.TrimSpace(string(data))
		fileExt := filepath.Ext(file)

		var protocol, payload string
		moduleFound := false

		for _, module := range modules.Registry {
			if module.Extension == fileExt {
				if strings.Contains(content, "://") {
					parts := strings.SplitN(content, "://", 2)
					protocol = parts[0]
					payload = parts[1]
				} else {
					protocol = ""
					payload = content
				}

				fmt.Printf("[Success] Module '%s' handling file via extension: %s\n", module.Name, file)
				module.Exec(protocol, payload, fileExt, file, OutputDir)
				moduleFound = true
				break
			}
		}

		if !moduleFound {
			if !strings.Contains(content, "://") {
				fmt.Printf("Invalid format in %s: missing protocol separator '://'\n", file)
				continue
			}

			parts := strings.SplitN(content, "://", 2)
			protocol = parts[0]
			payload = parts[1]

			for _, module := range modules.Registry {
				matchFound := false
				for _, protoPattern := range module.Proto {
					if strings.HasSuffix(protoPattern, "*") {
						prefix := strings.TrimSuffix(protoPattern, "*")
						if strings.HasPrefix(protocol, prefix) {
							matchFound = true
							break
						}
					} else if protocol == protoPattern {
						matchFound = true
						break
					}
				}

				if matchFound {
					fmt.Printf("[Success] Module '%s' handling file via protocol: %s\n", module.Name, file)
					module.Exec(protocol, payload, fileExt, file, OutputDir)
					moduleFound = true
					break
				}
			}
		}

		if !moduleFound {
			fmt.Printf("No matching module found for file: %s\n", file)
		}
	}
	fmt.Println("All files processed.")
	time.Sleep(time.Second * 5)
}
