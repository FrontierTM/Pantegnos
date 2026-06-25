# Pantegnos

[![Stars](https://img.shields.io/github/stars/FrontierTM/Pantegnos?style=flat-square)](https://github.com/FrontierTM/Pantegnos/stargazers)
[![Forks](https://img.shields.io/github/forks/FrontierTM/Pantegnos?style=flat-square)](https://github.com/FrontierTM/Pantegnos/network/members)
[![Issues](https://img.shields.io/github/issues/FrontierTM/Pantegnos?style=flat-square)](https://github.com/FrontierTM/Pantegnos/issues)
[![Go](https://img.shields.io/badge/Go-1.26.3+-00ADD8?style=flat-square&logo=go)](https://go.dev/)

A command-line decryptor for VPN and proxy configuration files used by various Android and desktop clients. Pantegnos extracts readable server metadata from encrypted proprietary formats, making it useful for security researchers analyzing these tools.

## Supported Formats

| Format | Extension | Protocol | Module |
|--------|-----------|----------|--------|
| SlipNet (Encrypted) | `.slip` | `slipnet-enc://` | AES-256-GCM with hardcoded key |
| SlipNet (Plaintext) | `.slip` | `slipnet://` | Base64 decode + profile parse |
| SlipNet Bundle (Password) | `.slip` | `slipnet-bundle-enc://` | PBKDF2 (600k iter) + AES-GCM |
| HA Tunnel Plus | `.hat` | *(extension-based)* | AES-ECB (SHA1-derived key) |
| NpvTunnel (NapsternetV) | `.npvt` | `NPVT1` | Custom whitebox AES CTR |
| NetMod | `.nm` | `nm-*://` | AES-ECB (fixed key) |
| Happ Proxy | `.happ` | `happ://crypt[1-4]/` | RSA-1024/4096 private key |

SlipNet profiles support schema versions 1 through 28, covering fields like VLESS, SSH tunneling, SOCKS5, DoH, SNI fragmentation, and more.

## Usage

1. Place your encrypted config files in a `configs/` directory (or use `-input` to specify one).

2. Run the tool:

```bash
chmod +x Pantegnos
./Pantegnos -input configs -output output
```

3. Decrypted files appear in the output directory as `.txt` files.

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | `configs` | Directory containing encrypted config files |
| `-output` | `output` | Directory where decrypted files are saved |

## Building

Requires **Go 1.26.3** or later.

```bash
go build -o pantegnos .
```

For cross-compilation:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o pantegnos-linux .

# Windows
GOOS=windows GOARCH=amd64 go build -o pantegnos-win.exe .
```

Pre-built binaries are available in the [Releases](https://github.com/KernelDotDLL/Pantegnos/releases) section.

## Dependencies

- [colorgrad](https://github.com/mazznoer/colorgrad) — Terminal gradient text
- [termenv](https://github.com/muesli/termenv) — Terminal capabilities
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) — PBKDF2 key derivation
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) — Secure password input (bundle mode)

## License

Copyright (c) 2026 FrontierTM. Licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

*This tool is provided as-is for security research purposes. Users are responsible for ensuring their use complies with applicable laws.*
