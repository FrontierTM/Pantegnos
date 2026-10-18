<div align="center">
  <h2>
    <img src="internal/brand/logo.svg" width="64" height="64" alt="Pantegnos" valign="middle">
    Pantegnos
  </h2>

  <p>
    <a href="https://github.com/FrontierTM/Pantegnos/stargazers">
      <img src="https://img.shields.io/github/stars/FrontierTM/Pantegnos?style=flat-square" alt="Stars">
    </a>
    <a href="https://github.com/FrontierTM/Pantegnos/network/members">
      <img src="https://img.shields.io/github/forks/FrontierTM/Pantegnos?style=flat-square" alt="Forks">
    </a>
    <a href="https://github.com/FrontierTM/Pantegnos/issues">
      <img src="https://img.shields.io/github/issues/FrontierTM/Pantegnos?style=flat-square" alt="Issues">
    </a>
    <a href="https://go.dev/">
      <img src="https://img.shields.io/badge/Go-1.26.3+-00ADD8?style=flat-square&logo=go" alt="Go">
    </a>
    <a href="https://frontiertm.github.io/Pantegnos/">
      <img src="https://img.shields.io/badge/Web%20Decryptor-frontiertm.github.io%2FPantegnos-ff9e3d?style=flat-square" alt="Web Decryptor">
    </a>
    <a href="https://github.com/FrontierTM/Pantegnos/actions/workflows/android.yml">
      <img src="https://img.shields.io/badge/Android%20APK-Actions-3DDC84?style=flat-square&logo=github-actions" alt="Android APK">
    </a>
  </p>
</div>


A multi-platform decryptor for VPN and proxy configuration files used by various Android and desktop clients. Pantegnos extracts readable server metadata from encrypted proprietary formats, making it useful for security researchers analyzing these tools.

One decryption core, three front-ends: a **CLI**, an **in-browser decryptor** at [frontiertm.github.io/Pantegnos](https://frontiertm.github.io/Pantegnos/), and an **Android app** written in Go. Everything runs locally — no telemetry, no uploads.

## Supported Formats

| Format                                   | Extension        | Protocol                                                |
|------------------------------------------|------------------|---------------------------------------------------------|
| SlipNet (Encrypted / Plaintext / Bundle) | `.slip`          | `slipnet://`, `slipnet-enc://`, `slipnet-bundle-enc://` |
| HTTP Injector (SSH/V2ray) - Native       | `.ehi`           | *(extension-based)*                                     |
| DarkTunnel - SSH DNSTT V2Ray             | `.dark`          | `darktunnel://`                                         |
| HA Tunnel Plus                           | `.hat`           | *(extension-based)*                                     |
| NpvTunnel (NapsternetV) (NPVT / NPVS)    | `.npvt`, `.npvs` | `NPVT1`, `NPVS`                                         |
| NetMod (OLD & NEW)                       | `.nm`            | `nm-*://`                                               |
| Happ Proxy                               | `.happ`          | `happ://crypt[1-5]/`                                    |
| sing-box profile export (SFA/SFI/SFM)    | `.bpf`           | *(extension-based)*                                     |
| TLS Tunnel (SSH/proxy payload profiles)  | `.tls`           | *(extension-based)*                                     |
| ZedSecure                                | `.zsx`           | `zedsecure://`                                          |

SlipNet profiles support schema versions 1 through 28, covering fields like VLESS, SSH tunneling, SOCKS5, DoH, SNI fragmentation, and more.

## Web Decryptor

The full decryptor also runs in your browser — no install, files never leave your machine:

**[frontiertm.github.io/Pantegnos](https://frontiertm.github.io/Pantegnos/)**

The page hosts the same Go decryption core compiled to WebAssembly (`GOOS=js GOARCH=wasm ./cmd/wasm`), built and published automatically by GitHub Actions from the `web/` directory.

To build and serve it locally:

```bash
# Build the WASM bundle
GOOS=js GOARCH=wasm go build -o web/pantegnos.wasm ./cmd/wasm

# Copy the Go WASM runtime glue (path is GOROOT-dependent)
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/wasm_exec.js

# Serve with any static file server, e.g.
python -m http.server -d web 8000
```

`web/pantegnos.wasm` and `web/wasm_exec.js` are build artifacts and are not committed; CI regenerates them on every push to `main`.

## Android App

The same decryption core ships as an Android app in [`android/`](android) — and it is **written in Go**. `cmd/mobile` is the entire application: the queue, the passphrase handling, the translations and every pixel of the interface, compiled to `js/wasm` and rendered by the system WebView. The Kotlin side is a single ~350-line `MainActivity` that provides only what the platform reserves for the app process — the document picker, the share sheet, the clipboard, the system bars and persisted preferences.

The app declares **zero permissions**: no `INTERNET`, no storage. The WebView serves its page from a virtual `https` origin through `WebViewAssetLoader`, the client refuses every other URL, and without `INTERNET` the runtime physically cannot ship a config anywhere.

**Features**

- Pick one or many config files through the system file picker, or paste a `…://` config URI from the clipboard
- Sequential queue with per-file module identification (`.slip`, `.ehi`, `.dark`, `.hat`, `.npvt`, `.npvs`, `.nm`, `.happ`, `.bpf`, `.tls`, `.zsx`)
- Passphrase prompt with automatic retry, for `.npvs` bundles and SlipNet bundle files
- Monospaced viewer with selectable text and a wrap/scroll toggle
- Copy, share (as a real `.txt` file via `FileProvider`, so a VPN client can import it) or save anywhere
- Light / dark / system themes, English and Persian (RTL) localisations, vector launcher icon with an Android 13+ themed variant

Because everything except the [`internal/mobile/index.html`](internal/mobile/index.html) shell is ordinary Go, the application is tested with `go test`:

```bash
go test ./internal/...             # queue, i18n, rendering, passphrase flow, brand drift
node tools/engine-smoke.mjs        # the decryption core, as shipped
node tools/mobile-smoke.mjs        # the interface, as shipped
```

**Building**

Needs **Go 1.26+**, **JDK 17+** and an Android SDK with platform 35. A Gradle task compiles the Go application, so there is no separate manual step:

```bash
cd android
./gradlew assembleDebug      # app/build/outputs/apk/debug/
./gradlew assembleRelease    # minified, resource-shrunk, signed
```

Signing uses `-PPANTEGNOS_KEYSTORE=… -PPANTEGNOS_STORE_PASSWORD=… -PPANTEGNOS_KEY_ALIAS=… -PPANTEGNOS_KEY_PASSWORD=…`. Without those properties the release variant falls back to the debug key so `assembleRelease` still produces an installable APK.

**Releases**

[`.github/workflows/android.yml`](.github/workflows/android.yml) runs `go vet` and `go test`, both smoke tests, then builds and signs the APKs on every push to `main`, and attaches them to the GitHub release for `v*` tags. Add the repository secrets `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS` and `KEY_PASSWORD` to publish with your own upload key; otherwise CI generates an ephemeral one for that run.

## Usage

1. Place your encrypted config files in a `configs/` directory (or use `-input` to specify one).

2. Run the tool:

```bash
chmod +x Pantegnos
./Pantegnos -input configs -output output
```

3. Decrypted files appear in the output directory as `.txt` files.

### CLI Flags

| Flag      | Default   | Description                                 |
|-----------|-----------|--------------------------------------------|
| `-input`  | `configs` | Directory containing encrypted config files |
| `-output` | `output`  | Directory where decrypted files are saved   |

## Building

Requires **Go 1.26.3** or later.

```bash
go build -o pantegnos ./cmd/pantegnos
```

For cross-compilation:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o pantegnos-linux ./cmd/pantegnos

# Windows
GOOS=windows GOARCH=amd64 go build -o pantegnos-win.exe ./cmd/pantegnos
```

Pre-built binaries are available in the [Releases](https://github.com/KernelDotDLL/Pantegnos/releases) section.

## Dependencies

- [colorgrad](https://github.com/mazznoer/colorgrad) — Terminal gradient text
- [termenv](https://github.com/muesli/termenv) — Terminal capabilities
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) — ChaCha20-Poly1305 AEAD
- [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) — Secure password input (bundle mode)

## License

Copyright (c) 2026 FrontierTM. All rights reserved.

Pantegnos is released under the **GNU Affero General Public License v3.0** ([AGPL-3.0](LICENSE)). Releases up to and including `v9.4.3` were published under the MIT License, and copies taken under that grant keep it; every later release is AGPL-3.0.

The AGPL keeps forks open: anyone who ships a modified version, or runs one as a network service — including a hosted copy of the web decryptor — must publish their source under the same license and keep the copyright notices intact. A rebrand cannot take the code closed.

The name and the mark are not part of the grant. Forks and rebrands must ship under their own name and logo, and must not state or imply that they are Pantegnos or that this project endorses them.

---

*This tool is provided as-is for security research purposes. Users are responsible for ensuring their use complies with applicable laws.*
