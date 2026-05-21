# Pantegnos
VPN decryption utility designed to parse, decrypt complex VPN and proxy configuration files. Built with a modular architecture, it allows security researchers to extract server metadata from encrypted proprietary formats used in various Android and desktop clients.

> Ready to go binaries are available in Release section if you are lazy to build the binaries

# Usage
- Just run the program, nothing complicated
```bash
chmod +x Pantegnos && ./Pantegnos -input configs -output outputs
```

# Current Support
- slipnet-enc://
- slipnet://
- slipnet-bundle-enc:// (Requires Bundle password)
- nm-(anytype eg. vless-dns-ssh)://
- happ://(crypt-[1-4])
- Slipnet - Netmod - Happ (More soon)

If you wanted to reach out or something message me on telegram
> https://t.me/panirpega
