# VaultIPFS — Decentralized Password Manager

**Zero-knowledge, client-side encrypted credential manager. Data stored on IPFS.**

No servers. No accounts. No tracking. Your passwords are encrypted in your browser before they ever touch the network.

## Features

- **AES-256-GCM Encryption** — All data encrypted client-side with PBKDF2 (600k iterations)
- **IPFS Storage** — Encrypted vault pinned to IPFS via Pinata for decentralized, permanent storage
- **Multiple Entry Types** — Logins, Aliases, Secure Notes, Identities, Credit Cards
- **Password Generator** — Built-in strong password generator with strength meter
- **TOTP/2FA** — Built-in TOTP code generator
- **Password Health** — Analyze your vault for weak passwords
- **Folders** — Organize entries into folders
- **Favorites & Trash** — Mark favorites, soft-delete with restore
- **Import/Export** — JSON and CSV export, JSON import with merge
- **Master Password Verification** — Quick hash-based verification on unlock
- **Auto-lock** — Configurable auto-lock timer
- **Clipboard Auto-clear** — Passwords auto-cleared from clipboard
- **Dark/Light Theme** — System-aware theme switching
- **Fully Responsive** — Works on mobile, tablet, and desktop
- **Keyboard Shortcuts** — Ctrl+K search, Ctrl+N new item, Ctrl+L lock

## Architecture

```
User Browser
├── Web Crypto API (AES-256-GCM)
├── PBKDF2 Key Derivation (600k iterations)
├── TOTP Generation (HMAC-SHA1)
└── IPFS Upload/Download (via Pinata)
    └── Encrypted JSON blob → IPFS CID
```

## How It Works

1. **Create Vault** → Choose master password (never leaves browser)
2. **Add Entries** → Passwords encrypted before storage
3. **Save** → Encrypted blob → IPFS via Pinata → CID stored locally
4. **Sync** → Enter CID on any device → fetch from IPFS → decrypt

## Quick Start

```bash
# Serve locally
python3 -m http.server 8080
# Open http://localhost:8080
```

Or deploy to **GitHub Pages**, **Netlify**, or any static host.

## Security

- Master password never leaves the browser
- All encryption via Web Crypto API (hardware-accelerated)
- 600,000 PBKDF2 iterations for key derivation
- Random 12-byte IV for each encryption
- IPFS only stores encrypted data — without the master password, it's just random bytes
- No telemetry, no analytics, no network calls except to IPFS

## License

MIT
