# VaultIPFS — Decentralized Password Manager

**Zero-knowledge, client-side encrypted credential manager. Data stored on Filebase S3.**

No servers. No accounts. No tracking. Your passwords are encrypted in your browser before they ever touch the network.

## Features

- **AES-256-GCM Encryption** — All data encrypted client-side with PBKDF2 (600k iterations)
- **Blockchain Auth** — Username/password login with genesis blocks on S3, each user gets their own chain
- **Multi-Password Support** — Primary password (AES-256-GCM) + secondary PINs/passwords (AES-256-CBC)
- **Filebase S3 Storage** — Encrypted vault stored on decentralized S3 with SigV4 browser signing
- **CORS Proxy Support** — Optional Cloudflare Worker proxy for browsers that need CORS headers
- **Multiple Entry Types** — Logins, Aliases, Secure Notes, Identities, Credit Cards
- **Password Generator** — Built-in strong password generator with strength meter
- **TOTP/2FA** — Built-in TOTP code generator (RFC 6238)
- **Password Health** — Analyze your vault for weak passwords
- **Folders** — Organize entries into folders
- **Favorites & Trash** — Mark favorites, soft-delete with restore
- **Import/Export** — JSON and CSV export, JSON import with merge
- **Auto-lock** — Configurable auto-lock timer with activity detection
- **Clipboard Auto-clear** — Passwords auto-cleared from clipboard
- **Dark/Light Theme** — Toggle between themes
- **Fully Responsive** — Works on mobile, tablet, and desktop
- **Keyboard Shortcuts** — Ctrl+K search, Ctrl+N new item, Ctrl+L lock

## Architecture

```
User Browser
├── Web Crypto API (AES-256-GCM, AES-256-CBC)
├── PBKDF2 Key Derivation (600k iterations primary, 100k secondary)
├── HMAC-SHA256 (manual implementation for S3 signing)
├── TOTP Generation (HMAC-SHA1, RFC 6238)
└── S3 Upload/Download (Filebase, SigV4 browser signing)
    └── Encrypted JSON blob → S3
```

## Quick Start

```bash
# Serve locally
python3 -m http.server 8080
# Open http://localhost:8080
```

Or deploy to **GitHub Pages**, **Netlify**, or any static host.

## Configuration

Edit `config.js` to customize:

```javascript
const CONFIG = {
  S3: {
    AK: 'your-access-key',      // Filebase S3 access key
    SK: 'your-secret-key',      // Filebase S3 secret key
    BUCKET: 'your-bucket',      // S3 bucket name
    REGION: 'auto',
    HOST: 's3.filebase.io'
  },
  CORS_PROXY: '',               // Optional: Cloudflare Worker URL
  PBKDF2_ITERATIONS: 600000     // Key derivation iterations
};
```

### CORS Proxy Setup

Filebase S3 free tier doesn't send CORS headers. To fix this:

1. Deploy `worker.js` to Cloudflare Workers (free tier: 100k req/day)
2. Set `CORS_PROXY` in `config.js` to your worker URL
3. The app will route all S3 requests through the proxy

## Security

- Master password never leaves the browser
- All encryption via Web Crypto API (hardware-accelerated)
- 600,000 PBKDF2 iterations for primary key derivation
- 100,000 PBKDF2 iterations for secondary passwords
- Random 12-byte IV for each encryption (GCM), 16-byte for CBC
- S3 only stores encrypted data — without the master password, it's just random bytes
- No telemetry, no analytics, no network calls except to S3
- Blockchain stores only username hash + password hash (no plaintext)

## License

MIT
