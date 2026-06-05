// ═══════════════════════════════════════════════════════════════
// VaultIPFS — Configuration
// ═══════════════════════════════════════════════════════════════
// Copy this file to config.js and fill in your own credentials.
// Get Filebase S3 credentials at: https://console.filebase.io/keys
// ═══════════════════════════════════════════════════════════════

const CONFIG = {
  // Filebase S3 credentials
  S3: {
    AK: 'DA7F33AD883379297825',   // Access Key
    SK: 'xSOU0s5Yfy9aBZhraaSxGG6Ls5ZSOBxPUw7JDQDI',   // Secret Key
    BUCKET: 'vault-ipfs',
    REGION: 'auto',
    HOST: 's3.filebase.io'
  },

  // Optional: Cloudflare Worker CORS proxy URL
  // Deploy worker.js to Cloudflare Workers and set the URL here
  // Example: 'https://your-worker.your-subdomain.workers.dev/proxy'
  CORS_PROXY: '',

  // IPFS gateway for public chain data
  IPFS_GW: 'https://gateway.filebase.io/ipfs/',

  // Crypto settings
  PBKDF2_ITERATIONS: 600000,
  SALT_SIZE: 32,
  IV_SIZE: 12
};
