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

  // Cloudflare Worker CORS proxy URL
  // This worker proxies S3 requests and adds CORS headers.
  // Deploy worker.js to Cloudflare Workers and set the URL here.
  // Your worker: royal-term-dfa3 (needs to be updated with latest worker.js)
  CORS_PROXY: 'https://royal-term-dfa3.jatinchahal2010.workers.dev/proxy',

  // IPFS gateway for public chain data
  IPFS_GW: 'https://gateway.filebase.io/ipfs/',

  // Crypto settings
  PBKDF2_ITERATIONS: 600000,
  SALT_SIZE: 32,
  IV_SIZE: 12
};
