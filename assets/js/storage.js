/**
 * VaultStorage — IPFS-based Decentralized Storage
 *
 * Stores encrypted vault data on IPFS via Pinata (pinata.cloud).
 * Also supports LocalStorage cache for offline access.
 *
 * Data flow:
 * 1. Encrypt vault data in browser (AES-256-GCM)
 * 2. Upload encrypted blob to IPFS via Pinata API
 * 3. Get CID (content identifier) back
 * 4. Store CID + encrypted cache in localStorage
 * 5. On load: fetch CID from IPFS gateway → decrypt in browser
 */

const VaultStorage = (() => {
    // Public IPFS gateways (with fallback chain)
    const GATEWAYS = [
        'https://gateway.pinata.cloud/ipfs/',
        'https://ipfs.io/ipfs/',
        'https://dweb.link/ipfs/',
        'https://cloudflare-ipfs.com/ipfs/',
    ];

    const LOCAL_KEY = 'vault_cid';
    const LOCAL_SALT_KEY = 'vault_salt';
    const LOCAL_CACHE_KEY = 'vault_cache';
    const LOCAL_HASH_KEY = 'vault_pw_hash';

    // Pinata JWT — used for authenticated pinning
    const PINATA_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiJkZDVmYzM3NC03MGVhLTQ0ZTItODA0Zi0yZjlhODJmYWEzOGEiLCJlbWFpbCI6ImphdGluY2hhaGFsQHByb3Rvbm1haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInBpbl9wb2xpY3kiOnsicmVnaW9ucyI6W3siZGVzaXJlZFJlcGxpY2F0aW9uQ291bnQiOjEsImlkIjoiRlJBMSJ9LHsiZGVzaXJlZFJlcGxpY2F0aW9uQ291bnQiOjEsImlkIjoiTllDMSJ9XSwidmVyc2lvbiI6MX0sIm1mYV9lbmFibGVkIjpmYWxzZSwic3RhdHVzIjoiQUNUSVZFIn0sImF1dGhlbnRpY2F0aW9uVHlwZSI6InNjb3BlZEtleSIsInNjb3BlZEtleUtleSI6IjE2MTBmZDA4MGQ5NWM0ODMxM2MyIiwic2NvcGVkS2V5U2VjcmV0IjoiZjkyNGNhNTcyNDk4YmM0NWMzYzg2NDFjZGNmZDNmNjNiNTljZTUyMjI5NjViZGU5ODRiNDBmYTBiOTlkNTU2NyIsImV4cCI6MTgxMTgxMTI5Nn0.yNTUihsJoyvGIyEO3ZdIALt7HB0BbePN9JGE0QRiic8';

    /**
     * Upload encrypted data to IPFS via Pinata
     */
    async function uploadToIPFS(encryptedBlob) {
        // Try Pinata first (authenticated, reliable)
        try {
            const cid = await uploadToPinata(encryptedBlob);
            // Also cache locally for offline access
            localStorage.setItem(LOCAL_CACHE_KEY, JSON.stringify(encryptedBlob));
            return cid;
        } catch (e) {
            console.warn('Pinata upload failed:', e.message);
        }

        // Fallback: store in localStorage only
        console.warn('IPFS upload failed, storing locally only');
        const cid = 'local_' + Date.now();
        localStorage.setItem(LOCAL_CACHE_KEY, JSON.stringify(encryptedBlob));
        return cid;
    }

    /**
     * Upload to Pinata using JWT Bearer auth
     */
    async function uploadToPinata(data) {
        const formData = new FormData();
        const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        formData.append('file', blob, 'vault-encrypted.json');

        // Also pin with a friendly name
        const pinMetadata = JSON.stringify({
            name: 'VaultIPFS Encrypted Backup',
            keyvalues: { app: 'vault-ipfs', type: 'encrypted-vault' }
        });
        formData.append('pinataMetadata', pinMetadata);

        const res = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${PINATA_JWT}`,
            },
            body: formData,
        });

        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Pinata ${res.status}: ${text}`);
        }
        const result = await res.json();
        return result.IpfsHash;
    }

    /**
     * Download encrypted data from IPFS by CID
     */
    async function downloadFromIPFS(cid) {
        // Check local cache first for speed
        if (cid.startsWith('local_')) {
            const cached = localStorage.getItem(LOCAL_CACHE_KEY);
            if (cached) {
                try { return JSON.parse(cached); }
                catch(e) { return cached; }
            }
            throw new Error('No local cache found');
        }

        // Try local cache first (fast)
        try {
            const cached = localStorage.getItem(LOCAL_CACHE_KEY);
            if (cached) {
                const cachedEncrypted = JSON.parse(cached);
                // Compare CIDs to see if cache matches
                const savedCid = localStorage.getItem(LOCAL_KEY);
                if (savedCid === cid) {
                    return cachedEncrypted;
                }
            }
        } catch(e) {}

        // Try each gateway
        let lastError;
        for (const gateway of GATEWAYS) {
            try {
                const res = await fetch(gateway + cid, {
                    signal: AbortSignal.timeout(15000),
                });
                if (res.ok) {
                    const data = await res.json();
                    // Update local cache
                    localStorage.setItem(LOCAL_CACHE_KEY, JSON.stringify(data));
                    return data;
                }
            } catch (e) {
                lastError = e;
                console.warn(`Gateway ${gateway} failed:`, e.message);
            }
        }

        // Last try: local cache regardless of CID match
        const cached = localStorage.getItem(LOCAL_CACHE_KEY);
        if (cached) {
            try { return JSON.parse(cached); }
            catch(e) {}
        }

        throw new Error('All IPFS gateways failed. ' + (lastError ? lastError.message : ''));
    }

    /**
     * Save IPFS CID to localStorage
     */
    function saveCID(cid) {
        localStorage.setItem(LOCAL_KEY, cid);
    }

    /**
     * Get IPFS CID from localStorage
     */
    function getCID() {
        return localStorage.getItem(LOCAL_KEY);
    }

    /**
     * Save salt to localStorage
     */
    function saveSalt(salt) {
        localStorage.setItem(LOCAL_SALT_KEY, VaultCrypto.arrayBufferToBase64(salt));
    }

    /**
     * Get salt from localStorage
     */
    function getSalt() {
        const saltB64 = localStorage.getItem(LOCAL_SALT_KEY);
        if (!saltB64) return null;
        return VaultCrypto.base64ToArrayBuffer(saltB64);
    }

    /**
     * Save password hash for verification (SHA-256 of password+salt)
     */
    function savePasswordHash(hashB64) {
        localStorage.setItem(LOCAL_HASH_KEY, hashB64);
    }

    /**
     * Get stored password hash
     */
    function getPasswordHash() {
        return localStorage.getItem(LOCAL_HASH_KEY);
    }

    /**
     * Check if vault exists (has salt stored)
     */
    function vaultExists() {
        return !!getSalt();
    }

    /**
     * Clear all local data (dangerous!)
     */
    function clearAll() {
        localStorage.removeItem(LOCAL_KEY);
        localStorage.removeItem(LOCAL_SALT_KEY);
        localStorage.removeItem(LOCAL_CACHE_KEY);
        localStorage.removeItem(LOCAL_HASH_KEY);
    }

    /**
     * Export encrypted vault as downloadable file
     */
    function exportToFile(encryptedData, filename) {
        const jsonStr = typeof encryptedData === 'string' ? encryptedData : JSON.stringify(encryptedData, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || 'vault-ipfs-backup-' + new Date().toISOString().slice(0, 10) + '.json';
        a.click();
        URL.revokeObjectURL(url);
    }

    /**
     * Import vault from file
     */
    function importFromFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const data = JSON.parse(e.target.result);
                    resolve(data);
                } catch (err) {
                    reject(new Error('Invalid vault file — must be valid JSON'));
                }
            };
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    return {
        uploadToIPFS,
        downloadFromIPFS,
        saveCID,
        getCID,
        saveSalt,
        getSalt,
        savePasswordHash,
        getPasswordHash,
        vaultExists,
        clearAll,
        exportToFile,
        importFromFile,
        GATEWAYS,
    };
})();
