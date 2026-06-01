/**
 * VaultUtils — Password Generator, TOTP, Clipboard, UI Helpers
 */
const VaultUtils = (() => {
    function generatePassword(length, options) {
        length = length || 16;
        options = options || {};
        var upper = options.uppercase !== false;
        var lower = options.lowercase !== false;
        var nums = options.numbers !== false;
        var syms = options.symbols !== false;
        var charset = '';
        var required = [];
        if (upper) { charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; required.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ'); }
        if (lower) { charset += 'abcdefghijklmnopqrstuvwxyz'; required.push('abcdefghijklmnopqrstuvwxyz'); }
        if (nums) { charset += '0123456789'; required.push('0123456789'); }
        if (syms) { charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'; required.push('!@#$%^&*()_+-=[]{}|;:,.<>?'); }
        if (!charset) charset = 'abcdefghijklmnopqrstuvwxyz';
        length = Math.max(length, required.length);
        var password = '';
        var array = new Uint32Array(length * 2);
        crypto.getRandomValues(array);
        var ai = 0;
        for (var i = 0; i < required.length; i++) { password += required[i][array[ai] % required[i].length]; ai++; }
        for (var i = required.length; i < length; i++) { password += charset[array[ai] % charset.length]; ai++; }
        var arr = password.split('');
        for (var i = arr.length - 1; i > 0; i--) { var j = array[ai % array.length] % (i + 1); ai++; var tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp; }
        return arr.join('');
    }

    function calculateStrength(password) {
        var s = 0;
        if (password.length >= 8) s++;
        if (password.length >= 12) s++;
        if (password.length >= 16) s++;
        if (/[a-z]/.test(password)) s++;
        if (/[A-Z]/.test(password)) s++;
        if (/[0-9]/.test(password)) s++;
        if (/[^a-zA-Z0-9]/.test(password)) s++;
        if (s <= 2) return { score: 1, label: 'Weak', color: 'var(--danger)' };
        if (s <= 4) return { score: 2, label: 'Fair', color: 'var(--warning)' };
        if (s <= 5) return { score: 3, label: 'Good', color: 'var(--primary)' };
        return { score: 4, label: 'Strong', color: 'var(--success)' };
    }

    function generateTOTPSecret(len) {
        len = len || 32;
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        var bytes = crypto.getRandomValues(new Uint8Array(len));
        var secret = '';
        for (var i = 0; i < len; i++) secret += chars[bytes[i] % 32];
        return secret;
    }

    function getTOTPTimeRemaining() { return 30 - (Math.floor(Date.now() / 1000) % 30); }

    async function generateTOTP(secret) {
        try {
            var ts = Math.floor(Date.now() / 1000 / 30);
            var key = await base32Decode(secret);
            var buf = new ArrayBuffer(8);
            new DataView(buf).setUint32(4, ts, false);
            var hk = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
            var hmac = await crypto.subtle.sign('HMAC', hk, buf);
            var b = new Uint8Array(hmac);
            var off = b[19] & 0x0f;
            var code = (((b[off] & 0x7f) << 24) | ((b[off+1] & 0xff) << 16) | ((b[off+2] & 0xff) << 8) | (b[off+3] & 0xff)) % 1000000;
            return String(code).padStart(6, '0');
        } catch(e) { return '000000'; }
    }

    async function base32Decode(input) {
        var map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        input = input.toUpperCase().replace(/=+$/, '');
        var out = [];
        var buf = 0, bits = 0;
        for (var i = 0; i < input.length; i++) {
            var val = map.indexOf(input[i]);
            if (val < 0) continue;
            buf = (buf << 5) | val;
            bits += 5;
            if (bits >= 8) { bits -= 8; out.push((buf >>> bits) & 0xff); }
        }
        return new Uint8Array(out).buffer;
    }

    async function copyToClipboard(text, clearAfter) {
        try {
            await navigator.clipboard.writeText(text);
            if (clearAfter > 0) {
                setTimeout(async function() {
                    try { await navigator.clipboard.writeText(''); } catch(e) {}
                }, clearAfter * 1000);
            }
            return true;
        } catch(e) { return false; }
    }

    function getFaviconUrl(url) {
        if (!url) return '';
        try { var p = new URL(url.startsWith('http') ? url : 'https://' + url); return 'https://www.google.com/s2/favicons?domain=' + p.hostname + '&sz=64'; } catch(e) { return ''; }
    }

    function escapeHtml(text) {
        if (!text) return '';
        var d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }

    function formatDate(ds) {
        if (!ds) return 'Unknown';
        try { return new Date(ds).toLocaleDateString(); } catch(e) { return 'Unknown'; }
    }

    function getTypeIcon(type) {
        var icons = {
            login: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
            alias: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
            note: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
            identity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
            credit_card: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>',
        };
        return icons[type] || icons.login;
    }

    function getTypeLabel(type) {
        var labels = { login: 'Login', alias: 'Alias', note: 'Secure Note', identity: 'Identity', credit_card: 'Credit Card' };
        return labels[type] || 'Item';
    }

    return {
        generatePassword: generatePassword,
        calculateStrength: calculateStrength,
        generateTOTPSecret: generateTOTPSecret,
        generateTOTP: generateTOTP,
        getTOTPTimeRemaining: getTOTPTimeRemaining,
        copyToClipboard: copyToClipboard,
        getFaviconUrl: getFaviconUrl,
        escapeHtml: escapeHtml,
        formatDate: formatDate,
        getTypeIcon: getTypeIcon,
        getTypeLabel: getTypeLabel,
    };
})();
