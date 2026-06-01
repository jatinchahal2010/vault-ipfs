/**
 * VaultIPFS — Main Application
 * Decentralized, zero-knowledge credential manager.
 * All data encrypted client-side, stored on IPFS.
 */
(function() {
    'use strict';

    var appEl, masterPassword = null, salt = null;
    var state = {
        view: 'all', search: '', type: '', selected: new Set(),
        selectMode: false, lastActivity: Date.now(),
    };

    document.addEventListener('DOMContentLoaded', init);

    function init() {
        appEl = document.getElementById('app');
        // Activity tracking for auto-lock
        ['click','keydown','mousemove','touchstart'].forEach(function(ev) {
            document.addEventListener(ev, function() { state.lastActivity = Date.now(); }, { passive: true });
        });
        setInterval(function() {
            var timeout = VaultModel.getSettings().autoLockTime * 60 * 1000;
            if (timeout > 0 && Date.now() - state.lastActivity > timeout) lockVault();
        }, 60000);

        if (VaultStorage.vaultExists()) {
            showUnlockScreen();
        } else {
            showSetupScreen();
        }
    }

    // ====================
    // SETUP (First time)
    // ====================
    function showSetupScreen() {
        appEl.innerHTML = '<div class="setup-page"><div class="setup-container">' +
            '<div class="auth-logo"><div class="auth-logo-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></div>' +
            '<h1 class="auth-logo-text">VaultIPFS</h1><p class="auth-logo-sub">Decentralized Password Manager</p></div>' +
            '<div class="setup-steps">' +
                '<div class="setup-step"><div class="setup-step-num">1</div><div class="setup-step-content"><h3>Choose a Master Password</h3><p>This password encrypts ALL your data. It never leaves your browser. If you lose it, your data cannot be recovered.</p></div></div>' +
                '<div class="setup-step"><div class="setup-step-num">2</div><div class="setup-step-content"><h3>Encrypted & Stored on IPFS</h3><p>Your encrypted vault is stored on IPFS (InterPlanetary File System) — a decentralized, permanent storage network.</p></div></div>' +
                '<div class="setup-step"><div class="setup-step-num">3</div><div class="setup-step-content"><h3>Zero Knowledge</h3><p>Only you can decrypt your data. No server, no company, no one else can see your passwords.</p></div></div>' +
            '</div>' +
            '<form id="setup-form" class="form-vertical">' +
                '<div class="form-group"><label class="form-label">Master Password *</label><input class="form-input" id="setup-password" type="password" required placeholder="Min 8 characters" autocomplete="new-password"></div>' +
                '<div class="form-group"><label class="form-label">Confirm Password *</label><input class="form-input" id="setup-password2" type="password" required placeholder="Repeat password" autocomplete="new-password"></div>' +
                '<div id="setup-strength" style="margin-top:-8px;margin-bottom:8px"></div>' +
                '<div class="form-error" id="setup-error"></div>' +
                '<button type="submit" class="btn btn-primary btn-full">Create Vault</button>' +
            '</form>' +
            '<p class="text-muted text-sm text-center" style="margin-top:16px">Already have a vault? <a href="#" id="link-import">Import from file</a></p>' +
            '<input type="file" id="import-setup-file" accept=".json" style="display:none">' +
        '</div></div>';

        document.getElementById('setup-password').addEventListener('input', function() {
            var s = VaultUtils.calculateStrength(this.value);
            document.getElementById('setup-strength').innerHTML = '<div class="strength-bar"><div class="strength-bar-track"><div class="strength-bar-fill" style="width:' + (s.score / 4 * 100) + '%;background:' + s.color + '"></div></div><span class="strength-label">' + s.label + '</span></div>';
        });

        document.getElementById('setup-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            var pw = document.getElementById('setup-password').value;
            var pw2 = document.getElementById('setup-password2').value;
            if (pw.length < 8) { document.getElementById('setup-error').textContent = 'Password must be at least 8 characters'; return; }
            if (pw !== pw2) { document.getElementById('setup-error').textContent = 'Passwords do not match'; return; }

            salt = VaultCrypto.generateSalt();
            masterPassword = pw;
            VaultStorage.saveSalt(salt);
            // Store password hash for quick verification on unlock
            var pwHash = await VaultCrypto.hashPassword(pw, salt);
            VaultStorage.savePasswordHash(pwHash);

            // Create empty vault and save
            VaultModel.setData({ version: 2, entries: [], folders: [], settings: { clipboardClearTime: 30, autoLockTime: 30, theme: 'system' }, updatedAt: new Date().toISOString() });
            await saveVault();
            showToast('Vault created!', 'success');
            renderApp();
        });

        document.getElementById('link-import').addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('import-setup-file').click();
        });
        document.getElementById('import-setup-file').addEventListener('change', async function(e) {
            var file = e.target.files[0];
            if (!file) return;
            var data = await VaultStorage.importFromFile(file);
            if (data && data.entries) {
                // Need to set master password first
                var pw = prompt('Enter the master password for this vault:');
                if (!pw) return;
                salt = VaultCrypto.generateSalt();
                masterPassword = pw;
                VaultStorage.saveSalt(salt);
                VaultModel.setData(data);
                await saveVault();
                showToast('Vault imported!', 'success');
                renderApp();
            } else {
                showToast('Invalid vault file', 'error');
            }
        });
    }

    // ====================
    // UNLOCK
    // ====================
    function showUnlockScreen() {
        var savedCid = VaultStorage.getCID() || '';
        appEl.innerHTML = '<div class="auth-page"><div class="auth-container">' +
            '<div class="auth-logo"><div class="auth-logo-icon"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>' +
            '<h1 class="auth-logo-text">VaultIPFS</h1><p class="auth-logo-sub">Enter your master password</p></div>' +
            '<form id="unlock-form" class="form-vertical">' +
                '<div class="form-group"><label class="form-label">Master Password</label><input class="form-input" id="unlock-password" type="password" required placeholder="Enter master password" autocomplete="current-password" autofocus></div>' +
                '<div class="form-group"><label class="form-label">IPFS CID <span class="text-sm text-muted">(optional — leave blank to use last saved)</span></label><input class="form-input" id="unlock-cid" type="text" placeholder="Qm..." value="' + savedCid + '"></div>' +
                '<div class="form-error" id="unlock-error"></div>' +
                '<button type="submit" class="btn btn-primary btn-full">Unlock</button>' +
            '</form>' +
            '<div style="margin-top:16px;text-align:center" class="text-muted text-sm">' +
                '<p><a href="#" id="link-import-unlock">Import from file</a> &middot; <a href="#" id="link-reset">Reset vault</a></p>' +
                '<p style="margin-top:8px"><a href="#" id="link-forgot">Forgot password?</a></p>' +
            '</div>' +
            '<input type="file" id="import-unlock-file" accept=".json" style="display:none">' +
        '</div></div>';

        // Unlock form submit
        document.getElementById('unlock-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            var pw = document.getElementById('unlock-password').value;
            var cidOverride = document.getElementById('unlock-cid').value.trim() || null;

            salt = VaultStorage.getSalt();

            // Quick password hash check (fast, no IPFS needed)
            var storedHash = VaultStorage.getPasswordHash();
            if (storedHash) {
                var inputHash = await VaultCrypto.hashPassword(pw, salt);
                if (inputHash !== storedHash) {
                    document.getElementById('unlock-error').textContent = 'Wrong master password';
                    return;
                }
            }

            masterPassword = pw;

            try {
                await loadVault(cidOverride);
                showToast('Vault unlocked!', 'success');
                renderApp();
            } catch (err) {
                document.getElementById('unlock-error').textContent = 'Error: ' + (err.message || 'Failed to load vault');
                masterPassword = null;
            }
        });

        // Import from file
        document.getElementById('link-import-unlock').addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('import-unlock-file').click();
        });
        document.getElementById('import-unlock-file').addEventListener('change', async function(e) {
            var file = e.target.files[0];
            if (!file) return;
            var data = await VaultStorage.importFromFile(file);
            if (data && data.entries) {
                var pw = prompt('Enter the master password for this vault:');
                if (!pw) return;
                masterPassword = pw;
                salt = VaultCrypto.generateSalt();
                VaultStorage.saveSalt(salt);
                var pwHash = await VaultCrypto.hashPassword(pw, salt);
                VaultStorage.savePasswordHash(pwHash);
                VaultModel.setData(data);
                await saveVault();
                showToast('Vault imported!', 'success');
                renderApp();
            } else {
                showToast('Invalid vault file', 'error');
            }
        });

        // Reset vault
        document.getElementById('link-reset').addEventListener('click', function(e) {
            e.preventDefault();
            if (!confirm('⚠️ This will DELETE all local vault data. Make sure you have a backup! Continue?')) return;
            if (!confirm('Are you ABSOLUTELY sure? This cannot be undone!')) return;
            VaultStorage.clearAll();
            masterPassword = null;
            salt = null;
            showToast('Vault reset. Reloading...', 'info');
            setTimeout(function() { location.reload(); }, 1000);
        });

        // Forgot password
        document.getElementById('link-forgot').addEventListener('click', function(e) {
            e.preventDefault();
            alert('There is no password recovery. Your master password is the only key to decrypt your data.\n\nIf you have a backup file, you can import it (but you still need the original password).\n\nIf you lose your master password, your vault is gone forever. This is by design.');
        });
    }

    // ====================
    // SAVE / LOAD (IPFS)
    // ====================
    async function saveVault() {
        var data = VaultModel.getData();
        var encrypted = await VaultCrypto.encrypt(masterPassword, salt, JSON.stringify(data));
        encrypted._vaultMeta = { version: 2, savedAt: new Date().toISOString() };

        try {
            var cid = await VaultStorage.uploadToIPFS(encrypted);
            VaultStorage.saveCID(cid);
            return cid;
        } catch (e) {
            console.error('Save failed:', e);
            throw e;
        }
    }

    async function loadVault(cidOverride) {
        var cid = cidOverride || VaultStorage.getCID();
        var encrypted = null;
        if (cid) {
            try {
                encrypted = await VaultStorage.downloadFromIPFS(cid);
            } catch (e) {
                console.warn('IPFS load failed, trying local cache:', e.message);
            }
        }
        if (!encrypted) {
            try {
                var cached = localStorage.getItem(VaultStorage.LOCAL_CACHE_KEY || 'vault_cache');
                if (cached) encrypted = JSON.parse(cached);
            } catch(e) {}
        }
        if (!encrypted) throw new Error('No vault data found. Check your IPFS CID or restore from backup file.');

        var decrypted = await VaultCrypto.decrypt(masterPassword, salt, encrypted);
        if (!decrypted) throw new Error('Decryption failed — wrong password or corrupted data');

        var data = JSON.parse(decrypted);
        VaultModel.setData(data);
    }

    function lockVault() {
        masterPassword = null;
        clearIntervalTimers();
        showUnlockScreen();
    }

    function clearIntervalTimers() {
        // Clear any running TOTP timers
    }

    // ====================
    // MAIN APP
    // ====================
    function renderApp() {
        var initials = 'U';
        if (VaultModel.getSettings) {
            // No user profile in this version
        }

        appEl.innerHTML = '<div class="layout">' +
            '<div class="sidebar-overlay" id="sidebar-overlay"></div>' +
            renderSidebar() +
            '<main class="main-content">' +
                '<header class="main-header">' +
                    '<div style="display:flex;align-items:center;gap:12px">' +
                        '<button class="mobile-menu-btn" id="mobile-menu-btn"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg></button>' +
                        '<h1 id="view-title">All Items</h1>' +
                    '</div>' +
                    '<div class="main-header-actions">' +
                        (state.selectMode ?
                            '<span class="select-count">' + state.selected.size + ' selected</span>' +
                            '<button class="btn btn-sm btn-danger" id="btn-bulk-del">Delete</button>' +
                            '<button class="btn btn-sm btn-outline" id="btn-sel-cancel">Cancel</button>'
                        : '<button class="btn btn-icon" id="btn-sel-mode" title="Select mode">☑</button>' +
                          '<button class="theme-toggle" id="hdr-theme"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg></button>'
                        ) +
                    '</div>' +
                '</header>' +
                '<div class="main-body" id="main-body"></div>' +
            '</main>' +
            '</div>' +
            '<div id="modal-overlay" class="modal-overlay"><div class="modal" id="modal-content"></div></div>' +
            '<div id="toast-container" class="toast-container"></div>';

        setupAppListeners();
        renderEntries();
        updateCounts();
    }

    function renderSidebar() {
        var stats = VaultModel.getStats();
        var lockIcon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
        var allIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
        var favIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>';
        var trashIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
        var healthIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
        var exportIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';

        var types = [
            { id: 'login', icon: allIcon, label: 'Logins', count: stats.byType.login },
            { id: 'alias', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>', label: 'Aliases', count: stats.byType.alias },
            { id: 'note', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>', label: 'Notes', count: stats.byType.note },
            { id: 'identity', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>', label: 'Identities', count: stats.byType.identity },
            { id: 'credit_card', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>', label: 'Cards', count: stats.byType.credit_card },
        ];

        var typeHtml = types.map(function(t) {
            return '<button class="sidebar-nav-item' + (state.type === t.id ? ' active' : '') + '" data-type="' + t.id + '">' + t.icon + '<span class="nav-label">' + t.label + '</span><span class="sidebar-badge">' + t.count + '</span></button>';
        }).join('');

        var folderHtml = VaultModel.getFolders().map(function(f) {
            return '<button class="sidebar-nav-item' + (state.view === 'folder-' + f.id ? ' active' : '') + '" data-view="folder-' + f.id + '"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span class="nav-label">' + VaultUtils.escapeHtml(f.name) + '</span></button>';
        }).join('');

        return '<aside class="sidebar" id="sidebar">' +
            '<div class="sidebar-header">' +
                '<div class="sidebar-brand"><div class="sidebar-brand-icon">' + lockIcon + '</div><span class="sidebar-brand-text">VaultIPFS</span></div>' +
                '<div class="sidebar-search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg><input type="search" placeholder="Search vault..." id="search-input"></div>' +
            '</div>' +
            '<div class="sidebar-body">' +
                '<div class="sidebar-section"><button class="btn btn-primary btn-full" id="btn-add" style="margin:0 12px;width:calc(100% - 24px);"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Add New</button></div>' +
                '<div class="sidebar-section"><div class="sidebar-section-header"><span class="sidebar-section-title">Overview</span></div>' +
                    '<button class="sidebar-nav-item' + (state.view === 'all' && !state.type ? ' active' : '') + '" data-view="all">' + allIcon + '<span class="nav-label">All Items</span><span class="sidebar-badge" id="cnt-all">' + stats.total + '</span></button>' +
                    '<button class="sidebar-nav-item' + (state.view === 'favorites' ? ' active' : '') + '" data-view="favorites">' + favIcon + '<span class="nav-label">Favorites</span><span class="sidebar-badge" id="cnt-fav">' + stats.favorites + '</span></button>' +
                    '<button class="sidebar-nav-item' + (state.view === 'trash' ? ' active' : '') + '" data-view="trash">' + trashIcon + '<span class="nav-label">Trash</span><span class="sidebar-badge" id="cnt-trash">' + stats.trash + '</span></button>' +
                '</div>' +
                '<div class="sidebar-section"><div class="sidebar-section-header"><span class="sidebar-section-title">Types</span></div>' + typeHtml + '</div>' +
                '<div class="sidebar-section"><div class="sidebar-section-header"><span class="sidebar-section-title">Folders</span><button class="sidebar-btn-add" id="btn-add-folder" title="New folder"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg></button></div><div id="folders-list">' + (folderHtml || '<div class="sidebar-empty">No folders yet</div>') + '</div></div>' +
                '<div class="sidebar-section"><div class="sidebar-section-header"><span class="sidebar-section-title">Tools</span></div>' +
                    '<button class="sidebar-nav-item" data-action="health">' + healthIcon + '<span class="nav-label">Password Health</span></button>' +
                    '<button class="sidebar-nav-item" data-action="import-export">' + exportIcon + '<span class="nav-label">Import / Export</span></button>' +
                '</div>' +
            '</div>' +
            '<div class="sidebar-footer">' +
                '<button class="sidebar-nav-item" id="btn-lock"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span>Lock Vault</span></button>' +
                '<button class="sidebar-nav-item" id="btn-settings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg><span>Settings</span></button>' +
            '</div>' +
        '</aside>';
    }

    function setupAppListeners() {
        // Search
        var searchInput = document.getElementById('search-input');
        var searchTimeout;
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(function() { state.search = searchInput.value; renderEntries(); }, 300);
        });

        // Add entry
        document.getElementById('btn-add').addEventListener('click', function() { showEntryModal(null); });

        // Add folder
        document.getElementById('btn-add-folder').addEventListener('click', function() {
            var name = prompt('Folder name:');
            if (name) { VaultModel.createFolder(name); renderApp(); showToast('Folder created', 'success'); }
        });

        // Lock
        document.getElementById('btn-lock').addEventListener('click', function() { if (confirm('Lock vault?')) lockVault(); });

        // Settings
        document.getElementById('btn-settings').addEventListener('click', function() { showSettings(); });

        // Theme
        document.getElementById('hdr-theme').addEventListener('click', function() {
            var s = VaultModel.getSettings();
            var themes = ['light', 'dark', 'system'];
            var idx = themes.indexOf(s.theme || 'system');
            var next = themes[(idx + 1) % 3];
            VaultModel.updateSettings({ theme: next });
            document.documentElement.setAttribute('data-theme', next);
        });

        // Sidebar nav
        document.querySelectorAll('.sidebar-nav-item[data-view]').forEach(function(btn) {
            btn.addEventListener('click', function() {
                state.view = btn.dataset.view; state.type = ''; state.search = '';
                searchInput.value = '';
                updateSidebarActive(); renderEntries(); updateViewTitle();
            });
        });

        // Type filter
        document.querySelectorAll('.sidebar-nav-item[data-type]').forEach(function(btn) {
            btn.addEventListener('click', function() {
                state.type = btn.dataset.type; state.view = 'all';
                updateSidebarActive(); renderEntries(); updateViewTitle();
            });
        });

        // Tools
        document.querySelectorAll('.sidebar-nav-item[data-action]').forEach(function(btn) {
            btn.addEventListener('click', function() {
                if (btn.dataset.action === 'health') showPasswordHealth();
                if (btn.dataset.action === 'import-export') showImportExport();
            });
        });

        // Select mode
        document.getElementById('btn-sel-mode')?.addEventListener('click', function() { state.selectMode = true; state.selected.clear(); renderApp(); });
        document.getElementById('btn-sel-cancel')?.addEventListener('click', function() { state.selectMode = false; state.selected.clear(); renderApp(); });
        document.getElementById('btn-bulk-del')?.addEventListener('click', async function() {
            if (state.selected.size === 0) return;
            if (!confirm('Move ' + state.selected.size + ' items to trash?')) return;
            state.selected.forEach(function(id) { VaultModel.deleteEntry(id); });
            state.selected.clear(); state.selectMode = false;
            await saveVault(); renderApp(); showToast('Items moved to trash', 'success');
        });

        // Mobile
        document.getElementById('mobile-menu-btn')?.addEventListener('click', function() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('sidebar-overlay').classList.toggle('active');
        });
        document.getElementById('sidebar-overlay')?.addEventListener('click', function() {
            document.getElementById('sidebar').classList.remove('open');
            this.classList.remove('active');
        });

        // Modal close
        document.getElementById('modal-overlay')?.addEventListener('click', function(e) {
            if (e.target === this) closeModal();
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); searchInput.focus(); }
            if ((e.ctrlKey || e.metaKey) && e.key === 'n') { e.preventDefault(); showEntryModal(null); }
            if ((e.ctrlKey || e.metaKey) && e.key === 'l') { e.preventDefault(); lockVault(); }
            if (e.key === 'Escape') { closeModal(); if (state.selectMode) { state.selectMode = false; state.selected.clear(); renderApp(); } }
        });
    }

    function updateSidebarActive() {
        document.querySelectorAll('.sidebar-nav-item').forEach(function(btn) {
            btn.classList.remove('active');
            if (btn.dataset.view === state.view) btn.classList.add('active');
            if (btn.dataset.type === state.type) btn.classList.add('active');
        });
    }

    function updateViewTitle() {
        var titles = { all: 'All Items', favorites: 'Favorites', trash: 'Trash' };
        var el = document.getElementById('view-title');
        if (!el) return;
        if (titles[state.view]) el.textContent = titles[state.view];
        else if (state.view.startsWith('folder-')) {
            var f = VaultModel.getFolder(state.view.substring(7));
            el.textContent = f ? f.name : 'Folder';
        } else if (state.type) {
            el.textContent = VaultUtils.getTypeLabel(state.type) + 's';
        } else { el.textContent = 'All Items'; }
    }

    function updateCounts() {
        var stats = VaultModel.getStats();
        var set = function(id, val) { var el = document.getElementById(id); if (el) el.textContent = val; };
        set('cnt-all', stats.total); set('cnt-fav', stats.favorites); set('cnt-trash', stats.trash);
    }

    // ====================
    // ENTRIES
    // ====================
    function renderEntries() {
        var container = document.getElementById('main-body');
        var entries = VaultModel.getEntries(state.view, state.search, state.type);

        if (entries.length === 0) {
            var msgs = {
                all: 'Your vault is empty', favorites: 'No favorites yet', trash: 'Trash is empty',
            };
            var msg = msgs[state.view] || 'No items found';
            container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🔒</div><h3>' + msg + '</h3><p>Start by adding your first password.</p><button class="btn btn-primary" id="empty-add">Add Item</button></div>';
            document.getElementById('empty-add')?.addEventListener('click', function() { showEntryModal(null); });
            return;
        }

        container.innerHTML = '<div class="vault-grid" id="vault-grid"></div>';
        var grid = document.getElementById('vault-grid');
        entries.forEach(function(entry) { grid.appendChild(createCard(entry)); });
    }

    function createCard(entry) {
        var div = document.createElement('div');
        div.className = 'vault-card' + (state.selectMode ? ' selectable' : '');
        if (state.selected.has(entry.id)) div.classList.add('selected');
        div.dataset.id = entry.id;

        var favIcon = entry.isFavorite ? '<svg viewBox="0 0 24 24" fill="currentColor" style="color:var(--warning)"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>' : '';
        var faviconUrl = VaultUtils.getFaviconUrl(entry.website);
        var typeIcon = VaultUtils.getTypeIcon(entry.type);
        var strengthBar = entry.passwordStrength ? '<div class="strength-bar" style="margin-top:4px"><div class="strength-bar-track"><div class="strength-bar-fill" style="width:' + (entry.passwordStrength / 4 * 100) + '%;background:' + (entry.passwordStrength <= 2 ? 'var(--danger)' : entry.passwordStrength <= 3 ? 'var(--warning)' : 'var(--success)') + '"></div></div></div>' : '';

        div.innerHTML = '<div class="vault-card-inner">' +
            (state.selectMode ? '<div class="card-checkbox">' + (state.selected.has(entry.id) ? '✓' : '') + '</div>' : '') +
            '<div class="vault-card-icon">' + (faviconUrl ? '<img src="' + faviconUrl + '" alt="" onerror="this.style.display=\'none\';this.parentElement.innerHTML=\'' + typeIcon.replace(/'/g, "\\'") + '\'">' : typeIcon) + '</div>' +
            '<div class="vault-card-body">' +
                '<div class="vault-card-title-row"><span class="vault-card-title">' + VaultUtils.escapeHtml(entry.title) + '</span>' + (favIcon ? '<span style="flex-shrink:0">' + favIcon + '</span>' : '') + '</div>' +
                '<div class="vault-card-sub">' + VaultUtils.escapeHtml(entry.username || entry.website || VaultUtils.getTypeLabel(entry.type)) + '</div>' +
                strengthBar +
            '</div>' +
            '<div class="vault-card-actions">' +
                (entry.encryptedPassword ? '<button class="btn btn-icon btn-cp" title="Copy password" data-id="' + entry.id + '"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>' : '') +
                (entry.totpSecret ? '<button class="btn btn-icon btn-totp" title="Copy TOTP" data-id="' + entry.id + '"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg></button>' : '') +
                '<button class="btn btn-icon btn-menu" title="Actions" data-id="' + entry.id + '"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg></button>' +
            '</div>' +
        '</div>';

        if (state.selectMode) {
            div.addEventListener('click', function(e) {
                if (e.target.closest('.btn-menu')) return;
                if (state.selected.has(entry.id)) state.selected.delete(entry.id);
                else state.selected.add(entry.id);
                renderEntries();
            });
        } else {
            div.querySelector('.btn-cp')?.addEventListener('click', async function(e) {
                e.stopPropagation();
                var dec = await VaultCrypto.decrypt(masterPassword, salt, { iv: entry.encryptedPassword.iv, data: entry.encryptedPassword.data });
                if (dec) {
                    await VaultUtils.copyToClipboard(dec, VaultModel.getSettings().clipboardClearTime);
                    showToast('Password copied!', 'success');
                }
            });
            div.querySelector('.btn-totp')?.addEventListener('click', async function(e) {
                e.stopPropagation();
                var code = await VaultUtils.generateTOTP(entry.totpSecret);
                await VaultUtils.copyToClipboard(code, 30);
                showToast('TOTP copied!', 'success');
            });
            div.querySelector('.btn-menu')?.addEventListener('click', function(e) {
                e.stopPropagation();
                showEntryMenu(entry, this);
            });
            div.addEventListener('click', function() { showEntryModal(entry); });
        }
        return div;
    }

    function showEntryMenu(entry, trigger) {
        var existing = document.querySelector('.entry-menu-dropdown');
        if (existing) existing.remove();
        var dd = document.createElement('div');
        dd.className = 'entry-menu-dropdown';
        dd.style.cssText = 'position:fixed;z-index:300;background:var(--card);border:1px solid var(--card-border);border-radius:var(--radius);box-shadow:var(--shadow-lg);padding:4px;min-width:180px';
        var isTrash = entry.isDeleted;
        dd.innerHTML = '<button class="btn btn-text btn-full" data-a="edit" style="justify-content:flex-start;background:none">✏️ ' + (isTrash ? 'View' : 'Edit') + '</button>' +
            (!isTrash ? '<button class="btn btn-text btn-full" data-a="fav" style="justify-content:flex-start;background:none">' + (entry.isFavorite ? '⭐ Unfavorite' : '☆ Favorite') + '</button>' : '') +
            (isTrash ? '<button class="btn btn-text btn-full" data-a="restore" style="justify-content:flex-start;background:none">↩️ Restore</button>' : '') +
            '<hr style="border:none;border-top:1px solid var(--border);margin:4px 0">' +
            '<button class="btn btn-text btn-full" data-a="del" style="justify-content:flex-start;color:var(--danger)">' + (isTrash ? '💀 Delete Forever' : '🗑️ Trash') + '</button>';
        document.body.appendChild(dd);
        var rect = trigger.getBoundingClientRect();
        dd.style.left = Math.min(rect.right - 180, window.innerWidth - 20) + 'px';
        dd.style.top = Math.min(rect.bottom + 4, window.innerHeight - 200) + 'px';
        dd.querySelector('[data-a="edit"]').addEventListener('click', function() { dd.remove(); showEntryModal(entry); });
        var favBtn = dd.querySelector('[data-a="fav"]');
        if (favBtn) favBtn.addEventListener('click', async function() { dd.remove(); VaultModel.toggleFavorite(entry.id); await saveVault(); renderEntries(); showToast(entry.isFavorite ? 'Unfavorited' : 'Favorited', 'success'); });
        var resBtn = dd.querySelector('[data-a="restore"]');
        if (resBtn) resBtn.addEventListener('click', async function() { dd.remove(); VaultModel.restoreEntry(entry.id); await saveVault(); renderApp(); showToast('Restored', 'success'); });
        dd.querySelector('[data-a="del"]').addEventListener('click', async function() {
            dd.remove();
            if (isTrash) {
                if (!confirm('Permanently delete?')) return;
                VaultModel.purgeEntry(entry.id);
            } else {
                if (!confirm('Move to trash?')) return;
                VaultModel.deleteEntry(entry.id);
            }
            await saveVault(); renderApp();
        });
        setTimeout(function() {
            var h = function(e) { if (!dd.contains(e.target)) { dd.remove(); document.removeEventListener('click', h); } };
            document.addEventListener('click', h);
        }, 10);
    }

    // ====================
    // ENTRY MODAL
    // ====================
    function showEntryModal(entry) {
        var isEdit = !!entry;
        var modal = document.getElementById('modal-content');
        var types = ['login', 'alias', 'note', 'identity', 'credit_card'];
        var typeOpts = types.map(function(t) { return '<option value="' + t + '"' + (entry && entry.type === t ? ' selected' : '') + '>' + VaultUtils.getTypeLabel(t) + '</option>'; }).join('');
        var folderOpts = VaultModel.getFolders().map(function(f) { return '<option value="' + f.id + '"' + (entry && entry.folderId === f.id ? ' selected' : '') + '>' + VaultUtils.escapeHtml(f.name) + '</option>'; }).join('');

        modal.innerHTML = '<div class="modal-header"><h2>' + (isEdit ? 'Edit Item' : 'Add New Item') + '</h2></div>' +
            '<div class="modal-body"><form id="entry-form" class="form-vertical">' +
                '<input type="hidden" id="e-id" value="' + (entry ? entry.id : '') + '">' +
                '<div class="form-group"><label class="form-label">Type</label><select class="form-input" id="e-type">' + typeOpts + '</select></div>' +
                '<div class="form-group"><label class="form-label">Title *</label><input class="form-input" id="e-title" value="' + (entry ? VaultUtils.escapeHtml(entry.title) : '') + '" required></div>' +
                '<div class="form-group" id="fg-web"><label class="form-label">Website</label><input class="form-input" id="e-web" value="' + (entry ? VaultUtils.escapeHtml(entry.website || '') : '') + '"></div>' +
                '<div class="form-group" id="fg-user"><label class="form-label">Username / Email</label><input class="form-input" id="e-user" value="' + (entry ? VaultUtils.escapeHtml(entry.username || '') : '') + '"></div>' +
                '<div class="form-group" id="fg-pw"><label class="form-label">Password</label><div style="position:relative"><input class="form-input" id="e-pw" type="password" value="" placeholder="' + (isEdit ? 'Leave blank to keep current' : 'Enter password') + '" style="padding-right:80px"><div style="position:absolute;right:6px;top:50%;transform:translateY(-50%);display:flex;gap:2px"><button type="button" class="btn btn-icon btn-sm" id="btn-toggle-pw">👁</button><button type="button" class="btn btn-icon btn-sm" id="btn-gen-pw">⚡</button></div></div><div id="pw-str" style="margin-top:8px"></div></div>' +
                '<div id="pw-gen" class="hidden pw-gen-section"><div class="pw-gen-length"><label class="form-label" style="margin:0">Length: <span id="pw-len-val">16</span></label></div><input type="range" class="form-slider" id="pw-len" min="8" max="64" value="16"><div class="pw-gen-options"><label class="pw-gen-option"><input type="checkbox" id="pw-up" checked> ABC</label><label class="pw-gen-option"><input type="checkbox" id="pw-lo" checked> abc</label><label class="pw-gen-option"><input type="checkbox" id="pw-nu" checked> 123</label><label class="pw-gen-option"><input type="checkbox" id="pw-sy" checked> #$%</label></div><button type="button" class="btn btn-primary btn-full" id="btn-gen-use" style="margin-top:12px">Use This Password</button></div>' +
                '<div class="form-group" id="fg-totp"><label class="form-label">TOTP Secret</label><input class="form-input" id="e-totp" value="' + (entry ? VaultUtils.escapeHtml(entry.totpSecret || '') : '') + '" placeholder="Base32 secret"></div>' +
                (folderOpts ? '<div class="form-group"><label class="form-label">Folder</label><select class="form-input" id="e-folder"><option value="">None</option>' + folderOpts + '</select></div>' : '') +
                '<div class="form-group"><label class="form-label">Notes</label><textarea class="form-input" id="e-notes">' + (entry ? VaultUtils.escapeHtml(entry.notes || '') : '') + '</textarea></div>' +
            '</form></div>' +
            '<div class="modal-footer"><button class="btn btn-outline" id="m-cancel">Cancel</button><button class="btn btn-primary" id="m-save"><span id="sv-txt">' + (isEdit ? 'Save' : 'Add') + '</span><span id="sv-load" style="display:none"><span class="spinner-sm"></span> Saving...</span></button></div>';

        showModal();
        updateFieldVisibility();

        document.getElementById('e-type').addEventListener('change', updateFieldVisibility);
        document.getElementById('e-pw').addEventListener('input', function() {
            var s = VaultUtils.calculateStrength(this.value);
            document.getElementById('pw-str').innerHTML = '<div class="strength-bar"><div class="strength-bar-track"><div class="strength-bar-fill" style="width:' + (s.score / 4 * 100) + '%;background:' + s.color + '"></div></div><span class="strength-label">' + s.label + '</span></div>';
        });
        document.getElementById('btn-toggle-pw').addEventListener('click', function() {
            var pw = document.getElementById('e-pw');
            pw.type = pw.type === 'password' ? 'text' : 'password';
        });
        document.getElementById('btn-gen-pw').addEventListener('click', function() {
            document.getElementById('pw-gen').classList.toggle('hidden');
        });

        var genLen = document.getElementById('pw-len');
        var genLenVal = document.getElementById('pw-len-val');
        genLen.addEventListener('input', function() { genLenVal.textContent = genLen.value; });

        function genFill() {
            var pw = VaultUtils.generatePassword(parseInt(genLen.value), {
                uppercase: document.getElementById('pw-up').checked,
                lowercase: document.getElementById('pw-lo').checked,
                numbers: document.getElementById('pw-nu').checked,
                symbols: document.getElementById('pw-sy').checked,
            });
            document.getElementById('e-pw').value = pw;
            document.getElementById('e-pw').type = 'text';
            document.getElementById('e-pw').dispatchEvent(new Event('input'));
            document.getElementById('pw-gen').classList.add('hidden');
        }
        document.getElementById('btn-gen-use').addEventListener('click', genFill);
        genLen.addEventListener('change', genFill);
        ['pw-up','pw-lo','pw-nu','pw-sy'].forEach(function(id) { document.getElementById(id).addEventListener('change', genFill); });
        genFill();

        document.getElementById('m-cancel').addEventListener('click', closeModal);
        document.getElementById('m-save').addEventListener('click', async function() {
            var title = document.getElementById('e-title').value.trim();
            var type = document.getElementById('e-type').value;
            if (!title) { showToast('Title required', 'error'); return; }
            if (type === 'login' && !document.getElementById('e-pw').value && !isEdit) { showToast('Password required', 'error'); return; }

            document.getElementById('sv-txt').style.display = 'none';
            document.getElementById('sv-load').style.display = 'flex';

            try {
                var pw = document.getElementById('e-pw').value;
                var encrypted = pw ? await VaultCrypto.encrypt(masterPassword, salt, pw) : (entry ? entry.encryptedPassword : '');
                var data = {
                    type: type, title: title,
                    website: document.getElementById('e-web').value.trim() || '',
                    username: document.getElementById('e-user').value.trim() || '',
                    encryptedPassword: encrypted,
                    totpSecret: document.getElementById('e-totp').value.trim() || '',
                    notes: document.getElementById('e-notes').value.trim() || '',
                    folderId: document.getElementById('e-folder')?.value || '',
                    passwordStrength: pw ? VaultUtils.calculateStrength(pw).score : (entry ? entry.passwordStrength : 0),
                };
                if (isEdit) {
                    VaultModel.updateEntry(entry.id, data);
                } else {
                    VaultModel.createEntry(data);
                }
                await saveVault();
                closeModal();
                renderApp();
                showToast(isEdit ? 'Updated!' : 'Added!', 'success');
            } catch (e) {
                showToast('Error: ' + e.message, 'error');
            } finally {
                document.getElementById('sv-txt').style.display = '';
                document.getElementById('sv-load').style.display = 'none';
            }
        });
    }

    function updateFieldVisibility() {
        var type = document.getElementById('e-type').value;
        document.getElementById('fg-web').style.display = (type === 'login' || type === 'alias') ? '' : 'none';
        document.getElementById('fg-user').style.display = (type === 'login' || type === 'alias' || type === 'identity') ? '' : 'none';
        document.getElementById('fg-pw').style.display = (type === 'login') ? '' : 'none';
        document.getElementById('fg-totp').style.display = (type === 'login') ? '' : 'none';
    }

    // ====================
    // PASSWORD HEALTH
    // ====================
    function showPasswordHealth() {
        var modal = document.getElementById('modal-content');
        var stats = VaultModel.getPasswordHealthStats();
        var scoreColor = stats.score >= 80 ? 'var(--success)' : stats.score >= 50 ? 'var(--warning)' : 'var(--danger)';
        modal.innerHTML = '<div class="modal-header"><h2>🔐 Password Health</h2></div>' +
            '<div class="modal-body">' +
                '<div style="text-align:center;margin-bottom:24px"><div style="font-size:48px;font-weight:700;color:' + scoreColor + '">' + stats.score + '%</div><div class="text-muted">Health Score</div></div>' +
                '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">' +
                    '<div class="card" style="text-align:center;padding:16px"><div style="font-size:24px;font-weight:600">' + stats.total + '</div><div class="text-sm text-muted">Total</div></div>' +
                    '<div class="card" style="text-align:center;padding:16px"><div style="font-size:24px;font-weight:600;color:var(--danger)">' + stats.weak + '</div><div class="text-sm text-muted">Weak</div></div>' +
                    '<div class="card" style="text-align:center;padding:16px"><div style="font-size:24px;font-weight:600;color:var(--success)">' + stats.strong + '</div><div class="text-sm text-muted">Strong</div></div>' +
                    '<div class="card" style="text-align:center;padding:16px"><div style="font-size:24px;font-weight:600;color:var(--warning)">' + stats.reused + '</div><div class="text-sm text-muted">Reused</div></div>' +
                '</div>' +
            '</div>' +
            '<div class="modal-footer"><button class="btn btn-outline" id="m-cancel">Close</button></div>';
        showModal();
        document.getElementById('m-cancel').addEventListener('click', closeModal);
    }

    // ====================
    // IMPORT / EXPORT
    // ====================
    function showImportExport() {
        var modal = document.getElementById('modal-content');
        modal.innerHTML = '<div class="modal-header"><h2>📦 Import / Export</h2></div>' +
            '<div class="modal-body">' +
                '<h3 style="margin-bottom:12px">Export</h3>' +
                '<div style="display:flex;gap:8px;margin-bottom:24px"><button class="btn btn-primary" id="btn-exp-json">Export JSON</button><button class="btn btn-outline" id="btn-exp-csv">Export CSV</button></div>' +
                '<hr style="border:none;border-top:1px solid var(--border);margin:24px 0">' +
                '<h3 style="margin-bottom:12px">Import</h3>' +
                '<input type="file" id="imp-file" accept=".json" style="display:none">' +
                '<button class="btn btn-outline" id="btn-imp">Choose File</button>' +
                '<div id="imp-status" style="margin-top:12px"></div>' +
            '</div>' +
            '<div class="modal-footer"><button class="btn btn-outline" id="m-cancel">Close</button></div>';
        showModal();
        document.getElementById('m-cancel').addEventListener('click', closeModal);

        document.getElementById('btn-exp-json').addEventListener('click', function() {
            var data = VaultModel.exportData('json');
            var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            var a = document.createElement('a'); a.href = URL.createObjectURL(blob);
            a.download = 'vault-backup-' + new Date().toISOString().slice(0, 10) + '.json'; a.click();
            showToast('Exported!', 'success');
        });
        document.getElementById('btn-exp-csv').addEventListener('click', function() {
            var data = VaultModel.exportData('csv');
            var blob = new Blob([data], { type: 'text/csv' });
            var a = document.createElement('a'); a.href = URL.createObjectURL(blob);
            a.download = 'vault-backup-' + new Date().toISOString().slice(0, 10) + '.csv'; a.click();
            showToast('CSV exported!', 'success');
        });
        var impFile = document.getElementById('imp-file');
        document.getElementById('btn-imp').addEventListener('click', function() { impFile.click(); });
        impFile.addEventListener('change', async function(e) {
            var file = e.target.files[0];
            if (!file) return;
            try {
                var data = await VaultStorage.importFromFile(file);
                if (data && data.entries) {
                    VaultModel.importData(data);
                    await saveVault();
                    document.getElementById('imp-status').innerHTML = '<div class="card" style="border-color:var(--success)"><div class="card-body">✅ Imported ' + data.entries.length + ' items</div></div>';
                    renderApp();
                } else {
                    document.getElementById('imp-status').innerHTML = '<div class="card" style="border-color:var(--danger)"><div class="card-body">❌ Invalid file</div></div>';
                }
            } catch (err) {
                document.getElementById('imp-status').innerHTML = '<div class="card" style="border-color:var(--danger)"><div class="card-body">❌ ' + err.message + '</div></div>';
            }
        });
    }

    // ====================
    // SETTINGS
    // ====================
    function showSettings() {
        var s = VaultModel.getSettings();
        var modal = document.getElementById('modal-content');
        modal.innerHTML = '<div class="modal-header"><h2>⚙️ Settings</h2></div>' +
            '<div class="modal-body">' +
                '<div class="settings-info-row"><span class="settings-info-label">Theme</span><button class="btn btn-outline btn-sm" id="set-theme">' + (s.theme || 'system') + '</button></div>' +
                '<div class="settings-info-row"><span class="settings-info-label">Clipboard clear</span><select class="form-input" id="set-clip" style="width:auto"><option value="0"' + (s.clipboardClearTime === 0 ? ' selected' : '') + '>Disabled</option><option value="15"' + (s.clipboardClearTime === 15 ? ' selected' : '') + '>15s</option><option value="30"' + (s.clipboardClearTime === 30 ? ' selected' : '') + '>30s</option><option value="60"' + (s.clipboardClearTime === 60 ? ' selected' : '') + '>60s</option></select></div>' +
                '<div class="settings-info-row"><span class="settings-info-label">Auto-lock</span><select class="form-input" id="set-lock" style="width:auto"><option value="0"' + (s.autoLockTime === 0 ? ' selected' : '') + '>Disabled</option><option value="5"' + (s.autoLockTime === 5 ? ' selected' : '') + '>5 min</option><option value="15"' + (s.autoLockTime === 15 ? ' selected' : '') + '>15 min</option><option value="30"' + (s.autoLockTime === 30 ? ' selected' : '') + '>30 min</option><option value="60"' + (s.autoLockTime === 60 ? ' selected' : '') + '>1 hour</option></select></div>' +
                '<div class="settings-info-row"><span class="settings-info-label">IPFS CID</span><span class="settings-info-value" style="font-size:11px;font-family:monospace;word-break:break-all">' + (VaultStorage.getCID() || 'Not saved to IPFS yet') + '</span></div>' +
                '<div style="margin-top:24px"><button class="btn btn-primary btn-full" id="btn-save-ipfs">💾 Save Vault to IPFS</button><p class="form-hint text-center" style="margin-top:8px">Manually sync your encrypted vault to IPFS</p></div>' +
            '</div>' +
            '<div class="modal-footer"><button class="btn btn-outline" id="m-cancel">Close</button></div>';
        showModal();
        document.getElementById('m-cancel').addEventListener('click', closeModal);
        document.getElementById('set-theme').addEventListener('click', function() {
            var themes = ['light', 'dark', 'system'];
            var idx = themes.indexOf(s.theme || 'system');
            var next = themes[(idx + 1) % 3];
            VaultModel.updateSettings({ theme: next });
            document.documentElement.setAttribute('data-theme', next);
            this.textContent = next;
        });
        document.getElementById('set-clip').addEventListener('change', function() {
            VaultModel.updateSettings({ clipboardClearTime: parseInt(this.value) });
        });
        document.getElementById('set-lock').addEventListener('change', function() {
            VaultModel.updateSettings({ autoLockTime: parseInt(this.value) });
        });
        document.getElementById('btn-save-ipfs').addEventListener('click', async function() {
            this.disabled = true; this.textContent = 'Saving...';
            try {
                await saveVault();
                showToast('Vault saved to IPFS!', 'success');
                showSettings(); // Refresh to show new CID
            } catch (e) {
                showToast('Save failed: ' + e.message, 'error');
                this.disabled = false; this.textContent = '💾 Save Vault to IPFS';
            }
        });
    }

    // ====================
    // MODAL / TOAST
    // ====================
    function showModal() { document.getElementById('modal-overlay').classList.add('active'); document.body.style.overflow = 'hidden'; }
    function closeModal() { document.getElementById('modal-overlay').classList.remove('active'); document.body.style.overflow = ''; }

    function showToast(msg, type) {
        var c = document.getElementById('toast-container');
        if (!c) { c = document.createElement('div'); c.id = 'toast-container'; c.className = 'toast-container'; document.body.appendChild(c); }
        var t = document.createElement('div'); t.className = 'toast toast-' + (type || 'info'); t.textContent = msg; c.appendChild(t);
        setTimeout(function() { t.classList.add('toast-out'); setTimeout(function() { t.remove(); }, 300); }, 3000);
    }

})();
