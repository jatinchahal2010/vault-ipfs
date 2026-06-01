/**
 * VaultModel — Data Management Layer
 * 
 * Manages all vault entries, folders, and settings.
 * All data is stored in memory and synced to IPFS as encrypted blob.
 * 
 * Vault structure:
 * {
 *   version: 2,
 *   entries: [...],
 *   folders: [...],
 *   settings: {...},
 *   updatedAt: "ISO date"
 * }
 */

const VaultModel = (() => {
    let data = {
        version: 2,
        entries: [],
        folders: [],
        settings: {
            clipboardClearTime: 30,
            autoLockTime: 30,
            theme: 'system',
        },
        updatedAt: null,
    };

    /**
     * Generate UUID v4
     */
    function uuid() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        });
    }

    // ====================
    // ENTRIES CRUD
    // ====================

    function createEntry(entryData) {
        const entry = {
            id: uuid(),
            type: entryData.type || 'login',
            title: entryData.title || '',
            website: entryData.website || '',
            username: entryData.username || '',
            encryptedPassword: entryData.encryptedPassword || '',
            totpSecret: entryData.totpSecret || '',
            notes: entryData.notes || '',
            customFields: entryData.customFields || [],
            extraFields: entryData.extraFields || {},
            folderId: entryData.folderId || '',
            isFavorite: false,
            isDeleted: false,
            passwordStrength: entryData.passwordStrength || 0,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
        };
        data.entries.push(entry);
        touch();
        return entry;
    }

    function getEntry(id) {
        return data.entries.find(e => e.id === id);
    }

    function updateEntry(id, updates) {
        const entry = getEntry(id);
        if (!entry) return null;
        
        Object.keys(updates).forEach(key => {
            if (key !== 'id' && key !== 'createdAt') {
                entry[key] = updates[key];
            }
        });
        entry.updatedAt = new Date().toISOString();
        touch();
        return entry;
    }

    function deleteEntry(id) {
        const entry = getEntry(id);
        if (!entry) return false;
        entry.isDeleted = true;
        entry.updatedAt = new Date().toISOString();
        touch();
        return true;
    }

    function restoreEntry(id) {
        const entry = getEntry(id);
        if (!entry) return false;
        entry.isDeleted = false;
        entry.updatedAt = new Date().toISOString();
        touch();
        return true;
    }

    function purgeEntry(id) {
        const idx = data.entries.findIndex(e => e.id === id);
        if (idx === -1) return false;
        data.entries.splice(idx, 1);
        touch();
        return true;
    }

    function toggleFavorite(id) {
        const entry = getEntry(id);
        if (!entry) return null;
        entry.isFavorite = !entry.isFavorite;
        entry.updatedAt = new Date().toISOString();
        touch();
        return entry;
    }

    function duplicateEntry(id) {
        const entry = getEntry(id);
        if (!entry) return null;
        const newEntry = createEntry({
            ...entry,
            id: undefined,
            title: entry.title + ' (copy)',
        });
        return newEntry;
    }

    // ====================
    // FOLDERS CRUD
    // ====================

    function createFolder(name, icon = 'folder') {
        const folder = {
            id: uuid(),
            name: name || 'New Folder',
            icon: icon,
            createdAt: new Date().toISOString(),
        };
        data.folders.push(folder);
        touch();
        return folder;
    }

    function updateFolder(id, updates) {
        const folder = data.folders.find(f => f.id === id);
        if (!folder) return null;
        Object.assign(folder, updates);
        touch();
        return folder;
    }

    function deleteFolder(id) {
        const idx = data.folders.findIndex(f => f.id === id);
        if (idx === -1) return false;
        data.folders.splice(idx, 1);
        // Move entries out of folder
        data.entries.forEach(e => {
            if (e.folderId === id) e.folderId = '';
        });
        touch();
        return true;
    }

    function getFolder(id) {
        return data.folders.find(f => f.id === id);
    }

    // ====================
    // QUERIES
    // ====================

    function getEntries(view = 'all', search = '', type = '') {
        let entries = [...data.entries];

        // View filter
        switch (view) {
            case 'favorites':
                entries = entries.filter(e => e.isFavorite && !e.isDeleted);
                break;
            case 'trash':
                entries = entries.filter(e => e.isDeleted);
                break;
            default:
                if (view.startsWith('folder-')) {
                    const folderId = view.substring(7);
                    entries = entries.filter(e => e.folderId === folderId && !e.isDeleted);
                } else {
                    entries = entries.filter(e => !e.isDeleted);
                }
        }

        // Type filter
        if (type) {
            entries = entries.filter(e => e.type === type);
        }

        // Search filter
        if (search) {
            const q = search.toLowerCase();
            entries = entries.filter(e =>
                (e.title || '').toLowerCase().includes(q) ||
                (e.website || '').toLowerCase().includes(q) ||
                (e.username || '').toLowerCase().includes(q) ||
                (e.notes || '').toLowerCase().includes(q)
            );
        }

        // Sort by updated date
        entries.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        return entries;
    }

    function getFolders() {
        return [...data.folders];
    }

    function getStats() {
        const active = data.entries.filter(e => !e.isDeleted);
        return {
            total: active.length,
            favorites: active.filter(e => e.isFavorite).length,
            trash: data.entries.filter(e => e.isDeleted).length,
            folders: data.folders.length,
            byType: {
                login: active.filter(e => e.type === 'login').length,
                alias: active.filter(e => e.type === 'alias').length,
                note: active.filter(e => e.type === 'note').length,
                identity: active.filter(e => e.type === 'identity').length,
                credit_card: active.filter(e => e.type === 'credit_card').length,
            },
            weakPasswords: active.filter(e => e.passwordStrength > 0 && e.passwordStrength <= 2).length,
        };
    }

    // ====================
    // PASSWORD HEALTH
    // ====================

    function getPasswordHealthStats() {
        const active = data.entries.filter(e => e.isDeleted === false && e.encryptedPassword);
        const total = active.length;
        if (total === 0) return { score: 100, total: 0, weak: 0, reused: 0, strong: 0 };

        let weak = 0;
        let reused = 0;

        // Weak passwords
        weak = active.filter(e => e.passwordStrength > 0 && e.passwordStrength <= 2).length;

        // Reuse detection (can't detect with encrypted passwords without decrypting)
        // Would need client-side decryption to check for duplicates
        // For now, we mark this as "requires manual check"

        const score = Math.round(((total - weak) / total) * 100);

        return {
            score,
            total,
            weak,
            reused,
            strong: total - weak,
        };
    }

    // ====================
    // IMPORT / EXPORT
    // ====================

    function exportData(format = 'json') {
        data.updatedAt = new Date().toISOString();
        
        if (format === 'csv') {
            let csv = 'title,type,website,username,password,notes,totpSecret,folder\n';
            data.entries.filter(e => !e.isDeleted).forEach(e => {
                csv += `"${(e.title||'').replace(/"/g,'""')}","${e.type}","${(e.website||'').replace(/"/g,'""')}","${(e.username||'').replace(/"/g,'""')}","[encrypted]","${(e.notes||'').replace(/"/g,'""')}","${e.totpSecret||''}","${e.folderId||''}"\n`;
            });
            return csv;
        }
        
        return JSON.parse(JSON.stringify(data));
    }

    function importData(imported, merge = false) {
        if (!imported || typeof imported !== 'object') return false;

        if (!merge) {
            // Full replace
            data = {
                version: 2,
                entries: imported.entries || [],
                folders: imported.folders || [],
                settings: imported.settings || data.settings,
                updatedAt: new Date().toISOString(),
            };
        } else {
            // Merge: add new entries, avoid duplicates by ID
            const existingIds = new Set(data.entries.map(e => e.id));
            (imported.entries || []).forEach(e => {
                if (!existingIds.has(e.id)) {
                    data.entries.push(e);
                }
            });
            const existingFolderIds = new Set(data.folders.map(f => f.id));
            (imported.folders || []).forEach(f => {
                if (!existingFolderIds.has(f.id)) {
                    data.folders.push(f);
                }
            });
        }
        touch();
        return true;
    }

    // ====================
    // SETTINGS
    // ====================

    function getSettings() {
        return { ...data.settings };
    }

    function updateSettings(updates) {
        Object.assign(data.settings, updates);
        touch();
        return data.settings;
    }

    // ====================
    // DATA ACCESS
    // ====================

    function getData() {
        return JSON.parse(JSON.stringify(data));
    }

    function setData(newData) {
        if (newData && typeof newData === 'object') {
            data = JSON.parse(JSON.stringify(newData));
            data.version = 2;
            touch();
            return true;
        }
        return false;
    }

    function touch() {
        data.updatedAt = new Date().toISOString();
    }

    function isEmpty() {
        return data.entries.filter(e => !e.isDeleted).length === 0;
    }

    return {
        uuid,
        createEntry,
        getEntry,
        updateEntry,
        deleteEntry,
        restoreEntry,
        purgeEntry,
        toggleFavorite,
        duplicateEntry,
        createFolder,
        updateFolder,
        deleteFolder,
        getFolder,
        getEntries,
        getFolders,
        getStats,
        getPasswordHealthStats,
        exportData,
        importData,
        getSettings,
        updateSettings,
        getData,
        setData,
        isEmpty,
    };
})();
