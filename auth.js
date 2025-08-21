// Système d'authentification JWT pour le serveur Snipex Pro
// Gestion des tokens et validation des utilisateurs

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'votre-jwt-secret-super-securise';
const JWT_EXPIRES_IN = '24h'; // Token valide 24 heures

// Stockage temporaire des utilisateurs (en production, utilisez une vraie base de données)
const users = new Map();

// Créer un utilisateur par défaut pour les tests
const createDefaultUser = () => {
    const defaultUser = {
        id: 'default-user-123',
        username: 'default_user',
        email: 'default@snipex.pro',
        password: bcrypt.hashSync('password123', 10),
        isActive: true,
        createdAt: new Date(),
        lastLogin: null
    };
    
    users.set(defaultUser.id, defaultUser);
    users.set(defaultUser.username, defaultUser);
    
    console.log('👤 Utilisateur par défaut créé:', defaultUser.username);
    return defaultUser;
};

// Créer un nouvel utilisateur
const createUser = async ({ username, email, password }) => {
    try {
        // Vérifier si l'utilisateur existe déjà
        if (users.has(username) || users.has(email)) {
            throw new Error('Utilisateur déjà existant');
        }

        // Créer le nouvel utilisateur
        const newUser = {
            id: uuidv4(),
            username,
            email,
            password: await bcrypt.hash(password, 10),
            isActive: true,
            createdAt: new Date(),
            lastLogin: null
        };

        // Stocker l'utilisateur
        users.set(newUser.id, newUser);
        users.set(newUser.username, newUser);
        users.set(newUser.email, newUser);

        console.log('✅ Nouvel utilisateur créé:', username);
        return { id: newUser.id, username: newUser.username, email: newUser.email };
        
    } catch (error) {
        console.error('❌ Erreur lors de la création de l\'utilisateur:', error);
        throw error;
    }
};

// Authentifier un utilisateur
const authenticateUser = async ({ username, password }) => {
    try {
        // Trouver l'utilisateur
        const user = users.get(username) || users.get(username + '@snipex.pro');
        
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }

        if (!user.isActive) {
            throw new Error('Compte désactivé');
        }

        // Vérifier le mot de passe
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            throw new Error('Mot de passe incorrect');
        }

        // Mettre à jour la dernière connexion
        user.lastLogin = new Date();
        users.set(user.id, user);
        users.set(user.username, user);
        users.set(user.email, user);

        console.log('✅ Authentification réussie pour:', username);
        return { id: user.id, username: user.username, email: user.email };
        
    } catch (error) {
        console.error('❌ Erreur lors de l\'authentification:', error);
        throw error;
    }
};

// Générer un token JWT
const generateToken = (user) => {
    try {
        const payload = {
            id: user.id,
            username: user.username,
            email: user.email,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 heures
        };

        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        
        console.log('🔑 Token JWT généré pour:', user.username);
        return token;
        
    } catch (error) {
        console.error('❌ Erreur lors de la génération du token:', error);
        throw error;
    }
};

// Valider un token JWT
const validateToken = (token) => {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Vérifier si l'utilisateur existe toujours
        const user = users.get(decoded.id);
        if (!user || !user.isActive) {
            throw new Error('Utilisateur invalide ou désactivé');
        }

        console.log('✅ Token JWT validé pour:', user.username);
        return {
            id: user.id,
            username: user.username,
            email: user.email
        };
        
    } catch (error) {
        console.error('❌ Erreur lors de la validation du token:', error);
        throw error;
    }
};

// Middleware d'authentification pour Express
const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ 
                error: 'Token d\'authentification manquant',
                message: 'Ajoutez l\'en-tête Authorization: Bearer <token>'
            });
        }

        const user = validateToken(token);
        req.user = user;
        next();
        
    } catch (error) {
        return res.status(403).json({ 
            error: 'Token invalide ou expiré',
            message: error.message
        });
    }
};

// Middleware d'authentification optionnelle
const optionalAuth = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token) {
            const user = validateToken(token);
            req.user = user;
        }

        next();
        
    } catch (error) {
        // Continuer sans authentification
        next();
    }
};

// Vérifier les permissions d'un utilisateur
const checkPermission = (permission) => {
    return (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentification requise' });
            }

            // Ici vous pouvez ajouter une logique de permissions plus complexe
            // Pour l'instant, tous les utilisateurs authentifiés ont accès
            next();
            
        } catch (error) {
            return res.status(403).json({ error: 'Permissions insuffisantes' });
        }
    };
};

// Obtenir les informations d'un utilisateur
const getUserInfo = (userId) => {
    try {
        const user = users.get(userId);
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }

        return {
            id: user.id,
            username: user.username,
            email: user.email,
            isActive: user.isActive,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        };
        
    } catch (error) {
        console.error('❌ Erreur lors de la récupération des infos utilisateur:', error);
        throw error;
    }
};

// Désactiver un utilisateur
const deactivateUser = (userId) => {
    try {
        const user = users.get(userId);
        if (!user) {
            throw new Error('Utilisateur non trouvé');
        }

        user.isActive = false;
        users.set(userId, user);
        users.set(user.username, user);
        users.set(user.email, user);

        console.log('🚫 Utilisateur désactivé:', user.username);
        return true;
        
    } catch (error) {
        console.error('❌ Erreur lors de la désactivation de l\'utilisateur:', error);
        throw error;
    }
};

// Lister tous les utilisateurs (admin only)
const listUsers = () => {
    try {
        const userList = [];
        for (const [key, user] of users.entries()) {
            // Éviter les doublons (un utilisateur peut être stocké sous plusieurs clés)
            if (user.id === key) {
                userList.push({
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    isActive: user.isActive,
                    createdAt: user.createdAt,
                    lastLogin: user.lastLogin
                });
            }
        }

        return userList;
        
    } catch (error) {
        console.error('❌ Erreur lors de la récupération de la liste des utilisateurs:', error);
        throw error;
    }
};

// Initialiser le système d'authentification
const initAuth = () => {
    createDefaultUser();
    console.log('🔐 Système d\'authentification initialisé');
};

// Initialiser au démarrage
initAuth();

// Export des fonctions
module.exports = {
    createUser,
    authenticateUser,
    generateToken,
    validateToken,
    authenticateToken,
    optionalAuth,
    checkPermission,
    getUserInfo,
    deactivateUser,
    listUsers
}; 