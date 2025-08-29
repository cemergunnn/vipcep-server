const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');

// PostgreSQL bağlantısı - Railway için güncellenmiş
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

console.log('🔗 Database URL:', process.env.DATABASE_URL ? 'FOUND' : 'NOT FOUND');
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');

// Express app oluştur
const app = express();
const server = http.createServer(app);

// Port ayarı (Railway için)
const PORT = process.env.PORT || 8080;

// Güvenlik konfigürasyonları
const SECURITY_CONFIG = {
    SUPER_ADMIN_PATH: 'panel-admin',
    NORMAL_ADMIN_PATH: 'desk-admin',
    CUSTOMER_PATH: 'app-customer',
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    TOTP_ISSUER: 'VIPCEP System',
    TOTP_WINDOW: 2
};

// Middleware
app.use(session({
    secret: SECURITY_CONFIG.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// WebSocket server
const wss = new WebSocket.Server({ server });

// Global değişkenler
const clients = new Map();
const activeHeartbeats = new Map();
const activeCallAdmins = new Map();
const activeCalls = new Map();
const adminCallbacks = new Map();  // adminId -> [{customerId, customerName, timestamp}]
const adminLocks = new Map();  // adminId -> { lockedBy, lockTime }
let currentAnnouncement = null;
const announcementClients = new Map();  // müşteri ID'leri tracking için
const HEARTBEAT_INTERVAL = 60000;

// ================== HELPER FUNCTIONS ==================

function generateCallId() {
    return `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function broadcastToCustomers(message) {
    clients.forEach(client => {
        if (client.userType === 'customer' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify(message));
        }
    });
}

function broadcastAnnouncementToCustomers(announcement) {
    const message = JSON.stringify({
        type: 'announcement-received',
        announcement: announcement
    });

    let sentCount = 0;
    clients.forEach(client => {
        if (client.userType === 'customer' && client.ws && client.ws.readyState === WebSocket.OPEN) {
            try {
                client.ws.send(message);
                sentCount++;
                console.log(`📢 Duyuru gönderildi: ${client.id}`);
            } catch (error) {
                console.log(`⚠️ Duyuru gönderme hatası: ${client.id}`, error.message);
            }
        }
    });

    console.log(`📡 Duyuru ${sentCount} müşteriye gönderildi`);
}

function broadcastAnnouncementDeletion() {
    const message = JSON.stringify({
        type: 'announcement-deleted'
    });

    let sentCount = 0;
    clients.forEach(client => {
        if (client.userType === 'customer' && client.ws && client.ws.readyState === WebSocket.OPEN) {
            try {
                client.ws.send(message);
                sentCount++;
            } catch (error) {
                console.log(`⚠️ Duyuru silme hatası: ${client.id}`, error.message);
            }
        }
    });

    console.log(`🗑️ Duyuru silme ${sentCount} müşteriye gönderildi`);
}

function broadcastAdminListToCustomers() {
    // DÜZELTME: Admin filtrelemesini iyileştir
    const adminList = Array.from(clients.values())
        .filter(c => {
            return c.userType === 'admin' &&
                   c.ws &&
                   c.ws.readyState === WebSocket.OPEN &&
                   c.online !== false;  // Offline admin'leri dahil etme
        })
        .map(admin => {
            const adminKey = admin.uniqueId || admin.id;
            const isInCall = activeCallAdmins.has(adminKey);

            return {
                id: adminKey,
                name: admin.name,
                status: (isInCall || adminLocks.has(adminKey)) ? 'busy' : 'available'
            };
        });

    // DÜZELTME: En son aktif admin'i tut
    const uniqueAdmins = [];
    const adminMap = new Map();

    adminList.forEach(admin => {
        const baseId = admin.id.split('_')[0];  // ADMIN001_123_abc -> ADMIN001

        // Eğer bu base ID için admin yoksa veya mevcut admin daha yeni ise
        if (!adminMap.has(baseId) || admin.id > adminMap.get(baseId).id) {
            adminMap.set(baseId, admin);
        }
    });

    // Map'den array'e çevir
    adminMap.forEach(admin => uniqueAdmins.push(admin));

    const message = JSON.stringify({
        type: 'admin-list-update',
        admins: uniqueAdmins  // Unique admin listesi gönder
    });

    let sentCount = 0;
    clients.forEach(client => {
        if (client.userType === 'customer' && client.ws && client.ws.readyState === WebSocket.OPEN) {
            try {
                client.ws.send(message);
                sentCount++;
            } catch (error) {
                console.log(`⚠️ Admin list broadcast error to ${client.id}`, error.message);
            }
        }
    });

    console.log(`📡 Admin list sent to ${sentCount} customers (${uniqueAdmins.length} unique admins)`);
}

function broadcastCallbacksToAdmin(adminId) {
    const adminClient = Array.from(clients.values()).find(c =>
        c.userType === 'admin' &&
        (c.uniqueId === adminId || c.id === adminId) &&
        c.ws && c.ws.readyState === WebSocket.OPEN
    );

    if (adminClient) {
        const callbacks = adminCallbacks.get(adminId) || [];
        adminClient.ws.send(JSON.stringify({
            type: 'callback-list-update',
            callbacks: callbacks
        }));
        console.log(`📋 Callback list sent to admin ${adminId} (${callbacks.length} callbacks)`);
    }
}

// ================== AUTHENTICATION FUNCTIONS ==================

async function checkRateLimit(ip, userType = 'customer') {
    try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const failedAttempts = await pool.query(
            'SELECT COUNT(*) FROM failed_logins WHERE ip_address = $1 AND user_type = $2 AND attempt_time > $3',
            [ip, userType, thirtyMinutesAgo]
        );

        const count = parseInt(failedAttempts.rows[0].count);

        return {
            allowed: count < 5,
            attempts: count,
            remaining: Math.max(0, 5 - count),
            resetTime: count === 5 ? new Date(Date.now() + 30 * 60 * 1000) : null
        };
    } catch (error) {
        return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
    }
}

async function recordFailedLogin(ip, userType = 'customer') {
    try {
        await pool.query(
            'INSERT INTO failed_logins (ip_address, user_type) VALUES ($1, $2)',
            [ip, userType]
        );

        const rateStatus = await checkRateLimit(ip, userType);
        return rateStatus;
    } catch (error) {
        return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
    }
}

function generateTOTPSecret() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function verifyTOTP(secret, token) {
    if (!secret || !token || token.length !== 6) return false;
    try {
        const secretBuffer = Buffer.from(secret, 'hex');
        const timeStep = 30;
        const currentTime = Math.floor(Date.now() / 1000 / timeStep);
        for (let i = -SECURITY_CONFIG.TOTP_WINDOW; i <= SECURITY_CONFIG.TOTP_WINDOW; i++) {
            const time = currentTime + i;
            const timeBuffer = Buffer.allocUnsafe(8);
            timeBuffer.writeUInt32BE(0, 0);
            timeBuffer.writeUInt32BE(time, 4);
            const hmac = crypto.createHmac('sha1', secretBuffer);
            hmac.update(timeBuffer);
            const hash = hmac.digest();
            const offset = hash[hash.length - 1] & 0xf;
            const code = ((hash[offset] & 0x7f) << 24) |
                         ((hash[offset + 1] & 0xff) << 16) |
                         ((hash[offset + 2] & 0xff) << 8) |
                         (hash[offset + 3] & 0xff);
            const otp = (code % 1000000).toString().padStart(6, '0');
            if (otp === token) {
                return true;
            }
        }
        return false;
    } catch (error) {
        return false;
    }
}

function generateTOTPQR(username, secret) {
    const serviceName = encodeURIComponent(SECURITY_CONFIG.TOTP_ISSUER);
    const accountName = encodeURIComponent(username);
    const otpauthURL = `otpauth://totp/${serviceName}:${accountName}?secret=${secret}&issuer=${serviceName}`;
    return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthURL)}`;
}

// ================== DATABASE FUNCTIONS ==================

async function initDatabase() {
    try {
        console.log('🔧 Veritabanı kontrol ediliyor...');

        // Approved users tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS approved_users (
                id VARCHAR(10) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                credits INTEGER DEFAULT 0,
                total_calls INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_call TIMESTAMP,
                status VARCHAR(20) DEFAULT 'active'
            )
        `);

        // Admin earnings tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_earnings (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                total_earned INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Failed logins tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                user_type VARCHAR(20) NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Log tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS application_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level VARCHAR(10),
                message TEXT
            )
        `);
        
        console.log('✅ Veritabanı tabloları hazır!');
    } catch (error) {
        console.error('❌ Veritabanı başlatma hatası:', error.stack);
        process.exit(1);
    }
}

// Loglama fonksiyonu
async function logToDb(level, message) {
    try {
        await pool.query('INSERT INTO application_logs (level, message) VALUES ($1, $2)', [level, message]);
    } catch (error) {
        console.error('❌ Veritabanı loglama hatası:', error.message);
    }
}

// ================== EXPRESS ROUTES ==================

app.post('/api/login', async (req, res) => {
    // ... (Login mantığı)
});

app.post('/api/logout', (req, res) => {
    // ... (Logout mantığı)
});

app.post('/api/register-admin', async (req, res) => {
    // ... (Admin kayıt mantığı)
});

// ================== WEBSOCKET MESSAGE HANDLER ==================

wss.on('connection', ws => {
    // ... (WebSocket bağlantı mantığı)
});

// ================== SERVER BAŞLATMA VE HATA YAKALAMA ==================

initDatabase().then(() => {
    // HTTP Server'ı başlat
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server çalışıyor!');
        console.log(`📍 Port: ${PORT}`);
        console.log(`🌐 URL: http://0.0.0.0:${PORT}`);
        console.log(`🔌 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('📱 Uygulamalar:');
        console.log(` 👨‍💼 Admin paneli: /admin-panel.html`);
        console.log(` 📱 Müşteri uygulaması: /customer-app.html`);
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('📞 WhatsApp: +90 537 479 24 03');
        console.log('✅ Sistem hazır - Arama kabul ediliyor!');
        console.log('═══════════════════════════════════════════');
    });
}).catch(error => {
    console.log('❌ Veritabanı başlatılamadı, sunucu başlatılmıyor.', error.stack);
    process.exit(1);
});

// Hata yakalama
process.on('uncaughtException', (error) => {
    console.log('❌ Yakalanmamış hata:', error.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.log('❌ İşlenmemiş promise reddi:', reason);
});

process.on('SIGTERM', () => {
    console.log('🔴 Server kapatılıyor...');
    
    for (const [callKey, heartbeat] of activeHeartbeats.entries()) {
        clearInterval(heartbeat);
        console.log(`💔 Stopping heartbeat ${callKey}`);
    }
    activeHeartbeats.clear();
    activeCallAdmins.clear();
    activeCalls.clear();
    adminCallbacks.clear();
    
    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});
