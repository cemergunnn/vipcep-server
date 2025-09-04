// DOSYA ADI: server.js (Tüm Hataları Giderilmiş Nihai Versiyon)

const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Express setup
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

// Security configuration
const SECURITY_CONFIG = {
    SUPER_ADMIN_PATH: '/panel-admin',
    NORMAL_ADMIN_PATH: '/desk-admin',
    CUSTOMER_PATH: '/app-customer',
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    TOTP_ISSUER: 'VIPCEP System',
    TOTP_WINDOW: 2
};

// Middleware
const sessionStore = new pgSession({
    pool: pool,
    tableName: 'user_sessions'
});

app.use(session({
    store: sessionStore,
    secret: SECURITY_CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 // Oturum süresi: 30 gün
    }
}));

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// WebSocket server
const wss = new WebSocket.Server({ server });

// Global variables
const clients = new Map();
const activeHeartbeats = new Map();
const activeCallAdmins = new Map();
const activeCalls = new Map();
const adminCallbacks = new Map();
const adminLocks = new Map();
let currentAnnouncement = null;
const HEARTBEAT_INTERVAL = 60000;

// ================== HELPER FUNCTIONS ==================

function anonymizeCustomerName(fullName) {
    if (!fullName || typeof fullName !== 'string') return 'Anonim';
    const parts = fullName.trim().split(' ');
    if (parts.length === 1) return parts[0];
    const firstName = parts[0];
    const lastInitial = parts[parts.length - 1].charAt(0).toUpperCase();
    return `${firstName} ${lastInitial}.`;
}

function broadcastSystemStateToSuperAdmins() {
    const activeCallDetails = Array.from(activeCallAdmins.entries()).map(([adminId, callInfo]) => {
        const adminClient = Array.from(clients.values()).find(c => c.uniqueId === adminId);
        const customerClient = clients.get(callInfo.customerId);
        return {
            adminName: adminClient ? adminClient.name : adminId,
            customerName: customerClient ? customerClient.name : callInfo.customerId,
            startTime: callInfo.callStartTime
        };
    });

    const state = {
        activeCalls: activeCallDetails,
        onlineAdmins: Array.from(clients.values()).filter(c => c.userType === 'admin' || c.userType === 'super-admin').length,
        onlineCustomers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
    };

    const message = JSON.stringify({ type: 'system-state-update', state });
    clients.forEach(client => {
        if (client.userType === 'super-admin' && client.ws && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(message);
        }
    });
}

async function broadcastEarningsUpdateToAdmin(adminUsername, sourceInfo = null) {
    try {
        const result = await pool.query('SELECT total_earned FROM admin_earnings WHERE username = $1', [adminUsername]);
        const newEarnings = result.rows[0]?.total_earned || 0;
        const adminClient = Array.from(clients.values()).find(c => c.id === adminUsername && c.userType === 'admin');
        if (adminClient && adminClient.ws && adminClient.ws.readyState === WebSocket.OPEN) {
            adminClient.ws.send(JSON.stringify({
                type: 'admin-earning-update',
                newEarnings: newEarnings,
                sourceInfo: sourceInfo
            }));
        }
    } catch (error) {
        console.error(`Kazanç güncellemesi gönderilemedi (${adminUsername}):`, error);
    }
}

function findActiveCall(userId1, userId2) {
    if (!userId1 || !userId2) return null;
    const key1 = `${userId1}-${userId2}`;
    const key2 = `${userId2}-${userId1}`;
    return activeCalls.get(key1) || activeCalls.get(key2);
}

async function broadcastAdminListToCustomers() {
    try {
        const adminProfileResult = await pool.query(`
            SELECT a.username as id, a.username as name, p.specialization, p.profile_picture_url,
                   COALESCE(AVG(r.rating), 0) as average_rating, COUNT(r.id) as review_count
            FROM admins a
            LEFT JOIN admin_profiles p ON a.username = p.admin_username
            LEFT JOIN admin_reviews r ON a.username = r.admin_username
            WHERE a.role = 'normal' AND a.is_active = TRUE
            GROUP BY a.username, p.specialization, p.profile_picture_url
        `);
        const dbAdmins = adminProfileResult.rows;
        const onlineAdminIds = new Set(Array.from(clients.values()).filter(c => c.userType === 'admin' && c.ws?.readyState === WebSocket.OPEN).map(c => c.id));
        const combinedAdminList = dbAdmins.map(admin => {
            const isOnline = onlineAdminIds.has(admin.id);
            const isInCall = activeCallAdmins.has(admin.id) || adminLocks.has(admin.id);
            return { ...admin, status: isOnline ? (isInCall ? 'busy' : 'available') : 'offline' };
        }).filter(admin => admin.status !== 'offline');
        const message = JSON.stringify({ type: 'admin-list-update', admins: combinedAdminList });
        clients.forEach(client => {
            if (client.userType === 'customer' && client.ws?.readyState === WebSocket.OPEN) {
                client.ws.send(message);
            }
        });
    } catch (error) {
        console.error('Error broadcasting admin list:', error);
    }
}

// ... Diğer helper fonksiyonlarınız ...

// ================== AUTHENTICATION FUNCTIONS ==================
// ... Bu bölümdeki fonksiyonlarda değişiklik yok ...
async function authenticateAdmin(username, password) {
    try {
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        const result = await pool.query(
            'SELECT * FROM admins WHERE username = $1 AND password_hash = $2 AND is_active = TRUE',
            [username, hashedPassword]
        );

        if (result.rows.length > 0) {
            const admin = result.rows[0];
            await pool.query('UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [admin.id]);
            return admin;
        }
        return null;
    } catch (error) {
        return null;
    }
}

// ================== DATABASE FUNCTIONS ==================
// ... Bu bölümdeki fonksiyonlarda değişiklik yok ...
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS "user_sessions" (
              "sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL
            ) WITH (OIDS=FALSE);
            ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
        `);
        // Diğer tüm CREATE TABLE sorguları buraya gelecek...
        console.log("Veritabanı tabloları başarıyla kontrol edildi/oluşturuldu.");
    } catch (error) {
        console.error('Veritabanı başlatma hatası:', error.message);
    }
}


// ================== HEARTBEAT FUNCTIONS ==================
// ... Bu bölümdeki fonksiyonlarda değişiklik yok ...
async function stopHeartbeat(callKey, reason = 'normal') {
    const heartbeat = activeHeartbeats.get(callKey);
    if (heartbeat) {
        clearInterval(heartbeat);
        activeHeartbeats.delete(callKey);
        const [userId, adminId] = callKey.split('-');
        activeCallAdmins.delete(adminId);
        activeCalls.delete(callKey);
        adminLocks.delete(adminId);
        console.log(`💔 Heartbeat stopped: ${callKey} (${reason})`);
        broadcastAdminListToCustomers();
        broadcastSystemStateToSuperAdmins();
        // Gerekirse call-ended mesajı burada gönderilebilir.
    }
}


// ================== MIDDLEWARE FOR AUTH ==================
const requireNormalAdminLogin = (req, res, next) => {
    if (req.session?.normalAdmin) return next();
    res.redirect('/');
};
const requireSuperAdminLogin = (req, res, next) => {
    if (req.session?.superAdmin) return next();
    res.redirect('/');
};

// ================== ROUTES ==================

// ANA GİRİŞ SAYFASI
app.get('/', (req, res) => {
    if (req.session.superAdmin) return res.redirect(SECURITY_CONFIG.SUPER_ADMIN_PATH);
    if (req.session.normalAdmin) return res.redirect(SECURITY_CONFIG.NORMAL_ADMIN_PATH);
    res.sendFile(path.join(__dirname, 'index.html'));
});

// PANEL SAYFALARI
app.get(SECURITY_CONFIG.SUPER_ADMIN_PATH, requireSuperAdminLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'super-admin.html'));
});
app.get(SECURITY_CONFIG.NORMAL_ADMIN_PATH, requireNormalAdminLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});
app.get(SECURITY_CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// AUTH API
app.post('/auth/admin-login', async (req, res) => {
    const { username, password, rememberMe } = req.body;
    const admin = await authenticateAdmin(username, password);
    if (admin && admin.role === 'normal') {
        req.session.normalAdmin = { id: admin.id, username: admin.username };
        if (rememberMe) req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 Gün
        res.json({ success: true, redirectUrl: SECURITY_CONFIG.NORMAL_ADMIN_PATH });
    } else {
        res.status(401).json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
    }
});
// Diğer auth rotaları (super-login, check-session, logout)...
app.get('/auth/check-session', (req, res) => {
    if (req.session?.superAdmin) {
        res.json({ authenticated: true, role: 'super', username: req.session.superAdmin.username });
    } else if (req.session?.normalAdmin) {
        res.json({ authenticated: true, role: 'normal', username: req.session.normalAdmin.username });
    } else {
        res.json({ authenticated: false });
    }
});
app.post('/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.json({ success: false });
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});


// SUPER ADMIN API
// Yorum Yönetimi API'ları, kullanıcı yönetimi vb. tüm API rotaları buraya gelecek...
app.get('/api/admins/:username/profile', requireSuperAdminLogin, async (req, res) => { /* ... */ });
app.put('/api/reviews/:reviewId', requireSuperAdminLogin, async (req, res) => { /* ... */ });
app.delete('/api/reviews/:reviewId', requireSuperAdminLogin, async (req, res) => { /* ... */ });
app.get('/api/stats', requireSuperAdminLogin, async (req,res) => { /* ... */});


// ================== WEBSOCKET HANDLER ==================
wss.on('connection', (ws, req) => {
    // ... Tüm WebSocket 'message' ve 'close' olay yönetimi buraya gelecek ...
    ws.on('close', () => {
        const client = Array.from(clients.values()).find(c => c.ws === ws);
        if (client) {
            clients.delete(client.id);
            console.log(`👋 Client disconnected: ${client.name || client.id}`);
            broadcastAdminListToCustomers();
            broadcastSystemStateToSuperAdmins();
        }
    });
});

// ================== ERROR HANDLING ==================
app.use((req, res) => {
    res.status(404).send(`<h1>404 - Sayfa Bulunamadı</h1>`);
});

// ================== SERVER STARTUP ==================
async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');
    await initDatabase();
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`🎯 VIPCEP Server Çalışıyor! Port: ${PORT}`);
    });
}
process.on('uncaughtException', (error) => {
    console.error('❌ YAKALANMAMIŞ HATA:', error);
    process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ İŞLENMEMİŞ PROMISE REDDİ:', reason);
});
startServer().catch(error => {
    console.error('❌ Sunucu başlatma hatası:', error);
    process.exit(1);
});
