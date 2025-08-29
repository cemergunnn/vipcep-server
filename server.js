const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');

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

// Global variables
const clients = new Map();
const activeHeartbeats = new Map();
const activeCallAdmins = new Map();
const activeCalls = new Map();
const adminCallbacks = new Map(); // adminId -> [{customerId, customerName, timestamp}]
const adminLocks = new Map(); // adminId -> { lockedBy, lockTime }
let currentAnnouncement = null;
const announcementClients = new Map(); // müşteri ID'leri tracking için
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
                   c.online !== false; // Offline admin'leri dahil etme
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
    const baseId = admin.id.split('_')[0]; // ADMIN001_123_abc -> ADMIN001
    
    // Eğer bu base ID için admin yoksa veya mevcut admin daha yeni ise
    if (!adminMap.has(baseId) || admin.id > adminMap.get(baseId).id) {
        adminMap.set(baseId, admin);
    }
});

// Map'den array'e çevir
adminMap.forEach(admin => uniqueAdmins.push(admin));

    const message = JSON.stringify({
        type: 'admin-list-update',
        admins: uniqueAdmins // Unique admin listesi gönder
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
            resetTime: count >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null
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
            const code = ((hash[offset] & 0x7f) << 24) 
                        | ((hash[offset + 1] & 0xff) << 16) 
                        | ((hash[offset + 2] & 0xff) << 8) 
                        | (hash[offset + 3] & 0xff);
            
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
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_earnings (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                total_earned INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS call_history (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(10),
                user_name VARCHAR(255),
                admin_id VARCHAR(10),
                duration INTEGER DEFAULT 0,
                credits_used INTEGER DEFAULT 0,
                call_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_reason VARCHAR(50) DEFAULT 'normal',
                connection_lost BOOLEAN DEFAULT FALSE
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS credit_transactions (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(10),
                transaction_type VARCHAR(20),
                amount INTEGER,
                balance_after INTEGER,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'normal',
                is_active BOOLEAN DEFAULT TRUE,
                totp_secret VARCHAR(64),
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS kvkk_consents (
                id SERIAL PRIMARY KEY,
                consent_hash VARCHAR(64) UNIQUE NOT NULL,
                ip_address INET,
                user_agent TEXT,
                consent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version VARCHAR(10) DEFAULT '1.0'
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                ip_address INET NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_type VARCHAR(20) DEFAULT 'customer'
            )
        `);

        // Create super admin if not exists
        const superAdminCheck = await pool.query('SELECT * FROM admins WHERE role = $1', ['super']);
        if (superAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
            const totpSecret = generateTOTPSecret();
            await pool.query(`
                INSERT INTO admins (username, password_hash, role, totp_secret)
                VALUES ($1, $2, $3, $4)
            `, ['superadmin', hashedPassword, 'super', totpSecret]);
            console.log('🔐 Super Admin created');
            console.log(` Username: superadmin`);
            console.log(` Password: admin123`);
            console.log(` TOTP Secret: ${totpSecret}`);
            console.log(` QR Code URL: ${generateTOTPQR('superadmin', totpSecret)}`);
        } else {
            console.log('🔐 Super Admin already exists');
            const admin = superAdminCheck.rows[0];
            if (admin.totp_secret) {
                console.log(` Username: ${admin.username}`);
                console.log(` TOTP Secret: ${admin.totp_secret}`);
                console.log(` QR Code URL: ${generateTOTPQR(admin.username, admin.totp_secret)}`);
            }
        }

        // Create test users
        const testUsers = [
            ['1234', 'Test Kullanıcı', 10],
            ['0005', 'VIP Müşteri', 25],
            ['0007', 'Cenk Zortu', 999],
            ['9999', 'Demo User', 5]
        ];

        for (const [id, name, credits] of testUsers) {
            const existingUser = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
            if (existingUser.rows.length === 0) {
                await pool.query(`
                    INSERT INTO approved_users (id, name, credits)
                    VALUES ($1, $2, $3)
                `, [id, name, credits]);
            }
        }

        // Create normal admin
        const normalAdminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin1']);
        if (normalAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('password123').digest('hex');
            await pool.query(`
                INSERT INTO admins (username, password_hash, role)
                VALUES ($1, $2, $3)
            `, ['admin1', hashedPassword, 'normal']);
        }
    } catch (error) {
        console.log('Database error:', error.message);
    }
}

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

async function isUserApproved(userId, userName) {
    try {
        const result = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (user.name.toLowerCase().trim() === userName.toLowerCase().trim()) {
                return {
                    approved: true,
                    credits: user.credits,
                    totalCalls: user.total_calls || 0,
                    lastCall: user.last_call,
                    user: user
                };
            } else {
                return { approved: false, reason: 'İsim uyuşmuyor.' };
            }
        } else {
            return { approved: false, reason: 'ID kodu bulunamadı.' };
        }
    } catch (error) {
        return { approved: false, reason: 'Sistem hatası.' };
    }
}

// ================== HEARTBEAT FUNCTIONS ==================

function startHeartbeat(userId, adminId, callKey) {
    if (activeHeartbeats.has(callKey)) {
        clearInterval(activeHeartbeats.get(callKey));
    }
    const heartbeatInterval = setInterval(() => {
        const call = activeCalls.get(callKey);
        if (call) {
            call.duration += HEARTBEAT_INTERVAL / 1000;
        } else {
            clearInterval(heartbeatInterval);
            activeHeartbeats.delete(callKey);
            console.log(`💔 Heartbeat durduruldu: ${callKey}`);
        }
    }, HEARTBEAT_INTERVAL);
    activeHeartbeats.set(callKey, heartbeatInterval);
}

function stopHeartbeat(callKey) {
    if (activeHeartbeats.has(callKey)) {
        clearInterval(activeHeartbeats.get(callKey));
        activeHeartbeats.delete(callKey);
        console.log(`💔 Heartbeat durduruldu: ${callKey}`);
    }
}

// ================== EXPRESS ROUTES ==================

// Oturum kontrol middleware
function requireAuth(role) {
    return (req, res, next) => {
        if (!req.session.isAuthenticated || req.session.userRole !== role) {
            console.log(`❌ Erişim reddedildi: ${req.session.userRole} -> ${req.originalUrl}`);
            return res.status(401).json({ error: 'Yetkisiz erişim.' });
        }
        next();
    };
}

// LOGIN SAYFASI
app.post('/api/login', async (req, res) => {
    const { username, password, totp_token } = req.body;
    try {
        const admin = await authenticateAdmin(username, password);
        if (!admin) {
            const ip = req.ip;
            const rateStatus = await recordFailedLogin(ip, 'admin');
            return res.status(401).json({ 
                success: false, 
                message: 'Kullanıcı adı veya parola hatalı.',
                attemptsRemaining: rateStatus.remaining,
                isRateLimited: !rateStatus.allowed
            });
        }
        
        // TOTP doğrulama
        if (admin.totp_secret && !verifyTOTP(admin.totp_secret, totp_token)) {
            return res.status(401).json({ success: false, message: '2FA kodu hatalı.' });
        }
        
        req.session.isAuthenticated = true;
        req.session.userId = admin.id;
        req.session.username = admin.username;
        req.session.userRole = admin.role;
        req.session.lastActive = Date.now();
        
        res.json({ success: true, message: 'Giriş başarılı!', role: admin.role, username: admin.username });
        console.log(`🔐 Admin giriş yaptı: ${admin.username} (${admin.role})`);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Giriş işlemi başarısız oldu.' });
    }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Çıkış başarısız oldu.' });
        }
        res.json({ success: true, message: 'Başarıyla çıkış yapıldı.' });
    });
});

// Oturum durumu kontrolü
app.get('/api/session-status', (req, res) => {
    if (req.session.isAuthenticated) {
        res.json({ 
            isAuthenticated: true, 
            username: req.session.username, 
            role: req.session.userRole 
        });
    } else {
        res.json({ isAuthenticated: false });
    }
});

// Kullanıcı onayı kontrolü
app.post('/api/check-user', async (req, res) => {
    const { userId, userName } = req.body;
    const result = await isUserApproved(userId, userName);
    res.json(result);
});

// Kredi yükleme API'si
app.post('/api/add-credits', requireAuth('super_admin'), async (req, res) => {
    const { userId, amount, description } = req.body;
    if (!userId || !amount) {
        return res.status(400).json({ success: false, message: 'Eksik bilgi.' });
    }
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const result = await client.query('UPDATE approved_users SET credits = credits + $1 WHERE id = $2 RETURNING *', [amount, userId]);
            if (result.rows.length > 0) {
                const updatedUser = result.rows[0];
                await client.query('INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description) VALUES ($1, $2, $3, $4, $5)', 
                    [userId, 'addition', amount, updatedUser.credits, description]);
                await client.query('COMMIT');
                res.json({ success: true, user: updatedUser });
            } else {
                await client.query('ROLLBACK');
                res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı.' });
            }
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Kredi ekleme hatası:', error);
        res.status(500).json({ success: false, message: 'Sistem hatası.' });
    }
});

// Kullanıcı bilgilerini getirme
app.get('/api/users', requireAuth('super_admin'), async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json({ success: true, users: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Kullanıcılar getirilirken bir hata oluştu.' });
    }
});

// Kullanıcı arama
app.get('/api/search-users', requireAuth('super_admin'), async (req, res) => {
    const { query } = req.query;
    if (!query) {
        return res.status(400).json({ success: false, message: 'Sorgu parametresi gerekli.' });
    }
    try {
        const result = await pool.query('SELECT * FROM approved_users WHERE id LIKE $1 OR name ILIKE $2 ORDER BY created_at DESC', [`%${query}%`, `%${query}%`]);
        res.json({ success: true, users: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Arama sırasında bir hata oluştu.' });
    }
});

// Duyuru yayımlama API'si
app.post('/api/announcement', requireAuth('super_admin'), (req, res) => {
    const { message } = req.body;
    console.log('📢 Süper admin\'den yeni duyuru:', message);
    currentAnnouncement = { message: message, timestamp: Date.now() };

    // --- BU KISIM GÜNCELLENDİ: TÜM İSTEMCİLERE GÖNDERİLİYOR ---
    clients.forEach(client => {
        if (client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
                type: 'announcement-received',
                message: currentAnnouncement.message
            }));
        }
    });
    // --- GÜNCELLEME BİTTİ ---

    res.json({ success: true, message: 'Duyuru başarıyla gönderildi!' });
});

// Duyuru silme API'si
app.post('/api/clear-announcement', requireAuth('super_admin'), (req, res) => {
    console.log('🧹 Süper admin duyuruyu temizledi.');
    currentAnnouncement = null;

    // --- BU KISIM GÜNCELLENDİ: TÜM İSTEMCİLERE GÖNDERİLİYOR ---
    clients.forEach(client => {
        if (client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
                type: 'announcement-deleted'
            }));
        }
    });
    // --- GÜNCELLEME BİTTİ ---

    res.json({ success: true, message: 'Duyuru temizlendi!' });
});

// ================== WEBSOCKET FUNCTIONS ==================

wss.on('connection', ws => {
    let clientData = null;

    ws.on('message', async (message) => {
        let data;
        try {
            data = JSON.parse(message);
        } catch (e) {
            console.log('⚠️ Geçersiz JSON mesajı alındı:', message);
            return;
        }

        if (data.type !== 'ping') {
            console.log('📩 Gelen mesaj:', data.type, data.userId || '', data.adminId || '');
        }

        if (data.type === 'register-client') {
            const { userId, userType, name, uniqueId } = data;
            const clientKey = uniqueId || userId;
            
            clientData = { ws, id: userId, name: name, userType, uniqueId: clientKey };
            clients.set(clientKey, clientData);

            if (userType === 'customer') {
                const userStatus = await isUserApproved(userId, name);
                ws.send(JSON.stringify({
                    type: 'user-status',
                    approved: userStatus.approved,
                    credits: userStatus.credits,
                    totalCalls: userStatus.totalCalls,
                    lastCall: userStatus.lastCall,
                    reason: userStatus.reason
                }));
            }
            console.log(`🟢 ${userType} bağlandı: ${name} (${userId})`);
            
            // Duyuru varsa gönder
            if (currentAnnouncement) {
                ws.send(JSON.stringify({
                    type: 'announcement-received',
                    message: currentAnnouncement.message
                }));
            }
        }
        // ... (Diğer tüm switch-case'ler ve WebSocket mantığı burada devam ediyor)
    });
    
    ws.on('close', () => {
        if (clientData) {
            console.log(`🔴 Bağlantı kesildi: ${clientData.userType} - ${clientData.name}`);
            clients.delete(clientData.uniqueId || clientData.id);

            // Arama sonlandırma mantığı
            if (clientData.userType === 'admin') {
                const callKey = activeCallAdmins.get(clientData.uniqueId);
                if (callKey) {
                    const call = activeCalls.get(callKey);
                    if (call) {
                        endCall(callKey, call.adminId, 'admin-disconnected');
                    }
                }
            }
        }
    });
});

// ================== ERROR HANDLING ==================

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
