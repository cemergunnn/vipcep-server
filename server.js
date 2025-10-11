const WebSocket = require('ws'); 
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);
const axios = require('axios');

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Express setup
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

app.set('trust proxy', 1); // Proxy arkasında çalışmak için bu satır zorunludur!

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
        maxAge: 24 * 60 * 60 * 1000 // Varsayılan: 1 gün
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
    const activeCallDetails = [];
    for (const [adminId, callInfo] of activeCallAdmins.entries()) {
        const adminClient = Array.from(clients.values()).find(c => c.uniqueId === adminId);
        const customerClient = clients.get(callInfo.customerId);
        activeCallDetails.push({
            adminName: adminClient ? adminClient.name : adminId,
            customerName: customerClient ? customerClient.name : callInfo.customerId,
            startTime: callInfo.callStartTime
        });
    }

    const state = {
        activeCalls: activeCallDetails,
        onlineAdmins: Array.from(clients.values()).filter(c => c.userType === 'admin').length,
        onlineCustomers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
    };
    
    const message = JSON.stringify({
        type: 'system-state-update',
        state: state
    });

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

async function broadcastAdminListToCustomers() {
    try {
        const adminProfileResult = await pool.query(`
            SELECT
                a.username as id,
                a.username as name,
                p.specialization,
                p.profile_picture_url,
                COALESCE(AVG(r.rating), 0) as average_rating,
                COUNT(r.id) as review_count
            FROM admins a
            LEFT JOIN admin_profiles p ON a.username = p.admin_username
            LEFT JOIN admin_reviews r ON a.username = r.admin_username
            WHERE a.role = 'normal' AND a.is_active = TRUE
            GROUP BY a.username, p.specialization, p.profile_picture_url
        `);

        const dbAdmins = adminProfileResult.rows;
        const onlineAdminIds = new Set();
        clients.forEach(client => {
            if (client.userType === 'admin' && client.ws && client.ws.readyState === WebSocket.OPEN && client.online !== false) {
                onlineAdminIds.add(client.id);
            }
        });

        const combinedAdminList = dbAdmins.map(admin => {
            const adminKey = admin.id;
            const isOnline = onlineAdminIds.has(adminKey);
            const isInCall = activeCallAdmins.has(adminKey) || adminLocks.has(adminKey);
            
            return {
                ...admin,
                status: isOnline ? (isInCall ? 'busy' : 'available') : 'offline'
            };
        }).filter(admin => admin.status !== 'offline');


        const message = JSON.stringify({
            type: 'admin-list-update',
            admins: combinedAdminList
        });

        clients.forEach(client => {
            if (client.userType === 'customer' && client.ws && client.ws.readyState === WebSocket.OPEN) {
                try {
                    client.ws.send(message);
                } catch (error) {
                    console.log(`⚠️ Admin list broadcast error to ${client.id}:`, error.message);
                }
            }
        });

    } catch (error) {
        console.error('Error broadcasting admin list:', error);
    }
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

// ================== DATABASE FUNCTIONS ==================

async function initDatabase() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE); ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;`);
        
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
                admin_id VARCHAR(50),
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
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_profiles (
                id SERIAL PRIMARY KEY,
                admin_username VARCHAR(50) UNIQUE NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
                specialization TEXT,
                bio TEXT,
                profile_picture_url TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_reviews (
                id SERIAL PRIMARY KEY,
                admin_username VARCHAR(50) NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
                customer_id VARCHAR(10) NOT NULL,
                customer_name VARCHAR(255),
                rating INTEGER CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                tip_amount INTEGER DEFAULT 0,
                call_id VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        const superAdminCheck = await pool.query('SELECT * FROM admins WHERE role = $1', ['super']);
        if (superAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
            const totpSecret = generateTOTPSecret();
            await pool.query(`
                INSERT INTO admins (username, password_hash, role, totp_secret)
                VALUES ($1, $2, $3, $4)
            `, ['superadmin', hashedPassword, 'super', totpSecret]);
            console.log('🔐 Super Admin created:');
            console.log(`   Username: superadmin`);
            console.log(`   Password: admin123`);
            console.log(`   TOTP Secret: ${totpSecret}`);
            console.log(`   QR Code URL: ${generateTOTPQR('superadmin', totpSecret)}`);
        } else {
            console.log('🔐 Super Admin already exists');
        }
        
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
        const normalAdminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin1']);
        if (normalAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('password123').digest('hex');
            await pool.query(`
                INSERT INTO admins (username, password_hash, role)
                VALUES ($1, $2, $3)
            `, ['admin1', hashedPassword, 'normal']);
        }
        
        console.log("Veritabanı tabloları başarıyla kontrol edildi/oluşturuldu.");

    } catch (error) {
        console.log('Database error:', error.message);
    }
}
// ================== HEARTBEAT FUNCTIONS ==================

async function startHeartbeat(userId, adminId, callKey) {
    if (activeHeartbeats.has(callKey)) {
        console.log(`⚠️ Heartbeat already exists for ${callKey}, stopping old one`);
        clearInterval(activeHeartbeats.get(callKey));
        activeHeartbeats.delete(callKey);
    }
    const callData = { startTime: Date.now(), creditsUsed: 0, customerId: userId, adminId: adminId, callKey: callKey };
    activeCalls.set(callKey, callData);

    const adminClient = Array.from(clients.values()).find(c => c.uniqueId === adminId);
    const adminUsername = adminClient ? adminClient.name : adminId;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userResult = await client.query('SELECT credits FROM approved_users WHERE id = $1 FOR UPDATE', [userId]);
        if (userResult.rows.length === 0 || userResult.rows[0].credits <= 0) {
            await client.query('COMMIT');
            await stopHeartbeat(callKey, 'no_credits');
            client.release();
            return;
        }
        const newCredits = userResult.rows[0].credits - 1;
        await client.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);
        await client.query(`INSERT INTO admin_earnings (username, total_earned) VALUES ($1, 1) ON CONFLICT (username) DO UPDATE SET total_earned = admin_earnings.total_earned + 1, last_updated = CURRENT_TIMESTAMP`, [adminUsername]);
        await client.query('COMMIT');
        
        callData.creditsUsed = 1;
        broadcastCreditUpdate(userId, newCredits);
        await broadcastEarningsUpdateToAdmin(adminUsername, { source: 'call', amount: 1 });
        broadcastSystemStateToSuperAdmins();
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Initial credit deduction error:', error);
        await stopHeartbeat(callKey, 'db_error');
    } finally {
        if (client) client.release();
    }

    const heartbeat = setInterval(async () => {
        const currentCall = activeCalls.get(callKey);
        if (!currentCall) {
            clearInterval(heartbeat);
            return;
        }
        const dbClient = await pool.connect();
        try {
            await dbClient.query('BEGIN');
            const userRes = await dbClient.query('SELECT credits FROM approved_users WHERE id = $1 FOR UPDATE', [userId]);
            if (userRes.rows.length === 0 || userRes.rows[0].credits <= 0) {
                await dbClient.query('COMMIT');
                await stopHeartbeat(callKey, 'no_credits');
                return;
            }
            const newCreds = userRes.rows[0].credits - 1;
            await dbClient.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCreds, userId]);
            await dbClient.query(`UPDATE admin_earnings SET total_earned = total_earned + 1, last_updated = CURRENT_TIMESTAMP WHERE username = $1`, [adminUsername]);
            await dbClient.query('COMMIT');

            currentCall.creditsUsed += 1;
            broadcastCreditUpdate(userId, newCreds);
            await broadcastEarningsUpdateToAdmin(adminUsername, { source: 'call', amount: 1 });
        } catch (err) {
            await dbClient.query('ROLLBACK');
            console.error('Heartbeat credit deduction error:', err);
        } finally {
            dbClient.release();
        }
    }, HEARTBEAT_INTERVAL);
    activeHeartbeats.set(callKey, heartbeat);

    activeCallAdmins.set(adminId, { customerId: userId, callStartTime: Date.now() });
    broadcastAdminListToCustomers();
    broadcastSystemStateToSuperAdmins();
}

async function stopHeartbeat(callKey, reason = 'normal') {
    const heartbeat = activeHeartbeats.get(callKey);
    if (heartbeat) {
        clearInterval(heartbeat);
        activeHeartbeats.delete(callKey);
    }
    const callInfo = activeCalls.get(callKey);
    if (callInfo) {
        const { customerId, adminId, startTime, creditsUsed } = callInfo;
        const duration = Math.floor((Date.now() - startTime) / 1000);
        activeCallAdmins.delete(adminId);
        adminLocks.delete(adminId);
        activeCalls.delete(callKey);

        broadcastCallEnd(customerId, adminId, reason, { duration, creditsUsed });
        
        try {
            const customer = clients.get(customerId);
            const admin = Array.from(clients.values()).find(c => c.uniqueId === adminId);
            await pool.query(`
                INSERT INTO call_history (user_id, user_name, admin_id, duration, credits_used, end_reason)
                VALUES ($1, $2, $3, $4, $5, $6)
            `, [customerId, customer ? customer.name : '', admin ? admin.name : adminId, duration, creditsUsed, reason]);
        } catch(e){
            console.error("Error saving call history", e);
        }
    }
    broadcastAdminListToCustomers();
    broadcastSystemStateToSuperAdmins();
}

function broadcastCreditUpdate(userId, newCredits) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'credit-update',
            credits: newCredits
        }));
    }
    broadcastSystemStateToSuperAdmins();
}

function broadcastCallEnd(userId, adminId, reason, details = {}) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'call-ended',
            reason: reason,
            ...details
        }));
    }

    const adminClient = Array.from(clients.values()).find(c => c.uniqueId === adminId);
    if (adminClient && adminClient.ws && adminClient.ws.readyState === WebSocket.OPEN) {
        adminClient.ws.send(JSON.stringify({
            type: 'call-ended',
            reason: reason,
            ...details
        }));
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
app.get('/admin-secure', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-login.html'));
});
app.get('/', (req, res) => {
    if (req.session.superAdmin) return res.redirect(SECURITY_CONFIG.SUPER_ADMIN_PATH);
    if (req.session.normalAdmin) return res.redirect(SECURITY_CONFIG.NORMAL_ADMIN_PATH);
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🔐 VIPCEP Güvenli Giriş</title>
            <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: system-ui; background: linear-gradient(135deg, #1e293b, #334155); color: white; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                .login-container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 16px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2); max-width: 400px; width: 90%; }
                .form-group { margin-bottom: 20px; }
                .form-input { width: 100%; padding: 14px; border: 2px solid rgba(255,255,255,0.2); border-radius: 8px; background: rgba(255,255,255,0.1); color: white; font-size: 16px; box-sizing: border-box; }
                .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; font-size: 16px; margin-bottom: 10px; }
                .btn-customer { background: linear-gradient(135deg, #059669, #047857); }
                .remember-me { display: flex; align-items: center; gap: 8px; font-size: 14px; margin-bottom: 20px; }
                #messageArea { text-align: center; font-size: 14px; padding: 10px; border-radius: 6px; margin-bottom: 15px; display:none; }
                #messageArea.error { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; }
                #messageArea.success { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; }
                .twofa-section { display: none; }
                .back-btn { background: linear-gradient(135deg, #64748b, #475569); }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h2 style="text-align:center; margin-bottom:20px;">🔐 VIPCEP</h2>
                <div id="messageArea"></div>
                <div id="step1">
                    <div class="form-group">
                        <input type="text" id="username" class="form-input" placeholder="👤 Kullanıcı Adı">
                    </div>
                    <div class="form-group">
                        <input type="password" id="password" class="form-input" placeholder="🔑 Şifre">
                    </div>
                    <div class="remember-me">
                        <input type="checkbox" id="rememberMeAdmin">
                        <label for="rememberMeAdmin">Beni Hatırla (30 Gün)</label>
                    </div>
                    <button class="btn" onclick="startSuperLogin()">🔴 SUPER ADMİN GİRİŞİ</button>
                    <button class="btn" onclick="normalAdminLogin()">🟡 ADMİN GİRİŞİ</button>
                    <button class="btn btn-customer" onclick="window.location.href='${SECURITY_CONFIG.CUSTOMER_PATH}'">🟢 MÜŞTERİ UYGULAMASI</button>
                </div>
                <div id="step2" class="twofa-section">
                     <div class="form-group">
                        <input type="text" id="totpCode" class="form-input" placeholder="******" maxlength="6" style="text-align:center; letter-spacing: 5px;">
                    </div>
                    <button class="btn" onclick="verify2FA()">🔐 DOĞRULA</button>
                    <button class="btn back-btn" onclick="goBackToStep1()">← GERİ</button>
                </div>
            </div>
            <script>
                const messageArea = document.getElementById('messageArea');
                let currentUsername = '';
                let currentPassword = '';

                function showMessage(msg, type = 'error') {
                    messageArea.textContent = msg;
                    messageArea.className = type;
                    messageArea.style.display = 'block';
                }
                
                function goBackToStep1() {
                    document.getElementById('step1').style.display = 'block';
                    document.getElementById('step2').style.display = 'none';
                }

                async function normalAdminLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    const rememberMe = document.getElementById('rememberMeAdmin').checked;
                    if (!username || !password) return showMessage('Kullanıcı adı ve şifre gerekli!');
                    try {
                        const response = await fetch('/auth/admin-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password, rememberMe })
                        });
                        const result = await response.json();
                        if (result.success) {
                            window.location.href = result.redirectUrl;
                        } else {
                            showMessage(result.error);
                        }
                    } catch (err) {
                        showMessage('Sunucu hatası.');
                    }
                }
                async function startSuperLogin() {
                    currentUsername = document.getElementById('username').value;
                    currentPassword = document.getElementById('password').value;
                    if (!currentUsername || !currentPassword) return showMessage('Kullanıcı adı ve şifre gerekli!');
                    try {
                         const response = await fetch('/auth/super-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username: currentUsername, password: currentPassword, step: 'credentials' })
                        });
                        const result = await response.json();
                        if (result.success) {
                            window.location.href = result.redirectUrl;
                        } else if (result.require2FA) {
                            document.getElementById('step1').style.display = 'none';
                            document.getElementById('step2').style.display = 'block';
                            document.getElementById('totpCode').focus();
                        }
                        else {
                             showMessage(result.error);
                        }
                    } catch(err) {
                        showMessage('Sunucu hatası.');
                    }
                }
                 async function verify2FA() {
                    const totpCode = document.getElementById('totpCode').value;
                     try {
                         const response = await fetch('/auth/super-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username: currentUsername, password: currentPassword, step: '2fa', totpCode: totpCode })
                        });
                        const result = await response.json();
                        if (result.success) {
                            window.location.href = result.redirectUrl;
                        } else {
                             showMessage(result.error);
                        }
                    } catch(err) {
                        showMessage('Sunucu hatası.');
                    }
                }
            </script>
        </body>
        </html>
    `);
});

app.get(SECURITY_CONFIG.SUPER_ADMIN_PATH, requireSuperAdminLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'super-admin.html'));
});
app.get(SECURITY_CONFIG.NORMAL_ADMIN_PATH, requireNormalAdminLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});
app.get(SECURITY_CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

app.post('/auth/admin-login', async (req, res) => {
    const { accessCode, username, password, rememberMe } = req.body;
    
    // Access code kontrolü ekleyin
    if (accessCode) {
        const VALID_ACCESS_CODE = process.env.ADMIN_ACCESS_CODE || "VIPCEP";
        if (accessCode !== VALID_ACCESS_CODE) {
            return res.status(401).json({ success: false, error: 'Geçersiz giriş kodu!' });
        }
    }
    const admin = await authenticateAdmin(username, password);
    if (admin && admin.role === 'normal') {
        req.session.normalAdmin = { id: admin.id, username: admin.username };
        if (rememberMe) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 Gün
        }
        res.json({ success: true, redirectUrl: SECURITY_CONFIG.NORMAL_ADMIN_PATH });
    } else {
        res.status(401).json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
    }
});

app.post('/auth/super-login', async (req, res) => {
    const { username, password, totpCode, step } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;

    try {
        const rateStatus = await checkRateLimit(clientIP, 'super-admin');
        if (!rateStatus.allowed) {
            return res.json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }

        const admin = await authenticateAdmin(username, password);
        if (!admin || admin.role !== 'super') {
            await recordFailedLogin(clientIP, 'super-admin');
            return res.json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }

        if (admin.totp_secret) {
            if (step !== '2fa') {
                req.session.tempSuperAdmin = {
                    id: admin.id,
                    username: admin.username,
                    timestamp: Date.now()
                };
                return res.json({
                    success: false,
                    require2FA: true,
                    message: '2FA kodu gerekli'
                });
            } else {
                if (!req.session.tempSuperAdmin ||
                    req.session.tempSuperAdmin.id !== admin.id ||
                    Date.now() - req.session.tempSuperAdmin.timestamp > 300000) {
                    return res.json({ success: false, error: 'Oturum süresi doldu, tekrar deneyin!' });
                }

                if (!totpCode || !verifyTOTP(admin.totp_secret, totpCode)) {
                    await recordFailedLogin(clientIP, 'super-admin');
                    return res.json({ success: false, error: 'Geçersiz 2FA kodu!' });
                }

                delete req.session.tempSuperAdmin;
            }
        }

        req.session.superAdmin = {
            id: admin.id,
            username: admin.username,
            loginTime: new Date()
        };
        res.json({ success: true, redirectUrl: SECURITY_CONFIG.SUPER_ADMIN_PATH });

    } catch (error) {
        console.log('Super login error:', error);
        res.json({ success: false, error: 'Sistem hatası!' });
    }
});
app.get('/auth/check-session', (req, res) => {
    if (req.session.superAdmin) {
        res.json({ authenticated: true, role: 'super', username: req.session.superAdmin.username });
    } else if (req.session.normalAdmin) {
        res.json({ authenticated: true, role: 'normal', username: req.session.normalAdmin.username });
    } else {
        res.json({ authenticated: false });
    }
});
app.post('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.json({ success: false });
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// ================== API ROUTES ==================

app.post('/api/approved-users', requireSuperAdminLogin, async (req, res) => {
    const { id, name, credits } = req.body;

    if (!id || !name || credits < 0) {
        return res.json({ success: false, error: 'Geçersiz veri!' });
    }

    try {
        const existingUser = await pool.query('SELECT id FROM approved_users WHERE id = $1', [id]);
        if (existingUser.rows.length > 0) {
            return res.json({ success: false, error: 'Bu ID zaten kullanılıyor!' });
        }

        const result = await pool.query(`
            INSERT INTO approved_users (id, name, credits)
            VALUES ($1, $2, $3)
            RETURNING *
        `, [id, name, parseInt(credits)]);

        const newUser = result.rows[0];

        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
            VALUES ($1, $2, $3, $4, $5)
        `, [id, 'initial', credits, credits, 'İlk kredi ataması']);

        res.json({ success: true, user: newUser });
    } catch (error) {
        console.log('User creation error:', error);
        res.json({ success: false, error: 'Kullanıcı oluşturulamadı!' });
    }
});
app.delete('/api/approved-users/:userId', requireSuperAdminLogin, async (req, res) => {
    const { userId } = req.params;

    try {
        const result = await pool.query('DELETE FROM approved_users WHERE id = $1', [userId]);

        if (result.rowCount > 0) {
            await pool.query('DELETE FROM credit_transactions WHERE user_id = $1', [userId]);
            await pool.query('DELETE FROM call_history WHERE user_id = $1', [userId]);

            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Kullanıcı bulunamadı!' });
        }
    } catch (error) {
        console.log('User deletion error:', error);
        res.json({ success: false, error: 'Kullanıcı silinemedi!' });
    }
});
app.post('/api/approved-users/:userId/credits', requireSuperAdminLogin, async (req, res) => {
    const { userId } = req.params;
    const { credits, reason } = req.body;

    if (credits < 0) {
        return res.json({ success: false, error: 'Kredi negatif olamaz!' });
    }

    try {
        const currentUser = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
        if (currentUser.rows.length === 0) {
            return res.json({ success: false, error: 'Kullanıcı bulunamadı!' });
        }

        const oldCredits = currentUser.rows[0].credits;
        const newCredits = parseInt(credits);
        const creditDiff = newCredits - oldCredits;

        await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);

        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
            VALUES ($1, $2, $3, $4, $5)
        `, [userId, creditDiff > 0 ? 'add' : 'subtract', creditDiff, newCredits, reason || 'Super admin tarafından güncellendi']);

        broadcastCreditUpdate(userId, newCredits);

        res.json({ success: true, credits: newCredits, oldCredits });
    } catch (error) {
        console.log('Credit update error:', error);
        res.json({ success: false, error: 'Kredi güncellenemedi!' });
    }
});
app.post('/api/admins', requireSuperAdminLogin, async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || password.length < 8) {
        return res.json({ success: false, error: 'Geçersiz veri! Şifre en az 8 karakter olmalı.' });
    }

    try {
        const existingAdmin = await pool.query('SELECT username FROM admins WHERE username = $1', [username]);
        if (existingAdmin.rows.length > 0) {
            return res.json({ success: false, error: 'Bu kullanıcı adı zaten kullanılıyor!' });
        }

        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        let totpSecret = null;

        if (role === 'super') {
            totpSecret = generateTOTPSecret();
        }

        const result = await pool.query(`
            INSERT INTO admins (username, password_hash, role, totp_secret)
            VALUES ($1, $2, $3, $4)
            RETURNING id, username, role
        `, [username, hashedPassword, role, totpSecret]);

        const newAdmin = result.rows[0];

        const response = { success: true, admin: newAdmin };
        if (totpSecret) {
            response.totpSecret = totpSecret;
            response.qrCode = generateTOTPQR(username, totpSecret);
        }

        res.json(response);
    } catch (error) {
        console.log('Admin creation error:', error);
        res.json({ success: false, error: 'Admin oluşturulamadı!' });
    }
});
app.post('/api/announcement', requireSuperAdminLogin, (req, res) => {
    const { text, type } = req.body;

    currentAnnouncement = {
        text,
        type,
        createdAt: new Date(),
        createdBy: req.session.superAdmin.username
    };

    broadcastToCustomers({
        type: 'announcement-broadcast',
        announcement: currentAnnouncement
    });

    res.json({ success: true });
});
app.delete('/api/announcement', requireSuperAdminLogin, (req, res) => {
    currentAnnouncement = null;

    broadcastToCustomers({
        type: 'announcement-deleted'
    });

    res.json({ success: true });
});
app.get('/api/announcement', requireSuperAdminLogin, (req, res) => {
    res.json({
        success: true,
        announcement: currentAnnouncement
    });
});
app.get('/api/approved-users', requireSuperAdminLogin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/admins', requireSuperAdminLogin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, role, is_active, last_login, created_at FROM admins ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/calls', requireSuperAdminLogin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ch.*, au.name as user_name
            FROM call_history ch
            LEFT JOIN approved_users au ON ch.user_id = au.id
            ORDER BY call_time DESC
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/stats', requireSuperAdminLogin, async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM approved_users');
        const totalCalls = await pool.query('SELECT COUNT(*) FROM call_history');
        const totalCredits = await pool.query('SELECT SUM(credits) FROM approved_users');
        const todayCalls = await pool.query("SELECT COUNT(*) FROM call_history WHERE DATE(call_time) = CURRENT_DATE");

        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalCalls: parseInt(totalCalls.rows[0].count),
            totalCredits: parseInt(totalCredits.rows[0].sum || 0),
            todayCalls: parseInt(todayCalls.rows[0].count),
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/online-customers', requireSuperAdminLogin, (req, res) => {
    const onlineCustomers = Array.from(clients.values())
        .filter(c => c.userType === 'customer')
        .map(c => ({ 
            id: c.id, 
            name: c.name, 
            userType: c.userType,
            online: true 
        }));
    res.json(onlineCustomers);
});
app.get('/api/admin-earnings', requireSuperAdminLogin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT username, total_earned, last_updated
            FROM admin_earnings
            ORDER BY total_earned DESC
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/my-earnings', async (req, res) => {
    if (!req.session.normalAdmin && !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }
    const username = req.session.normalAdmin?.username || req.session.superAdmin?.username;
    try {
        const result = await pool.query('SELECT total_earned FROM admin_earnings WHERE username = $1', [username]);
        const earnings = result.rows[0]?.total_earned || 0;
        res.json({ earnings });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/reset-admin-earnings/:username', requireSuperAdminLogin, async (req, res) => {
    const { username } = req.params;
    try {
        await pool.query('UPDATE admin_earnings SET total_earned = 0, last_updated = CURRENT_TIMESTAMP WHERE username = $1', [username]);
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});
app.get('/api/admins/:username/profile', async (req, res) => {
    const { username } = req.params;
    try {
        // İlgili adminin profil bilgilerini veritabanından çek
        const profileRes = await pool.query(
            `SELECT p.*, COALESCE(AVG(r.rating), 0) as average_rating
             FROM admins a
             LEFT JOIN admin_profiles p ON a.username = p.admin_username
             LEFT JOIN admin_reviews r ON a.username = r.admin_username
             WHERE a.username = $1
             GROUP BY p.id`,
            [username]
        );

        // İlgili admin için yazılmış tüm yorumları çek
        const reviewsRes = await pool.query(
            `SELECT * FROM admin_reviews WHERE admin_username = $1 ORDER BY created_at DESC`,
            [username]
        );

        // Profil ve yorum verilerini birleştir
        // Eğer adminin profili henüz oluşturulmamışsa bile boş bir obje ve kullanıcı adını gönder
        const profileData = profileRes.rows[0] || { admin_username: username };
        profileData.reviews = reviewsRes.rows; // Yorumları profile ekle

        res.json({ success: true, profile: profileData });

    } catch (error) {
        console.error(`Admin profili alınırken hata oluştu (${username}):`, error);
        res.status(500).json({ success: false, error: 'Sunucu hatası nedeniyle profil verileri alınamadı.' });
    }
});
app.put('/api/admins/:username/profile', requireSuperAdminLogin, async (req, res) => {
    const { username } = req.params;
    const { specialization, bio, profile_picture_url } = req.body;
    try {
        await pool.query(`
            INSERT INTO admin_profiles (admin_username, specialization, bio, profile_picture_url)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (admin_username)
            DO UPDATE SET specialization = $2, bio = $3, profile_picture_url = $4, updated_at = CURRENT_TIMESTAMP
        `, [username, specialization, bio, profile_picture_url]);
        res.json({ success: true, message: 'Profil güncellendi' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Profil güncellenemedi' });
    }
});

app.post('/api/admins/:adminUsername/review', async (req, res) => {
    const { adminUsername } = req.params;
    const { customerId, customerName, rating, comment, tipAmount } = req.body;
    if (!customerId || !rating) return res.status(400).json({ success: false, error: 'Geçersiz veri' });
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        if (tipAmount && tipAmount > 0) {
            const userRes = await client.query('SELECT credits FROM approved_users WHERE id = $1 FOR UPDATE', [customerId]);
            if (userRes.rows.length === 0 || userRes.rows[0].credits < tipAmount) {
                await client.query('ROLLBACK');
                return res.status(400).json({ success: false, error: 'Yetersiz kredi' });
            }
            const newCredits = userRes.rows[0].credits - tipAmount;
            await client.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, customerId]);
            await client.query(`INSERT INTO admin_earnings (username, total_earned) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET total_earned = admin_earnings.total_earned + $2, last_updated = CURRENT_TIMESTAMP`, [adminUsername, tipAmount]);
            await broadcastEarningsUpdateToAdmin(adminUsername, { source: 'tip', amount: tipAmount, customerName: anonymizeCustomerName(customerName) });
            broadcastCreditUpdate(customerId, newCredits);
        }
        await client.query(`INSERT INTO admin_reviews (admin_username, customer_id, customer_name, rating, comment, tip_amount) VALUES ($1, $2, $3, $4, $5, $6)`, [adminUsername, customerId, customerName, rating, comment, tipAmount || 0]);
        await client.query('COMMIT');
        res.json({ success: true });
    } catch (error) {
        await client.query('ROLLBACK');
        res.status(500).json({ success: false, error: 'Değerlendirme gönderilemedi.' });
    } finally {
        client.release();
    }
});

app.put('/api/reviews/:reviewId', requireSuperAdminLogin, async (req, res) => {
    const { reviewId } = req.params;
    const { rating, comment, tip_amount } = req.body;
    try {
        const result = await pool.query(
            `UPDATE admin_reviews SET rating = $1, comment = $2, tip_amount = $3 WHERE id = $4 RETURNING *`,
            [rating, comment, tip_amount, reviewId]
        );
        if (result.rowCount === 0) return res.status(404).json({ success: false, error: 'Yorum bulunamadı' });
        res.json({ success: true, review: result.rows[0] });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Sunucu hatası' });
    }
});

app.delete('/api/reviews/:reviewId', requireSuperAdminLogin, async (req, res) => {
    const { reviewId } = req.params;
    try {
        const result = await pool.query('DELETE FROM admin_reviews WHERE id = $1', [reviewId]);
        if (result.rowCount === 0) return res.status(404).json({ success: false, error: 'Yorum bulunamadı' });
        res.json({ success: true, message: 'Yorum başarıyla silindi' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Sunucu hatası' });
    }
});

app.post('/api/clear-failed-logins', requireSuperAdminLogin, async (req, res) => {
    try {
        await pool.query('DELETE FROM failed_logins');
        res.json({ success: true, message: 'Başarısız giriş denemesi kayıtları başarıyla temizlendi.' });
    } catch (error) {
        console.error('Failed logins clear error:', error);
        res.status(500).json({ success: false, error: 'Kayıtlar temizlenirken bir sunucu hatası oluştu.' });
    }
});

app.get('/api/export-data', requireSuperAdminLogin, async (req, res) => {
    try {
        const [usersRes, callsRes, adminsRes, reviewsRes] = await Promise.all([
            pool.query('SELECT id, name, credits, created_at FROM approved_users'),
            pool.query('SELECT * FROM call_history ORDER BY call_time DESC LIMIT 500'),
            pool.query('SELECT username, role, is_active, last_login FROM admins'),
            pool.query('SELECT * FROM admin_reviews')
        ]);
        const exportData = {
            exportDate: new Date().toISOString(),
            users: usersRes.rows,
            calls: callsRes.rows,
            admins: adminsRes.rows,
            reviews: reviewsRes.rows
        };
        res.json(exportData);
    } catch (error) {
        console.error('Data export error:', error);
        res.status(500).json({ success: false, error: 'Veri dışa aktarılırken hata oluştu.' });
    }
});
// ================== WEBSOCKET HANDLER ==================
wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);

            let senderInfo = null;
            for (const [clientId, clientData] of clients.entries()) {
                if (clientData.ws === ws) {
                    senderInfo = clientData;
                    break;
                }
            }

            const senderId = senderInfo ? (senderInfo.uniqueId || senderInfo.id) : (message.userId || 'unknown');
            const senderType = senderInfo ? senderInfo.userType : 'unknown';

            switch (message.type) {
                case 'register':
                    const { userId, name, userType } = message;
                    if (userType === 'super-admin') {
                        clients.set(userId, { ws, id: userId, uniqueId: userId, name, userType, online: true });
                        console.log(`👑 Super Admin connected: ${name}`);
                        broadcastSystemStateToSuperAdmins();
                        return;
                    }
                    if (userType === 'admin') {
                        clients.set(userId, { ws, id: userId, uniqueId: userId, name, userType, online: true });
                        ws.send(JSON.stringify({ type: 'admin-registered', uniqueId: userId }));
                        broadcastCallbacksToAdmin(userId);
                    } else {
                        clients.set(userId, { ws, id: userId, uniqueId: userId, name, userType, online: true });
                    }
                    console.log(`👤 Client registered: ${name} (${userId}) as ${userType}`);
                    broadcastAdminListToCustomers();
                    break;

                    case 'customer-accepted-call':
                        const { adminId, customerId } = message;
                        const adminClient = Array.from(clients.values()).find(c => c.uniqueId === adminId);
                        const customerClient = clients.get(customerId);
                    
                        if (adminClient && adminClient.ws && adminClient.ws.readyState === WebSocket.OPEN) {
                            // Admini meşgul eden kilidi kaldır, çünkü arama artık aktif seansa dönüşüyor.
                            adminLocks.delete(adminId);
                    
                            // Admine, müşterinin kabul ettiğini ve WebRTC görüşmesini başlatabileceğini bildir.
                            adminClient.ws.send(JSON.stringify({
                                type: 'call-accepted',
                                customerId: customerId,
                                customerName: customerClient ? customerClient.name : customerId
                            }));
                    
                            // KRİTİK EKSİK ADIM: Aktif arama seansını ve kalp atışını (kredi düşme) başlat.
                            const callKey = `${customerId}-${adminId}`;
                            startHeartbeat(customerId, adminId, callKey);
                            
                        } else {
                            // Eğer admin bu sırada bağlantıyı kopardıysa, kilidi temizle.
                            adminLocks.delete(adminId);
                        }
                        break;
                    // --- BU KOD BLOĞUNU server.js'deki switch içine EKLEYİN ---
                    
                    case 'admin-call-customer':
                        const { targetCustomerId, adminName } = message;
                        const targetCustomerClient = clients.get(targetCustomerId);
                        const callingAdmin = senderInfo; // 'senderInfo' zaten o kapsamda mevcut
                    
                        // Müşterinin çevrimiçi olup olmadığını kontrol et
                        if (targetCustomerClient && targetCustomerClient.ws && targetCustomerClient.ws.readyState === WebSocket.OPEN) {
                            
                            // Adminin zaten bir arama veya arama işlemi içinde olup olmadığını kontrol et
                            if (activeCallAdmins.has(callingAdmin.uniqueId) || adminLocks.has(callingAdmin.uniqueId)) {
                                callingAdmin.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Zaten başka bir işlemdesiniz.' }));
                                return;
                            }
                            
                            // Admini bu arama denemesi için kilitle
                            adminLocks.set(callingAdmin.uniqueId, targetCustomerId);
                    
                            // Müşteriye arama isteğini gönder
                            targetCustomerClient.ws.send(JSON.stringify({
                                type: 'admin-call-request',
                                adminId: callingAdmin.uniqueId,
                                adminName: adminName || callingAdmin.name
                            }));
                            
                            // Tüm müşterilere admin listesini yayınlayarak bu adminin meşgul olduğunu bildir
                            broadcastAdminListToCustomers();
                    
                        } else {
                            // Müşteri çevrimdışı ise admini bilgilendir
                            callingAdmin.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Müşteri şu anda çevrimdışı.' }));
                        }
                        break;
                case 'chat-message':
                    console.log('💬 Chat mesajı alındı:', message);
                    
                    // Mesajı karşı tarafa yönlendir
                    if (message.targetType === 'admin') {
                        // Müşteriden admin'e mesaj
                        const targetAdmin = Array.from(clients.values()).find(admin => 
                            admin.uniqueId === message.targetId && admin.userType === 'admin'
                        );
                        
                        if (targetAdmin && targetAdmin.ws && targetAdmin.ws.readyState === WebSocket.OPEN) {
                            targetAdmin.ws.send(JSON.stringify({
                                type: 'chat-message',
                                from: message.from,
                                text: message.text,
                                senderId: message.userId
                            }));
                            console.log('💬 Chat mesajı admin\'e gönderildi');
                        } else {
                            console.log('❌ Hedef admin bulunamadı veya çevrimdışı');
                        }
                        
                    } else if (message.targetType === 'customer') {
                        // Admin'den müşteriye mesaj
                        const targetCustomer = clients.get(message.targetId);
                        
                        if (targetCustomer && targetCustomer.ws && targetCustomer.ws.readyState === WebSocket.OPEN) {
                            targetCustomer.ws.send(JSON.stringify({
                                type: 'chat-message',
                                from: message.from,
                                text: message.text,
                                senderId: message.adminId
                            }));
                            console.log('💬 Chat mesajı müşteriye gönderildi');
                        } else {
                            console.log('❌ Hedef müşteri bulunamadı veya çevrimdışı');
                        }
                    }
                    break;
                case 'file-transfer-request':
                    console.log('📁 Dosya transfer isteği:', message.fileName);
                    
                    if (message.targetType === 'admin') {
                        const targetAdmin = Array.from(clients.values()).find(admin => 
                            admin.uniqueId === message.targetId && admin.userType === 'admin'
                        );
                        
                        if (targetAdmin && targetAdmin.ws && targetAdmin.ws.readyState === WebSocket.OPEN) {
                            targetAdmin.ws.send(JSON.stringify({
                                type: 'file-transfer-request',
                                from: message.from,
                                fileName: message.fileName,
                                fileSize: message.fileSize,
                                fileType: message.fileType,
                                senderId: message.userId,
                                transferId: message.transferId
                            }));
                        }
                    } else if (message.targetType === 'customer') {
                        const targetCustomer = clients.get(message.targetId);
                        
                        if (targetCustomer && targetCustomer.ws && targetCustomer.ws.readyState === WebSocket.OPEN) {
                            targetCustomer.ws.send(JSON.stringify({
                                type: 'file-transfer-request',
                                from: message.from,
                                fileName: message.fileName,
                                fileSize: message.fileSize,
                                fileType: message.fileType,
                                senderId: message.adminId,
                                transferId: message.transferId
                            }));
                        }
                    }
                    break;
                
                case 'file-chunk':
                    // Dosya parçalarını yönlendir
                    if (message.targetType === 'admin') {
                        const targetAdmin = Array.from(clients.values()).find(admin => 
                            admin.uniqueId === message.targetId && admin.userType === 'admin'
                        );
                        
                        if (targetAdmin && targetAdmin.ws && targetAdmin.ws.readyState === WebSocket.OPEN) {
                            targetAdmin.ws.send(JSON.stringify({
                                type: 'file-chunk',
                                transferId: message.transferId,
                                chunk: message.chunk,
                                chunkIndex: message.chunkIndex,
                                totalChunks: message.totalChunks
                            }));
                        }
                    } else if (message.targetType === 'customer') {
                        const targetCustomer = clients.get(message.targetId);
                        
                        if (targetCustomer && targetCustomer.ws && targetCustomer.ws.readyState === WebSocket.OPEN) {
                            targetCustomer.ws.send(JSON.stringify({
                                type: 'file-chunk',
                                transferId: message.transferId,
                                chunk: message.chunk,
                                chunkIndex: message.chunkIndex,
                                totalChunks: message.totalChunks
                            }));
                        }
                    }
                    break;
                case 'screen-sharing-started':
                    // Admin ekran paylaşımını başlattı, müşteriye bildir
                    const targetCustomer = connectedUsers.find(u => u.id === message.targetId && u.userType === 'customer');
                    if (targetCustomer && targetCustomer.ws && targetCustomer.ws.readyState === WebSocket.OPEN) {
                        targetCustomer.ws.send(JSON.stringify({
                            type: 'admin-screen-sharing-started',
                            adminId: message.adminId || message.userId
                        }));
                    }
                    break;
                
                case 'screen-sharing-stopped':
                    // Admin ekran paylaşımını durdurdu, müşteriye bildir
                    const targetCustomer2 = connectedUsers.find(u => u.id === message.targetId && u.userType === 'customer');
                    if (targetCustomer2 && targetCustomer2.ws && targetCustomer2.ws.readyState === WebSocket.OPEN) {
                        targetCustomer2.ws.send(JSON.stringify({
                            type: 'admin-screen-sharing-stopped',
                            adminId: message.adminId || message.userId
                        }));
                    }
                    break;
                    
                    // --- KOPYALAMAYI BURADA BİTİRİN ---
                
                case 'login-request':
                    const approval = await isUserApproved(message.userId, message.userName);
                    if (approval.approved) {
                        try {
                        const pushoverUserKey = 'u26unvsy7fntxaubde92p1dwgeg8qe';
                        const pushoverApiKey = 'ak3awa4ya2qi8wke5ibqxudxed7v61';
                        
                        // PushOver API'sine POST isteği gönder
                        await axios.post('https://api.pushover.net/1/messages.json', {
                            token: pushoverApiKey,
                            user: pushoverUserKey,
                            message: `${message.userName} uygulamaya giriş yaptı. Güncel kredi: ${approval.credits}`,
                            title: 'VIPCEP Giriş Bildirimi',
                            sound: 'magic' // Bildirim sesi
                        });

                        console.log('✅ PushOver bildirimi başarıyla gönderildi.');

                    } catch (pushError) {
                        console.error('❌ PushOver bildirimi gönderilirken hata oluştu:', pushError.response ? pushError.response.data : pushError.message);
                    }
                        ws.send(JSON.stringify({ type: 'login-response', success: true, credits: approval.credits }));
                    } else {
                        ws.send(JSON.stringify({ type: 'login-response', success: false, reason: approval.reason }));
                    }
                    break;

            case 'direct-call-request':
                    const targetAdminForDirectCall = Array.from(clients.values()).find(c => c.id === message.targetAdminId && c.userType === 'admin' && c.ws.readyState === WebSocket.OPEN);
                    
                    // Adminin müsait olup olmadığını kontrol et
                    if (targetAdminForDirectCall && !activeCallAdmins.has(targetAdminForDirectCall.id) && !adminLocks.has(targetAdminForDirectCall.id)) {
                        // Admin müsaitse, normal arama akışını başlat
                        adminLocks.set(targetAdminForDirectCall.id, message.userId); // Admini bu arama için kilitle
                        targetAdminForDirectCall.ws.send(JSON.stringify({ type: 'admin-call-request', userId: message.userId, userName: message.userName }));
                        broadcastAdminListToCustomers(); // Tüm müşterilere adminin meşgul olduğunu bildir
                        ws.send(JSON.stringify({ type: 'call-status-update', status: 'connecting', adminName: targetAdminForDirectCall.name }));
                    } else {
                        // Admin meşgulse, doğrudan reddet
                        ws.send(JSON.stringify({ type: 'call-rejected', reason: 'Usta meşgul, lütfen geri dönüş talebi bırakın.' }));
                    }
                    break;
                case 'heartbeat':
                    const client = clients.get(message.userId);
                    if (client) {
                        client.lastHeartbeat = Date.now();
                        console.log(`❤️ Kalp atışı alındı: ${client.name} (${client.id})`);
                    }
                    break;
                case 'accept-incoming-call':
                    const customerToCall = clients.get(message.userId);
                    const adminCalling = Array.from(clients.values()).find(c => c.ws === ws && c.userType === 'admin');
                    if (customerToCall && adminCalling) {
                        adminLocks.delete(adminCalling.id);
                        customerToCall.ws.send(JSON.stringify({ type: 'call-accepted', adminId: adminCalling.id, adminName: adminCalling.name }));
                        const callKey = `${message.userId}-${adminCalling.id}`;
                        startHeartbeat(message.userId, adminCalling.id, callKey);
                    }
                    break;
                
                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    const targetIdForSignal = message.targetId;
                    const targetClient = clients.get(targetIdForSignal) || Array.from(clients.values()).find(c => c.uniqueId === targetIdForSignal);
                    if (targetClient && targetClient.ws && targetClient.ws.readyState === WebSocket.OPEN) {
                        const sender = Array.from(clients.values()).find(c => c.ws === ws);
                        if (sender) {
                            const forwardMessage = {
                                type: message.type,
                                userId: sender.uniqueId || sender.id
                            };

                            if (message.offer) forwardMessage.offer = message.offer;
                            if (message.answer) forwardMessage.answer = message.answer;
                            if (message.candidate) forwardMessage.candidate = message.candidate;
                            
                            targetClient.ws.send(JSON.stringify(forwardMessage));
                        }
                    } else {
                        console.log(`⚠️ WebRTC target not found or not open: ${targetIdForSignal}`);
                    }
                    break;
                
                    case 'end-call':
                    const endedByAdmin = message.userType === 'admin';
                    const userId1 = message.userId;
                    const userId2 = message.targetId;
                
                    let callInfo = findActiveCall(userId1, userId2);
                
                    if (callInfo) {
            
                // Arama sona erdiğinde, callback listesini kontrol et ve temizle
                    if (message.reason === 'normal' || message.reason === 'user_ended') {
                        const customerIdForCallback = endedByAdmin ? message.targetId : message.userId;
                        const adminIdForCallback = endedByAdmin ? message.userId : message.targetId;
                        
                        // Bu görüşmenin, geri dönüş listesindeki bir müşteriyle mi yapıldığını kontrol ediyoruz
                        const callbacks = adminCallbacks.get(adminIdForCallback) || [];
                        const isFromCallbackList = callbacks.some(c => c.customerId === customerIdForCallback);
                        
                        if (isFromCallbackList) {
                            let filteredCallbacks = callbacks.filter(c => c.customerId !== customerIdForCallback);
                            adminCallbacks.set(adminIdForCallback, filteredCallbacks);
                            
                            console.log(`🗑️ Callback removed for customer ${customerIdForCallback} from admin ${adminIdForCallback}`);
                            broadcastCallbacksToAdmin(adminIdForCallback);
                        }
                    }
                        // Normal durum: Arama başlamış ve kalp atışı devam ediyor.
                        stopHeartbeat(callInfo.callKey, message.reason || 'user_ended');
                    } else {
                        // Hata durumu (B Planı): Arama kalp atışı başlamadan sonlandırıldı (örn: mikrofon hatası).
                        console.log('⚠️ Kalp atışı başlamamış bir arama sonlandırılıyor (örn: mikrofon hatası).');
                        
                        // Tarafların kim olduğunu belirle
                        const customerId = endedByAdmin ? userId2 : userId1;
                        const adminUniqueId = endedByAdmin ? userId1 : userId2;
                
                        // Her iki tarafa da aramanın bittiğini bildir
                        broadcastCallEnd(customerId, adminUniqueId, message.reason || 'ended_before_start');
                        
                        // Adminin durumunu sıfırlamak için kilitleri ve aktif aramaları temizle
                        adminLocks.delete(adminUniqueId);
                        activeCallAdmins.delete(adminUniqueId);
                        
                        // Adminin durumunu 'müsait' olarak güncelle
                        broadcastAdminListToCustomers();
                        broadcastSystemStateToSuperAdmins();
                    }
                    break;
                
                case 'reject-incoming-call':
                    const adminIdForReject = message.adminId;
                    if(adminIdForReject){
                        const customerToInformId = adminLocks.get(adminIdForReject);
                        const customerToInform = clients.get(customerToInformId);
                        if(customerToInform){
                            customerToInform.ws.send(JSON.stringify({type: 'call-rejected', reason: 'Usta aramayı reddetti.'}));
                        }
                        adminLocks.delete(adminIdForReject);
                        broadcastAdminListToCustomers();
                    }
                    break;

                case 'callback-request':
                    const callingCustomer = senderInfo;
                    // Müşteri zaten başka bir arama işlemindeyse geri dönüş talebini reddet
                    if (callingCustomer && callingCustomer.userType === 'customer' && adminLocks.has(message.targetAdminId) && adminLocks.get(message.targetAdminId) === callingCustomer.id) {
                         ws.send(JSON.stringify({ type: 'callback-failed', reason: 'Zaten aktif bir arama isteğiniz var, lütfen bekleyin veya aramayı iptal edin.' }));
                         return;
                    }
            
                    const targetAdminForCallback = Array.from(clients.values()).find(c => c.id === message.targetAdminId);
                    if(targetAdminForCallback){
                        let callbacks = adminCallbacks.get(targetAdminForCallback.id) || [];
                        // Müşterinin zaten listede olup olmadığını kontrol et
                        if (callbacks.some(c => c.customerId === message.userId)) {
                            ws.send(JSON.stringify({ type: 'callback-failed', reason: 'Geri dönüş listenize zaten eklenmişsiniz.' }));
                        } else {
                            callbacks.push({ customerId: message.userId, customerName: message.userName, timestamp: Date.now() });
                            adminCallbacks.set(targetAdminForCallback.id, callbacks);
                            ws.send(JSON.stringify({ type: 'callback-success' }));
                            broadcastCallbacksToAdmin(targetAdminForCallback.id);
                        }
                    } else {
                        ws.send(JSON.stringify({ type: 'callback-failed', reason: 'Usta şu anda çevrimdışı.' }));
                    }
                    break;
            }
        } catch (error) {
            console.error("Mesaj işlenirken hata:", error);
        }
    });

    ws.on('close', () => {
        let disconnectedClient = null;
        for (const [id, client] of clients.entries()) {
            if (client.ws === ws) {
                disconnectedClient = client;
                clients.delete(id);
                break;
            }
        }
        if (disconnectedClient) {
            console.log(`👋 Client disconnected: ${disconnectedClient.name || disconnectedClient.id}`);
            
            if (disconnectedClient.userType === 'admin') {
                adminLocks.forEach((customerId, adminId) => {
                    if (adminId === disconnectedClient.id) {
                        adminLocks.delete(adminId);
                        console.log(`🧹 Disconnected admin lock cleaned for: ${adminId}`);
                    }
                });
                
                const callInfo = activeCallAdmins.get(disconnectedClient.id);
                if(callInfo) {
                    stopHeartbeat(`${callInfo.customerId}-${disconnectedClient.id}`, 'admin_disconnected');
                }
            }
            broadcastAdminListToCustomers();
            broadcastSystemStateToSuperAdmins();
        }
    });
});

// ================== HELPER FUNCTIONS (end of file) ==================

function findClientById(ws) {
    for (const client of clients.values()) {
        if (client.ws === ws) {
            return client;
        }
    }
    return null;
}

function findWebRTCTarget(targetId) {
    if (!targetId) {
        console.log('⚠️ targetId is null or undefined');
        return null;
    }

    let targetClient = clients.get(targetId);
    if (targetClient) {
        return targetClient;
    }
    
    for (const client of clients.values()) {
        if (client.uniqueId === targetId) {
            return client;
        }
    }
    
    console.log(`⚠️ WebRTC target not found: ${targetId}`);
    return null;
}

function broadcastUserList() {
    const userList = Array.from(clients.values()).map(client => ({
        id: client.id,
        name: client.name,
        userType: client.userType,
        registeredAt: client.registeredAt,
        online: client.online
    }));

    const message = JSON.stringify({
        type: 'user-list-update',
        users: userList
    });

    clients.forEach(client => {
        if (client.ws && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(message);
        }
    });
}

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
















