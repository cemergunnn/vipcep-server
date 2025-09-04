const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session); // UYARI İÇİN EKLENDİ

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
const sessionStore = new pgSession({ // UYARI İÇİN EKLENDİ
    pool: pool,
    tableName: 'user_sessions'
});

app.use(session({
    store: sessionStore, // UYARI İÇİN GÜNCELLENDİ
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
    if (!fullName || typeof fullName !== 'string') {
        return 'Anonim';
    }
    const parts = fullName.trim().split(' ');
    if (parts.length === 1) {
        return parts[0];
    }
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
            const isInCall = activeCallAdmins.has(adminKey);
            
            return {
                ...admin,
                status: isOnline ? ((isInCall || adminLocks.has(adminKey)) ? 'busy' : 'available') : 'offline'
            };
        }).filter(admin => admin.status !== 'offline');


        const message = JSON.stringify({
            type: 'admin-list-update',
            admins: combinedAdminList
        });

        let sentCount = 0;
        clients.forEach(client => {
            if (client.userType === 'customer' && client.ws && client.ws.readyState === WebSocket.OPEN) {
                try {
                    client.ws.send(message);
                    sentCount++;
                } catch (error) {
                    console.log(`⚠️ Admin list broadcast error to ${client.id}:`, error.message);
                }
            }
        });

        console.log(`📡 Admin list sent to ${sentCount} customers: ${combinedAdminList.length} unique admins`);
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
        console.log(`📋 Callback list sent to admin ${adminId}: ${callbacks.length} callbacks`);
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

// ================== DATABASE FUNCTIONS ==================

async function initDatabase() {
    try {
        // Oturum tablosunu oluştur
        await pool.query(`
            CREATE TABLE IF NOT EXISTS "user_sessions" (
              "sid" varchar NOT NULL COLLATE "default",
              "sess" json NOT NULL,
              "expire" timestamp(6) NOT NULL
            ) WITH (OIDS=FALSE);
            ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
        `);

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

// ... Diğer fonksiyonlarınız ...

// ================== MIDDLEWARE FOR AUTH ==================

const requireNormalAdminLogin = (req, res, next) => {
    if (req.session && req.session.normalAdmin) {
        return next();
    } else {
        res.redirect('/');
    }
};

const requireSuperAdminLogin = (req, res, next) => {
    if (req.session && req.session.superAdmin) {
        return next();
    } else {
        res.redirect('/');
    }
};


// ================== ROUTES ==================

app.get('/', (req, res) => {
    if (req.session.superAdmin) {
        return res.redirect(SECURITY_CONFIG.SUPER_ADMIN_PATH);
    }
    if (req.session.normalAdmin) {
        return res.redirect(SECURITY_CONFIG.NORMAL_ADMIN_PATH);
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🔐 VIPCEP Güvenli Giriş</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: system-ui; background: linear-gradient(135deg, #1e293b, #334155); color: white; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                .login-container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 16px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2); max-width: 400px; width: 100%; }
                .form-group { margin-bottom: 20px; }
                .form-input { width: 100%; padding: 14px; border: 2px solid rgba(255,255,255,0.2); border-radius: 8px; background: rgba(255,255,255,0.1); color: white; font-size: 16px; box-sizing: border-box; }
                .form-input::placeholder { color: rgba(255,255,255,0.6); }
                .form-input:focus { outline: none; border-color: #dc2626; }
                .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; font-size: 16px; margin-bottom: 10px; transition: all 0.3s ease; }
                .btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
                .btn:disabled { opacity: 0.6; cursor: not-allowed; }
                .btn-customer { background: linear-gradient(135deg, #059669, #047857); }
                .title { text-align: center; margin-bottom: 30px; color: #dc2626; font-size: 24px; font-weight: bold; }
                .error-msg { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; font-size: 14px; }
                .success-msg { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; font-size: 14px; }
                .remember-me { display: flex; align-items: center; gap: 8px; font-size: 14px; color: rgba(255,255,255,0.8); margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="title">🔐 VIPCEP</div>
                <div id="messageArea"></div>
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
            <script>
                // Gerekli JavaScript kodları burada yer alıyor...
            </script>
        </body>
        </html>
    `);
});

app.post('/auth/admin-login', async (req, res) => {
    const { username, password, rememberMe } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;

    try {
        const rateStatus = await checkRateLimit(clientIP, 'admin');
        if (!rateStatus.allowed) {
            return res.status(429).json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }

        const admin = await authenticateAdmin(username, password);
        if (admin && admin.role === 'normal') {
            req.session.normalAdmin = { id: admin.id, username: admin.username, loginTime: new Date() };
            if (rememberMe) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 Gün
            }
            res.json({ success: true, redirectUrl: SECURITY_CONFIG.NORMAL_ADMIN_PATH });
        } else {
            await recordFailedLogin(clientIP, 'admin');
            res.status(401).json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'Sistem hatası!' });
    }
});

// ... Diğer tüm API ve WebSocket kodlarınız burada yer alıyor ...


// ================== SERVER STARTUP ==================

async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');

    await initDatabase();

    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server Çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
    });
}

process.on('uncaughtException', (error) => {
    console.log('❌ Yakalanmamış hata:', error.message);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.log('❌ İşlenmemiş promise reddi:', reason);
});

process.on('SIGTERM', () => {
    console.log('🔴 Server kapatılıyor...');
    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});

startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
