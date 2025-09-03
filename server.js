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
    SUPER_ADMIN_PATH: '/panel-admin',
    NORMAL_ADMIN_PATH: '/desk-admin',
    CUSTOMER_PATH: '/app-customer',
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
const adminCallbacks = new Map();
const adminLocks = new Map();
let currentAnnouncement = null;
const HEARTBEAT_INTERVAL = 60000;
const heartbeatMutex = new Map();
const callRateLimiter = new Map();

// ================== HELPER FUNCTIONS ==================
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
                rating INTEGER CHECK (rating >= 0 AND rating <= 5),
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
            const admin = superAdminCheck.rows[0];
            if (admin.totp_secret) {
                console.log(`   Username: ${admin.username}`);
                console.log(`   TOTP Secret: ${admin.totp_secret}`);
                console.log(`   QR Code URL: ${generateTOTPQR(admin.username, admin.totp_secret)}`);
            }
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

async function acquireAdminLockAtomic(adminId, customerId) {
    const lockKey = `admin_lock_${adminId}`;
    if (adminLocks.has(lockKey)) {
        return false;
    }
    const client = await pool.connect();
    try {
        const lockResult = await client.query(
            'SELECT pg_try_advisory_lock($1) as locked',
            [adminId.charCodeAt(0) * 1000 + adminId.charCodeAt(1)]
        );
        if (!lockResult.rows[0].locked) {
            return false;
        }
        adminLocks.set(adminId, {
            lockedBy: customerId,
            lockTime: Date.now(),
            pgLockId: lockResult.rows[0].locked
        });
        return true;
    } finally {
        client.release();
    }
}
async function releaseAdminLock(adminId) {
    const lock = adminLocks.get(adminId);
    if (!lock) return;
    const client = await pool.connect();
    try {
        await client.query(
            'SELECT pg_advisory_unlock($1)',
            [adminId.charCodeAt(0) * 1000 + adminId.charCodeAt(1)]
        );
    } finally {
        client.release();
    }
    adminLocks.delete(adminId);
}

async function startHeartbeat(userId, adminId, callKey) {
    if (heartbeatMutex.has(callKey)) {
        console.log(`⚠️ Heartbeat mutex active for ${callKey}, rejecting duplicate`);
        return false;
    }
    heartbeatMutex.set(callKey, true);

    try {
        if (activeHeartbeats.has(callKey)) {
            const oldInterval = activeHeartbeats.get(callKey);
            clearInterval(oldInterval);
            activeHeartbeats.delete(callKey);
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        activeCalls.set(callKey, {
            startTime: Date.now(),
            creditsUsed: 0,
            customerId: userId,
            adminId: adminId,
            callKey: callKey,
            heartbeatStarted: true
        });

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');

            const userResult = await client.query(
                'SELECT credits FROM approved_users WHERE id = $1 FOR UPDATE',
                [userId]
            );

            if (userResult.rows.length === 0 || userResult.rows[0].credits <= 0) {
                await client.query('ROLLBACK');
                heartbeatMutex.delete(callKey);
                await stopHeartbeat(callKey, 'no_credits');
                return false;
            }

            const currentCredits = userResult.rows[0].credits;
            const newCredits = currentCredits - 1;

            await client.query(
                'UPDATE approved_users SET credits = $1 WHERE id = $2',
                [newCredits, userId]
            );

            await client.query(
                `INSERT INTO credit_transactions 
                (user_id, transaction_type, amount, balance_after, description)
                VALUES ($1, $2, $3, $4, $5)`,
                [userId, 'initial_call', -1, newCredits, `Arama başlangıç - Admin: ${adminId}`]
            );

            await pool.query(`
                INSERT INTO admin_earnings (username, total_earned)
                VALUES ($1, 1)
                ON CONFLICT (username)
                DO UPDATE SET
                    total_earned = admin_earnings.total_earned + 1,
                    last_updated = CURRENT_TIMESTAMP
            `, [adminId]);


            await client.query('COMMIT');
            broadcastCreditUpdate(userId, newCredits, 1);
            console.log(`Initial credit deducted: ${userId} ${currentCredits}→${newCredits}`);
        } catch (error) {
            await client.query('ROLLBACK');
            console.error(`Initial credit error for ${callKey}:`, error);
            heartbeatMutex.delete(callKey);
            await stopHeartbeat(callKey, 'credit_error');
            return false;
        } finally {
            client.release();
        }

        console.log(`✅ Starting heartbeat for ${callKey}`);
        const heartbeat = setInterval(async () => {
            await processHeartbeatTick(callKey, userId, adminId);
        }, HEARTBEAT_INTERVAL);

        activeHeartbeats.set(callKey, heartbeat);
        activeCallAdmins.set(adminId, {
            customerId: userId,
            callStartTime: Date.now()
        });

        broadcastAdminListToCustomers();
        return true;
    } finally {
        heartbeatMutex.delete(callKey);
    }
}

async function processHeartbeatTick(callKey, userId, adminId) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');

        const adminClient = Array.from(clients.values()).find(c => c.uniqueId === adminId && c.userType === 'admin');
        const customerClient = clients.get(userId);

        if (!adminClient?.ws || adminClient.ws.readyState !== WebSocket.OPEN || !customerClient?.ws || customerClient.ws.readyState !== WebSocket.OPEN) {
            await client.query('COMMIT');
            await stopHeartbeat(callKey, 'connection_lost');
            return;
        }

        const userResult = await client.query(
            'SELECT credits FROM approved_users WHERE id = $1 FOR UPDATE',
            [userId]
        );

        if (userResult.rows.length === 0 || userResult.rows[0].credits <= 0) {
            await client.query('COMMIT');
            await stopHeartbeat(callKey, 'no_credits');
            return;
        }

        const newCredits = userResult.rows[0].credits - 1;
        await client.query(
            'UPDATE approved_users SET credits = $1 WHERE id = $2',
            [newCredits, userId]
        );

        const callInfo = activeCalls.get(callKey);
        if (callInfo) {
            callInfo.creditsUsed += 1;
        }

        await client.query(`
            INSERT INTO admin_earnings (username, total_earned)
            VALUES ($1, 1)
            ON CONFLICT (username)
            DO UPDATE SET
                total_earned = admin_earnings.total_earned + 1,
                last_updated = CURRENT_TIMESTAMP
        `, [adminId]);

        await client.query('COMMIT');
        broadcastCreditUpdate(userId, newCredits, 1);
        console.log(`Credit deducted: ${userId} ${newCredits} (Admin: ${adminId})`);
    } catch (error) {
        await client.query('ROLLBACK');
        console.error(`Heartbeat tick error ${callKey}:`, error);
    } finally {
        client.release();
    }
}
async function stopHeartbeat(callKey, reason = 'normal') {
    const heartbeat = activeHeartbeats.get(callKey);
    if (heartbeat) {
        clearInterval(heartbeat);
        activeHeartbeats.delete(callKey);

        const [userId, adminId] = callKey.split('-');
        const callInfo = activeCalls.get(callKey);
        const duration = callInfo ? Math.floor((Date.now() - callInfo.startTime) / 1000) : 0;
        const creditsUsed = callInfo ? callInfo.creditsUsed : 0;
        releaseAdminLock(adminId);
        console.log(`🔓 Admin ${adminId} lock kaldırıldı - call bitti`);

        activeCallAdmins.delete(adminId);
        activeCalls.delete(callKey);

        console.log(`💔 Heartbeat stopped: ${callKey} (${reason})`);
        let remainingCredits = 0;
        try {
            const userResult = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
            if (userResult.rows.length > 0) {
                remainingCredits = userResult.rows[0].credits;
            }
        } catch (error) {
            console.error('Kalan kredi alınamadı:', error);
        }

        broadcastCallEnd(userId, adminId, reason, { duration, creditsUsed, remainingCredits, callId: callKey });

        broadcastAdminListToCustomers();
        setTimeout(() => {
            broadcastAdminListToCustomers();
        }, 1000);
    }
}
function broadcastCreditUpdate(userId, newCredits, creditsUsed) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'credit-update',
            credits: newCredits,
            creditsUsed: creditsUsed,
            source: 'heartbeat'
        }));
    }

    const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
    adminClients.forEach(client => {
        if (client.ws && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
                type: 'auto-credit-update',
                userId: userId,
                creditsUsed: creditsUsed,
                newCredits: newCredits,
                source: 'heartbeat'
            }));
        }
    });
}
function broadcastCallEnd(userId, adminId, reason, details = {}) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'call-ended',
            reason: reason,
            endedBy: 'system',
            adminId: adminId, 
            ...details
        }));
    }

    const adminClient = Array.from(clients.values()).find(c =>
        c.userType === 'admin' && (c.uniqueId === adminId || c.id === adminId)
    );

    if (adminClient && adminClient.ws && adminClient.ws.readyState === WebSocket.OPEN) {
        adminClient.ws.send(JSON.stringify({
            type: 'call-ended',
            userId: userId,
            reason: reason,
            endedBy: 'system',
            ...details
        }));
    }
}


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
                .btn:hover { opacity: 0.9; transform: translateY(-1px); }
                .btn:disabled { opacity: 0.6; cursor: not-allowed; }
                .btn-customer { background: linear-gradient(135deg, #059669, #047857); }
                .title { text-align: center; margin-bottom: 30px; color: #dc2626; font-size: 24px; font-weight: bold; }
                .twofa-section { display: none; }
                .twofa-section.active { display: block; }
                .twofa-code { text-align: center; font-size: 18px; letter-spacing: 3px; font-family: monospace; }
                .back-btn { background: linear-gradient(135deg, #64748b, #475569); }
                .error-msg { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; font-size: 14px; }
                .success-msg { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; font-size: 14px; }
                .loading { opacity: 0.7; pointer-events: none; }
                .twofa-info { background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.3); color: #93c5fd; padding: 12px; border-radius: 6px; margin: 10px 0; font-size: 13px; text-align: center; }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="title">🔐 VIPCEP</div>

                <div id="step1">
                    <div class="form-group">
                        <input type="text" id="username" class="form-input" placeholder="👤 Kullanıcı Adı">
                    </div>
                    <div class="form-group">
                        <input type="password" id="password" class="form-input" placeholder="🔑 Şifre">
                    </div>
                    <button class="btn" id="superAdminBtn" onclick="startSuperLogin()">🔴 SUPER ADMİN GİRİŞİ</button>
                    <button class="btn" onclick="normalAdminLogin()">🟡 ADMİN GİRİŞİ</button>
                    <button class="btn btn-customer" onclick="window.location.href='${SECURITY_CONFIG.CUSTOMER_PATH}'">🟢 MÜŞTERİ UYGULAMASI</button>
                </div>

                <div id="step2" class="twofa-section">
                    <div class="twofa-info">
                        🔐 İki faktörlü kimlik doğrulaması gerekli
                    </div>
                    <div class="form-group">
                        <input type="text" id="totpCode" class="form-input twofa-code" placeholder="000000" maxlength="6" autocomplete="off">
                    </div>
                    <button class="btn" id="verify2FABtn" onclick="verify2FA()">🔐 DOĞ​RULA</button>
                    <button class="btn back-btn" onclick="goBackToStep1()">← GERİ</button>
                </div>

                <div id="messageArea"></div>
            </div>

            <script>
                let currentStep = 1;
                let currentUsername = '';
                let currentPassword = '';

                function showMessage(message, type = 'error') {
                    const area = document.getElementById('messageArea');
                    area.innerHTML = \`<div class="\${type}-msg">\${message}</div>\`;
                    setTimeout(() => { area.innerHTML = ''; }, 5000);
                }

                function setLoading(loading) {
                    const container = document.querySelector('.login-container');
                    if (loading) {
                        container.classList.add('loading');
                    } else {
                        container.classList.remove('loading');
                    }
                }

                function goToStep2() {
                    currentStep = 2;
                    document.getElementById('step1').style.display = 'none';
                    document.getElementById('step2').style.display = 'block';
                    document.getElementById('totpCode').focus();
                }

                function goBackToStep1() {
                    currentStep = 1;
                    document.getElementById('step1').style.display = 'block';
                    document.getElementById('step2').style.display = 'none';
                    document.getElementById('totpCode').value = '';
                    document.getElementById('messageArea').innerHTML = '';
                }

                async function startSuperLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;

                    if (!username || !password) {
                        return showMessage('Kullanıcı adı ve şifre gerekli!');
                    }

                    currentUsername = username;
                    currentPassword = password;

                    setLoading(true);

                    try {
                        const response = await fetch('/auth/super-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password, step: 'credentials' })
                        });

                        const result = await response.json();

                        if (result.success) {
                            window.location.href = '${SECURITY_CONFIG.SUPER_ADMIN_PATH}';
                        } else if (result.require2FA) {
                            showMessage('2FA kodu girin', 'success');
                            goToStep2();
                        } else {
                            showMessage(result.error || 'Giriş başarısız!');
                        }
                    } catch (error) {
                        showMessage('Bağlantı hatası!');
                    }

                    setLoading(false);
                }

                async function verify2FA() {
                    const totpCode = document.getElementById('totpCode').value.trim();

                    if (!totpCode || totpCode.length !== 6 || !/^\\d{6}$/.test(totpCode)) {
                        return showMessage('6 haneli kod gerekli!');
                    }

                    setLoading(true);

                    try {
                        const response = await fetch('/auth/super-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                username: currentUsername,
                                password: currentPassword,
                                totpCode: totpCode,
                                step: '2fa'
                            })
                        });

                        const result = await response.json();

                        if (result.success) {
                            showMessage('Giriş başarılı! Yönlendiriliyor...', 'success');
                            setTimeout(() => {
                                window.location.href = '${SECURITY_CONFIG.SUPER_ADMIN_PATH}';
                            }, 1000);
                        } else {
                            showMessage(result.error || '2FA kodu hatalı!');
                            document.getElementById('totpCode').value = '';
                            document.getElementById('totpCode').focus();
                        }
                    } catch (error) {
                        showMessage('Bağlantı hatası!');
                    }

                    setLoading(false);
                }

                async function normalAdminLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    if (!username || !password) return showMessage('Kullanıcı adı ve şifre gerekli!');

                    setLoading(true);

                    try {
                        const response = await fetch('/auth/admin-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password })
                        });
                        const result = await response.json();
                        if (result.success) {
                            showMessage('Giriş başarılı!', 'success');
                            setTimeout(() => {
                                window.location.href = '${SECURITY_CONFIG.NORMAL_ADMIN_PATH}';
                            }, 1000);
                        } else {
                            showMessage(result.error || 'Giriş başarısız!');
                        }
                    } catch (error) {
                        showMessage('Bağlantı hatası!');
                    }

                    setLoading(false);
                }

                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        if (currentStep === 1) {
                            startSuperLogin();
                        } else if (currentStep === 2) {
                            verify2FA();
                        }
                    }
                });

                document.getElementById('totpCode').addEventListener('input', (e) => {
                    e.target.value = e.target.value.replace(/[^0-9]/g, '');
                });
            </script>
        </body>
        </html>
    `);
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
app.post('/auth/admin-login', async (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;

    try {
        const rateStatus = await checkRateLimit(clientIP, 'admin');
        if (!rateStatus.allowed) {
            return res.json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }

        const admin = await authenticateAdmin(username, password);
        if (admin && admin.role === 'normal') {
            req.session.normalAdmin = { id: admin.id, username: admin.username, loginTime: new Date() };
            res.json({ success: true, redirectUrl: SECURITY_CONFIG.NORMAL_ADMIN_PATH });
        } else {
            await recordFailedLogin(clientIP, 'admin');
            res.json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }
    } catch (error) {
        res.json({ success: false, error: 'Sistem hatası!' });
    }
});
app.get('/auth/check-session', (req, res) => {
    if (req.session && req.session.superAdmin) {
        res.json({ authenticated: true, role: 'super', username: req.session.superAdmin.username });
    } else if (req.session && req.session.normalAdmin) {
        res.json({ authenticated: true, role: 'normal', username: req.session.normalAdmin.username });
    } else {
        res.json({ authenticated: false });
    }
});
app.post('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.json({ success: false, error: 'Çıkış hatası' });
        }
        res.json({ success: true });
    });
});
app.get(SECURITY_CONFIG.SUPER_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'super-admin.html'));
});
app.get(SECURITY_CONFIG.NORMAL_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});
app.get(SECURITY_CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});


// ================== API ROUTES ==================

app.post('/api/approved-users', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

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
app.delete('/api/approved-users/:userId', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

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
app.post('/api/approved-users/:userId/credits', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

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

        broadcastCreditUpdate(userId, newCredits, Math.abs(creditDiff));

        res.json({ success: true, credits: newCredits, oldCredits });
    } catch (error) {
        console.log('Credit update error:', error);
        res.json({ success: false, error: 'Kredi güncellenemedi!' });
    }
});
app.post('/api/admins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

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
app.post('/api/announcement', (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

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
app.delete('/api/announcement', (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

    currentAnnouncement = null;

    broadcastToCustomers({
        type: 'announcement-deleted'
    });

    res.json({ success: true });
});
app.get('/api/announcement', (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

    res.json({
        success: true,
        announcement: currentAnnouncement
    });
});
app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/admins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

    try {
        const result = await pool.query('SELECT id, username, role, is_active, last_login, created_at FROM admins ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('/api/calls', async (req, res) => {
    if (!req.session || (!req.session.superAdmin && !req.session.normalAdmin)) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

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
app.get('/api/stats', async (req, res) => {
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
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
            activeHeartbeats: activeHeartbeats.size,
            activeCallAdmins: activeCallAdmins.size
                });
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
            });
app.get('/api/admin-earnings', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erisim' });
    }

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
    if (!req.session || (!req.session.normalAdmin && !req.session.superAdmin)) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

    const username = req.session.normalAdmin?.username || req.session.superAdmin?.username;

    try {
        const result = await pool.query(
            'SELECT total_earned FROM admin_earnings WHERE username = $1',
            [username]
        );

        const earnings = result.rows[0]?.total_earned || 0;
        res.json({ earnings });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/reset-admin-earnings/:username', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }

    const { username } = req.params;

    try {
        await pool.query(
            'UPDATE admin_earnings SET total_earned = 0, last_updated = CURRENT_TIMESTAMP WHERE username = $1',
            [username]
        );

        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        clients: clients.size,
        activeHeartbeats: activeHeartbeats.size,
        activeCallAdmins: activeCallAdmins.size
    });
});


// YENİ: Usta Profili ve Değerlendirme API Route'ları
// -----------------------------------------------------------------------------

app.get('/api/admins/:username/profile', async (req, res) => {
    const { username } = req.params;
    try {
        const profileRes = await pool.query(`
            SELECT a.username, p.specialization, p.bio, p.profile_picture_url
            FROM admins a
            LEFT JOIN admin_profiles p ON a.username = p.admin_username
            WHERE a.username = $1
        `, [username]);

        if (profileRes.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Admin not found' });
        }

        const reviewsRes = await pool.query(`
            SELECT 
                customer_id, 
                customer_name, 
                rating, 
                comment, 
                tip_amount, 
                created_at 
            FROM admin_reviews 
            WHERE admin_username = $1 
            ORDER BY created_at DESC
        `, [username]);

        const averageRatingRes = await pool.query(`
            SELECT AVG(rating) as average_rating 
            FROM admin_reviews 
            WHERE admin_username = $1
        `, [username]);

        const profile = profileRes.rows[0];
        profile.reviews = reviewsRes.rows;
        profile.average_rating = parseFloat(averageRatingRes.rows[0].average_rating || 0).toFixed(1);

        res.json({ success: true, profile });
    } catch (error) {
        console.error(`Error fetching admin profile for ${username}:`, error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.put('/api/admins/:username/profile', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ success: false, error: 'Yetkisiz erişim' });
    }
    const { username } = req.params;
    const { specialization, bio, profile_picture_url } = req.body;

    try {
        await pool.query(`
            INSERT INTO admin_profiles (admin_username, specialization, bio, profile_picture_url, updated_at)
            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
            ON CONFLICT (admin_username)
            DO UPDATE SET
                specialization = EXCLUDED.specialization,
                bio = EXCLUDED.bio,
                profile_picture_url = EXCLUDED.profile_picture_url,
                updated_at = CURRENT_TIMESTAMP
        `, [username, specialization, bio, profile_picture_url]);

        res.json({ success: true, message: 'Profil güncellendi' });
    } catch (error) {
        console.error(`Error updating admin profile for ${username}:`, error);
        res.status(500).json({ success: false, error: 'Profil güncellenemedi' });
    }
});

app.post('/api/admins/:adminUsername/review', async (req, res) => {
    const { adminUsername } = req.params;
    const { customerId, customerName, rating, comment, tipAmount, callId } = req.body;

    if (!customerId) {
        return res.status(400).json({ success: false, error: 'Geçersiz veri: customerId eksik' });
    }

    // Derecelendirme (rating) 0 ise veya yoksa, yalnızca tipAmount'a bak
    if ((rating < 1 || rating > 5) && (!tipAmount || tipAmount <= 0)) {
        return res.status(400).json({ success: false, error: 'Geçersiz veri: En az 1 yıldız veya bahşiş gerekli' });
    }
    
    // Rating 0 olarak geliyorsa, bunu null olarak veritabanına kaydet
    const finalRating = (rating === 0 || !rating) ? null : rating;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const existingReview = await client.query(
            'SELECT id FROM admin_reviews WHERE call_id = $1 AND customer_id = $2',
            [callId, customerId]
        );

        if (existingReview.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.json({
                success: false,
                error: 'Bu arama için zaten değerlendirme yapılmış'
            });
        }
        
        if (tipAmount && tipAmount > 0) {
            await client.query('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE');
            const userRes = await client.query('SELECT credits FROM approved_users WHERE id = $1 FOR UPDATE', [customerId]);
            
            if (userRes.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({ success: false, error: 'Kullanıcı bulunamadı' });
            }

            const currentCredits = userRes.rows[0].credits;
            if (currentCredits < tipAmount) {
                await client.query('ROLLBACK');
                return res.status(400).json({ success: false, error: `Yetersiz kredi. Mevcut: ${currentCredits}, İstenen: ${tipAmount}` });
            }

            const newCredits = currentCredits - tipAmount;
            const updateResult = await client.query(
                `UPDATE approved_users 
                 SET credits = $1 
                 WHERE id = $2 AND credits = $3
                 RETURNING credits`,
                [newCredits, customerId, currentCredits]
            );

            if (updateResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({ success: false, error: 'İşlem çakışması, lütfen tekrar deneyin' });
            }

            await client.query(`
                INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                VALUES ($1, 'tip', $2, $3, $4)
            `, [customerId, -tipAmount, newCredits, `${adminUsername} ustasına bahşiş`]);

            await client.query(`
                INSERT INTO admin_earnings (username, total_earned)
                VALUES ($1, $2)
                ON CONFLICT (username)
                DO UPDATE SET
                    total_earned = admin_earnings.total_earned + $2,
                    last_updated = CURRENT_TIMESTAMP
            `, [adminUsername, tipAmount]);

            broadcastCreditUpdate(customerId, newCredits, tipAmount);
        }

        await client.query(`
            INSERT INTO admin_reviews (admin_username, customer_id, customer_name, rating, comment, tip_amount, call_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [adminUsername, customerId, customerName, finalRating, comment, tipAmount || 0, callId]);

        await client.query('COMMIT');
        res.json({ success: true, message: 'Değerlendirmeniz için teşekkürler!' });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error submitting review:', error);
        if (error.code === '40001') {
            return res.status(503).json({ success: false, error: 'Sistem yoğun, lütfen tekrar deneyin' });
        }
        res.status(500).json({ success: false, error: 'Değerlendirme gönderilemedi' });
    } finally {
        client.release();
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

            console.log(`📨 Message: ${message.type} from ${senderId} (${senderType})`);

            switch (message.type) {
                case 'register':
                    console.log(`🔄 Registration request: ${message.name} (${message.userId}) as ${message.userType}`);

                        if (message.userType === 'admin') {
                            const oldAdminEntries = Array.from(clients.entries()).filter(([clientId, clientData]) =>
                                clientData.id === message.userId &&
                                clientData.userType === 'admin' &&
                                (!clientData.ws || clientData.ws.readyState !== WebSocket.OPEN)
                            );

                            oldAdminEntries.forEach(([oldClientId, oldClientData]) => {
                                console.log(`🧹 Cleaning up dead admin connection: ${oldClientId}`);
                                clients.delete(oldClientId);
                            });
                            let activeAdminId = null;
                            for (const [adminId, callInfo] of activeCallAdmins.entries()) {
                                const baseAdminId = adminId.split('_')[0];
                                if (baseAdminId === message.userId) {
                                    activeAdminId = adminId;
                                    console.log(`🔄 Admin ${message.userId} has active call, preserving ID: ${adminId}`);
                                    break;
                                }
                            }

                            let uniqueClientId;
                            console.log(`DEBUG: Admin registration - userId: ${message.userId}, name: ${message.name}`);
                            const sameNameAdmin = Array.from(clients.values()).find(c =>
                                c.userType === 'admin' && c.name === message.name && c.id !== message.userId
                            );

                            if (sameNameAdmin) {
                                console.log(`⚠️ SORUN: ${message.name} admin'i farklı ID ile kayıtlı: ${sameNameAdmin.id}`);
                            }
                            uniqueClientId = message.userId;
                            clients.delete(uniqueClientId);

                            console.log(`👤 Admin connection: ${message.name} as ${uniqueClientId}`);

                            clients.set(uniqueClientId, {
                                ws: ws,
                                id: message.userId,
                                uniqueId: uniqueClientId,
                                name: message.name,
                                userType: 'admin',
                                registeredAt: new Date().toLocaleTimeString(),
                                online: true
                            });

                            ws.send(JSON.stringify({
                                type: 'admin-registered',
                                uniqueId: uniqueClientId,
                                originalId: message.userId
                            }));

                            if (!adminCallbacks.has(uniqueClientId)) {
                                adminCallbacks.set(uniqueClientId, []);
                            }

                            broadcastCallbacksToAdmin(uniqueClientId);

                            setTimeout(() => {
                                broadcastAdminListToCustomers();
                            }, 500);

                        } else {
                        const existingCustomer = clients.get(message.userId);
                        if (existingCustomer && existingCustomer.ws.readyState !== WebSocket.OPEN) {
                            clients.delete(message.userId);
                            console.log(`🧹 Cleaned up dead customer connection: ${message.userId}`);
                        }

                        clients.set(message.userId, {
                            ws: ws,
                            id: message.userId,
                            uniqueId: message.userId,
                            name: message.name,
                            userType: 'customer',
                            registeredAt: new Date().toLocaleTimeString(),
                            online: true
                        });

                        console.log(`👤 Customer registered: ${message.name} (${message.userId})`);

                        if (currentAnnouncement) {
                            ws.send(JSON.stringify({
                                type: 'announcement-broadcast',
                                announcement: currentAnnouncement
                            }));
                        }
                    }

                    broadcastUserList();
                    broadcastAdminListToCustomers();
                    break;
                
                case 'login-request':
                    const rateLimit = await checkRateLimit(clientIP);
                    if (!rateLimit.allowed) {
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            rateLimited: true,
                            attempts: rateLimit.attempts,
                            remaining: rateLimit.remaining,
                            resetTime: rateLimit.resetTime,
                            error: `Çok fazla başarısız deneme!`
                        }));
                        break;
                    }

                    const approval = await isUserApproved(message.userId, message.userName);

                    if (approval.approved) {
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: true,
                            credits: approval.credits,
                            user: approval.user
                        }));
                    } else {
                        const newRateStatus = await recordFailedLogin(clientIP);
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: approval.reason,
                            remaining: newRateStatus.remaining,
                            attempts: newRateStatus.attempts,
                            rateLimited: !newRateStatus.allowed
                        }));
                    }
                    break;

                case 'direct-call-request':
                    if (!checkCallRateLimit(message.userId)) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Çok fazla arama denemesi! Lütfen biraz bekleyin.'
                        }));
                        break;
                    }
                    console.log(`📞 Direct call request from ${message.userName} (${message.userId}) to admin ${message.targetAdminId}`);
                    const lockAcquired = await acquireAdminLockAtomic(message.targetAdminId, message.userId);
                    if (!lockAcquired) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Bu usta şu anda meşgul!'
                        }));
                        break;
                    }
                    console.log(`🔒 Admin ${message.targetAdminId} kilitlendi: ${message.userId}`);
                    broadcastAdminListToCustomers();
                    if (message.credits <= 0) {
                        await releaseAdminLock(message.targetAdminId);
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Yetersiz kredi!'
                        }));
                        break;
                    }
                    console.log('🔍 Admin aranıyor:', message.targetAdminId);
                    console.log('🔍 Mevcut adminler:', Array.from(clients.values()).filter(c => c.userType === 'admin').map(a => ({id: a.id, uniqueId: a.uniqueId, name: a.name})));
                    const targetAdmin = Array.from(clients.values()).find(c =>
                        c.userType === 'admin' &&
                        (c.uniqueId === message.targetAdminId || c.id === message.targetAdminId) &&
                        c.ws && c.ws.readyState === WebSocket.OPEN
                    );

                    if (!targetAdmin) {
                        await releaseAdminLock(message.targetAdminId);
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Seçilen usta şu anda bağlı değil!'
                        }));
                        break;
                    }

                    if (activeCallAdmins.has(targetAdmin.uniqueId)) {
                        await releaseAdminLock(message.targetAdminId);
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Seçilen usta şu anda başka bir aramada!'
                        }));
                        break;
                    }

                    targetAdmin.ws.send(JSON.stringify({
                        type: 'admin-call-request',
                        userId: message.userId,
                        userName: message.userName,
                        adminId: targetAdmin.uniqueId,
                        adminName: targetAdmin.name
                    }));

                    ws.send(JSON.stringify({
                        type: 'call-connecting'
                    }));

                    console.log(`📡 Call request sent to admin ${targetAdmin.name}`);
                    break;

                case 'callback-request':
                    console.log(`📝 Callback request from ${message.userName} (${message.userId}) to admin ${message.targetAdminId}`);

                    const callbackTargetAdmin = Array.from(clients.values()).find(c =>
                        c.userType === 'admin' &&
                        (c.uniqueId === message.targetAdminId || c.id === message.targetAdminId)
                    );

                    if (!callbackTargetAdmin) {
                        ws.send(JSON.stringify({
                            type: 'callback-failed',
                            reason: 'Seçilen usta bulunamadı!'
                        }));
                        break;
                    }

                    const adminCallbackList = adminCallbacks.get(callbackTargetAdmin.uniqueId) || [];

                    const existingCallback = adminCallbackList.find(cb => cb.customerId === message.userId);
                    if (existingCallback) {
                        ws.send(JSON.stringify({
                            type: 'callback-failed',
                            reason: 'Bu usta için zaten bir geri dönüş talebiniz var!'
                        }));
                        break;
                    }

                    adminCallbackList.push({
                        customerId: message.userId,
                        customerName: message.userName,
                        timestamp: Date.now()
                    });

                    adminCallbacks.set(callbackTargetAdmin.uniqueId, adminCallbackList);

                    ws.send(JSON.stringify({
                        type: 'callback-success',
                        adminName: callbackTargetAdmin.name
                    }));

                    broadcastCallbacksToAdmin(callbackTargetAdmin.uniqueId);

                    console.log(`📝 Callback added for admin ${callbackTargetAdmin.name}: ${message.userName}`);
                    break;

                case 'admin-call-customer':
                    console.log(`📞 Admin ${senderId} calling customer ${message.targetCustomerId}`);

                    const targetCustomer = clients.get(message.targetCustomerId);
                    if (!targetCustomer || targetCustomer.ws.readyState !== WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Müşteri şu anda bağlı değil!'
                        }));
                        break;
                    }

                    if (activeCallAdmins.has(senderId)) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Zaten bir aramada bulunuyorsunuz!'
                        }));
                        break;
                    }
                    
                    targetCustomer.ws.send(JSON.stringify({
                        type: 'admin-call-request',
                        adminId: senderId,
                        adminName: message.adminName || senderInfo?.name || 'Usta'
                    }));

                    ws.send(JSON.stringify({
                        type: 'call-connecting'
                    }));

                    const adminCallbackListForCall = adminCallbacks.get(senderId) || [];
                    const updatedCallbacks = adminCallbackListForCall.filter(cb => cb.customerId !== message.targetCustomerId);
                    adminCallbacks.set(senderId, updatedCallbacks);
                    broadcastCallbacksToAdmin(senderId);


                    console.log(`📡 Admin call request sent to customer ${message.targetCustomerId}`);
                    break;
                case 'accept-incoming-call': {
                    const adminClient = senderInfo;
                    let customerClient = clients.get(message.userId);
                    
                    if (!customerClient) {
                         console.log(`Client not found by key ${message.userId}, iterating...`);
                         for (const client of clients.values()) {
                            if (client.id === message.userId && client.userType === 'customer') {
                                customerClient = client;
                                console.log(`Found client by iteration: ${client.id}`);
                                break;
                            }
                         }
                    }

                    if (!adminClient) {
                        console.error(`CRITICAL: 'accept-incoming-call' from unknown sender.`, message);
                        break;
                    }
                    
                    console.log(`✅ Admin '${adminClient.name}' accepted call from customer '${message.userId}'`);

                    if (!customerClient || !customerClient.ws || customerClient.ws.readyState !== WebSocket.OPEN) {
                        console.log(`❌ Customer '${message.userId}' is no longer online. Informing admin.`);
                        adminClient.ws.send(JSON.stringify({
                            type: 'call-failed',
                            reason: 'Müşteri artık çevrimiçi değil!'
                        }));
                        releaseAdminLock(adminClient.uniqueId);
                        broadcastAdminListToCustomers();
                        break;
                    }

                    customerClient.ws.send(JSON.stringify({
                        type: 'call-accepted',
                        adminId: adminClient.uniqueId,
                        adminName: adminClient.name
                    }));
                    console.log(`📤 Sent 'call-accepted' to customer '${customerClient.id}'`);

                    const callKey = `${customerClient.id}-${adminClient.uniqueId}`;
                    startHeartbeat(customerClient.id, adminClient.uniqueId, callKey);
                    console.log(`💓 Heartbeat started for call: ${callKey}`);

                    const adminCallbackListUpdated = adminCallbacks.get(adminClient.uniqueId) || [];
                    const filteredCallbacks = adminCallbackListUpdated.filter(cb => cb.customerId !== customerClient.id);
                    if (adminCallbackListUpdated.length > filteredCallbacks.length) {
                        adminCallbacks.set(adminClient.uniqueId, filteredCallbacks);
                        broadcastCallbacksToAdmin(adminClient.uniqueId);
                        console.log(`📝 Cleared callback request for customer '${customerClient.id}'`);
                    }
                    break;
                }

                case 'reject-incoming-call':
                    console.log(`❌ Call rejected. Message from ${senderType}:`, message);
                    const adminIdForReject = message.adminId || (senderType === 'admin' ? senderId : null);
                    const customerIdForReject = message.userId || (senderType === 'customer' ? senderId : null);

                    if (adminIdForReject) {
                        const lockInfo = adminLocks.get(adminIdForReject);
                        const customerToNotify = clients.get(lockInfo ? lockInfo.lockedBy : customerIdForReject);
                        
                        if (customerToNotify && customerToNotify.ws.readyState === WebSocket.OPEN) {
                             customerToNotify.ws.send(JSON.stringify({
                                type: 'call-rejected',
                                reason: 'Usta şu anda meşgul veya aramanızı reddetti.'
                            }));
                        }
                        releaseAdminLock(adminIdForReject);
                        console.log(`🔓 Admin ${adminIdForReject} lock removed due to rejection.`);
                        broadcastAdminListToCustomers();
                    }
                    break;
                
                case 'remove-callback':
                    console.log(`🗑️ Admin ${senderId} removing callback for customer ${message.customerId}`);

                    const adminCallbackList2 = adminCallbacks.get(senderId) || [];
                    const filteredCallbacks2 = adminCallbackList2.filter(cb => cb.customerId !== message.customerId);
                    adminCallbacks.set(senderId, filteredCallbacks2);

                    broadcastCallbacksToAdmin(senderId);
                    break;
                case 'admin-ready-for-webrtc':
                        console.log(`🔗 Admin ${senderId} WebRTC için hazır, customer ${message.userId} bilgilendiriliyor`);

                        const readyCustomer = clients.get(message.userId);
                        if (readyCustomer && readyCustomer.ws.readyState === WebSocket.OPEN) {
                            readyCustomer.ws.send(JSON.stringify({
                                type: 'admin-ready-for-webrtc',
                                adminId: message.adminId,
                                message: 'Admin WebRTC için hazır'
                            }));
                            console.log(`📡 Admin ready mesajı customer ${message.userId}'e gönderildi`);
                        }
                        break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    const targetClient = findWebRTCTarget(message.targetId);
                    if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
                        const forwardMessage = {
                            type: message.type,
                            userId: senderId,
                            targetId: message.targetId
                        };

                        if (message.type === 'offer') forwardMessage.offer = message.offer;
                        if (message.type === 'answer') forwardMessage.answer = message.answer;
                        if (message.type === 'ice-candidate') forwardMessage.candidate = message.candidate;

                        targetClient.ws.send(JSON.stringify(forwardMessage));
                        console.log(`🔄 WebRTC ${message.type} forwarded: ${senderId} → ${message.targetId}`);
                    } else {
                        console.log(`⚠️ WebRTC target not found: ${message.targetId}`);
                    }
                    break;

                case 'end-call':
                    console.log(`📞 Call ended by ${senderType} ${senderId}`);

                    const targetId = message.targetId;
                    const callInfoToEnd = findActiveCall(senderId, targetId);

                    if (!callInfoToEnd) {
                        console.warn(`End-call isteği geldi ama aktif arama bulunamadı: ${senderId} & ${targetId}`);
                        const endTargetFallback = findWebRTCTarget(targetId);
                        if (endTargetFallback && endTargetFallback.ws.readyState === WebSocket.OPEN) {
                             endTargetFallback.ws.send(JSON.stringify({ type: 'call-ended', reason: 'force_end' }));
                        }
                        
                        releaseAdminLock(targetId);
                        broadcastAdminListToCustomers();
                        return;
                    }

                    const finalDuration = Math.floor((Date.now() - callInfoToEnd.startTime) / 1000);
                    const finalCreditsUsed = callInfoToEnd.creditsUsed;
                    const customerId = callInfoToEnd.customerId;
                    const adminId = callInfoToEnd.adminId;
                    const endedBy = senderType;
                    
                    await stopHeartbeat(callInfoToEnd.callKey, message.reason || 'user_ended');

                    let remainingCredits = 0;
                    try {
                        const userResult = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [customerId]);
                        if (userResult.rows.length > 0) {
                            remainingCredits = userResult.rows[0].credits;
                        }
                    } catch (error) {
                        console.error('Kalan kredi alınamadı (end-call):', error);
                    }
                    
                    const callEndMessage = {
                        type: 'call-ended',
                        userId: customerId,
                        adminId: adminId,
                        duration: finalDuration,
                        creditsUsed: finalCreditsUsed,
                        remainingCredits: remainingCredits,
                        endedBy: endedBy,
                        reason: message.reason || 'user_ended'
                    };

                    const finalCustomerTarget = clients.get(customerId);
                    if(finalCustomerTarget && finalCustomerTarget.ws.readyState === WebSocket.OPEN) {
                        finalCustomerTarget.ws.send(JSON.stringify(callEndMessage));
                    }

                    const finalAdminTarget = Array.from(clients.values()).find(c => c.uniqueId === adminId);
                    if(finalAdminTarget && finalAdminTarget.ws.readyState === WebSocket.OPEN) {
                        finalAdminTarget.ws.send(JSON.stringify(callEndMessage));
                    }

                    try {
                        await pool.query(`
                            INSERT INTO call_history (user_id, admin_id, duration, credits_used, end_reason)
                            VALUES ($1, $2, $3, $4, $5)
                        `, [
                            customerId,
                            adminId,
                            finalDuration,
                            finalCreditsUsed,
                            message.reason || 'normal'
                        ]);
                        console.log(`✅ Arama kaydı veritabanına eklendi: ${callInfoToEnd.callKey}`);
                    } catch (error) {
                        console.log('Call history save error:', error);
                    }
                    break;
            }

        } catch (error) {
            console.log('Message processing error:', error.message);
        }
    });

    ws.on('close', async () => {
        const client = findClientById(ws);
        console.log(`👋 WebSocket closed: ${client?.name || 'Unknown'} (${client?.userType || 'unknown'})`);

        if (client && client.userType === 'admin') {
            const adminKey = client.uniqueId || client.id;
            console.log(`🔴 Admin ${adminKey} WebSocket closed`);

            const adminCallInfo = activeCallAdmins.get(adminKey);

            if (adminCallInfo) {
                console.log(`⏳ Admin ${adminKey} in active call with ${adminCallInfo.customerId}, waiting for reconnection...`);
                for (const [key, clientData] of clients.entries()) {
                    if (clientData.ws === ws && clientData.userType === 'admin') {
                        clientData.ws = null;
                        clientData.online = false;
                        break;
                    }
                }
                const callKey = `${adminCallInfo.customerId}-${adminKey}`;
                const callInfo = activeCalls.get(callKey);
                const creditsUsedSoFar = callInfo ? callInfo.creditsUsed : 0;
                
                clients.set(`${adminKey}_disconnected`, {
                    ...client,
                    ws: null,
                    disconnectedAt: Date.now(),
                    creditsUsedBeforeDisconnect: creditsUsedSoFar
                });

                setTimeout(async () => {
                    const reconnectedClient = Array.from(clients.values()).find(c =>
                        c.uniqueId === adminKey &&
                        c.userType === 'admin' &&
                        c.ws &&
                        c.ws.readyState === WebSocket.OPEN
                    );

                    if (!reconnectedClient) {
                        console.log(`💔 Admin ${adminKey} failed to reconnect - ending call`);
                        const refundAmount = Math.max(0, Math.floor(creditsUsedSoFar * 0.5));
                        if (refundAmount > 0) {
                            const refundClient = await pool.connect();
                            try {
                                await refundClient.query('BEGIN');
                                await refundClient.query('UPDATE approved_users SET credits = credits + $1 WHERE id = $2',
                                    [refundAmount, adminCallInfo.customerId]
                                );
                                await refundClient.query(`
                                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                                    VALUES ($1, 'refund', $2, (SELECT credits FROM approved_users WHERE id = $1), $3)
                                `, [adminCallInfo.customerId, refundAmount, 'Admin bağlantı kaybı - kısmi iade']);
                                await refundClient.query('COMMIT');
                                console.log(`💰 Refunded ${refundAmount} credits to ${adminCallInfo.customerId}`);
                            } catch (error) {
                                await refundClient.query('ROLLBACK');
                                console.error('Credit refund error:', error);
                            } finally {
                                refundClient.release();
                            }
                        }
                        await stopHeartbeat(callKey, 'admin_permanently_disconnected');
                        activeCallAdmins.delete(adminKey);
                        clients.delete(`${adminKey}_disconnected`);
                    } else {
                        console.log(`✅ Admin ${adminKey} reconnected successfully`);
                    }
                }, 15000);
            } else {
                for (const [key, clientData] of clients.entries()) {
                    if (clientData.ws === ws) {
                        clients.delete(key);
                        if (adminCallbacks.has(key)) {
                            adminCallbacks.delete(key);
                            console.log(`🗑️ Disconnected admin (${key}) callbacks cleaned.`);
                        }
                        console.log(`🗑️ Deleted client record: ${key}`);
                        break;
                    }
                }
            }
        } else {
            for (const [key, clientData] of clients.entries()) {
                if (clientData.ws === ws) {
                    clients.delete(key);
                    console.log(`🗑️ Deleted client record: ${key}`);
                    break;
                }
            }
        }
        setTimeout(() => {
            broadcastAdminListToCustomers();
        }, 100);
    });

    ws.on('error', (error) => {
        console.log('WebSocket error:', error.message);
    });
});

// ================== HELPER FUNCTIONS ==================

function checkCallRateLimit(userId) {
    const now = Date.now();
    const userLimits = callRateLimiter.get(userId) || { lastCall: 0, callCount: 0, windowStart: now };

    if (now - userLimits.lastCall < 10000) {
        return false;
    }

    if (now - userLimits.windowStart < 60000) {
        if (userLimits.callCount >= 3) {
            return false;
        }
        userLimits.callCount++;
    } else {
        userLimits.windowStart = now;
        userLimits.callCount = 1;
    }

    userLimits.lastCall = now;
    callRateLimiter.set(userId, userLimits);
    return true;
}

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
        if (client.id === targetId && client.userType === 'admin') {
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
    res.status(404).send(`
        <div style="text-align: center; padding: 50px; font-family: system-ui;">
            <h1>🔐 404 - Sayfa Bulunamadı</h1>
            <p>Güvenlik nedeniyle bu sayfa mevcut değil.</p>
            <p><a href="/" style="color: #dc2626; text-decoration: none;">← Ana sayfaya dön</a></p>
        </div>
    `);
});

// ================== SERVER STARTUP ==================

async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');

    await initDatabase();

    // Süresi dolmuş callback'leri temizleyen periyodik görev
    setInterval(() => {
        const now = Date.now();
        for (const [adminId, callbacks] of adminCallbacks.entries()) {
            const filteredCallbacks = callbacks.filter(cb => now - cb.timestamp < 3600000); // 1 saatten eski olanları sil
            if (filteredCallbacks.length !== callbacks.length) {
                adminCallbacks.set(adminId, filteredCallbacks);
                console.log(`🧹 Admin ${adminId} için ${callbacks.length - filteredCallbacks.length} eski callback temizlendi.`);
            }
        }
    }, 600000); // Her 10 dakikada bir çalıştır

    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server Çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
        console.log(`🌐 URL: http://0.0.0.0:${PORT}`);
        console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('🔐 GÜVENLİK URL\'LERİ:');
        console.log(` 🔴 Super Admin: ${SECURITY_CONFIG.SUPER_ADMIN_PATH}`);
        console.log(` 🟡 Normal Admin: ${SECURITY_CONFIG.NORMAL_ADMIN_PATH}`);
        console.log(` 🟢 Customer App: ${SECURITY_CONFIG.CUSTOMER_PATH}`);
        console.log('');
        console.log('📞 YENİ SİSTEM: Admin Seçim + Callback + Kredi Düşme');
        console.log(`   └── Heartbeat interval: ${HEARTBEAT_INTERVAL/1000} saniye`);
        console.log(`   └── Direct admin selection: Aktif`);
        console.log(`   └── Callback system: Aktif`);
        console.log(`   └── Credit deduction: %100 Güvenli`);
        console.log('');
        console.log('🛡️ GÜVENLİK ÖZELLİKLERİ:');
        console.log('   ✅ Credit tracking güvenli');
        console.log('   ✅ Admin disconnect koruması');
        console.log('   ✅ Heartbeat duplicate koruması');
        console.log('   ✅ Super Admin API endpoints');
        console.log('   ✅ 2FA sistem hazır');
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('✅ Yeni sistem hazır - Admin seçim + Callback + Kredi düşme garantili!');
    });
}



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
        console.log(`💔 Stopping heartbeat: ${callKey}`);
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

startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
