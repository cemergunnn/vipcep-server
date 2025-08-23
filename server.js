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
    SUPER_ADMIN_PATH: '/panel-' + crypto.randomBytes(8).toString('hex'),
    NORMAL_ADMIN_PATH: '/desk-' + crypto.randomBytes(8).toString('hex'),
    CUSTOMER_PATH: '/app-' + crypto.randomBytes(8).toString('hex'),
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
const incomingCallQueue = new Map();
const callTimeouts = new Map();
const MAX_QUEUE_SIZE = 5;
const CALL_TIMEOUT_DURATION = 30000;
const HEARTBEAT_INTERVAL = 60000;

// ================== HELPER FUNCTIONS ==================

function generateCallId() {
    return `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function addToCallQueue(callData) {
    if (incomingCallQueue.size >= MAX_QUEUE_SIZE) {
        let oldestCall = null;
        let oldestTime = Date.now();
        
        for (const [callId, call] of incomingCallQueue.entries()) {
            if (call.timestamp < oldestTime) {
                oldestTime = call.timestamp;
                oldestCall = callId;
            }
        }
        
        if (oldestCall) {
            removeFromCallQueue(oldestCall, 'queue_full');
        }
    }
    
    const callId = generateCallId();
    const callEntry = {
        callId: callId,
        userId: callData.userId,
        userName: callData.userName,
        credits: callData.credits,
        timestamp: Date.now(),
        status: 'waiting'
    };
    
    incomingCallQueue.set(callId, callEntry);
    
    const timeoutId = setTimeout(() => {
        removeFromCallQueue(callId, 'timeout');
    }, CALL_TIMEOUT_DURATION);
    
    callTimeouts.set(callId, timeoutId);
    
    return callEntry;
}

function removeFromCallQueue(callId, reason = 'manual') {
    const callData = incomingCallQueue.get(callId);
    if (!callData) return null;
    
    const timeoutId = callTimeouts.get(callId);
    if (timeoutId) {
        clearTimeout(timeoutId);
        callTimeouts.delete(callId);
    }
    
    incomingCallQueue.delete(callId);
    broadcastCallQueueToAdmins();
    
    return callData;
}

function broadcastCallQueueToAdmins() {
    const queueArray = Array.from(incomingCallQueue.values()).sort((a, b) => a.timestamp - b.timestamp);
    
    const message = JSON.stringify({
        type: 'call-queue-update',
        queue: queueArray,
        queueSize: queueArray.length
    });
    
    const allAdminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
    const availableAdmins = allAdminClients.filter(adminClient => {
        return !activeCallAdmins.has(adminClient.uniqueId || adminClient.id);
    });
    
    console.log(`📡 Queue broadcast: ${queueArray.length} calls to ${availableAdmins.length} available admins`);
    
    availableAdmins.forEach(adminClient => {
        if (adminClient.ws.readyState === WebSocket.OPEN) {
            adminClient.ws.send(message);
        }
    });
}

function removeUserCallFromQueue(userId, reason = 'user_cancelled') {
    let removedCallId = null;
    
    for (const [callId, callData] of incomingCallQueue.entries()) {
        if (callData.userId === userId) {
            removedCallId = callId;
            break;
        }
    }
    
    if (removedCallId) {
        return removeFromCallQueue(removedCallId, reason);
    }
    
    return null;
}

function acceptCallFromQueue(callId, adminId) {
    const callData = incomingCallQueue.get(callId);
    if (!callData) return null;
    
    activeCalls.set(callId, {
        adminId: adminId,
        customerId: callData.userId,
        startTime: Date.now(),
        callId: callId
    });
    
    removeFromCallQueue(callId, 'accepted');
    return callData;
}

function clearAllCallQueue(reason = 'emergency') {
    for (const timeoutId of callTimeouts.values()) {
        clearTimeout(timeoutId);
    }
    
    callTimeouts.clear();
    incomingCallQueue.clear();
    broadcastCallQueueToAdmins();
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
        console.log(`⚠️ Heartbeat already exists for ${callKey}, stopping old one`);
        stopHeartbeat(callKey, 'duplicate_prevention');
    }
    
    console.log(`💓 Starting heartbeat: ${callKey}`);
    
    const heartbeat = setInterval(async () => {
        try {
            if (!activeCallAdmins.has(adminId)) {
                console.log(`⚠️ Admin ${adminId} no longer active, stopping heartbeat`);
                stopHeartbeat(callKey, 'admin_disconnected');
                return;
            }
            
            const userResult = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
            if (userResult.rows.length > 0) {
                const currentCredits = userResult.rows[0].credits;
                
                if (currentCredits <= 0) {
                    stopHeartbeat(callKey, 'no_credits');
                    return;
                }
                
                const newCredits = Math.max(0, currentCredits - 1);
                await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);
                
                await pool.query(`
                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                    VALUES ($1, $2, $3, $4, $5)
                `, [userId, 'heartbeat', -1, newCredits, `Arama dakikası`]);
                
                broadcastCreditUpdate(userId, newCredits, 1);
                
                console.log(`💳 Credit deducted: ${userId} ${currentCredits}→${newCredits}`);
            }
        } catch (error) {
            console.log(`Heartbeat error ${userId}:`, error.message);
        }
    }, HEARTBEAT_INTERVAL);
    
    activeHeartbeats.set(callKey, heartbeat);
    
    activeCallAdmins.set(adminId, {
        customerId: userId,
        callStartTime: Date.now()
    });
}

function stopHeartbeat(callKey, reason = 'normal') {
    const heartbeat = activeHeartbeats.get(callKey);
    if (heartbeat) {
        clearInterval(heartbeat);
        activeHeartbeats.delete(callKey);
        
        console.log(`💔 Heartbeat stopped: ${callKey} (${reason})`);
        
        const [userId, adminId] = callKey.split('-');
        
        activeCallAdmins.delete(adminId);
        
        for (const [id, call] of activeCalls.entries()) {
            if (call.adminId === adminId && call.customerId === userId) {
                activeCalls.delete(id);
                break;
            }
        }
        
        broadcastCallEnd(userId, adminId, reason);
        
        setTimeout(() => {
            broadcastCallQueueToAdmins();
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
        if (client.ws.readyState === WebSocket.OPEN) {
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

function broadcastCallEnd(userId, adminId, reason) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'call-ended',
            reason: reason,
            endedBy: 'system'
        }));
    }
    
    const adminClient = Array.from(clients.values()).find(c => 
        c.userType === 'admin' && (c.uniqueId === adminId || c.id === adminId)
    );
    
    if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
        adminClient.ws.send(JSON.stringify({
            type: 'call-ended',
            userId: userId,
            reason: reason,
            endedBy: 'system'
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
                
                <!-- İlk Adım: Username/Password -->
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
                
                <!-- İkinci Adım: 2FA -->
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
                            // 2FA gerektirmeyen giriş
                            window.location.href = '${SECURITY_CONFIG.SUPER_ADMIN_PATH}';
                        } else if (result.require2FA) {
                            // 2FA gerekli
                            showMessage('2FA kodu girin', 'success');
                            goToStep2();
                        } else {
                            // Hata
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
                
                // Enter tuşu desteği
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') {
                        if (currentStep === 1) {
                            startSuperLogin();
                        } else if (currentStep === 2) {
                            verify2FA();
                        }
                    }
                });
                
                // 2FA kod input sadece sayı kabul et
                document.getElementById('totpCode').addEventListener('input', (e) => {
                    e.target.value = e.target.value.replace(/[^0-9]/g, '');
                });
            </script>
        </body>
        </html>
    `);
});

// Auth endpoints
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
        
        // 2FA kontrolü
        if (admin.totp_secret) {
            if (step !== '2fa') {
                // İlk adım - username/password doğru, 2FA iste
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
                // İkinci adım - 2FA kod kontrolü
                if (!req.session.tempSuperAdmin || 
                    req.session.tempSuperAdmin.id !== admin.id ||
                    Date.now() - req.session.tempSuperAdmin.timestamp > 300000) { // 5 dakika timeout
                    return res.json({ success: false, error: 'Oturum süresi doldu, tekrar deneyin!' });
                }
                
                if (!totpCode || !verifyTOTP(admin.totp_secret, totpCode)) {
                    await recordFailedLogin(clientIP, 'super-admin');
                    return res.json({ success: false, error: 'Geçersiz 2FA kodu!' });
                }
                
                // 2FA başarılı
                delete req.session.tempSuperAdmin;
            }
        }
        
        // Giriş başarılı
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

// Route handlers
app.get(SECURITY_CONFIG.SUPER_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'super-admin.html'));
});

app.get(SECURITY_CONFIG.NORMAL_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get(SECURITY_CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// ================== SUPER ADMIN API ROUTES ==================

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

app.get('/api/kvkk-consents', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }
    
    try {
        const result = await pool.query('SELECT * FROM kvkk_consents ORDER BY consent_date DESC LIMIT 100');
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

app.get('/api/failed-logins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }
    
    try {
        const result = await pool.query(`
            SELECT ip_address, user_type, attempt_time 
            FROM failed_logins 
            WHERE attempt_time > NOW() - INTERVAL '24 hours'
            ORDER BY attempt_time DESC 
            LIMIT 200
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/clear-failed-logins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim' });
    }
    
    try {
        await pool.query('DELETE FROM failed_logins');
        res.json({ success: true });
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

// ================== GENERAL API ROUTES ==================

app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
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
            callQueueSize: incomingCallQueue.size,
            maxQueueSize: MAX_QUEUE_SIZE,
            activeHeartbeats: activeHeartbeats.size,
            activeCallAdmins: activeCallAdmins.size
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        clients: clients.size,
        callQueueSize: incomingCallQueue.size,
        maxQueueSize: MAX_QUEUE_SIZE,
        activeHeartbeats: activeHeartbeats.size,
        activeCallAdmins: activeCallAdmins.size
    });
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
                    // Önce mevcut kaydı kontrol et (sayfa yenileme durumu)
                    let existingClientId = null;
                    for (const [clientId, clientData] of clients.entries()) {
                        if (clientData.id === message.userId && 
                            clientData.userType === message.userType &&
                            clientData.ws.readyState !== WebSocket.OPEN) {
                            existingClientId = clientId;
                            break;
                        }
                    }
                    
                    // Eski kaydı temizle
                    if (existingClientId) {
                        console.log(`🔄 Replacing old client: ${existingClientId}`);
                        clients.delete(existingClientId);
                    }
                    
                    const uniqueClientId = message.userType === 'admin' 
                        ? `${message.userId}_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`
                        : message.userId;
                    
                    // Yeni client kaydı
                    clients.set(uniqueClientId, {
                        ws: ws,
                        id: message.userId,
                        uniqueId: uniqueClientId,
                        name: message.name,
                        userType: message.userType || 'customer',
                        registeredAt: new Date().toLocaleTimeString(),
                        online: true
                    });

                    console.log(`👤 Registered: ${message.name} as ${uniqueClientId} (${message.userType})`);

                    if (message.userType === 'admin') {
                        // Admin'in aktif görüşme durumunu kontrol et
                        const adminInCall = Array.from(activeCallAdmins.entries()).find(([adminId, callInfo]) => {
                            return adminId.startsWith(message.userId + '_');
                        });
                        
                        if (adminInCall) {
                            console.log(`🔄 Admin ${uniqueClientId} reconnected during active call`);
                            // Eski admin ID'sini yeni ID ile değiştir
                            const [oldAdminId, callInfo] = adminInCall;
                            activeCallAdmins.delete(oldAdminId);
                            activeCallAdmins.set(uniqueClientId, callInfo);
                            
                            // Heartbeat'i güncelle
                            const oldCallKey = `${callInfo.customerId}-${oldAdminId}`;
                            const newCallKey = `${callInfo.customerId}-${uniqueClientId}`;
                            
                            if (activeHeartbeats.has(oldCallKey)) {
                                const heartbeat = activeHeartbeats.get(oldCallKey);
                                activeHeartbeats.delete(oldCallKey);
                                activeHeartbeats.set(newCallKey, heartbeat);
                                console.log(`💓 Heartbeat transferred: ${oldCallKey} → ${newCallKey}`);
                            }
                        }
                        
                        ws.send(JSON.stringify({
                            type: 'admin-registered',
                            uniqueId: uniqueClientId,
                            originalId: message.userId
                        }));
                        
                        // Sadece müsait adminlere queue gönder
                        setTimeout(() => {
                            broadcastCallQueueToAdmins();
                        }, 500);
                    }
                    
                    broadcastUserList();
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

                case 'call-request':
                    console.log(`📞 Call request from ${message.userName} (${message.userId})`);
                    const callEntry = addToCallQueue({
                        userId: message.userId,
                        userName: message.userName,
                        credits: message.credits
                    });
                    
                    broadcastCallQueueToAdmins();
                    break;

                case 'accept-call-by-id':
                    console.log(`✅ Admin ${senderId} accepting call ${message.callId}`);
                    const acceptedCall = acceptCallFromQueue(message.callId, senderId);
                    if (!acceptedCall) {
                        ws.send(JSON.stringify({
                            type: 'call-accept-error',
                            error: 'Arama bulunamadı'
                        }));
                        break;
                    }
                    
                    if (activeCallAdmins.has(senderId)) {
                        console.log(`⚠️ Admin ${senderId} already in a call, rejecting new call`);
                        ws.send(JSON.stringify({
                            type: 'call-accept-error',
                            error: 'Zaten bir aramada bulunuyorsunuz!'
                        }));
                        break;
                    }
                    
                    activeCallAdmins.set(senderId, {
                        customerId: acceptedCall.userId,
                        callStartTime: Date.now()
                    });
                    
                    const acceptedCustomer = clients.get(acceptedCall.userId);
                    if (acceptedCustomer && acceptedCustomer.ws.readyState === WebSocket.OPEN) {
                        acceptedCustomer.ws.send(JSON.stringify({
                            type: 'call-accepted',
                            acceptedAdminId: senderId,
                            callId: message.callId
                        }));
                    }
                    
                    const allAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin');
                    allAdmins.forEach(adminClient => {
                        if (adminClient.uniqueId !== senderId && adminClient.ws.readyState === WebSocket.OPEN) {
                            adminClient.ws.send(JSON.stringify({
                                type: 'call-taken',
                                userId: acceptedCall.userId,
                                userName: acceptedCall.userName,
                                callId: message.callId,
                                takenBy: senderId
                            }));
                        }
                    });
                    
                    const acceptCallKey = `${acceptedCall.userId}-${senderId}`;
                    startHeartbeat(acceptedCall.userId, senderId, acceptCallKey);
                    
                    console.log(`💓 Heartbeat started for ${acceptCallKey}`);
                    break;

                case 'reject-call-by-id':
                    console.log(`❌ Admin ${senderId} rejecting call ${message.callId}`);
                    const rejectedCall = removeFromCallQueue(message.callId, 'admin_rejected');
                    if (rejectedCall) {
                        const rejectedCustomer = clients.get(rejectedCall.userId);
                        if (rejectedCustomer && rejectedCustomer.ws.readyState === WebSocket.OPEN) {
                            rejectedCustomer.ws.send(JSON.stringify({
                                type: 'call-rejected',
                                reason: message.reason || 'Arama reddedildi',
                                callId: message.callId
                            }));
                        }
                    }
                    break;

                case 'call-cancelled':
                    console.log(`🔴 Call cancelled by user ${message.userId}`);
                    removeUserCallFromQueue(message.userId, 'user_cancelled');
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    const targetClient = findWebRTCTarget(message.targetId, senderType);
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
                    
                    if (senderType === 'admin') {
                        activeCallAdmins.delete(senderId);
                    } else if (message.targetId) {
                        activeCallAdmins.delete(message.targetId);
                    }
                    
                    const endCallKey = senderType === 'admin' 
                        ? `${message.targetId || 'unknown'}-${senderId}`
                        : `${senderId}-${message.targetId || 'ADMIN001'}`;
                    
                    stopHeartbeat(endCallKey, 'user_ended');
                    
                    const duration = message.duration || 0;
                    const creditsUsed = Math.ceil(duration / 60);
                    
                    try {
                        await pool.query(`
                            INSERT INTO call_history (user_id, user_name, admin_id, duration, credits_used, end_reason)
                            VALUES ($1, $2, $3, $4, $5, $6)
                        `, [
                            senderType === 'customer' ? senderId : message.targetId,
                            senderInfo?.name || 'Unknown',
                            senderType === 'admin' ? senderId : message.targetId,
                            duration,
                            creditsUsed,
                            'normal'
                        ]);
                    } catch (error) {
                        console.log('Call history save error:', error);
                    }
                    
                    if (message.targetId) {
                        const endTarget = findWebRTCTarget(message.targetId, senderType);
                        if (endTarget && endTarget.ws.readyState === WebSocket.OPEN) {
                            endTarget.ws.send(JSON.stringify({
                                type: 'call-ended',
                                userId: senderId,
                                duration: duration,
                                creditsUsed: creditsUsed,
                                endedBy: senderType || 'unknown'
                            }));
                        }
                    }
                    
                    if (senderType === 'admin') {
                        setTimeout(() => {
                            broadcastCallQueueToAdmins();
                        }, 1000);
                    }
                    break;
            }

        } catch (error) {
            console.log('Message processing error:', error.message);
        }
    });

    ws.on('close', () => {
        const client = findClientById(ws);
        console.log(`👋 Client disconnected: ${client?.name || 'Unknown'} (${client?.userType || 'unknown'})`);
        
        if (client && client.userType === 'customer') {
            removeUserCallFromQueue(client.id, 'user_disconnected');
        }
        
        if (client && client.userType === 'admin') {
            const adminKey = client.uniqueId || client.id;
            if (activeCallAdmins.has(adminKey)) {
                console.log(`🔴 Admin ${adminKey} disconnected during call`);
                
                const callInfo = activeCallAdmins.get(adminKey);
                if (callInfo) {
                    const callKey = `${callInfo.customerId}-${adminKey}`;
                    stopHeartbeat(callKey, 'admin_disconnected');
                }
                
                activeCallAdmins.delete(adminKey);
            }
        }
        
        if (client) {
            for (const [callKey, heartbeat] of activeHeartbeats.entries()) {
                if (callKey.includes(client.id)) {
                    stopHeartbeat(callKey, 'connection_lost');
                }
            }
        }
        
        for (const [key, clientData] of clients.entries()) {
            if (clientData.ws === ws) {
                clients.delete(key);
                break;
            }
        }
        
        broadcastUserList();
        
        if (client && client.userType === 'admin') {
            setTimeout(() => {
                broadcastCallQueueToAdmins();
            }, 500);
        }
    });

    ws.on('error', (error) => {
        console.log('WebSocket error:', error.message);
    });
});

// ================== HELPER FUNCTIONS ==================

function findClientById(ws) {
    for (const client of clients.values()) {
        if (client.ws === ws) {
            return client;
        }
    }
    return null;
}

function findWebRTCTarget(targetId, sourceType) {
    let targetClient = clients.get(targetId);
    if (targetClient) {
        return targetClient;
    }
    
    if (targetId.includes('_')) {
        const normalId = targetId.split('_')[0];
        for (const [clientId, clientData] of clients.entries()) {
            if (clientData.id === normalId && clientData.userType === 'admin') {
                return clientData;
            }
        }
    } else {
        for (const [clientId, clientData] of clients.entries()) {
            if (clientId.startsWith(targetId + '_') && clientData.userType === 'admin') {
                return clientData;
            }
        }
    }
    
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
        if (client.ws.readyState === WebSocket.OPEN) {
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
        console.log('📞 ÇOKLU ARAMA SİSTEMİ: Aktif + Call Tracking Güvenli');
        console.log(`   └── Maksimum kuyruk boyutu: ${MAX_QUEUE_SIZE}`);
        console.log(`   └── Arama timeout süresi: ${CALL_TIMEOUT_DURATION/1000} saniye`);
        console.log(`   └── Heartbeat interval: ${HEARTBEAT_INTERVAL/1000} saniye`);
        console.log('');
        console.log('🛡️ GÜVENLİK ÖZELLİKLERİ:');
        console.log('   ✅ Call tracking güvenli');
        console.log('   ✅ Admin disconnect koruması');
        console.log('   ✅ Duplicate heartbeat koruması');
        console.log('   ✅ Super Admin API endpoints');
        console.log('   ⚠️ 2FA hazırlık tamamlandı');
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('✅ Sistem hazır - Tüm sorunlar düzeltildi!');
    });
}

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
        console.log(`💔 Stopping heartbeat: ${callKey}`);
    }
    activeHeartbeats.clear();
    activeCallAdmins.clear();
    activeCalls.clear();
    
    clearAllCallQueue('server_shutdown');
    
    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});

// Start server
startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
