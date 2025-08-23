// ============================================================================
// 🚀 VIPCEP SERVER - FAST DEVELOPMENT STRUCTURE
// ============================================================================
// Tek dosya, mantıksal bölümler - hızlı geliştirme için optimize edilmiş
// ============================================================================

const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');

// ============================================================================
// 🔧 CONFIGURATION & SETUP
// ============================================================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

const CONFIG = {
    // Security paths (randomly generated)
    SUPER_ADMIN_PATH: '/panel-' + crypto.randomBytes(8).toString('hex'),
    NORMAL_ADMIN_PATH: '/desk-' + crypto.randomBytes(8).toString('hex'),
    CUSTOMER_PATH: '/app-' + crypto.randomBytes(8).toString('hex'),
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    
    // Call system config
    MAX_QUEUE_SIZE: 5,
    CALL_TIMEOUT: 30000,
    HEARTBEAT_INTERVAL: 60000,
    
    // Security config
    TOTP_ISSUER: 'VIPCEP System',
    TOTP_WINDOW: 2,
    MAX_LOGIN_ATTEMPTS: 5,
    RATE_LIMIT_WINDOW: 30 * 60 * 1000 // 30 minutes
};

// ============================================================================
// 📊 GLOBAL STATE MANAGEMENT
// ============================================================================
const STATE = {
    // Client management
    clients: new Map(),
    
    // Call management
    callQueue: new Map(),
    callTimeouts: new Map(),
    activeHeartbeats: new Map(),
    activeCallAdmins: new Map(),
    
    // System stats
    stats: {
        totalConnections: 0,
        activeConnections: 0,
        totalCalls: 0,
        systemStartTime: Date.now()
    }
};

// ============================================================================
// 🛡️ SECURITY UTILITIES
// ============================================================================
const Security = {
    generateTOTPSecret() {
        return crypto.randomBytes(16).toString('hex').toUpperCase();
    },
    
    verifyTOTP(secret, token) {
        if (!secret || !token || token.length !== 6) return false;
        
        try {
            const secretBuffer = Buffer.from(secret, 'hex');
            const timeStep = 30;
            const currentTime = Math.floor(Date.now() / 1000 / timeStep);
            
            for (let i = -CONFIG.TOTP_WINDOW; i <= CONFIG.TOTP_WINDOW; i++) {
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
                if (otp === token) return true;
            }
            return false;
        } catch (error) {
            return false;
        }
    },
    
    async checkRateLimit(ip, userType = 'customer') {
        try {
            const windowStart = new Date(Date.now() - CONFIG.RATE_LIMIT_WINDOW);
            const result = await pool.query(
                'SELECT COUNT(*) FROM failed_logins WHERE ip_address = $1 AND user_type = $2 AND attempt_time > $3',
                [ip, userType, windowStart]
            );
            
            const attempts = parseInt(result.rows[0].count);
            return {
                allowed: attempts < CONFIG.MAX_LOGIN_ATTEMPTS,
                attempts,
                remaining: Math.max(0, CONFIG.MAX_LOGIN_ATTEMPTS - attempts)
            };
        } catch (error) {
            return { allowed: true, attempts: 0, remaining: CONFIG.MAX_LOGIN_ATTEMPTS };
        }
    },
    
    async recordFailedLogin(ip, userType = 'customer') {
        try {
            await pool.query(
                'INSERT INTO failed_logins (ip_address, user_type) VALUES ($1, $2)',
                [ip, userType]
            );
        } catch (error) {
            console.log('Failed to record failed login:', error.message);
        }
    }
};

// ============================================================================
// 🗄️ DATABASE OPERATIONS
// ============================================================================
const DB = {
    async init() {
        try {
            // Tables creation
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
                CREATE TABLE IF NOT EXISTS failed_logins (
                    id SERIAL PRIMARY KEY,
                    ip_address INET NOT NULL,
                    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_type VARCHAR(20) DEFAULT 'customer'
                )
            `);

            // Create default data
            await this.createDefaultData();
            
        } catch (error) {
            console.log('Database init error:', error.message);
        }
    },
    
    async createDefaultData() {
        // Super admin
        const superAdminCheck = await pool.query('SELECT * FROM admins WHERE role = $1', ['super']);
        if (superAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
            const totpSecret = Security.generateTOTPSecret();
            await pool.query(`
                INSERT INTO admins (username, password_hash, role, totp_secret) 
                VALUES ($1, $2, $3, $4)
            `, ['superadmin', hashedPassword, 'super', totpSecret]);
        }

        // Normal admin
        const normalAdminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin1']);
        if (normalAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('password123').digest('hex');
            await pool.query(`
                INSERT INTO admins (username, password_hash, role) 
                VALUES ($1, $2, $3)
            `, ['admin1', hashedPassword, 'normal']);
        }

        // Test users
        const testUsers = [
            ['1234', 'Test Kullanıcı', 10],
            ['0005', 'VIP Müşteri', 25],
            ['0007', 'Cenk Zortu', 999],
            ['9999', 'Demo User', 5]
        ];

        for (const [id, name, credits] of testUsers) {
            const existing = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
            if (existing.rows.length === 0) {
                await pool.query(`
                    INSERT INTO approved_users (id, name, credits) 
                    VALUES ($1, $2, $3)
                `, [id, name, credits]);
            }
        }
    },
    
    async authenticateAdmin(username, password) {
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
    },
    
    async isUserApproved(userId, userName) {
        try {
            const result = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
            
            if (result.rows.length > 0) {
                const user = result.rows[0];
                
                if (user.name.toLowerCase().trim() === userName.toLowerCase().trim()) {
                    return {
                        approved: true,
                        credits: user.credits,
                        totalCalls: user.total_calls || 0,
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
};

// ============================================================================
// 📞 CALL MANAGEMENT SYSTEM
// ============================================================================
const CallManager = {
    generateCallId() {
        return `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    },
    
    addToQueue(callData) {
        // Remove oldest if queue is full
        if (STATE.callQueue.size >= CONFIG.MAX_QUEUE_SIZE) {
            let oldestCall = null;
            let oldestTime = Date.now();
            
            for (const [callId, call] of STATE.callQueue.entries()) {
                if (call.timestamp < oldestTime) {
                    oldestTime = call.timestamp;
                    oldestCall = callId;
                }
            }
            
            if (oldestCall) {
                this.removeFromQueue(oldestCall, 'queue_full');
            }
        }
        
        const callId = this.generateCallId();
        const callEntry = {
            callId,
            userId: callData.userId,
            userName: callData.userName,
            credits: callData.credits,
            timestamp: Date.now(),
            status: 'waiting'
        };
        
        STATE.callQueue.set(callId, callEntry);
        
        // Set timeout
        const timeoutId = setTimeout(() => {
            this.removeFromQueue(callId, 'timeout');
        }, CONFIG.CALL_TIMEOUT);
        
        STATE.callTimeouts.set(callId, timeoutId);
        this.broadcastQueueToAdmins();
        
        return callEntry;
    },
    
    removeFromQueue(callId, reason = 'manual') {
        const callData = STATE.callQueue.get(callId);
        if (!callData) return null;
        
        // Clear timeout
        const timeoutId = STATE.callTimeouts.get(callId);
        if (timeoutId) {
            clearTimeout(timeoutId);
            STATE.callTimeouts.delete(callId);
        }
        
        STATE.callQueue.delete(callId);
        this.broadcastQueueToAdmins();
        
        return callData;
    },
    
    acceptCall(callId, adminId) {
        const callData = STATE.callQueue.get(callId);
        if (!callData) return null;
        
        this.removeFromQueue(callId, 'accepted');
        
        // Track active admin
        STATE.activeCallAdmins.set(adminId, {
            customerId: callData.userId,
            callStartTime: Date.now()
        });
        
        return callData;
    },
    
    broadcastQueueToAdmins() {
        const queueArray = Array.from(STATE.callQueue.values()).sort((a, b) => a.timestamp - b.timestamp);
        
        const message = JSON.stringify({
            type: 'call-queue-update',
            queue: queueArray,
            queueSize: queueArray.length
        });
        
        // Send to available admins only
        Array.from(STATE.clients.values())
            .filter(client => 
                client.userType === 'admin' && 
                !STATE.activeCallAdmins.has(client.uniqueId || client.id)
            )
            .forEach(client => {
                if (client.ws.readyState === WebSocket.OPEN) {
                    client.ws.send(message);
                }
            });
    },
    
    startHeartbeat(userId, adminId, callKey) {
        const heartbeat = setInterval(async () => {
            try {
                const userResult = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
                if (userResult.rows.length > 0) {
                    const currentCredits = userResult.rows[0].credits;
                    
                    if (currentCredits <= 0) {
                        this.stopHeartbeat(callKey, 'no_credits');
                        return;
                    }
                    
                    const newCredits = Math.max(0, currentCredits - 1);
                    await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);
                    
                    await pool.query(`
                        INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                        VALUES ($1, $2, $3, $4, $5)
                    `, [userId, 'heartbeat', -1, newCredits, `Arama dakikası`]);
                    
                    this.broadcastCreditUpdate(userId, newCredits, 1);
                }
            } catch (error) {
                console.log(`Heartbeat error ${userId}:`, error.message);
            }
        }, CONFIG.HEARTBEAT_INTERVAL);
        
        STATE.activeHeartbeats.set(callKey, heartbeat);
    },
    
    stopHeartbeat(callKey, reason = 'normal') {
        const heartbeat = STATE.activeHeartbeats.get(callKey);
        if (heartbeat) {
            clearInterval(heartbeat);
            STATE.activeHeartbeats.delete(callKey);
            
            const [userId, adminId] = callKey.split('-');
            this.broadcastCallEnd(userId, adminId, reason);
        }
    },
    
    broadcastCreditUpdate(userId, newCredits, creditsUsed) {
        const customerClient = STATE.clients.get(userId);
        if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
            customerClient.ws.send(JSON.stringify({
                type: 'credit-update',
                credits: newCredits,
                creditsUsed: creditsUsed,
                source: 'heartbeat'
            }));
        }
        
        // Notify all admins
        Array.from(STATE.clients.values())
            .filter(client => client.userType === 'admin')
            .forEach(client => {
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
    },
    
    broadcastCallEnd(userId, adminId, reason) {
        const customerClient = STATE.clients.get(userId);
        if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
            customerClient.ws.send(JSON.stringify({
                type: 'call-ended',
                reason: reason,
                endedBy: 'system'
            }));
        }
        
        const adminClient = STATE.clients.get(adminId);
        if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
            adminClient.ws.send(JSON.stringify({
                type: 'call-ended',
                userId: userId,
                reason: reason,
                endedBy: 'system'
            }));
        }
    },
    
    cleanup() {
        // Clear all heartbeats
        for (const [callKey, heartbeat] of STATE.activeHeartbeats.entries()) {
            clearInterval(heartbeat);
        }
        
        // Clear all timeouts
        for (const timeoutId of STATE.callTimeouts.values()) {
            clearTimeout(timeoutId);
        }
        
        STATE.activeHeartbeats.clear();
        STATE.activeCallAdmins.clear();
        STATE.callTimeouts.clear();
        STATE.callQueue.clear();
    }
};

// ============================================================================
// 🔌 WEBSOCKET CLIENT MANAGEMENT
// ============================================================================
const ClientManager = {
    add(uniqueId, clientData) {
        STATE.clients.set(uniqueId, clientData);
        STATE.stats.totalConnections++;
        STATE.stats.activeConnections++;
    },
    
    remove(uniqueId) {
        const removed = STATE.clients.delete(uniqueId);
        if (removed) STATE.stats.activeConnections--;
        return removed;
    },
    
    get(id) {
        const client = STATE.clients.get(id);
        if (client) return client;
        
        // Search by id or uniqueId
        for (const [clientId, clientData] of STATE.clients.entries()) {
            if (clientData.id === id || clientData.uniqueId === id) {
                return clientData;
            }
        }
        return null;
    },
    
    findByWebSocket(ws) {
        for (const client of STATE.clients.values()) {
            if (client.ws === ws) return client;
        }
        return null;
    },
    
    findWebRTCTarget(targetId) {
        let targetClient = STATE.clients.get(targetId);
        if (targetClient) return targetClient;
        
        if (targetId.includes('_')) {
            const normalId = targetId.split('_')[0];
            for (const [clientId, clientData] of STATE.clients.entries()) {
                if (clientData.id === normalId && clientData.userType === 'admin') {
                    return clientData;
                }
            }
        } else {
            for (const [clientId, clientData] of STATE.clients.entries()) {
                if (clientId.startsWith(targetId + '_') && clientData.userType === 'admin') {
                    return clientData;
                }
            }
        }
        
        return null;
    },
    
    broadcast(message, filter = null) {
        const messageStr = JSON.stringify(message);
        Array.from(STATE.clients.values())
            .filter(client => filter ? filter(client) : true)
            .forEach(client => {
                if (client.ws.readyState === WebSocket.OPEN) {
                    client.ws.send(messageStr);
                }
            });
    },
    
    broadcastUserList() {
        const userList = Array.from(STATE.clients.values()).map(client => ({
            id: client.id,
            name: client.name,
            userType: client.userType,
            registeredAt: client.registeredAt,
            online: client.online
        }));

        this.broadcast({
            type: 'user-list-update',
            users: userList
        });
    }
};

// ============================================================================
// ⚡ EXPRESS MIDDLEWARE SETUP
// ============================================================================
app.use(session({
    secret: CONFIG.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// ============================================================================
// 🌐 WEB ROUTES
// ============================================================================

// Main page
app.get('/', (req, res) => {
    if (req.session.superAdmin) return res.redirect(CONFIG.SUPER_ADMIN_PATH);
    if (req.session.normalAdmin) return res.redirect(CONFIG.NORMAL_ADMIN_PATH);
    
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
                .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; font-size: 16px; margin-bottom: 10px; transition: all 0.3s ease; }
                .btn:hover { opacity: 0.9; transform: translateY(-1px); }
                .btn-customer { background: linear-gradient(135deg, #059669, #047857); }
                .title { text-align: center; margin-bottom: 30px; color: #dc2626; font-size: 24px; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="title">🔐 VIPCEP</div>
                <div class="form-group">
                    <input type="text" id="username" class="form-input" placeholder="👤 Kullanıcı Adı">
                </div>
                <div class="form-group">
                    <input type="password" id="password" class="form-input" placeholder="🔑 Şifre">
                </div>
                <button class="btn" onclick="adminLogin()">🔴 SUPER ADMİN GİRİŞİ</button>
                <button class="btn" onclick="normalAdminLogin()">🟡 ADMİN GİRİŞİ</button>
                <button class="btn btn-customer" onclick="window.location.href='${CONFIG.CUSTOMER_PATH}'">🟢 MÜŞTERİ UYGULAMASI</button>
            </div>
            <script>
                async function adminLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    if (!username || !password) return alert('Kullanıcı adı ve şifre gerekli!');
                    
                    try {
                        const response = await fetch('/auth/super-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password })
                        });
                        const result = await response.json();
                        if (result.success) {
                            window.location.href = '${CONFIG.SUPER_ADMIN_PATH}';
                        } else {
                            alert(result.error || 'Giriş başarısız!');
                        }
                    } catch (error) {
                        alert('Bağlantı hatası!');
                    }
                }
                
                async function normalAdminLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    if (!username || !password) return alert('Kullanıcı adı ve şifre gerekli!');
                    
                    try {
                        const response = await fetch('/auth/admin-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password })
                        });
                        const result = await response.json();
                        if (result.success) {
                            window.location.href = '${CONFIG.NORMAL_ADMIN_PATH}';
                        } else {
                            alert(result.error || 'Giriş başarısız!');
                        }
                    } catch (error) {
                        alert('Bağlantı hatası!');
                    }
                }
            </script>
        </body>
        </html>
    `);
});

// Admin panels
app.get(CONFIG.SUPER_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'super-admin.html'));
});

app.get(CONFIG.NORMAL_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get(CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// ============================================================================
// 🔐 AUTH ENDPOINTS
// ============================================================================

app.post('/auth/super-login', async (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    try {
        const rateStatus = await Security.checkRateLimit(clientIP, 'super-admin');
        if (!rateStatus.allowed) {
            return res.json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }
        
        const admin = await DB.authenticateAdmin(username, password);
        if (admin && admin.role === 'super') {
            req.session.superAdmin = { id: admin.id, username: admin.username, loginTime: new Date() };
            res.json({ success: true, redirectUrl: CONFIG.SUPER_ADMIN_PATH });
        } else {
            await Security.recordFailedLogin(clientIP, 'super-admin');
            res.json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }
    } catch (error) {
        res.json({ success: false, error: 'Sistem hatası!' });
    }
});

app.post('/auth/admin-login', async (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    try {
        const rateStatus = await Security.checkRateLimit(clientIP, 'admin');
        if (!rateStatus.allowed) {
            return res.json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }
        
        const admin = await DB.authenticateAdmin(username, password);
        if (admin && admin.role === 'normal') {
            req.session.normalAdmin = { id: admin.id, username: admin.username, loginTime: new Date() };
            res.json({ success: true, redirectUrl: CONFIG.NORMAL_ADMIN_PATH });
        } else {
            await Security.recordFailedLogin(clientIP, 'admin');
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

// ============================================================================
// 📊 API ENDPOINTS
// ============================================================================

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
            onlineUsers: Array.from(STATE.clients.values()).filter(c => c.userType === 'customer').length,
            callQueueSize: STATE.callQueue.size,
            maxQueueSize: CONFIG.MAX_QUEUE_SIZE,
            systemStats: STATE.stats
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        clients: STATE.clients.size,
        callQueueSize: STATE.callQueue.size,
        maxQueueSize: CONFIG.MAX_QUEUE_SIZE,
        memoryUsage: process.memoryUsage(),
        systemStats: STATE.stats
    });
});

// ============================================================================
// 🔌 WEBSOCKET MESSAGE HANDLERS
// ============================================================================

const MessageHandlers = {
    async handleRegister(ws, message) {
        const uniqueClientId = message.userType === 'admin' 
            ? `${message.userId}_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`
            : message.userId;
        
        ClientManager.add(uniqueClientId, {
            ws: ws,
            id: message.userId,
            uniqueId: uniqueClientId,
            name: message.name,
            userType: message.userType || 'customer',
            registeredAt: new Date().toLocaleTimeString(),
            online: true
        });

        if (message.userType === 'admin') {
            ws.send(JSON.stringify({
                type: 'admin-registered',
                uniqueId: uniqueClientId,
                originalId: message.userId
            }));
            CallManager.broadcastQueueToAdmins();
        }
        
        ClientManager.broadcastUserList();
    },

    async handleLoginRequest(ws, message, clientIP) {
        const rateLimit = await Security.checkRateLimit(clientIP);
        if (!rateLimit.allowed) {
            ws.send(JSON.stringify({
                type: 'login-response',
                success: false,
                rateLimited: true,
                error: `Çok fazla başarısız deneme!`
            }));
            return;
        }

        const approval = await DB.isUserApproved(message.userId, message.userName);
        
        if (approval.approved) {
            ws.send(JSON.stringify({
                type: 'login-response',
                success: true,
                credits: approval.credits,
                user: approval.user
            }));
        } else {
            await Security.recordFailedLogin(clientIP);
            ws.send(JSON.stringify({
                type: 'login-response',
                success: false,
                reason: approval.reason
            }));
        }
    },

    handleCallRequest(message) {
        const callEntry = CallManager.addToQueue({
            userId: message.userId,
            userName: message.userName,
            credits: message.credits
        });
        
        CallManager.broadcastQueueToAdmins();
    },

    handleAcceptCall(ws, message, senderId) {
        const acceptedCall = CallManager.acceptCall(message.callId, senderId);
        if (!acceptedCall) {
            ws.send(JSON.stringify({
                type: 'call-accept-error',
                error: 'Arama bulunamadı'
            }));
            return;
        }
        
        const acceptedCustomer = ClientManager.get(acceptedCall.userId);
        if (acceptedCustomer && acceptedCustomer.ws.readyState === WebSocket.OPEN) {
            acceptedCustomer.ws.send(JSON.stringify({
                type: 'call-accepted',
                acceptedAdminId: senderId,
                callId: message.callId
            }));
        }
        
        // Notify other admins
        ClientManager.broadcast({
            type: 'call-taken',
            userId: acceptedCall.userId,
            callId: message.callId,
            takenBy: senderId
        }, client => client.userType === 'admin' && client.uniqueId !== senderId);
        
        const acceptCallKey = `${acceptedCall.userId}-${senderId}`;
        CallManager.startHeartbeat(acceptedCall.userId, senderId, acceptCallKey);
    },

    handleRejectCall(message) {
        const rejectedCall = CallManager.removeFromQueue(message.callId, 'admin_rejected');
        if (rejectedCall) {
            const rejectedCustomer = ClientManager.get(rejectedCall.userId);
            if (rejectedCustomer && rejectedCustomer.ws.readyState === WebSocket.OPEN) {
                rejectedCustomer.ws.send(JSON.stringify({
                    type: 'call-rejected',
                    reason: message.reason || 'Arama reddedildi',
                    callId: message.callId
                }));
            }
        }
    },

    handleWebRTCMessage(message, senderId, senderType) {
        const targetClient = ClientManager.findWebRTCTarget(message.targetId, senderType);
        if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
            const forwardMessage = {
                type: message.type,
                [message.type]: message[message.type],
                userId: senderId,
                targetId: message.targetId
            };
            
            if (message.type === 'ice-candidate') {
                forwardMessage.candidate = message.candidate;
            }
            
            targetClient.ws.send(JSON.stringify(forwardMessage));
        }
    },

    handleEndCall(message, senderId, senderType) {
        if (senderType === 'admin') {
            STATE.activeCallAdmins.delete(senderId);
        } else if (message.targetId) {
            STATE.activeCallAdmins.delete(message.targetId);
        }
        
        const endCallKey = message.targetId ? `${senderId}-${message.targetId}` : `${senderId}-ADMIN001`;
        CallManager.stopHeartbeat(endCallKey, 'user_ended');
        
        const duration = message.duration || 0;
        const creditsUsed = Math.ceil(duration / 60);
        
        if (message.targetId) {
            const endTarget = ClientManager.findWebRTCTarget(message.targetId, senderType);
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
                CallManager.broadcastQueueToAdmins();
            }, 1000);
        }
    }
};

// ============================================================================
// 🔌 WEBSOCKET SERVER SETUP
// ============================================================================

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            
            // Get sender info
            let senderInfo = ClientManager.findByWebSocket(ws);
            const senderId = senderInfo ? (senderInfo.uniqueId || senderInfo.id) : (message.userId || 'unknown');
            const senderType = senderInfo ? senderInfo.userType : 'unknown';

            // Route message to appropriate handler
            switch (message.type) {
                case 'register':
                    await MessageHandlers.handleRegister(ws, message);
                    break;

                case 'login-request':
                    await MessageHandlers.handleLoginRequest(ws, message, clientIP);
                    break;

                case 'call-request':
                    MessageHandlers.handleCallRequest(message);
                    break;

                case 'accept-call-by-id':
                    MessageHandlers.handleAcceptCall(ws, message, senderId);
                    break;

                case 'reject-call-by-id':
                    MessageHandlers.handleRejectCall(message);
                    break;

                case 'call-cancelled':
                    CallManager.removeFromQueue(message.userId, 'user_cancelled');
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    MessageHandlers.handleWebRTCMessage(message, senderId, senderType);
                    break;

                case 'end-call':
                    MessageHandlers.handleEndCall(message, senderId, senderType);
                    break;

                default:
                    console.log('Unknown message type:', message.type);
            }

        } catch (error) {
            console.log('Message processing error:', error.message);
        }
    });

    ws.on('close', () => {
        const client = ClientManager.findByWebSocket(ws);
        
        if (client && client.userType === 'customer') {
            // Remove user from call queue if exists
            for (const [callId, callData] of STATE.callQueue.entries()) {
                if (callData.userId === client.id) {
                    CallManager.removeFromQueue(callId, 'user_disconnected');
                    break;
                }
            }
        }
        
        if (client && client.userType === 'admin') {
            const adminKey = client.uniqueId || client.id;
            if (STATE.activeCallAdmins.has(adminKey)) {
                STATE.activeCallAdmins.delete(adminKey);
            }
        }
        
        // Clean up heartbeats
        if (client) {
            for (const [callKey, heartbeat] of STATE.activeHeartbeats.entries()) {
                if (callKey.includes(client.id)) {
                    CallManager.stopHeartbeat(callKey, 'connection_lost');
                }
            }
        }
        
        // Remove client
        for (const [key, clientData] of STATE.clients.entries()) {
            if (clientData.ws === ws) {
                ClientManager.remove(key);
                break;
            }
        }
        
        ClientManager.broadcastUserList();
        
        if (client && client.userType === 'admin') {
            setTimeout(() => {
                CallManager.broadcastQueueToAdmins();
            }, 500);
        }
    });

    ws.on('error', (error) => {
        console.log('WebSocket error:', error.message);
    });
});

// ============================================================================
// 🚫 404 HANDLER
// ============================================================================

app.use((req, res) => {
    res.status(404).send(`
        <div style="text-align: center; padding: 50px; font-family: system-ui;">
            <h1>🔐 404 - Sayfa Bulunamadı</h1>
            <p>Güvenlik nedeniyle bu sayfa mevcut değil.</p>
            <p><a href="/" style="color: #dc2626; text-decoration: none;">← Ana sayfaya dön</a></p>
        </div>
    `);
});

// ============================================================================
// 🚀 SERVER STARTUP & SHUTDOWN
// ============================================================================

async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');
    
    await DB.init();
    
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server Çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
        console.log(`🌍 URL: http://0.0.0.0:${PORT}`);
        console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('🔐 GÜVENLİK URL\'LERİ:');
        console.log(` 🔴 Super Admin: ${CONFIG.SUPER_ADMIN_PATH}`);
        console.log(` 🟡 Normal Admin: ${CONFIG.NORMAL_ADMIN_PATH}`);
        console.log(` 🟢 Customer App: ${CONFIG.CUSTOMER_PATH}`);
        console.log('');
        console.log('📞 ÇOKLU ARAMA SİSTEMİ: Aktif');
        console.log(`   └─ Maksimum kuyruk boyutu: ${CONFIG.MAX_QUEUE_SIZE}`);
        console.log(`   └─ Arama timeout süresi: ${CONFIG.CALL_TIMEOUT/1000} saniye`);
        console.log(`   └─ Heartbeat interval: ${CONFIG.HEARTBEAT_INTERVAL/1000} saniye`);
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('✅ Sistem hazır - Çoklu arama sistemi TAM çalışıyor!');
        console.log('⚡ Optimized for FAST DEVELOPMENT!');
    });
}

// Error handling
process.on('uncaughtException', (error) => {
    console.log('❌ Yakalanmamış hata:', error.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.log('❌ İşlenmemiş promise reddi:', reason);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔴 Server kapatılıyor...');
    
    CallManager.cleanup();
    STATE.clients.clear();
    
    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});

// Start the server
startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});

// ============================================================================
// 🎯 FAST DEVELOPMENT UTILITIES
// ============================================================================

// Development mode utilities
if (process.env.NODE_ENV === 'development') {
    // Hot reload helper - just restart process
    app.get('/dev/restart', (req, res) => {
        res.json({ message: 'Restarting server...' });
        setTimeout(() => process.exit(0), 1000);
    });
    
    // Debug info
    app.get('/dev/debug', (req, res) => {
        res.json({
            clients: Array.from(STATE.clients.entries()),
            callQueue: Array.from(STATE.callQueue.entries()),
            activeHeartbeats: Array.from(STATE.activeHeartbeats.keys()),
            activeCallAdmins: Array.from(STATE.activeCallAdmins.entries()),
            config: CONFIG,
            stats: STATE.stats
        });
    });
    
    console.log('🛠️ Development mode utilities enabled:');
    console.log('   GET /dev/debug - Debug info');
    console.log('   GET /dev/restart - Restart server');
}
