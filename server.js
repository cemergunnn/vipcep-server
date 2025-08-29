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
const adminCallbacks = new Map(); // adminId -> [{customerId, customerName, timestamp}]
const adminLocks = new Map(); // adminId -> { lockedBy, lockTime }
let currentAnnouncement = null;
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

function broadcastAdminListToCustomers() {
    const adminList = Array.from(clients.values())
        .filter(c => {
            return c.userType === 'admin' &&
                   c.ws &&
                   c.ws.readyState === WebSocket.OPEN &&
                   c.online !== false;
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

    const uniqueAdmins = [];
    const adminMap = new Map();

    adminList.forEach(admin => {
        const baseId = admin.id.split('_')[0];

        if (!adminMap.has(baseId) || admin.id > adminMap.get(baseId).id) {
            adminMap.set(baseId, admin);
        }
    });

    adminMap.forEach(admin => uniqueAdmins.push(admin));

    const message = JSON.stringify({
        type: 'admin-list-update',
        admins: uniqueAdmins
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

    console.log(`📡 Admin list sent to ${sentCount} customers: ${uniqueAdmins.length} unique admins`);
}

function broadcastCallbacksToAdmin(adminId) {
    const adminClient = Array.from(clients.values()).find(c =>
        c.userType === 'admin' &&
        (c.uniqueId === adminId || c.id === adminId) &&
        c.ws &&
        c.ws.readyState === WebSocket.OPEN
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

function broadcastToAdmins(message) {
    clients.forEach(client => {
        if (client.userType === 'admin' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify(message));
        }
    });
}

function sendToClient(clientId, message) {
    const client = clients.get(clientId);
    if (client && client.ws && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(JSON.stringify(message));
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
    } catch (error) {
        console.error('❌ Failed to record login attempt:', error.message);
    }
}

async function clearFailedLoginAttempts(ip) {
    try {
        await pool.query('DELETE FROM failed_logins WHERE ip_address = $1', [ip]);
    } catch (error) {
        console.error('❌ Failed to clear failed logins:', error.message);
    }
}

async function validateUser(username, password) {
    try {
        const userQuery = await pool.query('SELECT * FROM approved_users WHERE username = $1', [username]);
        const user = userQuery.rows[0];
        if (user && user.password === password) {
            return user;
        }
        return null;
    } catch (error) {
        console.error('❌ validateUser error:', error.message);
        return null;
    }
}

// ================== DATABASE FUNCTIONS ==================

async function getAdminEarning(username) {
    try {
        const result = await pool.query('SELECT total_earning FROM admins WHERE username = $1', [username]);
        if (result.rows.length > 0) {
            return result.rows[0].total_earning || 0;
        }
        return 0;
    } catch (error) {
        console.error('❌ Failed to get admin earning:', error.message);
        return 0;
    }
}

async function saveCallHistory(callData) {
    try {
        const query = `
            INSERT INTO call_history (
                call_id, customer_id, customer_name, customer_username,
                admin_id, admin_name, admin_username,
                start_time, end_time, duration_minutes,
                credit_deducted, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `;
        const values = [
            callData.callId,
            callData.customerId,
            callData.customerName,
            callData.customerUsername,
            callData.adminId,
            callData.adminName,
            callData.adminUsername,
            callData.startTime,
            callData.endTime,
            callData.duration,
            callData.creditDeducted,
            callData.status
        ];
        await pool.query(query, values);
        console.log(`✅ Call history saved for call ${callData.callId}`);
    } catch (error) {
        console.error('❌ Failed to save call history:', error.message);
    }
}

// ================== HEARTBEAT SYSTEM ==================

function startHeartbeat(callId, adminId, customerId) {
    if (activeHeartbeats.has(callId)) {
        console.warn(`⚠️ Heartbeat for call ${callId} is already running.`);
        return;
    }

    let lastBeatTime = Date.now();
    const interval = setInterval(() => {
        const now = Date.now();
        if (now - lastBeatTime > HEARTBEAT_INTERVAL * 2) {
            console.log(`💔 Call ${callId} heartbeat timeout. Ending call.`);
            endCall({ callId, reason: 'timeout' });
        }
    }, HEARTBEAT_INTERVAL);

    activeHeartbeats.set(callId, { interval, lastBeatTime, adminId, customerId });
    console.log(`❤️ Heartbeat started for call ${callId}`);
}

function stopHeartbeat(callId) {
    const heartbeatData = activeHeartbeats.get(callId);
    if (heartbeatData) {
        clearInterval(heartbeatData.interval);
        activeHeartbeats.delete(callId);
        console.log(`💔 Heartbeat stopped for call ${callId}`);
    } else {
        console.log(`⚠️ Attempted to stop non-existent heartbeat for call ${callId}`);
    }
}

function updateHeartbeat(callId) {
    const heartbeatData = activeHeartbeats.get(callId);
    if (heartbeatData) {
        heartbeatData.lastBeatTime = Date.now();
    }
}

// ================== CALL MANAGEMENT ==================

function endCall({ callId, reason }) {
    const callData = activeCalls.get(callId);
    if (!callData) {
        console.warn(`⚠️ Attempted to end a non-existent call: ${callId}`);
        return;
    }

    const { adminId, customerId, startTime, offerer } = callData;

    stopHeartbeat(callId);
    activeCalls.delete(callId);
    activeCallAdmins.delete(adminId);

    const endTime = new Date();
    const duration_minutes = Math.ceil((endTime.getTime() - startTime.getTime()) / 60000);
    let credit_deducted = 0;
    let final_status = 'ended';
    if (reason === 'admin-end' || reason === 'customer-end') {
        credit_deducted = duration_minutes;
    } else {
        final_status = reason;
        console.log(`📞 Call ${callId} ended due to reason: ${reason}. No credits deducted.`);
    }

    const customerClient = clients.get(customerId);
    if (customerClient) {
        if (credit_deducted > 0) {
            customerClient.credits -= credit_deducted;
        }
        sendToClient(customerId, {
            type: 'call-ended',
            reason: reason,
            duration: duration_minutes,
            creditDeducted: credit_deducted,
            remainingCredits: customerClient.credits
        });
        console.log(`✅ Müşteri ${customerClient.name}'den ${credit_deducted} kredi düşüldü. Kalan kredi: ${customerClient.credits}`);
    }
    const adminClient = clients.get(adminId);
    if (adminClient) {
        sendToClient(adminId, {
            type: 'call-ended',
            reason: reason,
            duration: duration_minutes,
            creditDeducted: credit_deducted
        });
    }

    // Call history
    saveCallHistory({
        callId: callData.callId,
        customerId: customerClient ? customerClient.id : 'N/A',
        customerName: customerClient ? customerClient.name : 'N/A',
        customerUsername: customerClient ? customerClient.username : 'N/A',
        adminId: adminClient ? adminClient.uniqueId : 'N/A',
        adminName: adminClient ? adminClient.name : 'N/A',
        adminUsername: adminClient ? adminClient.username : 'N/A',
        startTime: startTime,
        endTime: endTime,
        duration: duration_minutes,
        creditDeducted: credit_deducted,
        status: final_status
    });

    console.log(`📞 Call ${callId} ended.`);

    broadcastAdminListToCustomers();
}

// ================== ANNOUNCEMENT MANAGEMENT ==================

function broadcastAnnouncement(message) {
    currentAnnouncement = { message, timestamp: Date.now() };
    const announcementMessage = {
        type: 'announcement',
        message: message
    };
    broadcastToCustomers(announcementMessage);
}

function clearAnnouncement() {
    currentAnnouncement = null;
    const clearMessage = {
        type: 'announcement-clear'
    };
    broadcastToCustomers(clearMessage);
}

// ================== WEBSOCKET MESSAGE HANDLING ==================

wss.on('connection', ws => {
    console.log('🔗 Yeni WebSocket bağlantısı kuruldu');

    ws.on('message', async message => {
        const msg = JSON.parse(message);
        const clientId = ws.clientId;

        if (msg.type === 'register-user') {
            const { id, name, userType, credits, uniqueId, username } = msg;
            ws.clientId = id;
            ws.userType = userType;
            ws.uniqueId = uniqueId || id;
            ws.name = name;
            ws.credits = credits;
            ws.username = username;
            ws.online = true;
            clients.set(ws.clientId, { ws, id, name, userType, uniqueId, username, credits, online: true });
            console.log(`✅ ${userType} kullanıcı bağlandı: ${name} (${ws.clientId})`);

            if (userType === 'customer') {
                if (currentAnnouncement) {
                    sendToClient(ws.clientId, {
                        type: 'announcement',
                        message: currentAnnouncement.message
                    });
                }
                broadcastAdminListToCustomers();
            } else if (userType === 'admin') {
                broadcastAdminListToCustomers();
            }
        } else if (!clientId) {
            console.log('⚠️ Kayıt edilmemiş istemciden mesaj:', msg);
            ws.send(JSON.stringify({ type: 'error', message: 'Kullanıcı kaydı tamamlanmadı.' }));
            return;
        }

        const client = clients.get(clientId);

        switch (msg.type) {
            case 'request-call':
                const {
                    userId, userName, userCredits, adminId
                } = msg;
                const callId = generateCallId();
                const adminClient = clients.get(adminId);
                const customerClient = clients.get(userId);
                if (!adminClient || adminClient.userType !== 'admin') {
                    console.log(`❌ Admin ${adminId} bulunamadı veya admin değil.`);
                    sendToClient(userId, {
                        type: 'call-failed',
                        reason: 'admin-not-found'
                    });
                    break;
                }
                const adminKey = adminClient.uniqueId || adminClient.id;
                if (activeCallAdmins.has(adminKey)) {
                    console.log(`❌ Admin ${adminKey} zaten meşgul.`);
                    sendToClient(userId, {
                        type: 'call-failed',
                        reason: 'admin-busy'
                    });
                    break;
                }
                const hasLock = adminLocks.has(adminKey);
                if (hasLock) {
                    console.log(`❌ Admin ${adminKey} kilitli.`);
                    sendToClient(userId, {
                        type: 'call-failed',
                        reason: 'admin-locked'
                    });
                    break;
                }
                if (userCredits <= 0) {
                    console.log(`❌ Kullanıcı ${userName} kredisi yetersiz.`);
                    sendToClient(userId, {
                        type: 'call-failed',
                        reason: 'insufficient-credits'
                    });
                    break;
                }
                // Lock the admin immediately
                activeCallAdmins.set(adminKey, callId);
                console.log(`📞 Müşteri ${userName} (${userId}) - Admin ${adminClient.name} (${adminKey}) araması başlatılıyor. CallID: ${callId}`);
                // Notify admin of incoming call
                sendToClient(adminId, {
                    type: 'incoming-call',
                    callId,
                    userId,
                    userName,
                    userCredits,
                    offerer: 'customer'
                });
                // Update global call state
                activeCalls.set(callId, {
                    callId,
                    adminId: adminKey,
                    customerId: userId,
                    startTime: new Date(),
                    offerer: 'customer'
                });
                // Start heartbeat
                startHeartbeat(callId, adminKey, userId);
                broadcastAdminListToCustomers();
                break;
            case 'accept-call':
                {
                    const { callId } = msg;
                    const callData = activeCalls.get(callId);
                    if (!callData) {
                        console.warn(`⚠️ Admin tarafından kabul edilmeye çalışılan arama bulunamadı: ${callId}`);
                        break;
                    }
                    const { customerId } = callData;
                    // Notify customer that the call is accepted
                    sendToClient(customerId, {
                        type: 'call-accepted',
                        callId
                    });
                    console.log(`✅ Admin ${client.name} (${client.uniqueId}) aramayı kabul etti: ${callId}`);
                    // Ensure the heartbeat is updated upon acceptance
                    updateHeartbeat(callId);
                }
                break;
            case 'reject-call':
                {
                    const { callId } = msg;
                    const callData = activeCalls.get(callId);
                    if (!callData) {
                        console.warn(`⚠️ Admin tarafından reddedilmeye çalışılan arama bulunamadı: ${callId}`);
                        break;
                    }
                    const { customerId } = callData;
                    // Notify customer that the call is rejected
                    sendToClient(customerId, {
                        type: 'call-rejected',
                        reason: 'admin-busy',
                        callId
                    });
                    // End the call on the server side
                    endCall({ callId, reason: 'rejected' });
                    console.log(`❌ Admin ${client.name} (${client.uniqueId}) aramayı reddetti: ${callId}`);
                }
                break;
            case 'end-call':
                {
                    const { callId } = msg;
                    const callData = activeCalls.get(callId);
                    if (!callData) {
                        console.warn(`⚠️ Zaten bitirilmiş bir aramayı bitirme girişimi: ${callId}`);
                        break;
                    }
                    endCall({ callId, reason: `${client.userType}-end` });
                    console.log(`📞 Arama ${callId} ${client.userType} tarafından sonlandırıldı.`);
                }
                break;
            case 'ice-candidate':
                {
                    const { callId, candidate, to } = msg;
                    const destinationClient = clients.get(to);
                    if (destinationClient) {
                        sendToClient(to, {
                            type: 'ice-candidate',
                            candidate,
                            from: clientId,
                            callId
                        });
                    }
                }
                break;
            case 'session-description':
                {
                    const { callId, sdp, to } = msg;
                    const destinationClient = clients.get(to);
                    if (destinationClient) {
                        sendToClient(to, {
                            type: 'session-description',
                            sdp,
                            from: clientId,
                            callId
                        });
                    }
                }
                break;
            case 'heartbeat':
                {
                    const { callId } = msg;
                    updateHeartbeat(callId);
                }
                break;
            case 'admin-request-callback':
                {
                    const {
                        customerId, customerName, adminId
                    } = msg;
                    const callbacks = adminCallbacks.get(adminId) || [];
                    callbacks.push({ customerId, customerName, timestamp: new Date() });
                    adminCallbacks.set(adminId, callbacks);
                    console.log(`📋 Admin ${adminId} için geri arama talebi eklendi: ${customerName} (${customerId})`);
                    broadcastCallbacksToAdmin(adminId);
                }
                break;
            case 'admin-call-customer':
                {
                    const {
                        customerId, customerName
                    } = msg;
                    const callId = generateCallId();
                    const adminId = client.uniqueId || client.id;
                    const customerClient = clients.get(customerId);
                    if (!customerClient) {
                        console.log(`❌ Müşteri ${customerId} bulunamadı.`);
                        sendToClient(adminId, {
                            type: 'call-failed',
                            reason: 'customer-not-found'
                        });
                        break;
                    }
                    // Lock the admin for the new call
                    activeCallAdmins.set(adminId, callId);
                    console.log(`📞 Admin ${client.name} (${adminId}) - Müşteri ${customerName} (${customerId}) araması başlatılıyor. CallID: ${callId}`);
                    // Notify customer of incoming call
                    sendToClient(customerId, {
                        type: 'incoming-call',
                        callId,
                        userId: customerId,
                        userName: customerName,
                        offerer: 'admin'
                    });
                    // Update global call state
                    activeCalls.set(callId, {
                        callId,
                        adminId,
                        customerId,
                        startTime: new Date(),
                        offerer: 'admin'
                    });
                    startHeartbeat(callId, adminId, customerId);
                    broadcastAdminListToCustomers();
                }
                break;
            case 'admin-lock':
                {
                    const { adminId } = msg;
                    const lockTime = new Date();
                    adminLocks.set(adminId, {
                        lockedBy: adminId,
                        lockTime
                    });
                    const adminClient = clients.get(adminId);
                    if (adminClient) {
                        adminClient.online = false;
                    }
                    console.log(`🔒 Admin ${adminId} kilitlendi.`);
                    broadcastAdminListToCustomers();
                }
                break;
            case 'admin-unlock':
                {
                    const { adminId } = msg;
                    adminLocks.delete(adminId);
                    const adminClient = clients.get(adminId);
                    if (adminClient) {
                        adminClient.online = true;
                    }
                    console.log(`🔓 Admin ${adminId} kilidi açıldı.`);
                    broadcastAdminListToCustomers();
                }
                break;
            case 'update-online-status':
                {
                    const { adminId, isOnline } = msg;
                    const adminClient = clients.get(adminId);
                    if (adminClient) {
                        adminClient.online = isOnline;
                        console.log(`🟢 Admin ${adminId} durumu güncellendi: ${isOnline ? 'Online' : 'Offline'}`);
                        broadcastAdminListToCustomers();
                    } else {
                        console.log(`❌ Admin ${adminId} bulunamadı, durum güncellenemedi.`);
                    }
                }
                break;
            case 'post-announcement':
                {
                    const {
                        message
                    } = msg;
                    broadcastAnnouncement(message);
                    console.log(`📢 Yeni duyuru yayınlandı: ${message}`);
                }
                break;
            case 'delete-announcement':
                {
                    clearAnnouncement();
                    console.log('📢 Duyuru silindi.');
                }
                break;
            default:
                console.log(`❓ Bilinmeyen mesaj tipi: ${msg.type}`);
        }
    });

    ws.on('close', () => {
        const client = clients.get(ws.clientId);
        if (client) {
            console.log(`🔴 Bağlantı kesildi: ${client.name} (${client.id})`);
            clients.delete(ws.clientId);
            if (client.userType === 'admin') {
                activeCallAdmins.delete(client.uniqueId || client.id);
                adminLocks.delete(client.uniqueId || client.id);
                const callIdToTerminate = Array.from(activeCalls.values()).find(call => call.adminId === (client.uniqueId || client.id));
                if (callIdToTerminate) {
                    endCall({ callId: callIdToTerminate.callId, reason: 'admin-disconnect' });
                }
                broadcastAdminListToCustomers();
            } else if (client.userType === 'customer') {
                const callIdToTerminate = Array.from(activeCalls.values()).find(call => call.customerId === client.id);
                if (callIdToTerminate) {
                    endCall({ callId: callIdToTerminate.callId, reason: 'customer-disconnect' });
                }
            }
        }
    });

    ws.on('error', error => {
        console.error('❌ WebSocket hatası:', error.message);
    });
});

// ================== EXPRESS ROUTES (API) ==================

// Root route
app.get('/', (req, res) => {
    res.send('VIPCEP Server is running!');
});

// Admin Login
app.post('/api/admin-login', async (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip;
    const rateLimit = await checkRateLimit(ip, 'admin');

    if (!rateLimit.allowed) {
        return res.status(429).json({
            success: false,
            error: `Çok fazla deneme. Lütfen ${Math.ceil((rateLimit.resetTime - Date.now()) / 1000)} saniye sonra tekrar deneyin.`,
            remaining: rateLimit.remaining
        });
    }

    try {
        const user = await validateUser(username, password);

        if (!user) {
            await recordFailedLogin(ip, 'admin');
            return res.status(401).json({
                success: false,
                error: 'Geçersiz kullanıcı adı veya şifre.',
                remaining: rateLimit.remaining - 1
            });
        }
        await clearFailedLoginAttempts(ip);
        req.session.user = {
            id: user.user_id,
            username: user.username,
            name: user.name,
            role: user.role
        };
        req.session.save(err => {
            if (err) {
                console.error('❌ Session save error:', err);
            }
        });
        res.json({ success: true, user: { name: user.name, role: user.role } });
    } catch (error) {
        console.error('❌ Login error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Customer Login
app.post('/api/customer-login', async (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip;
    const rateLimit = await checkRateLimit(ip, 'customer');

    if (!rateLimit.allowed) {
        return res.status(429).json({
            success: false,
            error: `Çok fazla deneme. Lütfen ${Math.ceil((rateLimit.resetTime - Date.now()) / 1000)} saniye sonra tekrar deneyin.`,
            remaining: rateLimit.remaining
        });
    }

    try {
        const user = await validateUser(username, password);

        if (!user) {
            await recordFailedLogin(ip, 'customer');
            return res.status(401).json({
                success: false,
                error: 'Geçersiz kullanıcı adı veya şifre.',
                remaining: rateLimit.remaining - 1
            });
        }
        await clearFailedLoginAttempts(ip);
        req.session.user = {
            id: user.user_id,
            username: user.username,
            name: user.name,
            credits: user.credits,
            role: 'customer'
        };
        req.session.save(err => {
            if (err) {
                console.error('❌ Session save error:', err);
            }
        });
        res.json({
            success: true,
            user: {
                name: user.name,
                credits: user.credits
            }
        });
    } catch (error) {
        console.error('❌ Login error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Announcement
app.post('/api/announcement', (req, res) => {
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ success: false, error: 'Duyuru mesajı gerekli.' });
    }
    broadcastAnnouncement(message);
    res.json({ success: true, message: 'Duyuru başarıyla yayınlandı.' });
});

// Clear Announcement
app.delete('/api/announcement', (req, res) => {
    clearAnnouncement();
    res.json({ success: true, message: 'Duyuru başarıyla silindi.' });
});

// Get Admins
app.get('/api/admins', async (req, res) => {
    try {
        const result = await pool.query('SELECT user_id, name, username, role FROM admins WHERE role = $1 OR role = $2 ORDER BY username', ['admin', 'super-admin']);
        const admins = result.rows.map(admin => {
            const client = Array.from(clients.values()).find(c => c.username === admin.username);
            const isOnline = client ? client.online : false;
            const status = activeCallAdmins.has(admin.user_id) ? 'busy' : (isOnline ? 'available' : 'offline');
            return {
                id: admin.user_id,
                name: admin.name,
                username: admin.username,
                role: admin.role,
                status: status
            };
        });
        res.json({ success: true, admins });
    } catch (error) {
        console.error('❌ Admins fetching error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Get all users
app.get('/api/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT user_id, name, username, role, credits, created_at FROM approved_users ORDER BY created_at DESC');
        res.json({ success: true, users: result.rows });
    } catch (error) {
        console.error('❌ Users fetching error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Add a new user (super-admin only)
app.post('/api/users', async (req, res) => {
    const { name, username, password, role, credits } = req.body;
    if (!name || !username || !password || !role) {
        return res.status(400).json({ success: false, error: 'Eksik bilgi.' });
    }
    try {
        const checkUser = await pool.query('SELECT * FROM approved_users WHERE username = $1', [username]);
        if (checkUser.rows.length > 0) {
            return res.status(409).json({ success: false, error: 'Bu kullanıcı adı zaten mevcut.' });
        }
        await pool.query(
            'INSERT INTO approved_users (name, username, password, role, credits) VALUES ($1, $2, $3, $4, $5)', [name, username, password, role, credits || 0]
        );
        res.status(201).json({ success: true, message: 'Kullanıcı başarıyla eklendi.' });
    } catch (error) {
        console.error('❌ User addition error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Update a user (super-admin only)
app.put('/api/users/:userId', async (req, res) => {
    const { userId } = req.params;
    const { name, username, password, role, credits } = req.body;
    try {
        const checkUser = await pool.query('SELECT * FROM approved_users WHERE username = $1 AND user_id != $2', [username, userId]);
        if (checkUser.rows.length > 0) {
            return res.status(409).json({ success: false, error: 'Bu kullanıcı adı zaten mevcut.' });
        }
        await pool.query(
            'UPDATE approved_users SET name = $1, username = $2, password = $3, role = $4, credits = $5 WHERE user_id = $6', [name, username, password, role, credits, userId]
        );
        res.json({ success: true, message: 'Kullanıcı başarıyla güncellendi.' });
    } catch (error) {
        console.error('❌ User update error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Delete a user (super-admin only)
app.delete('/api/users/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
        await pool.query('DELETE FROM approved_users WHERE user_id = $1', [userId]);
        res.json({ success: true, message: 'Kullanıcı başarıyla silindi.' });
    } catch (error) {
        console.error('❌ User deletion error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Admin Earnings
app.get('/api/admin-earnings', async (req, res) => {
    try {
        const result = await pool.query('SELECT username, total_earning FROM admins ORDER BY total_earning DESC');
        res.json({ success: true, earnings: result.rows });
    } catch (error) {
        console.error('❌ Admin earnings fetching error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

app.post('/api/reset-admin-earnings/:username', async (req, res) => {
    const { username } = req.params;
    try {
        await pool.query('UPDATE admins SET total_earning = 0 WHERE username = $1', [username]);
        res.json({ success: true, message: 'Kazanç başarıyla sıfırlandı.' });
    } catch (error) {
        console.error('❌ Admin earnings reset error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Serve frontend files
app.get('/panel-admin', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'super-admin') {
        return res.status(403).send('Erişim Reddedildi');
    }
    res.sendFile(path.join(__dirname, 'super-admin.html'));
});

app.get('/desk-admin', (req, res) => {
    if (!req.session.user || (req.session.user.role !== 'admin' && req.session.user.role !== 'super-admin')) {
        return res.status(403).send('Erişim Reddedildi');
    }
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get('/app-customer', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'customer') {
        return res.status(403).send('Erişim Reddedildi');
    }
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

app.get('/widget', (req, res) => {
    res.sendFile(path.join(__dirname, 'widget.html'));
});

// ================== INITIALIZATION ==================

async function initDatabase() {
    try {
        console.log('🔧 Veritabanı kontrol ediliyor...');

        // approved_users tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS approved_users (
                user_id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                credits INTEGER DEFAULT 0,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ approved_users tablosu hazır.');

        // Admins view
        await pool.query(`
            CREATE OR REPLACE VIEW admins AS
            SELECT user_id, name, username, password, role, credits, created_at, 0 as total_earning
            FROM approved_users
            WHERE role IN ('admin', 'super-admin');
        `);
        console.log('✅ admins view hazır.');

        // call_history tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS call_history (
                call_id VARCHAR(255) PRIMARY KEY,
                customer_id VARCHAR(255),
                customer_name VARCHAR(255),
                customer_username VARCHAR(255),
                admin_id VARCHAR(255),
                admin_name VARCHAR(255),
                admin_username VARCHAR(255),
                start_time TIMESTAMP WITH TIME ZONE,
                end_time TIMESTAMP WITH TIME ZONE,
                duration_minutes INTEGER,
                credit_deducted INTEGER,
                status VARCHAR(50),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ call_history tablosu hazır.');

        // failed_logins tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(255) NOT NULL,
                user_type VARCHAR(50) NOT NULL,
                attempt_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ failed_logins tablosu hazır.');

        console.log('🎉 Veritabanı başlatma başarılı!');
    } catch (error) {
        console.error('❌ Veritabanı başlatma hatası:', error.message);
        process.exit(1);
    }
}
// Ana sunucuyu başlatma
function startServer() {
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
}

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
