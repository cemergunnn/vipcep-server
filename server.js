const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');
const PGSimpleStore = require('connect-pg-simple')(session);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

const SECURITY_CONFIG = {
    SUPER_ADMIN_PATH: '/panel-' + crypto.randomBytes(8).toString('hex'),
    NORMAL_ADMIN_PATH: '/desk-' + crypto.randomBytes(8).toString('hex'),
    CUSTOMER_PATH: '/app-' + crypto.randomBytes(8).toString('hex'),
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    TOTP_ISSUER: 'VIPCEP System',
    TOTP_WINDOW: 2
};

app.use(session({
    store: new PGSimpleStore({
        pool: pool,
        tableName: 'session'
    }),
    secret: SECURITY_CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

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

// Helper Functions
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
    
    broadcastCallQueueToAdmins();
    broadcastQueuePosition(callData.userId);
    
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
    
    if (callData.userId) {
        broadcastQueuePosition(callData.userId);
    }
    
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
    
    availableAdmins.forEach(adminClient => {
        if (adminClient.ws.readyState === WebSocket.OPEN) {
            adminClient.ws.send(message);
        }
    });
}

function broadcastQueuePosition(userId) {
    const queueArray = Array.from(incomingCallQueue.values()).sort((a, b) => a.timestamp - b.timestamp);
    const position = queueArray.findIndex(call => call.userId === userId) + 1;
    
    const client = clients.get(userId);
    if (client && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(JSON.stringify({
            type: 'queue-position',
            position: position > 0 ? position : 0,
            queueSize: queueArray.length
        }));
    }
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

// Authentication Functions
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
        
        return await checkRateLimit(ip, userType);
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

// Database Functions
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
                admin_name VARCHAR(255),
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
    } catch (error) {
        console.log('Database initialization error:', error.message);
    }
}

// Super Admin Functions
async function addUser(userId, name, credits) {
    try {
        const existingUser = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        if (existingUser.rows.length > 0) {
            return { success: false, reason: 'User ID already exists' };
        }
        
        await pool.query(`
            INSERT INTO approved_users (id, name, credits)
            VALUES ($1, $2, $3)
        `, [userId, name, credits]);
        
        return { success: true };
    } catch (error) {
        return { success: false, reason: error.message };
    }
}

async function deleteUser(userId) {
    try {
        const result = await pool.query('DELETE FROM approved_users WHERE id = $1', [userId]);
        return { success: result.rowCount > 0, reason: result.rowCount > 0 ? '' : 'User not found' };
    } catch (error) {
        return { success: false, reason: error.message };
    }
}

async function updateUserCredits(userId, credits) {
    try {
        const result = await pool.query(`
            UPDATE approved_users 
            SET credits = $2 
            WHERE id = $1 
            RETURNING *
        `, [userId, credits]);
        
        if (result.rowCount === 0) {
            return { success: false, reason: 'User not found' };
        }
        
        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
            VALUES ($1, $2, $3, $4, $5)
        `, [userId, 'update', credits, credits, 'Super admin credit update']);
        
        return { success: true };
    } catch (error) {
        return { success: false, reason: error.message };
    }
}

async function getCallHistory() {
    try {
        const result = await pool.query(`
            SELECT ch.*, au.name as user_name, a.username as admin_name 
            FROM call_history ch
            LEFT JOIN approved_users au ON ch.user_id = au.id
            LEFT JOIN admins a ON ch.admin_id = a.id
            ORDER BY call_time DESC
        `);
        return { success: true, history: result.rows };
    } catch (error) {
        return { success: false, reason: error.message };
    }
}

// WebSocket Handling
wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress;
    
    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            const senderId = message.userId || message.uniqueId;
            const senderType = message.userType;
            
            switch (message.type) {
                case 'login':
                    const rateStatus = await checkRateLimit(clientIP, message.userType);
                    if (!rateStatus.allowed) {
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: `Rate limit exceeded. Try again after ${new Date(rateStatus.resetTime).toLocaleTimeString()}`,
                            attempts: rateStatus.attempts,
                            remaining: rateStatus.remaining
                        }));
                        return;
                    }
                    
                    if (message.userType === 'customer') {
                        const userResult = await pool.query('SELECT * FROM approved_users WHERE id = $1 AND status = $2', [message.userId, 'active']);
                        if (userResult.rows.length > 0) {
                            const clientData = {
                                id: message.userId,
                                name: userResult.rows[0].name,
                                userType: 'customer',
                                credits: userResult.rows[0].credits,
                                ws: ws,
                                registeredAt: Date.now(),
                                online: true
                            };
                            clients.set(message.userId, clientData);
                            
                            ws.send(JSON.stringify({
                                type: 'login-response',
                                success: true,
                                user: clientData
                            }));
                            broadcastUserList();
                            broadcastQueuePosition(message.userId);
                        } else {
                            await recordFailedLogin(clientIP);
                            ws.send(JSON.stringify({
                                type: 'login-response',
                                success: false,
                                reason: 'Invalid user ID'
                            }));
                        }
                    } else if (message.userType === 'admin') {
                        const adminResult = await pool.query('SELECT * FROM admins WHERE username = $1', [message.username]);
                        if (adminResult.rows.length > 0) {
                            const admin = adminResult.rows[0];
                            const hashedPassword = crypto.createHash('sha256').update(message.password).digest('hex');
                            
                            if (hashedPassword === admin.password_hash) {
                                if (admin.role === 'super' && !verifyTOTP(admin.totp_secret, message.totp)) {
                                    await recordFailedLogin(clientIP, 'admin');
                                    ws.send(JSON.stringify({
                                        type: 'login-response',
                                        success: false,
                                        reason: 'Invalid 2FA code'
                                    }));
                                    return;
                                }
                                
                                const uniqueId = `${admin.id}_${crypto.randomBytes(4).toString('hex')}`;
                                const clientData = {
                                    id: admin.id,
                                    uniqueId: uniqueId,
                                    username: admin.username,
                                    userType: 'admin',
                                    role: admin.role,
                                    ws: ws,
                                    registeredAt: Date.now(),
                                    online: true,
                                    status: activeCallAdmins.has(uniqueId) ? 'busy' : 'available'
                                };
                                clients.set(uniqueId, clientData);
                                
                                ws.send(JSON.stringify({
                                    type: 'login-response',
                                    success: true,
                                    user: clientData,
                                    totpQR: admin.role === 'super' && !admin.totp_secret ? generateTOTPQR(admin.username, generateTOTPSecret()) : null
                                }));
                                broadcastUserList();
                                if (admin.role === 'super') {
                                    const callHistory = await getCallHistory();
                                    ws.send(JSON.stringify({
                                        type: 'call-history',
                                        history: callHistory.history
                                    }));
                                }
                            } else {
                                await recordFailedLogin(clientIP, 'admin');
                                ws.send(JSON.stringify({
                                    type: 'login-response',
                                    success: false,
                                    reason: 'Invalid credentials'
                                }));
                            }
                        } else {
                            await recordFailedLogin(clientIP, 'admin');
                            ws.send(JSON.stringify({
                                type: 'login-response',
                                success: false,
                                reason: 'Invalid credentials'
                            }));
                        }
                    }
                    break;

                case 'add-user':
                    if (senderType === 'admin' && clients.get(senderId).role === 'super') {
                        const result = await addUser(message.userId, message.name, message.credits);
                        ws.send(JSON.stringify({
                            type: 'add-user-response',
                            success: result.success,
                            reason: result.reason
                        }));
                        if (result.success) {
                            broadcastUserList();
                        }
                    }
                    break;

                case 'delete-user':
                    if (senderType === 'admin' && clients.get(senderId).role === 'super') {
                        const result = await deleteUser(message.userId);
                        ws.send(JSON.stringify({
                            type: 'delete-user-response',
                            success: result.success,
                            reason: result.reason
                        }));
                        if (result.success) {
                            broadcastUserList();
                        }
                    }
                    break;

                case 'update-credits':
                    if (senderType === 'admin' && clients.get(senderId).role === 'super') {
                        const result = await updateUserCredits(message.userId, message.credits);
                        ws.send(JSON.stringify({
                            type: 'update-credits-response',
                            success: result.success,
                            reason: result.reason
                        }));
                        if (result.success) {
                            broadcastUserList();
                        }
                    }
                    break;

                case 'call-request':
                    const callEntry = addToCallQueue({
                        userId: message.userId,
                        userName: message.userName,
                        credits: message.credits
                    });
                    broadcastCallQueueToAdmins();
                    break;

                case 'accept-call-by-id':
                    const acceptedCall = acceptCallFromQueue(message.callId, senderId);
                    if (!acceptedCall) {
                        ws.send(JSON.stringify({
                            type: 'call-accept-error',
                            error: 'Arama bulunamadı'
                        }));
                        break;
                    }
                    
                    activeCallAdmins.set(senderId, {
                        customerId: acceptedCall.userId,
                        callStartTime: Date.now()
                    });
                    
                    const senderClient = clients.get(senderId);
                    if (senderClient) {
                        senderClient.status = 'busy';
                        broadcastUserList();
                    }
                    
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
                                callId: message.callId,
                                takenBy: senderId
                            }));
                        }
                    });
                    
                    const acceptCallKey = `${acceptedCall.userId}-${senderId}`;
                    startHeartbeat(acceptedCall.userId, senderId, acceptCallKey);
                    
                    // Record call in history
                    const adminClient = clients.get(senderId);
                    await pool.query(`
                        INSERT INTO call_history (user_id, user_name, admin_id, admin_name, call_time)
                        VALUES ($1, $2, $3, $4, $5)
                    `, [acceptedCall.userId, acceptedCall.userName, adminClient.id, adminClient.username, new Date()]);
                    break;

                case 'reject-call-by-id':
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
                    removeUserCallFromQueue(message.userId, 'user_cancelled');
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    const targetClient = findWebRTCTarget(message.targetId, senderType);
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
                    break;

                case 'end-call':
                    if (senderType === 'admin') {
                        activeCallAdmins.delete(senderId);
                        const senderClient = clients.get(senderId);
                        if (senderClient) {
                            senderClient.status = 'available';
                            broadcastUserList();
                        }
                    } else if (message.targetId) {
                        activeCallAdmins.delete(message.targetId);
                        const targetClient = clients.get(message.targetId);
                        if (targetClient) {
                            targetClient.status = 'available';
                            broadcastUserList();
                        }
                    }
                    
                    const endCallKey = message.targetId ? `${senderId}-${message.targetId}` : `${senderId}-ADMIN001`;
                    stopHeartbeat(endCallKey, 'user_ended');
                    
                    const duration = message.duration || 0;
                    const creditsUsed = Math.ceil(duration / 60);
                    
                    // Update call history
                    await pool.query(`
                        UPDATE call_history 
                        SET duration = $1, credits_used = $2, end_reason = $3
                        WHERE user_id = $4 AND admin_id = $5 AND call_time = (SELECT MAX(call_time) FROM call_history WHERE user_id = $4 AND admin_id = $5)
                    `, [duration, creditsUsed, 'normal', senderType === 'customer' ? senderId : message.targetId, senderType === 'admin' ? senderId : message.targetId]);
                    
                    if (creditsUsed > 0 && senderType === 'customer') {
                        await pool.query(`
                            UPDATE approved_users 
                            SET credits = credits - $1 
                            WHERE id = $2
                        `, [creditsUsed, senderId]);
                        await pool.query(`
                            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                            VALUES ($1, $2, $3, (SELECT credits FROM approved_users WHERE id = $1), $4)
                        `, [senderId, 'deduction', -creditsUsed, 'Call credit deduction']);
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
                    
                    // Send updated call history to super admins
                    const superAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin' && c.role === 'super');
                    const callHistory = await getCallHistory();
                    superAdmins.forEach(admin => {
                        if (admin.ws.readyState === WebSocket.OPEN) {
                            admin.ws.send(JSON.stringify({
                                type: 'call-history',
                                history: callHistory.history
                            }));
                        }
                    });
                    break;
            }
        } catch (error) {
            console.log('Message processing error:', error.message);
        }
    });

    ws.on('close', () => {
        const client = findClientById(ws);
        
        if (client && client.userType === 'customer') {
            removeUserCallFromQueue(client.id, 'user_disconnected');
        }
        
        if (client && client.userType === 'admin') {
            const adminKey = client.uniqueId || client.id;
            if (activeCallAdmins.has(adminKey)) {
                activeCallAdmins.delete(adminKey);
                client.status = 'available';
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

function startHeartbeat(userId, adminId, callKey) {
    const heartbeat = setInterval(() => {
        const userClient = clients.get(userId);
        const adminClient = clients.get(adminId);
        
        if (!userClient || !adminClient || 
            userClient.ws.readyState !== WebSocket.OPEN || 
            adminClient.ws.readyState !== WebSocket.OPEN) {
            stopHeartbeat(callKey, 'connection_lost');
            return;
        }
        
        userClient.ws.send(JSON.stringify({ type: 'heartbeat' }));
        adminClient.ws.send(JSON.stringify({ type: 'heartbeat' }));
    }, HEARTBEAT_INTERVAL);
    
    activeHeartbeats.set(callKey, heartbeat);
}

function stopHeartbeat(callKey, reason) {
    const heartbeat = activeHeartbeats.get(callKey);
    if (heartbeat) {
        clearInterval(heartbeat);
        activeHeartbeats.delete(callKey);
    }
    
    const [userId, adminId] = callKey.split('-');
    if (reason === 'connection_lost') {
        const userClient = clients.get(userId);
        const adminClient = clients.get(adminId);
        
        if (userClient && userClient.ws.readyState === WebSocket.OPEN) {
            userClient.ws.send(JSON.stringify({
                type: 'call-ended',
                reason: 'connection_lost'
            }));
        }
        
        if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
            adminClient.ws.send(JSON.stringify({
                type: 'call-ended',
                reason: 'connection_lost'
            }));
            adminClient.status = 'available';
            broadcastUserList();
        }
        
        activeCallAdmins.delete(adminId);
        broadcastCallQueueToAdmins();
        
        // Update call history for connection loss
        pool.query(`
            UPDATE call_history 
            SET end_reason = $1, connection_lost = $2
            WHERE user_id = $3 AND admin_id = $4 AND call_time = (SELECT MAX(call_time) FROM call_history WHERE user_id = $3 AND admin_id = $4)
        `, ['connection_lost', true, userId, adminId]);
    }
}

function broadcastUserList() {
    const userList = Array.from(clients.values()).map(client => ({
        id: client.id,
        name: client.name || client.username,
        userType: client.userType,
        registeredAt: client.registeredAt,
        online: client.online,
        status: client.status || 'available'
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

// 404 handler
app.use((req, res) => {
    res.status(404).send(`
        <div style="text-align: center; padding: 50px; font-family: system-ui;">
            <h1>🔐 404 - Sayfa Bulunamadı</h1>
            <p>Güvenlik nedeniyle bu sayfa mevcut değil.</p>
            <p><a href="/" style="color: #dc2626; text-decoration: none;">← Ana sayfaya dön</a></p>
        </div>
    `);
});

// Server start
async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');
    
    await initDatabase();
    
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server Çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
        console.log(`🌍 URL: http://0.0.0.0:${PORT}`);
        console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('🔐 GÜVENLİK URL\'LERİ:');
        console.log(` 🔴 Super Admin: ${SECURITY_CONFIG.SUPER_ADMIN_PATH}`);
        console.log(` 🟡 Normal Admin: ${SECURITY_CONFIG.NORMAL_ADMIN_PATH}`);
        console.log(` 🟢 Customer App: ${SECURITY_CONFIG.CUSTOMER_PATH}`);
        console.log('');
        console.log('📞 ÇOKLU ARAMA SİSTEMİ: Aktif');
        console.log(`   └─ Maksimum kuyruk boyutu: ${MAX_QUEUE_SIZE}`);
        console.log(`   └─ Arama timeout süresi: ${CALL_TIMEOUT_DURATION/1000} saniye`);
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('✅ Sistem hazır - Çoklu arama sistemi TAM çalışıyor!');
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
    
    for (const [callKey, heartbeat] of activeHeartbeats.entries()) {
        clearInterval(heartbeat);
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
