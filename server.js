const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');

const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

console.log('🔗 Database URL:', process.env.DATABASE_URL ? 'FOUND' : 'NOT FOUND');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const wss = new WebSocket.Server({ server });
const clients = new Map();
const ADMIN_IDS = ['ADMIN_CEM', 'ADMIN_CENK'];

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
                admin_id VARCHAR(10),
                admin_name VARCHAR(255),
                duration INTEGER DEFAULT 0,
                credits_used INTEGER DEFAULT 0,
                call_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_reason VARCHAR(50) DEFAULT 'normal'
            )
        `);

        const testUsers = [
            ['1234', 'Test Kullanıcı', 10],
            ['0005', 'VIP Müşteri', 25],
            ['0007', 'Cenk Zortu', 999],
            ['9999', 'Demo User', 5]
        ];

        for (const [id, name, credits] of testUsers) {
            const existing = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
            if (existing.rows.length === 0) {
                await pool.query('INSERT INTO approved_users (id, name, credits) VALUES ($1, $2, $3)', [id, name, credits]);
                console.log(`🆔 Test kullanıcısı eklendi: ${id} - ${name}`);
            }
        }
        console.log('✅ Database hazır');
    } catch (error) {
        console.log('❌ Database hata:', error.message);
    }
}

function findAvailableAdmin() {
    const admins = Array.from(clients.values()).filter(c => c.userType === 'admin' && ADMIN_IDS.includes(c.id));
    
    const availableAdmin = admins.find(admin => admin.callStatus === 'available');
    if (availableAdmin) {
        console.log(`🔍 Available admin bulundu: ${availableAdmin.name}`);
        return availableAdmin;
    }
    
    console.log('🔍 Hiçbir admin müsait değil');
    return null;
}

function updateAdminStatus(adminId, status, currentCall = null) {
    const admin = clients.get(adminId);
    if (admin) {
        admin.callStatus = status;
        admin.currentCall = currentCall;
        console.log(`👤 ${admin.name} status: ${status}`);
    }
}

async function isUserApproved(userId, userName) {
    try {
        const result = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            if (user.name.toLowerCase().trim() === userName.toLowerCase().trim()) {
                return { approved: true, credits: user.credits, user: user };
            } else {
                return { approved: false, reason: 'İsim uyuşmuyor' };
            }
        } else {
            return { approved: false, reason: 'ID bulunamadı' };
        }
    } catch (error) {
        return { approved: false, reason: 'Sistem hatası' };
    }
}

async function saveCallToDatabase(callData) {
    try {
        const { userId, adminId, adminName, duration, creditsUsed } = callData;
        
        const userResult = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) {
            return { success: false, error: 'Kullanıcı bulunamadı' };
        }
        
        const user = userResult.rows[0];
        const oldCredits = user.credits;
        const newCredits = Math.max(0, oldCredits - creditsUsed);
        
        await pool.query('BEGIN');
        
        await pool.query(`
            INSERT INTO call_history (user_id, admin_id, admin_name, duration, credits_used, call_time)
            VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
        `, [userId, adminId, adminName, duration, creditsUsed]);
        
        await pool.query('UPDATE approved_users SET credits = $1, total_calls = total_calls + 1, last_call = CURRENT_TIMESTAMP WHERE id = $2', [newCredits, userId]);
        
        await pool.query('COMMIT');
        
        console.log(`✅ Kredi düştü: ${userId} -> ${oldCredits} -> ${newCredits}`);
        return { success: true, newCredits, creditsUsed, oldCredits };
    } catch (error) {
        await pool.query('ROLLBACK');
        console.log('❌ Database save error:', error.message);
        return { success: false, error: error.message };
    }
}

function findClientAdminId(ws) {
    for (const [id, client] of clients.entries()) {
        if (client.ws === ws && client.userType === 'admin') {
            return id;
        }
    }
    return null;
}

function broadcastUserList() {
    const userList = Array.from(clients.values()).map(client => ({
        id: client.id,
        name: client.name,
        userType: client.userType,
        callStatus: client.callStatus || 'available',
        registeredAt: client.registeredAt,
        online: true
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

wss.on('connection', (ws, req) => {
    console.log('🔗 Yeni bağlantı');

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            console.log('📨', message.type, 'from:', message.userId || 'unknown');

            switch (message.type) {
                case 'register':
                    clients.set(message.userId, {
                        ws: ws,
                        id: message.userId,
                        name: message.name,
                        userType: message.userType || 'customer',
                        callStatus: message.userType === 'admin' ? 'available' : 'customer',
                        registeredAt: new Date().toLocaleTimeString(),
                        online: true
                    });
                    console.log(`✅ ${message.userType}: ${message.name} (${message.userId})`);
                    broadcastUserList();
                    break;

                case 'login-request':
                    const approval = await isUserApproved(message.userId, message.userName);
                    ws.send(JSON.stringify({
                        type: 'login-response',
                        success: approval.approved,
                        credits: approval.credits,
                        reason: approval.reason,
                        user: approval.user
                    }));
                    break;

                case 'call-request':
                    const availableAdmin = findAvailableAdmin();
                    if (availableAdmin && availableAdmin.ws.readyState === WebSocket.OPEN) {
                        updateAdminStatus(availableAdmin.id, 'busy', message.userId);
                        availableAdmin.ws.send(JSON.stringify({
                            type: 'incoming-call',
                            userId: message.userId,
                            userName: message.userName,
                            credits: message.credits
                        }));
                        console.log(`📞 Arama ${availableAdmin.name} admin'e yönlendirildi`);
                    } else {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Tüm ustalar meşgul. Lütfen bekleyin.'
                        }));
                    }
                    break;

                case 'admin-call-request':
                    updateAdminStatus(message.adminId, 'busy', message.targetId);
                    const customerClient = clients.get(message.targetId);
                    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
                        customerClient.ws.send(JSON.stringify({
                            type: 'admin-call-request',
                            adminId: message.adminId,
                            adminName: message.adminName
                        }));
                    } else {
                        const adminSender = clients.get(message.adminId);
                        if (adminSender) {
                            adminSender.ws.send(JSON.stringify({
                                type: 'admin-call-rejected',
                                userId: message.targetId,
                                reason: 'Müşteri çevrimiçi değil'
                            }));
                        }
                        updateAdminStatus(message.adminId, 'available', null);
                    }
                    break;

                case 'admin-call-accepted':
                    const acceptingAdmin = clients.get(message.adminId);
                    if (acceptingAdmin) {
                        acceptingAdmin.ws.send(JSON.stringify({
                            type: 'admin-call-accepted',
                            userId: message.userId
                        }));
                    }
                    break;

                case 'admin-call-rejected':
                    const rejectingAdmin = clients.get(message.adminId);
                    if (rejectingAdmin) {
                        rejectingAdmin.ws.send(JSON.stringify({
                            type: 'admin-call-rejected',
                            userId: message.userId,
                            reason: message.reason
                        }));
                        updateAdminStatus(message.adminId, 'available', null);
                    }
                    break;

                case 'accept-call':
                    const callerClient = clients.get(message.userId);
                    if (callerClient) {
                        callerClient.ws.send(JSON.stringify({
                            type: 'call-accepted'
                        }));
                    }
                    break;

                case 'reject-call':
                    const rejectingAdminId = findClientAdminId(ws);
                    if (rejectingAdminId) {
                        updateAdminStatus(rejectingAdminId, 'available', null);
                    }
                    const rejectedClient = clients.get(message.userId);
                    if (rejectedClient) {
                        rejectedClient.ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: message.reason || 'Arama reddedildi'
                        }));
                    }
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    const targetClient = clients.get(message.targetId);
                    if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
                        targetClient.ws.send(JSON.stringify(message));
                    }
                    break;

                case 'end-call':
                    const duration = message.duration || 0;
                    const creditsUsed = Math.ceil(duration / 60);
                    const endingAdminId = findClientAdminId(ws);
                    const endingAdmin = endingAdminId ? clients.get(endingAdminId) : null;
                    
                    if (endingAdminId) {
                        updateAdminStatus(endingAdminId, 'available', null);
                    }
                    
                    if (message.targetId) {
                        const endTarget = clients.get(message.targetId);
                        if (endTarget && endTarget.ws.readyState === WebSocket.OPEN) {
                            endTarget.ws.send(JSON.stringify({
                                type: 'call-ended',
                                userId: message.userId,
                                duration: duration,
                                creditsUsed: creditsUsed
                            }));
                        }
                    }
                    
                    if (duration > 0 && message.userId && !ADMIN_IDS.includes(message.userId)) {
                        const saveResult = await saveCallToDatabase({
                            userId: message.userId,
                            adminId: endingAdminId || 'ADMIN_UNKNOWN',
                            adminName: endingAdmin ? endingAdmin.name : 'Unknown',
                            duration: duration,
                            creditsUsed: creditsUsed
                        });
                        
                        if (saveResult.success) {
                            const allClients = Array.from(clients.values());
                            allClients.forEach(client => {
                                if (client.ws.readyState === WebSocket.OPEN) {
                                    if (client.userType === 'admin') {
                                        client.ws.send(JSON.stringify({
                                            type: 'auto-credit-update',
                                            userId: message.userId,
                                            creditsUsed: creditsUsed,
                                            newCredits: saveResult.newCredits,
                                            oldCredits: saveResult.oldCredits,
                                            duration: duration
                                        }));
                                    } else if (client.id === message.userId) {
                                        client.ws.send(JSON.stringify({
                                            type: 'credit-update',
                                            credits: saveResult.newCredits,
                                            creditsUsed: creditsUsed,
                                            duration: duration
                                        }));
                                    }
                                }
                            });
                        }
                    }
                    break;

                case 'credit-update-broadcast':
                    const updatedUserClient = clients.get(message.userId);
                    if (updatedUserClient && updatedUserClient.userType === 'customer') {
                        updatedUserClient.ws.send(JSON.stringify({
                            type: 'credit-update',
                            credits: message.newCredits,
                            updatedBy: message.updatedBy
                        }));
                    }
                    break;
            }
        } catch (error) {
            console.log('❌ Message error:', error.message);
        }
    });

    ws.on('close', () => {
        for (const [key, client] of clients.entries()) {
            if (client.ws === ws) {
                console.log('👋', client.name, 'ayrıldı');
                clients.delete(key);
                break;
            }
        }
        broadcastUserList();
    });
});

// API Routes
app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/approved-users', async (req, res) => {
    try {
        const { id, name, credits = 0 } = req.body;
        if (!id || !name || !/^\d{4}$/.test(id)) {
            return res.status(400).json({ error: 'Geçersiz veri' });
        }
        
        const result = await pool.query('INSERT INTO approved_users (id, name, credits) VALUES ($1, $2, $3) RETURNING *', [id, name, credits]);
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        if (error.message.includes('duplicate')) {
            res.status(400).json({ error: 'ID zaten kullanımda' });
        } else {
            res.status(500).json({ error: error.message });
        }
    }
});

app.delete('/api/approved-users/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM approved_users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/approved-users/:id/credits', async (req, res) => {
    try {
        const { credits } = req.body;
        await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [credits, req.params.id]);
        res.json({ success: true, credits: credits });
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
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => {
    const adminStats = Array.from(clients.values()).filter(c => c.userType === 'admin');
    res.json({ 
        status: 'OK',
        clients: clients.size,
        admins: adminStats.map(a => ({ id: a.id, name: a.name, status: a.callStatus }))
    });
});

app.get('/', (req, res) => {
    res.send(`
        <h1>🎯 VIPCEP Multi-Admin Server</h1>
        <p><a href="/admin-panel.html">Admin Panel</a> | <a href="/customer-app.html">Müşteri App</a></p>
        <p>Status: <strong>RUNNING</strong></p>
        <p>Clients: <strong>${clients.size}</strong></p>
    `);
});

app.get('/admin-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get('/customer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

async function startServer() {
    console.log('🚀 VIPCEP Multi-Admin Server başlatılıyor...');
    await initDatabase();
    
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
        console.log('👑 Multi-Admin: Cem & Cenk');
        console.log('✅ Smart Call Routing aktif!');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    });
}

startServer().catch(error => {
    console.log('❌ Server error:', error.message);
    process.exit(1);
});
