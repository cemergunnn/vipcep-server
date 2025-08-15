const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

// PostgreSQL bağlantısı
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Express app
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// WebSocket server
const wss = new WebSocket.Server({ server });

// Global değişkenler
const clients = new Map();
const callQueue = [];
const ADMINS = {
    'ADMIN001': { name: 'Cem Usta', status: 'idle', currentCall: null },
    'ADMIN002': { name: 'Cenk Usta', status: 'idle', currentCall: null }
};

// Veritabanı başlatma
async function initDatabase() {
    try {
        // Approved users tablosu
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

        // Call history tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS call_history (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(10),
                admin_id VARCHAR(10),
                duration INTEGER DEFAULT 0,
                credits_used INTEGER DEFAULT 0,
                call_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_reason VARCHAR(50) DEFAULT 'normal'
            )
        `);

        // Call queue tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS call_queue (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(10) NOT NULL,
                user_name VARCHAR(255) NOT NULL,
                queue_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                call_attempts INTEGER DEFAULT 0,
                last_call_attempt TIMESTAMP,
                queue_position INTEGER,
                status VARCHAR(20) DEFAULT 'waiting',
                preferred_admin VARCHAR(10)
            )
        `);

        // Credit transactions tablosu
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

        console.log('✅ PostgreSQL tabloları hazır');
        
        // Test kullanıcıları
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
        console.log('⚠️ PostgreSQL bağlantı hatası:', error.message);
    }
}

// Müsait admin bulma
function findAvailableAdmin() {
    return Object.keys(ADMINS).find(adminId => 
        ADMINS[adminId].status === 'idle' && 
        clients.get(adminId)?.ws.readyState === WebSocket.OPEN
    );
}

// Kuyruğa ekleme
async function addToQueue(userId, userName) {
    try {
        await pool.query(`
            INSERT INTO call_queue (user_id, user_name, queue_position)
            VALUES ($1, $2, (SELECT COALESCE(MAX(queue_position), 0) + 1 FROM call_queue WHERE status = 'waiting'))
        `, [userId, userName]);
        
        const position = callQueue.push({ userId, userName, attempts: 0, time: Date.now() });
        
        const client = clients.get(userId);
        if (client) {
            client.ws.send(JSON.stringify({
                type: 'queue-added',
                position: position,
                message: `Görüşme için ${position}. sıradasınız`
            }));
        }
        
        broadcastQueueUpdate();
        return position;
    } catch (error) {
        console.log('Kuyruk ekleme hatası:', error);
        return -1;
    }
}

// Kuyruktan çıkarma
async function removeFromQueue(userId) {
    try {
        await pool.query(`
            UPDATE call_queue SET status = 'removed' 
            WHERE user_id = $1 AND status = 'waiting'
        `, [userId]);
        
        const index = callQueue.findIndex(item => item.userId === userId);
        if (index > -1) {
            callQueue.splice(index, 1);
        }
        
        broadcastQueueUpdate();
    } catch (error) {
        console.log('Kuyruk çıkarma hatası:', error);
    }
}

// Kuyruk güncelleme broadcast
function broadcastQueueUpdate() {
    const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
    adminClients.forEach(admin => {
        if (admin.ws.readyState === WebSocket.OPEN) {
            admin.ws.send(JSON.stringify({
                type: 'queue-update',
                queue: callQueue.map((item, index) => ({
                    ...item,
                    position: index + 1
                }))
            }));
        }
    });
    
    // Müşterilere sıra güncellemesi
    callQueue.forEach((item, index) => {
        const client = clients.get(item.userId);
        if (client && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
                type: 'queue-position-update',
                position: index + 1,
                totalInQueue: callQueue.length
            }));
        }
    });
}

// Kullanıcı onaylı mı kontrol
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
                return { 
                    approved: false, 
                    reason: 'İsim uyuşmuyor. Lütfen kayıtlı isminizi tam olarak girin.' 
                };
            }
        } else {
            return { 
                approved: false, 
                reason: 'ID kodu bulunamadı. Kredi talep etmek için WhatsApp ile iletişime geçin.' 
            };
        }
    } catch (error) {
        console.log('Kullanıcı kontrol hatası:', error.message);
        return { approved: false, reason: 'Sistem hatası. Lütfen tekrar deneyin.' };
    }
}

// Kredi düşme ve arama kaydetme - KRİTİK FONKSİYON
async function saveCallAndDeductCredits(userId, adminId, duration, endReason = 'normal') {
    let client = null;
    try {
        const creditsUsed = Math.ceil(duration / 60);
        
        if (!userId || userId === 'ADMIN001' || userId === 'ADMIN002') {
            return { success: false, error: 'Admin kredisi düşürülmez' };
        }
        
        client = await pool.connect();
        await client.query('BEGIN');
        
        // Kullanıcının mevcut kredisini al (FOR UPDATE ile kilitle)
        const userResult = await client.query(
            'SELECT * FROM approved_users WHERE id = $1 FOR UPDATE',
            [userId]
        );
        
        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return { success: false, error: 'Kullanıcı bulunamadı' };
        }
        
        const user = userResult.rows[0];
        const oldCredits = user.credits;
        const newCredits = Math.max(0, oldCredits - creditsUsed);
        
        console.log(`💰 Kredi düşme: ${userId} - Eski: ${oldCredits}, Kullanılan: ${creditsUsed}, Yeni: ${newCredits}`);
        
        // Krediyi güncelle
        await client.query(
            'UPDATE approved_users SET credits = $1, total_calls = total_calls + 1, last_call = CURRENT_TIMESTAMP WHERE id = $2',
            [newCredits, userId]
        );
        
        // Arama kaydını ekle
        await client.query(
            'INSERT INTO call_history (user_id, admin_id, duration, credits_used, end_reason) VALUES ($1, $2, $3, $4, $5)',
            [userId, adminId, duration, creditsUsed, endReason]
        );
        
        // Kredi transaction kaydı
        await client.query(
            'INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description) VALUES ($1, $2, $3, $4, $5)',
            [userId, 'call', -creditsUsed, newCredits, `Görüşme: ${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}`]
        );
        
        await client.query('COMMIT');
        
        // Frontend'lere bildirim gönder
        broadcastCreditUpdate(userId, oldCredits, newCredits, creditsUsed, duration);
        
        return { success: true, oldCredits, newCredits, creditsUsed };
        
    } catch (error) {
        if (client) await client.query('ROLLBACK');
        console.error('Kredi düşme hatası:', error);
        return { success: false, error: error.message };
    } finally {
        if (client) client.release();
    }
}

// Kredi güncelleme broadcast
function broadcastCreditUpdate(userId, oldCredits, newCredits, creditsUsed, duration) {
    // Tüm adminlere bildir
    const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
    adminClients.forEach(admin => {
        if (admin.ws.readyState === WebSocket.OPEN) {
            admin.ws.send(JSON.stringify({
                type: 'credit-updated',
                userId: userId,
                oldCredits: oldCredits,
                newCredits: newCredits,
                creditsUsed: creditsUsed,
                duration: duration
            }));
        }
    });
    
    // İlgili müşteriye bildir
    const customer = clients.get(userId);
    if (customer && customer.ws.readyState === WebSocket.OPEN) {
        customer.ws.send(JSON.stringify({
            type: 'credit-update',
            credits: newCredits,
            creditsUsed: creditsUsed,
            duration: duration
        }));
    }
}

// WebSocket bağlantı işleyicisi
wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';
    console.log('🔗 Yeni bağlantı:', clientIP);

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            console.log('📨 Mesaj:', message.type, 'from:', message.userId || 'unknown');

            switch (message.type) {
                case 'register':
                    const isAdmin = message.userType === 'admin' && (message.userId === 'ADMIN001' || message.userId === 'ADMIN002');
                    
                    clients.set(message.userId, {
                        ws: ws,
                        id: message.userId,
                        name: isAdmin ? ADMINS[message.userId].name : message.name,
                        userType: message.userType || 'customer',
                        registeredAt: new Date().toLocaleTimeString(),
                        online: true
                    });
                    
                    if (isAdmin) {
                        ADMINS[message.userId].status = 'idle';
                        broadcastQueueUpdate();
                    }
                    
                    console.log(`✅ ${message.userType} kayıt: ${message.name} (${message.userId})`);
                    broadcastUserList();
                    break;

                case 'login-request':
                    const approval = await isUserApproved(message.userId, message.userName);
                    
                    if (approval.approved) {
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: true,
                            credits: approval.credits,
                            user: approval.user
                        }));
                    } else {
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: approval.reason
                        }));
                    }
                    break;

                case 'call-request':
                    const availableAdmin = findAvailableAdmin();
                    
                    if (availableAdmin) {
                        ADMINS[availableAdmin].status = 'busy';
                        ADMINS[availableAdmin].currentCall = message.userId;
                        
                        const adminClient = clients.get(availableAdmin);
                        if (adminClient) {
                            adminClient.ws.send(JSON.stringify({
                                type: 'incoming-call',
                                userId: message.userId,
                                userName: message.userName,
                                credits: message.credits
                            }));
                        }
                    } else {
                        // Tüm adminler meşgul, kuyruğa al
                        const position = await addToQueue(message.userId, message.userName);
                        ws.send(JSON.stringify({
                            type: 'all-admins-busy',
                            message: 'Tüm uzmanlarımız meşgul. Çağrınız kaydedildi.',
                            queuePosition: position
                        }));
                    }
                    break;

                case 'admin-call-from-queue':
                    const queueItem = callQueue.find(item => item.userId === message.targetId);
                    if (queueItem) {
                        queueItem.attempts++;
                        queueItem.lastAttempt = Date.now();
                        
                        const customerClient = clients.get(message.targetId);
                        if (customerClient) {
                            customerClient.ws.send(JSON.stringify({
                                type: 'admin-call-request',
                                adminId: message.adminId,
                                adminName: ADMINS[message.adminId].name,
                                fromQueue: true
                            }));
                        }
                    }
                    break;

                case 'queue-remove':
                    await removeFromQueue(message.targetId);
                    const removedClient = clients.get(message.targetId);
                    if (removedClient) {
                        removedClient.ws.send(JSON.stringify({
                            type: 'removed-from-queue',
                            message: 'Kuyruktan çıkarıldınız'
                        }));
                    }
                    break;

                case 'accept-call':
                    const adminForAccept = Object.keys(ADMINS).find(id => 
                        ADMINS[id].currentCall === message.userId
                    );
                    if (adminForAccept) {
                        await removeFromQueue(message.userId);
                    }
                    
                    const callerClient = clients.get(message.userId);
                    if (callerClient) {
                        callerClient.ws.send(JSON.stringify({
                            type: 'call-accepted'
                        }));
                    }
                    break;

                case 'end-call':
                    const duration = message.duration || 0;
                    const adminId = message.adminId || message.targetId || 'ADMIN001';
                    
                    // Admin durumunu güncelle
                    if (ADMINS[adminId]) {
                        ADMINS[adminId].status = 'idle';
                        ADMINS[adminId].currentCall = null;
                    }
                    
                    // Hedef kullanıcıya bildir
                    if (message.targetId) {
                        const endTarget = clients.get(message.targetId);
                        if (endTarget && endTarget.ws.readyState === WebSocket.OPEN) {
                            endTarget.ws.send(JSON.stringify({
                                type: 'call-ended',
                                userId: message.userId,
                                duration: duration,
                                endedBy: message.userType || 'unknown'
                            }));
                        }
                    }
                    
                    // KREDİ DÜŞME - SADECE MÜŞTERİ ARAMALARINDA
                    if (duration > 0 && message.userId && !message.userId.startsWith('ADMIN')) {
                        const result = await saveCallAndDeductCredits(
                            message.userId,
                            adminId,
                            duration,
                            message.endedBy || 'normal'
                        );
                        
                        if (result.success) {
                            console.log(`✅ Kredi düştü: ${message.userId} - ${result.creditsUsed} dk`);
                        } else {
                            console.log(`❌ Kredi düşme hatası: ${result.error}`);
                        }
                    }
                    
                    // Kuyruk kontrolü
                    processNextInQueue();
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    const targetClient = clients.get(message.targetId);
                    if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
                        targetClient.ws.send(JSON.stringify(message));
                    }
                    break;
            }

        } catch (error) {
            console.log('❌ Mesaj işleme hatası:', error.message);
        }
    });

    ws.on('close', () => {
        const client = findClientById(ws);
        if (client) {
            console.log('👋 Ayrıldı:', client.name);
            
            // Admin ise durumu güncelle
            if (client.userType === 'admin' && ADMINS[client.id]) {
                ADMINS[client.id].status = 'offline';
                ADMINS[client.id].currentCall = null;
            }
            
            for (const [key, clientData] of clients.entries()) {
                if (clientData.ws === ws) {
                    clients.delete(key);
                    break;
                }
            }
        }
        
        broadcastUserList();
    });

    ws.on('error', (error) => {
        console.log('⚠️ WebSocket hatası:', error.message);
    });
});

// Sıradaki müşteriyi işle
function processNextInQueue() {
    if (callQueue.length === 0) return;
    
    const availableAdmin = findAvailableAdmin();
    if (!availableAdmin) return;
    
    const nextCustomer = callQueue.shift();
    const adminClient = clients.get(availableAdmin);
    const customerClient = clients.get(nextCustomer.userId);
    
    if (adminClient && customerClient) {
        adminClient.ws.send(JSON.stringify({
            type: 'auto-call-from-queue',
            userId: nextCustomer.userId,
            userName: nextCustomer.userName,
            message: 'Sıradaki müşteri hazır'
        }));
    }
    
    broadcastQueueUpdate();
}

function findClientById(ws) {
    for (const client of clients.values()) {
        if (client.ws === ws) {
            return client;
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

// Periyodik kuyruk güncellemesi (5 saniyede bir)
setInterval(() => {
    broadcastQueueUpdate();
}, 5000);

// API Routes

// Ana sayfa
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🎯 VIPCEP Server</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="manifest" href="/manifest.json">
            <style>
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; 
                    max-width: 900px; 
                    margin: 50px auto; 
                    padding: 20px;
                    background: #f8fafc;
                }
                .header { 
                    background: linear-gradient(135deg, #22c55e, #16a34a); 
                    color: white; 
                    padding: 30px; 
                    border-radius: 12px; 
                    text-align: center; 
                    margin-bottom: 30px;
                    box-shadow: 0 10px 30px rgba(34, 197, 94, 0.3);
                }
                .links { 
                    display: grid; 
                    grid-template-columns: 1fr 1fr; 
                    gap: 20px; 
                    margin: 30px 0; 
                }
                .link-card { 
                    background: white; 
                    padding: 25px; 
                    border-radius: 12px; 
                    text-align: center; 
                    border: 1px solid #e2e8f0;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                    transition: transform 0.3s ease;
                }
                .link-card:hover {
                    transform: translateY(-5px);
                }
                .link-card a { 
                    color: #2563eb; 
                    text-decoration: none; 
                    font-weight: bold; 
                    background: #eff6ff;
                    padding: 10px 20px;
                    border-radius: 8px;
                    display: inline-block;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎯 VIPCEP Server</h1>
                <p style="font-size: 18px;">Voice IP Communication Emergency Protocol</p>
                <p style="font-size: 14px; opacity: 0.9;">Port: ${PORT} | DB: ${process.env.DATABASE_URL ? 'PostgreSQL' : 'Offline'}</p>
            </div>
            
            <div class="links">
                <div class="link-card">
                    <h3>👨‍💼 Admin Panel</h3>
                    <p>Teknik servis yönetim sistemi</p>
                    <a href="/admin-panel.html">Admin Panel'e Git →</a>
                </div>
                <div class="link-card">
                    <h3>📱 Müşteri Uygulaması</h3>
                    <p>Sesli danışmanlık uygulaması</p>
                    <a href="/customer-app.html">Müşteri Uygulaması →</a>
                </div>
            </div>
        </body>
        </html>
    `);
});

// Onaylı kullanıcıları getir
app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Yeni onaylı kullanıcı ekle
app.post('/api/approved-users', async (req, res) => {
    try {
        const { id, name, credits = 0 } = req.body;
        
        const result = await pool.query(`
            INSERT INTO approved_users (id, name, credits) 
            VALUES ($1, $2, $3)
            ON CONFLICT (id) 
            DO UPDATE SET name = $2, credits = $3
            RETURNING *
        `, [id, name, credits]);
        
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Kullanıcıyı sil
app.delete('/api/approved-users/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM approved_users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Kredi güncelle
app.post('/api/approved-users/:id/credits', async (req, res) => {
    try {
        const { credits, reason } = req.body;
        
        await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [credits, req.params.id]);
        
        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
            VALUES ($1, $2, $3, $4, $5)
        `, [req.params.id, 'update', credits, credits, reason || 'Admin güncellemesi']);
        
        res.json({ success: true, credits: credits });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// İstatistikler
app.get('/api/stats', async (req, res) => {
    try {
        const todayCalls = await pool.query("SELECT COUNT(*) FROM call_history WHERE DATE(call_time) = CURRENT_DATE");
        
        res.json({
            todayCalls: parseInt(todayCalls.rows[0].count),
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Kuyruk bilgisi
app.get('/api/queue', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM call_queue WHERE status = 'waiting' ORDER BY queue_position");
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// PWA için manifest.json
app.get('/manifest.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'manifest.json'));
});

// Service Worker
app.get('/service-worker.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'service-worker.js'));
});

// Static dosyalar
app.get('/admin-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get('/customer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).send(`<h1>404 - Sayfa Bulunamadı</h1>`);
});

// Server başlatma
async function startServer() {
    await initDatabase();
    
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server çalışıyor!');
        console.log(`📍 Port: ${PORT}`);
        console.log(`🌐 URL: http://0.0.0.0:${PORT}`);
        console.log(`📱 Admin: /admin-panel.html`);
        console.log(`📱 Müşteri: /customer-app.html`);
        console.log('✅ Sistem hazır!');
    });
}

// Hata yakalama
process.on('uncaughtException', (error) => {
    console.log('❌ Yakalanmamış hata:', error.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.log('❌ İşlenmemiş promise reddi:', reason);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🔴 Server kapatılıyor...');
    server.close(() => {
        console.log('✅ Server kapatıldı');
        process.exit(0);
    });
});

// Başlat
startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
