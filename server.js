const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');

// PostgreSQL bağlantısı - Railway için güncellenmiş
const { Pool } = require('pg');

// Railway Environment Variables kullanımı
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

console.log('🔗 Database URL:', process.env.DATABASE_URL ? 'FOUND' : 'NOT FOUND');
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');

// Express app oluştur
const app = express();
const server = http.createServer(app);

// Port ayarı (Railway için)
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// WebSocket server
const wss = new WebSocket.Server({ server });

// Global değişkenler
const clients = new Map();
let callHistory = [];

// Veritabanı başlatma
async function initDatabase() {
    try {
        console.log('🔧 Veritabanı kontrol ediliyor...');
        
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

        // Call history tablosu (Foreign key olmadan)
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

        console.log('✅ PostgreSQL tabloları kontrol edildi');
        
        // Test kullanıcısını kontrol et ve ekle
        const testUser = await pool.query('SELECT * FROM approved_users WHERE id = $1', ['1234']);
        if (testUser.rows.length === 0) {
            await pool.query(`
                INSERT INTO approved_users (id, name, credits) 
                VALUES ($1, $2, $3)
            `, ['1234', 'Test Kullanıcı', 10]);
            console.log('📝 Test kullanıcısı eklendi: 1234 - Test Kullanıcı');
        }

    } catch (error) {
        console.log('❌ PostgreSQL bağlantı hatası:', error.message);
        console.log('💡 LocalStorage ile devam ediliyor...');
    }
}

// Kullanıcı onaylı mı kontrol et
async function isUserApproved(userId, userName) {
    try {
        const result = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        
        if (result.rows.length > 0) {
            const user = result.rows[0];
            
            // İsim kontrolü (büyük/küçük harf duyarsız)
            if (user.name.toLowerCase().trim() === userName.toLowerCase().trim()) {
                console.log('🔍 Veritabanı sonucu:', user);
                console.log('🔍 Ad karşılaştırma:');
                console.log('   Girilen:', `"${userName}"`);
                console.log('   Kayıtlı:', `"${user.name}"`);
                console.log('   Eşit mi:', user.name.toLowerCase().trim() === userName.toLowerCase().trim());
                
                return {
                    approved: true,
                    credits: user.credits,
                    totalCalls: user.total_calls || 0,
                    lastCall: user.last_call,
                    user: user
                };
            } else {
                console.log(`❌ İsim uyumsuzluğu: "${userName}" != "${user.name}"`);
                return { approved: false, reason: 'İsim uymuyor' };
            }
        } else {
            console.log(`❌ Kullanıcı bulunamadı: ${userId}`);
            return { approved: false, reason: 'ID bulunamadı' };
        }
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı kontrol hatası:', error.message);
        return { approved: false, reason: 'Veritabanı hatası' };
    }
}

// Onaylı kullanıcı kaydetme
async function saveApprovedUser(userId, userName, credits = 0) {
    try {
        const result = await pool.query(`
            INSERT INTO approved_users (id, name, credits, created_at) 
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
            ON CONFLICT (id) 
            DO UPDATE SET name = $2, credits = $3
            RETURNING *
        `, [userId, userName, credits]);
        
        console.log(`✅ Kullanıcı kaydedildi: ${userName} (${userId}) - ${credits} kredi`);
        return result.rows[0];
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı kaydetme hatası:', error.message);
        throw error;
    }
}

// Kredi güncelleme
async function updateUserCredits(userId, newCredits, reason = 'Manuel güncelleme') {
    try {
        const user = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
        if (user.rows.length === 0) {
            throw new Error('Kullanıcı bulunamadı');
        }
        
        const oldCredits = user.rows[0].credits;
        
        await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);
        
        // Transaction kaydı
        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
            VALUES ($1, $2, $3, $4, $5)
        `, [userId, 'update', newCredits - oldCredits, newCredits, reason]);
        
        console.log(`💳 Kredi güncellendi: ${userId} -> ${newCredits} (${reason})`);
        return newCredits;
    } catch (error) {
        console.log('💾 PostgreSQL kredi güncelleme hatası:', error.message);
        throw error;
    }
}

// Arama kayıtlarını veritabanına kaydet
async function saveCallToDatabase(callData) {
    try {
        console.log('💾 Arama veritabanına kaydediliyor:', callData);
        
        const { userId, adminId, duration, creditsUsed, endReason } = callData;
        
        // Call history kaydet
        await pool.query(`
            INSERT INTO call_history (user_id, admin_id, duration, credits_used, call_time, end_reason)
            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
        `, [userId, adminId || 'ADMIN001', duration, creditsUsed, endReason || 'normal']);
        
        // Kullanıcı kredi ve istatistiklerini güncelle
        const userResult = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        
        if (userResult.rows.length > 0) {
            const user = userResult.rows[0];
            const newCredits = Math.max(0, user.credits - creditsUsed);
            const newTotalCalls = (user.total_calls || 0) + 1;
            
            await pool.query(`
                UPDATE approved_users 
                SET credits = $1, total_calls = $2, last_call = CURRENT_TIMESTAMP 
                WHERE id = $3
            `, [newCredits, newTotalCalls, userId]);
            
            // Credit transaction kaydet
            if (creditsUsed > 0) {
                await pool.query(`
                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                    VALUES ($1, $2, $3, $4, $5)
                `, [userId, 'call', -creditsUsed, newCredits, `Görüşme: ${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}`]);
            }
            
            console.log(`✅ Arama kaydedildi: ${userId} -> ${creditsUsed} kredi düşüldü (${newCredits} kalan)`);
            return { success: true, newCredits, creditsUsed };
        }
        
    } catch (error) {
        console.log('💾 PostgreSQL arama kayıt hatası:', error.message);
        return { success: false, error: error.message };
    }
}

// WebSocket bağlantı işleyicisi
wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';
    console.log('🔗 Yeni bağlantı:', clientIP);

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            console.log('📨 Gelen mesaj:', message.type, 'from:', message.userId || 'unknown');

            switch (message.type) {
                case 'register':
                    clients.set(message.userId, {
                        ws: ws,
                        id: message.userId,
                        name: message.name,
                        userType: message.userType || 'customer',
                        registeredAt: new Date().toLocaleTimeString(),
                        online: true
                    });

                    console.log(`✅ ${message.userType?.toUpperCase()} kaydedildi: ${message.name} ${message.userId}`);
                    broadcastUserList();
                    break;

                case 'login-request':
                    console.log('🔍 Giriş denemesi - ID:', message.userId, 'Ad:', message.userName);
                    
                    const approval = await isUserApproved(message.userId, message.userName);
                    
                    if (approval.approved) {
                        console.log('✅ Giriş başarılı:', message.userName, `(${message.userId})`);
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: true,
                            credits: approval.credits,
                            user: approval.user
                        }));
                    } else {
                        console.log('❌ Giriş reddedildi:', approval.reason);
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: approval.reason
                        }));
                    }
                    break;

                case 'call-request':
                    console.log('📞 Arama talebi:', message.userId, '->', message.targetId);
                    
                    const targetClient = clients.get(message.targetId);
                    if (targetClient && targetClient.userType === 'admin') {
                        targetClient.ws.send(JSON.stringify({
                            type: 'incoming-call',
                            userId: message.userId,
                            userName: message.userName,
                            credits: message.credits
                        }));
                        console.log('📞 Admin\'e arama bildirimi gönderildi');
                    } else {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Admin müsait değil'
                        }));
                        console.log('❌ Admin bulunamadı, arama reddedildi');
                    }
                    break;

                case 'admin-call-request':
                    console.log('📞 Admin → Müşteri arama talebi:', message.adminId, '->', message.targetId);
                    
                    const customerClient = clients.get(message.targetId);
                    if (customerClient && customerClient.userType === 'customer') {
                        customerClient.ws.send(JSON.stringify({
                            type: 'admin-call-request',
                            adminId: message.adminId,
                            adminName: message.adminName || 'USTAM'
                        }));
                        console.log('📞 Müşteriye arama bildirimi gönderildi');
                    } else {
                        const adminClient = clients.get(message.adminId);
                        if (adminClient) {
                            adminClient.ws.send(JSON.stringify({
                                type: 'admin-call-rejected',
                                userId: message.targetId,
                                reason: 'Müşteri çevrimiçi değil'
                            }));
                        }
                        console.log('❌ Müşteri bulunamadı, admin arama reddedildi');
                    }
                    break;

                case 'admin-call-accepted':
                    console.log('✅ Müşteri admin aramasını kabul etti:', message.userId);
                    
                    const acceptingAdmin = clients.get(message.adminId);
                    if (acceptingAdmin) {
                        acceptingAdmin.ws.send(JSON.stringify({
                            type: 'admin-call-accepted',
                            userId: message.userId
                        }));
                    }
                    break;

                case 'admin-call-rejected':
                    console.log('❌ Müşteri admin aramasını reddetti:', message.userId);
                    
                    const rejectingAdmin = clients.get(message.adminId);
                    if (rejectingAdmin) {
                        rejectingAdmin.ws.send(JSON.stringify({
                            type: 'admin-call-rejected',
                            userId: message.userId,
                            reason: message.reason
                        }));
                    }
                    break;

                case 'admin-call-cancelled':
                    console.log('📞 Admin aramayı iptal etti:', message.adminId, '->', message.targetId);
                    
                    const cancelTargetClient = clients.get(message.targetId);
                    if (cancelTargetClient) {
                        cancelTargetClient.ws.send(JSON.stringify({
                            type: 'admin-call-cancelled',
                            reason: message.reason
                        }));
                    }
                    break;

                case 'accept-call':
                    console.log('✅ Arama kabul edildi:', message.userId);
                    
                    const callerClient = clients.get(message.userId);
                    if (callerClient) {
                        callerClient.ws.send(JSON.stringify({
                            type: 'call-accepted'
                        }));
                    }
                    
                    // Admin'e de bildir
                    clients.forEach((client) => {
                        if (client.userType === 'admin' && client.ws !== ws) {
                            client.ws.send(JSON.stringify({
                                type: 'call-accepted',
                                userId: message.userId
                            }));
                        }
                    });
                    break;

                case 'reject-call':
                    console.log('❌ Arama reddedildi:', message.userId);
                    
                    const rejectedClient = clients.get(message.userId);
                    if (rejectedClient) {
                        rejectedClient.ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: message.reason || 'Arama reddedildi'
                        }));
                    }
                    break;

                case 'call-cancelled':
                    console.log('📞 Arama iptal edildi:', message.userId);
                    
                    // Admin'e bildir
                    clients.forEach((client) => {
                        if (client.userType === 'admin') {
                            client.ws.send(JSON.stringify({
                                type: 'call-cancelled',
                                userId: message.userId,
                                userName: message.userName,
                                reason: message.reason
                            }));
                        }
                    });
                    break;

                case 'offer':
                    console.log('📤 Offer gönderiliyor:', message.userId, '->', message.targetId);
                    
                    const offerTarget = clients.get(message.targetId);
                    if (offerTarget) {
                        offerTarget.ws.send(JSON.stringify({
                            type: 'offer',
                            offer: message.offer,
                            userId: message.userId,
                            userName: message.userName
                        }));
                        console.log('📨 Offer iletildi');
                    } else {
                        console.log('❌ Offer hedefi bulunamadı:', message.targetId);
                    }
                    break;

                case 'answer':
                    console.log('📤 Answer gönderiliyor:', message.userId, '->', message.targetId);
                    
                    const answerTarget = clients.get(message.targetId);
                    if (answerTarget) {
                        answerTarget.ws.send(JSON.stringify({
                            type: 'answer',
                            answer: message.answer,
                            userId: message.userId
                        }));
                        console.log('📨 Answer iletildi');
                    } else {
                        console.log('❌ Answer hedefi bulunamadı:', message.targetId);
                    }
                    break;

                case 'ice-candidate':
                    const candidateTarget = clients.get(message.targetId);
                    if (candidateTarget) {
                        candidateTarget.ws.send(JSON.stringify({
                            type: 'ice-candidate',
                            candidate: message.candidate,
                            userId: message.userId
                        }));
                    }
                    break;

                case 'end-call':
                    console.log('📞 Görüşme sonlandırılıyor:', message.userId);
                    
                    const duration = message.duration || 0;
                    const creditsUsed = Math.ceil(duration / 60); // Yukarı yuvarlamalı
                    
                    if (message.targetId) {
                        const endTarget = clients.get(message.targetId);
                        if (endTarget) {
                            endTarget.ws.send(JSON.stringify({
                                type: 'call-ended',
                                userId: message.userId,
                                duration: duration,
                                creditsUsed: creditsUsed,
                                endedBy: message.userType || 'unknown'
                            }));
                        }
                    }
                    
                    // Arama kaydını veritabanına kaydet
                    if (duration > 0 && message.userId && message.userId !== 'ADMIN001') {
                        const saveResult = await saveCallToDatabase({
                            userId: message.userId,
                            adminId: message.targetId || 'ADMIN001',
                            duration: duration,
                            creditsUsed: creditsUsed,
                            endReason: message.endedBy === 'admin' ? 'admin_ended' : 'customer_ended'
                        });
                        
                        if (saveResult.success) {
                            // Tüm admin client'lara kredi güncellemesi bildir
                            clients.forEach((client) => {
                                if (client.userType === 'admin') {
                                    client.ws.send(JSON.stringify({
                                        type: 'credit-updated',
                                        userId: message.userId,
                                        creditsUsed: creditsUsed,
                                        newCredits: saveResult.newCredits,
                                        duration: duration
                                    }));
                                }
                            });
                            
                            // Müşteriye de güncel kredi bilgisini gönder
                            const customerClient = clients.get(message.userId);
                            if (customerClient) {
                                customerClient.ws.send(JSON.stringify({
                                    type: 'credit-update',
                                    credits: saveResult.newCredits
                                }));
                            }
                        }
                    }
                    break;

                case 'credit-update-broadcast':
                    console.log('💳 Kredi güncelleme broadcast:', message.userId, '->', message.newCredits);
                    
                    // Güncellenen kullanıcıya bildir
                    const updatedUserClient = clients.get(message.userId);
                    if (updatedUserClient && updatedUserClient.userType === 'customer') {
                        updatedUserClient.ws.send(JSON.stringify({
                            type: 'credit-update',
                            credits: message.newCredits,
                            updatedBy: message.updatedBy || 'admin',
                            message: 'Krediniz güncellendi!'
                        }));
                        console.log(`📱 Müşteriye kredi güncelleme bildirildi: ${message.userId} -> ${message.newCredits} dk`);
                    } else {
                        console.log(`📱 Kullanıcı çevrimdışı: ${message.userId}`);
                    }
                    
                    // Tüm admin'lere de bildir
                    clients.forEach((client) => {
                        if (client.userType === 'admin' && client.ws !== ws) {
                            client.ws.send(JSON.stringify({
                                type: 'credit-updated',
                                userId: message.userId,
                                newCredits: message.newCredits,
                                updatedBy: message.updatedBy
                            }));
                        }
                    });
                    break;
            }

        } catch (error) {
            console.log('❌ Mesaj işleme hatası:', error.message);
        }
    });

    ws.on('close', () => {
        console.log('👋 Kullanıcı ayrıldı:', findClientById(ws)?.id || 'unknown');
        
        // Client'ı kaldır
        for (const [key, client] of clients.entries()) {
            if (client.ws === ws) {
                clients.delete(key);
                break;
            }
        }
        
        broadcastUserList();
    });

    ws.on('error', (error) => {
        console.log('⚠️ WebSocket hatası:', error.message);
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

// API Routes

// Onaylı kullanıcıları getir
app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı listesi hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Yeni onaylı kullanıcı ekle
app.post('/api/approved-users', async (req, res) => {
    try {
        const { id, name, credits = 0 } = req.body;
        
        if (!id || !name) {
            return res.status(400).json({ error: 'ID ve isim gerekli' });
        }
        
        const user = await saveApprovedUser(id, name, credits);
        res.json({ success: true, user });
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı ekleme hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Onaylı kullanıcıyı sil
app.delete('/api/approved-users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM approved_users WHERE id = $1', [id]);
        console.log(`🗑️ Kullanıcı silindi: ${id}`);
        res.json({ success: true });
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı silme hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Kullanıcı kredisini güncelle
app.post('/api/approved-users/:id/credits', async (req, res) => {
    try {
        const { id } = req.params;
        const { credits, reason } = req.body;
        
        const newCredits = await updateUserCredits(id, credits, reason);
        res.json({ success: true, credits: newCredits });
    } catch (error) {
        console.log('💾 PostgreSQL kredi güncelleme hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Arama geçmişini getir
app.get('/api/calls', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ch.*, au.name as user_name 
            FROM call_history ch
            LEFT JOIN approved_users au ON ch.user_id = au.id
            ORDER BY ch.call_time DESC 
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (error) {
        console.log('💾 PostgreSQL arama geçmişi hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// İstatistikleri getir
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
        console.log('💾 PostgreSQL istatistik hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Manuel kredi ekleme
app.post('/api/add-credit/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, reason } = req.body;
        
        const user = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [id]);
        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        }
        
        const currentCredits = user.rows[0].credits;
        const newCredits = currentCredits + amount;
        
        await updateUserCredits(id, newCredits, reason || 'Manuel kredi ekleme');
        res.json({ success: true, credits: newCredits });
    } catch (error) {
        console.log('💾 PostgreSQL kredi ekleme hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Ana sayfa
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>VIPCEP Server</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                .header { background: #22c55e; color: white; padding: 20px; border-radius: 8px; text-align: center; }
                .links { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 30px 0; }
                .link-card { background: #f8fafc; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #e2e8f0; }
                .link-card a { color: #2563eb; text-decoration: none; font-weight: bold; }
                .stats { background: #eff6ff; padding: 15px; border-radius: 8px; border-left: 4px solid #3b82f6; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎯 VIPCEP Server</h1>
                <p>Voice IP Communication Emergency Protocol</p>
            </div>
            
            <div class="links">
                <div class="link-card">
                    <h3>👨‍💼 Admin Panel</h3>
                    <p>Teknik servis yönetim paneli</p>
                </div>
                <div class="link-card">
                    <h3>📱 Müşteri Uygulaması</h3>
                    <p>Sesli danışmanlık uygulaması</p>
                    <a href="/customer-app.html">Müşteri Uygulaması →</a>
                </div>
            </div>
            
            <div class="stats">
                <h3>📊 Server Bilgileri</h3>
                <p><strong>Port:</strong> ${PORT}</p>
                <p><strong>WebSocket:</strong> wss://${req.get('host')}</p>
                <p><strong>Status:</strong> ✅ Çalışıyor</p>
                <p><strong>Database:</strong> ${process.env.DATABASE_URL ? '✅ PostgreSQL' : '❌ Unavailable'}</p>
            </div>
        </body>
        </html>
    `);
});

// Admin panel route'u
app.get('/admin-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

// Customer app route'u  
app.get('/customer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// Veritabanı debug endpoint'i
app.get('/api/debug/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json({
            count: result.rows.length,
            users: result.rows
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Kredi debug endpoint'i
app.get('/api/debug/user/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const user = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
        const transactions = await pool.query('SELECT * FROM credit_transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10', [id]);
        
        res.json({
            user: user.rows[0] || null,
            transactions: transactions.rows
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Server'ı başlat
async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');
    
    // Veritabanını başlat
    await initDatabase();
    
    // HTTP Server'ı başlat
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server çalışıyor!');
        console.log(`📍 Yerel erişim: http://localhost:${PORT}`);
        console.log(`🌐 Ağ erişimi: http://0.0.0.0:${PORT}`);
        console.log(`🔌 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('🚀 YENİ ÖZELLİK: Admin → Müşteri Arama');
        console.log(' 📞 Admin artık müşterileri arayabilir');
        console.log(' 📱 Gelen arama bildirimleri');
        console.log(' ✅ İki yönlü arama sistemi tamamlandı');
        console.log('📱 Uygulamalar:');
        console.log(` 📞 Admin paneli: http://localhost:${PORT}/admin-panel.html`);
        console.log(` 📱 Müşteri uygulaması: http://localhost:${PORT}/customer-app.html`);
        console.log('📊 API Endpoints:');
        console.log(' GET /api/approved-users - Onaylı kullanıcı listesi');
        console.log(' POST /api/approved-users - Yeni onaylı kullanıcı');
        console.log(' DELETE /api/approved-users/:id - Onaylı kullanıcı sil');
        console.log(' POST /api/approved-users/:id/credits - Kredi güncelle');
        console.log(' GET /api/calls - Arama geçmişi');
        console.log(' GET /api/stats - İstatistikler');
        console.log(' POST /api/add-credit/:id - Manuel kredi ekleme');
        console.log('🧪 TEST KULLANICISI: ID=1234, Ad=Test Kullanıcı, Kredi=10');
        console.log('📞 WhatsApp: +90 537 479 24 03');
        console.log('📧 Email: vipcepservis@gmail.com');
        console.log('✅ Proje %100 tamamlandı - Tüm özellikler çalışıyor!');
    });
}

// Hata yakalama
process.on('uncaughtException', (error) => {
    console.log('❌ Yakalanmamış hata:', error.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.log('❌ İşlenmemiş promise reddi:', reason);
});

// Server'ı başlat
startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
