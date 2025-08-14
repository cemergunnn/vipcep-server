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

// Çoklu Admin sistemi
const ADMINS = {
    'ADMIN001': { name: 'Cem Usta', status: 'idle', currentCall: null },
    'ADMIN002': { name: 'Cenk Usta', status: 'idle', currentCall: null }
};

// Kuyruk sistemi
let callQueue = [];
let queueCounter = 0;

// İlk müsait admin bulma
function findAvailableAdmin() {
    return Object.keys(ADMINS).find(adminId => 
        ADMINS[adminId].status === 'idle' && 
        clients.get(adminId)?.ws.readyState === WebSocket.OPEN
    );
}

// Admin durumunu güncelle
function updateAdminStatus(adminId, status, callInfo = null) {
    if (ADMINS[adminId]) {
        ADMINS[adminId].status = status;
        ADMINS[adminId].currentCall = callInfo;
        console.log(`👨‍💼 ${ADMINS[adminId].name} durumu: ${status}`);
        broadcastAdminStatus();
    }
}

// Admin durumlarını broadcast et
function broadcastAdminStatus() {
    const adminStatus = Object.keys(ADMINS).map(adminId => ({
        id: adminId,
        name: ADMINS[adminId].name,
        status: ADMINS[adminId].status,
        currentCall: ADMINS[adminId].currentCall,
        online: clients.get(adminId)?.ws.readyState === WebSocket.OPEN
    }));

    const message = JSON.stringify({
        type: 'admin-status-update',
        admins: adminStatus
    });

    // Sadece admin client'lara gönder
    clients.forEach(client => {
        if (client.userType === 'admin' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(message);
        }
    });
}

// Kuyruğa ekle
function addToQueue(userId, userName, credits) {
    const queueItem = {
        id: ++queueCounter,
        userId,
        userName,
        credits,
        queueTime: Date.now(),
        callAttempts: 0,
        lastCallAttempt: null,
        status: 'waiting'
    };
    
    callQueue.push(queueItem);
    console.log(`📋 Kuyruğa eklendi: ${userName} (${userId}) - Sıra: ${callQueue.length}`);
    
    broadcastQueueUpdate();
    notifyUserQueuePosition(userId);
    
    return queueItem;
}

// Kuyruktan çıkar
function removeFromQueue(userId) {
    const index = callQueue.findIndex(item => item.userId === userId);
    if (index !== -1) {
        const removed = callQueue.splice(index, 1)[0];
        console.log(`📋 Kuyruktan çıkarıldı: ${removed.userName} (${removed.userId})`);
        broadcastQueueUpdate();
        updateAllQueuePositions();
        return removed;
    }
    return null;
}

// Kuyruk pozisyonunu bul
function getQueuePosition(userId) {
    return callQueue.findIndex(item => item.userId === userId) + 1;
}

// Tüm kuyruk pozisyonlarını güncelle
function updateAllQueuePositions() {
    callQueue.forEach((item, index) => {
        notifyUserQueuePosition(item.userId, index + 1);
    });
}

// Kullanıcıya kuyruk pozisyonunu bildir
function notifyUserQueuePosition(userId, position = null) {
    const client = clients.get(userId);
    if (client && client.ws.readyState === WebSocket.OPEN) {
        const currentPosition = position || getQueuePosition(userId);
        if (currentPosition > 0) {
            client.ws.send(JSON.stringify({
                type: 'queue-position-update',
                position: currentPosition,
                totalWaiting: callQueue.length,
                estimatedWait: currentPosition * 3 // 3 dakika tahmin
            }));
        }
    }
}

// Kuyruk güncellemesini broadcast et
function broadcastQueueUpdate() {
    const queueData = callQueue.map(item => ({
        id: item.id,
        userId: item.userId,
        userName: item.userName,
        credits: item.credits,
        queueTime: item.queueTime,
        callAttempts: item.callAttempts,
        lastCallAttempt: item.lastCallAttempt,
        status: item.status,
        waitingMinutes: Math.floor((Date.now() - item.queueTime) / 60000)
    }));

    const message = JSON.stringify({
        type: 'queue-update',
        queue: queueData
    });

    // Admin'lere gönder
    clients.forEach(client => {
        if (client.userType === 'admin' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(message);
        }
    });
}

// Kuyruktan admin ile arama yap
function callFromQueue(queueId, adminId) {
    const queueItem = callQueue.find(item => item.id === queueId);
    if (!queueItem) {
        console.log(`❌ Kuyruk öğesi bulunamadı: ${queueId}`);
        return false;
    }

    const customerClient = clients.get(queueItem.userId);
    if (!customerClient || customerClient.ws.readyState !== WebSocket.OPEN) {
        console.log(`❌ Müşteri çevrimdışı: ${queueItem.userId}`);
        return false;
    }

    // Arama denemesi say
    queueItem.callAttempts++;
    queueItem.lastCallAttempt = Date.now();
    queueItem.status = 'calling';

    console.log(`📞 Kuyruktan arama: ${ADMINS[adminId].name} -> ${queueItem.userName} (${queueItem.callAttempts}. deneme)`);

    // Müşteriye arama bildirimi gönder
    customerClient.ws.send(JSON.stringify({
        type: 'admin-call-request',
        adminId: adminId,
        adminName: ADMINS[adminId].name,
        fromQueue: true,
        callAttempt: queueItem.callAttempts
    }));

    // Admin durumunu güncelle
    updateAdminStatus(adminId, 'calling', {
        userId: queueItem.userId,
        userName: queueItem.userName
    });

    broadcastQueueUpdate();

    // 30 saniye timeout
    setTimeout(() => {
        if (queueItem.status === 'calling') {
            console.log(`⏰ Kuyruk araması zaman aşımı: ${queueItem.userName}`);
            queueItem.status = 'waiting';
            updateAdminStatus(adminId, 'idle');
            
            // Admin'e timeout bildirimi
            const adminClient = clients.get(adminId);
            if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                adminClient.ws.send(JSON.stringify({
                    type: 'queue-call-timeout',
                    userId: queueItem.userId,
                    userName: queueItem.userName
                }));
            }
            
            broadcastQueueUpdate();
        }
    }, 30000);

    return true;
}

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

        // Call queue tablosu (yeni)
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

        console.log('✅ PostgreSQL tabloları kontrol edildi');
        
        // Test kullanıcılarını kontrol et ve ekle
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
                console.log(`📝 Test kullanıcısı eklendi: ${id} - ${name} (${credits} dk)`);
            }
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
                console.log(`✅ Kullanıcı doğrulandı: ${userName} (${userId}) - ${user.credits} dk`);
                
                return {
                    approved: true,
                    credits: user.credits,
                    totalCalls: user.total_calls || 0,
                    lastCall: user.last_call,
                    user: user
                };
            } else {
                console.log(`❌ İsim uyumsuzluğu: "${userName}" != "${user.name}"`);
                return { approved: false, reason: 'İsim uyuşmuyor. Lütfen kayıtlı isminizi tam olarak girin.' };
            }
        } else {
            console.log(`❌ Kullanıcı bulunamadı: ${userId}`);
            return { approved: false, reason: 'ID kodu bulunamadı. Kredi talep etmek için WhatsApp ile iletişime geçin.' };
        }
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı kontrol hatası:', error.message);
        return { approved: false, reason: 'Sistem hatası. Lütfen tekrar deneyin.' };
    }
}

// Onaylı kullanıcı kaydetme
async function saveApprovedUser(userId, userName, credits = 0) {
    try {
        const result = await pool.query(`
            INSERT INTO approved_users (id, name, credits, created_at) 
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
            ON CONFLICT (id) 
            DO UPDATE SET name = $2, credits = $3, status = 'active'
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

// Arama kayıtlarını veritabanına kaydet ve kredi düş
async function saveCallToDatabase(callData) {
    try {
        console.log('💾 Arama veritabanına kaydediliyor:', callData);
        
        const { userId, adminId, duration, creditsUsed, endReason } = callData;
        
        // Önce kullanıcının mevcut kredisini al
        const userResult = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        
        if (userResult.rows.length === 0) {
            console.log(`❌ Kullanıcı bulunamadı: ${userId}`);
            return { success: false, error: 'Kullanıcı bulunamadı' };
        }
        
        const user = userResult.rows[0];
        const oldCredits = user.credits;
        const newCredits = Math.max(0, oldCredits - creditsUsed);
        const newTotalCalls = (user.total_calls || 0) + 1;
        
        console.log(`💳 Kredi işlemi: ${userId} -> Eski: ${oldCredits}, Düşecek: ${creditsUsed}, Yeni: ${newCredits}`);
        
        // Aynı transaction içinde hem call history'yi kaydet hem krediyi düş
        await pool.query('BEGIN');
        
        try {
            // Call history kaydet
            await pool.query(`
                INSERT INTO call_history (user_id, admin_id, duration, credits_used, call_time, end_reason)
                VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
            `, [userId, adminId || 'ADMIN001', duration, creditsUsed, endReason || 'normal']);
            
            // Kullanıcı kredi ve istatistiklerini güncelle
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
            
            await pool.query('COMMIT');
            
            console.log(`✅ KREDİ BAŞARIYLA DÜŞTÜ: ${userId} -> ${oldCredits} -> ${newCredits} (${creditsUsed} düştü)`);
            return { success: true, newCredits, creditsUsed, oldCredits };
            
        } catch (error) {
            await pool.query('ROLLBACK');
            throw error;
        }
        
    } catch (error) {
        console.log('💾 PostgreSQL arama kayıt/kredi düşme hatası:', error.message);
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

                    console.log(`✅ ${message.userType?.toUpperCase()} kaydedildi: ${message.name} (${message.userId})`);
                    
                    // Admin ise durumunu güncelle
                    if (message.userType === 'admin' && ADMINS[message.userId]) {
                        ADMINS[message.userId].status = 'idle';
                    }
                    
                    broadcastUserList();
                    broadcastAdminStatus();
                    broadcastQueueUpdate();
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
                    console.log('📞 Müşteri arama talebi:', message.userId);
                    
                    const availableAdmin = findAvailableAdmin();
                    
                    if (availableAdmin) {
                        // Müsait admin var, direkt bağla
                        const adminClient = clients.get(availableAdmin);
                        if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                            adminClient.ws.send(JSON.stringify({
                                type: 'incoming-call',
                                userId: message.userId,
                                userName: message.userName,
                                credits: message.credits
                            }));
                            
                            updateAdminStatus(availableAdmin, 'incoming_call', {
                                userId: message.userId,
                                userName: message.userName
                            });
                            
                            console.log(`📞 ${ADMINS[availableAdmin].name}'e arama bildirimi gönderildi`);
                        }
                    } else {
                        // Tüm adminler meşgul, kuyruğa al
                        addToQueue(message.userId, message.userName, message.credits);
                        
                        ws.send(JSON.stringify({
                            type: 'added-to-queue',
                            position: getQueuePosition(message.userId),
                            totalWaiting: callQueue.length,
                            message: 'Tüm uzmanlarımız meşgul. Çağrınız sıraya alındı.'
                        }));
                        
                        console.log(`📋 Müşteri kuyruğa alındı: ${message.userName} (${message.userId})`);
                    }
                    break;

                case 'queue-call-request':
                    console.log('📞 Admin kuyruktan arama talebi:', message.adminId, '->', message.queueId);
                    
                    if (ADMINS[message.adminId] && ADMINS[message.adminId].status === 'idle') {
                        callFromQueue(message.queueId, message.adminId);
                    } else {
                        console.log(`❌ Admin müsait değil: ${message.adminId}`);
                    }
                    break;

                case 'remove-from-queue':
                    console.log('📋 Kuyruktan çıkarma talebi:', message.adminId, '->', message.queueId);
                    
                    const queueItem = callQueue.find(item => item.id === message.queueId);
                    if (queueItem) {
                        removeFromQueue(queueItem.userId);
                        
                        // Müşteriye bildir
                        const customerClient = clients.get(queueItem.userId);
                        if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
                            customerClient.ws.send(JSON.stringify({
                                type: 'removed-from-queue',
                                reason: 'Admin tarafından çıkarıldınız',
                                message: 'Görüşme talebi iptal edildi'
                            }));
                        }
                    }
                    break;

                case 'leave-queue':
                    console.log('📋 Müşteri kuyruktan ayrıldı:', message.userId);
                    removeFromQueue(message.userId);
                    break;

                case 'admin-call-request':
                    console.log('📞 Admin → Müşteri arama talebi:', message.adminId, '->', message.targetId);
                    
                    const customerClient = clients.get(message.targetId);
                    if (customerClient && customerClient.userType === 'customer' && customerClient.ws.readyState === WebSocket.OPEN) {
                        customerClient.ws.send(JSON.stringify({
                            type: 'admin-call-request',
                            adminId: message.adminId,
                            adminName: message.adminName || ADMINS[message.adminId]?.name || 'USTAM'
                        }));
                        console.log('📞 Müşteriye arama bildirimi gönderildi');
                    } else {
                        const adminSender = clients.get(message.adminId);
                        if (adminSender) {
                            adminSender.ws.send(JSON.stringify({
                                type: 'admin-call-rejected',
                                userId: message.targetId,
                                reason: 'Müşteri çevrimiçi değil'
                            }));
                        }
                        console.log('❌ Müşteri bulunamadı/çevrimdışı, admin arama reddedildi');
                    }
                    break;

                case 'admin-call-accepted':
                    console.log('✅ Müşteri admin aramasını kabul etti:', message.userId);
                    
                    const acceptingAdmin = clients.get(message.adminId);
                    if (acceptingAdmin && acceptingAdmin.ws.readyState === WebSocket.OPEN) {
                        acceptingAdmin.ws.send(JSON.stringify({
                            type: 'admin-call-accepted',
                            userId: message.userId
                        }));
                        
                        // Admin durumunu güncelle
                        updateAdminStatus(message.adminId, 'connected', {
                            userId: message.userId
                        });
                        
                        // Kuyruktan çıkar (eğer kuyrukta ise)
                        removeFromQueue(message.userId);
                    }
                    break;

                case 'admin-call-rejected':
                    console.log('❌ Müşteri admin aramasını reddetti:', message.userId, '-', message.reason);
                    
                    const rejectingAdmin = clients.get(message.adminId);
                    if (rejectingAdmin && rejectingAdmin.ws.readyState === WebSocket.OPEN) {
                        rejectingAdmin.ws.send(JSON.stringify({
                            type: 'admin-call-rejected',
                            userId: message.userId,
                            reason: message.reason
                        }));
                        
                        // Admin durumunu serbest yap
                        updateAdminStatus(message.adminId, 'idle');
                        
                        // Kuyruk durumunu güncelle
                        const queueItem = callQueue.find(item => item.userId === message.userId);
                        if (queueItem) {
                            queueItem.status = 'waiting';
                            broadcastQueueUpdate();
                        }
                    }
                    break;

                case 'admin-call-cancelled':
                    console.log('📞 Admin aramayı iptal etti:', message.adminId, '->', message.targetId);
                    
                    const cancelTargetClient = clients.get(message.targetId);
                    if (cancelTargetClient && cancelTargetClient.ws.readyState === WebSocket.OPEN) {
                        cancelTargetClient.ws.send(JSON.stringify({
                            type: 'admin-call-cancelled',
                            reason: message.reason
                        }));
                    }
                    
                    // Admin durumunu serbest yap
                    updateAdminStatus(message.adminId, 'idle');
                    break;

                case 'accept-call':
                    console.log('✅ Arama kabul edildi (Admin tarafından):', message.userId);
                    
                    const callerClient = clients.get(message.userId);
                    if (callerClient && callerClient.ws.readyState === WebSocket.OPEN) {
                        callerClient.ws.send(JSON.stringify({
                            type: 'call-accepted'
                        }));
                    }
                    break;

                case 'reject-call':
                    console.log('❌ Arama reddedildi (Admin tarafından):', message.userId, '-', message.reason);
                    
                    const rejectedClient = clients.get(message.userId);
                    if (rejectedClient && rejectedClient.ws.readyState === WebSocket.OPEN) {
                        rejectedClient.ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: message.reason || 'Arama reddedildi'
                        }));
                    }
                    break;

                case 'call-cancelled':
                    console.log('📞 Arama iptal edildi (Müşteri tarafından):', message.userId);
                    
                    // Admin'e bildir
                    const adminToNotify = Array.from(clients.values()).find(c => c.userType === 'admin');
                    if (adminToNotify && adminToNotify.ws.readyState === WebSocket.OPEN) {
                        adminToNotify.ws.send(JSON.stringify({
                            type: 'call-cancelled',
                            userId: message.userId,
                            userName: message.userName,
                            reason: message.reason
                        }));
                    }
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    // WebRTC mesajlarını hedef kullanıcıya ilet
                    const targetClient = clients.get(message.targetId);
                    if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
                        targetClient.ws.send(JSON.stringify(message));
                        console.log(`🔄 ${message.type} iletildi: ${message.userId || 'unknown'} -> ${message.targetId}`);
                    } else {
                        console.log(`❌ ${message.type} hedefi bulunamadı: ${message.targetId}`);
                    }
                    break;

                case 'end-call':
                    console.log('📞 Görüşme sonlandırılıyor:', message.userId);
                    
                    const duration = message.duration || 0;
                    const creditsUsed = Math.ceil(duration / 60); // Yukarı yuvarlamalı
                    
                    // Admin durumunu serbest yap
                    if (message.targetId && ADMINS[message.targetId]) {
                        updateAdminStatus(message.targetId, 'idle');
                    }
                    if (message.userId && ADMINS[message.userId]) {
                        updateAdminStatus(message.userId, 'idle');
                    }
                    
                    // Hedef kullanıcıya bildir
                    if (message.targetId) {
                        const endTarget = clients.get(message.targetId);
                        if (endTarget && endTarget.ws.readyState === WebSocket.OPEN) {
                            endTarget.ws.send(JSON.stringify({
                                type: 'call-ended',
                                userId: message.userId,
                                duration: duration,
                                creditsUsed: creditsUsed,
                                endedBy: message.userType || 'unknown'
                            }));
                        }
                    }
                    
                    // Arama kaydını veritabanına kaydet ve kredi düş (sadece gerçek görüşmeler için)
                    if (duration > 0 && message.userId && !message.userId.startsWith('ADMIN')) {
                        console.log(`💾 KREDİ DÜŞÜRME İŞLEMİ BAŞLIYOR:`);
                        console.log(`   - Kullanıcı: ${message.userId}`);
                        console.log(`   - Süre: ${duration} saniye`);
                        console.log(`   - Düşecek Kredi: ${creditsUsed} dakika`);
                        
                        const saveResult = await saveCallToDatabase({
                            userId: message.userId,
                            adminId: message.targetId || 'ADMIN001',
                            duration: duration,
                            creditsUsed: creditsUsed,
                            endReason: message.endedBy === 'admin' ? 'admin_ended' : 'customer_ended'
                        });
                        
                        if (saveResult.success) {
                            console.log(`✅ KREDİ DÜŞÜRME BAŞARILI:`);
                            console.log(`   - Eski Kredi: ${saveResult.oldCredits}`);
                            console.log(`   - Yeni Kredi: ${saveResult.newCredits}`);
                            console.log(`   - Düşen: ${saveResult.creditsUsed}`);
                            
                            // Tüm admin client'lara kredi güncellemesi bildir
                            const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
                            adminClients.forEach(client => {
                                if (client.ws.readyState === WebSocket.OPEN) {
                                    client.ws.send(JSON.stringify({
                                        type: 'credit-updated',
                                        userId: message.userId,
                                        creditsUsed: creditsUsed,
                                        newCredits: saveResult.newCredits,
                                        oldCredits: saveResult.oldCredits,
                                        duration: duration
                                    }));
                                    console.log(`📨 Admin'e kredi güncelleme gönderildi: ${client.id}`);
                                }
                            });
                            
                            // Müşteriye de güncel kredi bilgisini gönder
                            const customerForUpdate = clients.get(message.userId);
                            if (customerForUpdate && customerForUpdate.ws.readyState === WebSocket.OPEN) {
                                customerForUpdate.ws.send(JSON.stringify({
                                    type: 'credit-update',
                                    credits: saveResult.newCredits
                                }));
                                console.log(`📨 Müşteriye kredi güncellemesi gönderildi: ${message.userId}`);
                            }
                        } else {
                            console.log(`❌ KREDİ DÜŞÜRME HATASI: ${saveResult.error}`);
                        }
                    } else {
                        console.log(`ℹ️ Kredi düşürülmedi: duration=${duration}, userId=${message.userId}`);
                    }
                    break;

                case 'credit-update-broadcast':
                    console.log('💳 Kredi güncelleme broadcast:', message.userId, '->', message.newCredits);
                    
                    // Güncellenen kullanıcıya bildir
                    const updatedUserClient = clients.get(message.userId);
                    if (updatedUserClient && updatedUserClient.userType === 'customer' && updatedUserClient.ws.readyState === WebSocket.OPEN) {
                        updatedUserClient.ws.send(JSON.stringify({
                            type: 'credit-update',
                            credits: message.newCredits,
                            updatedBy: message.updatedBy || 'admin',
                            message: 'Krediniz güncellendi!'
                        }));
                        console.log(`📱 Müşteriye kredi güncelleme bildirildi: ${message.userId} -> ${message.newCredits} dk`);
                    }
                    
                    // Diğer admin'lere de bildir
                    const otherAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin' && c.ws !== ws);
                    otherAdmins.forEach(client => {
                        if (client.ws.readyState === WebSocket.OPEN) {
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
        const client = findClientById(ws);
        console.log('👋 Kullanıcı ayrıldı:', client?.name || 'unknown');
        
        // Admin ise durumunu offline yap
        if (client && client.userType === 'admin' && ADMINS[client.id]) {
            ADMINS[client.id].status = 'offline';
        }
        
        // Eğer kuyrukta ise çıkar
        if (client && client.userType === 'customer') {
            removeFromQueue(client.id);
        }
        
        // Client'ı kaldır
        for (const [key, clientData] of clients.entries()) {
            if (clientData.ws === ws) {
                clients.delete(key);
                break;
            }
        }
        
        broadcastUserList();
        broadcastAdminStatus();
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

// Kuyruk pozisyonu güncellemelerini periyodik gönder
setInterval(() => {
    updateAllQueuePositions();
}, 5000); // Her 5 saniyede bir

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
        
        if (!/^\d{4}$/.test(id)) {
            return res.status(400).json({ error: 'ID 4 haneli sayı olmalı' });
        }
        
        const user = await saveApprovedUser(id, name, credits);
        res.json({ success: true, user });
    } catch (error) {
        if (error.message.includes('duplicate key')) {
            res.status(400).json({ error: 'Bu ID zaten kullanımda' });
        } else {
            console.log('💾 PostgreSQL kullanıcı ekleme hatası:', error.message);
            res.status(500).json({ error: error.message });
        }
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

// Kuyruk durumunu getir
app.get('/api/queue', (req, res) => {
    const queueData = callQueue.map(item => ({
        id: item.id,
        userId: item.userId,
        userName: item.userName,
        credits: item.credits,
        queueTime: item.queueTime,
        callAttempts: item.callAttempts,
        lastCallAttempt: item.lastCallAttempt,
        status: item.status,
        waitingMinutes: Math.floor((Date.now() - item.queueTime) / 60000)
    }));
    
    res.json(queueData);
});

// Admin durumlarını getir
app.get('/api/admin-status', (req, res) => {
    const adminStatus = Object.keys(ADMINS).map(adminId => ({
        id: adminId,
        name: ADMINS[adminId].name,
        status: ADMINS[adminId].status,
        currentCall: ADMINS[adminId].currentCall,
        online: clients.get(adminId)?.ws.readyState === WebSocket.OPEN
    }));
    
    res.json(adminStatus);
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
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
            queueLength: callQueue.length,
            adminStatus: Object.keys(ADMINS).map(adminId => ({
                id: adminId,
                name: ADMINS[adminId].name,
                status: ADMINS[adminId].status,
                online: clients.get(adminId)?.ws.readyState === WebSocket.OPEN
            }))
        });
    } catch (error) {
        console.log('💾 PostgreSQL istatistik hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        clients: clients.size,
        database: process.env.DATABASE_URL ? 'Connected' : 'Offline',
        queue: callQueue.length,
        admins: Object.keys(ADMINS).map(adminId => ({
            id: adminId,
            name: ADMINS[adminId].name,
            status: ADMINS[adminId].status,
            online: clients.get(adminId)?.ws.readyState === WebSocket.OPEN
        }))
    });
});

// Ana sayfa
app.get('/', (req, res) => {
    const host = req.get('host');
    const adminStatusHTML = Object.keys(ADMINS).map(adminId => {
        const admin = ADMINS[adminId];
        const isOnline = clients.get(adminId)?.ws.readyState === WebSocket.OPEN;
        const statusIcon = isOnline ? (admin.status === 'idle' ? '🟢' : '🟡') : '🔴';
        return `<li><strong>${admin.name}:</strong> ${statusIcon} ${admin.status} ${isOnline ? '(Çevrimiçi)' : '(Çevrimdışı)'}</li>`;
    }).join('');
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🎯 VIPCEP Server v2.0</title>
            <meta charset="UTF-8">
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
                .link-card a:hover {
                    background: #dbeafe;
                }
                .stats { 
                    background: linear-gradient(135deg, #eff6ff, #dbeafe); 
                    padding: 20px; 
                    border-radius: 12px; 
                    border-left: 4px solid #3b82f6; 
                    margin-bottom: 20px;
                }
                .status-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }
                .status-item {
                    background: rgba(255,255,255,0.8);
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }
                .status-value {
                    font-size: 24px;
                    font-weight: bold;
                    color: #059669;
                }
                .whatsapp-link {
                    background: #25d366;
                    color: white;
                    padding: 15px 25px;
                    border-radius: 10px;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 20px;
                    font-weight: bold;
                }
                .new-features {
                    background: linear-gradient(135deg, #fef3c7, #fde68a);
                    padding: 20px;
                    border-radius: 12px;
                    border-left: 4px solid #f59e0b;
                    margin-bottom: 20px;
                }
                .admin-status {
                    background: white;
                    padding: 20px;
                    border-radius: 12px;
                    margin-bottom: 20px;
                    border-left: 4px solid #8b5cf6;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎯 VIPCEP Server v2.0</h1>
                <p style="font-size: 18px; margin: 10px 0;">Voice IP Communication Emergency Protocol</p>
                <p style="font-size: 14px; opacity: 0.9;">Çoklu Admin & Kuyruk Yönetim Sistemi</p>
            </div>
            
            <div class="new-features">
                <h3>🚀 Yeni Özellikler (v2.0)</h3>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li><strong>Çoklu Admin Sistemi:</strong> Cem Usta & Cenk Usta ile paralel görüşme</li>
                    <li><strong>Akıllı Kuyruk:</strong> Tüm adminler meşgulken otomatik sıralama</li>
                    <li><strong>Geri Arama:</strong> Admin'ler kuyruktan müşteri arayabilir</li>
                    <li><strong>Real-time Bildirimler:</strong> Anlık kuyruk pozisyonu güncellemeleri</li>
                    <li><strong>Gelişmiş Kredi Senkronizasyonu:</strong> Otomatik bakiye güncelleme</li>
                </ul>
            </div>
            
            <div class="admin-status">
                <h3>👨‍💼 Admin Durumları</h3>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    ${adminStatusHTML}
                </ul>
            </div>
            
            <div class="links">
                <div class="link-card">
                    <h3>👨‍💼 Admin Panel</h3>
                    <p>Çoklu admin yönetim sistemi</p>
                    <p style="font-size: 12px; color: #64748b;">Kullanıcı yönetimi, kuyruk kontrolü, kredi sistemi</p>
                    <a href="/admin-panel.html">Admin Panel'e Git →</a>
                </div>
                <div class="link-card">
                    <h3>📱 Müşteri Uygulaması</h3>
                    <p>Sesli danışmanlık uygulaması</p>
                    <p style="font-size: 12px; color: #64748b;">Teknik destek almak için</p>
                    <a href="/customer-app.html">Müşteri Uygulaması →</a>
                </div>
            </div>
            
            <div class="stats">
                <h3>📊 Server Durumu</h3>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="status-value">${clients.size}</div>
                        <div>Aktif Bağlantı</div>
                    </div>
                    <div class="status-item">
                        <div class="status-value">${callQueue.length}</div>
                        <div>Bekleyen Çağrı</div>
                    </div>
                    <div class="status-item">
                        <div class="status-value">✅</div>
                        <div>Sistem Durumu</div>
                    </div>
                    <div class="status-item">
                        <div class="status-value">${process.env.DATABASE_URL ? '✅' : '❌'}</div>
                        <div>Veritabanı</div>
                    </div>
                </div>
                <p style="margin-top: 15px;"><strong>WebSocket URL:</strong> wss://${host}</p>
                <p><strong>Railway Deploy:</strong> ${process.env.RAILWAY_ENVIRONMENT || 'Local'}</p>
                <p><strong>Kuyruk Kapasitesi:</strong> Sınırsız | <strong>Admin Kapasitesi:</strong> 2 Paralel Görüşme</p>
            </div>

            <div style="background: white; padding: 20px; border-radius: 12px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                <h3>💳 Kredi Talebi</h3>
                <p style="color: #64748b; margin-bottom: 15px;">Sistemimizi kullanmak için kredi satın alın</p>
                <a href="https://wa.me/905374792403?text=VIPCEP%20Kredi%20Talebi%20-%20Lütfen%20bana%20kredi%20yükleyin" 
                   target="_blank" class="whatsapp-link">
                    📞 WhatsApp ile Kredi Talep Et
                </a>
                <p style="font-size: 12px; color: #64748b; margin-top: 10px;">
                    Telefon: +90 537 479 24 03
                </p>
            </div>

            <div style="background: #fef3c7; padding: 15px; border-radius: 8px; margin-top: 20px; border-left: 4px solid #f59e0b;">
                <h4>📋 Test Kullanıcıları:</h4>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li><strong>ID:</strong> 1234 | <strong>Ad:</strong> Test Kullanıcı | <strong>Kredi:</strong> 10 dk</li>
                    <li><strong>ID:</strong> 0005 | <strong>Ad:</strong> VIP Müşteri | <strong>Kredi:</strong> 25 dk</li>
                    <li><strong>ID:</strong> 0007 | <strong>Ad:</strong> Cenk Zortu | <strong>Kredi:</strong> 999 dk</li>
                    <li><strong>ID:</strong> 9999 | <strong>Ad:</strong> Demo User | <strong>Kredi:</strong> 5 dk</li>
                </ul>
                <h4>👨‍💼 Admin Giriş Kodları:</h4>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li><strong>ADMIN001:</strong> Cem Usta</li>
                    <li><strong>ADMIN002:</strong> Cenk Usta</li>
                </ul>
            </div>
        </body>
        </html>
    `);
});

// Static dosya route'ları
app.get('/admin-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get('/customer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).send(`
        <h1>404 - Sayfa Bulunamadı</h1>
        <p><a href="/">Ana sayfaya dön</a></p>
    `);
});

// Server'ı başlat
async function startServer() {
    console.log('🚀 VIPCEP Server v2.0 Başlatılıyor...');
    console.log('📍 Railway Environment:', process.env.RAILWAY_ENVIRONMENT || 'Local');
    
    // Veritabanını başlat
    await initDatabase();
    
    // HTTP Server'ı başlat
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server v2.0 çalışıyor!');
        console.log(`📍 Port: ${PORT}`);
        console.log(`🌐 URL: http://0.0.0.0:${PORT}`);
        console.log(`🔌 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('📱 Uygulamalar:');
        console.log(` 👨‍💼 Admin paneli: /admin-panel.html`);
        console.log(` 📱 Müşteri uygulaması: /customer-app.html`);
        console.log('');
        console.log('👨‍💼 Çoklu Admin Sistemi:');
        console.log(`  ${ADMINS['ADMIN001'].name} (ADMIN001) - ${ADMINS['ADMIN001'].status}`);
        console.log(`  ${ADMINS['ADMIN002'].name} (ADMIN002) - ${ADMINS['ADMIN002'].status}`);
        console.log('');
        console.log('📋 Kuyruk Sistemi: Aktif');
        console.log('🔄 Real-time Güncellemeler: Her 5 saniyede bir');
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('📞 WhatsApp: +90 537 479 24 03');
        console.log('✅ Sistem hazır - Çoklu görüşme kabul ediliyor!');
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

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('📴 Server kapatılıyor...');
    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});

// Server'ı başlat
startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
