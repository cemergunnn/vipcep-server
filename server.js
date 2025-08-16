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
console.log('🌐 Environment:', process.env.NODE_ENV || 'development');

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

// 🆕 ADMIN MANAGEMENT SYSTEM
const adminClients = new Map(); // Admin-specific tracking
const ADMIN_IDS = ['ADMIN_CEM', 'ADMIN_CENK'];

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
                admin_name VARCHAR(255),
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
                admin_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                console.log(`🆔 Test kullanıcısı eklendi: ${id} - ${name} (${credits} dk)`);
            }
        }

    } catch (error) {
        console.log('❌ PostgreSQL bağlantı hatası:', error.message);
        console.log('💡 LocalStorage ile devam ediliyor...');
    }
}

// 🆕 MULTI-ADMIN FUNCTIONS

// Available admin bul
function findAvailableAdmin() {
    const admins = Array.from(clients.values())
        .filter(c => c.userType === 'admin' && ADMIN_IDS.includes(c.id))
        .sort((a, b) => {
            // Priority: available > busy > offline
            const priorityA = a.callStatus === 'available' ? 3 : 
                            a.callStatus === 'busy' ? 2 : 1;
            const priorityB = b.callStatus === 'available' ? 3 : 
                            b.callStatus === 'busy' : 2 : 1;
            return priorityB - priorityA;
        });
    
    const availableAdmin = admins.find(admin => admin.callStatus === 'available');
    
    console.log(`🔍 Admin arama: ${admins.length} admin, ${availableAdmin ? 'available: ' + availableAdmin.name : 'hiçbiri müsait değil'}`);
    
    return availableAdmin || null;
}

// Admin status güncelle
function updateAdminStatus(adminId, status, currentCall = null) {
    const admin = clients.get(adminId);
    if (admin) {
        admin.callStatus = status;
        admin.currentCall = currentCall;
        admin.lastStatusUpdate = Date.now();
        
        console.log(`👤 Admin status güncellendi: ${admin.name} -> ${status}`);
        
        // Tüm admin'lere durum güncellemesi gönder
        broadcastAdminStatusUpdate();
    }
}

// Admin status broadcast
function broadcastAdminStatusUpdate() {
    const adminList = Array.from(clients.values())
        .filter(c => c.userType === 'admin')
        .map(admin => ({
            id: admin.id,
            name: admin.name,
            callStatus: admin.callStatus || 'available',
            currentCall: admin.currentCall,
            lastStatusUpdate: admin.lastStatusUpdate
        }));

    const message = JSON.stringify({
        type: 'admin-status-update',
        admins: adminList
    });

    // Sadece admin'lere gönder
    clients.forEach(client => {
        if (client.userType === 'admin' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(message);
        }
    });
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
async function saveApprovedUser(userId, userName, credits = 0, adminName = null) {
    try {
        const result = await pool.query(`
            INSERT INTO approved_users (id, name, credits, created_at) 
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
            ON CONFLICT (id) 
            DO UPDATE SET name = $2, credits = $3, status = 'active'
            RETURNING *
        `, [userId, userName, credits]);
        
        // Transaction kaydı
        if (adminName) {
            await pool.query(`
                INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description, admin_name)
                VALUES ($1, $2, $3, $4, $5, $6)
            `, [userId, 'user_created', credits, credits, `Kullanıcı oluşturuldu: ${adminName} tarafından`, adminName]);
        }
        
        console.log(`✅ Kullanıcı kaydedildi: ${userName} (${userId}) - ${credits} kredi`);
        return result.rows[0];
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı kaydetme hatası:', error.message);
        throw error;
    }
}

// Kredi güncelleme
async function updateUserCredits(userId, newCredits, reason = 'Manuel güncelleme', adminName = null) {
    try {
        const user = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
        if (user.rows.length === 0) {
            throw new Error('Kullanıcı bulunamadı');
        }
        
        const oldCredits = user.rows[0].credits;
        
        await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);
        
        // Transaction kaydı
        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description, admin_name)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [userId, 'manual_update', newCredits - oldCredits, newCredits, reason, adminName]);
        
        console.log(`💳 Kredi güncellendi: ${userId} -> ${newCredits} (${adminName || 'Unknown'} tarafından)`);
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
        
        const { userId, adminId, adminName, duration, creditsUsed, endReason } = callData;
        
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
                INSERT INTO call_history (user_id, admin_id, admin_name, duration, credits_used, call_time, end_reason)
                VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6)
            `, [userId, adminId || 'ADMIN_UNKNOWN', adminName || 'Unknown Admin', duration, creditsUsed, endReason || 'normal']);
            
            // Kullanıcı kredi ve istatistiklerini güncelle
            await pool.query(`
                UPDATE approved_users 
                SET credits = $1, total_calls = $2, last_call = CURRENT_TIMESTAMP 
                WHERE id = $3
            `, [newCredits, newTotalCalls, userId]);
            
            // Credit transaction kaydet
            if (creditsUsed > 0) {
                await pool.query(`
                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description, admin_name)
                    VALUES ($1, $2, $3, $4, $5, $6)
                `, [userId, 'call_deduction', -creditsUsed, newCredits, 
                    `Görüşme: ${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')} - ${adminName || 'Unknown Admin'}`, 
                    adminName || 'Unknown Admin']);
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
                    // 🆕 MULTI-ADMIN SUPPORT
                    const isAdmin = message.userType === 'admin';
                    const callStatus = isAdmin ? (message.callStatus || 'available') : 'customer';
                    
                    clients.set(message.userId, {
                        ws: ws,
                        id: message.userId,
                        name: message.name,
                        userType: message.userType || 'customer',
                        callStatus: callStatus,
                        registeredAt: new Date().toLocaleTimeString(),
                        online: true,
                        currentCall: null,
                        lastStatusUpdate: Date.now()
                    });

                    console.log(`✅ ${message.userType?.toUpperCase()} kaydedildi: ${message.name} (${message.userId})`);
                    
                    if (isAdmin) {
                        console.log(`👑 Admin aktif: ${message.name} - Status: ${callStatus}`);
                        broadcastAdminStatusUpdate();
                    }
                    
                    broadcastUserList();
                    break;

                case 'login-request':
                    console.log('🔐 Giriş denemesi - ID:', message.userId, 'Ad:', message.userName);
                    
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
                    console.log('📞 Müşteri → Admin arama talebi:', message.userId);
                    
                    // 🆕 SMART ADMIN ROUTING
                    const availableAdmin = findAvailableAdmin();
                    if (availableAdmin && availableAdmin.ws.readyState === WebSocket.OPEN) {
                        // Admin'i busy yap
                        updateAdminStatus(availableAdmin.id, 'busy', message.userId);
                        
                        availableAdmin.ws.send(JSON.stringify({
                            type: 'incoming-call',
                            userId: message.userId,
                            userName: message.userName,
                            credits: message.credits
                        }));
                        console.log(`📞 Arama ${availableAdmin.name}'e yönlendirildi`);
                    } else {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Tüm ustalar şu anda meşgul. Lütfen daha sonra tekrar deneyin.'
                        }));
                        console.log('❌ Hiçbir admin müsait değil, arama reddedildi');
                    }
                    break;

                case 'admin-call-request':
                    console.log('📞 Admin → Müşteri arama talebi:', message.adminId, '->', message.targetId);
                    
                    // Admin'i busy yap
                    updateAdminStatus(message.adminId, 'busy', message.targetId);
                    
                    const customerClient = clients.get(message.targetId);
                    if (customerClient && customerClient.userType === 'customer' && customerClient.ws.readyState === WebSocket.OPEN) {
                        customerClient.ws.send(JSON.stringify({
                            type: 'admin-call-request',
                            adminId: message.adminId,
                            adminName: message.adminName || 'USTAM'
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
                        // Admin'i tekrar available yap
                        updateAdminStatus(message.adminId, 'available', null);
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
                        
                        // Admin'i tekrar available yap
                        updateAdminStatus(message.adminId, 'available', null);
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
                    
                    // Admin'i tekrar available yap
                    updateAdminStatus(message.adminId, 'available', null);
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
                    
                    // Rejecting admin'i available yap
                    const rejectingAdminId = findClientAdminId(ws);
                    if (rejectingAdminId) {
                        updateAdminStatus(rejectingAdminId, 'available', null);
                    }
                    
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
                    
                    // Admin'lere bildir ve available yap
                    const adminToNotify = Array.from(clients.values()).find(c => c.userType === 'admin' && c.currentCall === message.userId);
                    if (adminToNotify) {
                        adminToNotify.ws.send(JSON.stringify({
                            type: 'call-cancelled',
                            userId: message.userId,
                            userName: message.userName,
                            reason: message.reason
                        }));
                        
                        updateAdminStatus(adminToNotify.id, 'available', null);
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
                    
                    // Admin'i available yap
                    const endingAdminId = findClientAdminId(ws);
                    const endingAdmin = endingAdminId ? clients.get(endingAdminId) : null;
                    
                    if (endingAdminId) {
                        updateAdminStatus(endingAdminId, 'available', null);
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
                    if (duration > 0 && message.userId && !ADMIN_IDS.includes(message.userId)) {
                        console.log(`💾 KREDİ DÜŞÜRME İŞLEMİ BAŞLIYOR:`);
                        console.log(`   - Kullanıcı: ${message.userId}`);
                        console.log(`   - Süre: ${duration} saniye`);
                        console.log(`   - Düşecek Kredi: ${creditsUsed} dakika`);
                        console.log(`   - Admin: ${endingAdmin ? endingAdmin.name : 'Unknown'}`);
                        
                        const saveResult = await saveCallToDatabase({
                            userId: message.userId,
                            adminId: endingAdminId || message.targetId || 'ADMIN_UNKNOWN',
                            adminName: endingAdmin ? endingAdmin.name : 'Unknown Admin',
                            duration: duration,
                            creditsUsed: creditsUsed,
                            endReason: message.endedBy === 'admin' ? 'admin_ended' : 'customer_ended'
                        });
                        
                        if (saveResult.success) {
                            console.log(`✅ KREDİ DÜŞÜRME BAŞARILI:`);
                            console.log(`   - Eski Kredi: ${saveResult.oldCredits}`);
                            console.log(`   - Yeni Kredi: ${saveResult.newCredits}`);
                            console.log(`   - Düşen: ${saveResult.creditsUsed}`);
                            
                            // 🔥 YENİ: TÜM CLIENT'LARA GÜNCEL KREDİYİ GÖNDER
                            const allClients = Array.from(clients.values());
                            allClients.forEach(client => {
                                if (client.ws.readyState === WebSocket.OPEN) {
                                    if (client.userType === 'admin') {
                                        // Admin'lere detaylı kredi update
                                        client.ws.send(JSON.stringify({
                                            type: 'auto-credit-update',
                                            userId: message.userId,
                                            creditsUsed: creditsUsed,
                                            newCredits: saveResult.newCredits,
                                            oldCredits: saveResult.oldCredits,
                                            duration: duration,
                                            adminName: endingAdmin ? endingAdmin.name : 'Unknown Admin',
                                            source: 'call_ended'
                                        }));
                                        console.log(`📨 Admin'e kredi güncellemesi gönderildi: ${client.id}`);
                                    } else if (client.id === message.userId && client.userType === 'customer') {
                                        // İlgili müşteriye kredi update
                                        client.ws.send(JSON.stringify({
                                            type: 'credit-update',
                                            credits: saveResult.newCredits,
                                            creditsUsed: creditsUsed,
                                            duration: duration,
                                            source: 'call_ended'
                                        }));
                                        console.log(`📨 Müşteriye kredi güncellemesi gönderildi: ${message.userId}`);
                                    }
                                }
                            });
                        } else {
                            console.log(`❌ KREDİ DÜŞÜRME HATASI: ${saveResult.error}`);
                            // Hata durumunda admin'lere bildir
                            const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
                            adminClients.forEach(client => {
                                if (client.ws.readyState === WebSocket.OPEN) {
                                    client.ws.send(JSON.stringify({
                                        type: 'credit-error',
                                        userId: message.userId,
                                        error: saveResult.error,
                                        message: 'Kredi düşürme işleminde hata oluştu!'
                                    }));
                                }
                            });
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
                        console.log(`📱 Müşteriye kredi güncelleme bildirimi: ${message.userId} -> ${message.newCredits} dk`);
