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

// Multi-Admin System
const adminClients = new Map();
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

        // Call history tablosu
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

// Available admin bul - FIXED SYNTAX
function findAvailableAdmin() {
    const admins = Array.from(clients.values())
        .filter(c => c.userType === 'admin' && ADMIN_IDS.includes(c.id))
        .sort((a, b) => {
            // Priority: available > busy > offline
            let priorityA = 1;
            if (a.callStatus === 'available') priorityA = 3;
            else if (a.callStatus === 'busy') priorityA = 2;
            
            let priorityB = 1;
            if (b.callStatus === 'available') priorityB = 3;
            else if (b.callStatus === 'busy') priorityB = 2;
            
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
                    // Multi-admin support
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
                    
                    // Smart admin routing
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
                            
                            // Tüm client'lara güncel krediyi gönder
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
        } catch (error) {
            console.log('❌ Mesaj işleme hatası:', error.message);
        }
    });

    ws.on('close', () => {
        const client = findClientById(ws);
        console.log('👋 Kullanıcı ayrıldı:', client?.name || 'unknown');
        
        // Admin ise status güncellemesi yap
        if (client && client.userType === 'admin') {
            console.log(`👑 Admin ayrıldı: ${client.name}`);
            // Admin offline olduğunda diğer admin'lere bildir
            setTimeout(() => {
                broadcastAdminStatusUpdate();
            }, 1000);
        }
        
        // Client'ı kaldır
        for (const [key, clientData] of clients.entries()) {
            if (clientData.ws === ws) {
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

// Helper functions
function findClientById(ws) {
    for (const client of clients.values()) {
        if (client.ws === ws) {
            return client;
        }
    }
    return null;
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
        callStatus: client.callStatus || (client.userType === 'admin' ? 'available' : 'customer'),
        registeredAt: client.registeredAt,
        online: client.online,
        currentCall: client.currentCall
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
app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı listesi hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/approved-users', async (req, res) => {
    try {
        const { id, name, credits = 0 } = req.body;
        const adminName = req.headers['x-admin-name'] || 'Unknown Admin';
        
        if (!id || !name) {
            return res.status(400).json({ error: 'ID ve isim gerekli' });
        }
        
        if (!/^\d{4}$/.test(id)) {
            return res.status(400).json({ error: 'ID 4 haneli sayı olmalı' });
        }
        
        const user = await saveApprovedUser(id, name, credits, adminName);
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

app.delete('/api/approved-users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const adminName = req.headers['x-admin-name'] || 'Unknown Admin';
        
        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description, admin_name)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [id, 'user_deleted', 0, 0, `Kullanıcı silindi: ${adminName} tarafından`, adminName]);
        
        await pool.query('DELETE FROM approved_users WHERE id = $1', [id]);
        console.log(`🗑️ Kullanıcı silindi: ${id} (${adminName} tarafından)`);
        res.json({ success: true });
    } catch (error) {
        console.log('💾 PostgreSQL kullanıcı silme hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/approved-users/:id/credits', async (req, res) => {
    try {
        const { id } = req.params;
        const { credits, reason } = req.body;
        const adminName = req.headers['x-admin-name'] || 'Unknown Admin';
        
        const newCredits = await updateUserCredits(id, credits, reason, adminName);
        res.json({ success: true, credits: newCredits });
    } catch (error) {
        console.log('💾 PostgreSQL kredi güncelleme hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

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

app.get('/api/stats', async (req, res) => {
    try {
        const { adminId } = req.query;
        
        const totalUsers = await pool.query('SELECT COUNT(*) FROM approved_users');
        const totalCalls = await pool.query('SELECT COUNT(*) FROM call_history');
        const totalCredits = await pool.query('SELECT SUM(credits) FROM approved_users');
        
        let todayCalls, adminTodayCalls = 0;
        
        if (adminId && ADMIN_IDS.includes(adminId)) {
            const adminCallsResult = await pool.query(
                "SELECT COUNT(*) FROM call_history WHERE DATE(call_time) = CURRENT_DATE AND admin_id = $1", 
                [adminId]
            );
            adminTodayCalls = parseInt(adminCallsResult.rows[0].count);
            todayCalls = adminTodayCalls;
        } else {
            const totalCallsResult = await pool.query(
                "SELECT COUNT(*) FROM call_history WHERE DATE(call_time) = CURRENT_DATE"
            );
            todayCalls = parseInt(totalCallsResult.rows[0].count);
        }
        
        const onlineCustomers = Array.from(clients.values()).filter(c => c.userType === 'customer').length;
        const onlineAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin').length;
        
        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalCalls: parseInt(totalCalls.rows[0].count),
            totalCredits: parseInt(totalCredits.rows[0].sum || 0),
            todayCalls: todayCalls,
            onlineUsers: onlineCustomers,
            onlineAdmins: onlineAdmins,
            adminTodayCalls: adminTodayCalls,
            availableAdmins: Array.from(clients.values())
                .filter(c => c.userType === 'admin' && c.callStatus === 'available').length
        });
    } catch (error) {
        console.log('💾 PostgreSQL istatistik hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => {
    const adminStats = Array.from(clients.values()).filter(c => c.userType === 'admin');
    
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        clients: clients.size,
        database: process.env.DATABASE_URL ? 'Connected' : 'Offline',
        admins: {
            total: adminStats.length,
            available: adminStats.filter(a => a.callStatus === 'available').length,
            busy: adminStats.filter(a => a.callStatus === 'busy').length,
            list: adminStats.map(a => ({ id: a.id, name: a.name, status: a.callStatus }))
        }
    });
});

app.get('/', (req, res) => {
    const host = req.get('host');
    const adminStats = Array.from(clients.values()).filter(c => c.userType === 'admin');
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🎯 VIPCEP Server - Multi Admin</title>
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
                .admin-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }
                .admin-card {
                    background: rgba(255,255,255,0.8);
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid #22c55e;
                }
                .admin-status {
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 12px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .status-available { background: #dcfce7; color: #166534; }
                .status-busy { background: #fef2f2; color: #dc2626; }
                .status-offline { background: #f1f5f9; color: #64748b; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎯 VIPCEP Server - Multi Admin</h1>
                <p>Çoklu Admin Destekli Teknik Danışmanlık Sistemi</p>
            </div>
            
            <div style="background: #eff6ff; padding: 20px; border-radius: 12px; margin: 20px 0;">
                <h3>👑 Admin Durumu</h3>
                <div class="admin-grid">
                    ${adminStats.map(admin => `
                        <div class="admin-card">
                            <strong>${admin.name}</strong><br>
                            <span class="admin-status status-${admin.callStatus || 'offline'}">
                                ${admin.callStatus === 'available' ? '🟢 Müsait' : 
                                  admin.callStatus === 'busy' ? '🔴 Meşgul' : '⚫ Çevrimdışı'}
                            </span>
                            <div style="font-size: 11px; color: #64748b; margin-top: 5px;">
                                ID: ${admin.id}<br>
                                ${admin.currentCall ? `Arama: ${admin.currentCall}` : 'Beklemede'}
                            </div>
                        </div>
                    `).join('')}
                    ${adminStats.length === 0 ? '<div style="text-align: center; color: #64748b; grid-column: 1/-1;">Henüz admin bağlanmadı</div>' : ''}
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;">
                <div style="background: white; padding: 20px; border-radius: 12px; text-align: center;">
                    <h3>👨‍💼 Admin Panel</h3>
                    <p>Multi-admin teknik servis yönetim sistemi</p>
                    <a href="/admin-panel.html" style="color: #2563eb; text-decoration: none; font-weight: bold;">
                        Admin Panel'e Git →
                    </a>
                </div>
                <div style="background: white; padding: 20px; border-radius: 12px; text-align: center;">
                    <h3>📱 Müşteri Uygulaması</h3>
                    <p>Smart routing ile otomatik yönlendirme</p>
                    <a href="/customer-app.html" style="color: #2563eb; text-decoration: none; font-weight: bold;">
                        Müşteri Uygulaması →
                    </a>
                </div>
            </div>

            <div style="background: #fef3c7; padding: 15px; border-radius: 8px; border-left: 4px solid #f59e0b;">
                <h4>🚀 Multi-Admin Özellikleri:</h4>
                <ul>
                    <li><strong>Smart Routing:</strong> Aramalar müsait admin'e otomatik yönlendiriliyor</li>
                    <li><strong>Load Balancing:</strong> İş yükü admin'ler arasında eşit dağıtılıyor</li>
                    <li><strong>Real-time Status:</strong> Admin durumları anlık takip ediliyor</li>
                </ul>
                
                <h4>🔐 Admin Girişleri:</h4>
                <ul>
                    <li><strong>Cem Usta:</strong> cem2025</li>
                    <li><strong>Cenk Usta:</strong> cenk2025</li>
                </ul>
            </div>
        </body>
        </html>
    `);
});

app.get('/admin-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get('/customer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

app.use((req, res) => {
    res.status(404).send(`
        <h1>404 - Sayfa Bulunamadı</h1>
        <p><a href="/">Ana sayfaya dön</a></p>
    `);
});

async function startServer() {
    console.log('🚀 VIPCEP Multi-Admin Server Başlatılıyor...');
    console.log('🔐 Railway Environment:', process.env.RAILWAY_ENVIRONMENT || 'Local');
    
    await initDatabase();
    
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Multi-Admin Server Çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
        console.log(`🌐 URL: http://0.0.0.0:${PORT}`);
        console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log('');
        console.log('👑 Multi-Admin System:');
        console.log(` 🔐 Cem Usta: cem2025`);
        console.log(` 🔐 Cenk Usta: cenk2025`);
        console.log(` 🎯 Smart Call Routing: ENABLED`);
        console.log(` 📊 Real-time Admin Status: ENABLED`);
        console.log('');
        console.log('✅ Multi-Admin Sistem Hazır!');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
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
    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});

startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
