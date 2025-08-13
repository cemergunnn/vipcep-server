const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');

// PostgreSQL bağlantısı - Railway için güncellenmiş
const { Pool } = require('pg');

// DÜZELTME 4: Database connection pool ayarları
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,                    // Maximum pool size
    idleTimeoutMillis: 30000,   // Connection idle timeout
    connectionTimeoutMillis: 2000, // Connection timeout
    keepAlive: true,
    statement_timeout: 10000    // Statement timeout
});

console.log('🔗 Database URL:', process.env.DATABASE_URL ? 'FOUND' : 'NOT FOUND');
console.log('🌐 Environment:', process.env.NODE_ENV || 'development');

// Express app oluştur
const app = express();
const server = http.createServer(app);

// Port ayarı (Railway için)
const PORT = process.env.PORT || 8080;

// DÜZELTME 3: CORS güvenlik yapılandırması
const corsOptions = {
    origin: process.env.NODE_ENV === 'production' 
        ? function (origin, callback) {
            // Railway deployment için origin kontrolü
            const allowedOrigins = [
                /\.railway\.app$/,
                /localhost/,
                /127\.0\.0\.1/
            ];
            
            if (!origin || allowedOrigins.some(pattern => pattern.test && pattern.test(origin) || pattern === origin)) {
                callback(null, true);
            } else {
                callback(new Error('CORS policy violation'));
            }
        }
        : ['http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:8080'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('.'));

// WebSocket server
const wss = new WebSocket.Server({ server });

// Global değişkenler
const clients = new Map();
let callHistory = [];

// DÜZELTME 4: Database connection error handling
pool.on('error', (err) => {
    console.error('💾 Unexpected database error:', err);
});

// DÜZELTME 5: Veritabanı başlatma - error handling eklendi
async function initDatabase() {
    let retries = 3;
    
    while (retries > 0) {
        try {
            console.log('🔧 Veritabanı kontrol ediliyor...');
            
            // Test connection
            await pool.query('SELECT NOW()');
            
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
            
            // Test kullanıcılarını kontrol et ve ekle
            const testUsers = [
                ['1234', 'Test Kullanıcı', 10],
                ['0005', 'VIP Müşteri', 25],
                ['0007', 'Cenk Zortu', 999],
                ['9999', 'Demo User', 5]
            ];

            for (const [id, name, credits] of testUsers) {
                try {
                    const existingUser = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
                    if (existingUser.rows.length === 0) {
                        await pool.query(`
                            INSERT INTO approved_users (id, name, credits) 
                            VALUES ($1, $2, $3)
                        `, [id, name, credits]);
                        console.log(`📝 Test kullanıcısı eklendi: ${id} - ${name} (${credits} dk)`);
                    }
                } catch (userError) {
                    console.log(`⚠️ Test kullanıcısı eklenemedi ${id}: ${userError.message}`);
                }
            }
            
            break; // Success, exit retry loop
            
        } catch (error) {
            retries--;
            console.log(`❌ PostgreSQL bağlantı hatası (${3 - retries}/3): ${error.message}`);
            
            if (retries === 0) {
                console.log('💡 LocalStorage ile devam ediliyor...');
                break;
            }
            
            // Wait before retry
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
}

// DÜZELTME 5: Kullanıcı onaylı mı kontrol et - error handling
async function isUserApproved(userId, userName) {
    try {
        // Input validation
        if (!userId || typeof userId !== 'string' || !/^\d{4}$/.test(userId)) {
            return { approved: false, reason: 'Geçersiz ID formatı' };
        }
        
        if (!userName || typeof userName !== 'string' || userName.trim().length < 2) {
            return { approved: false, reason: 'Geçersiz isim formatı' };
        }
        
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
        console.error('💾 PostgreSQL kullanıcı kontrol hatası:', error.message);
        return { approved: false, reason: 'Sistem hatası. Lütfen tekrar deneyin.' };
    }
}

// DÜZELTME 5: Onaylı kullanıcı kaydetme - error handling
async function saveApprovedUser(userId, userName, credits = 0) {
    try {
        // Input validation
        if (!userId || !/^\d{4}$/.test(userId)) {
            throw new Error('Geçersiz ID formatı');
        }
        
        if (!userName || userName.trim().length < 2) {
            throw new Error('Geçersiz isim');
        }
        
        if (typeof credits !== 'number' || credits < 0) {
            throw new Error('Geçersiz kredi miktarı');
        }
        
        const result = await pool.query(`
            INSERT INTO approved_users (id, name, credits, created_at) 
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
            ON CONFLICT (id) 
            DO UPDATE SET name = $2, credits = $3, status = 'active'
            RETURNING *
        `, [userId, userName.trim(), credits]);
        
        console.log(`✅ Kullanıcı kaydedildi: ${userName} (${userId}) - ${credits} kredi`);
        return result.rows[0];
    } catch (error) {
        console.error('💾 PostgreSQL kullanıcı kaydetme hatası:', error.message);
        throw error;
    }
}

// DÜZELTME 5: Kredi güncelleme - error handling
async function updateUserCredits(userId, newCredits, reason = 'Manuel güncelleme') {
    try {
        if (!userId || !/^\d{4}$/.test(userId)) {
            throw new Error('Geçersiz kullanıcı ID');
        }
        
        if (typeof newCredits !== 'number' || newCredits < 0) {
            throw new Error('Geçersiz kredi miktarı');
        }
        
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
        console.error('💾 PostgreSQL kredi güncelleme hatası:', error.message);
        throw error;
    }
}

// DÜZELTME 5: Arama kayıtlarını veritabanına kaydet - error handling
async function saveCallToDatabase(callData) {
    const client = await pool.connect();
    
    try {
        console.log('💾 Arama veritabanına kaydediliyor:', callData);
        
        const { userId, adminId, duration, creditsUsed, endReason } = callData;
        
        // Input validation
        if (!userId || !/^\d{4}$/.test(userId)) {
            throw new Error('Geçersiz kullanıcı ID');
        }
        
        if (typeof duration !== 'number' || duration < 0) {
            throw new Error('Geçersiz süre');
        }
        
        if (typeof creditsUsed !== 'number' || creditsUsed < 0) {
            throw new Error('Geçersiz kredi miktarı');
        }
        
        // Önce kullanıcının mevcut kredisini al
        const userResult = await client.query('SELECT * FROM approved_users WHERE id = $1', [userId]);
        
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
        await client.query('BEGIN');
        
        try {
            // Call history kaydet
            await client.query(`
                INSERT INTO call_history (user_id, admin_id, duration, credits_used, call_time, end_reason)
                VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, $5)
            `, [userId, adminId || 'ADMIN001', duration, creditsUsed, endReason || 'normal']);
            
            // Kullanıcı kredi ve istatistiklerini güncelle
            await client.query(`
                UPDATE approved_users 
                SET credits = $1, total_calls = $2, last_call = CURRENT_TIMESTAMP 
                WHERE id = $3
            `, [newCredits, newTotalCalls, userId]);
            
            // Credit transaction kaydet
            if (creditsUsed > 0) {
                await client.query(`
                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                    VALUES ($1, $2, $3, $4, $5)
                `, [userId, 'call', -creditsUsed, newCredits, `Görüşme: ${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}`]);
            }
            
            await client.query('COMMIT');
            
            console.log(`✅ KREDİ BAŞARIYLA DÜŞTÜ: ${userId} -> ${oldCredits} -> ${newCredits} (${creditsUsed} düştü)`);
            return { success: true, newCredits, creditsUsed, oldCredits };
            
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        }
        
    } catch (error) {
        console.error('💾 PostgreSQL arama kayıt/kredi düşme hatası:', error.message);
        return { success: false, error: error.message };
    } finally {
        client.release();
    }
}

// WebSocket bağlantı işleyicisi
wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';
    console.log('🔗 Yeni bağlantı:', clientIP);

    // DÜZELTME 5: Error handling eklendi
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
                    broadcastUserList();
                    break;

                case 'login-request':
                    try {
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
                    } catch (loginError) {
                        console.error('❌ Login process error:', loginError);
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: 'Sistem hatası, lütfen tekrar deneyin.'
                        }));
                    }
                    break;

                case 'call-request':
                    console.log('📞 Müşteri → Admin arama talebi:', message.userId);
                    
                    const adminClient = Array.from(clients.values()).find(c => c.userType === 'admin');
                    if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                        adminClient.ws.send(JSON.stringify({
                            type: 'incoming-call',
                            userId: message.userId,
                            userName: message.userName,
                            credits: message.credits
                        }));
                        console.log('📞 Admin\'e arama bildirimi gönderildi');
                    } else {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Teknik destek şu anda müsait değil. Lütfen daha sonra tekrar deneyin.'
                        }));
                        console.log('❌ Admin bulunamadı, arama reddedildi');
                    }
                    break;

                case 'admin-call-request':
                    console.log('📞 Admin → Müşteri arama talebi:', message.adminId, '->', message.targetId);
                    
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
                    try {
                        console.log('📞 Görüşme sonlandırılıyor:', message.userId);
                        
                        const duration = message.duration || 0;
                        const creditsUsed = Math.ceil(duration / 60); // Yukarı yuvarlama
                        
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
                        if (duration > 0 && message.userId && message.userId !== 'ADMIN001') {
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
                                
                                // Tüm admin client'lara kredi güncelleme bildir
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
                    } catch (endCallError) {
                        console.error('❌ End call processing error:', endCallError);
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
            console.error('❌ Mesaj işleme hatası:', error.message);
        }
    });

    ws.on('close', () => {
        const client = findClientById(ws);
        console.log('👋 Kullanıcı ayrıldı:', client?.name || 'unknown');
        
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
        console.error('⚠️ WebSocket hatası:', error.message);
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

// DÜZELTME 5: Onaylı kullanıcıları getir - error handling
app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('💾 PostgreSQL kullanıcı listesi hatası:', error.message);
        res.status(500).json({ error: 'Kullanıcı listesi alınamadı', details: error.message });
    }
});

// DÜZELTME 5: Yeni onaylı kullanıcı ekle - input validation
app.post('/api/approved-users', async (req, res) => {
    try {
        const { id, name, credits = 0 } = req.body;
        
        // Input validation
        if (!id || typeof id !== 'string' || id.length !== 4 || !/^\d{4}$/.test(id)) {
            return res.status(400).json({ error: 'ID 4 haneli sayı olmalı' });
        }
        
        if (!name || typeof name !== 'string' || name.trim().length < 2) {
            return res.status(400).json({ error: 'Geçerli bir isim girin' });
        }
        
        if (typeof credits !== 'number' || credits < 0) {
            return res.status(400).json({ error: 'Kredi negatif olamaz' });
        }
        
        const user = await saveApprovedUser(id, name.trim(), credits);
        res.json({ success: true, user });
    } catch (error) {
        if (error.message.includes('duplicate key')) {
            res.status(400).json({ error: 'Bu ID zaten kullanımda' });
        } else {
            console.error('💾 PostgreSQL kullanıcı ekleme hatası:', error.message);
            res.status(500).json({ error: 'Kullanıcı eklenemedi', details: error.message });
        }
    }
});

// DÜZELTME 5: Onaylı kullanıcıyı sil - error handling
app.delete('/api/approved-users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        if (!id || !/^\d{4}$/.test(id)) {
            return res.status(400).json({ error: 'Geçersiz ID formatı' });
        }
        
        await pool.query('DELETE FROM approved_users WHERE id = $1', [id]);
        console.log(`🗑️ Kullanıcı silindi: ${id}`);
        res.json({ success: true });
    } catch (error) {
        console.error('💾 PostgreSQL kullanıcı silme hatası:', error.message);
        res.status(500).json({ error: 'Kullanıcı silinemedi', details: error.message });
    }
});

// DÜZELTME 5: Kullanıcı kredisini güncelle - input validation
app.post('/api/approved-users/:id/credits', async (req, res) => {
    try {
        const { id } = req.params;
        const { credits, reason } = req.body;
        
        if (!id || !/^\d{4}$/.test(id)) {
            return res.status(400).json({ error: 'Geçersiz ID formatı' });
        }
        
        if (typeof credits !== 'number' || credits < 0) {
            return res.status(400).json({ error: 'Kredi negatif olamaz' });
        }
        
        const newCredits = await updateUserCredits(id, credits, reason || 'Admin güncelleme');
        res.json({ success: true, credits: newCredits });
    } catch (error) {
        console.error('💾 PostgreSQL kredi güncelleme hatası:', error.message);
        res.status(500).json({ error: 'Kredi güncellenemedi', details: error.message });
    }
});

// DÜZELTME 5: Arama geçmişini getir - error handling
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
        console.error('💾 PostgreSQL arama geçmişi hatası:', error.message);
        res.status(500).json({ error: 'Arama geçmişi alınamadı', details: error.message });
    }
});

// DÜZELTME 5: İstatistikleri getir - error handling
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
        console.error('💾 PostgreSQL istatistik hatası:', error.message);
        res.status(500).json({ 
            error: 'İstatistikler alınamadı', 
            details: error.message,
            // Fallback values
            totalUsers: 0,
            totalCalls: 0, 
            totalCredits: 0,
            todayCalls: 0,
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length
        });
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
        memory: process.memoryUsage(),
        version: process.version
    });
});

// Ana sayfa
app.get('/', (req, res) => {
    const host = req.get('host');
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🎯 VIPCEP Server</title>
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
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎯 VIPCEP Server</h1>
                <p style="font-size: 18px; margin: 10px 0;">Voice IP Communication Emergency Protocol</p>
                <p style="font-size: 14px; opacity: 0.9;">Mobil Cihaz Teknik Danışmanlık Sistemi</p>
            </div>
            
            <div class="links">
                <div class="link-card">
                    <h3>👨‍💼 Admin Panel</h3>
                    <p>Teknik servis yönetim sistemi</p>
                    <p style="font-size: 12px; color: #64748b;">Kullanıcı yönetimi, arama kontrolü, kredi sistemi</p>
                    <a href="/admin-panel.html">Admin Panel'e Git →</a>
                </div>
                <div class="link-card">
                    <h3>📱 Müşteri Uygulaması</h3>
                    <p>Sesli danışmanlık uygulaması</p>
                    <p style="font-size: 12px; color: #64748b;">Teknik destek almak için</p>
                    <a href="/costumer-app.html">Müşteri Uygulaması →</a>
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
                        <div class="status-value">✅</div>
                        <div>Sistem Durumu</div>
                    </div>
                    <div class="status-item">
                        <div class="status-value">${process.env.DATABASE_URL ? '✅' : '❌'}</div>
                        <div>Veritabanı</div>
                    </div>
                    <div class="status-item">
                        <div class="status-value">${PORT}</div>
                        <div>Port</div>
                    </div>
                </div>
                <p style="margin-top: 15px;"><strong>WebSocket URL:</strong> wss://${host}</p>
                <p><strong>Railway Deploy:</strong> ${process.env.RAILWAY_ENVIRONMENT || 'Local'}</p>
                <p><strong>Node Version:</strong> ${process.version}</p>
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
                    <li><strong>ID:</strong> 9999 | <strong>Ad:</strong> Demo User | <strong>Kredi:</strong> 5 dk</li>
                </ul>
            </div>

            <div style="background: #dcfce7; padding: 15px; border-radius: 8px; margin-top: 20px; border-left: 4px solid #22c55e;">
                <h4>✅ Düzeltilen Hatalar:</h4>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>✅ Dinamik WebSocket URL yapılandırması</li>
                    <li>✅ Express 4.x sürümüne downgrade</li>
                    <li>✅ CORS güvenlik ayarları</li>
                    <li>✅ Database connection pool optimizasyonu</li>
                    <li>✅ Kapsamlı error handling</li>
                    <li>✅ WebRTC ICE candidate race condition düzeltmesi</li>
                    <li>✅ Memory leak önleme (timer cleanup)</li>
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

app.get('/costumer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'costumer-app.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).send(`
        <h1>404 - Sayfa Bulunamadı</h1>
        <p><a href="/">Ana sayfaya dön</a></p>
    `);
});

// DÜZELTME 5: Error handlers
app.use((error, req, res, next) => {
    console.error('❌ Express error:', error);
    res.status(500).json({ 
        error: 'Sunucu hatası', 
        message: process.env.NODE_ENV === 'development' ? error.message : 'Bilinmeyen hata'
    });
});

// Server'ı başlat
async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');
    console.log('🔍 Railway Environment:', process.env.RAILWAY_ENVIRONMENT || 'Local');
    
    // Veritabanını başlat
    await initDatabase();
    
    // HTTP Server'ı başlat
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server Çalışıyor!');
        console.log(`🔌 Port: ${PORT}`);
        console.log(`🌐 URL: http://0.0.0.0:${PORT}`);
        console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('📱 Uygulamalar:');
        console.log(` 👨‍💼 Admin paneli: /admin-panel.html`);
        console.log(` 📱 Müşteri uygulaması: /costumer-app.html`);
        console.log('');
        console.log('✅ Düzeltilen Hatalar:');
        console.log(' ✅ Dinamik WebSocket URL');
        console.log(' ✅ Express 4.x downgrade');
        console.log(' ✅ CORS güvenlik');
        console.log(' ✅ Database pool');
        console.log(' ✅ Error handling');
        console.log(' ✅ ICE candidate fix');
        console.log(' ✅ Memory leak prevention');
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('📞 WhatsApp: +90 537 479 24 03');
        console.log('✅ Sistem hazır - Arama kabul ediliyor!');
        console.log('╔══════════════════════════════════════════════════════════╗');
    });
}

// DÜZELTME 5: Hata yakalama - improved error handling
process.on('uncaughtException', (error) => {
    console.error('❌ Yakalanmamış hata:', error.message);
    console.error('Stack:', error.stack);
    // Graceful shutdown yerine sadece log
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ İşlenmemiş promise reddi:', reason);
    console.error('Promise:', promise);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🔴 Server kapatılıyor...');
    
    // Close all WebSocket connections
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.close(1001, 'Server shutting down');
        }
    });
    
    // Close database pool
    try {
        await pool.end();
        console.log('💾 Database pool kapatıldı');
    } catch (error) {
        console.error('❌ Database pool kapatma hatası:', error);
    }
    
    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});

process.on('SIGINT', async () => {
    console.log('\n🔴 Ctrl+C ile kapatma işlemi başlatıldı...');
    process.emit('SIGTERM');
});

// Server'ı başlat
startServer().catch(error => {
    console.error('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
