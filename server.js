const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');

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

// Güvenlik yapılandırması - TAHMİN EDİLEMEZ URL'LER
const SECURITY_CONFIG = {
    // Random URL paths - Her deploy'da değişir
    SUPER_ADMIN_PATH: '/panel-' + crypto.randomBytes(8).toString('hex'),
    NORMAL_ADMIN_PATH: '/desk-' + crypto.randomBytes(8).toString('hex'),
    CUSTOMER_PATH: '/app-' + crypto.randomBytes(8).toString('hex'),
    
    // Session secret
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    
    // 2FA ayarları
    TOTP_ISSUER: 'VIPCEP System',
    TOTP_WINDOW: 2 // ±2 time step tolerance
};

console.log('🔐 GÜVENLİK URL\'LERİ OLUŞTURULDU:');
console.log(`🔴 Super Admin: ${SECURITY_CONFIG.SUPER_ADMIN_PATH}`);
console.log(`🟡 Normal Admin: ${SECURITY_CONFIG.NORMAL_ADMIN_PATH}`);
console.log(`🟢 Customer App: ${SECURITY_CONFIG.CUSTOMER_PATH}`);

// Session middleware ekle
app.use(session({
    secret: SECURITY_CONFIG.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// WebSocket server
const wss = new WebSocket.Server({ server });

// 🔥 ÇOKLU ARAMA SİSTEMİ - Global değişkenler
const clients = new Map();
const activeHeartbeats = new Map();
const activeCallAdmins = new Map();
const activeCalls = new Map();
const failedLogins = new Map();

// 🔥 YENİ: ÇOKLU ARAMA KUYRUK SİSTEMİ
const incomingCallQueue = new Map(); // callId -> callData
const callTimeouts = new Map(); // callId -> timeoutId
const MAX_QUEUE_SIZE = 5;
const CALL_TIMEOUT_DURATION = 30000; // 30 saniye

let callHistory = [];

// 2FA Secret key (production'da environment variable olmalı)
const SUPER_ADMIN_SECRET = process.env.SUPER_ADMIN_SECRET || 'VIPCEPTEST2024SECRET';

// 🔥 Heartbeat sistemi - Aktif aramaların kredi düşürmesini sağlar
const HEARTBEAT_INTERVAL = 60000; // 1 dakika = 1 kredi

// IP bazlı rate limiting
const rateLimitMap = new Map();

// 🔥 ÇOKLU ARAMA SİSTEMİ - Helper Functions

// Arama ID oluştur
function generateCallId() {
    return `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Arama kuyruğuna ekle
function addToCallQueue(callData) {
    // Kuyruk dolu mu kontrol et
    if (incomingCallQueue.size >= MAX_QUEUE_SIZE) {
        console.log(`⚠️ Arama kuyruğu dolu (${MAX_QUEUE_SIZE}), en eskisini kaldır`);
        
        // En eski aramayı bul ve kaldır
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
    
    // 30 saniye timeout ayarla
    const timeoutId = setTimeout(() => {
        console.log(`⏰ Arama timeout: ${callEntry.userName} (${callId})`);
        removeFromCallQueue(callId, 'timeout');
    }, CALL_TIMEOUT_DURATION);
    
    callTimeouts.set(callId, timeoutId);
    
    console.log(`📞 Arama kuyruğuna eklendi: ${callEntry.userName} (${callId}) - Kuyruk boyutu: ${incomingCallQueue.size}`);
    
    return callEntry;
}

// Aramayı kuyruktan çıkar
function removeFromCallQueue(callId, reason = 'manual') {
    const callData = incomingCallQueue.get(callId);
    if (!callData) {
        console.log(`⚠️ Silinecek arama bulunamadı: ${callId}`);
        return null;
    }
    
    // Timeout'u temizle
    const timeoutId = callTimeouts.get(callId);
    if (timeoutId) {
        clearTimeout(timeoutId);
        callTimeouts.delete(callId);
    }
    
    // Kuyruktan çıkar
    incomingCallQueue.delete(callId);
    
    console.log(`🗑️ Arama kuyruktan çıkarıldı: ${callData.userName} (${callId}) - Sebep: ${reason} - Kalan: ${incomingCallQueue.size}`);
    
    // Tüm adminlere güncel kuyruğu gönder
    broadcastCallQueueToAdmins();
    
    return callData;
}

// Arama kuyruğunu adminlere gönder
function broadcastCallQueueToAdmins() {
    const queueArray = Array.from(incomingCallQueue.values()).sort((a, b) => a.timestamp - b.timestamp);
    
    const message = JSON.stringify({
        type: 'call-queue-update',
        queue: queueArray,
        queueSize: queueArray.length
    });
    
    // Sadece müsait adminlere gönder
    const allAdminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
    const availableAdmins = allAdminClients.filter(adminClient => {
        return !activeCallAdmins.has(adminClient.uniqueId || adminClient.id);
    });
    
    availableAdmins.forEach(adminClient => {
        if (adminClient.ws.readyState === WebSocket.OPEN) {
            adminClient.ws.send(message);
        }
    });
    
    console.log(`📤 Arama kuyruğu ${availableAdmins.length} müsait admin'e gönderildi (${queueArray.length} arama)`);
}

// Belirli kullanıcının aramasını kuyruktan bul ve çıkar
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

// Admin aramayı kabul ettiğinde kuyruktan çıkar
function acceptCallFromQueue(callId, adminId) {
    const callData = incomingCallQueue.get(callId);
    if (!callData) {
        console.log(`⚠️ Kabul edilecek arama bulunamadı: ${callId}`);
        return null;
    }
    
    console.log(`✅ Arama kabul edildi: ${callData.userName} (${callId}) by ${adminId}`);
    
    // Bu aramayı kuyruktan çıkar
    removeFromCallQueue(callId, 'accepted');
    
    return callData;
}

// Tüm kuyruğu temizle (acil durum)
function clearAllCallQueue(reason = 'emergency') {
    console.log(`🚨 Tüm arama kuyruğu temizleniyor - Sebep: ${reason}`);
    
    // Tüm timeout'ları temizle
    for (const timeoutId of callTimeouts.values()) {
        clearTimeout(timeoutId);
    }
    
    callTimeouts.clear();
    incomingCallQueue.clear();
    
    // Adminlere boş kuyruk gönder
    broadcastCallQueueToAdmins();
}

// Authentication middleware
function requireSuperAuth(req, res, next) {
    if (req.session && req.session.superAdmin) {
        return next();
    }
    return res.status(401).json({ error: 'Super admin yetki gerekli' });
}

function requireNormalAuth(req, res, next) {
    if (req.session && (req.session.superAdmin || req.session.normalAdmin)) {
        return next();
    }
    return res.status(401).json({ error: 'Admin yetki gerekli' });
}

function requireAnyAuth(req, res, next) {
    if (req.session && (req.session.superAdmin || req.session.normalAdmin || req.session.customer)) {
        return next();
    }
    return res.status(401).json({ error: 'Yetki gerekli' });
}

// IP whitelist (opsiyonel - sadece belirli IP'lerden erişim)
const ALLOWED_IPS = process.env.ALLOWED_IPS ? process.env.ALLOWED_IPS.split(',') : [];

function checkIPWhitelist(req, res, next) {
    if (ALLOWED_IPS.length > 0) {
        const clientIP = req.ip || req.connection.remoteAddress;
        if (!ALLOWED_IPS.includes(clientIP)) {
            console.log(`🚫 IP engellendi: ${clientIP}`);
            return res.status(403).send('Erişim reddedildi');
        }
    }
    next();
}

// Rate limiting kontrolü - 5 denemeden sonra 30 dakika ban
async function checkRateLimit(ip, userType = 'customer') {
    try {
        // Son 30 dakikadaki başarısız girişleri kontrol et
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const failedAttempts = await pool.query(
            'SELECT COUNT(*) FROM failed_logins WHERE ip_address = $1 AND user_type = $2 AND attempt_time > $3',
            [ip, userType, thirtyMinutesAgo]
        );

        const count = parseInt(failedAttempts.rows[0].count);
        
        // Rate limit bilgilerini döndür
        return {
            allowed: count < 5,
            attempts: count,
            remaining: Math.max(0, 5 - count),
            resetTime: count >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null
        };
    } catch (error) {
        console.log('Rate limit kontrolü hatası:', error.message);
        return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
    }
}

// Başarısız giriş kaydet
async function recordFailedLogin(ip, userType = 'customer') {
    try {
        await pool.query(
            'INSERT INTO failed_logins (ip_address, user_type) VALUES ($1, $2)',
            [ip, userType]
        );
        
        // Güncel durumu kontrol et
        const rateStatus = await checkRateLimit(ip, userType);
        
        console.log(`🚫 Başarısız giriş: ${ip} (${userType}) - Kalan: ${rateStatus.remaining}`);
        
        return rateStatus;
    } catch (error) {
        console.log('Başarısız giriş kaydı hatası:', error.message);
        return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
    }
}

// TOTP Secret oluştur - DÜZELTMEsi: base32 yerine hex
function generateTOTPSecret() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

// TOTP doğrulama fonksiyonu - GERÇEK GOOGLE AUTHENTICATOR
function verifyTOTP(secret, token) {
    if (!secret || !token || token.length !== 6) return false;
    
    try {
        // Hex formatı kullan (base32 yerine)
        const secretBuffer = Buffer.from(secret, 'hex');
        
        // TOTP algoritması (RFC 6238)
        const timeStep = 30; // 30 saniye
        const currentTime = Math.floor(Date.now() / 1000 / timeStep);
        
        // ±window zaman penceresi kontrol et (clock skew için)
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
        console.log('TOTP doğrulama hatası:', error.message);
        return false;
    }
}

// TOTP QR kodu oluşturma - HEX formatı için manuel URL
function generateTOTPQR(username, secret) {
    // Google Authenticator için Base32 gerekli, hex'i base32'ye çevir
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const hexBuffer = Buffer.from(secret, 'hex');
    
    // Basit hex to base32 conversion (Google Authenticator için)
    let base32 = '';
    for (let i = 0; i < hexBuffer.length; i++) {
        base32 += hexBuffer[i].toString(16).padStart(2, '0');
    }
    
    // Doğrudan secret'i base32 formatına çevir
    const base32Secret = Buffer.from(secret, 'hex').toString('base64').replace(/=/g, '');
    
    const serviceName = encodeURIComponent(SECURITY_CONFIG.TOTP_ISSUER);
    const accountName = encodeURIComponent(username);
    const otpauthURL = `otpauth://totp/${serviceName}:${accountName}?secret=${secret}&issuer=${serviceName}`;
    return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthURL)}`;
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
                end_reason VARCHAR(50) DEFAULT 'normal',
                connection_lost BOOLEAN DEFAULT FALSE
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

        // Admins tablosu
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

        // KVKK onayları tablosu
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

        // Failed logins tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                ip_address INET NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_type VARCHAR(20) DEFAULT 'customer'
            )
        `);

        console.log('✅ PostgreSQL tabloları kontrol edildi');
        
        // Super admin oluştur (eğer yoksa)
        const superAdminCheck = await pool.query('SELECT * FROM admins WHERE role = $1', ['super']);
        if (superAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
            const totpSecret = generateTOTPSecret();
            await pool.query(`
                INSERT INTO admins (username, password_hash, role, totp_secret) 
                VALUES ($1, $2, $3, $4)
            `, ['superadmin', hashedPassword, 'super', totpSecret]);
            console.log('🔐 Super admin oluşturuldu: superadmin/admin123');
            console.log('🔐 TOTP Secret:', totpSecret);
        }

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

        // Test normal admin oluştur
        const normalAdminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin1']);
        if (normalAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('password123').digest('hex');
            await pool.query(`
                INSERT INTO admins (username, password_hash, role) 
                VALUES ($1, $2, $3)
            `, ['admin1', hashedPassword, 'normal']);
            console.log('👤 Normal admin oluşturuldu: admin1/password123');
        }

    } catch (error) {
        console.log('❌ PostgreSQL bağlantı hatası:', error.message);
        console.log('💡 LocalStorage ile devam ediliyor...');
    }
}

// KVKK onayı kontrol et
async function checkKVKKConsent(ip, userAgent) {
    try {
        const consentHash = crypto.createHash('sha256').update(ip + userAgent).digest('hex');
        const result = await pool.query('SELECT * FROM kvkk_consents WHERE consent_hash = $1', [consentHash]);
        return result.rows.length > 0;
    } catch (error) {
        console.log('KVKK kontrol hatası:', error.message);
        return false;
    }
}

// KVKK onayı kaydet
async function saveKVKKConsent(ip, userAgent) {
    try {
        const consentHash = crypto.createHash('sha256').update(ip + userAgent).digest('hex');
        await pool.query(`
            INSERT INTO kvkk_consents (consent_hash, ip_address, user_agent) 
            VALUES ($1, $2, $3)
            ON CONFLICT (consent_hash) DO NOTHING
        `, [consentHash, ip, userAgent]);
        console.log(`📋 KVKK onayı kaydedildi: ${ip.substring(0, 10)}...`);
        return true;
    } catch (error) {
        console.log('KVKK kayıt hatası:', error.message);
        return false;
    }
}

// Admin doğrulama
async function authenticateAdmin(username, password) {
    try {
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        const result = await pool.query(
            'SELECT * FROM admins WHERE username = $1 AND password_hash = $2 AND is_active = TRUE',
            [username, hashedPassword]
        );
        
        if (result.rows.length > 0) {
            const admin = result.rows[0];
            // Last login güncelle
            await pool.query('UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [admin.id]);
            return admin;
        }
        return null;
    } catch (error) {
        console.log('Admin doğrulama hatası:', error.message);
        return null;
    }
}

// 🔥 YENİ: Heartbeat sistemi - Internet kesintilerinde kredi düşürmesi
function startHeartbeat(userId, adminId, callKey) {
    console.log(`💗 Heartbeat başlatıldı: ${callKey}`);
    
    const heartbeat = setInterval(async () => {
        try {
            // Kullanıcının kredisini kontrol et ve düş
            const userResult = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
            if (userResult.rows.length > 0) {
                const currentCredits = userResult.rows[0].credits;
                
                if (currentCredits <= 0) {
                    console.log(`💳 Kredi bitti, arama sonlandırılıyor: ${userId}`);
                    stopHeartbeat(callKey, 'no_credits');
                    return;
                }
                
                const newCredits = Math.max(0, currentCredits - 1);
                await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);
                
                // Credit transaction kaydet
                await pool.query(`
                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                    VALUES ($1, $2, $3, $4, $5)
                `, [userId, 'heartbeat', -1, newCredits, `Arama dakikası (Heartbeat sistem)`]);
                
                console.log(`💗 Heartbeat kredi düştü: ${userId} -> ${newCredits} dk`);
                
                // Müşteriye ve admin'lere kredi güncellemesi gönder
                broadcastCreditUpdate(userId, newCredits, 1);
            }
        } catch (error) {
            console.log(`❌ Heartbeat hatası ${userId}:`, error.message);
        }
    }, HEARTBEAT_INTERVAL);
    
    activeHeartbeats.set(callKey, heartbeat);
}

function stopHeartbeat(callKey, reason = 'normal') {
    const heartbeat = activeHeartbeats.get(callKey);
    if (heartbeat) {
        clearInterval(heartbeat);
        activeHeartbeats.delete(callKey);
        console.log(`💗 Heartbeat durduruldu: ${callKey} - ${reason}`);
        
        // Aramanın sonlandırıldığını tüm ilgili taraflara bildir
        const [userId, adminId] = callKey.split('-');
        broadcastCallEnd(userId, adminId, reason);
    }
}

// Kredi güncellemesini tüm ilgili taraflara gönder
function broadcastCreditUpdate(userId, newCredits, creditsUsed) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'credit-update',
            credits: newCredits,
            creditsUsed: creditsUsed,
            source: 'heartbeat'
        }));
    }
    
    // Admin'lere güncellenmiş kredi gönder
    const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
    adminClients.forEach(client => {
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
}

// Arama sonlandırma bildirimini gönder
function broadcastCallEnd(userId, adminId, reason) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'call-ended',
            reason: reason,
            endedBy: 'system'
        }));
    }
    
    const adminClient = clients.get(adminId);
    if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
        adminClient.ws.send(JSON.stringify({
            type: 'call-ended',
            userId: userId,
            reason: reason,
            endedBy: 'system'
        }));
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

// Ana sayfa - GÜVENLİ GİRİŞ SİSTEMİ
app.get('/', checkIPWhitelist, (req, res) => {
    // Eğer zaten giriş yapmışsa yönlendir
    if (req.session.superAdmin) {
        return res.redirect(SECURITY_CONFIG.SUPER_ADMIN_PATH);
    }
    if (req.session.normalAdmin) {
        return res.redirect(SECURITY_CONFIG.NORMAL_ADMIN_PATH);
    }
    
    // Ana giriş sayfası göster
    const host = req.get('host');
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🔐 VIPCEP Güvenli Giriş</title>
            <meta charset="UTF-8">
            <style>
                body { 
                    font-family: system-ui; 
                    background: linear-gradient(135deg, #1e293b, #334155); 
                    color: white; 
                    display: flex; 
                    align-items: center; 
                    justify-content: center; 
                    min-height: 100vh; 
                    margin: 0;
                }
                .login-container { 
                    background: rgba(255,255,255,0.1); 
                    padding: 40px; 
                    border-radius: 16px; 
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255,255,255,0.2);
                    max-width: 400px;
                    width: 100%;
                }
                .form-group { margin-bottom: 20px; }
                .form-input { 
                    width: 100%; 
                    padding: 14px; 
                    border: 2px solid rgba(255,255,255,0.2); 
                    border-radius: 8px; 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    font-size: 16px;
                    box-sizing: border-box;
                }
                .form-input::placeholder { color: rgba(255,255,255,0.6); }
                .btn { 
                    width: 100%; 
                    padding: 14px; 
                    background: linear-gradient(135deg, #dc2626, #b91c1c); 
                    color: white; 
                    border: none; 
                    border-radius: 8px; 
                    font-weight: bold; 
                    cursor: pointer; 
                    font-size: 16px;
                    margin-bottom: 10px;
                    transition: all 0.3s ease;
                }
                .btn:hover { opacity: 0.9; transform: translateY(-1px); }
                .btn:disabled { opacity: 0.6; cursor: not-allowed; }
                .btn-customer { background: linear-gradient(135deg, #059669, #047857); }
                .error { 
                    color: #fca5a5; 
                    text-align: center; 
                    margin-top: 15px; 
                    padding: 15px; 
                    border-radius: 8px; 
                    display: none; 
                    background: rgba(239, 68, 68, 0.1);
                    border: 1px solid rgba(239, 68, 68, 0.3);
                }
                .title { text-align: center; margin-bottom: 30px; color: #dc2626; font-size: 24px; font-weight: bold; }
                .subtitle { text-align: center; margin-bottom: 20px; color: rgba(255,255,255,0.8); font-size: 14px; }
                .rate-limit-severe {
                    background: linear-gradient(135deg, #dc2626, #b91c1c) !important;
                    animation: shake 0.5s ease-in-out !important;
                    border-color: #fca5a5 !important;
                }
                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-5px); }
                    75% { transform: translateX(5px); }
                }
                .success {
                    background: rgba(34, 197, 94, 0.2);
                    color: #86efac;
                    border: 1px solid rgba(34, 197, 94, 0.3);
                    padding: 15px;
                    border-radius: 8px;
                    margin-top: 15px;
                    font-size: 14px;
                    display: none;
                }
                #totpGroup { display: none; }
                .modal-overlay {
                    position: fixed;
                    top: 0; left: 0; right: 0; bottom: 0;
                    background: rgba(0,0,0,0.8);
                    display: none;
                    align-items: center;
                    justify-content: center;
                    z-index: 1000;
                }
                .modal {
                    background: white;
                    padding: 30px;
                    border-radius: 16px;
                    text-align: center;
                    color: #333;
                    max-width: 400px;
                    width: 90%;
                }
                .modal h3 { color: #dc2626; margin-bottom: 20px; }
                .modal img { margin: 20px 0; }
                .modal button {
                    background: #dc2626;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="title">🔐 VIPCEP</div>
                <div class="subtitle">Güvenli Giriş Sistemi</div>
                
                <div class="form-group">
                    <input type="text" id="username" class="form-input" placeholder="👤 Kullanıcı Adı">
                </div>
                <div class="form-group">
                    <input type="password" id="password" class="form-input" placeholder="🔑 Şifre">
                </div>
                <div class="form-group" id="totpGroup">
                    <input type="text" id="totpCode" class="form-input" placeholder="🔒 2FA Kodu (6 haneli)" maxlength="6">
                </div>
                
                <button class="btn" id="superBtn" onclick="adminLogin()">🔴 SUPER ADMİN GİRİŞİ</button>
                <button class="btn" id="normalBtn" onclick="normalAdminLogin()">🟡 ADMİN GİRİŞİ</button>
                <button class="btn btn-customer" onclick="window.location.href='${SECURITY_CONFIG.CUSTOMER_PATH}'">🟢 MÜŞTERİ UYGULAMASI</button>
                
                <div id="error" class="error"></div>
                <div id="success" class="success"></div>
                
                <div style="text-align: center; margin-top: 30px; font-size: 12px; color: rgba(255,255,255,0.5);">
                    VIPCEP Security v2.0 | ${host}
                </div>
            </div>
            
            <!-- 2FA QR Code Modal -->
            <div id="qrModal" class="modal-overlay">
                <div class="modal">
                    <h3>🔒 2FA Kurulumu</h3>
                    <p>Google Authenticator ile QR kodu tarayın:</p>
                    <img id="qrImage" src="" alt="QR Code">
                    <p style="font-size: 12px; word-break: break-all; margin: 10px 0;">
                        Manuel kod: <span id="manualCode"></span>
                    </p>
                    <button onclick="closeQRModal()">Tamam</button>
                </div>
            </div>
            
            <script>
                async function adminLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    const totpCode = document.getElementById('totpCode').value;
                    const btn = document.getElementById('superBtn');
                    
                    if (!username || !password) {
                        showError('Kullanıcı adı ve şifre gerekli!');
                        return;
                    }
                    
                    btn.disabled = true;
                    btn.textContent = '⏳ Giriş yapılıyor...';
                    
                    try {
                        const response = await fetch('/auth/super-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password, totpCode })
                        });
                        
                        const result = await response.json();
                        
                        if (result.success) {
                            showSuccess(result.message || 'Giriş başarılı!');
                            setTimeout(() => {
                                if (result.redirectUrl) {
                                    window.location.href = result.redirectUrl;
                                } else {
                                    window.location.href = '${SECURITY_CONFIG.SUPER_ADMIN_PATH}';
                                }
                            }, 1000);
                        } else if (result.requiresTOTP) {
                            document.getElementById('totpGroup').style.display = 'block';
                            
                            if (result.firstTimeSetup && result.qrCode) {
                                showQRCode(result.qrCode, result.secret);
                            }
                            
                            showError(result.error);
                        } else {
                            showError(result.error || 'Giriş başarısız!', result.remaining);
                        }
                    } catch (error) {
                        showError('Bağlantı hatası!');
                    } finally {
                        btn.disabled = false;
                        btn.textContent = '🔴 SUPER ADMİN GİRİŞİ';
                    }
                }
                
                async function normalAdminLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    const btn = document.getElementById('normalBtn');
                    
                    if (!username || !password) {
                        showError('Kullanıcı adı ve şifre gerekli!');
                        return;
                    }
                    
                    btn.disabled = true;
                    btn.textContent = '⏳ Giriş yapılıyor...';
                    
                    try {
                        const response = await fetch('/auth/admin-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password })
                        });
                        
                        const result = await response.json();
                        
                        if (result.success) {
                            showSuccess(result.message || 'Giriş başarılı!');
                            setTimeout(() => {
                                if (result.redirectUrl) {
                                    window.location.href = result.redirectUrl;
                                } else {
                                    window.location.href = '${SECURITY_CONFIG.NORMAL_ADMIN_PATH}';
                                }
                            }, 1000);
                        } else {
                            showError(result.error || 'Giriş başarısız!', result.remaining);
                        }
                    } catch (error) {
                        showError('Bağlantı hatası!');
                    } finally {
                        btn.disabled = false;
                        btn.textContent = '🟡 ADMİN GİRİŞİ';
                    }
                }
                
                function showError(message, remaining) {
                    const errorDiv = document.getElementById('error');
                    const successDiv = document.getElementById('success');
                    
                    successDiv.style.display = 'none';
                    
                    if (message.includes('Çok fazla') || remaining === 0) {
                        errorDiv.className = 'error rate-limit-severe';
                    } else if (remaining && remaining <= 2) {
                        errorDiv.style.background = 'linear-gradient(135deg, #f59e0b, #d97706)';
                        errorDiv.style.border = '2px solid #fbbf24';
                    } else {
                        errorDiv.className = 'error';
                        errorDiv.style.background = 'rgba(239, 68, 68, 0.1)';
                        errorDiv.style.border = '1px solid rgba(239, 68, 68, 0.3)';
                    }
                    
                    errorDiv.innerHTML = message.replace(/\\\\n/g, '<br>');
                    errorDiv.style.display = 'block';
                    
                    setTimeout(() => {
                        if (remaining === 0) return;
                        errorDiv.style.display = 'none';
                    }, 8000);
                }
                
                function showSuccess(message) {
                    const errorDiv = document.getElementById('error');
                    const successDiv = document.getElementById('success');
                    
                    errorDiv.style.display = 'none';
                    successDiv.textContent = message;
                    successDiv.style.display = 'block';
                }
                
                function showQRCode(qrUrl, secret) {
                    document.getElementById('qrImage').src = qrUrl;
                    document.getElementById('manualCode').textContent = secret;
                    document.getElementById('qrModal').style.display = 'flex';
                }
                
                function closeQRModal() {
                    document.getElementById('qrModal').style.display = 'none';
                }
                
                // Enter tuşu ile giriş
                document.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        const totpVisible = document.getElementById('totpGroup').style.display !== 'none';
                        if (totpVisible) {
                            adminLogin();
                        }
                    }
                });
            </script>
        </body>
        </html>
    `);
});

// Authentication API endpoints
app.post('/auth/super-login', async (req, res) => {
    const { username, password, totpCode } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    try {
        // Rate limiting kontrolü
        const rateStatus = await checkRateLimit(clientIP, 'super-admin');
        
        if (!rateStatus.allowed) {
            const resetTime = rateStatus.resetTime.toLocaleTimeString('tr-TR');
            return res.json({
                success: false,
                rateLimited: true,
                error: `Çok fazla başarısız deneme!\\n\\n⏰ ${resetTime} sonra tekrar deneyin.\\n📊 Toplam deneme: ${rateStatus.attempts}/5`,
                resetTime: rateStatus.resetTime,
                remaining: 0
            });
        }
        
        // Super admin doğrulaması
        const admin = await authenticateAdmin(username, password);
        
        if (admin && admin.role === 'super') {
            // 2FA kontrolü - ZORUNLU!
            if (!admin.totp_secret) {
                // İlk kez giriş - TOTP secret oluştur
                const newSecret = generateTOTPSecret();
                await pool.query(
                    'UPDATE admins SET totp_secret = $1 WHERE id = $2',
                    [newSecret, admin.id]
                );
                
                admin.totp_secret = newSecret;
                
                return res.json({
                    success: false,
                    requiresTOTP: true,
                    firstTimeSetup: true,
                    qrCode: generateTOTPQR(admin.username, newSecret),
                    secret: newSecret,
                    error: 'İlk kez giriş - 2FA kurulumu gerekli!\\n\\nGoogle Authenticator ile QR kodu tarayın.'
                });
            }
            
            if (!totpCode) {
                return res.json({
                    success: false,
                    requiresTOTP: true,
                    remaining: rateStatus.remaining,
                    error: `2FA kodu gerekli!\\n\\n📱 Google Authenticator uygulamasından 6 haneli kodu girin.\\n⚠️ Kalan deneme hakkı: ${rateStatus.remaining}`
                });
            }
            
            const totpValid = verifyTOTP(admin.totp_secret, totpCode);
            if (!totpValid) {
                const newRateStatus = await recordFailedLogin(clientIP, 'super-admin');
                
                return res.json({
                    success: false,
                    remaining: newRateStatus.remaining,
                    error: `❌ Geçersiz 2FA kodu!\\n\\n⚠️ Kalan deneme hakkı: ${newRateStatus.remaining}${newRateStatus.remaining === 0 ? '\\n🔒 30 dakika bekleyin!' : ''}`
                });
            }
            
            // Başarılı giriş - session oluştur
            req.session.superAdmin = {
                id: admin.id,
                username: admin.username,
                loginTime: new Date()
            };
            
            console.log(`🔴 Super Admin giriş başarılı: ${username} - IP: ${clientIP}`);
            console.log(`🔗 Session oluşturuldu:`, req.session.superAdmin);
            
            res.json({ 
                success: true,
                message: `Hoş geldiniz ${admin.username}! Super Admin paneline yönlendiriliyorsunuz...`,
                redirectUrl: SECURITY_CONFIG.SUPER_ADMIN_PATH
            });
            
        } else {
            const newRateStatus = await recordFailedLogin(clientIP, 'super-admin');
            
            res.json({
                success: false,
                remaining: newRateStatus.remaining,
                error: `❌ Geçersiz kullanıcı adı veya şifre!\\n\\n⚠️ Kalan deneme hakkı: ${newRateStatus.remaining}${newRateStatus.remaining === 0 ? '\\n🔒 30 dakika bekleyin!' : ''}`
            });
        }
        
    } catch (error) {
        console.error('Super admin giriş hatası:', error);
        res.json({
            success: false,
            error: 'Sistem hatası! Lütfen daha sonra tekrar deneyin.'
        });
    }
});

app.post('/auth/admin-login', async (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    try {
        // Rate limiting kontrolü
        const rateStatus = await checkRateLimit(clientIP, 'admin');
        
        if (!rateStatus.allowed) {
            const resetTime = rateStatus.resetTime.toLocaleTimeString('tr-TR');
            return res.json({
                success: false,
                rateLimited: true,
                error: `Çok fazla başarısız deneme!\\n\\n⏰ ${resetTime} sonra tekrar deneyin.\\n📊 Toplam deneme: ${rateStatus.attempts}/5`,
                resetTime: rateStatus.resetTime,
                remaining: 0
            });
        }
        
        // Normal admin doğrulaması
        const admin = await authenticateAdmin(username, password);
        
        if (admin && admin.role === 'normal') {
            // Session oluştur
            req.session.normalAdmin = {
                id: admin.id,
                username: admin.username,
                loginTime: new Date()
            };
            
            console.log(`🟡 Normal Admin giriş başarılı: ${username} - IP: ${clientIP}`);
            console.log(`🔗 Session oluşturuldu:`, req.session.normalAdmin);
            
            res.json({ 
                success: true,
                message: `Hoş geldiniz ${admin.username}! Admin paneline yönlendiriliyorsunuz...`,
                redirectUrl: SECURITY_CONFIG.NORMAL_ADMIN_PATH
            });
            
        } else {
            const newRateStatus = await recordFailedLogin(clientIP, 'admin');
            
            res.json({
                success: false,
                remaining: newRateStatus.remaining,
                error: `❌ Geçersiz kullanıcı adı veya şifre!\\n\\n⚠️ Kalan deneme hakkı: ${newRateStatus.remaining}${newRateStatus.remaining === 0 ? '\\n🔒 30 dakika bekleyin!' : ''}`
            });
        }
        
    } catch (error) {
        console.error('Normal admin giriş hatası:', error);
        res.json({
            success: false,
            error: 'Sistem hatası! Lütfen daha sonra tekrar deneyin.'
        });
    }
});

// Session check endpoint
app.get('/auth/check-session', (req, res) => {
    console.log('🔍 Session kontrolü:', req.session);
    
    if (req.session && req.session.superAdmin) {
        console.log('✅ Super admin session bulundu:', req.session.superAdmin.username);
        res.json({ 
            authenticated: true, 
            role: 'super', 
            username: req.session.superAdmin.username 
        });
    } else if (req.session && req.session.normalAdmin) {
        console.log('✅ Normal admin session bulundu:', req.session.normalAdmin.username);
        res.json({ 
            authenticated: true, 
            role: 'normal', 
            username: req.session.normalAdmin.username 
        });
    } else {
        console.log('❌ Session bulunamadı');
        res.json({ authenticated: false });
    }
});

// Yönlendirme endpoint'i
app.get('/redirect-after-login', (req, res) => {
    if (req.session && req.session.superAdmin) {
        res.redirect(SECURITY_CONFIG.SUPER_ADMIN_PATH);
    } else if (req.session && req.session.normalAdmin) {
        res.redirect(SECURITY_CONFIG.NORMAL_ADMIN_PATH);
    } else {
        res.redirect('/');
    }
});

// Logout endpoint
app.post('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.json({ success: false, error: 'Çıkış hatası' });
        }
        res.json({ success: true });
    });
});

// GÜVENLİ ROUTE'LAR - TAHMİN EDİLEMEZ URL'LER
app.get(SECURITY_CONFIG.SUPER_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'super-admin.html'));
});

app.get(SECURITY_CONFIG.NORMAL_ADMIN_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get(SECURITY_CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// ESKİ ROUTE'LARI DEVRE DIŞI BIRAK - GÜVENLİK
app.get('/super-admin.html', (req, res) => {
    res.status(404).send('Sayfa bulunamadı');
});

app.get('/admin-panel.html', (req, res) => {
    res.status(404).send('Sayfa bulunamadı');
});

app.get('/customer-app.html', (req, res) => {
    res.status(404).send('Sayfa bulunamadı');
});

// 🔥 WebRTC ROUTING FIX: Aktif görüşme tracking helper fonksiyonları
function createCallSession(customerId, adminId, customerUniqueId, adminUniqueId) {
    const callId = `${customerId}-${adminId}`;
    activeCalls.set(callId, {
        customerId: customerId,
        adminId: adminId,
        customerUniqueId: customerUniqueId,
        adminUniqueId: adminUniqueId,
        startTime: Date.now(),
        status: 'connecting'
    });
    console.log(`📞 Yeni görüşme session'ı oluşturuldu: ${callId}`);
    return callId;
}

function getCallSession(customerId, adminId) {
    const callId = `${customerId}-${adminId}`;
    return activeCalls.get(callId);
}

function removeCallSession(customerId, adminId) {
    const callId = `${customerId}-${adminId}`;
    const session = activeCalls.get(callId);
    if (session) {
        activeCalls.delete(callId);
        console.log(`📞 Görüşme session'ı kaldırıldı: ${callId}`);
    }
    return session;
}

// 🔥 WebRTC ROUTING FIX: Doğru hedefi bulma fonksiyonu
function findWebRTCTarget(targetId, sourceType) {
    console.log(`🎯 WebRTC target aranıyor: ${targetId} (source: ${sourceType})`);
    
    // Direct ID ile ara
    let targetClient = clients.get(targetId);
    if (targetClient) {
        console.log(`✅ Direct target bulundu: ${targetId} (${targetClient.userType})`);
        return targetClient;
    }
    
    // Unique ID varsa normal ID ile ara
    if (targetId.includes('_')) {
        // Bu bir admin unique ID'si - normal ID'yi çıkar
        const normalId = targetId.split('_')[0];
        for (const [clientId, clientData] of clients.entries()) {
            if (clientData.id === normalId && clientData.userType === 'admin') {
                console.log(`✅ Admin unique ID ile bulundu: ${normalId} -> ${clientId}`);
                return clientData;
            }
        }
    } else {
        // Normal customer ID'si için unique admin ID'sini ara
        for (const [clientId, clientData] of clients.entries()) {
            if (clientId.startsWith(targetId + '_') && clientData.userType === 'admin') {
                console.log(`✅ Customer için admin unique ID bulundu: ${targetId} -> ${clientId}`);
                return clientData;
            }
        }
    }
    
    console.log(`❌ WebRTC target bulunamadı: ${targetId}`);
    console.log(`🔍 Mevcut clients:`, Array.from(clients.keys()));
    return null;
}

// WebSocket bağlantı işleyicisi - 🔥 ÇOKLU ARAMA SİSTEMİ + MULTI-ADMIN FIX + WebRTC ROUTING FIX
wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';
    console.log('🔗 Yeni bağlantı:', clientIP);

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            
            // 🔧 FIX: Gönderen client'ın bilgilerini tespit et
            let senderInfo = null;
            for (const [clientId, clientData] of clients.entries()) {
                if (clientData.ws === ws) {
                    senderInfo = clientData;
                    break;
                }
            }
            
            const senderId = senderInfo ? (senderInfo.uniqueId || senderInfo.id) : (message.userId || 'unknown');
            const senderType = senderInfo ? senderInfo.userType : 'unknown';
            
            console.log('📨 Gelen mesaj:', message.type, 'from:', senderId, `(${senderType})`);

            switch (message.type) {
                case 'kvkk-check':
                    const hasConsent = await checkKVKKConsent(clientIP, req.headers['user-agent'] || '');
                    ws.send(JSON.stringify({
                        type: 'kvkk-status',
                        hasConsent: hasConsent
                    }
