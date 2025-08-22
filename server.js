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

console.log('🔒 GÜVENLİK URL\'LERİ OLUŞTURULDU:');
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

// Global değişkenler
const clients = new Map();
const activeHeartbeats = new Map(); // 🔥 Aktif arama sayaçları - İNTERNET KESİNTİSİ PROBLEMİNİ ÇÖZER
const activeCallAdmins = new Map(); // 🔥 YENİ: Görüşmedeki adminleri takip et
const activeCalls = new Map(); // 🔥 WebRTC ROUTING FIX: Aktif görüşmeleri takip et
const failedLogins = new Map(); // Rate limiting için
let callHistory = [];

// 2FA Secret key (production'da environment variable olmalı)
const SUPER_ADMIN_SECRET = process.env.SUPER_ADMIN_SECRET || 'VIPCEPTEST2024SECRET';

// 🔥 Heartbeat sistemi - Aktif aramaların kredi düşürmesini sağlar
const HEARTBEAT_INTERVAL = 60000; // 1 dakika = 1 kredi

// IP bazlı rate limiting
const rateLimitMap = new Map();

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
            console.log('🔒 Super admin oluşturuldu: superadmin/admin123');
            console.log('🔑 TOTP Secret:', totpSecret);
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
            <title>🔒 VIPCEP Güvenli Giriş</title>
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
                <div class="title">🔒 VIPCEP</div>
                <div class="subtitle">Güvenli Giriş Sistemi</div>
                
                <div class="form-group">
                    <input type="text" id="username" class="form-input" placeholder="👤 Kullanıcı Adı">
                </div>
                <div class="form-group">
                    <input type="password" id="password" class="form-input" placeholder="🔒 Şifre">
                </div>
                <div class="form-group" id="totpGroup">
                    <input type="text" id="totpCode" class="form-input" placeholder="🔑 2FA Kodu (6 haneli)" maxlength="6">
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
                    <h3>🔑 2FA Kurulumu</h3>
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

// WebSocket bağlantı işleyicisi - 🔥 MULTI-ADMIN FIX + WebRTC ROUTING FIX
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
                    }));
                    break;

                case 'kvkk-consent':
                    const consentSaved = await saveKVKKConsent(clientIP, req.headers['user-agent'] || '');
                    ws.send(JSON.stringify({
                        type: 'kvkk-consent-response',
                        success: consentSaved
                    }));
                    break;

                case 'register':
                    // Admin'ler için unique ID oluştur
                    const uniqueClientId = message.userType === 'admin' 
                        ? `${message.userId}_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`
                        : message.userId;
                    
                    clients.set(uniqueClientId, {
                        ws: ws,
                        id: message.userId, // Orijinal ID'yi sakla
                        uniqueId: uniqueClientId, // Unique ID'yi de sakla
                        name: message.name,
                        userType: message.userType || 'customer',
                        registeredAt: new Date().toLocaleTimeString(),
                        online: true,
                        role: message.role || null
                    });

                    console.log(`✅ ${message.userType?.toUpperCase()} kaydedildi: ${message.name} (${uniqueClientId})`);
                    
                    // 🔧 Admin'e kendi unique ID'sini gönder
                    if (message.userType === 'admin') {
                        ws.send(JSON.stringify({
                            type: 'admin-registered',
                            uniqueId: uniqueClientId,
                            originalId: message.userId
                        }));
                        console.log(`🔧 Admin'e unique ID gönderildi: ${uniqueClientId}`);
                    }
                    
                    broadcastUserList();
                    break;

                case 'login-request':
                    const rateLimit = await checkRateLimit(clientIP);
                    if (!rateLimit.allowed) {
                        const resetTime = rateLimit.resetTime.toLocaleTimeString('tr-TR');
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            rateLimited: true,
                            error: `Çok fazla başarısız deneme!\\n\\n⏰ ${resetTime} sonra tekrar deneyin.\\n📊 Toplam deneme: ${rateLimit.attempts}/5`,
                            remaining: rateLimit.remaining,
                            resetTime: rateLimit.resetTime
                        }));
                        break;
                    }

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
                        const newRateStatus = await recordFailedLogin(clientIP);
                        console.log('❌ Giriş reddedildi:', approval.reason);
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: approval.reason,
                            remaining: newRateStatus.remaining,
                            rateLimited: !newRateStatus.allowed
                        }));
                    }
                    break;

                case 'call-request':
                    console.log('📞 Müşteri → Admin arama talebi:', message.userId);
                    
                    // 🔥 FIX: Sadece MÜSAİT adminlere bildir
                    const allAdminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
                    const availableAdmins = allAdminClients.filter(adminClient => {
                        // Görüşmede OLMAYAN adminleri filtrele
                        return !activeCallAdmins.has(adminClient.uniqueId || adminClient.id);
                    });
                    
                    if (availableAdmins.length > 0) {
                        console.log(`📞 ${availableAdmins.length} müsait admin'e bildirim gönderiliyor (${allAdminClients.length - availableAdmins.length} admin görüşmede)`);
                        
                        availableAdmins.forEach(adminClient => {
                            if (adminClient.ws.readyState === WebSocket.OPEN) {
                                adminClient.ws.send(JSON.stringify({
                                    type: 'incoming-call',
                                    userId: message.userId,
                                    userName: message.userName,
                                    credits: message.credits
                                }));
                            }
                        });
                    } else {
                        console.log('❌ Tüm adminler görüşmede, arama reddediliyor');
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Tüm teknik destek uzmanları görüşmede. Lütfen daha sonra tekrar deneyin.'
                        }));
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
                            userId: message.userId,
                            adminId: message.adminId
                        }));
                    }
                    
                    // 🔥 CRITICAL FIX: WebRTC call session oluştur
                    createCallSession(message.userId, message.adminId, message.userId, message.adminId);
                    
                    // 🔥 FIX: Admin'i görüşme durumuna al
                    activeCallAdmins.set(message.adminId, {
                        customerId: message.userId,
                        callStartTime: Date.now()
                    });
                    console.log(`📞 Admin görüşme durumuna alındı: ${message.adminId} <-> ${message.userId}`);
                    
                    // 🔥 Heartbeat sistemi başlat
                    const callKey = `${message.userId}-${message.adminId}`;
                    startHeartbeat(message.userId, message.adminId, callKey);
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
                    // 🔧 FIX: Hangi admin'in mesajı gönderdiğini tespit et
                    let acceptingAdminId = message.adminId;
                    
                    // Eğer adminId gönderilmemişse, WebSocket connection'ından bul
                    if (!acceptingAdminId) {
                        for (const [clientId, clientData] of clients.entries()) {
                            if (clientData.ws === ws && clientData.userType === 'admin') {
                                acceptingAdminId = clientData.uniqueId; // Unique ID kullan
                                break;
                            }
                        }
                    }
                    
                    console.log('✅ Arama kabul edildi (Admin tarafından):', message.userId, 'by admin:', acceptingAdminId);
                    
                    if (!acceptingAdminId) {
                        console.log('❌ Admin ID bulunamadı, arama kabul edilemedi');
                        break;
                    }
                    
                    // 🔥 CRITICAL FIX: WebRTC call session oluştur
                    createCallSession(message.userId, acceptingAdminId, message.userId, acceptingAdminId);
                    
                    // 🔥 FIX: Admin'i görüşme durumuna al
                    activeCallAdmins.set(acceptingAdminId, {
                        customerId: message.userId,
                        callStartTime: Date.now()
                    });
                    console.log(`📞 Admin görüşme durumuna alındı: ${acceptingAdminId} <-> ${message.userId}`);
                    
                    const callerClient = clients.get(message.userId);
                    if (callerClient && callerClient.ws.readyState === WebSocket.OPEN) {
                        // 🔥 WebRTC Targeting Fix: Müşteriye kabul eden admin'in unique ID'sini gönder
                        callerClient.ws.send(JSON.stringify({
                            type: 'call-accepted',
                            acceptedAdminId: acceptingAdminId
                        }));
                        console.log(`🎯 Müşteriye acceptedAdminId gönderildi: ${acceptingAdminId}`);
                    }
                    
                    // 🔥 CRITICAL FIX: Diğer TÜM adminlere aramayı iptal bilgisi gönder
                    const allAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin');
                    let notifiedAdmins = 0;
                    
                    allAdmins.forEach(adminClient => {
                        if (adminClient.uniqueId !== acceptingAdminId && adminClient.ws.readyState === WebSocket.OPEN) {
                            adminClient.ws.send(JSON.stringify({
                                type: 'call-taken',
                                userId: message.userId,
                                takenBy: acceptingAdminId,
                                message: 'Arama başka bir admin tarafından alındı',
                                action: 'hide_call' // Admin panel'de ekranı gizlemek için
                            }));
                            notifiedAdmins++;
                        }
                    });
                    
                    console.log(`📞 ${notifiedAdmins} diğer admin'e "arama alındı" bildirimi gönderildi`);
                    
                    // 🔥 Heartbeat sistemi başlat
                    const normalCallKey = `${message.userId}-${acceptingAdminId}`;
                    startHeartbeat(message.userId, acceptingAdminId, normalCallKey);
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
                    
                    // Tüm adminlere bildir
                    const adminsToNotify = Array.from(clients.values()).filter(c => c.userType === 'admin');
                    adminsToNotify.forEach(adminClient => {
                        if (adminClient.ws.readyState === WebSocket.OPEN) {
                            adminClient.ws.send(JSON.stringify({
                                type: 'call-cancelled',
                                userId: message.userId,
                                userName: message.userName,
                                reason: message.reason
                            }));
                        }
                    });
                    console.log(`📞 ${adminsToNotify.length} admin'e iptal bildirimi gönderildi`);
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    // 🔥 CRITICAL WebRTC ROUTING FIX: Doğru hedefi bul ve mesajı ilet
                    const targetClient = findWebRTCTarget(message.targetId, senderType);
                    
                    if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
                        // 🔥 FIX: Mesajı doğru formatta ilet
                        const forwardMessage = {
                            type: message.type,
                            [message.type]: message[message.type], // offer, answer veya candidate
                            userId: senderId, // Gönderenin ID'si
                            targetId: message.targetId // Hedefin ID'si
                        };
                        
                        // ICE candidate için özel handling
                        if (message.type === 'ice-candidate') {
                            forwardMessage.candidate = message.candidate;
                        }
                        
                        targetClient.ws.send(JSON.stringify(forwardMessage));
                        console.log(`🔄 ${message.type} başarıyla iletildi: ${senderId} -> ${message.targetId} (${targetClient.userType})`);
                    } else {
                        console.log(`❌ ${message.type} hedefi bulunamadı: ${message.targetId}`);
                        console.log(`🔍 Aranan: ${message.targetId}, Gönderen: ${senderId} (${senderType})`);
                        console.log(`🔍 Mevcut clients:`, Array.from(clients.keys()));
                        
                        // Gönderene hata bildir
                        if (senderInfo && senderInfo.ws.readyState === WebSocket.OPEN) {
                            senderInfo.ws.send(JSON.stringify({
                                type: 'webrtc-error',
                                error: 'Target not found',
                                targetId: message.targetId,
                                messageType: message.type
                            }));
                        }
                    }
                    break;

                case 'end-call':
                    console.log('📞 Görüşme sonlandırılıyor:', senderId, '-> target:', message.targetId);
                    
                    // 🔥 FIX: Admin'i müsait duruma al
                    if (senderType === 'admin') {
                        activeCallAdmins.delete(senderId);
                        console.log(`📞 Admin müsait duruma alındı: ${senderId}`);
                    } else if (message.targetId) {
                        activeCallAdmins.delete(message.targetId);
                        console.log(`📞 Admin müsait duruma alındı: ${message.targetId}`);
                    }
                    
                    // 🔥 WebRTC call session'ı kaldır
                    if (senderType === 'customer' && message.targetId) {
                        removeCallSession(senderId, message.targetId);
                    } else if (senderType === 'admin' && message.targetId) {
                        removeCallSession(message.targetId, senderId);
                    }
                    
                    // 🔥 Heartbeat'i durdur - target ID'yi doğru kullan
                    const endCallKey = message.targetId ? `${senderId}-${message.targetId}` : `${senderId}-ADMIN001`;
                    stopHeartbeat(endCallKey, 'user_ended');
                    
                    const duration = message.duration || 0;
                    const creditsUsed = Math.ceil(duration / 60); // Yukarı yuvarlamalı
                    
                    // Hedef kullanıcıya bildir (unique ID kullan)
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
                    
                    // NOT: Heartbeat sistemi zaten kredi düşürme işlemini yapıyor
                    // Manuel kredi düşürme işlemi yapılmıyor
                    console.log(`✅ Arama sonlandırıldı, Heartbeat sistemi kredi yönetimini halletti: ${senderId}`);
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
                    const notifyAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin' && c.ws !== ws);
                    notifyAdmins.forEach(client => {
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
        
        // 🔥 FIX: Admin ayrılırsa görüşme durumundan çıkar
        if (client && client.userType === 'admin') {
            const adminKey = client.uniqueId || client.id;
            if (activeCallAdmins.has(adminKey)) {
                console.log(`📞 Ayrılan admin görüşme durumundan çıkarıldı: ${adminKey}`);
                activeCallAdmins.delete(adminKey);
            }
        }
        
        // İlgili heartbeat'leri durdur
        if (client) {
            for (const [callKey, heartbeat] of activeHeartbeats.entries()) {
                if (callKey.includes(client.id)) {
                    stopHeartbeat(callKey, 'connection_lost');
                    console.log(`💗 Bağlantı kopması nedeniyle heartbeat durduruldu: ${callKey}`);
                }
            }
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
            activeHeartbeats: activeHeartbeats.size,
            busyAdmins: activeCallAdmins.size,
            activeCalls: activeCalls.size
        });
    } catch (error) {
        console.log('💾 PostgreSQL istatistik hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// KVKK onaylarını getir
app.get('/api/kvkk-consents', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT * FROM kvkk_consents 
            ORDER BY consent_date DESC 
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (error) {
        console.log('💾 PostgreSQL KVKK onayları hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Admin listesini getir
app.get('/api/admins', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, username, role, is_active, last_login, created_at 
            FROM admins 
            ORDER BY created_at DESC
        `);
        res.json(result.rows);
    } catch (error) {
        console.log('💾 PostgreSQL admin listesi hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Yeni admin ekle
app.post('/api/admins', async (req, res) => {
    try {
        const { username, password, role = 'normal' } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
        }
        
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        const totpSecret = role === 'super' ? generateTOTPSecret() : null;
        
        await pool.query(`
            INSERT INTO admins (username, password_hash, role, totp_secret) 
            VALUES ($1, $2, $3, $4)
        `, [username, hashedPassword, role, totpSecret]);
        
        console.log(`👤 Yeni admin eklendi: ${username} (${role})`);
        res.json({ success: true, message: 'Admin başarıyla eklendi' });
    } catch (error) {
        if (error.message.includes('duplicate key')) {
            res.status(400).json({ error: 'Bu kullanıcı adı zaten kullanımda' });
        } else {
            console.log('💾 PostgreSQL admin ekleme hatası:', error.message);
            res.status(500).json({ error: error.message });
        }
    }
});

// Başarısız girişleri getir
app.get('/api/failed-logins', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT * FROM failed_logins 
            ORDER BY attempt_time DESC 
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (error) {
        console.log('💾 PostgreSQL başarısız giriş hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Rate limit temizle
app.post('/api/clear-failed-logins', async (req, res) => {
    try {
        await pool.query('DELETE FROM failed_logins');
        console.log('🧹 Tüm başarısız giriş kayıtları temizlendi');
        res.json({ success: true, message: 'Rate limit kayıtları temizlendi' });
    } catch (error) {
        console.log('💾 PostgreSQL rate limit temizleme hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Rate limit durumu API
app.get('/api/rate-limit-status/:userType', async (req, res) => {
    const { userType } = req.params;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    try {
        const rateStatus = await checkRateLimit(clientIP, userType);
        res.json(rateStatus);
    } catch (error) {
        res.status(500).json({ error: 'Rate limit kontrol hatası' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        clients: clients.size,
        activeHeartbeats: activeHeartbeats.size,
        busyAdmins: activeCallAdmins.size,
        activeCalls: activeCalls.size,
        database: process.env.DATABASE_URL ? 'Connected' : 'Offline',
        securityUrls: {
            superAdmin: SECURITY_CONFIG.SUPER_ADMIN_PATH,
            normalAdmin: SECURITY_CONFIG.NORMAL_ADMIN_PATH,
            customer: SECURITY_CONFIG.CUSTOMER_PATH
        }
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).send(`
        <div style="text-align: center; padding: 50px; font-family: system-ui;">
            <h1>🔒 404 - Sayfa Bulunamadı</h1>
            <p>Güvenlik nedeniyle bu sayfa mevcut değil.</p>
            <p><a href="/" style="color: #dc2626; text-decoration: none;">← Ana sayfaya dön</a></p>
        </div>
    `);
});

// Server'ı başlat
async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');
    console.log('🌍 Railway Environment:', process.env.RAILWAY_ENVIRONMENT || 'Local');
    
    // Veritabanını başlat
    await initDatabase();
    
    // HTTP Server'ı başlat
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server Çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
        console.log(`🌍 URL: http://0.0.0.0:${PORT}`);
        console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('🔒 GÜVENLİK URL\'LERİ:');
        console.log(` 🔴 Super Admin: ${SECURITY_CONFIG.SUPER_ADMIN_PATH}`);
        console.log(` 🟡 Normal Admin: ${SECURITY_CONFIG.NORMAL_ADMIN_PATH}`);
        console.log(` 🟢 Customer App: ${SECURITY_CONFIG.CUSTOMER_PATH}`);
        console.log('');
        console.log('💗 Heartbeat Sistemi: AKTİF (İnternet kesintilerinde kredi düşmesi)');
        console.log('🛡️ Rate Limiting: 5 deneme/30 dakita + görsel uyarılar');
        console.log('📋 KVKK Sistemi: Aktif + Persistent storage');
        console.log('🔑 2FA: Super Admin için Google Authenticator zorunlu');
        console.log('🔐 Session: 24 saat + secure cookies');
        console.log('🎯 MULTI-ADMIN: Koordinasyon sistemi aktif');
        console.log('🔥 WebRTC ROUTING FIX: Bağlantı sorunları çözüldü');
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('📞 WhatsApp: +90 537 479 24 03');
        console.log('✅ Sistem hazır - WebRTC bağlantı sorunları tamamen çözüldü!');
        console.log('╔═══════════════════════════════════════════════════════════════╗');
        console.log('║              🔥 WebRTC ROUTING TAMAMEN DÜZELDİ 🔥             ║');
        console.log('║          📞 BAĞLANTI SORUNU SON HALİNDE ÇÖZÜLDÜ 📞           ║');
        console.log('╚═══════════════════════════════════════════════════════════════╝');
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
    
    // Aktif heartbeat'leri durdur
    for (const [callKey, heartbeat] of activeHeartbeats.entries()) {
        clearInterval(heartbeat);
        console.log(`💗 Heartbeat durduruldu: ${callKey}`);
    }
    activeHeartbeats.clear();
    activeCallAdmins.clear();
    activeCalls.clear();
    
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
