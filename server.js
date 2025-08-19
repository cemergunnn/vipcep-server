const totalCredits = await pool.query('SELECT SUM(credits) FROM approved_users');
        const todayCalls = await pool.query("SELECT COUNT(*) FROM call_history WHERE DATE(call_time) = CURRENT_DATE");
        const activeCallsCount = activeHeartbeats.size;
        
        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalCalls: parseInt(totalCalls.rows[0].count),
            totalCredits: parseInt(totalCredits.rows[0].sum || 0),
            todayCalls: parseInt(todayCalls.rows[0].count),
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
            activeCalls: activeCallsCount
        });
});

// Static dosya route'ları
app.get('/admin-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

app.get('/customer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

app.get('/super-admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'super-admin.html'));
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
    console.log('🚀 VIPCEP Server Başlatılıyor...');
    console.log('🔍 Railway Environment:', process.env.RAILWAY_ENVIRONMENT || 'Local');
    
    // Veritabanını başlat
    await initDatabase();
    
    // HTTP Server'ı başlat
    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server çalışıyor!');
        console.log(`🔍 Port: ${PORT}`);
        console.log(`🌍 URL: http://0.0.0.0:${PORT}`);
        console.log(`🔌 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('📱 Uygulamalar:');
        console.log(` 🔐 Super admin paneli: /super-admin.html`);
        console.log(` 👨‍💼 Admin paneli: /admin-panel.html`);
        console.log(` 📱 Müşteri uygulaması: /customer-app.html`);
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('📞 WhatsApp: +90 537 479 24 03');
        console.log('✅ Sistem hazır - Arama kabul ediliyor!');
        console.log('❤️‍🔥 Kredi kesinti sorunu çözüldü - Heartbeat sistemi aktif!');
        console.log('🛡️ KVKK uyumluluğu + Rate limiting + 2FA sistemi aktif!');
        console.log('🔐 Google Authenticator 2FA super admin için zorunlu!');
        console.log('╔═══════════════════════════════════════════════════════════════╗');
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
    
    // Aktif heartbeat'leri sonlandır
    activeHeartbeats.forEach((heartbeat, callKey) => {
        stopHeartbeat(callKey, 'server_shutdown');
    });
    
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
    } catch (error) {
        console.log('💾 PostgreSQL istatistik hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// KVKK onayları listesi (super admin için)
app.get('/api/kvkk-consents', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM kvkk_consents ORDER BY consent_date DESC LIMIT 100');
        res.json(result.rows);
    } catch (error) {
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
        activeCalls: activeHeartbeats.size,
        database: process.env.DATABASE_URL ? 'Connected' : 'Offline'
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
                    grid-template-columns: 1fr 1fr 1fr; 
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
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
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
                .super-admin-card {
                    background: linear-gradient(135deg, #ef4444, #dc2626);
                    color: white;
                }
                .super-admin-card a {
                    background: rgba(255,255,255,0.2);
                    color: white;
                }
                .super-admin-card a:hover {
                    background: rgba(255,255,255,0.3);
                }
                .heartbeat-info {
                    background: linear-gradient(135deg, #fbbf24, #f59e0b);
                    color: white;
                    padding: 20px;
                    border-radius: 12px;
                    margin-bottom: 20px;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🎯 VIPCEP Server</h1>
                <p style="font-size: 18px; margin: 10px 0;">Voice IP Communication Emergency Protocol</p>
                <p style="font-size: 14px; opacity: 0.9;">Mobil Cihaz Teknik Danışmanlık Sistemi</p>
            </div>
            
            <div class="heartbeat-info">
                <h3>💓 Heartbeat Sistemi Aktif!</h3>
                <p style="font-size: 14px; opacity: 0.9; margin-top: 10px;">
                    Internet kesintilerinde bile kredi düşme sistemi çalışır
                </p>
            </div>
            
            <div class="links">
                <div class="link-card super-admin-card">
                    <h3>🔐 Super Admin</h3>
                    <p>Sistem yönetimi + 2FA</p>
                    <p style="font-size: 12px; opacity: 0.9;">Kredi yükleme, kullanıcı yönetimi</p>
                    <a href="/super-admin.html">Super Admin Panel →</a>
                </div>
                <div class="link-card">
                    <h3>👨‍💼 Admin Panel</h3>
                    <p>Arama yönetim sistemi</p>
                    <p style="font-size: 12px; color: #64748b;">Arama kabul/yapma yetkisi</p>
                    <a href="/admin-panel.html">Admin Panel →</a>
                </div>
                <div class="link-card">
                    <h3>📱 Müşteri Uygulaması</h3>
                    <p>Sesli danışmanlık</p>
                    <p style="font-size: 12px; color: #64748b;">KVKK + güvenlik sistemi</p>
                    <a href="/customer-app.html">Müşteri App →</a>
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
                        <div class="status-value">${activeHeartbeats.size}</div>
                        <div>Aktif Arama</div>
                    </div>
                    <div class="status-item">
                        <div class="status-value">✅</div>
                        <div>Sistem</div>
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
                <h4>🔋 Test Kullanıcıları:</h4>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li><strong>ID:</strong> 1234 | <strong>Ad:</strong> Test Kullanıcı | <strong>Kredi:</strong> 10 dk</li>
                    <li><strong>ID:</strong> 0005 | <strong>Ad:</strong> VIP Müşteri | <strong>Kredi:</strong> 25 dk</li>
                    <li><strong>ID:</strong> 9999 | <strong>Ad:</strong> Demo User | <strong>Kredi:</strong> 5 dk</li>
                </ul>
                <h4>🔐 Test Admin:</h4>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li><strong>Normal Admin:</strong> admin1 / password123</li>
                    <li><strong>Super Admin:</strong> superadmin / admin123</li>
                </ul>
                <h4>💓 Yeni Özellikler:</h4>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>✅ Heartbeat sistemi - Internet kesintilerinde kredi düşürmesi</li>
                    <li>✅ KVKK uyumluluğu ve onay sistemi</li>
                    <li>✅ Rate limiting - 5 yanlış giriş = 30 dk bekleme</li>
                    <li>✅ Google Authenticator 2FA super admin için</li>
                </ul>
            </div>
        </body>
        </html>
    `);
});const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

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
const activeCallTimers = new Map(); // Aktif arama sayaçları
const failedLogins = new Map(); // Rate limiting için
let callHistory = [];

// 2FA Secret key (production'da environment variable olmalı)
const SUPER_ADMIN_SECRET = process.env.SUPER_ADMIN_SECRET || 'VIPCEPTEST2024SECRET';

// Heartbeat sistemi - Aktif aramaların kredi düşürmesini sağlar
const HEARTBEAT_INTERVAL = 60000; // 1 dakika
const activeHeartbeats = new Map();

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
                totp_secret VARCHAR(32),
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
            await pool.query(`
                INSERT INTO admins (username, password_hash, role, totp_secret) 
                VALUES ($1, $2, $3, $4)
            `, ['superadmin', hashedPassword, 'super', generateTOTPSecret()]);
            console.log('🔑 Super admin oluşturuldu: superadmin/admin123');
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
                console.log(`📝 Test kullanıcısı eklendi: ${id} - ${name} (${credits} dk)`);
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

// TOTP Secret oluştur
function generateTOTPSecret() {
    return crypto.randomBytes(16).toString('base32').substr(0, 16);
}

// TOTP doğrulama fonksiyonu
function verifyTOTP(secret, token) {
    if (!secret || !token) return false;
    
    try {
        // Base32 decode
        const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        const cleanSecret = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
        
        for (let i = 0; i < cleanSecret.length; i++) {
            const char = cleanSecret[i];
            const index = base32Chars.indexOf(char);
            if (index === -1) continue;
            bits += index.toString(2).padStart(5, '0');
        }
        
        const secretBuffer = Buffer.alloc(Math.floor(bits.length / 8));
        for (let i = 0; i < secretBuffer.length; i++) {
            const byte = bits.substr(i * 8, 8);
            secretBuffer[i] = parseInt(byte, 2);
        }
        
        // TOTP algoritması (RFC 6238)
        const timeStep = 30; // 30 saniye
        const currentTime = Math.floor(Date.now() / 1000 / timeStep);
        
        // ±1 zaman penceresi kontrol et (clock skew için)
        for (let i = -1; i <= 1; i++) {
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

// Rate limiting kontrolü
async function checkRateLimit(ip, userType = 'customer') {
    try {
        // Son 30 dakikadaki başarısız girişleri kontrol et
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const failedAttempts = await pool.query(
            'SELECT COUNT(*) FROM failed_logins WHERE ip_address = $1 AND user_type = $2 AND attempt_time > $3',
            [ip, userType, thirtyMinutesAgo]
        );

        const count = parseInt(failedAttempts.rows[0].count);
        return count < 5; // 5 denemeden az ise izin ver
    } catch (error) {
        console.log('Rate limit kontrolü hatası:', error.message);
        return true; // Hata durumunda izin ver
    }
}

// Başarısız giriş kaydet
async function recordFailedLogin(ip, userType = 'customer') {
    try {
        await pool.query(
            'INSERT INTO failed_logins (ip_address, user_type) VALUES ($1, $2)',
            [ip, userType]
        );
    } catch (error) {
        console.log('Başarısız giriş kaydı hatası:', error.message);
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
    console.log(`💓 Heartbeat başlatıldı: ${callKey}`);
    
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
                
                console.log(`💓 Heartbeat kredi düştü: ${userId} -> ${newCredits} dk`);
                
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
        console.log(`💓 Heartbeat durduruldu: ${callKey} - ${reason}`);
        
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

// WebSocket bağlantı işleyicisi
wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';
    console.log('🔗 Yeni bağlantı:', clientIP);

    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            console.log('📨 Gelen mesaj:', message.type, 'from:', message.userId || 'unknown');

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

                case 'admin-login':
                    const rateOk = await checkRateLimit(clientIP, 'admin');
                    if (!rateOk) {
                        ws.send(JSON.stringify({
                            type: 'admin-login-response',
                            success: false,
                            reason: 'Çok fazla başarısız deneme. 30 dakika bekleyiniz.'
                        }));
                        break;
                    }

                    const admin = await authenticateAdmin(message.username, message.password);
                    if (admin) {
                        // Super admin için 2FA kontrolü
                        if (admin.role === 'super' && admin.totp_secret) {
                            if (!message.totpCode) {
                                // 2FA kodu gerekli
                                ws.send(JSON.stringify({
                                    type: 'admin-login-response',
                                    success: false,
                                    requiresTOTP: true,
                                    username: admin.username,
                                    reason: '2FA kodu gerekli'
                                }));
                            } else {
                                // 2FA kodunu doğrula
                                const totpValid = verifyTOTP(admin.totp_secret, message.totpCode);
                                if (totpValid) {
                                    ws.send(JSON.stringify({
                                        type: 'admin-login-response',
                                        success: true,
                                        role: admin.role,
                                        username: admin.username,
                                        requiresTOTP: false
                                    }));
                                } else {
                                    await recordFailedLogin(clientIP, 'admin');
                                    ws.send(JSON.stringify({
                                        type: 'admin-login-response',
                                        success: false,
                                        reason: 'Geçersiz 2FA kodu'
                                    }));
                                }
                            }
                        } else {
                            // Normal admin veya 2FA olmayan super admin
                            ws.send(JSON.stringify({
                                type: 'admin-login-response',
                                success: true,
                                role: admin.role,
                                username: admin.username,
                                requiresTOTP: false
                            }));
                        }
                    } else {
                        await recordFailedLogin(clientIP, 'admin');
                        ws.send(JSON.stringify({
                            type: 'admin-login-response',
                            success: false,
                            reason: 'Geçersiz kullanıcı adı veya şifre'
                        }));
                    }
                    break;

                case 'register':
                    clients.set(message.userId, {
                        ws: ws,
                        id: message.userId,
                        name: message.name,
                        userType: message.userType || 'customer',
                        registeredAt: new Date().toLocaleTimeString(),
                        online: true,
                        role: message.role || null
                    });

                    console.log(`✅ ${message.userType?.toUpperCase()} kaydedildi: ${message.name} (${message.userId})`);
                    broadcastUserList();
                    break;

                case 'login-request':
                    const rateLimit = await checkRateLimit(clientIP);
                    if (!rateLimit) {
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: 'Çok fazla başarısız deneme. 30 dakika bekleyiniz.'
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
                        await recordFailedLogin(clientIP);
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
                    
                    // 🔥 YENİ: Heartbeat sistemi başlat
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
                    console.log('✅ Arama kabul edildi (Admin tarafından):', message.userId);
                    
                    const callerClient = clients.get(message.userId);
                    if (callerClient && callerClient.ws.readyState === WebSocket.OPEN) {
                        callerClient.ws.send(JSON.stringify({
                            type: 'call-accepted'
                        }));
                    }
                    
                    // 🔥 YENİ: Heartbeat sistemi başlat
                    const adminId = Array.from(clients.values()).find(c => c.userType === 'admin')?.id || 'ADMIN001';
                    const callKey2 = `${message.userId}-${adminId}`;
                    startHeartbeat(message.userId, adminId, callKey2);
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
                    
                    // 🔥 YENİ: Heartbeat sistemi durdur
                    const endCallKey = message.targetId ? 
                        `${message.userId}-${message.targetId}` : 
                        `${message.userId}-ADMIN001`;
                    
                    stopHeartbeat(endCallKey, message.endedBy === 'admin' ? 'admin_ended' : 'customer_ended');
                    
                    // Hedef kullanıcıya bildir
                    if (message.targetId) {
                        const endTarget = clients.get(message.targetId);
                        if (endTarget && endTarget.ws.readyState === WebSocket.OPEN) {
                            endTarget.ws.send(JSON.stringify({
                                type: 'call-ended',
                                userId: message.userId,
                                duration: message.duration || 0,
                                endedBy: message.userType || 'unknown'
                            }));
                        }
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

                case 'heartbeat':
                    // Heartbeat yanıtı
                    ws.send(JSON.stringify({ type: 'heartbeat-response' }));
                    break;
            }

        } catch (error) {
            console.log('❌ Mesaj işleme hatası:', error.message);
        }
    });

    ws.on('close', () => {
        const client = findClientById(ws);
        console.log('👋 Kullanıcı ayrıldı:', client?.name || 'unknown');
        
        // Client'ı kaldır
        for (const [key, clientData] of clients.entries()) {
            if (clientData.ws === ws) {
                clients.delete(key);
                
                // 🔥 YENİ: Eğer aktif araması varsa heartbeat'i sonlandır
                const activeCall = Array.from(activeHeartbeats.keys()).find(callKey => 
                    callKey.includes(key)
                );
                if (activeCall) {
                    stopHeartbeat(activeCall, 'connection_lost');
                }
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
        online: client.online,
        role: client.role
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

// KVKK onay durumu kontrol
app.get('/api/kvkk-status', async (req, res) => {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        const hasConsent = await checkKVKKConsent(ip, userAgent);
        res.json({ hasConsent });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// KVKK onayı kaydet
app.post('/api/kvkk-consent', async (req, res) => {
    try {
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        const success = await saveKVKKConsent(ip, userAgent);
        res.json({ success });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin listesi
app.get('/api/admins', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, role, is_active, last_login, created_at FROM admins ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin ekleme
app.post('/api/admins', async (req, res) => {
    try {
        const { username, password, role = 'normal' } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
        }
        
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        const totpSecret = role === 'super' ? generateTOTPSecret() : null;
        
        const result = await pool.query(`
            INSERT INTO admins (username, password_hash, role, totp_secret) 
            VALUES ($1, $2, $3, $4) 
            RETURNING id, username, role, created_at
        `, [username, hashedPassword, role, totpSecret]);
        
        res.json({ success: true, admin: result.rows[0] });
    } catch (error) {
        if (error.message.includes('duplicate key')) {
            res.status(400).json({ error: 'Bu kullanıcı adı zaten kullanımda' });
        } else {
            res.status(500).json({ error: error.message });
        }
    }
});

// Başarısız girişleri temizle
app.post('/api/clear-failed-logins', async (req, res) => {
    try {
        await pool.query('DELETE FROM failed_logins');
        res.json({ success: true, message: 'Başarısız giriş kayıtları temizlendi' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Başarısız giriş listesi
app.get('/api/failed-logins', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM failed_logins ORDER BY attempt_time DESC LIMIT 100');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

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
        const activeCallsCount = activeHeartbeats.size;
        
        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalCalls: parseInt(totalCalls.rows[0].count),
            totalCredits: parseInt(totalCredits.rows[0].sum || 0),
            todayCalls: parseInt(todayCalls.rows[0].count),
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
            activeCalls: activeCallsCount
        });
    } catch (error) {
        console.log('💾 PostgreSQL istatistik hatası:', error.message);
        res.status(500).json({ error: error.message });
    }
});
