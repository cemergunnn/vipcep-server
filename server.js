const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');
const speakeasy = require('speakeasy'); // 2FA için eklendi, lütfen package.json'a eklediğinizden emin olun

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Express setup
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

// Security configuration
const SECURITY_CONFIG = {
    SUPER_ADMIN_PATH: '/panel-admin',
    NORMAL_ADMIN_PATH: '/desk-admin', 
    CUSTOMER_PATH: '/app-customer',
    WIDGET_PATH: '/widget', // Widget yolu eklendi
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    TOTP_ISSUER: 'VIPCEP System',
    TOTP_WINDOW: 2
};

// Middleware
app.use(session({
    secret: SECURITY_CONFIG.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// WebSocket server
const wss = new WebSocket.Server({ server });

// Global variables
const clients = new Map(); // Tüm bağlı istemcileri (müşteri, admin, widget) yönetir
let activeCalls = new Map(); // Aktif görüşmeleri tutar (callKey -> {customerId, adminId, startTime, status})
let activeCallAdmins = new Map(); // Hangi adminin hangi callKey ile meşgul olduğunu tutar (adminId -> callKey)
let activeHeartbeats = new Map(); // Aktif heartbeat'leri tutar (callKey -> interval)
let adminCallbacks = new Map(); // Adminlere bırakılan geri dönüş taleplerini tutar (adminId -> [{customerId, customerName, timestamp}])
let adminLocks = new Map(); // Adminlerin meşguliyetini belirtir (adminId -> {lockedBy: customerId, lockTime: Date})
let currentAnnouncement = null; // Aktif duyuruyu tutar {text, type, createdAt, createdBy}
const HEARTBEAT_INTERVAL = 60000;


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
            );
        `);
        console.log('✅ "approved_users" tablosu hazır.');

        // Admin credentials tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_credentials ( -- Orijinal dosyanızdaki 'admins' yerine
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'normal',
                secret_totp VARCHAR(255),
                earnings DECIMAL(10, 2) DEFAULT 0, -- Orijinal dosyanızda 'earnings' yoktu, tutarlılık için ekledim
                is_active BOOLEAN DEFAULT TRUE,
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "admin_credentials" tablosu hazır.');

        // Admin Earnings tablosu (Adminlerin kazançlarını takip etmek için)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_earnings (
                username VARCHAR(255) PRIMARY KEY,
                total_earned DECIMAL(10, 2) DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "admin_earnings" tablosu hazır.');

        // Duyurular tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS announcements (
                id SERIAL PRIMARY KEY,
                message TEXT NOT NULL,
                type VARCHAR(50) DEFAULT 'info',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            );
        `);
        console.log('✅ "announcements" tablosu hazır.');

        // Çağrı geçmişi tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS call_history (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(10),
                user_name VARCHAR(255),
                admin_id VARCHAR(10),
                duration INTEGER DEFAULT 0,
                credits_used DECIMAL(10,2) DEFAULT 0,
                call_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_reason VARCHAR(50) DEFAULT 'normal',
                connection_lost BOOLEAN DEFAULT FALSE
            );
        `);
        console.log('✅ "call_history" tablosu hazır.');

        // Kredi hareketleri tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS credit_transactions (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(10),
                transaction_type VARCHAR(20),
                amount DECIMAL(10, 2),
                balance_after DECIMAL(10, 2),
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "credit_transactions" tablosu hazır.');
        
        // KVKK onayları tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS kvkk_consents (
                id SERIAL PRIMARY KEY,
                consent_hash VARCHAR(64) UNIQUE NOT NULL,
                ip_address INET,
                user_agent TEXT,
                consent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version VARCHAR(10) DEFAULT '1.0'
            );
        `);
        console.log('✅ "kvkk_consents" tablosu hazır.');
        
        // Başarısız giriş denemeleri tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                ip_address INET NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_type VARCHAR(20) DEFAULT 'customer'
            );
        `);
        console.log('✅ "failed_logins" tablosu hazır.');

        // İlk super admin'i ekle (sadece yoksa)
        const superAdminUsername = 'superadmin';
        const superAdminPassword = 'superadminpassword'; // **UYARI: PRODUCTION İÇİN GÜVENLİK İYİLEŞTİRMESİ GEREKİR**
        const secretTOTP = 'N73K34N4A25VCNF5C5R4XU2655K6F2S5B7J3E37Q73B24F3Q4X7'; // Örnek gizli anahtar
        const checkAdmin = await pool.query('SELECT * FROM admin_credentials WHERE username = $1', [superAdminUsername]); // 'admins' yerine

        if (checkAdmin.rows.length === 0) {
            console.log('🔧 İlk super admin oluşturuluyor...');
            const passwordHash = crypto.createHash('sha256').update(superAdminPassword).digest('hex');
            await pool.query(
                'INSERT INTO admin_credentials (username, password_hash, role, secret_totp) VALUES ($1, $2, $3, $4)', // 'admins' yerine
                [superAdminUsername, passwordHash, 'super', secretTOTP] 
            );
            console.log('✅ Super admin oluşturuldu.');
        } else {
            // Varolan super adminin TOTP sırrını kontrol et ve güncelle
            if (!checkAdmin.rows[0].secret_totp) {
                console.log(`🔐 Super Admin ${superAdminUsername} için TOTP sırrı güncelleniyor...`);
                await pool.query('UPDATE admin_credentials SET secret_totp = $1 WHERE username = $2', [secretTOTP, superAdminUsername]);
            }
            console.log('🔐 Super Admin zaten mevcut.');
            // Var olan super admin'in TOTP bilgilerini logla
            const admin = checkAdmin.rows[0];
            if (admin.secret_totp) {
                console.log(`   Kullanıcı Adı: ${admin.username}`);
                console.log(`   TOTP Sırrı: ${admin.secret_totp}`);
                console.log(`   QR Kod URL: ${generateTOTPQR(admin.username, admin.secret_totp)}`);
            }
        }

        // Test kullanıcıları oluştur (sadece yoksa)
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

        // Normal admin oluştur (sadece yoksa)
        const normalAdminCheck = await pool.query('SELECT * FROM admin_credentials WHERE username = $1', ['admin1']); // 'admins' yerine
        if (normalAdminCheck.rows.length === 0) {
            const hashedPassword = crypto.createHash('sha256').update('password123').digest('hex');
            await pool.query(`
                INSERT INTO admin_credentials (username, password_hash, role) 
                VALUES ($1, $2, $3)
            `, ['admin1', hashedPassword, 'normal']);
        }


    } catch (error) {
        console.error('❌ Veritabanı başlatma hatası:', error.message);
        throw error;
    }
}

// ================== YARDIMCI FONKSİYONLAR ==================

function generateCallId() {
    return `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function broadcastToCustomers(message) {
    clients.forEach(client => {
        if (client.userType === 'customer' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify(message));
        }
    });
}

// YENİ: Widget'lara yayın yapma fonksiyonu
function broadcastToWidgets(message) {
    clients.forEach(client => {
        if (client.userType === 'widget' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify(message));
        }
    });
}

// Admin listesini yayınlama fonksiyonu, şimdi widget'ları da destekliyor
function broadcastAdminListToCustomers() {
    const adminList = Array.from(clients.values())
        .filter(c => {
            return c.userType === 'admin' && 
                   c.ws && 
                   c.ws.readyState === WebSocket.OPEN &&
                   c.online !== false; // Offline admin'leri dahil etme
        })
        .map(admin => {
            const adminKey = admin.uniqueId || admin.id;
            const isInCall = activeCallAdmins.has(adminKey);
            const isLocked = adminLocks.has(adminKey); // AdminLock kontrolü eklendi

            return {
                id: adminKey,
                name: admin.name,
                status: (isInCall || isLocked) ? 'busy' : 'available' // Lock durumu da meşgul sayılır
            };
        });

    const uniqueAdmins = [];
    const adminMap = new Map();

    adminList.forEach(admin => {
        const baseId = admin.id.split('_')[0]; 
        if (!adminMap.has(baseId) || admin.id > adminMap.get(baseId).id) {
            adminMap.set(baseId, admin);
        }
    });

    adminMap.forEach(admin => uniqueAdmins.push(admin));

    const message = JSON.stringify({
        type: 'admin-list-update',
        admins: uniqueAdmins
    });

    let customerSentCount = 0;
    clients.forEach(client => {
        if (client.userType === 'customer' && client.ws && client.ws.readyState === WebSocket.OPEN) {
            try {
                client.ws.send(message);
                customerSentCount++;
            } catch (error) {
                console.log(`⚠️ Admin list broadcast error to customer ${client.id}:`, error.message);
            }
        }
    });
    
    // Widget'lara da gönder
    let widgetSentCount = 0;
    clients.forEach(client => {
        if (client.userType === 'widget' && client.ws && client.ws.readyState === WebSocket.OPEN) {
            try {
                client.ws.send(message);
                widgetSentCount++;
            } catch (error) {
                console.log(`⚠️ Admin list broadcast error to widget ${client.id}:`, error.message);
            }
        }
    });

    console.log(`📡 Admin list sent to ${customerSentCount} customers and ${widgetSentCount} widgets: ${uniqueAdmins.length} unique admins`);
}


function broadcastCallbacksToAdmin(adminId) {
    const adminClient = Array.from(clients.values()).find(c => 
        c.userType === 'admin' && 
        (c.uniqueId === adminId || c.id === adminId) &&
        c.ws && c.ws.readyState === WebSocket.OPEN
    );

    if (adminClient) {
        const callbacks = adminCallbacks.get(adminId) || [];
        adminClient.ws.send(JSON.stringify({
            type: 'callback-list-update',
            callbacks: callbacks
        }));
        console.log(`📋 Callback list sent to admin ${adminId}: ${callbacks.length} callbacks`);
    }
}

// ================== AUTHENTICATION FUNCTIONS ==================

async function checkRateLimit(ip, userType = 'customer') {
    try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        const failedAttempts = await pool.query(
            'SELECT COUNT(*) FROM failed_logins WHERE ip_address = $1 AND user_type = $2 AND attempt_time > $3',
            [ip, userType, thirtyMinutesAgo]
        );

        const count = parseInt(failedAttempts.rows[0].count);

        return {
            allowed: count < 5,
            attempts: count,
            remaining: Math.max(0, 5 - count),
            resetTime: count >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null
        };
    } catch (error) {
        // Hata durumunda, rate limit uygulamadan devam et
        console.error('Rate limit kontrol hatası:', error.message);
        return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
    }
}

async function recordFailedLogin(ip, userType = 'customer') {
    try {
        await pool.query(
            'INSERT INTO failed_logins (ip_address, user_type) VALUES ($1, $2)',
            [ip, userType]
        );

        const rateStatus = await checkRateLimit(ip, userType);
        return rateStatus;
    } catch (error) {
        console.error('Başarısız giriş kaydetme hatası:', error.message);
        return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
    }
}

function generateTOTPSecret() {
    return speakeasy.generateSecret({ length: 20, name: SECURITY_CONFIG.TOTP_ISSUER }).base32;
}

function verifyTOTP(secret, token) {
    if (!secret || !token || token.length !== 6) return false;

    try {
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: SECURITY_CONFIG.TOTP_WINDOW
        });

        return verified;
    } catch (error) {
        console.error('TOTP doğrulama hatası:', error.message);
        return false;
    }
}

function generateTOTPQR(username, secret) {
    const serviceName = encodeURIComponent(SECURITY_CONFIG.TOTP_ISSUER);
    const accountName = encodeURIComponent(username);
    const otpauthURL = `otpauth://totp/${serviceName}:${accountName}?secret=${secret}&issuer=${serviceName}`;
    return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthURL)}`;
}

// ================== DATABASE FUNCTIONS (TEKRAR TANIMLANDI - initDatabase'deki tablo isimleri ve admin tablosu ile tutarlılık sağlandı) ==================

async function authenticateAdmin(username, password) {
    try {
        const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
        const result = await pool.query(
            'SELECT * FROM admin_credentials WHERE username = $1 AND password_hash = $2 AND is_active = TRUE',
            [username, hashedPassword]
        );

        if (result.rows.length > 0) {
            const admin = result.rows[0];
            await pool.query('UPDATE admin_credentials SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [admin.id]);
            return admin;
        }
        return null;
    } catch (error) {
        console.error('Admin kimlik doğrulama hatası:', error.message);
        return null;
    }
}

async function isUserApproved(userId, userName) {
    try {
        const result = await pool.query('SELECT * FROM approved_users WHERE id = $1', [userId]);

        if (result.rows.length > 0) {
            const user = result.rows[0];

            if (user.name.toLowerCase().trim() === userName.toLowerCase().trim()) {
                return {
                    approved: true,
                    credits: parseFloat(user.credits), // Decimal'i float olarak döndür
                    totalCalls: user.total_calls || 0,
                    lastCall: user.last_call,
                    user: user
                };
            } else {
                return { approved: false, reason: 'İsim uyuşmuyor.' };
            }
        } else {
            return { approved: false, reason: 'ID kodu bulunamadı.' };
        }
    } catch (error) {
        console.error('Kullanıcı onay kontrol hatası:', error.message);
        return { approved: false, reason: 'Sistem hatası.' };
    }
}

// ================== HEARTBEAT FUNCTIONS ==================

function startHeartbeat(userId, adminId, callKey) {
    if (activeHeartbeats.has(callKey)) {
        console.log(`⚠️ Heartbeat already exists for ${callKey}, stopping old one`);
        clearInterval(activeHeartbeats.get(callKey));
        activeHeartbeats.delete(callKey);
    }

    // Admin username'ini bul
    let adminUsername = adminId;
    const adminClient = Array.from(clients.values()).find(c => 
        c.userType === 'admin' && (c.uniqueId === adminId || c.id === adminId)
    );
    if (adminClient && adminClient.name) {
        adminUsername = adminClient.name;
    }

    console.log(`Admin earnings icin username: ${adminUsername}`);

    // İlk dakika krediyi hemen düş (call başında)
    (async () => {
        try {
            console.log(`Initial credit deduction for ${userId}`);
            const userResult = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);

            if (userResult.rows.length > 0) {
                const currentCredits = userResult.rows[0].credits;

                if (currentCredits <= 0) {
                    console.log(`No credits available for ${userId}, ending call immediately`);
                    stopHeartbeat(callKey, 'no_credits');
                    return;
                }

                const newCredits = Math.max(0, currentCredits - 1);
                await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);

                await pool.query(`
                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                    VALUES ($1, $2, $3, $4, $5)
                `, [userId, 'initial', -1, newCredits, `Arama baslangic kredisi`]);

                // Initial admin kazancı
                try {
                    await pool.query(`
                        INSERT INTO admin_earnings (username, total_earned) 
                        VALUES ($1, 1)
                        ON CONFLICT (username) 
                        DO UPDATE SET 
                            total_earned = admin_earnings.total_earned + 1,
                            last_updated = CURRENT_TIMESTAMP
                    `, [adminUsername]);
                    console.log(`Admin ${adminUsername} kazanci +1 kredi`);
                } catch (error) {
                    console.log(`Admin kazanc hatası: ${error.message}`);
                }

                // Customer'a kredi güncellemesi gönder
                const customerClient = clients.get(userId);
                if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
                    customerClient.ws.send(JSON.stringify({
                        type: 'credit-update',
                        credits: newCredits,
                        creditsUsed: 1
                    }));
                }
                console.log(`Initial credit deducted: ${userId} ${currentCredits}→${newCredits}`);
            }
        } catch (error) {
            console.log(`Initial credit deduction error ${callKey}:`, error.message);
        }
    })();

    console.log(`Starting heartbeat: ${callKey}`);

    const heartbeat = setInterval(async () => {
        console.log(`Heartbeat tick for ${callKey}`);
        console.log(`Checking credits for user: ${userId}`);

        try {
            // Admin hala aktif mi kontrol et
            const adminClient = Array.from(clients.values()).find(c => 
                c.uniqueId === adminId && 
                c.userType === 'admin' && 
                c.ws && c.ws.readyState === WebSocket.OPEN
            );

            if (!adminClient) {
                console.log(`Admin ${adminId} disconnected, stopping heartbeat`);
                stopHeartbeat(callKey, 'admin_disconnected');
                return;
            }

            // Customer hala bağlı mı?
            const customerClient = clients.get(userId);
            if (!customerClient || customerClient.ws.readyState !== WebSocket.OPEN) {
                console.log(`Customer ${userId} disconnected, stopping heartbeat`);
                stopHeartbeat(callKey, 'customer_disconnected');
                return;
            }

            const userResult = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
            console.log(`Query result:`, userResult.rows);

            if (userResult.rows.length > 0) {
                const currentCredits = userResult.rows[0].credits;

                if (currentCredits <= 0) {
                    stopHeartbeat(callKey, 'no_credits');
                    return;
                }

                const newCredits = Math.max(0, currentCredits - 1);
                await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);

                // Admin kazancı artır
                try {
                    await pool.query(`
                        INSERT INTO admin_earnings (username, total_earned) 
                        VALUES ($1, 1)
                        ON CONFLICT (username) 
                        DO UPDATE SET 
                            total_earned = admin_earnings.total_earned + 1,
                            last_updated = CURRENT_TIMESTAMP
                    `, [adminUsername]);
                    console.log(`Admin ${adminUsername} kazanci +1 kredi`);
                } catch (error) {
                    console.log(`Admin kazanc hatası: ${error.message}`);
                }

                await pool.query(`
                    INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
                    VALUES ($1, $2, $3, $4, $5)
                `, [userId, 'heartbeat', -1, newCredits, `Arama dakikasi`]);

                // Customer'a kredi güncellemesi gönder
                const customerClient = clients.get(userId);
                if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
                    customerClient.ws.send(JSON.stringify({
                        type: 'credit-update',
                        credits: newCredits,
                        creditsUsed: 1
                    }));
                }
                console.log(`Credit deducted: ${userId} ${currentCredits}→${newCredits} (Admin: ${adminId})`);
            }
        } catch (error) {
            console.error(`❌ Heartbeat error ${callKey}:`, error.message);
        }
    }, HEARTBEAT_INTERVAL);

    activeHeartbeats.set(callKey, heartbeat);

    activeCallAdmins.set(adminId, {
        customerId: userId,
        callStartTime: Date.now()
    });

    // Admin meşgul oldu, listesi güncelle
    broadcastAdminListToCustomers();
}

function stopHeartbeat(callKey, reason = 'normal') {
    const heartbeat = activeHeartbeats.get(callKey);
    if (heartbeat) {
        clearInterval(heartbeat);
        activeHeartbeats.delete(callKey);

        // CallKey'den userId ve adminId'yi çıkar
        let userId = 'unknown';
        let adminId = 'unknown';
        const parts = callKey.split('-');
        if (parts.length === 2) {
            userId = parts[0];
            adminId = parts[1];
        }

        // Lock'u temizle
        adminLocks.delete(adminId);
        console.log(`🔓 Admin ${adminId} lock kaldırıldı - call bitti`);

        // activeCallAdmins'den temizle
        activeCallAdmins.delete(adminId);

        console.log(`💔 Heartbeat stopped: ${callKey} (${reason})`);

        // activeCalls'tan ilgili çağrıyı temizle
        for (const [id, call] of activeCalls.entries()) {
            if (call.adminId === adminId && call.customerId === userId) {
                activeCalls.delete(id);
                break;
            }
        }

        broadcastCallEnd(userId, adminId, reason);

        // Admin listesini güncelle - ÖNEMLİ!
        broadcastAdminListToCustomers();

        setTimeout(() => {
            broadcastAdminListToCustomers();
        }, 1000);
    }
}

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

    const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
    adminClients.forEach(client => {
        if (client.ws && client.ws.readyState === WebSocket.OPEN) {
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

function broadcastCallEnd(userId, adminId, reason) {
    const customerClient = clients.get(userId);
    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({
            type: 'call-ended',
            reason: reason,
            endedBy: 'system'
        }));
    }

    const adminClient = Array.from(clients.values()).find(c => 
        c.userType === 'admin' && (c.uniqueId === adminId || c.id === adminId)
    );

    if (adminClient && adminClient.ws && adminClient.ws.readyState === WebSocket.OPEN) {
        adminClient.ws.send(JSON.stringify({
            type: 'call-ended',
            userId: userId,
            reason: reason,
            endedBy: 'system'
        }));
    }
}

// ================== EXPRESS ROUTE HANDLERS ==================

app.get('/', (req, res) => {
    if (req.session.superAdmin) {
        return res.redirect(SECURITY_CONFIG.SUPER_ADMIN_PATH);
    }
    if (req.session.normalAdmin) {
        return res.redirect(SECURITY_CONFIG.NORMAL_ADMIN_PATH);
    }

    res.sendFile(path.join(__dirname, 'login.html')); // Doğrudan login.html'yi sun
});

// Admin giriş sayfaları
app.get(SECURITY_CONFIG.SUPER_ADMIN_PATH, (req, res) => {
    // Sadece Super Admin'lerin erişimine izin ver
    if (req.session.superAdmin && req.session.superAdmin.username) {
        res.sendFile(path.join(__dirname, 'super-admin.html'));
    } else {
        res.redirect('/'); // Giriş sayfasına yönlendir
    }
});

app.get(SECURITY_CONFIG.NORMAL_ADMIN_PATH, (req, res) => {
    // Super veya Normal Admin'lerin erişimine izin ver
    if (req.session.superAdmin || req.session.normalAdmin) {
        res.sendFile(path.join(__dirname, 'admin-panel.html'));
    } else {
        res.redirect('/'); // Giriş sayfasına yönlendir
    }
});

// Müşteri uygulaması
app.get(SECURITY_CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// YENİ: Widget uygulaması
app.get(SECURITY_CONFIG.WIDGET_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'widget.html'));
});

// Auth endpoints
app.post('/auth/super-login', async (req, res) => {
    const { username, password, totpCode, step } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;

    try {
        const rateStatus = await checkRateLimit(clientIP, 'super-admin');
        if (!rateStatus.allowed) {
            return res.json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }

        const admin = await authenticateAdmin(username, password);
        if (!admin || admin.role !== 'super') {
            await recordFailedLogin(clientIP, 'super-admin');
            return res.json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }

        if (admin.secret_totp) { // 'totp_secret' yerine 'secret_totp'
            if (step !== '2fa') {
                req.session.tempSuperAdmin = { 
                    id: admin.id, 
                    username: admin.username,
                    timestamp: Date.now()
                };
                return res.json({ 
                    success: false, 
                    require2FA: true,
                    message: '2FA kodu gerekli'
                });
            } else {
                if (!req.session.tempSuperAdmin || 
                    req.session.tempSuperAdmin.id !== admin.id ||
                    Date.now() - req.session.tempSuperAdmin.timestamp > 300000) {
                    return res.json({ success: false, error: 'Oturum süresi doldu, tekrar deneyin!' });
                }

                if (!totpCode || !verifyTOTP(admin.secret_totp, totpCode)) { // 'totp_secret' yerine 'secret_totp'
                    await recordFailedLogin(clientIP, 'super-admin');
                    return res.json({ success: false, error: 'Geçersiz 2FA kodu!' });
                }

                delete req.session.tempSuperAdmin;
            }
        } else {
            // Eğer 2FA sırrı yoksa, oluştur ve kullanıcıya QR kodu ile birlikte gönder
            const newSecret = generateTOTPSecret();
            await pool.query('UPDATE admin_credentials SET secret_totp = $1 WHERE username = $2', [newSecret, username]);
            const qrCodeUrl = generateTOTPQR(username, newSecret);
            return res.json({
                success: false,
                error: '2FA kurulumu gerekli. Lütfen QR kodunu tarayın ve kodu girin.',
                requires2FASetup: true,
                secretTotp: newSecret,
                qrCodeUrl: qrCodeUrl
            });
        }

        req.session.superAdmin = { 
            id: admin.id, 
            username: admin.username, 
            loginTime: new Date() 
        };
        res.json({ success: true, redirectUrl: SECURITY_CONFIG.SUPER_ADMIN_PATH });

    } catch (error) {
        console.error('Super login error:', error);
        res.status(500).json({ success: false, error: 'Sistem hatası!' });
    }
});

app.post('/auth/admin-login', async (req, res) => {
    const { username, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;

    try {
        const rateStatus = await checkRateLimit(clientIP, 'admin');
        if (!rateStatus.allowed) {
            return res.json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }

        const admin = await authenticateAdmin(username, password);
        if (admin && admin.role === 'normal') {
            req.session.normalAdmin = { id: admin.id, username: admin.username, loginTime: new Date() };
            res.json({ success: true, redirectUrl: SECURITY_CONFIG.NORMAL_ADMIN_PATH });
        } else {
            await recordFailedLogin(clientIP, 'admin');
            res.json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ success: false, error: 'Sistem hatası!' });
    }
});

app.get('/auth/check-session', (req, res) => {
    if (req.session && req.session.superAdmin) {
        res.json({ authenticated: true, role: 'super', username: req.session.superAdmin.username });
    } else if (req.session && req.session.normalAdmin) {
        res.json({ authenticated: true, role: 'normal', username: req.session.normalAdmin.username });
    } else {
        res.json({ authenticated: false });
    }
});

app.post('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ success: false, error: 'Çıkış hatası' });
        }
        res.json({ success: true });
    });
});

// ================== SUPER ADMIN API ENDPOINTS ==================

// İstatistikleri al (Super Admin)
app.get('/api/stats', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const totalUsers = (await pool.query('SELECT COUNT(*) FROM approved_users')).rows[0].count;
        const totalCredits = (await pool.query('SELECT SUM(credits) FROM approved_users')).rows[0].sum || 0;
        const totalCalls = (await pool.query('SELECT COUNT(*) FROM call_history')).rows[0].count;
        const onlineUsers = Array.from(clients.values()).filter(c => c.userType === 'customer' && c.ws.readyState === WebSocket.OPEN).length;
        const activeAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin' && c.ws.readyState === WebSocket.OPEN).length;

        res.json({
            totalUsers: parseInt(totalUsers),
            totalCredits: parseFloat(totalCredits),
            totalCalls: parseInt(totalCalls),
            onlineUsers: onlineUsers,
            activeAdmins: activeAdmins,
            activeHeartbeats: activeHeartbeats.size
        });
    } catch (error) {
        console.error('API stats error:', error.message);
        res.status(500).json({ error: 'İstatistikler alınamadı.' });
    }
});

// Onaylı kullanıcıları al (Super Admin)
app.get('/api/approved-users', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows.map(user => ({
            ...user,
            credits: parseFloat(user.credits) // Krediyi float olarak gönder
        })));
    } catch (error) {
        console.error('API approved-users error:', error.message);
        res.status(500).json({ error: 'Onaylı kullanıcılar alınamadı.' });
    }
});

// Onaylı kullanıcı ekle (Super Admin)
app.post('/api/approved-users', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    const { id, name, credits } = req.body;
    try {
        const check = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
        if (check.rows.length > 0) {
            return res.status(400).json({ success: false, error: 'Bu ID zaten kullanılıyor.' });
        }
        const result = await pool.query(
            'INSERT INTO approved_users (id, name, credits) VALUES ($1, $2, $3) RETURNING *',
            [id, name, credits]
        );
        res.json({ success: true, user: { ...result.rows[0], credits: parseFloat(result.rows[0].credits) } });
    } catch (error) {
        console.error('API add user error:', error.message);
        res.status(500).json({ success: false, error: 'Kullanıcı eklenemedi.' });
    }
});

// Kullanıcı kredisi güncelle (Super Admin)
app.post('/api/approved-users/:userId/credits', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    const { userId } = req.params;
    const { credits, reason } = req.body;
    try {
        const currentUser = (await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId])).rows[0];
        if (!currentUser) {
            return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });
        }
        const oldCredits = parseFloat(currentUser.credits);
        const newCredits = parseInt(credits);
        const creditDiff = newCredits - oldCredits;
        const transactionType = creditDiff > 0 ? 'add' : 'subtract';

        await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);

        await pool.query(`
            INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description)
            VALUES ($1, $2, $3, $4, $5)
        `, [userId, transactionType, creditDiff, newCredits, reason || 'Super admin tarafından güncellendi']);
        
        // Eğer kullanıcı online ise, client'ına kredi güncellemesi gönder
        const userClient = clients.get(userId);
        if (userClient && userClient.ws.readyState === WebSocket.OPEN) {
            userClient.credits = newCredits; // Client objesindeki krediyi güncelle
            userClient.ws.send(JSON.stringify({ type: 'credit-update', credits: newCredits }));
            console.log(`📡 Kullanıcı ${userId} kredisi online olarak güncellendi: ${newCredits}`);
        }

        res.json({ success: true, credits: newCredits, oldCredits });
    } catch (error) {
        console.error('API update user credits error:', error.message);
        res.status(500).json({ success: false, error: 'Kredi güncellenemedi.' });
    }
});

// Kullanıcı sil (Super Admin)
app.delete('/api/approved-users/:userId', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    const { userId } = req.params;
    try {
        await pool.query('DELETE FROM approved_users WHERE id = $1', [userId]);
        res.json({ success: true, message: 'Kullanıcı başarıyla silindi.' });
    } catch (error) {
        console.error('API delete user error:', error.message);
        res.status(500).json({ success: false, error: 'Kullanıcı silinemedi.' });
    }
});

// Tüm çağrıları al (Super Admin)
app.get('/api/calls', async (req, res) => {
    if (!req.session || !req.session.superAdmin) { // Normal adminler de çağrıları görebilmeli
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT * FROM call_history ORDER BY call_time DESC LIMIT 100');
        res.json(result.rows);
    } catch (error) {
        console.error('API get calls error:', error.message);
        res.status(500).json({ error: 'Çağrılar alınamadı.' });
    }
});

// Tüm adminleri al (Super Admin)
app.get('/api/admins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT id, username, role, is_active, last_login FROM admin_credentials ORDER BY username ASC');
        res.json(result.rows);
    } catch (error) {
        console.error('API get admins error:', error.message);
        res.status(500).json({ error: 'Adminler alınamadı.' });
    }
});

// Yeni admin ekle (Super Admin)
app.post('/api/admins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    const { username, password, role } = req.body;
    try {
        const check = await pool.query('SELECT * FROM admin_credentials WHERE username = $1', [username]);
        if (check.rows.length > 0) {
            return res.status(400).json({ success: false, error: 'Bu kullanıcı adı zaten kullanılıyor.' });
        }
        
        const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
        let totpSecret = null;
        if (role === 'super') {
            totpSecret = generateTOTPSecret();
        }
        await pool.query(
            'INSERT INTO admin_credentials (username, password_hash, role, secret_totp) VALUES ($1, $2, $3, $4)',
            [username, passwordHash, role, totpSecret]
        );
        const response = { success: true, message: 'Admin başarıyla eklendi.' };
        if (totpSecret) {
            response.totpSecret = totpSecret;
            response.qrCode = generateTOTPQR(username, totpSecret);
        }
        res.json(response);
    } catch (error) {
        console.error('API add admin error:', error.message);
        res.status(500).json({ success: false, error: 'Admin eklenemedi.' });
    }
});

// KVKK onaylarını al (Super Admin)
app.get('/api/kvkk-consents', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT * FROM kvkk_consents ORDER BY consent_date DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('API get kvkk consents error:', error.message);
        res.status(500).json({ error: 'KVKK onayları alınamadı.' });
    }
});

// Başarısız girişleri al (Super Admin)
app.get('/api/failed-logins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT * FROM failed_logins ORDER BY attempt_time DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('API get failed logins error:', error.message);
        res.status(500).json({ error: 'Başarısız girişler alınamadı.' });
    }
});

// Başarısız girişleri temizle (Super Admin)
app.post('/api/clear-failed-logins', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        await pool.query('DELETE FROM failed_logins');
        res.json({ success: true, message: 'Başarısız giriş kayıtları temizlendi.' });
    } catch (error) {
        console.error('API clear failed logins error:', error.message);
        res.status(500).json({ success: false, error: 'Başarısız giriş kayıtları temizlenemedi.' });
    }
});

// Duyuru gönderme (Super Admin)
app.post('/api/announcement', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    const { text, type, expires_at } = req.body;
    if (!text) {
        return res.status(400).json({ success: false, error: 'Duyuru metni boş olamaz.' });
    }

    try {
        // Mevcut duyuruyu sil
        await pool.query('DELETE FROM announcements');

        const result = await pool.query(
            'INSERT INTO announcements (message, type, expires_at) VALUES ($1, $2, $3) RETURNING *',
            [text, type || 'info', expires_at || null]
        );
        currentAnnouncement = { text, type: type || 'info' };

        // Tüm müşterilere ve WIDGET'lara duyuruyu yayınla
        broadcastToCustomers({ type: 'announcement-broadcast', announcement: { text, type: type || 'info' } });
        broadcastToWidgets({ type: 'announcement-broadcast', announcement: { text, type: type || 'info' } }); // Widget'lara eklendi

        res.json({ success: true, announcement: result.rows[0] });
    } catch (error) {
        console.error('API send announcement error:', error.message);
        res.status(500).json({ success: false, error: 'Duyuru gönderilemedi.' });
    }
});

// Duyuru silme (Super Admin)
app.delete('/api/announcement', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        await pool.query('DELETE FROM announcements');
        currentAnnouncement = null;

        // Tüm müşterilere ve WIDGET'lara duyurunun silindiğini bildir
        broadcastToCustomers({ type: 'announcement-deleted' });
        broadcastToWidgets({ type: 'announcement-deleted' }); // Widget'lara eklendi

        res.json({ success: true, message: 'Duyuru başarıyla silindi.' });
    } catch (error) {
        console.error('API delete announcement error:', error.message);
        res.status(500).json({ success: false, error: 'Duyuru silinemedi.' });
    }
});

// Mevcut duyuruyu al (Super Admin)
app.get('/api/announcement', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT message AS text, type FROM announcements ORDER BY created_at DESC LIMIT 1');
        if (result.rows.length > 0) {
            res.json({ announcement: result.rows[0] });
        } else {
            res.json({ announcement: null });
        }
    } catch (error) {
        console.error('API get announcement error:', error.message);
        res.status(500).json({ error: 'Duyuru alınamadı.' });
    }
});


// Admin kazançlarını al (Super Admin)
app.get('/api/admin-earnings', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT username, total_earned, last_updated FROM admin_earnings ORDER BY total_earned DESC');
        res.json(result.rows.map(row => ({
            ...row,
            total_earned: parseFloat(row.total_earned) // float olarak gönder
        })));
    } catch (error) {
        console.error('API get admin earnings error:', error.message);
        res.status(500).json({ error: 'Admin kazançları alınamadı.' });
    }
});

// Admin kazancını sıfırla (Super Admin)
app.post('/api/reset-admin-earnings/:username', async (req, res) => {
    if (!req.session || !req.session.superAdmin) {
        return res.status(401).json({ error: 'Yetkisiz erişim.' });
    }
    const { username } = req.params;
    try {
        await pool.query('UPDATE admin_earnings SET total_earned = 0, last_updated = CURRENT_TIMESTAMP WHERE username = $1', [username]);
        res.json({ success: true, message: 'Admin kazancı sıfırlandı.' });
    } catch (error) {
        console.error('API reset admin earnings error:', error.message);
        res.status(500).json({ success: false, error: 'Kazanç sıfırlanamadı.' });
    }
});


// ================== WebSocket Mesaj İşleyicileri ==================

wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress || 'unknown';
    // Yeni bağlantı için benzersiz bir ID oluştur ve clients map'ine ekle
    const uniqueId = `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    clients.set(uniqueId, { ws, uniqueId, userType: null, id: null, name: null, credits: null, ip: clientIP, online: true });
    console.log(`⚡️ Yeni bağlantı: ${uniqueId} (IP: ${clientIP})`);


    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);

            let senderInfo = clients.get(uniqueId); // uniqueId ile senderInfo'yu al
            
            // Eğer register mesajı gelirse senderInfo'yu güncelleriz
            if (message.type === 'register' && message.userType) {
                senderInfo.userType = message.userType;
                senderInfo.id = message.userId;
                senderInfo.name = message.name;
                senderInfo.credits = message.credits; // Müşteri ise kredi bilgisini al
                clients.set(message.userId, senderInfo); // ID bazında da erişim için
                clients.delete(uniqueId); // Geçici uniqueId'yi sil
                senderInfo.uniqueId = message.userId; // uniqueId'yi kalıcı id yap
                console.log(`📝 ${senderInfo.userType} kaydedildi: ${senderInfo.name} (ID: ${senderInfo.id})`);

                // Widget'lar için özel kayıt
                if (senderInfo.userType === 'widget') {
                    console.log(`📝 Widget kaydedildi: ${senderInfo.id}`);
                    // Duyuru varsa gönder
                    if (currentAnnouncement) {
                        senderInfo.ws.send(JSON.stringify({ type: 'announcement-broadcast', announcement: currentAnnouncement }));
                    }
                    // Admin listesini gönder
                    broadcastAdminListToCustomers(); // Bu fonksiyon zaten widget'lara da gönderiyor
                    return; // Widget kaydından sonra diğer işlemlere devam etme
                }
            }
            
            const senderId = senderInfo ? (senderInfo.uniqueId || senderInfo.id) : (message.userId || 'unknown');
            const senderType = senderInfo ? senderInfo.userType : 'unknown';

            console.log(`📨 Message: ${message.type} from ${senderId} (${senderType})`);

            switch (message.type) {
                case 'register':
                    // Üstte halihazırda işlendi
                    // Duyuru varsa gönder
                    if (currentAnnouncement) {
                        senderInfo.ws.send(JSON.stringify({ type: 'announcement-broadcast', announcement: currentAnnouncement }));
                    }
                    broadcastAdminListToCustomers();
                    // Admin ise, callback listesini de gönder
                    if (senderInfo.userType === 'admin') {
                        broadcastCallbacksToAdmin(senderInfo.id);
                    }
                    break;

                case 'login-request':
                    const rateLimit = await checkRateLimit(clientIP);
                    if (!rateLimit.allowed) {
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            rateLimited: true,
                            attempts: rateLimit.attempts,
                            remaining: rateLimit.remaining,
                            resetTime: rateLimit.resetTime,
                            error: `Çok fazla başarısız deneme!`
                        }));
                        break;
                    }

                    const approval = await isUserApproved(message.userId, message.userName);

                    if (approval.approved) {
                        // Client objesindeki kredi bilgisini güncelle
                        if (senderInfo) {
                            senderInfo.credits = approval.credits;
                        }

                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: true,
                            credits: approval.credits,
                            user: approval.user
                        }));
                    } else {
                        const newRateStatus = await recordFailedLogin(clientIP);
                        ws.send(JSON.stringify({
                            type: 'login-response',
                            success: false,
                            reason: approval.reason,
                            remaining: newRateStatus.remaining,
                            attempts: newRateStatus.attempts,
                            rateLimited: !newRateStatus.allowed
                        }));
                    }
                    break;

                case 'direct-call-request':
                    console.log(`📞 Direct call request from ${message.userName} (${message.userId}) to admin ${message.targetAdminId}`);
                    // Admin lock kontrolü
                    if (adminLocks.has(message.targetAdminId)) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Bu usta şu anda meşgul!'
                        }));
                        break;
                    }

                    // Admin'i kilitle
                    adminLocks.set(message.targetAdminId, {
                        lockedBy: message.userId,
                        lockTime: Date.now()
                    });

                    console.log(`🔒 Admin ${message.targetAdminId} kilitlendi: ${message.userId}`);
                    broadcastAdminListToCustomers();
                    
                    if (senderInfo.credits <= 0) { // SenderInfo'daki krediyi kontrol et
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Yetersiz kredi!'
                        }));
                        // Admin kilidini geri al (eğer kredi yetersizse)
                        adminLocks.delete(message.targetAdminId);
                        broadcastAdminListToCustomers();
                        break;
                    }
                    console.log('🔍 Admin aranıyor:', message.targetAdminId);
                    console.log('🔍 Mevcut adminler:', Array.from(clients.values()).filter(c => c.userType === 'admin').map(a => ({id: a.id, uniqueId: a.uniqueId, name: a.name})));
                    const targetAdmin = Array.from(clients.values()).find(c => 
                        c.userType === 'admin' && 
                        (c.uniqueId === message.targetAdminId || c.id === message.targetAdminId) &&
                        c.ws && c.ws.readyState === WebSocket.OPEN
                    );

                    if (!targetAdmin) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Seçilen usta şu anda bağlı değil!'
                        }));
                        // Admin kilidini geri al
                        adminLocks.delete(message.targetAdminId);
                        broadcastAdminListToCustomers();
                        break;
                    }

                    if (activeCallAdmins.has(targetAdmin.uniqueId)) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Seçilen usta şu anda başka bir aramada!'
                        }));
                        // Admin kilidini geri al
                        adminLocks.delete(message.targetAdminId);
                        broadcastAdminListToCustomers();
                        break;
                    }

                    targetAdmin.ws.send(JSON.stringify({
                        type: 'admin-call-request',
                        userId: message.userId,
                        userName: message.userName,
                        adminId: targetAdmin.uniqueId,
                        adminName: targetAdmin.name
                    }));

                    ws.send(JSON.stringify({
                        type: 'call-connecting'
                    }));

                    console.log(`📡 Call request sent to admin ${targetAdmin.name}`);
                    break;

                case 'callback-request':
                    console.log(`📝 Callback request from ${message.userName} (${message.userId}) to admin ${message.targetAdminId}`);

                    const callbackTargetAdmin = Array.from(clients.values()).find(c => 
                        c.userType === 'admin' && 
                        (c.uniqueId === message.targetAdminId || c.id === message.targetAdminId)
                    );

                    if (!callbackTargetAdmin) {
                        ws.send(JSON.stringify({
                            type: 'callback-failed',
                            reason: 'Seçilen usta bulunamadı!'
                        }));
                        break;
                    }

                    const adminCallbackList = adminCallbacks.get(callbackTargetAdmin.uniqueId) || [];

                    const existingCallback = adminCallbackList.find(cb => cb.customerId === message.userId);
                    if (existingCallback) {
                        ws.send(JSON.stringify({
                            type: 'callback-failed',
                            reason: 'Bu usta için zaten bir geri dönüş talebiniz var!'
                        }));
                        break;
                    }

                    adminCallbackList.push({
                        customerId: message.userId,
                        customerName: message.userName,
                        timestamp: Date.now()
                    });

                    adminCallbacks.set(callbackTargetAdmin.uniqueId, adminCallbackList);

                    ws.send(JSON.stringify({
                        type: 'callback-success',
                        adminName: callbackTargetAdmin.name
                    }));

                    broadcastCallbacksToAdmin(callbackTargetAdmin.uniqueId);

                    console.log(`📝 Callback added for admin ${callbackTargetAdmin.name}: ${message.userName}`);
                    break;

                case 'admin-call-customer':
                    console.log(`📞 Admin ${senderId} calling customer ${message.targetCustomerId}`);

                    const targetCustomer = clients.get(message.targetCustomerId);
                    if (!targetCustomer || targetCustomer.ws.readyState !== WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Müşteri şu anda bağlı değil!'
                        }));
                        break;
                    }

                    if (activeCallAdmins.has(senderId)) {
                        ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Zaten bir aramada bulunuyorsunuz!'
                        }));
                        break;
                    }

                    // Admin'i kilitle (admin bir müşteriyi aradığında)
                    adminLocks.set(senderId, {
                        lockedBy: message.targetCustomerId,
                        lockTime: Date.now()
                    });
                    broadcastAdminListToCustomers();

                    targetCustomer.ws.send(JSON.stringify({
                        type: 'admin-call-request',
                        adminId: senderId,
                        adminName: message.adminName || senderInfo?.name || 'Usta'
                    }));

                    ws.send(JSON.stringify({
                        type: 'call-connecting'
                    }));

                    console.log(`📡 Admin call request sent to customer ${message.targetCustomerId}`);
                    break;

                case 'accept-incoming-call':
                    console.log(`✅ Customer ${senderId} accepting call from admin ${message.adminId}`);

                    const acceptingAdmin = Array.from(clients.values()).find(c => 
                        c.userType === 'admin' && 
                        (c.uniqueId === message.adminId || c.id === message.adminId) &&
                        c.ws && c.ws.readyState === WebSocket.OPEN
                    );

                    if (!acceptingAdmin) {
                        ws.send(JSON.stringify({
                            type: 'call-failed',
                            reason: 'Usta artık bağlı değil!'
                        }));
                        break;
                    }
                    
                    const acceptCallKey = `${senderId}-${acceptingAdmin.uniqueId}`; // CallKey formatını düzelt
                    startHeartbeat(senderId, acceptingAdmin.uniqueId, acceptCallKey); // UserId'yi senderId olarak gönder

                    console.log(`💓 Heartbeat started for call: ${acceptCallKey}`);

                    acceptingAdmin.ws.send(JSON.stringify({
                        type: 'call-accepted',
                        customerId: senderId,
                        customerName: senderInfo?.name || 'Müşteri'
                    }));

                    const adminCallbacks2 = adminCallbacks.get(acceptingAdmin.uniqueId) || [];
                    const filteredCallbacks = adminCallbacks2.filter(cb => cb.customerId !== senderId);
                    adminCallbacks.set(acceptingAdmin.uniqueId, filteredCallbacks);
                    broadcastCallbacksToAdmin(acceptingAdmin.uniqueId);

                    broadcastAdminListToCustomers();
                    
                    ws.send(JSON.stringify({
                        type: 'call-accepted',
                        adminId: message.adminId,
                        adminName: acceptingAdmin.name || 'Admin'
                    }));
                    console.log('📤 call-accepted mesajı gönderildi customer a');
                    
                    break;

                case 'reject-incoming-call':
                    console.log(`❌ Gelen arama reddedildi (Admin: ${message.adminId}, Müşteri: ${senderId})`);

                    // Admin tarafından arama reddedildi
                    const rejectingAdmin = Array.from(clients.values()).find(c => 
                        c.userType === 'admin' && 
                        (c.uniqueId === message.adminId || c.id === message.adminId)
                    );

                    if (rejectingAdmin && rejectingAdmin.ws.readyState === WebSocket.OPEN) {
                        rejectingAdmin.ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Müşteri aramanızı reddetti.'
                        }));
                    }
                    
                    // Admin kilidini kaldır
                    adminLocks.delete(message.adminId);
                    broadcastAdminListToCustomers();
                    console.log(`🔓 Admin ${message.adminId} lock kaldırıldı - red`);
                    break;

                case 'admin-reject-call-request': // Admin gelen müşteri arama isteğini reddettiğinde
                    console.log(`❌ Admin ${senderId} müşteri arama isteğini reddetti: Müşteri ID: ${message.customerId}`);
                    const customerClientForReject = clients.get(message.customerId);
                    if (customerClientForReject && customerClientForReject.ws.readyState === WebSocket.OPEN) {
                        customerClientForReject.ws.send(JSON.stringify({
                            type: 'call-rejected',
                            reason: 'Usta arama isteğinizi reddetti.'
                        }));
                    }
                    // Admin kilidini kaldır
                    adminLocks.delete(senderId);
                    activeCallAdmins.delete(senderId);
                    broadcastAdminListToCustomers();
                    break;


                case 'remove-callback':
                    console.log(`🗑️ Admin ${senderId} removing callback for customer ${message.customerId}`);

                    const adminCallbackList2 = adminCallbacks.get(senderId) || [];
                    const filteredCallbacks2 = adminCallbackList2.filter(cb => cb.customerId !== message.customerId);
                    adminCallbacks.set(senderId, filteredCallbacks2);

                    broadcastCallbacksToAdmin(senderId);
                    break;
                    
                case 'admin-ready-for-webrtc':
                    console.log(`🔗 Admin ${senderId} WebRTC için hazır, customer ${message.userId} bilgilendiriliyor`);

                    const readyCustomer = clients.get(message.userId);
                    if (readyCustomer && readyCustomer.ws.readyState === WebSocket.OPEN) {
                        readyCustomer.ws.send(JSON.stringify({
                            type: 'admin-ready-for-webrtc',
                            adminId: message.adminId,
                            message: 'Admin WebRTC için hazır'
                        }));
                        console.log(`📡 Admin ready mesajı customer ${message.userId}'e gönderildi`);
                    }
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    const targetClient = findWebRTCTarget(message.targetId, senderType);
                    if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
                        const forwardMessage = {
                            type: message.type,
                            userId: senderId,
                            targetId: message.targetId
                        };

                        if (message.type === 'offer') forwardMessage.offer = message.offer;
                        if (message.type === 'answer') forwardMessage.answer = message.answer;
                        if (message.type === 'ice-candidate') forwardMessage.candidate = message.candidate;

                        targetClient.ws.send(JSON.stringify(forwardMessage));
                        console.log(`🔄 WebRTC ${message.type} forwarded: ${senderId} → ${message.targetId}`);
                    } else {
                        console.log(`⚠️ WebRTC target not found: ${message.targetId}`);
                    }
                    break;

                case 'end-call':
                    console.log(`📞 Call ended by ${senderType} ${senderId}`);

                    // CallKey'i bulmak için önce senderId ve targetId'yi belirle
                    let endCallCustomerId = null;
                    let endCallAdminId = null;

                    if (senderType === 'admin') {
                        endCallAdminId = senderId;
                        endCallCustomerId = message.targetId; // Admin'den geliyorsa targetId müşteridir
                    } else if (senderType === 'customer') {
                        endCallCustomerId = senderId;
                        endCallAdminId = message.targetId; // Müşteriden geliyorsa targetId admindir
                    }

                    if (endCallCustomerId && endCallAdminId) {
                        const endCallKey = `${endCallCustomerId}-${endCallAdminId}`;
                        stopHeartbeat(endCallKey, 'user_ended');
                    } else {
                        console.warn(`⚠️ end-call mesajı için müşteri veya admin ID bulunamadı.`);
                    }
                    break;
            }

        } catch (error) {
            console.log('Message processing error:', error.message);
        }
    });

ws.on('close', () => {
    const client = clients.get(uniqueId); // uniqueId ile istemciyi bul
    if (!client) {
        // Eğer client uniqueId ile bulunamazsa, zaten register ile id'ye geçiş yapmış olabilir
        for (const [id, c] of clients.entries()) {
            if (c.ws === ws) {
                client = c;
                break;
            }
        }
    }

    if (client) {
        console.log(`👋 WebSocket closed: ${client.name || 'Unknown'} (${client.userType || 'unknown'})`);

        if (client.userType === 'admin') {
            const adminKey = client.uniqueId || client.id;
            console.log(`🔴 Admin ${adminKey} WebSocket closed`);

            const adminCallInfo = activeCallAdmins.get(adminKey);

            if (adminCallInfo) {
                console.log(`⏳ Admin ${adminKey} in active call with ${adminCallInfo.customerId}, waiting for reconnection...`);

                // Admin'i clients'tan SILME, sadece ws'i null yap ve online durumunu güncelle
                client.ws = null;
                client.online = false;
                
                setTimeout(() => {
                    const currentClient = clients.get(adminKey); // Yeniden bağlantı kontrolü
                    // Admin hala var ama bağlantısı yok mu kontrol et
                    if (!currentClient || !currentClient.ws || currentClient.ws.readyState !== WebSocket.OPEN) {
                        console.log(`💔 Admin ${adminKey} failed to reconnect - ending call`);
                        const callKey = `${adminCallInfo.customerId}-${adminKey}`;
                        stopHeartbeat(callKey, 'admin_permanently_disconnected');
                        activeCallAdmins.delete(adminKey);
                        broadcastAdminListToCustomers(); // Admin listesini güncelle

                        // Admin'i tamamen temizle
                        clients.delete(adminKey);
                    } else {
                        console.log(`✅ Admin ${adminKey} successfully reconnected`);
                    }
                }, 15000); // 15 saniye bekleme süresi
            } else {
                // Call'da olmayan admin'i normal şekilde temizle
                clients.delete(adminKey);
                console.log(`🗑️ Deleted admin client record: ${adminKey}`);
            }
        } else if (client.userType === 'customer') {
            // Customer cleanup - normal
            let customerCallKey = null;
            for(const [ckey, cval] of activeCalls.entries()){
                if(cval.customerId === client.id){
                    customerCallKey = ckey;
                    break;
                }
            }
            if(customerCallKey){
                stopHeartbeat(customerCallKey, 'customer_disconnected');
            }
            clients.delete(client.id);
            console.log(`🗑️ Deleted customer client record: ${client.id}`);
        } else if (client.userType === 'widget') { // YENİ: Widget temizliği
            clients.delete(client.id);
            console.log(`🗑️ Deleted widget client record: ${client.id}`);
        }
    }

    // Her durumda broadcast yap
    setTimeout(() => {
        broadcastAdminListToCustomers();
    }, 100);
});

    ws.on('error', (error) => {
        console.log('WebSocket error:', error.message);
    });
});

// ================== HELPER FUNCTIONS ==================

function findClientById(ws) {
    for (const client of clients.values()) {
        if (client.ws === ws) {
            return client;
        }
    }
    return null;
}

function findWebRTCTarget(targetId, sourceType) {
    if (!targetId) {
        console.log('⚠️ targetId is null or undefined');
        return null;
    }

    let targetClient = clients.get(targetId);
    if (targetClient) {
        return targetClient;
    }

    // uniqueId ile arama (ADMIN123_456_abc formatı)
    if (targetId.includes('_')) {
        const normalId = targetId.split('_')[0];
        for (const [clientId, clientData] of clients.entries()) {
            if (clientData.id === normalId && clientData.userType === 'admin') {
                return clientData;
            }
        }
    } else {
        // Normal ID ile arama (ADMIN123 formatı)
        for (const [clientId, clientData] of clients.entries()) {
            if ((clientId.startsWith && clientId.startsWith(targetId + '_')) && clientData.userType === 'admin') {
                return clientData;
            }
        }
    }

    console.log(`⚠️ WebRTC target not found: ${targetId}`);
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
        if (client.ws && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(message);
        }
    });
}

// ================== ERROR HANDLING ==================

app.use((req, res) => {
    res.status(404).send(`
        <div style="text-align: center; padding: 50px; font-family: system-ui;">
            <h1>🔐 404 - Sayfa Bulunamadı</h1>
            <p>Güvenlik nedeniyle bu sayfa mevcut değil.</p>
            <p><a href="/" style="color: #dc2626; text-decoration: none;">← Ana sayfaya dön</a></p>
        </div>
    `);
});

// ================== SERVER STARTUP ==================

async function startServer() {
    console.log('🚀 VIPCEP Server Başlatılıyor...');

    await initDatabase();
    
    // Aktif duyuruyu veritabanından yükle (uygulama başlangıcında)
    try {
        const result = await pool.query('SELECT message AS text, type FROM announcements ORDER BY created_at DESC LIMIT 1');
        if (result.rows.length > 0) {
            currentAnnouncement = result.rows[0];
            console.log('📢 Aktif duyuru yüklendi:', currentAnnouncement);
        } else {
            console.log('📢 Aktif duyuru bulunamadı.');
        }
    } catch (error) {
        console.error('❌ Aktif duyuru yükleme hatası:', error.message);
    }


    server.listen(PORT, '0.0.0.0', () => {
        console.log('🎯 VIPCEP Server Çalışıyor!');
        console.log(`🔗 Port: ${PORT}`);
        console.log(`🌐 URL: http://0.0.0.0:${PORT}`);
        console.log(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
        console.log(`🗄️ Veritabanı: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
        console.log('');
        console.log('� GÜVENLİK URL\'LERİ:');
        console.log(` 🔴 Super Admin: ${SECURITY_CONFIG.SUPER_ADMIN_PATH}`);
        console.log(` 🟡 Normal Admin: ${SECURITY_CONFIG.NORMAL_ADMIN_PATH}`);
        console.log(` 🟢 Customer App: ${SECURITY_CONFIG.CUSTOMER_PATH}`);
        console.log(` 🔵 Widget App: ${SECURITY_CONFIG.WIDGET_PATH}`); // Widget yolu eklendi
        console.log('');
        console.log('📞 YENİ SİSTEM: Admin Seçim + Callback + Kredi Düşme');
        console.log(`   └── Heartbeat interval: ${HEARTBEAT_INTERVAL/1000} saniye`);
        console.log(`   └── Direct admin selection: Aktif`);
        console.log(`   └── Callback system: Aktif`);
        console.log(`   └── Credit deduction: %100 Güvenli`);
        console.log('');
        console.log('🛡️ GÜVENLİK ÖZELLİKLERİ:');
        console.log('   ✅ Credit tracking güvenli');
        console.log('   ✅ Admin disconnect koruması');
        console.log('   ✅ Heartbeat duplicate koruması');
        console.log('   ✅ Super Admin API endpoints');
        console.log('   ✅ 2FA sistem hazır');
        console.log('');
        console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
        console.log('✅ Yeni sistem hazır - Admin seçim + Callback + Kredi düşme garantili!');
    });
}

// ================== ERROR HANDLING ==================

process.on('uncaughtException', (error) => {
    console.log('❌ Yakalanmamış hata:', error.message);
});

process.on('unhandledRejection', (reason, promise) => {
    console.log('❌ İşlenmemiş promise reddi:', reason);
});

process.on('SIGTERM', () => {
    console.log('🔴 Server kapatılıyor...');

    for (const [callKey, heartbeat] of activeHeartbeats.entries()) {
        clearInterval(heartbeat);
        console.log(`💔 Stopping heartbeat: ${callKey}`);
    }
    activeHeartbeats.clear();
    activeCallAdmins.clear();
    activeCalls.clear();
    adminCallbacks.clear();

    server.close(() => {
        console.log('✅ Server başarıyla kapatıldı');
        process.exit(0);
    });
});

startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
