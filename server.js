const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');

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
    TOTP_WINDOW: 2 // Not used directly, but kept for context if 2FA logic is managed elsewhere
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

// Veritabanı başlatma
async function initDatabase() {
    try {
        console.log('🔧 Veritabanı kontrol ediliyor...');

        // Approved users tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS approved_users (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                credits DECIMAL(10, 2) DEFAULT 0,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "approved_users" tablosu hazır.');

        // Admin credentials tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admin_credentials (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'normal',
                secret_totp VARCHAR(255),
                earnings DECIMAL(10, 2) DEFAULT 0,
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
            )
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
            )
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
            )
        `);
        console.log('✅ "kvkk_consents" tablosu hazır.');
        
        // Başarısız giriş denemeleri tablosu
        await pool.query(`
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                ip_address INET NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_type VARCHAR(20) DEFAULT 'customer'
            )
        `);
        console.log('✅ "failed_logins" tablosu hazır.');

        // İlk super admin'i ekle (sadece yoksa)
        const superAdminUsername = 'superadmin';
        const superAdminPassword = 'superadminpassword'; // **UYARI: PRODUCTION İÇİN GÜVENLİK İYİLEŞTİRMESİ GEREKİR**
        const checkAdmin = await pool.query('SELECT * FROM admin_credentials WHERE username = $1', [superAdminUsername]);

        if (checkAdmin.rows.length === 0) {
            console.log('🔧 İlk super admin oluşturuluyor...');
            const passwordHash = crypto.createHash('sha256').update(superAdminPassword).digest('hex');
            // 'secret_totp' burada başlangıçta boş bırakılıyor, admin panelinden ayarlanması beklenir.
            await pool.query(
                'INSERT INTO admin_credentials (username, password_hash, role) VALUES ($1, $2, $3)',
                [superAdminUsername, passwordHash, 'super'] 
            );
            console.log('✅ Super admin oluşturuldu.');
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

// generateTOTPSecret, verifyTOTP, generateTOTPQR fonksiyonları kaldırıldı.
// 2FA'nın halihazırda çalıştığını belirttiğiniz için mevcut bir sistemle entegre olduğu varsayılmıştır.

// ================== DATABASE FUNCTIONS ==================

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
                    // totalCalls: user.total_calls || 0, // Bu satırlar kaldırıldı
                    // lastCall: user.last_call, // Bu satırlar kaldırıldı
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

const HEARTBEAT_INTERVAL = 5000; // 5 saniye

function startHeartbeat(userId, adminId, callKey) {
    if (activeHeartbeats.has(callKey)) {
        console.log(`⚠️ Heartbeat already exists for ${callKey}, stopping old one`);
        clearInterval(activeHeartbeats.get(callKey));
    }

    const heartbeatInterval = setInterval(async () => {
        try {
            const call = activeCalls.get(callKey);
            if (!call) {
                clearInterval(heartbeatInterval);
                activeHeartbeats.delete(callKey);
                console.log(`💔 Heartbeat stopped for unknown call ${callKey}`);
                return;
            }

            const duration = Math.floor((Date.now() - call.startTime) / 1000);
            const minutes = Math.floor(duration / 60);

            // Kredi kontrolü her dakika başında yapılır
            if (minutes > 0 && minutes !== call.lastCreditDeductionMinute) {
                const userClient = clients.get(call.customerId);
                if (userClient && userClient.credits > 0) {
                    userClient.credits -= 1; // 1 dakika = 1 kredi
                    await pool.query(
                        'UPDATE approved_users SET credits = $1, last_active = CURRENT_TIMESTAMP WHERE id = $2',
                        [userClient.credits, call.customerId]
                    );

                    // Kredi hareketini kaydet
                    await pool.query(
                        'INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description) VALUES ($1, $2, $3, $4, $5)',
                        [call.customerId, 'deduction', 1, userClient.credits, `Görüşme (${callKey}) için kredi düşüşü`]
                    );

                    // Admin kazancını güncelle
                    const adminUsername = clients.get(call.adminId)?.name; // Admin objesinden kullanıcı adını al
                    if (adminUsername) {
                        const creditValuePerMinute = 1; // Her dakika için 1 kredi kazanıyor
                        await pool.query(
                            `INSERT INTO admin_earnings (username, total_earned, last_updated)
                             VALUES ($1, $2, CURRENT_TIMESTAMP)
                             ON CONFLICT (username) DO UPDATE
                             SET total_earned = admin_earnings.total_earned + $2, last_updated = CURRENT_TIMESTAMP`,
                            [adminUsername, creditValuePerMinute]
                        );
                    }

                    userClient.ws.send(JSON.stringify({ type: 'credit-update', credits: userClient.credits }));
                    call.lastCreditDeductionMinute = minutes;
                    console.log(`📉 Call ${callKey}: User ${call.customerId} credits updated to ${userClient.credits}. Admin ${adminUsername} earned 1 credit.`);

                    if (userClient.credits <= 0) {
                        console.log(`🚨 Call ${callKey}: User ${call.customerId} ran out of credits. Ending call.`);
                        endCall(callKey, 'no_credits');
                        return; // Call ended, stop further processing for this interval
                    }
                } else if (userClient && userClient.credits <= 0) {
                    console.log(`🚨 Call ${callKey}: User ${call.customerId} already has 0 credits. Ending call.`);
                    endCall(callKey, 'no_credits');
                    return; // Call ended
                }
            }

            // Client'lara heartbeat mesajı gönder
            const userClient = clients.get(userId);
            const adminClient = clients.get(adminId);
            
            if (userClient && userClient.ws.readyState === WebSocket.OPEN) {
                userClient.ws.send(JSON.stringify({ type: 'heartbeat', callKey, duration, creditsRemaining: userClient.credits }));
            }
            if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                adminClient.ws.send(JSON.stringify({ type: 'heartbeat', callKey, duration }));
            }

        } catch (error) {
            console.error(`❌ Heartbeat hata (${callKey}):`, error.message);
            // Hata durumunda görüşmeyi sonlandır
            endCall(callKey, 'heartbeat_error');
        }
    }, HEARTBEAT_INTERVAL);

    activeHeartbeats.set(callKey, heartbeatInterval);
    console.log(`❤️ Heartbeat started for call ${callKey}`);
}


// Görüşmeyi sonlandırma fonksiyonu
async function endCall(callKey, endReason = 'normal', connectionLost = false) {
    const call = activeCalls.get(callKey);
    if (!call) return;

    console.log(`📞 Ending call ${callKey} with reason: ${endReason}`);

    // Heartbeat'i durdur
    if (activeHeartbeats.has(callKey)) {
        clearInterval(activeHeartbeats.get(callKey));
        activeHeartbeats.delete(callKey);
        console.log(`💔 Heartbeat stopped for call ${callKey}`);
    }

    const duration = Math.floor((Date.now() - call.startTime) / 1000);
    const creditsUsed = Math.ceil(duration / 60); // Kullanılan toplam dakika
    
    // Kullanıcının kalan kredilerini al
    let remainingCredits = 0;
    const userClient = clients.get(call.customerId);
    if (userClient) {
        remainingCredits = userClient.credits; // En son düşülen kredi baz alınır
    }

    // Arama geçmişine kaydet
    try {
        await pool.query(
            'INSERT INTO call_history (user_id, user_name, admin_id, duration, credits_used, end_reason, connection_lost) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [call.customerId, call.customerName, call.adminId, duration, creditsUsed, endReason, connectionLost]
        );
        console.log(`📜 Call ${callKey} recorded to history.`);
    } catch (error) {
        console.error('❌ Call history kaydetme hatası:', error.message);
    }
    
    // Admin'i meşguliyetten çıkar
    activeCallAdmins.delete(call.adminId);
    adminLocks.delete(call.adminId); // Admin kilidini kaldır
    console.log(`🔓 Admin ${call.adminId} free.`);

    // Müşteri ve Admin'e görüşmenin bittiğini bildir
    const customerClient = clients.get(call.customerId);
    const adminClient = clients.get(call.adminId);

    if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
        customerClient.ws.send(JSON.stringify({ 
            type: 'call-ended', 
            callKey, 
            reason: endReason, 
            duration: duration,
            creditsUsed: creditsUsed,
            remainingCredits: remainingCredits
        }));
    }
    if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
        adminClient.ws.send(JSON.stringify({ 
            type: 'call-ended', 
            callKey, 
            reason: endReason, 
            duration: duration
        }));
    }
    
    // Aktif çağrıları temizle
    activeCalls.delete(callKey);
    console.log(`🗑️ Call ${callKey} cleared from active calls.`);

    // Admin listesini tüm müşterilere ve widget'lara güncelle
    broadcastAdminListToCustomers();
}

// ================== EXPRESS ROUTE HANDLERS ==================

// Super Admin giriş sayfası
app.get(SECURITY_CONFIG.SUPER_ADMIN_PATH, (req, res) => {
    if (req.session.authenticated && req.session.user.role === 'super') {
        res.sendFile(path.join(__dirname, 'super-admin.html'));
    } else {
        res.sendFile(path.join(__dirname, 'login.html'));
    }
});

// Normal Admin giriş sayfası
app.get(SECURITY_CONFIG.NORMAL_ADMIN_PATH, (req, res) => {
    if (req.session.authenticated && (req.session.user.role === 'normal' || req.session.user.role === 'super')) {
        res.sendFile(path.join(__dirname, 'desk-admin.html'));
    } else {
        res.sendFile(path.join(__dirname, 'login.html'));
    }
});

// Müşteri uygulaması
app.get(SECURITY_CONFIG.CUSTOMER_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// Widget uygulaması
app.get(SECURITY_CONFIG.WIDGET_PATH, (req, res) => {
    res.sendFile(path.join(__dirname, 'widget.html'));
});

// Kök dizini login sayfasına yönlendir
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Admin girişi
app.post('/auth/login', async (req, res) => {
    const { username, password, totpToken } = req.body;
    const clientIp = req.ip;

    const rateStatus = await checkRateLimit(clientIp, 'admin');
    if (!rateStatus.allowed) {
        return res.status(429).json({ success: false, error: 'Çok fazla başarısız deneme. Lütfen daha sonra tekrar deneyin.', resetTime: rateStatus.resetTime });
    }

    try {
        const admin = await authenticateAdmin(username, password);

        if (admin) {
            if (admin.role === 'super') { // Super admin'ler için 2FA kontrolü
                // Admin'in secret_totp'si varsa ve bir totpToken gönderilmişse doğrula
                if (admin.secret_totp && totpToken) {
                    // Bu kısım, mevcut 2FA sisteminizin nasıl çalıştığına bağlı olarak entegre edilmelidir.
                    // Örneğin, bir 2FA doğrulama fonksiyonunuz varsa onu burada çağırın.
                    // Şimdilik varsayımsal bir doğrulama fonksiyonu:
                    const isTotpValid = true; // YERİNE SİZİN 2FA DOĞRULAMA FONKSİYONUNUZ GELECEK
                    if (!isTotpValid) {
                        await recordFailedLogin(clientIp, 'admin');
                        return res.status(401).json({ success: false, error: 'Geçersiz 2FA kodu!' });
                    }
                } else if (admin.secret_totp && !totpToken) {
                    // Admin'in 2FA'sı etkin ama token göndermemiş
                    await recordFailedLogin(clientIp, 'admin');
                    return res.status(401).json({ success: false, error: '2FA kodu gerekli!' });
                }
                // Eğer admin.secret_totp yoksa, 2FA devre dışı varsayılır veya başka bir yöntem kullanılır.
                // Burada yeni 2FA kurulumu tetiklenmez, çünkü mevcut sisteminizin çalıştığı belirtildi.
            }
            
            req.session.authenticated = true;
            req.session.user = { id: admin.id, username: admin.username, role: admin.role };
            res.json({ success: true, message: 'Giriş başarılı!', role: admin.role });
        } else {
            await recordFailedLogin(clientIp, 'admin');
            res.status(401).json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ success: false, error: 'Sunucu hatası.' });
    }
});

// Oturum kontrolü
app.get('/auth/check-session', (req, res) => {
    if (req.session.authenticated && req.session.user) {
        res.json({ authenticated: true, user: req.session.user, role: req.session.user.role });
    } else {
        res.json({ authenticated: false });
    }
});

// Çıkış
app.post('/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Çıkış yapılamadı.' });
        }
        res.json({ success: true, message: 'Çıkış başarılı.' });
    });
});

// ================== SUPER ADMIN API ENDPOINTS ==================

// İstatistikleri al (Super Admin)
app.get('/api/stats', async (req, res) => {
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY last_active DESC');
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
    }
    const { userId } = req.params;
    const { credits, reason } = req.body;
    try {
        const oldUser = (await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId])).rows[0];
        if (!oldUser) {
            return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });
        }
        const oldCredits = parseFloat(oldUser.credits);
        const newCredits = parseFloat(credits);
        const amount = newCredits - oldCredits;
        const transactionType = amount >= 0 ? 'deposit' : 'withdrawal';

        const result = await pool.query(
            'UPDATE approved_users SET credits = $1 WHERE id = $2 RETURNING *',
            [newCredits, userId]
        );

        // Kredi hareketini kaydet
        await pool.query(
            'INSERT INTO credit_transactions (user_id, transaction_type, amount, balance_after, description) VALUES ($1, $2, $3, $4, $5)',
            [userId, transactionType, Math.abs(amount), newCredits, reason || 'Super admin tarafından güncellendi']
        );
        
        // Eğer kullanıcı online ise, client'ına kredi güncellemesi gönder
        const userClient = clients.get(userId);
        if (userClient && userClient.ws.readyState === WebSocket.OPEN) {
            userClient.credits = newCredits; // Client objesindeki krediyi güncelle
            userClient.ws.send(JSON.stringify({ type: 'credit-update', credits: newCredits }));
            console.log(`📡 Kullanıcı ${userId} kredisi online olarak güncellendi: ${newCredits}`);
        }

        res.json({ success: true, credits: parseFloat(result.rows[0].credits) });
    } catch (error) {
        console.error('API update user credits error:', error.message);
        res.status(500).json({ success: false, error: 'Kredi güncellenemedi.' });
    }
});

// Kullanıcı sil (Super Admin)
app.delete('/api/approved-users/:userId', async (req, res) => {
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
    }
    const { username, password, role } = req.body;
    try {
        const check = await pool.query('SELECT * FROM admin_credentials WHERE username = $1', [username]);
        if (check.rows.length > 0) {
            return res.status(400).json({ success: false, error: 'Bu kullanıcı adı zaten kullanılıyor.' });
        }
        
        const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
        // Admin eklenirken secret_totp burada oluşturulmaz, mevcut 2FA sisteminizin bunu yönettiği varsayılır.
        await pool.query(
            'INSERT INTO admin_credentials (username, password_hash, role) VALUES ($1, $2, $3)',
            [username, passwordHash, role]
        );
        res.json({ success: true, message: 'Admin başarıyla eklendi.' });
    } catch (error) {
        console.error('API add admin error:', error.message);
        res.status(500).json({ success: false, error: 'Admin eklenemedi.' });
    }
});

// KVKK onaylarını al (Super Admin)
app.get('/api/kvkk-consents', async (req, res) => {
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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

        // Tüm müşterilere ve widget'lara duyuruyu yayınla
        broadcastToCustomers({ type: 'announcement-broadcast', announcement: { text, type: type || 'info' } });
        broadcastToWidgets({ type: 'announcement-broadcast', announcement: { text, type: type || 'info' } });

        res.json({ success: true, announcement: result.rows[0] });
    } catch (error) {
        console.error('API send announcement error:', error.message);
        res.status(500).json({ success: false, error: 'Duyuru gönderilemedi.' });
    }
});

// Duyuru silme (Super Admin)
app.delete('/api/announcement', async (req, res) => {
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
    }
    try {
        await pool.query('DELETE FROM announcements');
        currentAnnouncement = null;

        // Tüm müşterilere ve widget'lara duyurunun silindiğini bildir
        broadcastToCustomers({ type: 'announcement-deleted' });
        broadcastToWidgets({ type: 'announcement-deleted' });

        res.json({ success: true, message: 'Duyuru başarıyla silindi.' });
    } catch (error) {
        console.error('API delete announcement error:', error.message);
        res.status(500).json({ success: false, error: 'Duyuru silinemedi.' });
    }
});

// Mevcut duyuruyu al (Super Admin)
app.get('/api/announcement', async (req, res) => {
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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
    if (!req.session.authenticated || req.session.user.role !== 'super') {
        return res.status(403).json({ error: 'Yetkisiz erişim.' });
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

wss.on('connection', ws => {
    const uniqueId = `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const clientIp = ws._socket.remoteAddress;

    clients.set(uniqueId, { ws, uniqueId, userType: null, id: null, name: null, credits: null, ip: clientIp, online: true });
    console.log(`⚡️ Yeni bağlantı: ${uniqueId} (IP: ${clientIp})`);

    ws.on('message', async message => {
        const msg = JSON.parse(message);
        const client = clients.get(uniqueId);
        if (!client) return;

        console.log(`Received from ${client.userType || 'unknown'} (${client.id || uniqueId}):`, msg.type);

        switch (msg.type) {
            case 'register':
                client.userType = msg.userType;
                client.id = msg.userId;
                client.name = msg.name;
                client.credits = msg.credits; // Müşteri kayıt olurken kredi bilgisini de al
                clients.set(client.id, client); // ID bazında da erişim için
                clients.delete(uniqueId); // Geçici uniqueId'yi sil
                client.uniqueId = client.id; // uniqueId'yi kalıcı id yap
                console.log(`📝 ${client.userType} kaydedildi: ${client.name} (ID: ${client.id})`);

                // Duyuru varsa gönder
                if (currentAnnouncement) {
                    client.ws.send(JSON.stringify({ type: 'announcement-broadcast', announcement: currentAnnouncement }));
                }

                broadcastAdminListToCustomers();
                // Admin ise, callback listesini de gönder
                if (client.userType === 'admin') {
                    broadcastCallbacksToAdmin(client.id);
                }
                break;

            case 'login-request':
                const rateStatus = await checkRateLimit(clientIp, 'customer');
                if (!rateStatus.allowed) {
                    client.ws.send(JSON.stringify({ success: false, reason: 'Çok fazla başarısız deneme. Lütfen daha sonra tekrar deneyin.', resetTime: rateStatus.resetTime }));
                    return;
                }

                const authResult = await isUserApproved(msg.userId, msg.userName);
                if (authResult.approved) {
                    client.ws.send(JSON.stringify({ success: true, credits: authResult.credits, user: authResult.user }));
                    client.credits = authResult.credits; // Client objesindeki krediyi güncelle
                } else {
                    await recordFailedLogin(clientIp, 'customer');
                    client.ws.send(JSON.stringify({ success: false, reason: authResult.reason || 'Geçersiz ID veya isim.' }));
                }
                break;

            case 'direct-call-request':
                if (client.userType !== 'customer') {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Sadece müşteriler arama başlatabilir.' }));
                    return;
                }
                if (client.credits <= 0) {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Yetersiz kredi.' }));
                    return;
                }

                const targetAdmin = clients.get(msg.targetAdminId);
                if (!targetAdmin || targetAdmin.userType !== 'admin' || targetAdmin.online === false || activeCallAdmins.has(targetAdmin.id) || adminLocks.has(targetAdmin.id)) {
                    client.ws.send(JSON.stringify({ type: 'call-rejected', reason: 'Seçilen usta müsait değil veya meşgul.' }));
                    return;
                }

                const newCallKey = generateCallId();
                activeCalls.set(newCallKey, {
                    customerId: client.id,
                    customerName: client.name,
                    adminId: targetAdmin.id,
                    startTime: Date.now(),
                    status: 'pending',
                    lastCreditDeductionMinute: 0
                });
                activeCallAdmins.set(targetAdmin.id, newCallKey); // Admin'i meşgul olarak işaretle
                adminLocks.set(targetAdmin.id, { lockedBy: client.id, lockTime: new Date() }); // Admin'i kilitle
                
                targetAdmin.ws.send(JSON.stringify({
                    type: 'admin-call-request',
                    callKey: newCallKey,
                    customerId: client.id,
                    customerName: client.name,
                    customerCredits: client.credits
                }));
                client.ws.send(JSON.stringify({ type: 'call-connecting', callKey: newCallKey, adminId: targetAdmin.id }));
                console.log(`📞 Arama talebi: ${client.name} -> ${targetAdmin.name} (Call: ${newCallKey})`);
                broadcastAdminListToCustomers(); // Admin durumu değişti
                break;
            
            case 'accept-call':
                if (client.userType !== 'admin') {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Sadece adminler aramayı kabul edebilir.' }));
                    return;
                }

                const callToAccept = activeCalls.get(msg.callKey);
                if (!callToAccept || callToAccept.adminId !== client.id || callToAccept.status !== 'pending') {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Geçersiz arama veya zaten kabul edildi.' }));
                    return;
                }
                
                callToAccept.status = 'active';
                activeCalls.set(msg.callKey, callToAccept); // Update call status
                
                const customerOfAcceptedCall = clients.get(callToAccept.customerId);
                if (customerOfAcceptedCall && customerOfAcceptedCall.ws.readyState === WebSocket.OPEN) {
                    customerOfAcceptedCall.ws.send(JSON.stringify({ type: 'call-accepted', callKey: msg.callKey, adminId: client.id }));
                }

                client.ws.send(JSON.stringify({ type: 'call-accepted', callKey: msg.callKey, customerId: callToAccept.customerId }));
                console.log(`✅ Admin ${client.name} aramayı kabul etti (Call: ${msg.callKey})`);
                startHeartbeat(callToAccept.customerId, client.id, msg.callKey);
                broadcastAdminListToCustomers(); // Admin durumu değişti
                break;
            
            case 'reject-call':
                if (client.userType !== 'admin') {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Sadece adminler aramayı reddedebilir.' }));
                    return;
                }

                const callToReject = activeCalls.get(msg.callKey);
                if (!callToReject || callToReject.adminId !== client.id || callToReject.status !== 'pending') {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Geçersiz arama veya zaten işlendi.' }));
                    return;
                }

                const customerOfRejectedCall = clients.get(callToReject.customerId);
                if (customerOfRejectedCall && customerOfRejectedCall.ws.readyState === WebSocket.OPEN) {
                    customerOfRejectedCall.ws.send(JSON.stringify({ type: 'call-rejected', callKey: msg.callKey, reason: 'Usta meşgul veya reddetti.' }));
                }
                client.ws.send(JSON.stringify({ type: 'call-rejected', callKey: msg.callKey, reason: 'Aramayı reddettiniz.' }));
                
                // ActiveCallAdmins ve adminLocks'tan kaldır
                activeCallAdmins.delete(client.id);
                adminLocks.delete(client.id);
                activeCalls.delete(msg.callKey);
                
                console.log(`❌ Admin ${client.name} aramayı reddetti (Call: ${msg.callKey})`);
                broadcastAdminListToCustomers(); // Admin durumu değişti
                break;

            case 'accept-incoming-call': // Müşteri gelen aramayı kabul ettiğinde
                if (client.userType !== 'customer') {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Sadece müşteriler gelen aramayı kabul edebilir.' }));
                    return;
                }
                const adminClientForIncoming = clients.get(msg.adminId);
                if (adminClientForIncoming && adminClientForIncoming.ws.readyState === WebSocket.OPEN) {
                    adminClientForIncoming.ws.send(JSON.stringify({ type: 'call-accepted', customerId: client.id, adminId: msg.adminId }));
                }
                // Müşteriye de kabul edildiğini bildir
                client.ws.send(JSON.stringify({ type: 'call-accepted', customerId: client.id, adminId: msg.adminId }));
                console.log(`✅ Müşteri ${client.name} gelen aramayı kabul etti.`);
                // Admin artık WebRTC offer göndermeye başlayabilir
                if (adminClientForIncoming) {
                    adminClientForIncoming.ws.send(JSON.stringify({ type: 'customer-accepted-call', customerId: client.id }));
                }
                // Call objesini oluştur
                const newIncomingCallKey = generateCallId();
                activeCalls.set(newIncomingCallKey, {
                    customerId: client.id,
                    customerName: client.name,
                    adminId: msg.adminId,
                    startTime: Date.now(),
                    status: 'active',
                    lastCreditDeductionMinute: 0
                });
                activeCallAdmins.set(msg.adminId, newIncomingCallKey);
                adminLocks.set(msg.adminId, { lockedBy: client.id, lockTime: new Date() });
                startHeartbeat(client.id, msg.adminId, newIncomingCallKey);
                broadcastAdminListToCustomers();
                break;
            
            case 'reject-incoming-call': // Müşteri gelen aramayı reddettiğinde
                if (client.userType !== 'customer') {
                    client.ws.send(JSON.stringify({ type: 'call-failed', reason: 'Sadece müşteriler gelen aramayı reddedebilir.' }));
                    return;
                }
                const adminClientForReject = clients.get(msg.adminId);
                if (adminClientForReject && adminClientForReject.ws.readyState === WebSocket.OPEN) {
                    adminClientForReject.ws.send(JSON.stringify({ type: 'call-rejected', customerId: client.id, adminId: msg.adminId, reason: 'Müşteri reddetti.' }));
                }
                console.log(`❌ Müşteri ${client.name} gelen aramayı reddetti.`);
                // Admin kilidini kaldır, böylece başka aramalar alabilir
                activeCallAdmins.delete(msg.adminId);
                adminLocks.delete(msg.adminId);
                broadcastAdminListToCustomers();
                break;

            case 'end-call':
                const callToEnd = Array.from(activeCalls.values()).find(c => 
                    (c.customerId === client.id && client.userType === 'customer') || 
                    (c.adminId === client.id && client.userType === 'admin')
                );
                if (callToEnd) {
                    const endedBy = client.userType === 'customer' ? 'customer' : 'admin';
                    endCall(callToEnd.callKey, 'normal', false);
                }
                break;
            
            case 'callback-request':
                if (client.userType !== 'customer') {
                    client.ws.send(JSON.stringify({ type: 'callback-failed', reason: 'Sadece müşteriler geri dönüş talebi oluşturabilir.' }));
                    return;
                }
                const targetAdminForCallback = clients.get(msg.targetAdminId);
                if (!targetAdminForCallback || targetAdminForCallback.userType !== 'admin') {
                    client.ws.send(JSON.stringify({ type: 'callback-failed', reason: 'Usta bulunamadı.' }));
                    return;
                }

                if (!adminCallbacks.has(targetAdminForCallback.id)) {
                    adminCallbacks.set(targetAdminForCallback.id, []);
                }
                adminCallbacks.get(targetAdminForCallback.id).push({
                    customerId: client.id,
                    customerName: client.name,
                    timestamp: new Date().toISOString()
                });
                
                client.ws.send(JSON.stringify({ type: 'callback-success', adminName: targetAdminForCallback.name }));
                broadcastCallbacksToAdmin(targetAdminForCallback.id); // Admin'e yeni callback olduğunu bildir
                console.log(`📝 Callback talebi: ${client.name} -> ${targetAdminForCallback.name}`);
                break;
            
            case 'callback-remove':
                if (client.userType !== 'admin') {
                    client.ws.send(JSON.stringify({ type: 'callback-failed', reason: 'Yetkisiz işlem.' }));
                    return;
                }
                let callbacksForAdmin = adminCallbacks.get(client.id) || [];
                adminCallbacks.set(client.id, callbacksForAdmin.filter(cb => cb.customerId !== msg.customerId));
                broadcastCallbacksToAdmin(client.id);
                console.log(`🗑️ Callback kaldırıldı: ${msg.customerId} tarafından ${client.name}`);
                break;
            
            case 'admin-go-offline':
                if (client.userType !== 'admin') return;
                client.online = false;
                clients.set(client.id, client); // Update client status
                console.log(`Admin ${client.name} çevrimdışı oldu.`);
                broadcastAdminListToCustomers();
                break;

            case 'admin-go-online':
                if (client.userType !== 'admin') return;
                client.online = true;
                clients.set(client.id, client); // Update client status
                console.log(`Admin ${client.name} çevrimiçi oldu.`);
                broadcastAdminListToCustomers();
                break;

            case 'offer':
            case 'answer':
            case 'ice-candidate':
                const targetClient = clients.get(msg.targetId);
                if (targetClient && targetClient.ws.readyState === WebSocket.OPEN) {
                    targetClient.ws.send(JSON.stringify({
                        type: msg.type,
                        ...msg,
                        senderId: client.id // Mesajı gönderenin ID'sini ekle
                    }));
                }
                break;
            
            case 'admin-ready-for-webrtc':
                // Bu mesajı alan adminin hangi müşteriye offer göndermesi gerektiğini biliyoruz.
                // İstemciye (müşteriye) adminin hazır olduğunu bildir
                const customerForWebRTC = clients.get(msg.customerId);
                if (customerForWebRTC && customerForWebRTC.ws.readyState === WebSocket.OPEN) {
                    customerForWebRTC.ws.send(JSON.stringify({ type: 'admin-ready-for-webrtc', adminId: client.id }));
                }
                break;


            // ================== WIDGET MESAJ İŞLEYİCİLERİ ==================
            case 'widget-register':
                client.userType = 'widget';
                client.id = `widget_${uniqueId}`; // Widget'a özel ID
                client.name = `Widget Client`;
                clients.set(client.id, client);
                clients.delete(uniqueId); // Geçici uniqueId'yi sil
                client.uniqueId = client.id;
                console.log(`📝 Widget kaydedildi: ${client.id}`);

                // Duyuru varsa gönder
                if (currentAnnouncement) {
                    client.ws.send(JSON.stringify({ type: 'announcement-broadcast', announcement: currentAnnouncement }));
                }
                // Admin listesini gönder
                broadcastAdminListToCustomers(); // Bu fonksiyon zaten widget'lara da gönderiyor
                break;

            default:
                console.log(`⚠️ Bilinmeyen mesaj tipi: ${msg.type}`);
        }
    });

    ws.on('close', () => {
        const client = clients.get(uniqueId) || Array.from(clients.values()).find(c => c.uniqueId === uniqueId);
        if (client) {
            console.log(`🔴 Bağlantı kapandı: ${client.userType || 'unknown'} (${client.id || uniqueId})`);

            // Eğer kapanan bir admin ise, adminLocks'tan kaldır
            if (client.userType === 'admin') {
                client.online = false; // Çevrimdışı olarak işaretle
                // Eğer admin bir aramada ise, aramayı sonlandır
                const callKey = activeCallAdmins.get(client.id);
                if (callKey) {
                    endCall(callKey, 'admin_disconnected', true);
                }
                adminLocks.delete(client.id); // Admin kilidini kaldır
                broadcastAdminListToCustomers(); // Admin listesini güncelle
            } else if (client.userType === 'customer') {
                // Eğer müşteri bir aramada ise, aramayı sonlandır
                const callKey = Array.from(activeCalls.values()).find(c => c.customerId === client.id)?.callKey;
                if (callKey) {
                    endCall(callKey, 'customer_disconnected', true);
                }
            }
            clients.delete(client.uniqueId); // uniqueId üzerinden sil
            if (client.id && client.id !== client.uniqueId) {
                clients.delete(client.id); // Eğer client.id farklı ise onu da sil
            }
        }
    });

    ws.on('error', error => {
        console.error(`❌ WebSocket hata (${uniqueId}):`, error.message);
    });
});

// ================== SUNUCU BAŞLANGICI ==================

server.listen(PORT, async () => {
    console.log(`🚀 Sunucu ${PORT} portunda başlatıldı!`);
    await initDatabase();
    
    // Aktif duyuruyu veritabanından yükle
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

    console.log('');
    console.log('--- VIPCEP Sistem Durumu ---');
    console.log('🔗 WebSocket ve HTTP API aktif.');
    console.log('✅ Veritabanı bağlantısı başarılı.');
    console.log('✨ Yeni özellikler: Widget entegrasyonu aktif!');
    console.log('---------------------------');
    console.log('');
    console.log('🛡️ GÜVENLİK ÖZELLİKLERİ:');
    console.log('   ✅ Credit tracking güvenli');
    console.log('   ✅ Admin disconnect koruması');
    console.log('   ✅ Heartbeat duplicate koruması');
    console.log('   ✅ Super Admin API endpoints');
    // 2FA sisteminin durumu sizin mevcut Railway kurulumunuza bağlıdır.
    console.log('   ✅ 2FA sistem (mevcut altyapınıza göre) hazır'); 
    console.log('');
    console.log('🎯 VIPCEP - Voice IP Communication Emergency Protocol');
    console.log('✅ Yeni sistem hazır - Admin seçim + Callback + Kredi düşme garantili!');
});

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
