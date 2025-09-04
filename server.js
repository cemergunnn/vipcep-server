// DOSYA ADI: server.js (Tüm özellikler tamamlandı)

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
    SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    TOTP_ISSUER: 'VIPCEP System',
    TOTP_WINDOW: 2
};

// Middleware
app.use(session({
    secret: SECURITY_CONFIG.SESSION_SECRET,
    resave: false, // Daha verimli oturum yönetimi için false olarak ayarlandı
    saveUninitialized: false, // Sadece giriş yapıldığında oturum oluştur
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Production'da true olmalı
        httpOnly: true, 
        maxAge: 24 * 60 * 60 * 1000 // Varsayılan oturum süresi: 1 gün
    }
}));

app.use(cors());
app.use(express.json());
// Statik dosyalar için express.static middleware'i en başa taşımak daha iyidir.
// Proje kök dizinindeki dosyaları sunar (örn: cash.mp3, css/style.css vb.)
app.use(express.static(__dirname));


// WebSocket server
const wss = new WebSocket.Server({ server });

// Global variables
const clients = new Map();
const activeHeartbeats = new Map();
const activeCallAdmins = new Map();
const activeCalls = new Map();
const adminCallbacks = new Map();
const adminLocks = new Map();
let currentAnnouncement = null;
const HEARTBEAT_INTERVAL = 60000;

// ================== HELPER FUNCTIONS ==================

function anonymizeCustomerName(fullName) {
    if (!fullName || typeof fullName !== 'string') {
        return 'Anonim';
    }
    const parts = fullName.trim().split(' ');
    if (parts.length === 1) {
        return parts[0];
    }
    const firstName = parts[0];
    const lastInitial = parts[parts.length - 1].charAt(0).toUpperCase();
    return `${firstName} ${lastInitial}.`;
}

function broadcastSystemStateToSuperAdmins() {
    const activeCallDetails = [];
    for (const [adminId, callInfo] of activeCallAdmins.entries()) {
        const adminClient = Array.from(clients.values()).find(c => c.uniqueId === adminId);
        const customerClient = clients.get(callInfo.customerId);
        activeCallDetails.push({
            adminName: adminClient ? adminClient.name : adminId,
            customerName: customerClient ? customerClient.name : callInfo.customerId,
            startTime: callInfo.callStartTime
        });
    }

    const state = {
        activeCalls: activeCallDetails,
        onlineAdmins: Array.from(clients.values()).filter(c => c.userType === 'admin').length,
        onlineCustomers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
    };
    
    const message = JSON.stringify({
        type: 'system-state-update',
        state: state
    });

    clients.forEach(client => {
        if (client.userType === 'super-admin' && client.ws && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(message);
        }
    });
}

async function broadcastEarningsUpdateToAdmin(adminUsername, sourceInfo = null) {
    try {
        const result = await pool.query('SELECT total_earned FROM admin_earnings WHERE username = $1', [adminUsername]);
        const newEarnings = result.rows[0]?.total_earned || 0;

        const adminClient = Array.from(clients.values()).find(c => c.id === adminUsername && c.userType === 'admin');
        if (adminClient && adminClient.ws && adminClient.ws.readyState === WebSocket.OPEN) {
            adminClient.ws.send(JSON.stringify({
                type: 'admin-earning-update',
                newEarnings: newEarnings,
                sourceInfo: sourceInfo 
            }));
        }
    } catch (error) {
        console.error(`Kazanç güncellemesi gönderilemedi (${adminUsername}):`, error);
    }
}


function findActiveCall(userId1, userId2) {
    if (!userId1 || !userId2) return null;
    const key1 = `${userId1}-${userId2}`;
    const key2 = `${userId2}-${userId1}`;
    return activeCalls.get(key1) || activeCalls.get(key2);
}

// ... (Diğer helper fonksiyonlarınızda değişiklik yok) ...

// ================== AUTHENTICATION FUNCTIONS ==================
// ... (Bu bölümdeki fonksiyonlarda değişiklik yok) ...

// ================== DATABASE FUNCTIONS ==================
// ... (Bu bölümdeki fonksiyonlarda değişiklik yok) ...

// ================== HEARTBEAT FUNCTIONS ==================
// ... (Bu bölümdeki fonksiyonlarda değişiklik yok, içindeki broadcastEarningsUpdateToAdmin çağrısı hariç) ...

// ================== MIDDLEWARE FOR AUTH ==================

const requireNormalAdminLogin = (req, res, next) => {
    if (req.session && req.session.normalAdmin) {
        return next();
    } else {
        res.redirect('/');
    }
};

const requireSuperAdminLogin = (req, res, next) => {
    if (req.session && req.session.superAdmin) {
        return next();
    } else {
        res.redirect('/');
    }
};


// ================== ROUTES ==================

// YENİ: Güncellenmiş Ana Giriş Sayfası
app.get('/', (req, res) => {
    if (req.session.superAdmin) {
        return res.redirect(SECURITY_CONFIG.SUPER_ADMIN_PATH);
    }
    if (req.session.normalAdmin) {
        return res.redirect(SECURITY_CONFIG.NORMAL_ADMIN_PATH);
    }

    // Artık `index.html` dosyası olmadığı için HTML'i burada oluşturuyoruz
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>🔐 VIPCEP Güvenli Giriş</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: system-ui; background: linear-gradient(135deg, #1e293b, #334155); color: white; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
                .login-container { background: rgba(255,255,255,0.1); padding: 40px; border-radius: 16px; backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.2); max-width: 400px; width: 100%; }
                .form-group { margin-bottom: 20px; }
                .form-input { width: 100%; padding: 14px; border: 2px solid rgba(255,255,255,0.2); border-radius: 8px; background: rgba(255,255,255,0.1); color: white; font-size: 16px; box-sizing: border-box; }
                .form-input::placeholder { color: rgba(255,255,255,0.6); }
                .form-input:focus { outline: none; border-color: #dc2626; }
                .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #dc2626, #b91c1c); color: white; border: none; border-radius: 8px; font-weight: bold; cursor: pointer; font-size: 16px; margin-bottom: 10px; transition: all 0.3s ease; }
                .btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
                .btn:disabled { opacity: 0.6; cursor: not-allowed; }
                .btn-customer { background: linear-gradient(135deg, #059669, #047857); }
                .title { text-align: center; margin-bottom: 30px; color: #dc2626; font-size: 24px; font-weight: bold; }
                .twofa-section { display: none; }
                .twofa-section.active { display: block; }
                .twofa-code { text-align: center; font-size: 18px; letter-spacing: 3px; font-family: monospace; }
                .back-btn { background: linear-gradient(135deg, #64748b, #475569); }
                .error-msg { background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; font-size: 14px; }
                .success-msg { background: rgba(34, 197, 94, 0.2); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; font-size: 14px; }
                .loading { opacity: 0.7; pointer-events: none; }
                .twofa-info { background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.3); color: #93c5fd; padding: 12px; border-radius: 6px; margin: 10px 0; font-size: 13px; text-align: center; }
                .remember-me { display: flex; align-items: center; gap: 8px; font-size: 14px; color: rgba(255,255,255,0.8); margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="title">🔐 VIPCEP</div>

                <div id="step1">
                    <div class="form-group">
                        <input type="text" id="username" class="form-input" placeholder="👤 Kullanıcı Adı">
                    </div>
                    <div class="form-group">
                        <input type="password" id="password" class="form-input" placeholder="🔑 Şifre">
                    </div>
                    <div class="remember-me">
                        <input type="checkbox" id="rememberMeAdmin">
                        <label for="rememberMeAdmin">Beni Hatırla (30 Gün)</label>
                    </div>
                    <button class="btn" id="superAdminBtn" onclick="startSuperLogin()">🔴 SUPER ADMİN GİRİŞİ</button>
                    <button class="btn" onclick="normalAdminLogin()">🟡 ADMİN GİRİŞİ</button>
                    <button class="btn btn-customer" onclick="window.location.href='${SECURITY_CONFIG.CUSTOMER_PATH}'">🟢 MÜŞTERİ UYGULAMASI</button>
                </div>

                <div id="step2" class="twofa-section">
                     </div>

                <div id="messageArea"></div>
            </div>

            <script>
                let currentStep = 1;
                let currentUsername = '';
                let currentPassword = '';

                // ... (showMessage, setLoading, goToStep2, goBackToStep1 fonksiyonları değişmedi)

                async function startSuperLogin() { /* ... Bu fonksiyon değişmedi */ }
                async function verify2FA() { /* ... Bu fonksiyon değişmedi */ }

                async function normalAdminLogin() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    const rememberMe = document.getElementById('rememberMeAdmin').checked; // YENİ
                    if (!username || !password) return showMessage('Kullanıcı adı ve şifre gerekli!');

                    setLoading(true);

                    try {
                        const response = await fetch('/auth/admin-login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password, rememberMe }) // YENİ: Beni hatırla bilgisi gönderiliyor
                        });
                        const result = await response.json();
                        if (result.success) {
                            showMessage('Giriş başarılı!', 'success');
                            setTimeout(() => {
                                window.location.href = result.redirectUrl;
                            }, 1000);
                        } else {
                            showMessage(result.error || 'Giriş başarısız!');
                        }
                    } catch (error) {
                        showMessage('Bağlantı hatası!');
                    }

                    setLoading(false);
                }
                
                // ... (Diğer script kodları değişmedi)
            </script>
        </body>
        </html>
    `);
});

// YENİ: Güncellenmiş Admin Giriş Rotası
app.post('/auth/admin-login', async (req, res) => {
    const { username, password, rememberMe } = req.body; // rememberMe eklendi
    const clientIP = req.ip || req.connection.remoteAddress;

    try {
        const rateStatus = await checkRateLimit(clientIP, 'admin');
        if (!rateStatus.allowed) {
            return res.status(429).json({ success: false, error: 'Çok fazla başarısız deneme!' });
        }

        const admin = await authenticateAdmin(username, password);
        if (admin && admin.role === 'normal') {
            // Oturum bilgilerini ata
            req.session.normalAdmin = { id: admin.id, username: admin.username, loginTime: new Date() };
            
            // "Beni Hatırla" seçiliyse, oturumun ömrünü uzat
            if (rememberMe) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 Gün
            }
            
            res.json({ success: true, redirectUrl: SECURITY_CONFIG.NORMAL_ADMIN_PATH });
        } else {
            await recordFailedLogin(clientIP, 'admin');
            res.status(401).json({ success: false, error: 'Geçersiz kullanıcı adı veya şifre!' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'Sistem hatası!' });
    }
});


// ... (Diğer tüm rotalarınız ve WebSocket mantığınız önceden güncellendiği gibi kalır) ...


// ================== SERVER STARTUP ==================
// ... (Sunucu başlatma kodunuzda değişiklik yok) ...

startServer().catch(error => {
    console.log('❌ Server başlatma hatası:', error.message);
    process.exit(1);
});
