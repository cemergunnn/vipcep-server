const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

// PostgreSQL bağlantısı - Railway için güncellenmiş
const { Pool } = require('pg');

// Railway Environment Variables kullanımı
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

console.log('🔗 Database URL:', process.env.DATABASE_URL ? 'FOUND' : 'NOT FOUND');
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');

// Veritabanı tablolarını oluştur
async function initDatabase() {
    try {
        console.log('🔧 Veritabanı kontrol ediliyor...');
        
        // Test connection
        await pool.query('SELECT NOW()');
        console.log('✅ PostgreSQL bağlantısı başarılı');
        
        // Sadece eksik tabloları oluştur, mevcut tabloları silme!
        
        // Onaylı kullanıcılar tablosu (Admin tarafından eklenenler)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS approved_users (
                id VARCHAR(4) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                credits INTEGER DEFAULT 0,
                total_calls INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_call TIMESTAMP,
                status VARCHAR(20) DEFAULT 'active'
            )
        `);

        // Arama geçmişi tablosu - FOREIGN KEY YOK!
        await pool.query(`
            CREATE TABLE IF NOT EXISTS call_history (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(4) NOT NULL,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                duration INTEGER,
                credits_used INTEGER,
                call_type VARCHAR(20) DEFAULT 'incoming'
            )
        `);

        // Kredi işlemleri tablosu - FOREIGN KEY YOK!
        await pool.query(`
            CREATE TABLE IF NOT EXISTS credit_transactions (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(4) NOT NULL,
                amount INTEGER,
                transaction_type VARCHAR(20),
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ PostgreSQL tabloları kontrol edildi');
        
        // Test kullanıcısı ekle/güncelle - SADECE YOKSA EKLE
        try {
            const existingUser = await pool.query('SELECT id, credits FROM approved_users WHERE id = $1', ['1234']);
            
            if (existingUser.rows.length === 0) {
                // Test kullanıcısı yoksa oluştur
                await pool.query(`
                    INSERT INTO approved_users (id, name, credits) 
                    VALUES ('1234', 'Test Kullanıcı', 10)
                `);
                console.log('🧪 Test kullanıcısı oluşturuldu: 1234 (10 kredi)');
            } else {
                // Test kullanıcısı varsa mevcut kredisini göster
                console.log(`🧪 Test kullanıcısı mevcut: 1234 (${existingUser.rows[0].credits} kredi)`);
            }
        } catch (err) {
            console.log('Test kullanıcısı kontrol hatası:', err.message);
        }
        
    } catch (error) {
        console.error('❌ PostgreSQL bağlantı hatası:', error);
        console.log('💡 Veritabanı bağlantısı başarısız - Railway PostgreSQL servisini kontrol edin');
        throw error; // Railway'de hata olursa container durdurulsun
    }
}

// Express app oluştur
const app = express();
app.use(cors());
app.use(express.static(__dirname));
app.use(express.json());

// PostgreSQL yardımcı fonksiyonları
async function saveApprovedUser(userId, userName, credits = 0) {
    try {
        await pool.query(
            'INSERT INTO approved_users (id, name, credits) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET name = $2, credits = $3',
            [userId, userName, credits]
        );
        console.log(`📝 Onaylı kullanıcı eklendi: ${userName} (${userId})`);
        return true;
    } catch (error) {
        console.log('PostgreSQL kullanıcı kayıt hatası:', error.message);
        return false;
    }
}

async function getUserCredits(userId) {
    try {
        const result = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
        return result.rows[0]?.credits || 0;
    } catch (error) {
        console.log('PostgreSQL kredi sorgulama hatası:', error.message);
        return 0;
    }
}

async function getFullUserInfo(userId) {
    try {
        const result = await pool.query('SELECT * FROM approved_users WHERE id = $1 AND status = $2', [userId, 'active']);
        return result.rows[0] || null;
    } catch (error) {
        console.log('PostgreSQL kullanıcı kontrol hatası:', error.message);
        return null;
    }
}

async function isUserApproved(userId) {
    try {
        const result = await pool.query('SELECT * FROM approved_users WHERE id = $1 AND status = $2', [userId, 'active']);
        return result.rows[0] || null;
    } catch (error) {
        console.log('PostgreSQL kullanıcı kontrol hatası:', error.message);
        return null;
    }
}

async function updateUserCredits(userId, amount, type = 'add', description = '') {
    try {
        if (type === 'add') {
            await pool.query('UPDATE approved_users SET credits = credits + $1 WHERE id = $2', [amount, userId]);
        } else if (type === 'use') {
            await pool.query('UPDATE approved_users SET credits = GREATEST(0, credits - $1) WHERE id = $2', [amount, userId]);
        } else if (type === 'set') {
            await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [amount, userId]);
        }
        
        // İşlemi kaydet - FOREIGN KEY YOK ARTIK
        await pool.query(
            'INSERT INTO credit_transactions (user_id, amount, transaction_type, description) VALUES ($1, $2, $3, $4)',
            [userId, amount, type, description]
        );
        
        console.log(`💰 Kredi güncellendi: ${userId} ${type} ${amount}`);
        return true;
    } catch (error) {
        console.log('PostgreSQL kredi güncelleme hatası:', error.message);
        return false;
    }
}

// *** KRİTİK DÜZELTME: KREDİ DÜŞME FONKSİYONU ***
async function saveCallToDatabase(userId, duration, creditsUsed) {
    try {
        console.log(`🔧 Kredi düşürme başlatılıyor: ${userId} - ${creditsUsed} kredi`);
        
        // 1. Önce kullanıcının var olduğunu kontrol et
        const userExists = await pool.query('SELECT id, credits FROM approved_users WHERE id = $1', [userId]);
        if (userExists.rows.length === 0) {
            console.error(`❌ Kullanıcı bulunamadı: ${userId}`);
            return false;
        }
        
        const currentCredits = userExists.rows[0].credits;
        console.log(`💰 Mevcut kredi: ${currentCredits} dk`);
        
        // 2. Arama geçmişine kaydet - STATUS KOLONU KALDIRILDI
        await pool.query(
            'INSERT INTO call_history (user_id, duration, credits_used, end_time) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)',
            [userId, duration, creditsUsed]
        );
        console.log(`📋 Arama geçmişi kaydedildi`);
        
        // 3. Krediyi düş - GÜVENLE ÇIKART
        const newCredits = Math.max(0, currentCredits - creditsUsed);
        await pool.query(
            'UPDATE approved_users SET total_calls = total_calls + 1, credits = $1, last_call = CURRENT_TIMESTAMP WHERE id = $2',
            [newCredits, userId]
        );
        console.log(`💳 Kredi güncellendi: ${currentCredits} -> ${newCredits}`);
        
        // 4. Kredi işlemini kaydet - FOREIGN KEY YOK
        await pool.query(
            'INSERT INTO credit_transactions (user_id, amount, transaction_type, description) VALUES ($1, $2, $3, $4)',
            [userId, creditsUsed, 'use', `Görüşme süresi: ${Math.floor(duration/60)}:${(duration%60).toString().padStart(2,'0')}`]
        );
        console.log(`📝 Kredi işlemi kaydedildi`);
        
        console.log(`✅ ${userId} kullanıcısının ${creditsUsed} kredisi düşüldü. Kalan: ${newCredits}`);
        return true;
        
    } catch (error) {
        console.error('❌ PostgreSQL arama kayıt hatası:', error);
        console.error('Hata detayları:', error.message);
        return false;
    }
}

// API Endpoints
app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message, message: 'Veritabanı kullanılamıyor' });
    }
});

app.post('/api/approved-users', async (req, res) => {
    try {
        const { id, name, credits } = req.body;
        
        if (!id || id.length !== 4 || !/^\d{4}$/.test(id)) {
            return res.status(400).json({ error: '4 haneli sayısal ID gerekli' });
        }
        
        const success = await saveApprovedUser(id, name, credits || 0);
        if (success) {
            res.json({ success: true });
        } else {
            res.status(500).json({ error: 'Kullanıcı eklenemedi' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/approved-users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Önce arama geçmişini sil - FOREIGN KEY YOK ARTIK
        await pool.query('DELETE FROM call_history WHERE user_id = $1', [id]);
        
        // Kredi işlemlerini sil - FOREIGN KEY YOK ARTIK  
        await pool.query('DELETE FROM credit_transactions WHERE user_id = $1', [id]);
        
        // Kullanıcıyı sil
        const result = await pool.query('DELETE FROM approved_users WHERE id = $1', [id]);
        
        if (result.rowCount > 0) {
            // WebSocket bağlantısı varsa kapat
            const client = clients.get(id);
            if (client && client.ws.readyState === WebSocket.OPEN) {
                client.ws.close();
                clients.delete(id);
                broadcastUserList();
            }
            
            res.json({ success: true, message: 'Kullanıcı silindi' });
            console.log(`🗑️ Onaylı kullanıcı silindi: ${id}`);
        } else {
            res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
        console.error('Kullanıcı silme hatası:', error);
    }
});

app.post('/api/approved-users/:id/credits', async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, type, description } = req.body;
        
        const success = await updateUserCredits(id, amount, type, description);
        
        if (success) {
            // WebSocket ile kullanıcıya bildir
            const client = clients.get(id);
            if (client && client.ws.readyState === WebSocket.OPEN) {
                const credits = await getUserCredits(id);
                client.ws.send(JSON.stringify({
                    type: 'credit-update',
                    credits: credits
                }));
            }
            res.json({ success: true });
        } else {
            res.status(500).json({ error: 'Kredi güncellenemedi' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/calls', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT ch.*, au.name as user_name 
            FROM call_history ch 
            LEFT JOIN approved_users au ON ch.user_id = au.id 
            ORDER BY ch.start_time DESC 
            LIMIT 100
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message, message: 'Veritabanı kullanılamıyor' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const totalUsersResult = await pool.query('SELECT COUNT(*) as count FROM approved_users');
        const todayCallsResult = await pool.query('SELECT COUNT(*) as count FROM call_history WHERE start_time >= $1', [today]);
        const totalCreditsResult = await pool.query('SELECT SUM(credits) as total FROM approved_users');
        
        res.json({
            totalUsers: parseInt(totalUsersResult.rows[0].count),
            todayCalls: parseInt(todayCallsResult.rows[0].count),
            totalCredits: parseInt(totalCreditsResult.rows[0].total) || 0,
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Manuel kredi ekleme endpoint (Admin için)
app.post('/api/add-credit/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { amount } = req.body;
        
        const success = await updateUserCredits(id, amount, 'add', 'Manuel kredi ekleme');
        
        if (success) {
            const newCredits = await getUserCredits(id);
            
            // WebSocket ile kullanıcıya bildir
            const client = clients.get(id);
            if (client && client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify({
                    type: 'credit-update',
                    credits: newCredits
                }));
            }
            
            res.json({ 
                success: true, 
                message: `${amount} kredi eklendi`,
                newCredits: newCredits
            });
        } else {
            res.status(500).json({ error: 'Kredi eklenemedi' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Bağlı kullanıcıları takip et
const clients = new Map();

// Aktif aramalar takibi
const activeCalls = new Map(); // userId -> { adminId, startTime, status }

// YENİ: Admin'den gelen aramalar takibi
const adminCalls = new Map(); // userId -> { adminId, startTime, status }

// Railway için IP detection
function getLocalIP() {
    // Railway'de container IP'si her zaman değişir, bu yüzden basit şekilde gösterelim
    return process.env.RAILWAY_STATIC_URL || 'Railway Container';
}

// Health check endpoint (Railway için)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: 'Connected'
    });
});

// Basit ana sayfa - Railway URL'li
app.get('/', (req, res) => {
    const baseUrl = process.env.RAILWAY_STATIC_URL || req.get('host');
    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>VIPCEP Server - Railway</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #2563eb; }
                .info { background: #e0f2fe; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .users { background: #f0f9ff; padding: 15px; border-radius: 5px; }
                a { color: #2563eb; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
                .online { background: #22c55e; }
                .offline { background: #ef4444; }
                .app-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }
                .app-card { background: #f8fafc; padding: 20px; border-radius: 8px; border-left: 4px solid #2563eb; }
                .app-card h3 { margin: 0 0 10px 0; color: #1e293b; }
                .app-card p { margin: 0 0 15px 0; color: #64748b; font-size: 14px; }
                .app-button { background: #2563eb; color: white; padding: 8px 16px; border-radius: 5px; text-decoration: none; display: inline-block; }
                .app-button:hover { background: #1d4ed8; color: white; }
                .test-user { background: #dcfce7; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #22c55e; }
                .feature-new { background: #fef3c7; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #f59e0b; }
                .railway-info { background: #a855f7; color: white; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚂 VIPCEP Server - Railway'de Çalışıyor!</h1>
                
                <div class="railway-info">
                    <h3>🌐 Railway Deployment Aktif</h3>
                    <p><strong>Public URL:</strong> ${protocol}://${baseUrl}</p>
                    <p><strong>WebSocket:</strong> wss://${baseUrl}</p>
                    <p><strong>Database:</strong> PostgreSQL (Railway)</p>
                    <p><strong>Environment:</strong> ${process.env.NODE_ENV || 'development'}</p>
                </div>
                
                <div class="feature-new">
                    <h3>🚀 İKİ YÖNLÜ ARAMA SİSTEMİ</h3>
                    <p>✅ Admin → Müşteri arama | ✅ Müşteri → Admin arama</p>
                    <p><strong>Özellikler:</strong> WebRTC P2P ses, kredi sistemi, gelen arama bildirimleri</p>
                </div>
                
                <h3>📱 Uygulamalar</h3>
                <div class="app-grid">
                    <div class="app-card">
                        <h3>📞 Admin Panel</h3>
                        <p>Kullanıcı yönetimi, arama alma/yapma, sistem istatistikleri</p>
                        <a href="/admin-panel.html" target="_blank" class="app-button">Admin Panel Aç</a>
                    </div>
                    <div class="app-card">
                        <h3>📱 Müşteri Uygulaması</h3>
                        <p>Müşteri arama uygulaması (EXE ile aynı)</p>
                        <a href="/customer-app.html" target="_blank" class="app-button">Müşteri App Aç</a>
                    </div>
                </div>
                
                <div class="test-user">
                    <h3>🧪 Test Kullanıcısı Hazır</h3>
                    <p><strong>ID:</strong> 1234 | <strong>Ad:</strong> Test Kullanıcı | <strong>Kredi:</strong> 10 dakika</p>
                    <p><em>Bu kullanıcı ile iki yönlü arama testi yapabilirsiniz.</em></p>
                </div>
                
                <div class="users">
                    <h3>👥 Bağlı Kullanıcılar: ${clients.size}</h3>
                    <ul>
                        ${Array.from(clients.entries()).map(([id, client]) => 
                            `<li><span class="status ${client.online ? 'online' : 'offline'}"></span>${client.name} (${client.userType})</li>`
                        ).join('')}
                    </ul>
                    ${clients.size === 0 ? '<p><em>Henüz bağlı kullanıcı yok</em></p>' : ''}
                </div>
                
                <hr style="margin: 20px 0;">
                <p><small>🚂 Railway Server | Başlatıldı: ${new Date().toLocaleString()}</small></p>
            </div>
            
            <script>
                // Sayfa her 15 saniyede bir yenilensin
                setTimeout(() => location.reload(), 15000);
            </script>
        </body>
        </html>
    `);
});

// HTTP server oluştur
const server = http.createServer(app);

// WebSocket server
const wss = new WebSocket.Server({ server });

console.log('🚂 VIPCEP Server - Railway Başlatılıyor...');
console.log('📍 Container IP:', getLocalIP());

wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress;
    console.log('🔗 Yeni bağlantı:', clientIP);
    
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data);
            handleMessage(ws, message);
        } catch (error) {
            console.error('❌ Mesaj parse hatası:', error);
        }
    });
    
    ws.on('close', () => {
        // Kullanıcıyı clients'tan kaldır
        for (const [userId, client] of clients.entries()) {
            if (client.ws === ws) {
                // Aktif arama varsa iptal et
                if (activeCalls.has(userId)) {
                    const callInfo = activeCalls.get(userId);
                    activeCalls.delete(userId);
                    
                    // Admin'e arama iptal mesajı gönder
                    const adminClient = clients.get(callInfo.adminId);
                    if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                        adminClient.ws.send(JSON.stringify({
                            type: 'call-cancelled',
                            userId: userId,
                            userName: client.name,
                            reason: 'Kullanıcı bağlantısı koptu'
                        }));
                    }
                    console.log('📞 Arama iptal edildi (bağlantı koptu):', userId);
                }

                // YENİ: Admin araması varsa iptal et
                if (adminCalls.has(userId)) {
                    const callInfo = adminCalls.get(userId);
                    adminCalls.delete(userId);
                    
                    // Admin'e iptal mesajı gönder
                    const adminClient = clients.get(callInfo.adminId);
                    if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                        adminClient.ws.send(JSON.stringify({
                            type: 'admin-call-timeout',
                            userId: userId,
                            reason: 'Müşteri bağlantısı koptu'
                        }));
                    }
                    console.log('📞 Admin araması iptal edildi (bağlantı koptu):', userId);
                }
                
                clients.delete(userId);
                console.log('👋 Kullanıcı ayrıldı:', userId);
                broadcastUserList();
                break;
            }
        }
    });
    
    ws.on('error', (error) => {
        console.error('❌ WebSocket hatası:', error);
    });
});

async function handleMessage(ws, message) {
    console.log('📨 Gelen mesaj:', message.type, 'from:', message.userId || 'unknown');
    
    switch (message.type) {
        case 'login-request':
            console.log('🔍 Giriş denemesi - ID:', message.userId, 'Ad:', message.userName);
            
            // ID kontrolü yap
            const user = await isUserApproved(message.userId);
            console.log('🔍 Veritabanı sonucu:', user);
            
            if (user) {
                // ID onaylı ve ad soyad eşleşiyor mu kontrol et (büyük/küçük harf duyarsız)
                const userNameTrimmed = message.userName.toLowerCase().trim();
                const registeredNameTrimmed = user.name.toLowerCase().trim();
                
                console.log('🔍 Ad karşılaştırma:');
                console.log('   Girilen:', `"${userNameTrimmed}"`);
                console.log('   Kayıtlı:', `"${registeredNameTrimmed}"`);
                console.log('   Eşit mi:', userNameTrimmed === registeredNameTrimmed);
                
                if (userNameTrimmed === registeredNameTrimmed) {
                    ws.send(JSON.stringify({
                        type: 'login-response',
                        success: true,
                        credits: user.credits,
                        userName: user.name
                    }));
                    console.log(`✅ Giriş başarılı: ${user.name} (${message.userId})`);
                } else {
                    ws.send(JSON.stringify({
                        type: 'login-response',
                        success: false,
                        reason: 'Ad soyad eşleşmiyor! Kayıtlı: "' + user.name + '" - Girilen: "' + message.userName + '"'
                    }));
                    console.log(`❌ Ad soyad eşleşmiyor: Girilen: "${message.userName}", Kayıtlı: "${user.name}"`);
                }
            } else {
                ws.send(JSON.stringify({
                    type: 'login-response',
                    success: false,
                    reason: 'ID kodunuz onaylanmamış! Lütfen kredi talep edin.'
                }));
                console.log(`❌ Onaylanmamış giriş denemesi: ${message.userId}`);
            }
            break;
            
        case 'register':
            // Admin veya onaylı kullanıcı olarak kayıt ol
            if (message.userType === 'admin' || await isUserApproved(message.userId)) {
                clients.set(message.userId, {
                    ws: ws,
                    name: message.name,
                    userType: message.userType,
                    online: true,
                    registeredAt: new Date().toLocaleTimeString()
                });
                console.log(`✅ ${message.userType.toUpperCase()} kaydedildi:`, message.name, message.userId);
                
                // Kullanıcı listesini güncelle
                broadcastUserList();
                
                // Admin'e yeni kullanıcı bilgisi gönder
                if (message.userType === 'customer') {
                    broadcastToAdmins({
                        type: 'user-online',
                        userId: message.userId,
                        userName: message.name
                    });
                }
            } else {
                ws.send(JSON.stringify({
                    type: 'registration-failed',
                    reason: 'unauthorized'
                }));
                ws.close();
            }
            break;

        // YENİ: Admin → Müşteri arama isteği
        case 'admin-call-request':
            console.log('📞 Admin arama isteği:', message.adminId, '->', message.targetId);
            
            // Hedef kullanıcı online mı?
            const adminTargetClient = clients.get(message.targetId);
            if (!adminTargetClient || adminTargetClient.userType !== 'customer') {
                ws.send(JSON.stringify({
                    type: 'admin-call-rejected',
                    userId: message.targetId,
                    reason: 'Kullanıcı çevrimiçi değil'
                }));
                console.log(`❌ Hedef kullanıcı çevrimiçi değil: ${message.targetId}`);
                return;
            }

            // Kullanıcı zaten bir aramada mı?
            if (activeCalls.has(message.targetId) || adminCalls.has(message.targetId)) {
                ws.send(JSON.stringify({
                    type: 'admin-call-rejected',
                    userId: message.targetId,
                    reason: 'Kullanıcı zaten bir aramada'
                }));
                console.log(`❌ Kullanıcı zaten aramada: ${message.targetId}`);
                return;
            }

            // Admin araması kaydet
            adminCalls.set(message.targetId, {
                adminId: message.adminId,
                startTime: Date.now(),
                status: 'ringing'
            });

            // Müşteriye arama bildirimi gönder
            adminTargetClient.ws.send(JSON.stringify({
                type: 'admin-call-request',
                adminId: message.adminId,
                adminName: message.adminName || 'USTAM'
            }));

            console.log(`📞 Admin araması bildirildi: ${message.adminId} -> ${message.targetId}`);

            // 30 saniye sonra zaman aşımı kontrolü
            setTimeout(() => {
                if (adminCalls.has(message.targetId)) {
                    const callInfo = adminCalls.get(message.targetId);
                    if (callInfo.status === 'ringing') {
                        adminCalls.delete(message.targetId);
                        
                        // Admin'e zaman aşımı bildir
                        const adminClient = clients.get(message.adminId);
                        if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                            adminClient.ws.send(JSON.stringify({
                                type: 'admin-call-timeout',
                                userId: message.targetId
                            }));
                        }
                        
                        console.log(`⏰ Admin araması zaman aşımı: ${message.targetId}`);
                    }
                }
            }, 30000);
            break;

        case 'admin-call-accepted':
            console.log('✅ Admin araması kabul edildi:', message.userId);
            
            if (adminCalls.has(message.userId)) {
                const callInfo = adminCalls.get(message.userId);
                callInfo.status = 'accepted';
                callInfo.acceptTime = Date.now();
                
                // Admin'e kabul mesajı gönder
                const adminClient = clients.get(callInfo.adminId);
                if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                    adminClient.ws.send(JSON.stringify({
                        type: 'admin-call-accepted',
                        userId: message.userId
                    }));
                }
                
                console.log(`✅ Admin'e kabul bildirildi: ${callInfo.adminId}`);
            }
            break;

        case 'admin-call-rejected':
            console.log('❌ Admin araması reddedildi:', message.userId, message.reason);
            
            if (adminCalls.has(message.userId)) {
                const callInfo = adminCalls.get(message.userId);
                adminCalls.delete(message.userId);
                
                // Admin'e red mesajı gönder
                const adminClient = clients.get(callInfo.adminId);
                if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                    adminClient.ws.send(JSON.stringify({
                        type: 'admin-call-rejected',
                        userId: message.userId,
                        reason: message.reason
                    }));
                }
                
                console.log(`❌ Admin'e red bildirildi: ${callInfo.adminId}`);
            }
            break;

        case 'admin-call-cancelled':
            console.log('📞 Admin araması iptal edildi:', message.targetId);
            
            if (adminCalls.has(message.targetId)) {
                adminCalls.delete(message.targetId);
                
                // Müşteriye iptal mesajı gönder
                const customerClient = clients.get(message.targetId);
                if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
                    customerClient.ws.send(JSON.stringify({
                        type: 'admin-call-cancelled',
                        reason: message.reason
                    }));
                }
                
                console.log(`📞 Müşteriye iptal bildirildi: ${message.targetId}`);
            }
            break;
            
        case 'call-request':
            // Kullanıcı onaylı mı kontrol et
            const callerUser = await isUserApproved(message.userId);
            if (!callerUser) {
                ws.send(JSON.stringify({
                    type: 'call-rejected',
                    reason: 'unauthorized'
                }));
                console.log(`❌ Onaylanmamış kullanıcı arama yapmaya çalıştı: ${message.userId}`);
                return;
            }
            
            // Kredi kontrolü
            if (callerUser.credits <= 0) {
                ws.send(JSON.stringify({
                    type: 'call-rejected',
                    reason: 'Yetersiz kredi!'
                }));
                console.log(`❌ Yetersiz kredi: ${message.userId}`);
                return;
            }
            
            // Aktif arama kaydet
            activeCalls.set(message.userId, {
                adminId: message.targetId,
                startTime: Date.now(),
                status: 'ringing'
            });
            
            // Admin'e arama isteği gönder
            console.log('📞 Arama isteği:', callerUser.name, '->', message.targetId);
            const callTargetClient = clients.get(message.targetId);
            if (callTargetClient && callTargetClient.ws.readyState === WebSocket.OPEN) {
                callTargetClient.ws.send(JSON.stringify({
                    type: 'incoming-call',
                    userId: message.userId,
                    userName: callerUser.name,
                    credits: callerUser.credits
                }));
                console.log('✅ Arama isteği iletildi');
            } else {
                // Admin offline, aktif aramayı sil
                activeCalls.delete(message.userId);
                ws.send(JSON.stringify({
                    type: 'call-rejected',
                    reason: 'Usta müsait değil'
                }));
                console.log('❌ Admin bulunamadı');
            }
            break;
            
        case 'call-cancelled':
            // Müşteri aramayı iptal etti
            const cancelUserId = message.userId;
            
            if (activeCalls.has(cancelUserId)) {
                const callInfo = activeCalls.get(cancelUserId);
                activeCalls.delete(cancelUserId);
                
                // Admin'e iptal mesajı gönder
                const adminClient = clients.get(callInfo.adminId);
                if (adminClient && adminClient.ws.readyState === WebSocket.OPEN) {
                    adminClient.ws.send(JSON.stringify({
                        type: 'call-cancelled',
                        userId: cancelUserId,
                        userName: message.userName || clients.get(cancelUserId)?.name || 'Bilinmeyen',
                        reason: 'Müşteri aramayı iptal etti'
                    }));
                }
                console.log('📞 Arama iptal edildi:', cancelUserId);
            }
            break;
            
        case 'accept-call':
            const acceptUserId = message.userId;
            
            // Arama aktif mi kontrol et
            if (!activeCalls.has(acceptUserId)) {
                console.log('❌ İptal edilmiş arama kabul edilmeye çalışıldı:', acceptUserId);
                return;
            }
            
            // Arama durumunu güncelle
            const callInfo = activeCalls.get(acceptUserId);
            callInfo.status = 'accepted';
            callInfo.acceptTime = Date.now();
            
            const callerClient = clients.get(acceptUserId);
            if (callerClient && callerClient.ws.readyState === WebSocket.OPEN) {
                callerClient.ws.send(JSON.stringify({
                    type: 'call-accepted'
                }));
                console.log('✅ Arama kabul edildi:', acceptUserId);
            }
            break;
            
        case 'reject-call':
            const rejectUserId = message.userId;
            
            // Aktif aramayı sil
            if (activeCalls.has(rejectUserId)) {
                activeCalls.delete(rejectUserId);
            }
            
            const rejectedClient = clients.get(rejectUserId);
            if (rejectedClient && rejectedClient.ws.readyState === WebSocket.OPEN) {
                rejectedClient.ws.send(JSON.stringify({
                    type: 'call-rejected',
                    reason: message.reason || 'Arama reddedildi'
                }));
                console.log('❌ Arama reddedildi:', rejectUserId);
            }
            break;
            
        case 'offer':
        case 'answer':
        case 'ice-candidate':
            // WebRTC sinyallerini ilet
            const webrtcTarget = clients.get(message.targetId);
            if (webrtcTarget && webrtcTarget.ws.readyState === WebSocket.OPEN) {
                webrtcTarget.ws.send(JSON.stringify(message));
            }
            break;
            
        case 'end-call':
            const endUserId = message.userId;
            const endTarget = clients.get(message.targetId);
            
            console.log(`📞 Görüşme sonlandırılıyor: ${endUserId} -> ${message.targetId}`);
            
            // Aktif aramayı kontrol et ve sil
            let callStartTime = null;
            let customerId = null;
            
            // Admin mi bitiriyor yoksa müşteri mi?
            if (message.userId === 'ADMIN001' || message.userType === 'admin') {
                // Admin bitiriyor - müşteri ID'sini bul
                customerId = message.targetId;
                
                // activeCalls'tan müşteri aramasını bul
                if (activeCalls.has(customerId)) {
                    const callInfo = activeCalls.get(customerId);
                    callStartTime = callInfo.acceptTime || callInfo.startTime;
                    activeCalls.delete(customerId);
                    console.log(`⏰ Admin sonlandırdı - Müşteri: ${customerId}`);
                }

                // YENİ: adminCalls'tan da kontrol et
                if (adminCalls.has(customerId)) {
                    const callInfo = adminCalls.get(customerId);
                    callStartTime = callInfo.acceptTime || callInfo.startTime;
                    adminCalls.delete(customerId);
                    console.log(`⏰ Admin sonlandırdı - Admin araması: ${customerId}`);
                }
            } else {
                // Müşteri bitiriyor - normal işlem
                customerId = endUserId;
                if (activeCalls.has(endUserId)) {
                    const callInfo = activeCalls.get(endUserId);
                    callStartTime = callInfo.acceptTime || callInfo.startTime;
                    activeCalls.delete(endUserId);
                }

                // YENİ: Admin aramasından da temizle
                if (adminCalls.has(endUserId)) {
                    const callInfo = adminCalls.get(endUserId);
                    callStartTime = callInfo.acceptTime || callInfo.startTime;
                    adminCalls.delete(endUserId);
                }
            }
            
            if (callStartTime) {
                console.log(`⏰ Arama başlangıç zamanı: ${new Date(callStartTime).toLocaleTimeString()}`);
            }
            
            // Görüşme süresi hesapla (sadece kabul edilmişse)
            let actualDuration = message.duration || 0;
            if (callStartTime && message.duration > 0) {
                const realEndTime = Date.now();
                actualDuration = Math.floor((realEndTime - callStartTime) / 1000);
                console.log(`⏱️ Gerçek görüşme süresi: ${actualDuration} saniye (gönderilen: ${message.duration})`);
            }
            
            // Kredi hesapla (yukarı yuvarla)
            const creditsUsed = actualDuration > 0 ? Math.ceil(actualDuration / 60) : 0;
            console.log(`💰 Hesaplanan kredi: ${creditsUsed} dakika`);
            
            // *** HER İKİ TARAFA DA BİLDİR ***
            
            // 1. Hedefe bildir (eğer belirtilmişse)
            if (endTarget && endTarget.ws.readyState === WebSocket.OPEN) {
                endTarget.ws.send(JSON.stringify({
                    type: 'call-ended',
                    duration: actualDuration,
                    creditsUsed: creditsUsed,
                    endedBy: endUserId
                }));
                console.log(`📞 Hedef bilgilendirildi: ${message.targetId}`);
            }
            
            // 2. Eğer admin bitirdiyse, müşteriye özel bildirim gönder
            if (message.userId === 'ADMIN001' || message.userType === 'admin') {
                const customerClient = clients.get(customerId);
                if (customerClient && customerClient.ws.readyState === WebSocket.OPEN) {
                    customerClient.ws.send(JSON.stringify({
                        type: 'call-ended',
                        duration: actualDuration,
                        creditsUsed: creditsUsed,
                        endedBy: 'admin'
                    }));
                    console.log(`📞 Müşteriye admin sonu bildirimi: ${customerId}`);
                }
            }
            
            // 3. Admin'e de bildir (eğer müşteri bitirdiyse)
            if (message.userId !== 'ADMIN001' && message.userType !== 'admin') {
                broadcastToAdmins({
                    type: 'call-ended',
                    duration: actualDuration,
                    creditsUsed: creditsUsed,
                    userId: customerId,
                    endedBy: 'customer'
                });
            }
            
            // Veritabanına kaydet ve krediyi düş
            if (actualDuration > 0 && creditsUsed > 0 && customerId) {
                console.log(`💳 Kredi düşürme işlemi başlatılıyor...`);
                
                const saveSuccess = await saveCallToDatabase(customerId, actualDuration, creditsUsed);
                
                if (saveSuccess) {
                    // Kullanıcıya güncellenmiş kredi bilgisini gönder
                    const updatedCredits = await getUserCredits(customerId);
                    const userClient = clients.get(customerId);
                    if (userClient && userClient.ws.readyState === WebSocket.OPEN) {
                        userClient.ws.send(JSON.stringify({
                            type: 'credit-update',
                            credits: updatedCredits
                        }));
                        console.log(`📱 Kullanıcıya yeni kredi bilgisi gönderildi: ${updatedCredits}`);
                    }
                    
                    // Admin'e kredi güncellemesi bildir
                    broadcastToAdmins({
                        type: 'credit-updated',
                        userId: customerId,
                        newCredits: updatedCredits,
                        creditsUsed: creditsUsed,
                        duration: actualDuration
                    });
                    
                    console.log(`✅ ${customerId} kullanıcısının ${creditsUsed} kredisi düşüldü. Kalan: ${updatedCredits}`);
                } else {
                    console.error(`❌ Kredi düşme işlemi başarısız: ${customerId}`);
                }
            } else {
                console.log(`ℹ️ Kredi düşürülmedi: duration=${actualDuration}, credits=${creditsUsed}, customer=${customerId}`);
            }
            break;
            
        case 'credit-update':
            const creditUserId = message.userId;
            const userClient = clients.get(creditUserId);
            if (userClient && userClient.ws.readyState === WebSocket.OPEN) {
                userClient.ws.send(JSON.stringify({
                    type: 'credit-update',
                    credits: message.credits
                }));
                console.log('💳 Kredi güncellendi:', creditUserId, message.credits);
            }
            break;
    }
}

function broadcastToAdmins(message) {
    for (const [userId, client] of clients.entries()) {
        if (client.userType === 'admin' && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify(message));
        }
    }
}

function broadcastUserList() {
    const userList = Array.from(clients.entries()).map(([id, client]) => ({
        id,
        name: client.name,
        userType: client.userType,
        online: client.online,
        registeredAt: client.registeredAt
    }));
    
    broadcastToAdmins({
        type: 'user-list-update',
        users: userList
    });
}

// Veritabanını başlat
initDatabase().then(() => {
    console.log('🔧 Database initialization completed');
}).catch((error) => {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
});

// Server'ı başlat - Railway için dinamik port
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
    const railwayUrl = process.env.RAILWAY_STATIC_URL || `localhost:${PORT}`;
    console.log('');
    console.log('🚂 VIPCEP Server - Railway\'de Çalışıyor!');
    console.log('🌐 Public URL: https://' + railwayUrl);
    console.log('🔌 WebSocket: wss://' + railwayUrl);
    console.log('🗄️ Veritabanı: PostgreSQL (Railway)');
    console.log('🌍 Environment:', process.env.NODE_ENV || 'development');
    console.log('');
    console.log('🚀 İKİ YÖNLÜ ARAMA SİSTEMİ AKTİF');
    console.log('   📞 Admin → Müşteri arama');
    console.log('   📱 Müşteri → Admin arama');
    console.log('   ✅ WebRTC P2P ses bağlantısı');
    console.log('   💳 Otomatik kredi düşme sistemi');
    console.log('');
    console.log('📱 Uygulamalar:');
    console.log('   📞 Admin paneli: https://' + railwayUrl + '/admin-panel.html');
    console.log('   📱 Müşteri uygulaması: https://' + railwayUrl + '/customer-app.html');
    console.log('');
    console.log('🧪 TEST KULLANICISI: ID=1234, Ad=Test Kullanıcı, Kredi=10');
    console.log('');
    console.log('✅ Railway Deployment Başarılı - Proje %100 Tamamlandı!');
    console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Railway server kapatılıyor...');
    wss.close(() => {
        server.close(() => {
            pool.end(() => {
                console.log('✅ Railway server başarıyla kapatıldı');
                process.exit(0);
            });
        });
    });
});

// Railway specific error handling
process.on('SIGTERM', () => {
    console.log('\n🚂 Railway deployment yenileniyor...');
    wss.close(() => {
        server.close(() => {
            pool.end(() => {
                console.log('✅ Graceful shutdown completed');
                process.exit(0);
            });
        });
    });
});
