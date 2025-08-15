const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Veritabanı olarak basit bir JSON dosyası kullanıyoruz (örnek)
const USERS_DB_PATH = path.join(__dirname, 'approved-users.json');

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'main')));

// API: Tüm onaylı kullanıcıları getir
app.get('/api/approved-users', (req, res) => {
    fs.readFile(USERS_DB_PATH, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Veritabanı okunamadı' });
        let users = [];
        try {
            users = JSON.parse(data);
        } catch (e) { }
        res.json(users);
    });
});

// API: Belirli bir kullanıcıyı getir
app.get('/api/approved-users/:id', (req, res) => {
    fs.readFile(USERS_DB_PATH, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Veritabanı okunamadı' });
        let users = [];
        try {
            users = JSON.parse(data);
        } catch (e) { }
        const user = users.find(u => u.id === req.params.id);
        if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        res.json(user);
    });
});

// API: Kullanıcı kredi güncelle
app.post('/api/approved-users/:id/credits', (req, res) => {
    const { credits, reason } = req.body;
    fs.readFile(USERS_DB_PATH, 'utf8', (err, data) => {
        if (err) return res.status(500).json({ error: 'Veritabanı okunamadı' });
        let users = [];
        try {
            users = JSON.parse(data);
        } catch (e) { }
        const userIndex = users.findIndex(u => u.id === req.params.id);
        if (userIndex < 0) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        users[userIndex].credits = credits;
        users[userIndex].lastCreditUpdate = new Date().toISOString();
        users[userIndex].creditUpdateReason = reason || '';
        fs.writeFile(USERS_DB_PATH, JSON.stringify(users, null, 2), (err) => {
            if (err) return res.status(500).json({ error: 'Veritabanı güncellenemedi' });
            res.json({ success: true, user: users[userIndex] });
        });
    });
});

// Part 2'de: WebSocket iletişimi, yeni kullanıcı ekleme/silme, arama yönetimi// WebSocket bağlantıları ve çağrı yönetimi
let connectedAdmins = [];
let connectedCustomers = [];

wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.on('pong', () => ws.isAlive = true);

    ws.on('message', (msg) => {
        try {
            const data = JSON.parse(msg);
            // Admin bağlanınca
            if (data.type === 'admin-connect') {
                ws.role = 'admin';
                ws.adminId = data.adminId || 'ADMIN001';
                connectedAdmins.push(ws);
                ws.send(JSON.stringify({ type: 'admin-confirmed', message: 'Admin bağlı' }));
            }
            // Müşteri bağlanınca
            if (data.type === 'customer-connect') {
                ws.role = 'customer';
                ws.userId = data.userId;
                connectedCustomers.push(ws);
                ws.send(JSON.stringify({ type: 'customer-confirmed', message: 'Müşteri bağlı' }));
            }
            // Müşteri çağrı başlatınca
            if (data.type === 'customer-call') {
                // Adminlere ilet
                connectedAdmins.forEach(a =>
                    a.send(JSON.stringify({ type: 'incoming-call', userId: data.userId }))
                );
            }
            // Admin çağrıyı kabul edince
            if (data.type === 'admin-accept-call') {
                connectedCustomers.forEach(c => {
                    if (c.userId === data.userId) {
                        c.send(JSON.stringify({ type: 'call-accepted' }));
                    }
                });
            }
            // Admin çağrıyı reddedince
            if (data.type === 'admin-reject-call') {
                connectedCustomers.forEach(c => {
                    if (c.userId === data.userId) {
                        c.send(JSON.stringify({ type: 'call-rejected' }));
                    }
                });
            }
            // Kredi güncelleme yayını
            if (data.type === 'credit-update-broadcast') {
                connectedCustomers.forEach(c => {
                    if (c.userId === data.userId) {
                        c.send(JSON.stringify({
                            type: 'credit-update',
                            newCredits: data.newCredits
                        }))
                    }
                });
            }
        } catch (err) { /* Mesaj parse hatası */ }
    });

    ws.on('close', () => {
        if (ws.role === 'admin') {
            connectedAdmins = connectedAdmins.filter(a => a !== ws);
        }
        if (ws.role === 'customer') {
            connectedCustomers = connectedCustomers.filter(c => c !== ws);
        }
    });
});

// Sağlık kontrolü (ping-pong)
setInterval(() => {
    wss.clients.forEach(ws => {
        if (!ws.isAlive) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

// Yeni kullanıcı ekleme/silme endpoints'i (örnek)
app.post('/api/approved-users', (req, res) => {
    const { id, name, credits } = req.body;
    fs.readFile(USERS_DB_PATH, 'utf8', (err, data) => {
        let users = [];
        if (!err && data) {
            try { users = JSON.parse(data); } catch (e) {}
        }
        if (users.some(u => u.id === id)) {
            return res.status(400).json({ error: 'ID zaten mevcut' });
        }
        const newUser = { id, name, credits: credits || 0, created_at: new Date().toISOString() };
        users.push(newUser);
        fs.writeFile(USERS_DB_PATH, JSON.stringify(users, null, 2), (err) => {
            if (err) return res.status(500).json({ error: 'Kullanıcı eklenemedi' });
            res.json({ success: true, user: newUser });
        });
    });
});

app.delete('/api/approved-users/:id', (req, res) => {
    fs.readFile(USERS_DB_PATH, 'utf8', (err, data) => {
        let users = [];
        if (!err && data) {
            try { users = JSON.parse(data); } catch (e) {}
        }
        const index = users.findIndex(u => u.id === req.params.id);
        if (index < 0) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        users.splice(index, 1);
        fs.writeFile(USERS_DB_PATH, JSON.stringify(users, null, 2), (err) => {
            if (err) return res.status(500).json({ error: 'Kullanıcı silinemedi' });
            res.json({ success: true });
        });
    });
});

// Part 3'te sunucuyu başlatma ve dinleme kodu, eksik dosya uyarıları// Sunucu başlatma ve eksik dosya uyarıları
const PORT = process.env.PORT || 8080;

server.listen(PORT, () => {
    console.log(`VIPCEP sunucu ${PORT} portunda çalışıyor.`);
    // Eksik dosyalar için uyarı
    if (!fs.existsSync(USERS_DB_PATH)) {
        fs.writeFileSync(USERS_DB_PATH, JSON.stringify([], null, 2));
        console.log('approved-users.json dosyası oluşturuldu!');
    }
});

// Sunucu dosyası tamamlandı!

