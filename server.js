const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const wss = new WebSocket.Server({ server });
const clients = new Map();

async function initDatabase() {
    try {
        await pool.query(`CREATE TABLE IF NOT EXISTS approved_users (id VARCHAR(10) PRIMARY KEY, name VARCHAR(255) NOT NULL, credits INTEGER DEFAULT 0, total_calls INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_call TIMESTAMP, status VARCHAR(20) DEFAULT 'active')`);
        await pool.query(`CREATE TABLE IF NOT EXISTS call_history (id SERIAL PRIMARY KEY, user_id VARCHAR(10), admin_id VARCHAR(10), duration INTEGER DEFAULT 0, credits_used INTEGER DEFAULT 0, call_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, end_reason VARCHAR(50) DEFAULT 'normal')`);
        await pool.query(`CREATE TABLE IF NOT EXISTS credit_transactions (id SERIAL PRIMARY KEY, user_id VARCHAR(10), transaction_type VARCHAR(20), amount INTEGER, description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
        
        const testUsers = [['1234', 'Test Kullanıcı', 10], ['0005', 'VIP Müşteri', 25], ['0007', 'Cenk Zortu', 999], ['9999', 'Demo User', 5]];
        for (const [id, name, credits] of testUsers) {
            const existingUser = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
            if (existingUser.rows.length === 0) {
                await pool.query(`INSERT INTO approved_users (id, name, credits) VALUES ($1, $2, $3)`, [id, name, credits]);
            }
        }
        console.log('✅ Database initialized');
    } catch (error) {
        console.log('❌ Database error:', error.message);
    }
}

async function updateUserCredits(userId, newCredits, reason = 'Admin update') {
    try {
        const user = await pool.query('SELECT credits FROM approved_users WHERE id = $1', [userId]);
        if (user.rows.length === 0) throw new Error('User not found');
        
        const oldCredits = user.rows[0].credits;
        await pool.query('UPDATE approved_users SET credits = $1 WHERE id = $2', [newCredits, userId]);
        await pool.query(`INSERT INTO credit_transactions (user_id, transaction_type, amount, description) VALUES ($1, $2, $3, $4)`, [userId, 'update', newCredits - oldCredits, reason]);
        
        return { newCredits, oldCredits };
    } catch (error) {
        throw error;
    }
}

wss.on('connection', (ws) => {
    ws.on('message', async (data) => {
        try {
            const message = JSON.parse(data);
            
            switch (message.type) {
                case 'register':
                    clients.set(message.userId, { ws, id: message.userId, name: message.name, userType: message.userType || 'customer', online: true });
                    break;
                    
                case 'credit-updated':
                    const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
                    adminClients.forEach(client => {
                        if (client.ws.readyState === WebSocket.OPEN) {
                            client.ws.send(JSON.stringify(message));
                        }
                    });
                    break;
                    
                default:
                    if (message.targetId && clients.has(message.targetId)) {
                        clients.get(message.targetId).ws.send(JSON.stringify(message));
                    }
                    break;
            }
        } catch (error) {
            console.log('Message error:', error.message);
        }
    });
    
    ws.on('close', () => {
        for (const [key, clientData] of clients.entries()) {
            if (clientData.ws === ws) {
                clients.delete(key);
                break;
            }
        }
    });
});

app.get('/api/approved-users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/approved-users', async (req, res) => {
    try {
        const { id, name, credits = 0 } = req.body;
        if (!id || !name) return res.status(400).json({ error: 'ID and name required' });
        
        const result = await pool.query(`INSERT INTO approved_users (id, name, credits) VALUES ($1, $2, $3) RETURNING *`, [id, name, credits]);
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/approved-users/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM approved_users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/approved-users/:id/credits', async (req, res) => {
    try {
        const { id } = req.params;
        const { credits, reason } = req.body;
        
        const result = await updateUserCredits(id, credits, reason);
        
        const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
        adminClients.forEach(client => {
            if (client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify({
                    type: 'credit-updated',
                    userId: id,
                    newCredits: result.newCredits,
                    oldCredits: result.oldCredits,
                    updatedBy: 'admin-panel'
                }));
            }
        });
        
        res.json({ success: true, credits: result.newCredits });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM approved_users');
        const totalCredits = await pool.query('SELECT SUM(credits) FROM approved_users');
        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalCredits: parseInt(totalCredits.rows[0].sum || 0),
            onlineUsers: Array.from(clients.values()).filter(c => c.userType === 'customer').length,
            todayCalls: 0
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', clients: clients.size });
});

app.get('/', (req, res) => {
    res.send('<h1>🎯 VIPCEP Server</h1><p><a href="/admin-panel.html">Admin Panel</a></p>');
});

server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    initDatabase();
});
