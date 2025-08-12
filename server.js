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
        res.status(500).json({ error: error.message });
    }
});

// Kredi debug endpoint'i
app.get('/api/debug/user/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const user = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
        const transactions = await pool.query('SELECT * FROM credit_transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10', [id]);
        
        res.json({
            user: user.rows[0] || null,
            transactions: transactions.rows
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin panel route'u
app.get('/admin-panel.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-panel.html'));
});

// Customer app route'u  
app.get('/customer-app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'customer-app.html'));
});

// Veritabanı debug endpoint'i
app.get('/api/debug/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM approved_users ORDER BY created_at DESC');
        res.json({
            count: result.rows.length,
            users: result.rows
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Kredi debug endpoint'i
app.get('/api/debug/user/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const user = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
        const transactions = await pool.query('SELECT * FROM credit_transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10', [id]);
        
        res.json({
            user: user.rows[0] || null,
            transactions: transactions.rows
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


