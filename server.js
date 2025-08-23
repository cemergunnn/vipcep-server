const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');
const session = require('express-session');
const { Pool } = require('pg');
const winston = require('winston');
const path = require('path');

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Database setup
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
  SUPER_ADMIN_PATH: '/panel-' + crypto.randomBytes(8).toString('hex'),
  NORMAL_ADMIN_PATH: '/desk-' + crypto.randomBytes(8).toString('hex'),
  CUSTOMER_PATH: '/app-' + crypto.randomBytes(8).toString('hex'),
  SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  TOTP_ISSUER: 'VIPCEP System',
  TOTP_WINDOW: 2
};

// Middleware
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));
app.use(session({
  secret: SECURITY_CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    httpOnly: true, 
    maxAge: 24 * 60 * 60 * 1000 
  }
}));

// WebSocket setup
const wss = new WebSocket.Server({ server });

// Global variables
const clients = new Map();
const activeHeartbeats = new Map();
const activeCallAdmins = new Map();
const activeCalls = new Map();
const incomingCallQueue = new Map();
const callTimeouts = new Map();
const MAX_QUEUE_SIZE = 5;
const CALL_TIMEOUT_DURATION = 30000;
const HEARTBEAT_INTERVAL = 60000;

// Helper functions
const generateCallId = () => `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

const addToCallQueue = (callData) => {
  if (incomingCallQueue.size >= MAX_QUEUE_SIZE) {
    let oldestCall = null;
    let oldestTime = Date.now();
    for (const [callId, call] of incomingCallQueue.entries()) {
      if (call.timestamp < oldestTime) {
        oldestTime = call.timestamp;
        oldestCall = callId;
      }
    }
    if (oldestCall) removeFromCallQueue(oldestCall, 'queue_full');
  }

  const callId = generateCallId();
  const callEntry = {
    callId,
    userId: callData.userId,
    userName: callData.userName,
    credits: callData.credits,
    timestamp: Date.now(),
    status: 'waiting'
  };

  incomingCallQueue.set(callId, callEntry);
  const timeoutId = setTimeout(() => removeFromCallQueue(callId, 'timeout'), CALL_TIMEOUT_DURATION);
  callTimeouts.set(callId, timeoutId);

  logger.info(`Call added to queue: ${callId}`);
  return callEntry;
};

const removeFromCallQueue = (callId, reason = 'manual') => {
  const callData = incomingCallQueue.get(callId);
  if (!callData) return null;

  const timeoutId = callTimeouts.get(callId);
  if (timeoutId) {
    clearTimeout(timeoutId);
    callTimeouts.delete(callId);
  }

  incomingCallQueue.delete(callId);
  broadcastCallQueueToAdmins();
  logger.info(`Call removed from queue: ${callId}, reason: ${reason}`);
  return callData;
};

const broadcastCallQueueToAdmins = () => {
  const queueArray = Array.from(incomingCallQueue.values()).sort((a, b) => a.timestamp - b.timestamp);
  const message = JSON.stringify({
    type: 'call-queue-update',
    queue: queueArray,
    queueSize: queueArray.length
  });

  const availableAdmins = Array.from(clients.values())
    .filter(c => c.userType === 'admin' && !activeCallAdmins.has(c.uniqueId || c.id));
  
  availableAdmins.forEach(adminClient => {
    if (adminClient.ws.readyState === WebSocket.OPEN) {
      adminClient.ws.send(message);
    }
  });
};

const removeUserCallFromQueue = (userId, reason = 'user_cancelled') => {
  const callId = [...incomingCallQueue.entries()].find(([_, callData]) => callData.userId === userId)?.[0];
  if (callId) return removeFromCallQueue(callId, reason);
  return null;
};

const acceptCallFromQueue = (callId, adminId) => {
  const callData = incomingCallQueue.get(callId);
  if (!callData) return null;

  removeFromCallQueue(callId, 'accepted');
  return callData;
};

const clearAllCallQueue = (reason = 'emergency') => {
  for (const timeoutId of callTimeouts.values()) clearTimeout(timeoutId);
  callTimeouts.clear();
  incomingCallQueue.clear();
  broadcastCallQueueToAdmins();
  logger.info(`Call queue cleared: ${reason}`);
};

// Authentication functions
const checkRateLimit = async (ip, userType = 'customer') => {
  try {
    const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
    const { rows } = await pool.query(
      'SELECT COUNT(*) as count FROM failed_logins WHERE ip_address = $1 AND user_type = $2 AND attempt_time > $3',
      [ip, userType, thirtyMinutesAgo]
    );

    const count = parseInt(rows[0].count);
    return {
      allowed: count < 5,
      attempts: count,
      remaining: Math.max(0, 5 - count),
      resetTime: count >= 5 ? new Date(Date.now() + 30 * 60 * 1000) : null
    };
  } catch (error) {
    logger.error(`Rate limit check failed: ${error.message}`);
    return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
  }
};

const recordFailedLogin = async (ip, userType = 'customer') => {
  try {
    await pool.query(
      'INSERT INTO failed_logins (ip_address, user_type) VALUES ($1, $2)',
      [ip, userType]
    );
    return await checkRateLimit(ip, userType);
  } catch (error) {
    logger.error(`Failed login record error: ${error.message}`);
    return { allowed: true, attempts: 0, remaining: 5, resetTime: null };
  }
};

const generateTOTPSecret = () => crypto.randomBytes(16).toString('hex').toUpperCase();

const verifyTOTP = (secret, token) => {
  if (!secret || !token || token.length !== 6) return false;

  try {
    const secretBuffer = Buffer.from(secret, 'hex');
    const timeStep = 30;
    const currentTime = Math.floor(Date.now() / 1000 / timeStep);

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
      if (otp === token) return true;
    }
    return false;
  } catch (error) {
    logger.error(`TOTP verification failed: ${error.message}`);
    return false;
  }
};

const generateTOTPQR = (username, secret) => {
  const serviceName = encodeURIComponent(SECURITY_CONFIG.TOTP_ISSUER);
  const accountName = encodeURIComponent(username);
  return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=otpauth://totp/${serviceName}:${accountName}?secret=${secret}&issuer=${serviceName}`;
};

// Database initialization
const initDatabase = async () => {
  try {
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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS failed_logins (
        id SERIAL PRIMARY KEY,
        ip_address INET NOT NULL,
        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_type VARCHAR(20) DEFAULT 'customer'
      )
    `);

    const superAdminCheck = await pool.query('SELECT * FROM admins WHERE role = $1', ['super']);
    if (!superAdminCheck.rows.length) {
      const hashedPassword = crypto.createHash('sha256').update('admin123').digest('hex');
      const totpSecret = generateTOTPSecret();
      await pool.query(
        'INSERT INTO admins (username, password_hash, role, totp_secret) VALUES ($1, $2, $3, $4)',
        ['superadmin', hashedPassword, 'super', totpSecret]
      );
      logger.info('Super admin created');
    }

    const testUsers = [
      ['1234', 'Test Kullanıcı', 10],
      ['0005', 'VIP Müşteri', 25],
      ['0007', 'Cenk Zortu', 999],
      ['9999', 'Demo User', 5]
    ];

    for (const [id, name, credits] of testUsers) {
      const existingUser = await pool.query('SELECT * FROM approved_users WHERE id = $1', [id]);
      if (!existingUser.rows.length) {
        await pool.query(
          'INSERT INTO approved_users (id, name, credits) VALUES ($1, $2, $3)',
          [id, name, credits]
        );
        logger.info(`Test user created: ${id}`);
      }
    }
  } catch (error) {
    logger.error(`Database initialization failed: ${error.message}`);
    throw error;
  }
};

// WebSocket message handling
wss.on('connection', (ws, req) => {
  const clientIP = req.socket.remoteAddress;
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      const { type, userId, userName, credits, callId, targetId, reason, duration } = data;
      const senderId = data.userId || data.adminId;
      const senderType = data.userType;

      switch (type) {
        case 'register':
          const rateStatus = await checkRateLimit(clientIP, data.userType);
          if (!rateStatus.allowed) {
            ws.send(JSON.stringify({
              type: 'login-response',
              success: false,
              reason: `Rate limit exceeded. Try again after ${rateStatus.resetTime}`
            }));
            return;
          }

          const approval = await pool.query('SELECT * FROM approved_users WHERE id = $1', [data.id]);
          if (approval.rows.length && approval.rows[0].status === 'active') {
            clients.set(data.id, {
              ws,
              id: data.id,
              name: approval.rows[0].name,
              userType: data.userType,
              registeredAt: Date.now(),
              online: true
            });
            ws.send(JSON.stringify({
              type: 'login-response',
              success: true,
              credits: approval.rows[0].credits,
              user: approval.rows[0]
            }));
            broadcastUserList();
          } else {
            await recordFailedLogin(clientIP);
            ws.send(JSON.stringify({
              type: 'login-response',
              success: false,
              reason: approval.rows[0]?.reason || 'User not approved'
            }));
          }
          break;

        case 'call-request':
          const callEntry = addToCallQueue({ userId, userName, credits });
          broadcastCallQueueToAdmins();
          break;

        case 'accept-call-by-id':
          const acceptedCall = acceptCallFromQueue(callId, senderId);
          if (!acceptedCall) {
            ws.send(JSON.stringify({
              type: 'call-accept-error',
              error: 'Call not found'
            }));
            return;
          }

          activeCallAdmins.set(senderId, {
            customerId: acceptedCall.userId,
            callStartTime: Date.now()
          });

          const acceptedCustomer = clients.get(acceptedCall.userId);
          if (acceptedCustomer?.ws.readyState === WebSocket.OPEN) {
            acceptedCustomer.ws.send(JSON.stringify({
              type: 'call-accepted',
              acceptedAdminId: senderId,
              callId
            }));
          }

          const allAdmins = Array.from(clients.values()).filter(c => c.userType === 'admin');
          allAdmins.forEach(adminClient => {
            if (adminClient.uniqueId !== senderId && adminClient.ws.readyState === WebSocket.OPEN) {
              adminClient.ws.send(JSON.stringify({
                type: 'call-taken',
                userId: acceptedCall.userId,
                callId,
                takenBy: senderId
              }));
            }
          });

          const acceptCallKey = `${acceptedCall.userId}-${senderId}`;
          startHeartbeat(acceptedCall.userId, senderId, acceptCallKey);
          break;

        case 'reject-call-by-id':
          const rejectedCall = removeFromCallQueue(callId, 'admin_rejected');
          if (rejectedCall) {
            const rejectedCustomer = clients.get(rejectedCall.userId);
            if (rejectedCustomer?.ws.readyState === WebSocket.OPEN) {
              rejectedCustomer.ws.send(JSON.stringify({
                type: 'call-rejected',
                reason: reason || 'Call rejected',
                callId
              }));
            }
          }
          break;

        case 'call-cancelled':
          removeUserCallFromQueue(userId, 'user_cancelled');
          break;

        case 'offer':
        case 'answer':
        case 'ice-candidate':
          const targetClient = findWebRTCTarget(targetId, senderType);
          if (targetClient?.ws.readyState === WebSocket.OPEN) {
            const forwardMessage = {
              type,
              [type]: data[type],
              userId: senderId,
              targetId
            };
            if (type === 'ice-candidate') forwardMessage.candidate = data.candidate;
            targetClient.ws.send(JSON.stringify(forwardMessage));
          }
          break;

        case 'end-call':
          if (senderType === 'admin') {
            activeCallAdmins.delete(senderId);
          } else if (targetId) {
            activeCallAdmins.delete(targetId);
          }

          const endCallKey = targetId ? `${senderId}-${targetId}` : `${senderId}-ADMIN001`;
          stopHeartbeat(endCallKey, 'user_ended');

          const creditsUsed = Math.ceil(duration / 60);
          if (targetId) {
            const endTarget = findWebRTCTarget(targetId, senderType);
            if (endTarget?.ws.readyState === WebSocket.OPEN) {
              endTarget.ws.send(JSON.stringify({
                type: 'call-ended',
                userId: senderId,
                duration,
                creditsUsed,
                endedBy: senderType || 'unknown'
              }));
            }
          }

          if (senderType === 'admin') {
            setTimeout(broadcastCallQueueToAdmins, 1000);
          }
          break;
      }
    } catch (error) {
      logger.error(`Message processing error: ${error.message}`);
    }
  });

  ws.on('close', () => {
    const client = findClientById(ws);
    if (client) {
      if (client.userType === 'customer') {
        removeUserCallFromQueue(client.id, 'user_disconnected');
      }
      if (client.userType === 'admin') {
        const adminKey = client.uniqueId || client.id;
        activeCallAdmins.delete(adminKey);
      }
      for (const [callKey, heartbeat] of activeHeartbeats.entries()) {
        if (callKey.includes(client.id)) stopHeartbeat(callKey, 'connection_lost');
      }
      clients.delete(client.id);
      broadcastUserList();
      if (client.userType === 'admin') {
        setTimeout(broadcastCallQueueToAdmins, 500);
      }
    }
  });

  ws.on('error', (error) => logger.error(`WebSocket error: ${error.message}`));
});

const findClientById = (ws) => {
  for (const [id, client] of clients) {
    if (client.ws === ws) return client;
  }
  return null;
};

const findWebRTCTarget = (targetId, sourceType) => {
  let targetClient = clients.get(targetId);
  if (targetClient) return targetClient;

  if (targetId.includes('_')) {
    const normalId = targetId.split('_')[0];
    for (const [_, clientData] of clients) {
      if (clientData.id === normalId && clientData.userType === 'admin') return clientData;
    }
  } else {
    for (const [clientId, clientData] of clients) {
      if (clientId.startsWith(targetId + '_') && clientData.userType === 'admin') return clientData;
    }
  }
  return null;
};

const broadcastUserList = () => {
  const userList = Array.from(clients.values()).map(client => ({
    id: client.id,
    name: client.name,
    userType: client.userType,
    registeredAt: client.registeredAt,
    online: client.online
  }));

  const message = JSON.stringify({ type: 'user-list-update', users: userList });
  clients.forEach(client => {
    if (client.ws.readyState === WebSocket.OPEN) client.ws.send(message);
  });
};

const startHeartbeat = (userId, adminId, callKey) => {
  const heartbeat = setInterval(() => {
    const user = clients.get(userId);
    const admin = clients.get(adminId);
    if (!user || !admin || user.ws.readyState !== WebSocket.OPEN || admin.ws.readyState !== WebSocket.OPEN) {
      stopHeartbeat(callKey, 'connection_lost');
    }
  }, HEARTBEAT_INTERVAL);
  activeHeartbeats.set(callKey, heartbeat);
};

const stopHeartbeat = (callKey, reason) => {
  const heartbeat = activeHeartbeats.get(callKey);
  if (heartbeat) {
    clearInterval(heartbeat);
    activeHeartbeats.delete(callKey);
    logger.info(`Heartbeat stopped for ${callKey}: ${reason}`);
  }
};

// 404 handler
app.use((req, res) => {
  res.status(404).send(`
    <div style="text-align: center; padding: 50px; font-family: system-ui;">
      <h1>🔐 404 - Page Not Found</h1>
      <p>This page does not exist for security reasons.</p>
      <p><a href="/" style="color: #dc2626; text-decoration: none;">← Back to Home</a></p>
    </div>
  `);
});

// Server startup
const startServer = async () => {
  try {
    logger.info('🚀 Starting VIPCEP Server...');
    await initDatabase();
    server.listen(PORT, '0.0.0.0', () => {
      logger.info(`🎯 VIPCEP Server Running on port ${PORT}`);
      logger.info(`🔗 URL: http://0.0.0.0:${PORT}`);
      logger.info(`📡 WebSocket: ws://0.0.0.0:${PORT}`);
      logger.info(`🗄️ Database: ${process.env.DATABASE_URL ? 'PostgreSQL (Railway)' : 'LocalStorage'}`);
      logger.info('🔐 Security URLs:');
      logger.info(` 🔴 Super Admin: ${SECURITY_CONFIG.SUPER_ADMIN_PATH}`);
      logger.info(` 🟡 Normal Admin: ${SECURITY_CONFIG.NORMAL_ADMIN_PATH}`);
      logger.info(` 🟢 Customer App: ${SECURITY_CONFIG.CUSTOMER_PATH}`);
      logger.info(`📞 Multi-call system active. Max queue: ${MAX_QUEUE_SIZE}, Timeout: ${CALL_TIMEOUT_DURATION/1000}s`);
    });
  } catch (error) {
    logger.error(`Server startup failed: ${error.message}`);
    process.exit(1);
  }
};

// Error handling
process.on('uncaughtException', (error) => logger.error(`Uncaught Exception: ${error.message}`));
process.on('unhandledRejection', (reason) => logger.error(`Unhandled Rejection: ${reason}`));
process.on('SIGTERM', () => {
  logger.info('🔴 Shutting down server...');
  for (const [callKey, heartbeat] of activeHeartbeats) clearInterval(heartbeat);
  activeHeartbeats.clear();
  activeCallAdmins.clear();
  activeCalls.clear();
  clearAllCallQueue('server_shutdown');
  server.close(() => {
    logger.info('✅ Server shut down successfully');
    process.exit(0);
  });
});

startServer();
