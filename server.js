const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const { Client } = require("pg");
const fs = require("fs");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.static("public"));
app.use(cors());
app.use(express.json());

const clients = new Map();
const callQueue = [];
const adminStatuses = new Map(); // Admin durumlarını yönetmek için yeni harita

const pgClient = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

pgClient.connect();

// Yeni admin durumu yönetimi
wss.on("connection", (ws) => {
  const clientId = uuidv4();
  clients.set(clientId, ws);
  console.log(`Client connected: ${clientId}`);

  ws.on("message", async (message) => {
    const data = JSON.parse(message);
    console.log("Received data:", data);

    switch (data.type) {
      case "register_admin":
        adminStatuses.set(clientId, "available"); // Admin durumunu müsait olarak ayarla
        ws.is_admin = true;
        ws.user_id = data.user_id;
        ws.client_id = clientId;
        break;

      case "register_customer":
        ws.is_admin = false;
        ws.user_id = data.user_id;
        ws.client_id = clientId;
        break;

      case "call_request":
        const availableAdmin = [...adminStatuses.entries()].find(
          ([id, status]) => status === "available"
        );

        if (availableAdmin) {
          const [adminId] = availableAdmin;
          const adminWs = clients.get(adminId);

          if (adminWs) {
            adminWs.send(
              JSON.stringify({
                type: "incoming_call",
                from: clientId,
                customer_name: "Müşteri " + data.user_id,
              })
            );
            ws.send(
              JSON.stringify({
                type: "call_initiated",
                to: adminId,
              })
            );
            adminStatuses.set(adminId, "busy"); // Admin durumunu meşgul olarak ayarla
          }
        } else {
          callQueue.push(clientId);
          ws.send(
            JSON.stringify({
              type: "call_queued",
              queue_position: callQueue.length,
            })
          );
        }
        break;

      case "webrtc_offer":
      case "webrtc_answer":
      case "webrtc_ice_candidate":
        const targetWs = clients.get(data.to);
        if (targetWs) {
          targetWs.send(JSON.stringify(data));
        }
        break;

      case "call_end":
        // Kredi güncellemesi
        const { duration, customer_id, admin_id } = data;
        const creditsUsed = Math.ceil(duration / 60);

        try {
          const result = await pgClient.query(
            "SELECT credits FROM users WHERE user_id = $1",
            [customer_id]
          );
          const currentCredits = result.rows[0].credits;
          const newCredits = currentCredits - creditsUsed;

          await pgClient.query("UPDATE users SET credits = $1 WHERE user_id = $2", [
            newCredits,
            customer_id,
          ]);

          // Admin durumunu müsait olarak ayarla
          adminStatuses.set(admin_id, "available");

          // Müşteri ve admin'e anlık bakiye güncellemesi gönder
          const customerWs = clients.get(customer_id);
          if (customerWs) {
            customerWs.send(
              JSON.stringify({
                type: "credit_update",
                credits: newCredits,
              })
            );
          }
          const adminWs = clients.get(admin_id);
          if (adminWs) {
            adminWs.send(
              JSON.stringify({
                type: "credit_update",
                credits: newCredits, // Admin panelinde de gösterilebilir
              })
            );
          }

          // Kuyruktaki ilk kişiyi çağır
          if (callQueue.length > 0) {
            const nextCustomerId = callQueue.shift();
            const nextCustomerWs = clients.get(nextCustomerId);
            if (nextCustomerWs) {
              nextCustomerWs.send(
                JSON.stringify({
                  type: "call_initiated",
                  to: admin_id,
                })
              );
              // Admin'e yeni arama bildirimi gönder
              adminWs.send(
                JSON.stringify({
                  type: "incoming_call",
                  from: nextCustomerId,
                  customer_name: "Müşteri " + nextCustomerId,
                })
              );
              adminStatuses.set(admin_id, "busy"); // Tekrar meşgul yap
            }
          }
        } catch (error) {
          console.error("Error updating credits:", error);
        }
        break;
    }
  });

  ws.on("close", () => {
    console.log(`Client disconnected: ${clientId}`);
    clients.delete(clientId);
    adminStatuses.delete(clientId); // Bağlantı kapanınca admin durumunu sil
    const queueIndex = callQueue.indexOf(clientId);
    if (queueIndex > -1) {
      callQueue.splice(queueIndex, 1);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
