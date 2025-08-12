// server.js'e bu case'i ekle (WebSocket message handler'ına)

case 'credit-update-broadcast':
    console.log('💳 Kredi güncelleme broadcast:', message.userId, '->', message.newCredits);
    
    // Güncellenen kullanıcıya bildir
    const updatedUserClient = clients.get(message.userId);
    if (updatedUserClient && updatedUserClient.userType === 'customer') {
        updatedUserClient.ws.send(JSON.stringify({
            type: 'credit-update',
            credits: message.newCredits,
            updatedBy: message.updatedBy || 'admin',
            message: 'Krediniz güncellendi!'
        }));
        console.log(`📱 Müşteriye kredi güncelleme bildirildi: ${message.userId} -> ${message.newCredits} dk`);
    } else {
        console.log(`📱 Kullanıcı çevrimdışı: ${message.userId}`);
    }
    
    // Tüm admin'lere de bildir
    clients.forEach((client) => {
        if (client.userType === 'admin' && client.ws !== ws) {
            client.ws.send(JSON.stringify({
                type: 'credit-updated',
                userId: message.userId,
                newCredits: message.newCredits,
                updatedBy: message.updatedBy
            }));
        }
    });
    break;
