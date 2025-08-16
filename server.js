// server.js içinde sadece değişen kısımlar

// end-call case'ini bununla değiştir (satır ~320 civarı)
case 'end-call':
    console.log('📞 Görüşme sonlandırılıyor:', message.userId);
    
    const duration = message.duration || 0;
    const creditsUsed = Math.ceil(duration / 60); // Yukarı yuvarlamalı
    
    // Hedef kullanıcıya bildir
    if (message.targetId) {
        const endTarget = clients.get(message.targetId);
        if (endTarget && endTarget.ws.readyState === WebSocket.OPEN) {
            endTarget.ws.send(JSON.stringify({
                type: 'call-ended',
                userId: message.userId,
                duration: duration,
                creditsUsed: creditsUsed,
                endedBy: message.userType || 'unknown'
            }));
        }
    }
    
    // Arama kaydını veritabanına kaydet ve kredi düş (sadece gerçek görüşmeler için)
    if (duration > 0 && message.userId && message.userId !== 'ADMIN001') {
        console.log(`💾 KREDİ DÜŞÜRME İŞLEMİ BAŞLIYOR:`);
        console.log(`   - Kullanıcı: ${message.userId}`);
        console.log(`   - Süre: ${duration} saniye`);
        console.log(`   - Düşecek Kredi: ${creditsUsed} dakika`);
        
        const saveResult = await saveCallToDatabase({
            userId: message.userId,
            adminId: message.targetId || 'ADMIN001',
            duration: duration,
            creditsUsed: creditsUsed,
            endReason: message.endedBy === 'admin' ? 'admin_ended' : 'customer_ended'
        });
        
        if (saveResult.success) {
            console.log(`✅ KREDİ DÜŞÜRME BAŞARILI:`);
            console.log(`   - Eski Kredi: ${saveResult.oldCredits}`);
            console.log(`   - Yeni Kredi: ${saveResult.newCredits}`);
            console.log(`   - Düşen: ${saveResult.creditsUsed}`);
            
            // 🔥 YENİ: TÜM CLIENT'LARA GÜNCEL KREDİYİ GÖNDER
            const allClients = Array.from(clients.values());
            allClients.forEach(client => {
                if (client.ws.readyState === WebSocket.OPEN) {
                    if (client.userType === 'admin') {
                        // Admin'lere detaylı kredi update
                        client.ws.send(JSON.stringify({
                            type: 'auto-credit-update',
                            userId: message.userId,
                            creditsUsed: creditsUsed,
                            newCredits: saveResult.newCredits,
                            oldCredits: saveResult.oldCredits,
                            duration: duration,
                            source: 'call_ended'
                        }));
                        console.log(`📨 Admin'e kredi güncellemesi gönderildi: ${client.id}`);
                    } else if (client.id === message.userId && client.userType === 'customer') {
                        // İlgili müşteriye kredi update
                        client.ws.send(JSON.stringify({
                            type: 'credit-update',
                            credits: saveResult.newCredits,
                            creditsUsed: creditsUsed,
                            duration: duration,
                            source: 'call_ended'
                        }));
                        console.log(`📨 Müşteriye kredi güncellemesi gönderildi: ${message.userId}`);
                    }
                }
            });
        } else {
            console.log(`❌ KREDİ DÜŞÜRME HATASI: ${saveResult.error}`);
            // Hata durumunda admin'lere bildir
            const adminClients = Array.from(clients.values()).filter(c => c.userType === 'admin');
            adminClients.forEach(client => {
                if (client.ws.readyState === WebSocket.OPEN) {
                    client.ws.send(JSON.stringify({
                        type: 'credit-error',
                        userId: message.userId,
                        error: saveResult.error,
                        message: 'Kredi düşürme işleminde hata oluştu!'
                    }));
                }
            });
        }
    } else {
        console.log(`ℹ️ Kredi düşürülmedi: duration=${duration}, userId=${message.userId}`);
    }
    break;
