// Push notification setup for customer and admin panels

// Register service worker for PWA and push
export function setupPushNotifications() {
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/service-worker.js')
            .then(reg => {
                console.log('Service Worker registered:', reg.scope);
                // Notification permission
                if (Notification.permission === 'default') {
                    Notification.requestPermission();
                }
            })
            .catch(err => console.error('Service Worker error:', err));
    }
}

// Local notification (for instant alerts)
export function sendLocalNotification(title, body) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, { body });
    }
}
