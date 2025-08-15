self.addEventListener('install', event => {
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    clients.claim();
});

// Temel offline desteği ve push olayları
self.addEventListener('fetch', event => {
    // Burada offline cache ve fallback kodları eklenebilir
});

self.addEventListener('push', event => {
    const data = event.data.json();
    event.waitUntil(
        self.registration.showNotification(data.title, {
            body: data.body,
            icon: '/icon-192.png',
        })
    );
});
