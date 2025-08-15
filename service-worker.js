// Service Worker for VIPCEP
const CACHE_NAME = 'vipcep-v1';
const urlsToCache = [
  '/',
  '/customer-app.html',
  '/admin-panel.html',
  '/manifest.json'
];

// Install event
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting();
});

// Activate event
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(cacheName => cacheName !== CACHE_NAME)
          .map(cacheName => caches.delete(cacheName))
      );
    })
  );
  self.clients.claim();
});

// Fetch event
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/api/') || event.request.url.includes('ws://') || event.request.url.includes('wss://')) {
    return;
  }
  
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});

// Push notification event
self.addEventListener('push', event => {
  const options = {
    body: event.data ? event.data.text() : 'Yeni arama var!',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    vibrate: [200, 100, 200, 100, 200],
    tag: 'vipcep-call',
    requireInteraction: true,
    actions: [
      { action: 'accept', title: 'Kabul Et', icon: '/icon-accept.png' },
      { action: 'reject', title: 'Reddet', icon: '/icon-reject.png' }
    ],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    }
  };

  event.waitUntil(
    self.registration.showNotification('📞 VIPCEP Gelen Arama', options)
  );
});

// Notification click event
self.addEventListener('notificationclick', event => {
  event.notification.close();

  if (event.action === 'accept') {
    event.waitUntil(
      clients.openWindow('/customer-app.html?action=accept')
    );
  } else if (event.action === 'reject') {
    event.waitUntil(
      clients.openWindow('/customer-app.html?action=reject')
    );
  } else {
    event.waitUntil(
      clients.openWindow('/customer-app.html')
    );
  }
});

// Message event for WebSocket notifications
self.addEventListener('message', event => {
  if (event.data.type === 'INCOMING_CALL') {
    self.registration.showNotification('📞 Gelen Arama', {
      body: `${event.data.caller} sizi arıyor`,
      icon: '/icon-192.png',
      vibrate: [200, 100, 200],
      requireInteraction: true,
      actions: [
        { action: 'accept', title: 'Kabul Et' },
        { action: 'reject', title: 'Reddet' }
      ]
    });
  }
});
