const CACHE_NAME = 'mumbigames-v2';
const OFFLINE_URLS = [
  '/index.html',
  '/manifest.json'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(OFFLINE_URLS).catch(() => {}))
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Only manage our own site's files (the app shell). Firebase/Firestore,
  // imgbb images, Google Fonts, etc. are a different origin — leave those
  // completely untouched so live data (games, chat, tournaments) always
  // stays fresh and nothing here can interfere with them.
  if (url.origin !== self.location.origin) return;

  // Stale-while-revalidate: serve the cached shell INSTANTLY (this is what
  // makes reopening the app — e.g. after returning from Chrome — feel fast),
  // then quietly fetch a fresh copy in the background for next time.
  event.respondWith(
    caches.match(req).then((cached) => {
      const fetchPromise = fetch(req)
        .then((networkResponse) => {
          caches.open(CACHE_NAME).then((cache) => cache.put(req, networkResponse.clone()));
          return networkResponse;
        })
        .catch(() => cached);
      return cached || fetchPromise;
    })
  );
});

