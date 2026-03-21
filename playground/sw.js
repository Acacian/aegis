/**
 * Aegis Playground Service Worker — caches static assets for fast repeat loads.
 * Pyodide + WASM are cached on first use for near-instant subsequent visits.
 */
const CACHE_NAME = "aegis-playground-v2";
const STATIC_ASSETS = [
  "./",
  "./index.html",
  "./css/style.css",
  "./js/presets.js",
  "./js/app.js",
  "./favicon.svg",
  "./manifest.json",
  "./opensearch.xml",
];

// CDN assets cached on first fetch (cache-first for versioned URLs)
const CDN_PATTERNS = [
  "cdnjs.cloudflare.com/ajax/libs/codemirror",
  "cdn.jsdelivr.net/pyodide",
  "files.pythonhosted.org",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = event.request.url;

  // CDN assets: cache-first (immutable versioned URLs)
  if (CDN_PATTERNS.some((p) => url.includes(p))) {
    event.respondWith(
      caches.match(event.request).then(
        (cached) => cached || fetch(event.request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
      )
    );
    return;
  }

  // Local assets: network-first with cache fallback
  if (event.request.method === "GET") {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request))
    );
  }
});
