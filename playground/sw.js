/**
 * Aegis Playground Service Worker — caches static assets for fast repeat loads.
 * Pyodide + WASM are cached on first use for near-instant subsequent visits.
 */
const CACHE_NAME = "aegis-playground-v16";
const STATIC_ASSETS = [
  "./",
  "./index.html",
  "./css/style.css",
  "./js/i18n.js",
  "./js/presets.js",
  "./js/app.js",
  "./js/demos.js",
  "./js/guardrails.js",
  "./js/streaming-demo.js",
  "./js/sw-register.js",
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

// Cache the open-cache promise to avoid reopening on every fetch
let _cachePromise = null;
function _getCache() {
  return _cachePromise || (_cachePromise = caches.open(CACHE_NAME));
}

self.addEventListener("fetch", (event) => {
  const url = event.request.url;

  // CDN assets: cache-first (immutable versioned URLs)
  if (CDN_PATTERNS.some((p) => url.includes(p))) {
    event.respondWith(
      caches.match(event.request).then(
        (cached) => cached || fetch(event.request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            _getCache().then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
      )
    );
    return;
  }

  // Local assets: network-first with cache fallback (same-origin only)
  if (event.request.method === "GET" && new URL(url).origin === self.location.origin) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.ok) {
            const clone = response.clone();
            _getCache().then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request))
    );
  }
});
