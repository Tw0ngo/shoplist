// Offline copy of the app shell: always the network first, the last good copy only when there is no connection.
// Lists and items never pass through here (the page keeps those itself); /api, /login and the bot check are not cached.
const CACHE = 'shoplist-1';
const SHELL = ['/', '/style.css', '/fonts.css', '/i18n.js', '/pwrules.js', '/favicon-32.png',
  '/fonts/dotgothic16-latin.woff2', '/fonts/dotgothic16-latin-ext.woff2',
  '/fonts/shippori-mincho-b1-latin.woff2', '/fonts/shippori-mincho-b1-latin-ext.woff2'];

// the app page is marked by the server; anything else that comes back as HTML is a redirect or the bot check
const good = (path, r) => r.ok && !r.redirected &&
  (path === '/' ? r.headers.get('x-shoplist-app') === '1' : !(r.headers.get('content-type') || '').startsWith('text/html'));

async function keep(path, r) {
  if (good(path, r)) await (await caches.open(CACHE)).put(path, r.clone());
  return r;
}

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(Promise.all(SHELL.map(p => fetch(p).then(r => keep(p, r)).catch(() => {}))));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  const path = url.pathname === '/index.html' ? '/' : url.pathname;
  if (!SHELL.includes(path)) return;
  e.respondWith(fetch(e.request).then(r => keep(path, r)).catch(async () => (await caches.match(path)) || Response.error()));
});
