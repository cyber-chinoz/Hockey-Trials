const C='ht-v36',F=['./','index.html','manifest.webmanifest','vendor.js','icon-180.png','icon-512.png','icon-192.png','favicon.ico','favicon-16.png','favicon-32.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(F)));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))));self.clients.claim()});
self.addEventListener('fetch',e=>{
  const r=e.request;
  if(r.method!=='GET'||new URL(r.url).origin!==location.origin)return; // Supabase calls go straight to the network
  // Pages: network first so updates show up immediately, cache when offline
  if(r.mode==='navigate'){
    e.respondWith(fetch(r).then(n=>{if(n.ok){const c=n.clone();caches.open(C).then(x=>x.put(r,c))}return n}).catch(()=>caches.match(r).then(h=>h||caches.match('index.html')||caches.match('./'))));
    return;
  }
  // Assets: cache first, refreshed in the background
  e.respondWith(caches.match(r).then(h=>{const n=fetch(r).then(n=>{if(n.ok){const c=n.clone();caches.open(C).then(x=>x.put(r,c))}return n}).catch(()=>h);return h||n}));
});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>l.length?l[0].focus():clients.openWindow('./')))});
