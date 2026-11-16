"use strict";
/* ───────── helpers ───────── */
const $ = s => document.querySelector(s);
function h(tag, attrs, ...kids){
  const el = document.createElement(tag);
  for (const k in attrs || {}){
    const v = attrs[k];
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'disabled' || k === 'checked' || k === 'value' || k === 'hidden') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(9)){ if (c == null || c === false) continue; el.append(c.nodeType ? c : document.createTextNode(String(c))); }
  return el;
}
const rid = n => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => 'abcdefghjkmnpqrstuvwxyz23456789'[b % 31]).join('');
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const ease = x => x < .5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2;
const plural = (n, w) => n + ' ' + w + (n === 1 ? '' : 's');
const fmtDay = ms => new Date(ms).toLocaleDateString(undefined, {day: 'numeric', month: 'short'});
function fmtRange(a, b){ if (!a) return ''; const x = fmtDay(a), y = fmtDay(b); return (x === y ? x : x + ' – ' + y) + ' ' + new Date(b).getFullYear(); }
let toastTimer;
function toast(msg){ document.querySelector('.toast')?.remove(); const t = h('div', {class: 'toast', role: 'status'}, msg); document.body.append(t); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.remove(), 4200); }
const loadImg = src => new Promise((res, rej) => { const im = new Image(); im.onload = () => res(im); im.onerror = () => rej(new Error('image')); im.src = src; });
const toBlob = (cv, q) => new Promise(res => cv.toBlob(res, 'image/jpeg', q));
const slug = s => (s || 'trip').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'trip';
const RING = '<svg class="ring" viewBox="0 0 100 70" preserveAspectRatio="none" aria-hidden="true"><path d="M52 5C24 3 5 17 5 36s22 31 48 30 43-13 42-33C94 14 72 4 44 7"/></svg>';

/* ───────── state ───────── */
const CFG = window.GF_CONFIG || {};
const LS = {
  get(k, d){ try { const v = localStorage.getItem('gf.' + k); return v == null ? d : JSON.parse(v); } catch (e){ return d; } },
  set(k, v){ try { localStorage.setItem('gf.' + k, JSON.stringify(v)); } catch (e){} }
};
const myId = LS.get('uid') || 'u' + rid(12); LS.set('uid', myId);
const S = {
  cloud: !!(CFG.supabaseUrl && CFG.supabaseAnonKey), me: {id: myId, name: LS.get('name', '')}, canWrite: true, canUpload: true, isOwner: false,
  trips: LS.get('trips', []), tripId: null, trip: null, photos: [], people: {}, members: {}, tripLoaded: false, slow: false, creating: false,
  tab: 'photos', filter: {people: [], only: false, by: null}, selecting: false, sel: new Set(), work: ''
};

/* ───────── encryption: everything is sealed in the browser before it leaves ─────────
   The invite link carries a 256-bit secret after the #, which browsers never send to a server.
   From it we derive (HKDF-SHA-256) an AES-256-GCM key for content and a separate access token
   for the server. Each item is bound to its album and id, so stored data cannot be swapped around. */
const te = new TextEncoder(), td = new TextDecoder();
const b64u = {
  enc(u8){ let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  dec(str){ const s = atob(str.replace(/-/g, '+').replace(/_/g, '/')), u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
};
const randId = n => b64u.enc(crypto.getRandomValues(new Uint8Array(n)));
async function deriveKeys(secret, albumId){
  const base = await crypto.subtle.importKey('raw', b64u.dec(secret), 'HKDF', false, ['deriveKey', 'deriveBits']);
  const salt = te.encode('groupflicks-v1:' + albumId);
  const key = await crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt, info: te.encode('content')}, base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
  const bits = await crypto.subtle.deriveBits({name: 'HKDF', hash: 'SHA-256', salt, info: te.encode('access')}, base, 256);
  return {key, token: b64u.enc(new Uint8Array(bits))};
}
async function seal(key, bytes, aad){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: te.encode(aad)}, key, bytes));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
}
async function unseal(key, bytes, aad){
  return new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: te.encode(aad)}, key, bytes.subarray(12)));
}

/* ───────── backends: Supabase over HTTPS, or memory for the demo ───────── */
class Remote {
  constructor(url, key){ this.url = url.replace(/\/+$/, ''); this.h = {apikey: key, Authorization: 'Bearer ' + key}; }
  async rpc(fn, args){
    const r = await fetch(`${this.url}/rest/v1/rpc/${fn}`, {method: 'POST', headers: {...this.h, 'Content-Type': 'application/json'}, body: JSON.stringify(args)});
    if (!r.ok){
      // the database reports a wrong or unknown link as code P0002, which arrives as a server error
      let code = ''; try { code = (await r.json()).code || ''; } catch (e){}
      throw Object.assign(new Error('rpc ' + r.status), {status: code === 'P0002' ? 404 : r.status});
    }
    const t = await r.text(); return t ? JSON.parse(t) : null;
  }
  createAlbum(a, t){ return this.rpc('gf_create_album', {p_album: a, p_token: t}); }
  put(a, t, id, kind, data){ return this.rpc('gf_put', {p_album: a, p_token: t, p_id: id, p_kind: kind, p_data: data}); }
  del(a, t, id){ return this.rpc('gf_delete', {p_album: a, p_token: t, p_id: id}); }
  list(a, t, since){ return this.rpc('gf_list', {p_album: a, p_token: t, p_since: since}); }
  async upload(a, bid, bytes){
    const r = await fetch(`${this.url}/storage/v1/object/gf-photos/${a}/${bid}`, {method: 'POST', headers: {...this.h, 'Content-Type': 'application/octet-stream', 'x-upsert': 'false'}, body: bytes});
    if (!r.ok) throw Object.assign(new Error('upload ' + r.status), {status: r.status});
  }
  async download(a, bid){ const r = await fetch(`${this.url}/storage/v1/object/public/gf-photos/${a}/${bid}`); if (!r.ok) throw new Error('download ' + r.status); return r.arrayBuffer(); }
  async remove(a, bid){ try { return (await fetch(`${this.url}/storage/v1/object/gf-photos/${a}/${bid}`, {method: 'DELETE', headers: this.h})).ok; } catch (e){ return false; } }
  deleteAlbum(a, t){ return this.rpc('gf_delete_album', {p_album: a, p_token: t}); }
}
class Memory {
  constructor(){ this.albums = new Map(); this.blobs = new Map(); this.n = 0; }
  need(a, t){ const al = this.albums.get(a); if (!al || al.token !== t) throw Object.assign(new Error('not found'), {status: 404}); return al; }
  async createAlbum(a, t){ this.albums.set(a, {token: t, docs: new Map()}); }
  async put(a, t, id, kind, data){ this.need(a, t).docs.set(id, {id, kind, data, deleted: false, seq: ++this.n}); return this.n; }
  async del(a, t, id){ const d = this.need(a, t).docs.get(id); if (d){ d.deleted = true; d.data = ''; d.seq = ++this.n; } }
  async list(a, t, since){ return [...this.need(a, t).docs.values()].filter(d => d.seq > since).sort((x, y) => x.seq - y.seq); }
  async upload(a, bid, bytes){ this.blobs.set(a + '/' + bid, bytes); }
  async download(a, bid){ const b = this.blobs.get(a + '/' + bid); if (!b) throw new Error('missing'); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); }
  async remove(a, bid){ return this.blobs.delete(a + '/' + bid); }
  async deleteAlbum(a, t){ this.need(a, t); this.albums.delete(a); }
}
const BE = S.cloud ? new Remote(CFG.supabaseUrl, CFG.supabaseAnonKey) : new Memory();

/* ───────── the open album ───────── */
const A = {id: null, secret: null, key: null, token: null, seq: 0, docs: new Map(), blobs: new Map(), urls: new Map(), timer: 0, polls: 0};
const aad = id => A.id + '/' + id;
function syncState(){
  const photos = [], people = {}, members = {};
  for (const [id, d] of A.docs){
    if (d.kind === 'photo') photos.push({id, ...d.v}); else if (d.kind === 'person') people[id] = d.v; else if (d.kind === 'member') members[id.slice(2)] = d.v;
  }
  const had = !!S.trip;
  S.trip = A.docs.get('album')?.v || null; S.photos = photos; S.people = people; S.members = members;
  if (had && !S.trip && !S.creating){ S.gone = true; clearInterval(A.timer); forget(A.id); }
  S.isOwner = !!S.trip && S.trip.by === S.me.id;
  if (S.trip) remember();
  changed();
}
function forget(id){ S.trips = S.trips.filter(t => t.id !== id); LS.set('trips', S.trips); }
function albumGone(){ if (!A.id) return; clearInterval(A.timer); const had = !!S.trip; A.docs = new Map(); forget(A.id); syncState(); if (had) S.gone = true; changed(); }
function remember(){
  const cur = S.trips.find(t => t.id === A.id);
  if (cur && cur.name === S.trip.name && cur.place === S.trip.place) return;
  S.trips = [{id: A.id, secret: A.secret, name: S.trip.name, place: S.trip.place || '', at: Date.now()}, ...S.trips.filter(t => t.id !== A.id)].slice(0, 50);
  LS.set('trips', S.trips);
}
async function pull(full){
  const id = A.id, rows = await BE.list(id, A.token, full ? 0 : A.seq);
  if (A.id !== id || !rows) return;
  let dirty = false;
  for (const r of rows){
    A.seq = Math.max(A.seq, r.seq);
    const have = A.docs.get(r.id);
    if (r.deleted){ if (have && !(have.seq > r.seq)){ A.docs.delete(r.id); dirty = true; } continue; }
    if (have && have.seq >= r.seq) continue;
    try { A.docs.set(r.id, {kind: r.kind, seq: r.seq, v: JSON.parse(td.decode(await unseal(A.key, b64u.dec(r.data), aad(r.id))))}); dirty = true; }
    catch (e){ /* not sealed with this album's key: ignore it */ }
  }
  if (dirty){ syncState(); Face.backfill(); }
}
async function putDoc(id, kind, v){
  const prev = A.docs.get(id);
  A.docs.set(id, {kind, v, seq: prev?.seq || 0}); syncState();
  const data = b64u.enc(await seal(A.key, te.encode(JSON.stringify(v)), aad(id)));
  await BE.put(A.id, A.token, id, kind, data);
}
function closeTrip(){
  clearInterval(A.timer); for (const u of A.urls.values()) URL.revokeObjectURL(u);
  Object.assign(A, {id: null, secret: null, key: null, token: null, seq: 0, docs: new Map(), blobs: new Map(), urls: new Map(), polls: 0});
  Object.assign(S, {tripId: null, trip: null, photos: [], people: {}, members: {}, tripLoaded: false, slow: false, gone: false});
}
async function openTrip(id, secret){
  closeTrip();
  Object.assign(S, {tripId: id, tab: 'photos', filter: {people: [], only: false, by: null}, selecting: false, sel: new Set()});
  A.id = id; A.secret = secret; changed();
  try {
    const k = await deriveKeys(secret, id); if (A.id !== id) return;
    A.key = k.key; A.token = k.token; await pull(true);
  } catch (e){
    if (A.id !== id) return;
    S.tripLoaded = true; S.slow = !(e.status >= 400 && e.status < 500); if (e.status === 404) forget(id); changed(); return;
  }
  if (A.id !== id) return;
  S.tripLoaded = true; if (!S.trip && !S.creating) forget(id); changed(); joinTrip();
  A.timer = setInterval(() => { if (!document.hidden && A.key) pull(++A.polls % 12 === 0).catch(e => { if (e.status === 404) albumGone(); }); }, 5000);
}
async function deleteAlbum(onStep){
  const id = A.id, token = A.token, docs = [...A.docs.keys()], files = S.photos.flatMap(p => [p.full, p.thumb]).filter(Boolean);
  clearInterval(A.timer);
  let left = 0;
  for (let i = 0; i < files.length; i += 6){ onStep(`Deleting file ${Math.min(i + 6, files.length)} of ${files.length}…`); left += (await Promise.all(files.slice(i, i + 6).map(f => BE.remove(id, f)))).filter(ok => !ok).length; }
  if (left) console.warn(`Groupflicks: ${left} encrypted files could not be erased from storage.`);
  onStep('Removing the album…');
  try { await BE.deleteAlbum(id, token); }
  catch (e){ // a database set up before album deletion existed: blank every record instead
    for (const d of docs) if (d !== 'album') await BE.del(id, token, d);
    await BE.del(id, token, 'album');
  }
  forget(id);
}
async function createTrip(name, place, extra){
  const id = randId(16), secret = randId(32), k = await deriveKeys(secret, id);
  await BE.createAlbum(id, k.token);
  S.creating = true;
  try { await openTrip(id, secret); await putDoc('album', 'album', {name, place: place || '', createdAt: Date.now(), by: S.me.id, ...extra}); }
  finally { S.creating = false; }
  location.hash = 'a=' + id + '.' + secret; joinTrip();
}
function joinTrip(){
  if (!S.trip || S.members[S.me.id]) return;
  if (!S.me.name){ nameDialog(); return; }
  store.putMember(S.tripId, {name: S.me.name, joinedAt: Date.now()}).catch(() => {});
}
function setName(name){ S.me.name = name.trim().slice(0, 40); LS.set('name', S.me.name); }
const nameOf = uid => uid === S.me.id ? 'You' : (S.members[uid]?.name || 'A friend');
const store = {
  url: id => A.urls.get(id) || '',
  blob(id){
    let p = A.blobs.get(id);
    if (!p){
      const key = A.key, album = A.id, ad = aad(id);
      p = (async () => new Blob([await unseal(key, new Uint8Array(await BE.download(album, id)), ad)], {type: 'image/jpeg'}))();
      A.blobs.set(id, p); p.catch(() => A.blobs.delete(id));
    }
    return p;
  },
  async urlOf(id){ const urls = A.urls; if (!urls.has(id)){ const b = await this.blob(id); if (!urls.has(id)) urls.set(id, URL.createObjectURL(b)); } return urls.get(id); },
  async upload(blob){
    const id = randId(16);
    await BE.upload(A.id, id, await seal(A.key, new Uint8Array(await blob.arrayBuffer()), aad(id)));
    A.blobs.set(id, Promise.resolve(blob)); A.urls.set(id, URL.createObjectURL(blob)); return id;
  },
  putPhoto: (_, pid, data) => putDoc(pid, 'photo', data),
  patchPhoto: (_, pid, patch) => putDoc(pid, 'photo', {...A.docs.get(pid)?.v, ...patch}),
  async delPhoto(_, p){
    A.docs.delete(p.id); syncState(); await BE.del(A.id, A.token, p.id);
    const ok = await Promise.all([BE.remove(A.id, p.full), BE.remove(A.id, p.thumb)]);
    if (ok.includes(false)) console.warn('Groupflicks: a deleted photo is gone from the album, but its encrypted file could not be erased from storage.');
  },
  putPerson: (_, pid, patch) => putDoc(pid, 'person', {...(S.people[pid] || {}), ...patch}),
  putMember: (_, patch) => putDoc('m_' + S.me.id, 'member', {...(S.members[S.me.id] || {}), ...patch})
};
/* show a decrypted image as soon as it is available */
function lazy(el, id, bg){
  const set = u => { if (bg) el.style.backgroundImage = `url("${u}")`; else el.src = u; };
  const u = store.url(id); if (u) set(u); else store.urlOf(id).then(set).catch(() => {});
}
const loadScript = src => new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.append(s); });

const lazyImg = (id, alt) => { const im = h('img', {alt: alt || ''}); lazy(im, id); return im; };

/* ───────── people model ───────── */
function root(pid){ let n = 0; while (S.people[pid]?.mergedInto && n++ < 20) pid = S.people[pid].mergedInto; return pid; }
function photoPeople(p){ const s = new Set(); for (const f of p.faces || []) if (f.p) s.add(root(f.p)); for (const t of p.tags || []) s.add(root(t)); return s; }
function peopleList(){
  const m = new Map();
  const get = id => m.get(id) || m.set(id, {id, name: S.people[id]?.name || '', count: 0, cover: null, area: 0}).get(id);
  for (const id in S.people) if (!S.people[id].mergedInto) get(id);
  for (const p of S.photos){
    for (const id of photoPeople(p)) get(id).count++;
    for (const f of p.faces || []){ if (!f.p) continue; const e = get(root(f.p)); const a = f.b[2] * f.b[3]; if (a > e.area){ e.area = a; e.cover = {thumb: p.thumb, b: f.b, r: p.h / p.w}; } }
  }
  return [...m.values()].sort((a, b) => (!!b.name - !!a.name) || b.count - a.count);
}
const myPerson = () => { const id = S.members[S.me.id]?.me; return id ? root(id) : null; };
const personLabel = e => e.name || 'Unnamed';
function avatar(e, cls){
  const el = h('span', {class: 'av ' + (cls || '')});
  if (e?.cover){
    const {b, r} = e.cover, s = Math.max(b[2], b[3] * r) * 1.7, cx = b[0] + b[2] / 2, cy = (b[1] + b[3] / 2) * r;
    const px = Math.abs(1 - s) < .02 ? 50 : clamp((cx - s / 2) / (1 - s) * 100, 0, 100), py = Math.abs(r - s) < .02 ? 50 : clamp((cy - s / 2) / (r - s) * 100, 0, 100);
    lazy(el, e.cover.thumb, true); el.style.backgroundSize = (100 / s) + '% auto'; el.style.backgroundPosition = px + '% ' + py + '%';
  } else el.textContent = (e?.name || '?').trim().slice(0, 2).toUpperCase();
  return el;
}
/* the people filter: a photo must contain everyone picked, and with "only" set, nobody else */
const pickedPeople = () => [...new Set(S.filter.people.map(root))];
function matchPeople(p){ const want = pickedPeople(), s = photoPeople(p); return want.every(id => s.has(id)) && (!S.filter.only || s.size === want.length); }
function pickedLabel(){
  const me = myPerson(), all = peopleList(), names = pickedPeople().map(id => id === me ? 'you' : personLabel(all.find(e => e.id === id) || {}));
  return (names.length > 1 ? names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1] : names[0]) + (S.filter.only ? ', no one else' : '');
}
function shown(){
  let list = [...S.photos].sort((a, b) => (a.takenAt || a.at) - (b.takenAt || b.at));
  const f = S.filter;
  if (f.people.length) list = list.filter(matchPeople);
  if (f.by) list = list.filter(p => p.by === f.by);
  return list;
}

/* ───────── faces: found and compared on the device; only encrypted results are stored ───────── */
const FACE_CDN = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.13';
const Face = {
  state: 'off', queue: Promise.resolve(), busy: new Set(),
  async init(){
    try {
      this.state = 'loading'; changed();
      await loadScript(FACE_CDN + '/dist/face-api.js');
      await Promise.all([faceapi.nets.ssdMobilenetv1.loadFromUri(FACE_CDN + '/model'), faceapi.nets.faceLandmark68Net.loadFromUri(FACE_CDN + '/model'), faceapi.nets.faceRecognitionNet.loadFromUri(FACE_CDN + '/model')]);
      this.state = 'ready'; changed(); this.backfill();
    } catch (e){ this.state = 'off'; changed(); }
  },
  async detect(canvas){
    const W = canvas.width, H = canvas.height, r4 = x => Math.round(x * 1e4) / 1e4;
    const res = await faceapi.detectAllFaces(canvas, new faceapi.SsdMobilenetv1Options({minConfidence: .5, maxResults: 40})).withFaceLandmarks().withFaceDescriptors();
    return res.filter(r => Math.min(r.detection.box.width, r.detection.box.height) >= 34)
      .map(r => { const b = r.detection.box; return {b: [r4(b.x / W), r4(b.y / H), r4(b.width / W), r4(b.height / H)], d: Array.from(r.descriptor, r4)}; });
  },
  dist(a, b){ let s = 0; for (let i = 0; i < a.length; i++){ const d = a[i] - b[i]; s += d * d; } return Math.sqrt(s); },
  nearest(d){ let best = null, bd = 9; for (const p of S.photos) for (const f of p.faces || []) if (f.d && f.p){ const x = this.dist(d, f.d); if (x < bd){ bd = x; best = f; } } return {face: best, dist: bd}; },
  assign(faces){
    const fresh = [];
    for (const f of faces){
      let {face, dist} = this.nearest(f.d), pid = face && dist < .5 ? root(face.p) : null;
      if (!pid) for (const g of fresh) if (this.dist(f.d, g.d) < .5){ pid = g.p; break; }
      f.p = pid || 'p' + rid(7); fresh.push(f);
    }
    return faces;
  },
  backfill(){
    if (this.state !== 'ready' || !S.canWrite) return;
    for (const p of S.photos){
      if (p.faces || this.busy.has(p.id) || !(p.by === S.me.id || S.isOwner)) continue;
      this.busy.add(p.id); const tid = S.tripId;
      this.queue = this.queue.then(async () => {
        if (S.tripId !== tid) return;
        try {
          setWork('Looking for faces…');
          const bmp = await createImageBitmap(await store.blob(p.full)); const cv = fit(bmp, 1600);
          await store.patchPhoto(tid, p.id, {faces: this.assign(await this.detect(cv))});
        } catch (e){} finally { setWork(''); }
      });
    }
  }
};

/* ───────── adding photos ───────── */
function fit(src, max){
  const w = src.width || src.naturalWidth, hh = src.height || src.naturalHeight, k = Math.min(1, max / Math.max(w, hh));
  const cv = h('canvas', {width: Math.round(w * k), height: Math.round(hh * k)}); cv.getContext('2d').drawImage(src, 0, 0, cv.width, cv.height); return cv;
}
function sharpness(src){
  const cv = fit(src, 160), d = cv.getContext('2d').getImageData(0, 0, cv.width, cv.height), w = cv.width, hh = cv.height, g = new Float32Array(w * hh);
  for (let i = 0; i < g.length; i++) g[i] = d.data[i * 4] * .3 + d.data[i * 4 + 1] * .59 + d.data[i * 4 + 2] * .11;
  let sum = 0, sq = 0, n = 0;
  for (let y = 1; y < hh - 1; y++) for (let x = 1; x < w - 1; x++){ const i = y * w + x, l = 4 * g[i] - g[i - 1] - g[i + 1] - g[i - w] - g[i + w]; sum += l; sq += l * l; n++; }
  return Math.round(sq / n - (sum / n) ** 2);
}
async function exifDate(file){
  try {
    const v = new DataView(await file.slice(0, 262144).arrayBuffer());
    if (v.getUint16(0) !== 0xFFD8) return null;
    let o = 2;
    while (o < v.byteLength - 12){
      const m = v.getUint16(o), len = v.getUint16(o + 2);
      if (m === 0xFFE1 && v.getUint32(o + 4) === 0x45786966){
        const t = o + 10, le = v.getUint16(t) === 0x4949, u16 = x => v.getUint16(x, le), u32 = x => v.getUint32(x, le);
        const ifd = (off, want) => { const out = {}, n = u16(t + off); for (let i = 0; i < n; i++){ const e = t + off + 2 + i * 12; if (want.includes(u16(e))) out[u16(e)] = {count: u32(e + 4), at: e + 8}; } return out; };
        const str = e => { const at = e.count > 4 ? t + u32(e.at) : e.at; let r = ''; for (let i = 0; i < e.count - 1; i++) r += String.fromCharCode(v.getUint8(at + i)); return r; };
        const a = ifd(u32(t + 4), [0x8769, 0x0132]); let s = null;
        if (a[0x8769]){ const b = ifd(u32(a[0x8769].at), [0x9003]); if (b[0x9003]) s = str(b[0x9003]); }
        if (!s && a[0x0132]) s = str(a[0x0132]);
        const k = s && s.match(/(\d{4}):(\d\d):(\d\d) (\d\d):(\d\d):(\d\d)/);
        return k ? new Date(+k[1], k[2] - 1, +k[3], +k[4], +k[5], +k[6]).getTime() : null;
      }
      if ((m & 0xFF00) !== 0xFF00) break;
      o += 2 + len;
    }
  } catch (e){}
  return null;
}
async function addImage(source, takenAt){
  const full = fit(source, 2048), thumb = fit(source, 480);
  const [fb, tb] = await Promise.all([toBlob(full, .88), toBlob(thumb, .8)]);
  const data = {full: await store.upload(fb), thumb: await store.upload(tb), w: full.width, h: full.height, takenAt, at: Date.now(), by: S.me.id, sharp: sharpness(thumb)};
  if (Face.state === 'ready'){ try { data.faces = Face.assign(await Face.detect(fit(full, 1600))); } catch (e){} }
  const id = rid(9); Face.busy.add(id);
  await store.putPhoto(S.tripId, id, data);
}
async function addFiles(files){
  files = [...files].filter(f => f.type.startsWith('image/') || /\.(jpe?g|png|webp|heic)$/i.test(f.name));
  if (!files.length) return;
  let ok = 0; const failed = [];
  for (let i = 0; i < files.length; i++){
    setWork(`Adding ${i + 1} of ${files.length}…`);
    try {
      const f = files[i];
      let src; try { src = await createImageBitmap(f, {imageOrientation: 'from-image'}); } catch (e){ const u = URL.createObjectURL(f); src = await loadImg(u); }
      await addImage(src, (await exifDate(f)) || f.lastModified || Date.now()); ok++;
    } catch (e){
      failed.push(files[i].name);
      if (e?.code === 'quota_or_state' || e?.code === 'quota_exceeded'){ toast('This album is out of storage. Remove some photos to add more.'); break; }
    }
  }
  setWork('');
  toast(failed.length ? `Added ${ok}. Couldn't read ${failed.length} (${failed.slice(0, 2).join(', ')}${failed.length > 2 ? '…' : ''}). Try JPEG or PNG.` : `Added ${plural(ok, 'photo')}.`);
}
function setWork(msg){ S.work = msg; const el = $('#work'); if (el) el.textContent = msg; }

/* sample trip: drawn scenery, clearly labelled, so the album and reel can be tried without real photos */
function drawScene(i){
  const tall = i % 4 === 1, W = tall ? 1200 : 1600, H = tall ? 1600 : 1067, cv = h('canvas', {width: W, height: H}), c = cv.getContext('2d');
  const pal = [['#ffb347', '#ff5e62', '#2b1055'], ['#89f7fe', '#66a6ff', '#0f2a4a'], ['#fddb92', '#d1fdff', '#1b4b5a'], ['#f6d365', '#fda085', '#40223a'], ['#a1c4fd', '#c2e9fb', '#24405c'], ['#ff9a9e', '#fecfef', '#4a2545']][i % 6];
  const sky = c.createLinearGradient(0, 0, 0, H); sky.addColorStop(0, pal[1]); sky.addColorStop(.62, pal[0]); c.fillStyle = sky; c.fillRect(0, 0, W, H);
  const sx = W * (.2 + .6 * ((i * 37) % 10) / 10), sy = H * (.3 + .1 * (i % 3)); const sun = c.createRadialGradient(sx, sy, 0, sx, sy, H * .3); sun.addColorStop(0, 'rgba(255,255,240,.95)'); sun.addColorStop(.18, 'rgba(255,250,220,.6)'); sun.addColorStop(1, 'rgba(255,255,255,0)'); c.fillStyle = sun; c.fillRect(0, 0, W, H);
  for (let l = 0; l < 4; l++){
    c.fillStyle = pal[2]; c.globalAlpha = .35 + l * .2; c.beginPath(); c.moveTo(0, H);
    for (let x = 0; x <= W; x += 20) c.lineTo(x, H * (.58 + l * .09) + Math.sin(x / (130 + l * 60) + i * 1.7 + l) * H * (.07 - l * .012) + Math.sin(x / 47 + i + l * 3) * 9);
    c.lineTo(W, H); c.fill();
  }
  c.globalAlpha = 1; c.fillStyle = 'rgba(255,255,255,.75)'; c.font = '600 ' + Math.round(W / 46) + 'px sans-serif'; c.fillText('SAMPLE ' + String(i + 1).padStart(2, '0'), W * .04, H * .07);
  return cv;
}
async function makeSample(){
  setWork('Drawing sample photos…');
  await createTrip('Sample: Lisbon weekend', 'Lisbon', {sample: true});
  const day0 = new Date(2026, 5, 12, 9, 30).getTime();
  for (let i = 0; i < 12; i++){ setWork(`Drawing sample ${i + 1} of 12…`); await addImage(drawScene(i), day0 + Math.floor(i / 4) * 864e5 + (i % 4) * 7.5e6); }
  setWork('');
}

/* ───────── saving files ───────── */
async function saveFile(filename, blob){
  const url = URL.createObjectURL(blob), a = h('a', {href: url, download: filename});
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 60000);
  toast('Saved ' + filename); return true;
}
async function downloadPhotos(list){
  if (!list.length) return;
  const base = slug(S.trip?.name);
  try {
    if (list.length === 1){ setWork('Preparing photo…'); await saveFile(`${base}-${list[0].id}.jpg`, await store.blob(list[0].full)); return; }
    if (!window.JSZip){ toast("The zip tool didn't load. Check your connection and reload."); return; }
    const zip = new JSZip();
    for (let i = 0; i < list.length; i++){ setWork(`Packing ${i + 1} of ${list.length}…`); zip.file(`${base}-${String(i + 1).padStart(3, '0')}.jpg`, await store.blob(list[i].full)); }
    setWork('Zipping…');
    await saveFile(`${base}-${list.length}-photos.zip`, await zip.generateAsync({type: 'blob', compression: 'STORE'}));
  } catch (e){ toast("Some photos couldn't be fetched. Try again."); }
  finally { setWork(''); }
}

/* ───────── rendering ───────── */
let renderQueued = false;
function changed(){ if (renderQueued) return; renderQueued = true; requestAnimationFrame(() => { renderQueued = false; render(); }); }
function render(){
  $('#who').textContent = S.cloud ? 'End-to-end encrypted' : 'Demo · this tab only';
  const main = $('#main');
  if (S.tripId && S.tab === 'reel' && main.dataset.view === 'reel:' + S.tripId){ renderDock(); return; } // keep the canvas alive
  main.replaceChildren(S.tripId ? viewTrip() : viewHome());
  main.dataset.view = S.tripId ? S.tab + ':' + S.tripId : 'home';
  renderDock();
}
function parseLink(text){ const m = (text || '').match(/a=([A-Za-z0-9_-]{16,40})\.([A-Za-z0-9_-]{40,50})/); return m ? {id: m[1], secret: m[2]} : null; }
function viewHome(){
  const colors = ['#c98b5a', '#6b93b8', '#d9a441', '#7fa58a', '#b86a6a', '#8d86b5'];
  const strip = h('div', {class: 'strip', 'aria-hidden': 'true'}, colors.map((c, i) => h('span', {class: i === 4 ? 'pick' : '', style: {background: `linear-gradient(160deg, ${c}, #1a1c1f 140%)`}}, h('b', null, (i + 11) + 'A'))));
  const create = h('form', {class: 'panel', onsubmit: async e => {
    e.preventDefault(); const name = $('#trip-name').value.trim(); if (!name) return;
    if ($('#your-name')) setName($('#your-name').value);
    const btn = e.target.querySelector('button[type=submit]'); btn.disabled = true;
    try { await createTrip(name, $('#trip-place').value.trim()); }
    catch (err){ btn.disabled = false; toast("Couldn't create the trip. Check your connection and try again."); }
  }},
    h('h2', {class: 'sect'}, 'Start a trip'),
    h('div', {class: 'row'},
      h('div', {class: 'field'}, h('label', {for: 'trip-name'}, 'Trip name'), h('input', {id: 'trip-name', placeholder: 'Lisbon with the flatmates', maxlength: 60, required: true})),
      h('div', {class: 'field'}, h('label', {for: 'trip-place'}, 'Place (optional)'), h('input', {id: 'trip-place', placeholder: 'Lisbon, Portugal', maxlength: 60})),
      !S.me.name && h('div', {class: 'field'}, h('label', {for: 'your-name'}, 'Your name'), h('input', {id: 'your-name', placeholder: 'What friends call you', maxlength: 40, required: true, autocomplete: 'given-name'})),
      h('button', {class: 'btn primary', type: 'submit'}, 'Create album')));
  const join = h('form', {class: 'panel', onsubmit: e => { e.preventDefault(); const l = parseLink($('#join-link').value); if (l) location.hash = 'a=' + l.id + '.' + l.secret; else toast("That doesn't look like a Groupflicks link. Paste the whole link."); }},
    h('h2', {class: 'sect'}, 'Got an invite link?'),
    h('div', {class: 'row'}, h('div', {class: 'field'}, h('label', {for: 'join-link'}, 'Paste the link'), h('input', {id: 'join-link', placeholder: 'https://…#a=…', autocomplete: 'off'})), h('button', {class: 'btn', type: 'submit'}, 'Open')));
  const trips = [...S.trips].sort((a, b) => (b.at || 0) - (a.at || 0));
  const list = h('div', null, h('h2', {class: 'sect'}, 'Your trips on this device'),
    trips.length ? h('ul', {class: 'trips'}, trips.map(t => h('li', null, h('button', {class: 'trip', type: 'button', onclick: () => { location.hash = 'a=' + t.id + '.' + t.secret; }},
      h('span', {class: 'tn'}), h('span', null, h('strong', null, t.name), h('small', null, t.place || 'Open album'))))))
    : h('div', {class: 'panel'}, h('p', {style: {margin: '0 0 12px', color: 'var(--muted)'}}, 'No trips yet. Create one, or try the sample to see how the album and reel work.'),
        h('button', {class: 'btn small', type: 'button', onclick: makeSample}, 'Try a sample trip'), ' ', h('span', {class: 'busy', id: 'work'}, S.work)));
  return h('div', null,
    h('section', {class: 'hero'}, h('div', null, h('h1', null, "Everyone's photos. ", h('em', null, "Just the ones you're in.")),
      h('p', null, 'One album per trip. Friends add their shots, Groupflicks sorts them by who is in the frame, and cuts a highlight reel you can post. Photos are encrypted on your device before they are uploaded.')), strip),
    !S.cloud && h('p', {class: 'note', style: {marginBottom: '16px'}}, 'Demo mode: no server is set up yet, so albums stay in this tab and invite links will not work for friends. Add your Supabase project URL and key to config.js to turn sharing on.'),
    h('div', {class: 'cols'}, h('div', {style: {display: 'grid', gap: '16px'}}, create, join), list));
}
function viewTrip(){
  if (!S.trip) return h('div', {class: 'panel'}, h('h2', {class: 'sect'}, S.gone ? 'This album was deleted' : (S.tripLoaded && !S.creating) ? "This trip isn't here" : 'Opening trip…'),
    h('p', {style: {color: 'var(--muted)'}}, S.gone ? 'Its photos have been removed for everyone.' : !(S.tripLoaded && !S.creating) ? '' : S.slow ? "The album can't be reached yet. Check your connection." : 'Check that you pasted the whole invite link, including everything after the #.'),
    h('button', {class: 'btn', type: 'button', onclick: goHome}, 'All trips'));
  const ts = S.photos.map(p => p.takenAt || p.at), ppl = new Set([...Object.keys(S.members), ...S.photos.map(p => p.by)]);
  const meta = [S.trip.place, ts.length ? fmtRange(Math.min(...ts), Math.max(...ts)) : '', plural(S.photos.length, 'photo'), plural(Math.max(1, ppl.size), 'contributor')].filter(Boolean).join(' · ');
  const tab = (id, label) => h('button', {type: 'button', role: 'tab', 'aria-selected': String(S.tab === id), onclick: () => { Reel.stop(); S.tab = id; S.selecting = false; S.sel.clear(); render(); }}, label);
  return h('div', null,
    h('div', {class: 'thead'},
      h('div', null, h('button', {class: 'btn small quiet', type: 'button', onclick: goHome, style: {marginBottom: '12px'}}, '← All trips'), h('h1', null, S.trip.name), h('div', {class: 'meta'}, meta)),
      h('div', {class: 'row'}, h('span', {class: 'busy', id: 'work'}, S.work),
        h('button', {class: 'btn quiet', type: 'button', onclick: albumDialog}, 'Album options'),
        h('button', {class: 'btn', type: 'button', onclick: inviteDialog}, 'Invite friends'),
        S.canWrite && S.canUpload && h('button', {class: 'btn primary', type: 'button', onclick: () => $('#file-photos').click()}, 'Add photos'))),
    h('div', {class: 'tabs', role: 'tablist'}, tab('photos', 'Photos'), tab('people', 'People'), tab('reel', 'Highlight reel')),
    S.tab === 'photos' ? viewPhotos() : S.tab === 'people' ? viewPeople() : viewReel());
}
function chipsRow(){
  const ppl = peopleList().filter(e => e.count), me = myPerson(), f = S.filter, on = pickedPeople();
  const set = id => { f.people = on.includes(id) ? on.filter(x => x !== id) : [...on, id]; if (!f.people.length) f.only = false; S.sel.clear(); render(); };
  return h('div', {class: 'chips'},
    h('button', {class: 'chip plain', type: 'button', 'aria-pressed': String(!on.length), onclick: () => { f.people = []; f.only = false; S.sel.clear(); render(); }}, 'Everyone'),
    me ? h('button', {class: 'chip', type: 'button', 'aria-pressed': String(on.includes(me)), onclick: () => set(me)}, avatar(ppl.find(e => e.id === me) || {name: 'Me'}), 'Me')
       : h('button', {class: 'chip plain', type: 'button', onclick: findMeDialog}, 'Find me'),
    ppl.filter(e => e.id !== me).map(e => h('button', {class: 'chip', type: 'button', 'aria-pressed': String(on.includes(e.id)), onclick: () => set(e.id)}, avatar(e), personLabel(e), h('span', {style: {color: 'var(--muted)'}}, e.count))),
    on.length > 0 && h('button', {class: 'chip plain only', type: 'button', 'aria-pressed': String(f.only), title: 'Hide photos that have anyone else in them', onclick: () => { f.only = !f.only; S.sel.clear(); render(); }}, on.length > 1 ? 'Just them' : on[0] === me ? 'Just me' : 'Just this person'));
}
function viewPhotos(){
  const list = shown(), all = [...S.photos].sort((a, b) => (a.takenAt || a.at) - (b.takenAt || b.at));
  const uploaders = [...new Set(S.photos.map(p => p.by))];
  const frames = list.map(p => {
    const n = all.indexOf(p) + 1;
    return h('button', {class: 'frame', type: 'button', 'aria-pressed': String(S.sel.has(p.id)), 'aria-label': 'Photo ' + n,
      onclick: e => { if (S.selecting){ S.sel.has(p.id) ? S.sel.delete(p.id) : S.sel.add(p.id); e.currentTarget.setAttribute('aria-pressed', String(S.sel.has(p.id))); renderDock(); } else photoDialog(p); }},
      lazyImg(p.thumb),
      h('span', {class: 'edge'}, h('span', null, '▸ ' + String(n).padStart(2, '0') + 'A'), h('span', null, nameOf(p.by).toUpperCase().slice(0, 12))));
  });
  frames.forEach(fr => fr.insertAdjacentHTML('beforeend', RING));
  const who = S.filter.people.length ? pickedLabel() : null;
  return h('div', null, chipsRow(),
    h('div', {class: 'tools'},
      h('span', {class: 'count'}, who ? `${plural(list.length, 'photo')} with ${who}` : plural(list.length, 'photo')),
      h('div', {class: 'row'},
        uploaders.length > 1 && h('select', {id: 'by-filter', 'aria-label': 'Filter by who took it', class: 'btn small quiet', onchange: e => { S.filter.by = e.target.value || null; render(); }},
          h('option', {value: ''}, 'Shot by anyone'), uploaders.map(u => h('option', {value: u, selected: S.filter.by === u || null}, 'Shot by ' + nameOf(u)))),
        list.length > 0 && h('button', {class: 'btn small', type: 'button', onclick: () => { S.selecting = !S.selecting; S.sel.clear(); render(); }}, S.selecting ? 'Done picking' : 'Pick photos'))),
    h('div', {class: 'sheet', id: 'sheet'}, frames.length ? frames : h('div', {class: 'empty'},
      h('strong', null, S.photos.length ? 'No photos match' : 'An empty roll'),
      S.photos.length ? 'Clear the filter to see the whole trip.' : S.canWrite && S.canUpload ? 'Add your photos, then invite the people you travelled with to add theirs.' : 'No one has added photos yet.')));
}
function renderDock(){
  const dock = $('#dock');
  if (!S.tripId || S.tab !== 'photos' || !S.trip){ dock.replaceChildren(); return; }
  const list = shown(), picked = list.filter(p => S.sel.has(p.id));
  if (S.selecting){
    dock.replaceChildren(h('div', {class: 'dock'}, h('div', null,
      h('strong', null, picked.length ? plural(picked.length, 'photo') + ' circled' : 'Tap photos to circle them'),
      h('div', {class: 'row'},
        h('button', {class: 'btn small quiet', type: 'button', onclick: () => { list.forEach(p => S.sel.add(p.id)); render(); }}, 'Circle all'),
        S.canWrite && h('button', {class: 'btn small', type: 'button', disabled: !picked.length, onclick: () => tagDialog(picked)}, "Tag who's in these"),
        S.canWrite && h('button', {class: 'btn small', type: 'button', disabled: !picked.length, onclick: () => removeDialog(picked)}, 'Remove'),
        h('button', {class: 'btn small primary', type: 'button', disabled: !picked.length, onclick: () => downloadPhotos(picked)}, 'Download ' + picked.length)))));
  } else if (S.filter.people.length || S.filter.by){
    dock.replaceChildren(h('div', {class: 'dock'}, h('div', null,
      h('span', null, 'Filtered to ', h('strong', null, plural(list.length, 'photo'))),
      h('button', {class: 'btn primary', type: 'button', disabled: !list.length, onclick: () => downloadPhotos(list)}, list.length === 1 ? 'Download this photo' : `Download these ${list.length}`))));
  } else dock.replaceChildren();
}
function viewPeople(){
  const ppl = peopleList(), me = myPerson();
  const intro = Face.state === 'ready' ? 'Faces are grouped automatically as photos come in. Name a group once and the name sticks. If the same person shows up as two groups, open one and combine it with the other. If one group mixes two people, open it and use Separate faces.'
    : Face.state === 'loading' ? 'Loading face grouping…'
    : 'Automatic face grouping could not load on this device, so people are tagged by hand: open a photo, or pick several, and tag who is in them. Filters, downloads and the reel work from those tags.';
  return h('div', null,
    h('p', {class: 'note', style: {marginBottom: '14px'}}, intro),
    h('div', {class: 'row', style: {marginBottom: '14px'}},
      h('button', {class: 'btn', type: 'button', onclick: findMeDialog}, me ? 'Change which one is me' : 'Find me'),
      S.canWrite && h('button', {class: 'btn quiet', type: 'button', onclick: () => personDialog(null)}, 'Add a person')),
    ppl.length ? h('div', {class: 'people'}, ppl.map(e => h('button', {class: 'person', type: 'button', onclick: () => personDialog(e)},
      avatar(e), h('strong', {class: e.name ? '' : 'unnamed'}, e.name || 'Add a name'), h('small', null, plural(e.count, 'photo')), e.id === me && h('span', {class: 'badge'}, 'Me'))))
      : h('div', {class: 'panel'}, 'No people yet.'));
}

/* ───────── dialogs ───────── */
function openDlg(...kids){ const d = $('#dlg'); d.replaceChildren(h('div', {class: 'dlg'}, h('button', {class: 'btn small quiet x', type: 'button', 'aria-label': 'Close', onclick: () => d.close()}, 'Close'), ...kids)); if (!d.open) d.showModal(); return d; }
const closeDlg = () => $('#dlg').close();
function inviteDialog(){
  const link = location.origin + location.pathname + '#a=' + A.id + '.' + A.secret;
  openDlg(h('h2', null, 'Invite friends'),
    h('p', {style: {margin: 0}}, 'Send this link to the people who were on the trip. Anyone who has it can see the album and add photos, so share it only with them.'),
    h('div', {class: 'row'}, h('div', {class: 'field'}, h('label', {for: 'link-out'}, 'Invite link'), h('input', {id: 'link-out', readonly: true, value: link, onfocus: e => e.target.select()})),
      h('button', {class: 'btn primary', type: 'button', onclick: async () => { try { await navigator.clipboard.writeText(link); toast('Link copied'); } catch (e){ $('#link-out').select(); toast('Select the link and copy it'); } }}, 'Copy link'),
      navigator.share && h('button', {class: 'btn', type: 'button', onclick: () => navigator.share({title: S.trip.name + ' on Groupflicks', url: link}).catch(() => {})}, 'Share')),
    h('p', {class: 'note'}, 'Photos, names and tags are encrypted on your device. The key is the part of the link after the #, which is never sent to the server. Keep the link somewhere safe: without it the album cannot be opened by anyone, including you.'),
    !S.cloud && h('p', {class: 'note'}, 'Demo mode: this link only works in this tab until a server is set up.'));
}
function albumDialog(){
  const status = h('span', {class: 'busy', id: 'del-status'});
  const del = h('button', {class: 'btn primary', type: 'button', onclick: async e => {
    const b = e.currentTarget;
    if (!b.dataset.sure){ b.dataset.sure = 1; b.textContent = `Yes, delete all ${plural(S.photos.length, 'photo')} for everyone`; return; }
    b.disabled = true; Reel.stop();
    try { await deleteAlbum(m => { status.textContent = m; }); closeDlg(); goHome(); toast('Album deleted for everyone.'); }
    catch (err){ b.disabled = false; status.textContent = ''; toast("Couldn't finish deleting. Check your connection and try again."); }
  }}, 'Delete album');
  openDlg(h('h2', null, 'Album options'),
    h('div', {class: 'panel'}, h('strong', null, 'Remove from this device'),
      h('p', {style: {margin: '6px 0 12px', color: 'var(--muted)'}}, 'Takes this trip off your list here. The album stays for everyone else, and the invite link still opens it.'),
      h('button', {class: 'btn', type: 'button', onclick: () => { forget(A.id); closeDlg(); goHome(); toast('Removed from this device.'); }}, 'Remove from my list')),
    h('div', {class: 'panel'}, h('strong', null, 'Delete album'),
      h('p', {style: {margin: '6px 0 12px', color: 'var(--muted)'}}, S.isOwner
        ? 'Permanently deletes every photo, tag and name in this album from the server, for everyone. Invite links stop working. This cannot be undone, so download anything you want to keep first.'
        : 'Only the person who created this album can delete it, from the browser they created it in.'),
      S.isOwner && h('div', {class: 'row'}, del, status)));
}
function nameDialog(){
  const d = openDlg(h('h2', null, 'What should friends call you?'),
    h('form', {class: 'row', onsubmit: e => { e.preventDefault(); const n = $('#name-in').value.trim(); if (!n) return; setName(n); closeDlg(); joinTrip(); }},
      h('div', {class: 'field'}, h('label', {for: 'name-in'}, 'Your name'), h('input', {id: 'name-in', maxlength: 40, required: true, autocomplete: 'given-name'})),
      h('button', {class: 'btn primary', type: 'submit'}, 'Join album')),
    h('p', {style: {margin: 0, color: 'var(--muted)', fontSize: '14px'}}, 'It shows next to the photos you add. Only people with the link can see it.'));
  d.querySelector('.x')?.remove();
}
function peoplePicker(onPick, exclude){
  const ppl = peopleList().filter(e => e.id !== exclude);
  return h('div', {class: 'pick-list'}, ppl.map(e => h('button', {class: 'chip', type: 'button', onclick: () => onPick(e.id)}, avatar(e), personLabel(e))));
}
async function newPerson(name){ const id = 'p' + rid(7); await store.putPerson(S.tripId, id, {name, createdAt: Date.now()}); return id; }
async function tagPhotos(list, pid){
  for (const p of list){ const tags = new Set(p.tags || []); if (photoPeople(p).has(pid)) continue; tags.add(pid); await store.patchPhoto(S.tripId, p.id, {tags: [...tags]}); }
}
function tagDialog(list){
  const done = async pid => { closeDlg(); try { await tagPhotos(list, pid); toast('Tagged ' + plural(list.length, 'photo')); } catch (e){ toast("Couldn't save the tag."); } };
  openDlg(h('h2', null, list.length === 1 ? "Who's in this photo?" : `Who's in these ${list.length} photos?`),
    peoplePicker(done),
    h('form', {class: 'row', onsubmit: async e => { e.preventDefault(); const n = $('#new-person').value.trim(); if (n) done(await newPerson(n)); }},
      h('div', {class: 'field'}, h('label', {for: 'new-person'}, 'Someone new'), h('input', {id: 'new-person', placeholder: 'Name', maxlength: 40})), h('button', {class: 'btn', type: 'submit'}, 'Add and tag')));
}
const canRemove = p => p.by === S.me.id || S.isOwner;
function removeDialog(picked){
  const mine = picked.filter(canRemove), skip = picked.length - mine.length, status = h('span', {class: 'busy'});
  const go = h('button', {class: 'btn primary', type: 'button', onclick: async e => {
    e.currentTarget.disabled = true; let done = 0, failed = 0;
    for (const p of mine){ status.textContent = `Removing ${++done} of ${mine.length}…`; try { await store.delPhoto(S.tripId, p); S.sel.delete(p.id); } catch (err){ failed++; } }
    closeDlg(); if (!failed){ S.selecting = false; S.sel.clear(); } render();
    toast(failed ? `Removed ${mine.length - failed}. ${plural(failed, 'photo')} couldn't be removed; check your connection and try again.` : `Removed ${plural(mine.length, 'photo')}.`);
  }}, `Remove ${plural(mine.length, 'photo')} for everyone`);
  openDlg(h('h2', null, mine.length ? `Remove ${plural(mine.length, 'photo')}?` : "These aren't yours to remove"),
    mine.length ? h('p', {style: {margin: 0}}, 'They are deleted from the album for everyone and cannot be brought back. Anyone who already downloaded them keeps their copy.')
                : h('p', {style: {margin: 0}}, 'You can remove photos you added. The person who created the album can remove any photo.'),
    mine.length > 0 && skip > 0 && h('p', {class: 'note'}, `${plural(skip, 'circled photo')} ${skip === 1 ? 'was' : 'were'} added by someone else and will stay.`),
    mine.length > 0 && h('div', {class: 'row'}, go, h('button', {class: 'btn quiet', type: 'button', onclick: closeDlg}, 'Keep them'), status));
}
function photoDialog(p){
  const img = lazyImg(p.full, 'Photo by ' + nameOf(p.by));
  const view = h('div', {class: 'viewer'}, img, (p.faces || []).map(f => h('span', {class: 'box', style: {left: f.b[0] * 100 + '%', top: f.b[1] * 100 + '%', width: f.b[2] * 100 + '%', height: f.b[3] * 100 + '%'}})));
  const inside = h('span', {style: {position: 'relative', display: 'inline-block', lineHeight: 0}}); inside.append(...view.childNodes); view.append(inside);
  const who = [...photoPeople(p)].map(id => peopleList().find(e => e.id === id)).filter(Boolean);
  const untag = async id => { await store.patchPhoto(S.tripId, p.id, {tags: (p.tags || []).filter(t => root(t) !== id)}); closeDlg(); };
  openDlg(h('h2', null, 'Shot by ' + nameOf(p.by)), h('div', {class: 'mono', style: {color: 'var(--muted)'}}, new Date(p.takenAt || p.at).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'})),
    view,
    h('div', {class: 'pick-list'}, who.length ? who.map(e => h('span', {class: 'chip'}, avatar(e), personLabel(e),
      S.canWrite && (p.tags || []).some(t => root(t) === e.id) && h('button', {class: 'btn small quiet', type: 'button', 'aria-label': 'Remove tag ' + personLabel(e), onclick: () => untag(e.id)}, '×'))) : h('span', {style: {color: 'var(--muted)'}}, 'No one tagged yet.')),
    h('div', {class: 'row'},
      S.canWrite && h('button', {class: 'btn', type: 'button', onclick: () => tagDialog([p])}, 'Tag someone'),
      h('button', {class: 'btn primary', type: 'button', onclick: () => downloadPhotos([p])}, 'Download'),
      S.canWrite && canRemove(p) && h('button', {class: 'btn quiet', type: 'button', onclick: e => {
        if (e.currentTarget.dataset.sure){ closeDlg(); store.delPhoto(S.tripId, p).catch(() => toast("Couldn't remove it.")); }
        else { e.currentTarget.dataset.sure = 1; e.currentTarget.textContent = 'Tap again to remove for everyone'; } }}, 'Remove')));
}
/* two face groups that are really one person: point one at the other, so every photo counts once */
async function mergePeople(from, into){
  if (!into.name && from.name) await store.putPerson(S.tripId, into.id, {name: from.name});
  await store.putPerson(S.tripId, from.id, {mergedInto: into.id});
  S.filter.people = [...new Set(S.filter.people.map(id => id === from.id ? into.id : id))];
}
function mergedInto(id){ return Object.keys(S.people).filter(k => S.people[k].mergedInto && k !== id && root(k) === id); }
function groupFace(id){
  let best = null, area = 0;
  for (const p of S.photos) for (const f of p.faces || []) if (f.p === id && f.b[2] * f.b[3] > area){ area = f.b[2] * f.b[3]; best = {thumb: p.thumb, b: f.b, r: p.h / p.w}; }
  return {name: S.people[id]?.name || '', cover: best};
}
/* every detected face currently counted as this person */
function facesOf(id){ const out = []; for (const p of S.photos) (p.faces || []).forEach((f, i) => { if (f.p && root(f.p) === id) out.push({p, i, f}); }); return out; }
async function moveFaces(faces, to){
  const byPhoto = new Map(); for (const x of faces){ if (!byPhoto.has(x.p.id)) byPhoto.set(x.p.id, {p: x.p, idx: new Set()}); byPhoto.get(x.p.id).idx.add(x.i); }
  for (const {p, idx} of byPhoto.values()) await store.patchPhoto(S.tripId, p.id, {faces: p.faces.map((f, i) => idx.has(i) ? {...f, p: to} : f)});
}
function separateDialog(e){
  const faces = facesOf(e.id), picked = new Set(), others = peopleList().filter(o => o.id !== e.id);
  const count = h('strong', null, 'Tap the faces that are someone else'), actions = h('div', {style: {display: 'grid', gap: '12px'}});
  const run = async getTarget => {
    actions.querySelectorAll('button,input').forEach(b => b.disabled = true);
    try { const to = await getTarget(), n = picked.size; await moveFaces(faces.filter((_, i) => picked.has(i)), to); closeDlg(); toast(`Moved ${plural(n, 'face')}.`); }
    catch (err){ closeDlg(); toast("Couldn't move them. Check your connection and try again."); }
  };
  const refresh = () => {
    count.textContent = picked.size ? `${plural(picked.size, 'face')} picked` : 'Tap the faces that are someone else';
    actions.replaceChildren(...(picked.size ? [
      h('form', {class: 'row', onsubmit: ev => { ev.preventDefault(); const name = $('#sep-name').value.trim(); run(() => newPerson(name)); }},
        h('div', {class: 'field'}, h('label', {for: 'sep-name'}, 'They are a new person'), h('input', {id: 'sep-name', placeholder: 'Name (optional)', maxlength: 40})),
        h('button', {class: 'btn primary', type: 'submit'}, 'Move to a new person')),
      others.length > 0 && h('div', null, h('p', {style: {margin: '0 0 8px', color: 'var(--muted)', fontSize: '14px'}}, 'Or they are someone already in the album:'),
        h('div', {class: 'pick-list'}, others.map(o => h('button', {class: 'chip', type: 'button', onclick: () => run(async () => o.id)}, avatar(o), personLabel(o)))))
    ].filter(Boolean) : []));
  };
  openDlg(h('h2', null, 'Separate ' + (e.name || 'this group')),
    h('p', {style: {margin: 0, color: 'var(--muted)'}}, 'These are all the faces counted as this person. Pick the ones that belong to someone else and move them.'),
    h('div', {class: 'faces'}, faces.map((x, i) => h('button', {class: 'face', type: 'button', 'aria-pressed': 'false', 'aria-label': 'Face ' + (i + 1), onclick: ev => {
      picked.has(i) ? picked.delete(i) : picked.add(i); ev.currentTarget.setAttribute('aria-pressed', String(picked.has(i))); refresh(); }},
      avatar({cover: {thumb: x.p.thumb, b: x.f.b, r: x.p.h / x.p.w}})))),
    count, actions);
  refresh();
}
function personDialog(e){
  const isNew = !e, me = myPerson(), others = isNew ? [] : peopleList().filter(o => o.id !== e.id), parts = isNew ? [] : mergedInto(e.id);
  const save = async ev => {
    ev.preventDefault(); const name = $('#person-name').value.trim();
    try {
      if (isNew){ if (name) await newPerson(name); }
      else {
        const twin = name && peopleList().find(o => o.id !== e.id && o.name.toLowerCase() === name.toLowerCase());
        if (twin){ await mergePeople(e, twin); toast('Combined with ' + twin.name); }
        else await store.putPerson(S.tripId, e.id, {name});
      }
    } catch (err){ toast("Couldn't save. Check your connection."); }
    closeDlg();
  };
  openDlg(h('h2', null, isNew ? 'Add a person' : (e.name || 'Who is this?')),
    !isNew && h('div', {class: 'row', style: {alignItems: 'center'}}, avatar(e), h('span', {style: {color: 'var(--muted)'}}, 'In ' + plural(e.count, 'photo'))),
    h('form', {class: 'row', onsubmit: save}, h('div', {class: 'field'}, h('label', {for: 'person-name'}, 'Name'), h('input', {id: 'person-name', value: e?.name || '', maxlength: 40, placeholder: 'Maya', disabled: !S.canWrite})),
      S.canWrite && h('button', {class: 'btn primary', type: 'submit'}, 'Save')),
    !isNew && S.canWrite && others.length > 0 && h('div', {class: 'panel'}, h('strong', null, 'Same person as another group?'),
      h('p', {style: {margin: '6px 0 10px', color: 'var(--muted)', fontSize: '14px'}}, 'Tap the other group to combine them. Their photos are counted together from then on.'),
      h('div', {class: 'pick-list'}, others.map(o => h('button', {class: 'chip', type: 'button', onclick: async () => {
        try { await mergePeople(e, o); toast(`Combined into ${o.name || e.name || 'one person'}.`); } catch (err){ toast("Couldn't combine them. Check your connection."); }
        closeDlg(); }}, avatar(o), personLabel(o), h('span', {style: {color: 'var(--muted)'}}, o.count))))),
    !isNew && S.canWrite && parts.length > 0 && h('div', {class: 'panel'}, h('strong', null, 'Combined from'),
      h('p', {style: {margin: '6px 0 10px', color: 'var(--muted)', fontSize: '14px'}}, 'Split a group back out if it was combined by mistake.'),
      h('div', {class: 'pick-list'}, parts.map(id => h('span', {class: 'chip'}, avatar(groupFace(id)), groupFace(id).name || 'Group',
        h('button', {class: 'btn small quiet', type: 'button', onclick: async () => { try { await store.putPerson(S.tripId, id, {mergedInto: null}); toast('Split back out.'); } catch (err){ toast("Couldn't split it. Check your connection."); } closeDlg(); }}, 'Split'))))),
    !isNew && h('div', {class: 'row'},
      h('button', {class: 'btn', type: 'button', onclick: () => { S.filter.people = [e.id]; S.filter.only = false; S.tab = 'photos'; closeDlg(); render(); }}, 'Show their photos'),
      e.id !== me && S.me.id !== 'anon' && h('button', {class: 'btn', type: 'button', onclick: async () => { await setMe(e.id); closeDlg(); }}, 'This is me'),
      S.canWrite && facesOf(e.id).length > 1 && h('button', {class: 'btn', type: 'button', onclick: () => separateDialog(e)}, 'Separate faces')));
}
async function setMe(pid){ try { await store.putMember(S.tripId, {me: pid}); toast("Got it. Use the Me filter to see your photos."); } catch (e){ S.members[S.me.id] = {...S.members[S.me.id], me: pid}; changed(); } }
function findMeDialog(){
  const pick = async id => { await setMe(id); S.filter.people = [id]; S.filter.only = false; S.tab = 'photos'; closeDlg(); render(); };
  openDlg(h('h2', null, 'Which one is you?'),
    Face.state === 'ready' && h('div', {class: 'row'}, h('button', {class: 'btn primary', type: 'button', onclick: () => $('#file-selfie').click()}, 'Match me with a selfie'), h('span', {class: 'busy', id: 'selfie-status'})),
    Face.state === 'ready' && h('p', {style: {margin: 0, color: 'var(--muted)', fontSize: '14px'}}, 'The selfie is only compared on this device. It is not added to the album.'),
    peopleList().length ? h('div', null, h('p', {style: {margin: '0 0 8px'}}, 'Or pick yourself:'), peoplePicker(pick)) : null,
    S.canWrite && h('form', {class: 'row', onsubmit: async e => { e.preventDefault(); const n = $('#me-name').value.trim(); if (n) pick(await newPerson(n)); }},
      h('div', {class: 'field'}, h('label', {for: 'me-name'}, "I'm not listed"), h('input', {id: 'me-name', placeholder: 'Your name', maxlength: 40})), h('button', {class: 'btn', type: 'submit'}, 'Add me')));
  $('#file-selfie').onchange = async e => {
    const f = e.target.files[0]; e.target.value = ''; if (!f) return; const st = $('#selfie-status');
    try {
      st.textContent = 'Comparing…';
      const faces = await Face.detect(fit(await createImageBitmap(f, {imageOrientation: 'from-image'}), 1200));
      if (!faces.length){ st.textContent = 'No face found. Try a brighter, front-on photo.'; return; }
      const big = faces.sort((a, b) => b.b[2] * b.b[3] - a.b[2] * a.b[3])[0], hit = Face.nearest(big.d);
      if (hit.face && hit.dist < .56) pick(root(hit.face.p)); else st.textContent = "Couldn't find you in this album yet. Pick yourself below.";
    } catch (err){ st.textContent = "Couldn't read that photo."; }
  };
}

/* ───────── highlight reel ─────────
   The edit is planned in beats. A title, a quick montage that builds, the main body (single shots,
   split-screen collages and day cards cut on the beat), a rapid recap, then the outro. The music is
   arranged from the same plan, so its build, drop and ending land on the picture. */
const MUSIC = {
  golden: {label: 'Golden hour', bpm: 96, chords: [[53, 57, 60, 64], [55, 59, 62, 64], [52, 55, 59, 62], [57, 60, 64, 67]], lead: [76, 79, 81, 79, 76, 74, 72, 74, 71, 74, 76, 79, 81, 79, 76, 72],
    pad: ['triangle', 1500, .045], arp: 'eighth', kick: [0, 2.5], kickG: .8, snare: [1, 3], snareG: .12, hat: 'eighth', hatG: .035, hatF: 7500, bass: ['sine', 0, [0, 2.5], -12, .22], leadV: ['triangle', 0, .07, 0]},
  night: {label: 'Night bus', bpm: 122, chords: [[57, 60, 64], [53, 57, 60], [48, 52, 55], [55, 59, 62]], lead: [81, 0, 84, 81, 0, 79, 0, 76, 79, 0, 84, 79, 0, 83, 0, 79],
    pad: ['sawtooth', 900, .028], arp: 'stab', kick: [0, 1, 2, 3], kickG: .9, snare: [1, 3], snareG: .16, hat: 'off', hatG: .06, hatF: 8000, bass: ['sawtooth', 320, [.5, 1.5, 2.5, 3.5], -24, .17], leadV: ['sawtooth', 2400, .045, 0]},
  postcard: {label: 'Postcard', bpm: 88, chords: [[48, 52, 55, 60], [55, 59, 62, 67], [57, 60, 64, 69], [53, 57, 60, 65]], lead: [72, 76, 79, 76, 74, 79, 83, 79, 76, 81, 84, 81, 77, 81, 84, 81],
    pad: ['triangle', 2000, .03], arp: 'strum', kick: [0, 2], kickG: .5, snare: [1, 3], snareG: .07, hat: 'eighth', hatG: .028, hatF: 5200, bass: ['sine', 0, [0, 2], -12, .2], leadV: ['sine', 0, .06, 12]}
};
async function renderMusic(style, dur, bars){
  const sr = 44100, C = new OfflineAudioContext(2, Math.ceil(sr * dur), sr), M = MUSIC[style], beat = 60 / M.bpm, bar = 4 * beat;
  const master = C.createGain(), lp = C.createBiquadFilter(), comp = C.createDynamicsCompressor();
  lp.type = 'lowpass'; master.connect(lp); lp.connect(comp); comp.connect(C.destination);
  // a generated room, so pads, leads and snares have some space around them
  const rv = C.createConvolver(), ir = C.createBuffer(2, Math.floor(sr * 2.2), sr), wet = C.createGain();
  for (let ch = 0; ch < 2; ch++){ const d = ir.getChannelData(ch); for (let i = 0; i < d.length; i++) d[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / d.length, 2.6); }
  rv.buffer = ir; wet.gain.value = .5; rv.connect(wet); wet.connect(master);
  const nz = C.createBuffer(1, sr * 2, sr), nd = nz.getChannelData(0); for (let i = 0; i < nd.length; i++) nd[i] = Math.random() * 2 - 1;
  const hz = m => 440 * Math.pow(2, (m - 69) / 12);
  const out = (node, pan, send) => {
    let n = node; if (pan && C.createStereoPanner){ const p = C.createStereoPanner(); p.pan.value = pan; n.connect(p); n = p; }
    n.connect(master); if (send){ const g = C.createGain(); g.gain.value = send; n.connect(g); g.connect(rv); }
  };
  const tone = (t, m, d, type, g, cut, pan, send, att) => {
    if (t >= dur) return; const o = C.createOscillator(), a = C.createGain(); o.type = type; o.frequency.value = hz(m);
    a.gain.setValueAtTime(.0001, t); a.gain.exponentialRampToValueAtTime(g, t + (att || .012)); a.gain.exponentialRampToValueAtTime(.0001, t + d);
    let n = o; if (cut){ const f = C.createBiquadFilter(); f.type = 'lowpass'; f.frequency.value = cut; o.connect(f); n = f; }
    n.connect(a); out(a, pan, send); o.start(t); o.stop(t + d + .05);
  };
  const noise = (t, d, g, type, freq, pan, send) => {
    if (t >= dur) return; const s = C.createBufferSource(), f = C.createBiquadFilter(), a = C.createGain(); s.buffer = nz; f.type = type; f.frequency.value = freq;
    a.gain.setValueAtTime(g, t); a.gain.exponentialRampToValueAtTime(.0001, t + d); s.connect(f); f.connect(a); out(a, pan, send); s.start(t, Math.random()); s.stop(t + d + .02);
  };
  const kick = (t, g) => { if (t >= dur) return; const o = C.createOscillator(), a = C.createGain(); o.frequency.setValueAtTime(140, t); o.frequency.exponentialRampToValueAtTime(42, t + .13); a.gain.setValueAtTime(g, t); a.gain.exponentialRampToValueAtTime(.0001, t + .3); o.connect(a); a.connect(master); o.start(t); o.stop(t + .32); };
  const snare = (t, g) => { noise(t, .16, g, 'bandpass', 1800, 0, .25); tone(t, 54, .09, 'triangle', g * .6); };
  const riser = (t0, t1, g) => {
    if (t0 >= dur) return; const s = C.createBufferSource(), f = C.createBiquadFilter(), a = C.createGain(); s.buffer = nz; s.loop = true; f.type = 'bandpass'; f.Q.value = 1.2;
    f.frequency.setValueAtTime(300, t0); f.frequency.exponentialRampToValueAtTime(7000, t1); a.gain.setValueAtTime(.0001, t0); a.gain.exponentialRampToValueAtTime(g, t1 - .02); a.gain.linearRampToValueAtTime(.0001, t1);
    s.connect(f); f.connect(a); out(a, 0, .3); s.start(t0); s.stop(t1 + .02);
  };
  const impact = t => {
    if (t >= dur) return; const o = C.createOscillator(), a = C.createGain(); o.frequency.setValueAtTime(70, t); o.frequency.exponentialRampToValueAtTime(28, t + .9); a.gain.setValueAtTime(.7, t); a.gain.exponentialRampToValueAtTime(.0001, t + 1.1);
    o.connect(a); a.connect(master); o.start(t); o.stop(t + 1.2); noise(t, .9, .28, 'lowpass', 1400, 0, .6); noise(t, .5, .1, 'highpass', 6000, 0, .5);
  };
  const loud = s => s === 'drop' || s === 'fill';
  const first = bars.findIndex(s => s !== 'intro' && s !== 'build'), tDrop = Math.max(0, first) * bar;
  if (first > 0){ lp.frequency.setValueAtTime(700, 0); lp.frequency.exponentialRampToValueAtTime(5200, Math.max(.05, tDrop - .03)); lp.frequency.setValueAtTime(18000, tDrop); } else lp.frequency.value = 18000;
  master.gain.setValueAtTime(.72, 0); master.gain.setValueAtTime(.72, Math.max(0, dur - 2)); master.gain.linearRampToValueAtTime(.0001, dur);
  const [padT, padCut, padG] = M.pad, [bassT, bassCut, bassPat, bassOct, bassG] = M.bass, [leadT, leadCut, leadG, leadOct] = M.leadV;
  for (let b = 0; b * bar < dur; b++){
    const sec = bars[b] || 'outro', prev = bars[b - 1], t0 = b * bar, ch = M.chords[b % M.chords.length], soft = sec === 'intro' || sec === 'outro' ? .7 : 1, last = (b + 1) * bar >= dur - .01;
    ch.forEach((m, k) => tone(t0, m, bar * (last ? 1.6 : 1.06), padT, padG * (last ? 1.5 : 1), padCut, (k - 1.5) * .3, .5, .08));
    if (!last){
      if (M.arp === 'eighth') for (let i = 0; i < 8; i++) tone(t0 + i * beat / 2, ch[[0, 2, 1, 3, 2, 1, 3, 2][i] % ch.length] + 12, .32, 'sine', .06 * soft, 0, i % 2 ? .35 : -.35, .3);
      if (M.arp === 'strum') for (let i = 0; i < 4; i++) ch.forEach((m, k) => tone(t0 + i * beat + k * .028, m + (i % 2 ? 12 : 0), .9, 'triangle', (i ? .045 : .07) * soft, 2200, (k - 1.5) * .25, .3));
      if (M.arp === 'stab') [0, 1.5, 3].forEach(o => ch.forEach(m => tone(t0 + o * beat, m + 12, .2, 'square', .028 * soft, 1700, 0, .35)));
    }
    if (sec === 'build'){
      riser(t0, t0 + bar, .2);
      for (let i = 0; i < 6; i++) snare(t0 + i * beat / 2, .04 + i * .02); for (let i = 0; i < 4; i++) snare(t0 + 3 * beat + i * beat / 4, .16 + i * .03);
    }
    if (sec === 'break') riser(t0 + 2 * beat, t0 + bar, .16);
    if (loud(sec)){
      if (!loud(prev)) impact(t0);
      M.kick.forEach(k => kick(t0 + k * beat, M.kickG)); M.snare.forEach(k => snare(t0 + k * beat, M.snareG));
      for (let i = 0; i < 8; i++){ if (M.hat === 'off' && !(i % 2)) continue; noise(t0 + i * beat / 2, .045, M.hatG * (i % 2 ? 1 : .6), 'highpass', M.hatF, i % 4 < 2 ? .3 : -.3); }
      if (M.hat === 'off') for (let i = 0; i < 16; i++) noise(t0 + i * beat / 4, .025, .018, 'highpass', 9500, .2);
      bassPat.forEach(k => tone(t0 + k * beat, ch[0] + bassOct, bassT === 'sine' ? beat * 1.3 : .2, bassT, bassG, bassCut));
      if (sec === 'fill'){ for (let i = 0; i < 4; i++) snare(t0 + 3 * beat + i * beat / 4, .1 + i * .03); riser(t0 + 2 * beat, t0 + bar, .12); }
    }
    if (loud(sec) || sec === 'break') for (let i = 0; i < 4; i++){ const m = M.lead[(b % 4) * 4 + i]; if (m) tone(t0 + i * beat, m + leadOct, beat * .9, leadT, leadG, leadCut, .15, .4); }
  }
  return C.startRendering();
}
const SHAPES = {tall: [9, 16], square: [1, 1], wide: [16, 9]};
const reelSize = o => { const s = o.quality === 'hd' ? 1080 : 720, [a, b] = SHAPES[o.shape]; return a < b ? [s, Math.round(s * b / a)] : a > b ? [Math.round(s * a / b), s] : [s, s]; };
const Reel = {
  opts: {who: 'all', len: 30, music: 'golden', title: '', captions: true, shape: 'tall', look: 'film', quality: 'hd'},
  tl: null, img: new Map(), buf: null, own: null, ownName: '', key: '', ac: null, src: null, raf: 0, playing: false, rec: null, out: null, grain: null,
  pool(){ const w = this.opts.who; return [...S.photos].filter(p => w === 'all' || (w === 'sel' ? matchPeople(p) : photoPeople(p).has(w))).sort((a, b) => (a.takenAt || a.at) - (b.takenAt || b.at)); },
  pick(pool, n, score){
    if (pool.length <= n) return pool; const out = [];
    for (let i = 0; i < n; i++){ const a = Math.floor(i * pool.length / n), b = Math.floor((i + 1) * pool.length / n); out.push(pool.slice(a, b).sort((x, y) => score(y) - score(x))[0]); }
    return out;
  },
  /* the rhythm of the body: how many beats each shot holds and whether it is one photo or a collage */
  pattern(beats, level){
    const out = [], intro = level < 2 && beats >= 20, finale = level < 2 && beats >= 28; let left = beats - (finale ? 4 : 0);
    if (intro){ for (let i = 0; i < 4; i++) out.push({lay: 'flash', beats: 1, n: 1}); left -= 4; }
    const cyc = level === 0 ? [['single', 4], ['single', 2], ['single', 2], ['duo', 4], ['single', 2], ['single', 1], ['single', 1], ['single', 4], ['trio', 4], ['single', 2], ['single', 2]]
      : level === 1 ? [['single', 4], ['single', 2], ['single', 2], ['single', 4], ['single', 2], ['single', 1], ['single', 1]] : [['single', 4]];
    for (let i = 0; left > 0; i++){ let [lay, b] = cyc[i % cyc.length]; if (b > left){ lay = 'single'; b = left; } out.push({lay, beats: b, n: lay === 'duo' ? 2 : lay === 'trio' ? 3 : 1}); left -= b; }
    if (finale) out.push({lay: 'recap', beats: 4, n: 0});
    return out;
  },
  plan(pool, o){
    const M = MUSIC[o.music], beat = M ? 60 / M.bpm : .6, bar = 4 * beat, when = p => p.takenAt || p.at;
    const ts = pool.map(when), d0 = new Date(Math.min(...ts)); d0.setHours(0, 0, 0, 0);
    const dayOf = p => Math.floor((new Date(when(p)).setHours(0, 0, 0, 0) - d0.getTime()) / 864e5) + 1;
    const maxS = Math.max(1, ...pool.map(p => p.sharp || 0)), score = p => (p.sharp || 0) / maxS + Math.min(photoPeople(p).size, 4) * .15;
    const uniq = []; // burst shots: keep the best of several taken seconds apart by the same person
    for (const p of pool){ const q = uniq[uniq.length - 1]; if (q && q.by === p.by && Math.abs(when(p) - when(q)) < 3000){ if (score(p) > score(q)) uniq[uniq.length - 1] = p; } else uniq.push(p); }
    const cap = Math.min(uniq.length, 48), B = Math.max(4, Math.floor(o.len / bar)), tB = B >= 16 ? 2 : 1, oB = B >= 16 ? 2 : 1;
    let cards = o.captions ? Math.max(0, Math.min(new Set(uniq.map(dayOf)).size - 1, Math.floor(B / 5))) : 0;
    const bodyBeats = (B - tB - oB) * 4 - cards * 2;
    let slots = [], need = 0;
    for (let level = 0; level < 3; level++){ slots = this.pattern(bodyBeats, level); need = slots.reduce((n, s) => n + s.n, 0); if (need <= cap) break; }
    if (need > cap){ slots = slots.slice(0, cap); need = cap; }
    const picks = this.pick(uniq, need, score), hero = [...picks].sort((a, b) => score(b) - score(a))[0] || uniq[0];
    const segs = []; let beats = 0, k = 0, day = picks.length ? dayOf(picks[0]) : 1, shot = 0;
    const add = (s, b) => { s.t0 = beats * beat; beats += b; s.t1 = beats * beat; s.i = segs.length; segs.push(s); };
    add({kind: 'title', ps: [hero]}, tB * 4);
    for (const sl of slots){
      if (sl.lay === 'recap'){ if (picks.length > 3) add({kind: 'recap', ps: Array.from({length: 8}, (_, i) => picks[Math.floor(i * picks.length / 8)]), step: beat / 2}, 4); continue; }
      const ps = picks.slice(k, k + sl.n); k += sl.n; if (!ps.length) break;
      const d = dayOf(ps[0]); if (d !== day && cards > 0){ cards--; add({kind: 'card', ps: [ps[0]], day: d, ms: when(ps[0])}, 2); } day = d;
      add({kind: sl.lay === 'flash' ? 'flash' : 'shot', lay: ps.length === 3 ? 'trio' : ps.length === 2 ? 'duo' : 'single', ps, n: ++shot}, sl.beats);
    }
    add({kind: 'outro', ps: [hero]}, oB * 4);
    const total = beats * beat, bars = [];
    for (let b = 0; b * bar < total - 1e-6; b++){ const s = segs.find(s => b * bar + 1e-6 < s.t1); bars.push(s.kind === 'title' ? 'intro' : s.kind === 'flash' ? 'build' : s.kind === 'recap' ? 'fill' : s.kind === 'outro' ? 'outro' : 'drop'); }
    const drops = bars.map((s, i) => s === 'drop' ? i : -1).filter(i => i >= 0); if (drops.length >= 10) bars[drops[Math.floor(drops.length * .55)]] = 'break';
    const lastFlash = segs.map(s => s.kind).lastIndexOf('flash');
    return {segs, total, beat, bar, bars, shots: shot, n: picks.length, dropAt: lastFlash >= 0 ? segs[lastFlash].t1 : -9,
      range: fmtRange(Math.min(...ts), Math.max(...ts)), pool: pool.length, people: new Set(pool.map(p => p.by)).size};
  },
  async prepare(onStep){
    const o = this.opts, pool = this.pool();
    if (!pool.length) throw new Error('empty');
    const key = JSON.stringify([o.who, o.len, o.music, o.captions, o.quality, pool.map(p => p.id), this.ownName]);
    if (key !== this.key || !this.tl){
      const tl = this.plan(pool, o), side = o.quality === 'hd' ? 1600 : 1100, need = new Map();
      tl.segs.forEach(s => s.ps.forEach(p => need.set(p.id, p)));
      for (const [id, v] of this.img) if (!need.has(id) || v.side !== side) this.img.delete(id);
      let done = 0;
      for (const p of need.values()){
        onStep?.(`Loading photo ${++done} of ${need.size}…`); if (this.img.has(p.id)) continue;
        const blob = await store.blob(p.full); let src; try { src = await createImageBitmap(blob); } catch (e){ src = await loadImg(await store.urlOf(p.full)); }
        const im = fit(src, side), tiny = h('canvas', {width: 18, height: 18}), back = h('canvas', {width: 216, height: 216}), kk = Math.max(18 / im.width, 18 / im.height); src.close?.();
        tiny.getContext('2d').drawImage(im, (18 - im.width * kk) / 2, (18 - im.height * kk) / 2, im.width * kk, im.height * kk);
        const bc = back.getContext('2d'); bc.imageSmoothingQuality = 'high'; bc.drawImage(tiny, 0, 0, 216, 216); // a soft blur made by shrinking and enlarging
        this.img.set(p.id, {im, back, side});
      }
      if (MUSIC[o.music]) onStep?.('Composing the music…');
      this.buf = o.music === 'own' ? this.own : MUSIC[o.music] ? await renderMusic(o.music, tl.total, tl.bars) : null;
      this.tl = tl; this.key = key;
    }
    try { await Promise.all([document.fonts.load('800 80px "Bricolage Grotesque"'), document.fonts.load('500 24px "DM Mono"')]); } catch (e){}
    return this.tl;
  },
  focal(p){ const f = p.faces || []; if (!f.length) return [.5, .45]; return [f.reduce((s, x) => s + x.b[0] + x.b[2] / 2, 0) / f.length, f.reduce((s, x) => s + x.b[1] + x.b[3] / 2, 0) / f.length]; },
  /* one photo, cropped into a rectangle around its faces, drifting slowly */
  cell(c, x, y, w, hh, p, u, seed, zm){
    const {im, back} = this.img.get(p.id), iw = im.width, ih = im.height, cover = Math.max(w / iw, hh / ih), keep = (w * hh) / (iw * ih * cover * cover), mode = seed % 4, dir = mode % 2 ? 1 - u : u;
    c.save(); c.beginPath(); c.rect(x, y, w, hh); c.clip();
    if (keep < .42){
      c.drawImage(back, x, y, w, hh); c.fillStyle = 'rgba(8,9,10,.45)'; c.fillRect(x, y, w, hh);
      const k = Math.min(w / iw, hh / ih) * (1 + .06 * dir) * zm, dw = iw * k, dh = ih * k;
      c.shadowColor = 'rgba(0,0,0,.55)'; c.shadowBlur = w * .05; c.drawImage(im, x + (w - dw) / 2 + (mode < 2 ? -1 : 1) * (u - .5) * w * .04, y + (hh - dh) / 2, dw, dh); c.shadowBlur = 0;
    } else {
      const k = cover * (1.04 + .12 * dir) * zm, dw = iw * k, dh = ih * k, [fx, fy] = this.focal(p), pan = mode >= 2 ? (u - .5) * .06 * w : 0;
      c.drawImage(im, x + clamp(w / 2 - fx * dw + pan, w - dw, 0), y + clamp(hh / 2 - fy * dh, hh - dh, 0), dw, dh);
    }
    c.restore();
  },
  rects(lay, W, H, g){
    if (lay === 'duo') return H > W ? [[0, 0, W, (H - g) / 2], [0, (H + g) / 2, W, (H - g) / 2]] : [[0, 0, (W - g) / 2, H], [(W + g) / 2, 0, (W - g) / 2, H]];
    if (lay === 'trio'){
      if (H > W){ const a = Math.round(H * .58); return [[0, 0, W, a - g / 2], [0, a + g / 2, (W - g) / 2, H - a - g / 2], [(W + g) / 2, a + g / 2, (W - g) / 2, H - a - g / 2]]; }
      const a = Math.round(W * .6); return [[0, 0, a - g / 2, H], [a + g / 2, 0, W - a - g / 2, (H - g) / 2], [a + g / 2, (H + g) / 2, W - a - g / 2, (H - g) / 2]];
    }
    return [[0, 0, W, H]];
  },
  lines(c, text, maxW){ const out = []; let line = ''; for (const w of text.split(/\s+/)){ const t = line ? line + ' ' + w : w; if (c.measureText(t).width > maxW && line){ out.push(line); line = w; } else line = t; } if (line) out.push(line); return out; },
  backdrop(c, W, H, p, dark){ c.drawImage(this.img.get(p.id).back, 0, 0, W, H); c.fillStyle = `rgba(8,9,10,${dark})`; c.fillRect(0, 0, W, H); },
  seg(c, W, H, s, t, fx){
    const el = t - s.t0, u = clamp(el / (s.t1 - s.t0), 0, 1.25), U = Math.min(W, H) / 720, pad = 44 * U, o = this.opts, tl = this.tl, a = fx?.a ?? 1;
    const title = (o.title || S.trip?.name || 'Our trip').trim(), display = px => `800 ${px}px "Bricolage Grotesque", sans-serif`, mono = px => `500 ${px}px "DM Mono", monospace`;
    c.save();
    if (fx){ c.translate(W / 2 + (fx.dx || 0), H / 2 + (fx.dy || 0)); c.scale(fx.sc || 1, fx.sc || 1); c.translate(-W / 2, -H / 2); }
    c.globalAlpha = a; c.beginPath(); c.rect(0, 0, W, H); c.clip(); c.textBaseline = 'alphabetic';
    if (s.kind === 'shot'){
      const rs = this.rects(s.lay, W, H, 10 * U); c.fillStyle = '#0b0c0d'; c.fillRect(0, 0, W, H);
      rs.forEach((r, i) => {
        const ke = rs.length > 1 ? ease(clamp((el - i * .08) / .32, 0, 1)) : 1; if (ke <= 0) return;
        c.globalAlpha = a * ke; this.cell(c, r[0], r[1] + (1 - ke) * 36 * U, r[2], r[3], s.ps[i], u, s.i + i, 1);
      });
      c.globalAlpha = a; c.fillStyle = '#f0b429'; c.font = mono(19 * U); c.textBaseline = 'top'; c.fillText(`▸ ${String(s.n).padStart(2, '0')} / ${String(tl.shots).padStart(2, '0')}`, pad, pad); c.textBaseline = 'alphabetic';
      if (o.captions && s.lay === 'single' && s.t1 - s.t0 >= tl.beat * 2 - .01){
        const g = c.createLinearGradient(0, H * .78, 0, H); g.addColorStop(0, 'rgba(0,0,0,0)'); g.addColorStop(1, 'rgba(0,0,0,.6)'); c.fillStyle = g; c.fillRect(0, H * .78, W, H * .22);
        const k = ease(clamp(el / .3, 0, 1)), ms = s.ps[0].takenAt || s.ps[0].at; c.globalAlpha = a * k; c.font = mono(19 * U); c.fillStyle = 'rgba(255,255,255,.9)';
        c.fillText((new Date(ms).toLocaleDateString(undefined, {weekday: 'short', day: 'numeric', month: 'short'}) + ' · shot by ' + nameOf(s.ps[0].by)).toUpperCase(), pad, H - pad + (1 - k) * 12 * U);
      }
    } else if (s.kind === 'flash'){
      this.cell(c, 0, 0, W, H, s.ps[0], u, s.i, 1.07 - .07 * ease(clamp(u * 2, 0, 1)));
    } else if (s.kind === 'recap'){
      const i = clamp(Math.floor(el / s.step), 0, s.ps.length - 1), v = clamp((el - i * s.step) / s.step, 0, 1);
      this.cell(c, 0, 0, W, H, s.ps[i], v, i, 1.09 - .07 * v);
    } else if (s.kind === 'card'){
      this.backdrop(c, W, H, s.ps[0], .6);
      const k = ease(clamp(el / .35, 0, 1)), size = 150 * U; c.globalAlpha = a * k; c.font = display(size); c.fillStyle = '#fff';
      c.fillText('Day ' + s.day, pad, H * .52 + (1 - k) * 40 * U);
      c.fillStyle = '#f0b429'; c.fillRect(pad, H * .52 + 30 * U, (W - pad * 2) * ease(clamp(el / .6, 0, 1)), 4 * U);
      c.font = mono(24 * U); c.fillText(new Date(s.ms).toLocaleDateString(undefined, {weekday: 'long', day: 'numeric', month: 'long'}).toUpperCase(), pad, H * .52 + 78 * U);
    } else {
      if (s.kind === 'title'){ this.cell(c, 0, 0, W, H, s.ps[0], u * .8, 0, 1); c.fillStyle = 'rgba(8,9,10,.42)'; c.fillRect(0, 0, W, H); const g = c.createLinearGradient(0, H * .4, 0, H); g.addColorStop(0, 'rgba(0,0,0,0)'); g.addColorStop(1, 'rgba(0,0,0,.6)'); c.fillStyle = g; c.fillRect(0, H * .4, W, H * .6); }
      else this.backdrop(c, W, H, s.ps[0], .72);
      const size = (W > H ? 96 : 108) * U; c.font = display(size); c.fillStyle = '#fff';
      const ls = this.lines(c, s.kind === 'title' ? title : 'Until next time', W - pad * 2), y0 = H * .58 - (ls.length - 1) * size * .5;
      ls.forEach((l, i) => { const k = ease(clamp((el - .12 - i * .12) / .5, 0, 1)); c.globalAlpha = a * k; c.fillText(l, pad, y0 + i * size * .98 + (1 - k) * 44 * U); });
      const k2 = ease(clamp((el - .45 - ls.length * .12) / .5, 0, 1)); c.globalAlpha = a * k2; c.font = mono(22 * U); c.fillStyle = '#f0b429';
      const sub = s.kind === 'title' ? [S.trip?.place, tl.range].filter(Boolean).join(' · ') : `${title} · ${plural(tl.pool, 'photo')} · ${plural(tl.people, 'photographer')}`;
      this.lines(c, sub.toUpperCase(), W - pad * 2).forEach((l, i) => c.fillText(l, pad, y0 + (ls.length - 1) * size * .98 + 48 * U + i * 30 * U));
      c.globalAlpha = a; c.strokeStyle = '#ff4a32'; c.lineWidth = 7 * U; c.lineCap = 'round'; c.beginPath(); c.ellipse(pad + 34 * U, y0 - size - 30 * U, 34 * U, 24 * U, -.3, .3, .3 + Math.PI * 2 * clamp(el / .8, 0.001, 1)); c.stroke();
    }
    c.restore();
  },
  /* the look laid over every frame: colour, vignette, grain, light leaks and cut flashes */
  grade(c, W, H, t, flash){
    const look = this.opts.look, tl = this.tl;
    if (look === 'noir'){ c.globalCompositeOperation = 'saturation'; c.fillStyle = '#808080'; c.fillRect(0, 0, W, H); c.globalCompositeOperation = 'soft-light'; c.fillStyle = 'rgba(255,255,255,.12)'; c.fillRect(0, 0, W, H); }
    if (look === 'film'){
      c.globalCompositeOperation = 'soft-light'; c.fillStyle = 'rgba(255,176,96,.2)'; c.fillRect(0, 0, W, H);
      c.globalCompositeOperation = 'lighten'; c.fillStyle = '#17131d'; c.fillRect(0, 0, W, H);
      const leaks = [tl.dropAt, ...tl.segs.filter(s => s.kind === 'card' || s.kind === 'outro').map(s => s.t0)];
      for (const l of leaks){ const k = (t - l) / 1.3; if (k <= 0 || k >= 1) continue; const x = W * (-.2 + 1.4 * k), g = c.createRadialGradient(x, H * .3, 0, x, H * .3, H * .7), al = .5 * Math.sin(Math.PI * k);
        g.addColorStop(0, `rgba(255,150,60,${al})`); g.addColorStop(.5, `rgba(255,70,40,${al * .4})`); g.addColorStop(1, 'rgba(255,60,30,0)'); c.globalCompositeOperation = 'screen'; c.fillStyle = g; c.fillRect(0, 0, W, H); }
    }
    if (look !== 'clean'){
      c.globalCompositeOperation = 'source-over'; const v = c.createRadialGradient(W / 2, H / 2, Math.min(W, H) * .42, W / 2, H / 2, Math.hypot(W, H) / 2); v.addColorStop(0, 'rgba(0,0,0,0)'); v.addColorStop(1, 'rgba(0,0,0,.42)'); c.fillStyle = v; c.fillRect(0, 0, W, H);
      if (!this.grain || this.grain.c !== c){
        const n = h('canvas', {width: 160, height: 160}), nc = n.getContext('2d'), d = nc.createImageData(160, 160);
        for (let i = 0; i < d.data.length; i += 4){ const g = 128 + (Math.random() - .5) * 150; d.data[i] = d.data[i + 1] = d.data[i + 2] = g; d.data[i + 3] = 255; } nc.putImageData(d, 0, 0);
        this.grain = {c, p: c.createPattern(n, 'repeat')};
      }
      const f = Math.floor(t * 24), ox = (f * 73) % 160, oy = (f * 41) % 160;
      c.save(); c.globalCompositeOperation = 'overlay'; c.globalAlpha = look === 'noir' ? .2 : .13; c.translate(-ox, -oy); c.fillStyle = this.grain.p; c.fillRect(0, 0, W + 160, H + 160); c.restore();
    }
    c.globalCompositeOperation = 'source-over'; c.globalAlpha = 1;
    if (flash > .01){ c.fillStyle = `rgba(255,246,232,${flash})`; c.fillRect(0, 0, W, H); }
  },
  draw(c, W, H, t){
    const tl = this.tl, segs = tl.segs; t = clamp(t, 0, tl.total - .001);
    const i = segs.findIndex(s => t < s.t1), s = segs[i], p = segs[i - 1], dt = t - s.t0, fast = x => x && (x.kind === 'flash' || x.kind === 'recap');
    c.globalCompositeOperation = 'source-over'; c.globalAlpha = 1; c.imageSmoothingQuality = 'high'; c.fillStyle = '#0b0c0d'; c.fillRect(0, 0, W, H);
    const quick = fast(s) || fast(p), X = quick || !p ? 0 : Math.min(.34, (s.t1 - s.t0) * .4); let flash = 0;
    if (X && dt < X){
      const k = ease(dt / X), mode = s.kind === 'card' || s.kind === 'outro' || p.kind === 'card' || p.kind === 'title' ? 'fade' : ['push', 'zoom', 'fade', 'up', 'zoom'][s.i % 5];
      if (mode === 'push'){ this.seg(c, W, H, p, t, {dx: -k * W}); this.seg(c, W, H, s, t, {dx: (1 - k) * W}); }
      else if (mode === 'up'){ this.seg(c, W, H, p, t, {dy: -k * H}); this.seg(c, W, H, s, t, {dy: (1 - k) * H}); }
      else if (mode === 'zoom'){ this.seg(c, W, H, p, t, {sc: 1 + k * .35}); this.seg(c, W, H, s, t, {sc: .86 + .14 * k, a: k}); }
      else { this.seg(c, W, H, p, t, {}); this.seg(c, W, H, s, t, {a: k}); }
    } else this.seg(c, W, H, s, t, null);
    if (quick && p) flash = .5 * (1 - clamp(dt / .11, 0, 1));
    if (s.kind === 'recap'){ const v = (t - s.t0) % s.step; flash = Math.max(flash, .4 * (1 - clamp(v / .09, 0, 1))); }
    const dd = t - tl.dropAt; if (dd >= 0 && dd < .45) flash = Math.max(flash, .8 * (1 - dd / .45) ** 2);
    this.grade(c, W, H, t, flash);
  },
  stop(){
    cancelAnimationFrame(this.raf); this.playing = false;
    try { this.src?.stop(); } catch (e){} this.src = null;
    if (this.rec && this.rec.state !== 'inactive') { this.rec.onstop = null; try { this.rec.stop(); } catch (e){} } this.rec = null;
  },
  async play(record){
    const cv = $('#reel-canvas'), status = $('#reel-status'), bar = $('#reel-prog');
    if (!cv) return; this.stop(); this.showCanvas(); this.setBusy(true); status.textContent = 'Getting the cut ready…';
    // the audio context must start inside the click
    try { this.ac ||= new (window.AudioContext || window.webkitAudioContext)(); await this.ac.resume(); } catch (e){ this.ac = null; }
    let tl; try { tl = await this.prepare(m => { status.textContent = m; }); } catch (e){ status.textContent = e.message === 'empty' ? 'No photos to cut from. Add photos or change who the reel is about.' : "Couldn't load the photos. Try again."; this.setBusy(false); return; }
    const [W, H] = reelSize(this.opts); cv.width = W; cv.height = H;
    const c = cv.getContext('2d'), ac = this.ac; let dest = null, chunks = [], mime = '';
    this.draw(c, W, H, 0);
    if (record){
      if (!window.MediaRecorder || !cv.captureStream){ status.textContent = "This browser can't record video. Try Chrome, Edge or Safari."; this.setBusy(false); return; }
      mime = ['video/mp4;codecs=avc1.640028,mp4a.40.2', 'video/mp4;codecs=avc1.42E01E,mp4a.40.2', 'video/mp4;codecs=avc1,mp4a.40.2', 'video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm', 'video/mp4'].find(m => MediaRecorder.isTypeSupported(m)) || '';
      const tracks = [...cv.captureStream(30).getVideoTracks()];
      if (this.buf && ac){ dest = ac.createMediaStreamDestination(); tracks.push(...dest.stream.getAudioTracks()); }
      try { this.rec = new MediaRecorder(new MediaStream(tracks), {mimeType: mime || undefined, videoBitsPerSecond: this.opts.quality === 'hd' ? 12e6 : 6e6, audioBitsPerSecond: 192000}); }
      catch (e){ status.textContent = "Recording couldn't start in this browser."; this.setBusy(false); return; }
      this.rec.ondataavailable = e => e.data.size && chunks.push(e.data);
      this.rec.start(500);
    }
    let t0;
    if (this.buf && ac){
      const g = ac.createGain(); this.src = ac.createBufferSource(); this.src.buffer = this.buf; this.src.connect(g);
      if (this.opts.music === 'own'){ g.gain.setValueAtTime(1, ac.currentTime + Math.max(0, tl.total - 1.6)); g.gain.linearRampToValueAtTime(.0001, ac.currentTime + tl.total); }
      g.connect(ac.destination); if (dest) g.connect(dest);
      t0 = ac.currentTime + .06; this.src.start(t0, 0, tl.total);
    }
    const clock = this.buf && ac ? () => ac.currentTime - t0 : (p0 => () => (performance.now() - p0) / 1000)(performance.now());
    this.playing = true; $('#reel-stop').hidden = false;
    const done = () => {
      this.playing = false; $('#reel-stop').hidden = true; try { this.src?.stop(); } catch (e){} this.src = null;
      if (record && this.rec){
        const rec = this.rec; status.textContent = 'Finishing the video…';
        rec.onstop = () => {
          const type = (rec.mimeType || mime || 'video/webm').split(';')[0], ext = type.includes('mp4') ? 'mp4' : 'webm';
          this.out = {blob: new Blob(chunks, {type}), name: `${slug(S.trip?.name)}-reel.${ext}`};
          const v = $('#reel-video'); if (v){ v.src = URL.createObjectURL(this.out.blob); v.hidden = false; cv.hidden = true; $('#reel-save').hidden = false; }
          status.textContent = `Video ready · ${W}×${H} · ${Math.round(tl.total)} s · ${(this.out.blob.size / 1048576).toFixed(1)} MB`; this.setBusy(false); this.rec = null;
        };
        rec.stop();
      } else { status.textContent = `${plural(tl.n, 'photo')} · ${Math.round(tl.total)} s`; this.setBusy(false); }
    };
    const frame = () => {
      if (!this.playing) return; const t = clock();
      this.draw(c, W, H, t); bar.style.width = clamp(t / tl.total * 100, 0, 100) + '%';
      status.textContent = (record ? 'Recording ' : 'Playing ') + Math.max(0, Math.ceil(tl.total - t)) + ' s';
      if (t >= tl.total) return done(); this.raf = requestAnimationFrame(frame);
    };
    this.raf = requestAnimationFrame(frame);
  },
  /* back to the live preview: any finished video no longer matches the settings, so drop it */
  showCanvas(){
    const v = $('#reel-video'), cv = $('#reel-canvas'), save = $('#reel-save');
    if (v){ if (v.src){ try { v.pause(); } catch (e){} URL.revokeObjectURL(v.src); v.removeAttribute('src'); v.load(); } v.hidden = true; }
    if (cv) cv.hidden = false; if (save) save.hidden = true; this.out = null;
  },
  setBusy(b){ document.querySelectorAll('[data-reel-go]').forEach(el => el.disabled = b); }
};
function viewReel(){
  const o = Reel.opts, ppl = peopleList().filter(e => e.count), me = myPerson();
  const group = S.filter.people.length > 0 && (S.filter.people.length > 1 || S.filter.only);
  if (o.who === 'sel' ? !group : o.who !== 'all' && !ppl.some(e => e.id === o.who)) o.who = 'all';
  let posterRun = 0;
  const poster = async () => {
    const run = ++posterRun, st = () => $('#reel-status');
    if (!Reel.playing) Reel.showCanvas();
    try {
      await Reel.prepare(m => { if (run === posterRun && st() && !Reel.playing) st().textContent = m; });
      const cv = $('#reel-canvas'); if (!cv || Reel.playing || run !== posterRun) return;
      const [w, hh] = reelSize(o); cv.width = w; cv.height = hh; Reel.draw(cv.getContext('2d'), w, hh, Math.min(1.4, Reel.tl.total / 2));
      st().textContent = `${plural(Reel.tl.n, 'photo')} · ${Math.round(Reel.tl.total)} s`;
    } catch (e){ if (st()) st().textContent = e.message === 'empty' ? 'Add photos to cut a reel.' : "Couldn't load the photos."; }
  };
  const seg = (key, choices) => h('div', {class: 'seg', role: 'group'}, choices.map(([v, label]) => h('button', {type: 'button', 'aria-pressed': String(o[key] === v), onclick: e => { o[key] = v; e.currentTarget.parentNode.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === e.currentTarget))); if (!Reel.playing) poster(); }}, label)));
  const [W, H] = reelSize(o);
  setTimeout(poster, 0);
  $('#file-audio').onchange = async e => {
    const f = e.target.files[0]; e.target.value = ''; if (!f) return;
    try { Reel.ac ||= new (window.AudioContext || window.webkitAudioContext)(); Reel.own = await Reel.ac.decodeAudioData(await f.arrayBuffer()); Reel.ownName = f.name; o.music = 'own'; Reel.key = ''; $('#main').dataset.view = ''; render(); }
    catch (err){ toast("Couldn't read that audio file. Try an MP3 or M4A."); }
  };
  return h('div', {class: 'reel'},
    h('div', {class: 'stage'},
      h('canvas', {id: 'reel-canvas', width: W, height: H}), h('video', {id: 'reel-video', controls: true, playsinline: true, hidden: true}),
      h('div', {class: 'prog'}, h('i', {id: 'reel-prog'})), h('span', {class: 'mono', id: 'reel-status'}, 'Picking the best shots…')),
    h('div', {class: 'opts'},
      h('div', {class: 'field'}, h('label', {for: 'reel-title'}, 'Title'), h('input', {id: 'reel-title', value: o.title || S.trip.name, maxlength: 48, oninput: e => { o.title = e.target.value; }, onchange: poster})),
      h('div', {class: 'field'}, h('label', {for: 'reel-who'}, 'Starring'), h('select', {id: 'reel-who', onchange: e => { o.who = e.target.value; poster(); }},
        h('option', {value: 'all'}, 'Everyone'), group && h('option', {value: 'sel', selected: o.who === 'sel' || null}, 'Photos with ' + pickedLabel()), ppl.map(e => h('option', {value: e.id, selected: o.who === e.id || null}, (e.id === me ? 'Me' : personLabel(e)) + ` (${e.count})`)))),
      h('div', {class: 'field'}, h('label', null, 'Length'), seg('len', [[15, '15 s'], [30, '30 s'], [45, '45 s'], [60, '60 s']])),
      h('div', {class: 'field'}, h('label', null, 'Shape'), seg('shape', [['tall', 'Tall 9:16'], ['square', 'Square'], ['wide', 'Wide 16:9']])),
      h('div', {class: 'field'}, h('label', null, 'Look'), seg('look', [['film', 'Film'], ['clean', 'Clean'], ['noir', 'Black and white']])),
      h('div', {class: 'field'}, h('label', null, 'Music'), seg('music', [...Object.entries(MUSIC).map(([k, m]) => [k, m.label]), ...(Reel.own ? [['own', Reel.ownName.slice(0, 18)]] : []), ['none', 'No music']]),
        h('div', null, h('button', {class: 'btn small quiet', type: 'button', onclick: () => $('#file-audio').click()}, 'Use my own track'))),
      h('div', {class: 'field'}, h('label', null, 'Quality'), seg('quality', [['hd', 'Full HD 1080p'], ['sd', 'Standard 720p']])),
      h('label', {class: 'check', for: 'reel-cap'}, h('input', {type: 'checkbox', id: 'reel-cap', checked: o.captions, onchange: e => { o.captions = e.target.checked; poster(); }}), 'Day cards and photographer credits'),
      h('div', {class: 'row'},
        h('button', {class: 'btn', type: 'button', 'data-reel-go': 1, onclick: () => Reel.play(false)}, 'Preview'),
        h('button', {class: 'btn primary', type: 'button', 'data-reel-go': 1, onclick: () => Reel.play(true)}, 'Make the video'),
        h('button', {class: 'btn quiet', type: 'button', id: 'reel-stop', hidden: true, onclick: () => { Reel.stop(); Reel.setBusy(false); $('#reel-stop').hidden = true; $('#reel-status').textContent = 'Stopped'; }}, 'Stop'),
        h('button', {class: 'btn primary', type: 'button', id: 'reel-save', hidden: true, onclick: () => Reel.out && saveFile(Reel.out.name, Reel.out.blob)}, 'Save video')),
      h('p', {class: 'note'}, 'The video records in real time, so a 30 second reel takes 30 seconds. Keep this tab in front while it records, then press Save video. Changing any setting replaces the video with a fresh preview. If the picture stutters, switch Quality to Standard. The built-in tracks are generated here and are free to post.')));
}

/* ───────── routing and boot ───────── */
function goHome(){ Reel.stop(); closeTrip(); if (location.hash) history.pushState(null, '', location.pathname + location.search); render(); }
function route(){
  const l = parseLink(location.hash);
  if (l){ if (l.id !== S.tripId){ Reel.stop(); openTrip(l.id, l.secret); } }
  else if (S.tripId){ Reel.stop(); closeTrip(); }
  changed();
}
$('#home-link').onclick = goHome;
$('#file-photos').onchange = e => { const fs = [...e.target.files]; e.target.value = ''; addFiles(fs); };
addEventListener('dragover', e => { if (S.tripId) e.preventDefault(); });
addEventListener('drop', e => { if (S.tripId && S.trip && e.dataTransfer?.files?.length){ e.preventDefault(); addFiles(e.dataTransfer.files); } });
addEventListener('hashchange', route);
addEventListener('popstate', route);
document.addEventListener('visibilitychange', () => { if (!document.hidden && A.key && !S.gone) pull(false).catch(e => { if (e.status === 404) albumGone(); }); });
if (!window.crypto?.subtle) $('#main').replaceChildren(h('div', {class: 'panel'}, h('h2', {class: 'sect'}, 'Open this page over https'), h('p', null, 'Groupflicks encrypts photos in the browser, which only works on a secure (https) address.')));
else { route(); Face.init(); }
if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
