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
  tab: 'photos', filter: {person: null, by: null}, selecting: false, sel: new Set(), work: ''
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
  async remove(a, bid){ try { await fetch(`${this.url}/storage/v1/object/gf-photos/${a}/${bid}`, {method: 'DELETE', headers: this.h}); } catch (e){} }
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
  async remove(a, bid){ this.blobs.delete(a + '/' + bid); }
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
  S.trip = A.docs.get('album')?.v || null; S.photos = photos; S.people = people; S.members = members;
  S.isOwner = !!S.trip && S.trip.by === S.me.id;
  if (S.trip) remember();
  changed();
}
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
  Object.assign(S, {tripId: null, trip: null, photos: [], people: {}, members: {}, tripLoaded: false, slow: false});
}
async function openTrip(id, secret){
  closeTrip();
  Object.assign(S, {tripId: id, tab: 'photos', filter: {person: null, by: null}, selecting: false, sel: new Set()});
  A.id = id; A.secret = secret; changed();
  try {
    const k = await deriveKeys(secret, id); if (A.id !== id) return;
    A.key = k.key; A.token = k.token; await pull(true);
  } catch (e){
    if (A.id !== id) return;
    S.tripLoaded = true; S.slow = !(e.status >= 400 && e.status < 500); changed(); return;
  }
  if (A.id !== id) return;
  S.tripLoaded = true; changed(); joinTrip();
  A.timer = setInterval(() => { if (!document.hidden && A.key) pull(++A.polls % 12 === 0).catch(() => {}); }, 5000);
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
  async delPhoto(_, p){ A.docs.delete(p.id); syncState(); await BE.del(A.id, A.token, p.id); BE.remove(A.id, p.full); BE.remove(A.id, p.thumb); },
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
function shown(){
  let list = [...S.photos].sort((a, b) => (a.takenAt || a.at) - (b.takenAt || b.at));
  const f = S.filter;
  if (f.person) list = list.filter(p => photoPeople(p).has(f.person));
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
  if (!S.trip) return h('div', {class: 'panel'}, h('h2', {class: 'sect'}, (S.tripLoaded && !S.creating) ? "This trip isn't here" : 'Opening trip…'),
    h('p', {style: {color: 'var(--muted)'}}, !(S.tripLoaded && !S.creating) ? '' : S.slow ? "The album can't be reached yet. Check your connection." : 'Check that you pasted the whole invite link, including everything after the #.'),
    h('button', {class: 'btn', type: 'button', onclick: goHome}, 'All trips'));
  const ts = S.photos.map(p => p.takenAt || p.at), ppl = new Set([...Object.keys(S.members), ...S.photos.map(p => p.by)]);
  const meta = [S.trip.place, ts.length ? fmtRange(Math.min(...ts), Math.max(...ts)) : '', plural(S.photos.length, 'photo'), plural(Math.max(1, ppl.size), 'contributor')].filter(Boolean).join(' · ');
  const tab = (id, label) => h('button', {type: 'button', role: 'tab', 'aria-selected': String(S.tab === id), onclick: () => { Reel.stop(); S.tab = id; S.selecting = false; S.sel.clear(); render(); }}, label);
  return h('div', null,
    h('div', {class: 'thead'},
      h('div', null, h('button', {class: 'btn small quiet', type: 'button', onclick: goHome, style: {marginBottom: '12px'}}, '← All trips'), h('h1', null, S.trip.name), h('div', {class: 'meta'}, meta)),
      h('div', {class: 'row'}, h('span', {class: 'busy', id: 'work'}, S.work),
        h('button', {class: 'btn', type: 'button', onclick: inviteDialog}, 'Invite friends'),
        S.canWrite && S.canUpload && h('button', {class: 'btn primary', type: 'button', onclick: () => $('#file-photos').click()}, 'Add photos'))),
    h('div', {class: 'tabs', role: 'tablist'}, tab('photos', 'Photos'), tab('people', 'People'), tab('reel', 'Highlight reel')),
    S.tab === 'photos' ? viewPhotos() : S.tab === 'people' ? viewPeople() : viewReel());
}
function chipsRow(){
  const ppl = peopleList().filter(e => e.count), me = myPerson(), f = S.filter;
  const set = id => { f.person = f.person === id ? null : id; S.sel.clear(); render(); };
  return h('div', {class: 'chips'},
    h('button', {class: 'chip plain', type: 'button', 'aria-pressed': String(!f.person), onclick: () => { f.person = null; render(); }}, 'Everyone'),
    me ? h('button', {class: 'chip', type: 'button', 'aria-pressed': String(f.person === me), onclick: () => set(me)}, avatar(ppl.find(e => e.id === me) || {name: 'Me'}), 'Me')
       : h('button', {class: 'chip plain', type: 'button', onclick: findMeDialog}, 'Find me'),
    ppl.filter(e => e.id !== me).map(e => h('button', {class: 'chip', type: 'button', 'aria-pressed': String(f.person === e.id), onclick: () => set(e.id)}, avatar(e), personLabel(e), h('span', {style: {color: 'var(--muted)'}}, e.count))));
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
  const who = S.filter.person ? (S.filter.person === myPerson() ? 'you' : personLabel(peopleList().find(e => e.id === S.filter.person) || {})) : null;
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
        h('button', {class: 'btn small primary', type: 'button', disabled: !picked.length, onclick: () => downloadPhotos(picked)}, 'Download ' + picked.length)))));
  } else if (S.filter.person || S.filter.by){
    dock.replaceChildren(h('div', {class: 'dock'}, h('div', null,
      h('span', null, 'Filtered to ', h('strong', null, plural(list.length, 'photo'))),
      h('button', {class: 'btn primary', type: 'button', disabled: !list.length, onclick: () => downloadPhotos(list)}, `Download these ${list.length}`))));
  } else dock.replaceChildren();
}
function viewPeople(){
  const ppl = peopleList(), me = myPerson();
  const intro = Face.state === 'ready' ? 'Faces are grouped automatically as photos come in. Name a group once and the name sticks. Give two groups the same person by merging them.'
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
      S.canWrite && (p.by === S.me.id || S.isOwner) && h('button', {class: 'btn quiet', type: 'button', onclick: e => {
        if (e.currentTarget.dataset.sure){ closeDlg(); store.delPhoto(S.tripId, p).catch(() => toast("Couldn't remove it.")); }
        else { e.currentTarget.dataset.sure = 1; e.currentTarget.textContent = 'Tap again to remove for everyone'; } }}, 'Remove')));
}
function personDialog(e){
  const isNew = !e, me = myPerson();
  const save = async ev => {
    ev.preventDefault(); const name = $('#person-name').value.trim();
    try {
      if (isNew){ if (name) await newPerson(name); }
      else {
        const twin = name && peopleList().find(o => o.id !== e.id && o.name.toLowerCase() === name.toLowerCase());
        if (twin){ await store.putPerson(S.tripId, e.id, {mergedInto: twin.id}); toast('Merged with ' + twin.name); }
        else await store.putPerson(S.tripId, e.id, {name});
      }
    } catch (err){ toast("Couldn't save. Check your connection."); }
    closeDlg();
  };
  openDlg(h('h2', null, isNew ? 'Add a person' : (e.name || 'Who is this?')),
    !isNew && h('div', {class: 'row', style: {alignItems: 'center'}}, avatar(e), h('span', {style: {color: 'var(--muted)'}}, 'In ' + plural(e.count, 'photo'))),
    h('form', {class: 'row', onsubmit: save}, h('div', {class: 'field'}, h('label', {for: 'person-name'}, 'Name'), h('input', {id: 'person-name', value: e?.name || '', maxlength: 40, placeholder: 'Maya', disabled: !S.canWrite})),
      S.canWrite && h('button', {class: 'btn primary', type: 'submit'}, 'Save')),
    !isNew && h('p', {style: {margin: 0, color: 'var(--muted)', fontSize: '14px'}}, 'Typing a name that another group already has merges the two.'),
    !isNew && h('div', {class: 'row'},
      h('button', {class: 'btn', type: 'button', onclick: () => { S.filter.person = e.id; S.tab = 'photos'; closeDlg(); render(); }}, 'Show their photos'),
      e.id !== me && S.me.id !== 'anon' && h('button', {class: 'btn', type: 'button', onclick: async () => { await setMe(e.id); closeDlg(); }}, 'This is me')));
}
async function setMe(pid){ try { await store.putMember(S.tripId, {me: pid}); toast("Got it. Use the Me filter to see your photos."); } catch (e){ S.members[S.me.id] = {...S.members[S.me.id], me: pid}; changed(); } }
function findMeDialog(){
  const pick = async id => { await setMe(id); S.filter.person = id; S.tab = 'photos'; closeDlg(); render(); };
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

/* ───────── highlight reel ───────── */
const MUSIC = {
  golden: {label: 'Golden hour', bpm: 92, chords: [[53, 57, 60, 64], [55, 59, 62, 64], [52, 55, 59, 62], [57, 60, 64, 67]],
    bar({t0, beat, ch, b, tone, kick, noise}){
      ch.forEach(m => tone(t0, m, beat * 4.2, 'triangle', .05, 1400)); tone(t0, ch[0] - 12, beat * 1.6, 'sine', .22); tone(t0 + beat * 2.5, ch[0] - 12, beat * 1.2, 'sine', .18);
      for (let i = 0; i < 8; i++) tone(t0 + i * beat / 2, ch[[0, 2, 1, 3, 2, 1, 3, 2][i]] + 12, .32, 'sine', .07);
      if (b > 0){ kick(t0, .8); kick(t0 + beat * 2.5, .6); noise(t0 + beat, .13, .13, 'bandpass', 1900); noise(t0 + beat * 3, .13, .13, 'bandpass', 1900); for (let i = 0; i < 8; i++) noise(t0 + i * beat / 2, .04, i % 2 ? .05 : .025, 'highpass', 7500); }
    }},
  night: {label: 'Night bus', bpm: 120, chords: [[57, 60, 64], [53, 57, 60], [48, 52, 55], [55, 59, 62]],
    bar({t0, beat, ch, b, tone, kick, noise}){
      for (let i = 0; i < 4; i++){ if (b > 0) kick(t0 + i * beat, .9); noise(t0 + i * beat + beat / 2, .05, .07, 'highpass', 8000); tone(t0 + i * beat + beat / 2, ch[0] - 24, .2, 'sawtooth', .17, 320); }
      if (b > 1){ noise(t0 + beat, .14, .16, 'bandpass', 1500); noise(t0 + beat * 3, .14, .16, 'bandpass', 1500); }
      [0, 1.5, 3].forEach(o => ch.forEach(m => tone(t0 + o * beat, m + 12, .2, 'square', .028, 1600)));
    }},
  postcard: {label: 'Postcard', bpm: 84, chords: [[48, 52, 55, 60], [55, 59, 62, 67], [57, 60, 64, 69], [53, 57, 60, 65]],
    bar({t0, beat, ch, b, tone, kick, noise}){
      for (let i = 0; i < 4; i++) ch.forEach((m, k) => tone(t0 + i * beat + k * .028, m + (i % 2 ? 12 : 0), .9, 'triangle', i ? .05 : .08, 2200));
      tone(t0, ch[0] - 12, beat * 2, 'sine', .2); tone(t0, ch[2] + 12, beat * 1.6, 'sine', .08); tone(t0 + beat * 2, ch[3] + 12, beat * 1.6, 'sine', .08);
      if (b > 0){ kick(t0, .5); kick(t0 + beat * 2, .4); for (let i = 0; i < 8; i++) noise(t0 + i * beat / 2, .06, i % 2 ? .04 : .02, 'highpass', 5200); }
    }}
};
async function renderMusic(style, dur){
  const sr = 44100, C = new OfflineAudioContext(2, Math.ceil(sr * dur), sr), M = MUSIC[style], beat = 60 / M.bpm;
  const master = C.createGain(), comp = C.createDynamicsCompressor(); master.connect(comp); comp.connect(C.destination);
  master.gain.setValueAtTime(.9, 0); master.gain.setValueAtTime(.9, Math.max(0, dur - 1.8)); master.gain.linearRampToValueAtTime(.0001, dur);
  const nz = C.createBuffer(1, sr * 2, sr), nd = nz.getChannelData(0); for (let i = 0; i < nd.length; i++) nd[i] = Math.random() * 2 - 1;
  const hz = m => 440 * Math.pow(2, (m - 69) / 12);
  const tone = (t, m, d, type, g, cut) => { const o = C.createOscillator(), a = C.createGain(); o.type = type; o.frequency.value = hz(m); a.gain.setValueAtTime(.0001, t); a.gain.exponentialRampToValueAtTime(g, t + .012); a.gain.exponentialRampToValueAtTime(.0001, t + d); let n = o; if (cut){ const f = C.createBiquadFilter(); f.type = 'lowpass'; f.frequency.value = cut; o.connect(f); n = f; } n.connect(a); a.connect(master); o.start(t); o.stop(t + d + .05); };
  const kick = (t, g) => { const o = C.createOscillator(), a = C.createGain(); o.frequency.setValueAtTime(140, t); o.frequency.exponentialRampToValueAtTime(42, t + .13); a.gain.setValueAtTime(g, t); a.gain.exponentialRampToValueAtTime(.0001, t + .3); o.connect(a); a.connect(master); o.start(t); o.stop(t + .32); };
  const noise = (t, d, g, type, freq) => { const s = C.createBufferSource(), f = C.createBiquadFilter(), a = C.createGain(); s.buffer = nz; f.type = type; f.frequency.value = freq; a.gain.setValueAtTime(g, t); a.gain.exponentialRampToValueAtTime(.0001, t + d); s.connect(f); f.connect(a); a.connect(master); s.start(t, Math.random()); s.stop(t + d + .02); };
  for (let b = 0; b * 4 * beat < dur; b++) M.bar({t0: b * 4 * beat, beat, ch: M.chords[b % M.chords.length], b, tone, kick, noise});
  return C.startRendering();
}
const SHAPES = {tall: [720, 1280, '9:16'], square: [960, 960, '1:1'], wide: [1280, 720, '16:9']};
const Reel = {
  opts: {who: 'all', len: 30, music: 'golden', title: '', captions: true, shape: 'tall'},
  tl: null, img: new Map(), buf: null, own: null, ownName: '', key: '', ac: null, src: null, raf: 0, playing: false, rec: null, out: null,
  pool(){ const w = this.opts.who; return [...S.photos].filter(p => w === 'all' || photoPeople(p).has(w)).sort((a, b) => (a.takenAt || a.at) - (b.takenAt || b.at)); },
  pick(pool, n){
    if (pool.length <= n) return pool;
    const maxS = Math.max(1, ...pool.map(p => p.sharp || 0)), score = p => (p.sharp || 0) / maxS + Math.min(photoPeople(p).size, 4) * .15, out = [];
    for (let i = 0; i < n; i++){ const a = Math.floor(i * pool.length / n), b = Math.floor((i + 1) * pool.length / n); out.push(pool.slice(a, b).sort((x, y) => score(y) - score(x))[0]); }
    return out;
  },
  async prepare(){
    const o = this.opts, pool = this.pool();
    if (!pool.length) throw new Error('empty');
    const key = JSON.stringify([o.who, o.len, o.music, pool.map(p => p.id), this.ownName]);
    if (key !== this.key || !this.tl){
      const M = MUSIC[o.music], seg = M ? 4 * 60 / M.bpm : 2.4;
      const n = clamp(Math.floor((o.len - 2 * seg) / seg) + 1, 1, 40), picks = this.pick(pool, n), segs = [];
      let t = 0; segs.push({kind: 'title', t0: 0, t1: seg, p: picks[0], i: 0}); t = seg;
      picks.slice(1).forEach((p, i) => { segs.push({kind: 'photo', t0: t, t1: t + seg, p, i: i + 1}); t += seg; });
      segs.push({kind: 'outro', t0: t, t1: t + seg, p: picks[0], i: picks.length}); t += seg;
      const ts = pool.map(p => p.takenAt || p.at), d0 = new Date(Math.min(...ts)); d0.setHours(0, 0, 0, 0);
      this.tl = {segs, total: t, n: picks.length, d0: d0.getTime(), range: fmtRange(Math.min(...ts), Math.max(...ts)), pool: pool.length, people: new Set(pool.map(p => p.by)).size};
      await Promise.all(picks.map(async p => { if (this.img.has(p.id)) return; const im = await loadImg(await store.urlOf(p.full)); const back = h('canvas', {width: 48, height: 48}); const k = Math.max(48 / im.naturalWidth, 48 / im.naturalHeight); back.getContext('2d').drawImage(im, (48 - im.naturalWidth * k) / 2, (48 - im.naturalHeight * k) / 2, im.naturalWidth * k, im.naturalHeight * k); this.img.set(p.id, {im, back}); }));
      this.buf = o.music === 'own' ? this.own : M ? await renderMusic(o.music, t) : null;
      this.key = key;
    }
    try { await Promise.all([document.fonts.load('800 80px "Bricolage Grotesque"'), document.fonts.load('500 24px "DM Mono"')]); } catch (e){}
    return this.tl;
  },
  focal(p){ const f = p.faces || []; if (!f.length) return [.5, .45]; return [f.reduce((s, x) => s + x.b[0] + x.b[2] / 2, 0) / f.length, f.reduce((s, x) => s + x.b[1] + x.b[3] / 2, 0) / f.length]; },
  photo(c, W, H, s, u, zm){
    const {im, back} = this.img.get(s.p.id), iw = im.naturalWidth, ih = im.naturalHeight, cover = Math.max(W / iw, H / ih), keep = (W * H) / (iw * ih * cover * cover), dir = s.i % 2 ? 1 - u : u;
    if (keep < .45){
      c.imageSmoothingQuality = 'high'; c.drawImage(back, 0, 0, W, H); c.fillStyle = 'rgba(8,9,10,.5)'; c.fillRect(0, 0, W, H);
      const k = Math.min(W / iw, H / ih) * (1 + .05 * dir) * zm, w = iw * k, hh = ih * k, x = (W - w) / 2 + (s.i % 2 ? -1 : 1) * (u - .5) * W * .03, y = (H - hh) / 2;
      c.shadowColor = 'rgba(0,0,0,.5)'; c.shadowBlur = 40; c.drawImage(im, x, y, w, hh); c.shadowBlur = 0;
    } else {
      const k = cover * (1.05 + .11 * dir) * zm, w = iw * k, hh = ih * k, [fx, fy] = this.focal(s.p);
      c.drawImage(im, clamp(W / 2 - fx * w, W - w, 0), clamp(H / 2 - fy * hh, H - hh, 0), w, hh);
    }
  },
  lines(c, text, maxW){ const out = []; let line = ''; for (const w of text.split(/\s+/)){ const t = line ? line + ' ' + w : w; if (c.measureText(t).width > maxW && line){ out.push(line); line = w; } else line = t; } if (line) out.push(line); return out; },
  seg(c, W, H, s, t, alpha, dx, zm){
    const u = (t - s.t0) / (s.t1 - s.t0), tl = this.tl, U = Math.min(W, H) / 720, pad = 44 * U, o = this.opts;
    c.save(); c.globalAlpha = alpha; if (dx){ c.translate(dx, 0); c.beginPath(); c.rect(0, 0, W, H); c.clip(); }
    this.photo(c, W, H, s, u, zm || 1);
    const title = (o.title || S.trip?.name || 'Our trip').trim();
    if (s.kind === 'photo'){
      const g = c.createLinearGradient(0, H * .62, 0, H); g.addColorStop(0, 'rgba(0,0,0,0)'); g.addColorStop(1, 'rgba(0,0,0,.72)'); c.fillStyle = g; c.fillRect(0, H * .62, W, H * .38);
      c.fillStyle = '#f0b429'; c.font = `500 ${20 * U}px "DM Mono", monospace`; c.textBaseline = 'top'; c.fillText(`▸ ${String(s.i).padStart(2, '0')} / ${String(tl.n - 1).padStart(2, '0')}`, pad, pad);
      if (o.captions){
        const ms = s.p.takenAt || s.p.at, day = Math.floor((new Date(ms).setHours(0, 0, 0, 0) - tl.d0) / 864e5) + 1, k = ease(clamp(u * 5, 0, 1));
        c.globalAlpha = alpha * k; c.textBaseline = 'alphabetic'; c.fillStyle = '#fff'; c.font = `800 ${54 * U}px "Bricolage Grotesque", sans-serif`;
        c.fillText('Day ' + day, pad, H - pad - 34 * U + (1 - k) * 16);
        c.font = `500 ${20 * U}px "DM Mono", monospace`; c.fillStyle = 'rgba(255,255,255,.85)';
        c.fillText((new Date(ms).toLocaleDateString(undefined, {weekday: 'short', day: 'numeric', month: 'short'}) + ' · shot by ' + nameOf(s.p.by)).toUpperCase(), pad, H - pad + (1 - k) * 16);
      }
    } else {
      c.fillStyle = s.kind === 'title' ? 'rgba(8,9,10,.5)' : 'rgba(8,9,10,.72)'; c.fillRect(0, 0, W, H);
      const k = ease(clamp(u * 3, 0, 1)); c.globalAlpha = alpha * k; c.textBaseline = 'alphabetic';
      const size = (W > H ? 92 : 104) * U; c.font = `800 ${size}px "Bricolage Grotesque", sans-serif`; c.fillStyle = '#fff';
      const text = s.kind === 'title' ? title : 'Until next time', ls = this.lines(c, text, W - pad * 2), y0 = H * .56 - (ls.length - 1) * size * .5 + (1 - k) * 30;
      ls.forEach((l, i) => c.fillText(l, pad, y0 + i * size * .98));
      c.font = `500 ${22 * U}px "DM Mono", monospace`; c.fillStyle = '#f0b429';
      const sub = s.kind === 'title' ? [S.trip?.place, tl.range].filter(Boolean).join(' · ') : `${title} · ${plural(tl.pool, 'photo')} · ${plural(tl.people, 'photographer')}`;
      this.lines(c, sub.toUpperCase(), W - pad * 2).forEach((l, i) => c.fillText(l, pad, y0 + (ls.length - 1) * size * .98 + 46 * U + i * 30 * U));
      c.strokeStyle = '#ff4a32'; c.lineWidth = 7 * U; c.beginPath(); c.ellipse(pad + 34 * U, y0 - (ls.length ? size : 0) - 34 * U, 34 * U, 24 * U, -.3, .3, Math.PI * 2 * clamp(u * 2.2, 0, 1) + .3); c.stroke();
    }
    c.restore();
  },
  draw(c, W, H, t){
    const segs = this.tl.segs; t = clamp(t, 0, this.tl.total - .001);
    const i = segs.findIndex(s => t < s.t1), s = segs[i], dt = t - s.t0, X = .38;
    c.fillStyle = '#0b0c0d'; c.fillRect(0, 0, W, H);
    if (i > 0 && dt < X){
      const k = ease(dt / X), mode = i % 3; this.seg(c, W, H, segs[i - 1], t, 1, 0, 1);
      if (mode === 1) this.seg(c, W, H, s, t, 1, (1 - k) * W, 1); else if (mode === 2) this.seg(c, W, H, s, t, k, 0, 1 + (1 - k) * .22); else this.seg(c, W, H, s, t, k, 0, 1);
    } else this.seg(c, W, H, s, t, 1, 0, 1);
  },
  stop(){
    cancelAnimationFrame(this.raf); this.playing = false;
    try { this.src?.stop(); } catch (e){} this.src = null;
    if (this.rec && this.rec.state !== 'inactive') { this.rec.onstop = null; try { this.rec.stop(); } catch (e){} } this.rec = null;
  },
  async play(record){
    const cv = $('#reel-canvas'), status = $('#reel-status'), bar = $('#reel-prog');
    if (!cv) return; this.stop(); this.setBusy(true); status.textContent = 'Getting the cut ready…';
    // the audio context must start inside the click
    try { this.ac ||= new (window.AudioContext || window.webkitAudioContext)(); await this.ac.resume(); } catch (e){ this.ac = null; }
    let tl; try { tl = await this.prepare(); } catch (e){ status.textContent = e.message === 'empty' ? 'No photos to cut from. Add photos or change who the reel is about.' : "Couldn't load the photos. Try again."; this.setBusy(false); return; }
    const [W, H] = SHAPES[this.opts.shape]; cv.width = W; cv.height = H; cv.hidden = false; $('#reel-video').hidden = true;
    const c = cv.getContext('2d'), ac = this.ac; let dest = null, chunks = [], mime = '';
    this.draw(c, W, H, 0);
    if (record){
      if (!window.MediaRecorder || !cv.captureStream){ status.textContent = "This browser can't record video. Try Chrome, Edge or Safari."; this.setBusy(false); return; }
      mime = ['video/mp4;codecs=avc1.42E01E,mp4a.40.2', 'video/mp4;codecs=avc1,mp4a.40.2', 'video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm', 'video/mp4'].find(m => MediaRecorder.isTypeSupported(m)) || '';
      const tracks = [...cv.captureStream(30).getVideoTracks()];
      if (this.buf && ac){ dest = ac.createMediaStreamDestination(); tracks.push(...dest.stream.getAudioTracks()); }
      try { this.rec = new MediaRecorder(new MediaStream(tracks), {mimeType: mime || undefined, videoBitsPerSecond: 6e6}); }
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
          status.textContent = `Video ready · ${Math.round(tl.total)} s · ${(this.out.blob.size / 1048576).toFixed(1)} MB`; this.setBusy(false); this.rec = null;
          saveFile(this.out.name, this.out.blob);
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
  setBusy(b){ document.querySelectorAll('[data-reel-go]').forEach(el => el.disabled = b); }
};
function viewReel(){
  const o = Reel.opts, ppl = peopleList().filter(e => e.count), me = myPerson();
  if (o.who !== 'all' && !ppl.some(e => e.id === o.who)) o.who = 'all';
  const seg = (key, choices) => h('div', {class: 'seg', role: 'group'}, choices.map(([v, label]) => h('button', {type: 'button', 'aria-pressed': String(o[key] === v), onclick: e => { o[key] = v; e.currentTarget.parentNode.querySelectorAll('button').forEach(b => b.setAttribute('aria-pressed', String(b === e.currentTarget))); if (key === 'shape') sizeCanvas(); }}, label)));
  const [W, H] = SHAPES[o.shape];
  const sizeCanvas = () => { if (Reel.playing) return; const cv = $('#reel-canvas'), [w, hh] = SHAPES[o.shape]; cv.width = w; cv.height = hh; poster(); };
  const poster = async () => { try { await Reel.prepare(); const cv = $('#reel-canvas'); if (cv && !Reel.playing) Reel.draw(cv.getContext('2d'), cv.width, cv.height, .9); $('#reel-status').textContent = `${plural(Reel.tl.n, 'photo')} · ${Math.round(Reel.tl.total)} s`; } catch (e){ const st = $('#reel-status'); if (st) st.textContent = 'Add photos to cut a reel.'; } };
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
        h('option', {value: 'all'}, 'Everyone'), ppl.map(e => h('option', {value: e.id, selected: o.who === e.id || null}, (e.id === me ? 'Me' : personLabel(e)) + ` (${e.count})`)))),
      h('div', {class: 'field'}, h('label', null, 'Length'), seg('len', [[15, '15 s'], [30, '30 s'], [45, '45 s'], [60, '60 s']])),
      h('div', {class: 'field'}, h('label', null, 'Shape'), seg('shape', [['tall', 'Tall 9:16'], ['square', 'Square'], ['wide', 'Wide 16:9']])),
      h('div', {class: 'field'}, h('label', null, 'Music'), seg('music', [...Object.entries(MUSIC).map(([k, m]) => [k, m.label]), ...(Reel.own ? [['own', Reel.ownName.slice(0, 18)]] : []), ['none', 'No music']]),
        h('div', null, h('button', {class: 'btn small quiet', type: 'button', onclick: () => $('#file-audio').click()}, 'Use my own track'))),
      h('label', {class: 'check', for: 'reel-cap'}, h('input', {type: 'checkbox', id: 'reel-cap', checked: o.captions, onchange: e => { o.captions = e.target.checked; poster(); }}), 'Day and photographer captions'),
      h('div', {class: 'row'},
        h('button', {class: 'btn', type: 'button', 'data-reel-go': 1, onclick: () => Reel.play(false)}, 'Preview'),
        h('button', {class: 'btn primary', type: 'button', 'data-reel-go': 1, onclick: () => Reel.play(true)}, 'Make the video'),
        h('button', {class: 'btn quiet', type: 'button', id: 'reel-stop', hidden: true, onclick: () => { Reel.stop(); Reel.setBusy(false); $('#reel-stop').hidden = true; $('#reel-status').textContent = 'Stopped'; }}, 'Stop'),
        h('button', {class: 'btn', type: 'button', id: 'reel-save', hidden: true, onclick: () => Reel.out && saveFile(Reel.out.name, Reel.out.blob)}, 'Save video again')),
      h('p', {class: 'note'}, 'The video records in real time, so a 30 second reel takes 30 seconds. Keep this tab in front while it records. The three built-in tracks are generated here and are free to post.')));
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
document.addEventListener('visibilitychange', () => { if (!document.hidden && A.key) pull(false).catch(() => {}); });
if (!window.crypto?.subtle) $('#main').replaceChildren(h('div', {class: 'panel'}, h('h2', {class: 'sect'}, 'Open this page over https'), h('p', null, 'Groupflicks encrypts photos in the browser, which only works on a secure (https) address.')));
else { route(); Face.init(); }
if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
