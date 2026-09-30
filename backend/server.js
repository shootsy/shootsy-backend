// Shootsy API — plain Node http server, no framework, no npm dependencies.
// Real SQLite database (node:sqlite), real password hashing, real token auth.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const db = require('./db');
const { hashPassword, verifyPassword, newToken, readJsonBody, send } = require('./utils');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// ---------- helpers ----------

function getUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}
function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, email: u.email, role: u.role, name: u.name, city: u.city, created_at: u.created_at };
}
function getCreatorProfile(userId) {
  return db.prepare('SELECT * FROM creator_profiles WHERE user_id = ?').get(userId);
}
function creatorPublic(u, p) {
  return {
    id: u.id,
    name: u.name,
    city: u.city,
    bio: p ? p.bio : '',
    contentType: p ? p.content_type : 'both',
    rate: p ? p.rate : 0,
    portfolio: p ? JSON.parse(p.portfolio || '[]') : [],
    styles: p ? JSON.parse(p.styles || '[]') : [],
    experience: p ? (p.experience || '') : '',
    photos: p ? JSON.parse(p.photos || '[]') : [],
    verified: p ? !!p.verified : false,
    lat: p ? p.lat : null,
    lng: p ? p.lng : null,
    ratingAvg: p ? p.rating_avg : 0,
    ratingCount: p ? p.rating_count : 0,
  };
}

// Distance between two lat/lng points in km (haversine formula).
function distanceKm(lat1, lng1, lat2, lng2) {
  if ([lat1, lng1, lat2, lng2].some(v => v === null || v === undefined || Number.isNaN(v))) return null;
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function authenticate(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return null;
  return getUserById(session.user_id);
}

// ---------- static file serving ----------

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res, pathname) {
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // SPA fallback
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, data2) => {
        if (err2) { res.writeHead(404); res.end('Not found'); return; }
        res.writeHead(200, { 'Content-Type': MIME['.html'] });
        res.end(data2);
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- route handlers ----------

async function handleSignup(req, res) {
  const body = await readJsonBody(req);
  const { email, password, role, name, city } = body;
  if (!email || !password || !role || !name) return send(res, 400, { error: 'email, password, role and name are required' });
  if (!['client', 'creator'].includes(role)) return send(res, 400, { error: 'role must be client or creator' });
  if (getUserByEmail(email)) return send(res, 409, { error: 'An account with that email already exists' });

  const { hash, salt } = hashPassword(password);
  const now = new Date().toISOString();
  const info = db.prepare(
    'INSERT INTO users (email, password_hash, salt, role, name, city, created_at) VALUES (?,?,?,?,?,?,?)'
  ).run(email, hash, salt, role, name, city || '', now);
  const userId = info.lastInsertRowid;

  if (role === 'creator') {
    db.prepare('INSERT INTO creator_profiles (user_id) VALUES (?)').run(userId);
  }

  const token = newToken();
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)').run(token, userId, now);

  send(res, 201, { token, user: publicUser(getUserById(userId)) });
}

async function handleLogin(req, res) {
  const body = await readJsonBody(req);
  const { email, password } = body;
  const user = getUserByEmail(email);
  if (!user || !verifyPassword(password, user.salt, user.password_hash)) {
    return send(res, 401, { error: 'Invalid email or password' });
  }
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)').run(token, user.id, new Date().toISOString());
  send(res, 200, { token, user: publicUser(user) });
}

function handleMe(req, res, user) {
  if (!user) return send(res, 401, { error: 'Not authenticated' });
  const out = publicUser(user);
  if (user.role === 'creator') {
    out.creatorProfile = creatorPublic(user, getCreatorProfile(user.id));
  }
  send(res, 200, out);
}

function handleListCreators(req, res, query) {
  const search = (query.get('q') || '').toLowerCase();
  const type = query.get('type');
  const nearLat = query.get('lat') !== null ? Number(query.get('lat')) : null;
  const nearLng = query.get('lng') !== null ? Number(query.get('lng')) : null;
  let rows = db.prepare(`
    SELECT u.*, p.bio, p.content_type, p.rate, p.portfolio, p.styles, p.experience, p.photos, p.verified, p.lat, p.lng, p.rating_avg, p.rating_count
    FROM users u JOIN creator_profiles p ON p.user_id = u.id
    WHERE u.role = 'creator'
  `).all();
  rows = rows.filter(r => {
    const styles = (() => { try { return JSON.parse(r.styles || '[]'); } catch (e) { return []; } })();
    const matchesSearch = !search
      || r.name.toLowerCase().includes(search)
      || (r.city || '').toLowerCase().includes(search)
      || (r.bio || '').toLowerCase().includes(search)
      || styles.some(s => s.toLowerCase().includes(search));
    const matchesType = !type || type === 'all' || r.content_type === type || r.content_type === 'both';
    return matchesSearch && matchesType;
  });
  let out = rows.map(r => creatorPublic(r, r));
  if (nearLat !== null && nearLng !== null) {
    out = out.map(c => ({ ...c, distanceKm: distanceKm(nearLat, nearLng, c.lat, c.lng) }));
    out.sort((a, b) => {
      if (a.distanceKm === null) return 1;
      if (b.distanceKm === null) return -1;
      return a.distanceKm - b.distanceKm;
    });
  }
  send(res, 200, out);
}

function handleGetCreator(req, res, id) {
  const user = getUserById(id);
  if (!user || user.role !== 'creator') return send(res, 404, { error: 'Creator not found' });
  const profile = getCreatorProfile(id);
  const reviews = db.prepare(`
    SELECT r.*, c.name as client_name FROM reviews r JOIN users c ON c.id = r.client_id WHERE r.creator_id = ? ORDER BY r.created_at DESC
  `).all(id);
  send(res, 200, { ...creatorPublic(user, profile), reviews });
}

async function handleUpdateCreatorProfile(req, res, user) {
  if (!user || user.role !== 'creator') return send(res, 403, { error: 'Creators only' });
  const body = await readJsonBody(req);
  const current = getCreatorProfile(user.id);
  const bio = body.bio ?? current.bio;
  const contentType = body.contentType ?? current.content_type;
  const rate = body.rate ?? current.rate;
  const portfolio = body.portfolio ? JSON.stringify(body.portfolio) : current.portfolio;
  const styles = body.styles ? JSON.stringify(body.styles) : (current.styles || '[]');
  const experience = body.experience ?? (current.experience || '');
  const photos = body.photos ? JSON.stringify(body.photos) : (current.photos || '[]');
  const lat = body.lat ?? current.lat;
  const lng = body.lng ?? current.lng;
  db.prepare('UPDATE creator_profiles SET bio=?, content_type=?, rate=?, portfolio=?, styles=?, experience=?, photos=?, lat=?, lng=? WHERE user_id=?')
    .run(bio, contentType, rate, portfolio, styles, experience, photos, lat, lng, user.id);
  send(res, 200, creatorPublic(user, getCreatorProfile(user.id)));
}

// ---------- favorites ----------

function handleListFavorites(req, res, user) {
  if (!user || user.role !== 'client') return send(res, 403, { error: 'Clients only' });
  const rows = db.prepare(`
    SELECT u.*, p.bio, p.content_type, p.rate, p.portfolio, p.styles, p.experience, p.photos, p.verified, p.lat, p.lng, p.rating_avg, p.rating_count
    FROM favorites f JOIN users u ON u.id = f.creator_id JOIN creator_profiles p ON p.user_id = u.id
    WHERE f.client_id = ? ORDER BY f.created_at DESC
  `).all(user.id);
  send(res, 200, rows.map(r => creatorPublic(r, r)));
}

async function handleAddFavorite(req, res, user) {
  if (!user || user.role !== 'client') return send(res, 403, { error: 'Clients only' });
  const body = await readJsonBody(req);
  const creatorId = Number(body.creatorId);
  const creator = getUserById(creatorId);
  if (!creator || creator.role !== 'creator') return send(res, 400, { error: 'Invalid creator' });
  db.prepare('INSERT OR IGNORE INTO favorites (client_id, creator_id, created_at) VALUES (?,?,?)')
    .run(user.id, creatorId, new Date().toISOString());
  send(res, 201, { ok: true });
}

function handleRemoveFavorite(req, res, user, creatorId) {
  if (!user || user.role !== 'client') return send(res, 403, { error: 'Clients only' });
  db.prepare('DELETE FROM favorites WHERE client_id = ? AND creator_id = ?').run(user.id, creatorId);
  send(res, 200, { ok: true });
}

// ---------- availability ----------

function handleListAvailability(req, res, creatorId) {
  const rows = db.prepare('SELECT * FROM availability_blocks WHERE creator_id = ? ORDER BY start_datetime ASC').all(creatorId);
  send(res, 200, rows.map(r => ({ id: r.id, start: r.start_datetime, end: r.end_datetime, note: r.note })));
}

async function handleAddAvailability(req, res, user) {
  if (!user || user.role !== 'creator') return send(res, 403, { error: 'Creators only' });
  const body = await readJsonBody(req);
  if (!body.start || !body.end) return send(res, 400, { error: 'start and end are required' });
  const info = db.prepare('INSERT INTO availability_blocks (creator_id, start_datetime, end_datetime, note) VALUES (?,?,?,?)')
    .run(user.id, body.start, body.end, body.note || '');
  send(res, 201, { id: info.lastInsertRowid, start: body.start, end: body.end, note: body.note || '' });
}

function handleDeleteAvailability(req, res, user, id) {
  if (!user || user.role !== 'creator') return send(res, 403, { error: 'Creators only' });
  const block = db.prepare('SELECT * FROM availability_blocks WHERE id = ?').get(id);
  if (!block || block.creator_id !== user.id) return send(res, 404, { error: 'Not found' });
  db.prepare('DELETE FROM availability_blocks WHERE id = ?').run(id);
  send(res, 200, { ok: true });
}

// ---------- verification (admin only, via ADMIN_KEY env var) ----------

async function handleSetVerified(req, res, query) {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey || query.get('adminKey') !== adminKey) return send(res, 403, { error: 'Not authorized' });
  const body = await readJsonBody(req);
  const creatorId = Number(body.creatorId);
  const verified = body.verified ? 1 : 0;
  db.prepare('UPDATE creator_profiles SET verified = ? WHERE user_id = ?').run(verified, creatorId);
  send(res, 200, { ok: true });
}

async function handleCreateBooking(req, res, user) {
  if (!user || user.role !== 'client') return send(res, 403, { error: 'Clients only' });
  const body = await readJsonBody(req);
  const { creatorId, datetime, location, notes } = body;
  const creator = getUserById(creatorId);
  if (!creator || creator.role !== 'creator') return send(res, 400, { error: 'Invalid creator' });
  if (!datetime) return send(res, 400, { error: 'datetime is required' });
  const blocked = db.prepare(
    'SELECT id FROM availability_blocks WHERE creator_id = ? AND ? >= start_datetime AND ? < end_datetime'
  ).get(creatorId, datetime, datetime);
  if (blocked) return send(res, 409, { error: 'This creator is unavailable at that time' });
  const now = new Date().toISOString();
  const info = db.prepare(
    'INSERT INTO bookings (client_id, creator_id, session_datetime, location, notes, status, created_at) VALUES (?,?,?,?,?,?,?)'
  ).run(user.id, creatorId, datetime, location || '', notes || '', 'pending', now);
  send(res, 201, getBookingView(info.lastInsertRowid));
}

function getBookingView(id) {
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (!b) return null;
  const client = getUserById(b.client_id);
  const creator = getUserById(b.creator_id);
  return {
    id: b.id,
    status: b.status,
    datetime: b.session_datetime,
    location: b.location,
    notes: b.notes,
    createdAt: b.created_at,
    client: { id: client.id, name: client.name },
    creator: { id: creator.id, name: creator.name },
  };
}

function handleListBookings(req, res, user) {
  if (!user) return send(res, 401, { error: 'Not authenticated' });
  const col = user.role === 'client' ? 'client_id' : 'creator_id';
  const rows = db.prepare(`SELECT id FROM bookings WHERE ${col} = ? ORDER BY created_at DESC`).all(user.id);
  send(res, 200, rows.map(r => getBookingView(r.id)));
}

async function handleUpdateBookingStatus(req, res, user, id) {
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (!booking) return send(res, 404, { error: 'Booking not found' });
  const body = await readJsonBody(req);
  const { status } = body;
  const validTransitions = {
    creator: ['accepted', 'declined', 'completed'],
    client: ['cancelled'],
  };
  if (!user || (user.id !== booking.creator_id && user.id !== booking.client_id)) {
    return send(res, 403, { error: 'Not part of this booking' });
  }
  const allowed = user.id === booking.creator_id ? validTransitions.creator : validTransitions.client;
  if (!allowed.includes(status)) return send(res, 400, { error: `Cannot set status to ${status}` });
  db.prepare('UPDATE bookings SET status = ? WHERE id = ?').run(status, id);
  send(res, 200, getBookingView(id));
}

function assertBookingParticipant(user, booking) {
  return user && (user.id === booking.creator_id || user.id === booking.client_id);
}

function handleListMessages(req, res, user, bookingId) {
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId);
  if (!booking) return send(res, 404, { error: 'Booking not found' });
  if (!assertBookingParticipant(user, booking)) return send(res, 403, { error: 'Not part of this booking' });
  const rows = db.prepare(`
    SELECT m.*, u.name as sender_name FROM messages m JOIN users u ON u.id = m.sender_id
    WHERE m.booking_id = ? ORDER BY m.created_at ASC
  `).all(bookingId);
  send(res, 200, rows);
}

async function handleSendMessage(req, res, user, bookingId) {
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId);
  if (!booking) return send(res, 404, { error: 'Booking not found' });
  if (!assertBookingParticipant(user, booking)) return send(res, 403, { error: 'Not part of this booking' });
  const body = await readJsonBody(req);
  if (!body.text || !body.text.trim()) return send(res, 400, { error: 'text is required' });
  const now = new Date().toISOString();
  const info = db.prepare('INSERT INTO messages (booking_id, sender_id, text, created_at) VALUES (?,?,?,?)')
    .run(bookingId, user.id, body.text.trim(), now);
  const row = db.prepare('SELECT m.*, u.name as sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id = ?').get(info.lastInsertRowid);
  send(res, 201, row);
}

async function handleCreateReview(req, res, user, bookingId) {
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId);
  if (!booking) return send(res, 404, { error: 'Booking not found' });
  if (!user || user.id !== booking.client_id) return send(res, 403, { error: 'Only the client can leave a review' });
  if (booking.status !== 'completed') return send(res, 400, { error: 'Booking must be completed first' });
  const body = await readJsonBody(req);
  const rating = Number(body.rating);
  if (!rating || rating < 1 || rating > 5) return send(res, 400, { error: 'rating must be 1-5' });
  const now = new Date().toISOString();
  try {
    db.prepare('INSERT INTO reviews (booking_id, creator_id, client_id, rating, comment, created_at) VALUES (?,?,?,?,?,?)')
      .run(bookingId, booking.creator_id, user.id, rating, body.comment || '', now);
  } catch (e) {
    return send(res, 409, { error: 'A review already exists for this booking' });
  }
  const agg = db.prepare('SELECT AVG(rating) as avg, COUNT(*) as cnt FROM reviews WHERE creator_id = ?').get(booking.creator_id);
  db.prepare('UPDATE creator_profiles SET rating_avg = ?, rating_count = ? WHERE user_id = ?')
    .run(agg.avg, agg.cnt, booking.creator_id);
  send(res, 201, { ok: true });
}

// ---------- router ----------

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
  const method = req.method;

  if (!pathname.startsWith('/api/')) {
    return serveStatic(req, res, pathname);
  }

  try {
    const user = authenticate(req);

    if (method === 'POST' && pathname === '/api/signup') return await handleSignup(req, res);
    if (method === 'POST' && pathname === '/api/login') return await handleLogin(req, res);
    if (method === 'GET' && pathname === '/api/me') return handleMe(req, res, user);
    if (method === 'GET' && pathname === '/api/creators') return handleListCreators(req, res, url.searchParams);
    if (method === 'PUT' && pathname === '/api/creator-profile') return await handleUpdateCreatorProfile(req, res, user);

    let m;
    if (method === 'GET' && (m = pathname.match(/^\/api\/creators\/(\d+)$/))) return handleGetCreator(req, res, Number(m[1]));

    if (method === 'POST' && pathname === '/api/bookings') return await handleCreateBooking(req, res, user);
    if (method === 'GET' && pathname === '/api/bookings') return handleListBookings(req, res, user);
    if (method === 'PUT' && (m = pathname.match(/^\/api\/bookings\/(\d+)\/status$/))) return await handleUpdateBookingStatus(req, res, user, Number(m[1]));
    if (method === 'GET' && (m = pathname.match(/^\/api\/bookings\/(\d+)\/messages$/))) return handleListMessages(req, res, user, Number(m[1]));
    if (method === 'POST' && (m = pathname.match(/^\/api\/bookings\/(\d+)\/messages$/))) return await handleSendMessage(req, res, user, Number(m[1]));
    if (method === 'POST' && (m = pathname.match(/^\/api\/bookings\/(\d+)\/review$/))) return await handleCreateReview(req, res, user, Number(m[1]));

    if (method === 'GET' && pathname === '/api/favorites') return handleListFavorites(req, res, user);
    if (method === 'POST' && pathname === '/api/favorites') return await handleAddFavorite(req, res, user);
    if (method === 'DELETE' && (m = pathname.match(/^\/api\/favorites\/(\d+)$/))) return handleRemoveFavorite(req, res, user, Number(m[1]));

    if (method === 'GET' && (m = pathname.match(/^\/api\/availability\/(\d+)$/))) return handleListAvailability(req, res, Number(m[1]));
    if (method === 'POST' && pathname === '/api/availability') return await handleAddAvailability(req, res, user);
    if (method === 'DELETE' && (m = pathname.match(/^\/api\/availability\/(\d+)$/))) return handleDeleteAvailability(req, res, user, Number(m[1]));

    if (method === 'POST' && pathname === '/api/admin/verify') return await handleSetVerified(req, res, url.searchParams);

    send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    send(res, 500, { error: err.message || 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Shootsy API + web app running at http://localhost:${PORT}`);
});
