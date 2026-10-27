// Shootsy API — plain Node http server, no framework, no npm dependencies.
// Real SQLite database (node:sqlite), real password hashing, real token auth.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { URL } = require('node:url');
const db = require('./db');
const { hashPassword, verifyPassword, newToken, readJsonBody, send } = require('./utils');

const payments = require('./payments');
require('./backup');

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

// ---------- email notifications (via Resend; needs RESEND_API_KEY on the server) ----------

const mailer = require('./mailer');

db.exec(`CREATE TABLE IF NOT EXISTS password_resets (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
)`);

// Simple in-memory limiter: max 5 reset requests per email and per IP per hour.
const resetHits = new Map();
function tooMany(key) {
  const now = Date.now();
  const arr = (resetHits.get(key) || []).filter(t => now - t < 3600_000);
  arr.push(now); resetHits.set(key, arr);
  return arr.length > 5;
}
const sha = t => crypto.createHash('sha256').update(t).digest('hex');

const { escHtml, MAIL_FROM, sendEmail, notifyOwner } = mailer;

function welcomeEmail(name, role) {
  const first = escHtml(String(name || '').trim().split(/\s+/)[0] || 'there');
  const site = 'https://shootsy.co.uk/app.html';
  const nextStep = role === 'creator'
    ? `<p style="margin:0 0 14px">Here's your to-do list so clients can find you:</p>
       <ul style="margin:0 0 18px;padding-left:20px">
         <li>Add your bio, your rate and your style (portrait, events, food and so on)</li>
         <li>Upload a few of your best photos</li>
         <li>Block out any days you're busy so you only get requests that work</li>
       </ul>`
    : `<p style="margin:0 0 14px">Ready to find your photographer or videographer? Pick the kind of shoot you want, check out their work and ratings, save your favourites, and chat before you book.</p>`;
  const cta = role === 'creator' ? 'Set up my profile' : 'Find a creator';
  const html = `<div style="background:#FDF1F5;padding:24px 12px;font-family:Arial,Helvetica,sans-serif;color:#170F26">
    <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:20px;overflow:hidden;border:1px solid #F6DCE7">
      <div style="background:#E22E72;padding:22px 26px;color:#ffffff;font-size:26px;font-weight:bold">Shootsy</div>
      <div style="padding:26px;font-size:15px;line-height:1.6">
        <h2 style="margin:0 0 12px;font-size:22px">Welcome, ${first}!</h2>
        <p style="margin:0 0 14px">Thanks so much for joining Shootsy. You're one of our very first members, and that really means a lot.</p>
        ${nextStep}
        <p style="margin:0 0 22px"><a href="${site}" style="background:#E22E72;color:#ffffff;text-decoration:none;padding:12px 22px;border-radius:999px;font-weight:bold;display:inline-block">${cta}</a></p>
        <p style="margin:0 0 4px">Got a question or an idea? Just reply to this email. It comes straight to me.</p>
        <p style="margin:14px 0 0">Daisy x<br><span style="color:#3E3352">Founder, Shootsy</span></p>
      </div>
    </div>
    <p style="text-align:center;font-size:12px;color:#3E3352;margin:14px 0 0">You're getting this because you created a Shootsy account.</p>
  </div>`;
  return { subject: `Welcome to Shootsy, ${String(name || '').trim().split(/\s+/)[0] || 'there'}!`, html };
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

  try {
    const counts = db.prepare("SELECT role, COUNT(*) AS n FROM users GROUP BY role").all();
    const total = counts.reduce((a, r) => a + r.n, 0);
    const byRole = counts.map(r => `${r.n} ${r.role}${r.n === 1 ? '' : 's'}`).join(', ');
    notifyOwner(
      `New Shootsy ${role}: ${name}`,
      `<h2>New ${escHtml(role)} signed up</h2>` +
      `<p><strong>Name:</strong> ${escHtml(name)}<br>` +
      `<strong>Email:</strong> ${escHtml(email)}<br>` +
      `<strong>City:</strong> ${escHtml(city || 'not given')}<br>` +
      `<strong>Role:</strong> ${escHtml(role)}</p>` +
      `<p>Total users now: ${total} (${escHtml(byRole)})</p>`
    );
  } catch (e) { console.error('Notify error:', e.message); }

  // Thank-you email to the new user (only once a verified sending domain is configured).
  try {
    if (!/resend\.dev/i.test(MAIL_FROM()) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const w = welcomeEmail(name, role);
      sendEmail(email, w.subject, w.html, { reply_to: 'hello@shootsy.co.uk' });
    }
  } catch (e) { console.error('Welcome email error:', e.message); }
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

// POST /api/forgot  { email }  -> always the same reply, so it can't be used to find out who has an account
async function handleForgot(req, res) {
  const body = await readJsonBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  send(res, 200, { ok: true });
  try {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
    if (tooMany('e:' + email) || tooMany('i:' + ip)) return;
    const user = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(email);
    if (!user || !mailer.canEmailUsers()) return;
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?,?,?)')
      .run(sha(token), user.id, new Date(Date.now() + 3600_000).toISOString());
    const link = mailer.SITE() + '/app.html?reset=' + token;
    mailer.mailUser(user.id, 'Reset your Shootsy password', {
      heading: 'Reset your password',
      paragraphs: [
        `Hi ${escHtml(mailer.first(user.name))}, we got a request to reset your Shootsy password. Click the button below to choose a new one. The link works for 1 hour.`,
        'If you did not ask for this, you can ignore this email. Your password has not been changed.',
      ],
      ctaText: 'Choose a new password', ctaUrl: link,
      footer: 'You are getting this because someone asked to reset the password on your Shootsy account.',
    });
  } catch (e) { console.error('Forgot error:', e.message); }
}

// POST /api/reset  { token, password }
async function handleReset(req, res) {
  const body = await readJsonBody(req);
  const token = String(body.token || '');
  const password = String(body.password || '');
  if (password.length < 8) return send(res, 400, { error: 'Password must be at least 8 characters' });
  const row = db.prepare('SELECT * FROM password_resets WHERE token_hash = ?').get(sha(token));
  if (!row || row.used || new Date(row.expires_at) < new Date()) {
    return send(res, 400, { error: 'This reset link has expired or was already used. Please request a new one.' });
  }
  const { hash, salt } = hashPassword(password);
  db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').run(hash, salt, row.user_id);
  db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ?').run(row.user_id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.user_id); // log out everywhere
  const newTok = newToken();
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)').run(newTok, row.user_id, new Date().toISOString());
  send(res, 200, { token: newTok, user: publicUser(getUserById(row.user_id)) });
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

const crypto = require('node:crypto');

// Admin key comes from the X-Admin-Key header (preferred) or ?adminKey= (older).
function isAdmin(req, query) {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) return false;
  const given = String(req.headers['x-admin-key'] || (query && query.get('adminKey')) || '');
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(adminKey).digest();
  return crypto.timingSafeEqual(a, b);
}

function adminUserRows() {
  return db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.city, u.created_at,
           p.bio, p.rate, p.photos, p.verified
    FROM users u LEFT JOIN creator_profiles p ON p.user_id = u.id
    ORDER BY u.created_at DESC
  `).all().map(r => {
    let photoCount = 0;
    try { photoCount = JSON.parse(r.photos || '[]').length; } catch (e) {}
    return {
      id: r.id, name: r.name, email: r.email, role: r.role, city: r.city || '',
      signedUp: r.created_at,
      profileDone: r.role === 'creator' ? !!(r.bio && r.rate > 0 && photoCount > 0) : null,
      verified: r.role === 'creator' ? !!r.verified : null,
    };
  });
}

// Stops spreadsheet programs treating a cell as a formula.
function csvCell(v) {
  let s = String(v === null || v === undefined ? '' : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

async function failDelay() { await new Promise(r => setTimeout(r, 800)); }

async function handleAdminUsers(req, res, query) {
  if (!isAdmin(req, query)) { await failDelay(); return send(res, 403, { error: 'Not authorized' }); }
  send(res, 200, { users: adminUserRows() });
}

async function handleAdminUsersCsv(req, res, query) {
  if (!isAdmin(req, query)) { await failDelay(); return send(res, 403, { error: 'Not authorized' }); }
  const header = ['Name', 'Email', 'Role', 'City', 'Signed up', 'Profile complete', 'Verified'];
  const lines = [header.map(csvCell).join(',')].concat(adminUserRows().map(u => [
    u.name, u.email, u.role, u.city, u.signedUp,
    u.profileDone === null ? '' : (u.profileDone ? 'yes' : 'no'),
    u.verified === null ? '' : (u.verified ? 'yes' : 'no'),
  ].map(csvCell).join(',')));
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="shootsy-signups.csv"',
    'Cache-Control': 'no-store',
  });
  res.end(lines.join('\r\n'));
}

async function handleSetVerified(req, res, query) {
  if (!isAdmin(req, query)) { await failDelay(); return send(res, 403, { error: 'Not authorized' }); }
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
  mailer.bookingRequested(db.prepare('SELECT * FROM bookings WHERE id = ?').get(info.lastInsertRowid));
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
    paymentStatus: b.payment_status || 'unpaid',
    pricePence: b.price_pence || 0,
    completedAt: b.completed_at || null,
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
  if (status === 'completed') {
    db.prepare('UPDATE bookings SET status = ?, completed_at = ? WHERE id = ?').run(status, new Date().toISOString(), id);
  } else {
    db.prepare('UPDATE bookings SET status = ? WHERE id = ?').run(status, id);
  }
  send(res, 200, getBookingView(id));
  const updated = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (status === 'accepted' || status === 'declined') mailer.bookingAnswered(updated, status);
  else if (status === 'cancelled') mailer.bookingCancelled(updated);
  else if (status === 'completed') mailer.bookingCompleted(updated);
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

  if (pathname === '/admin') return serveStatic(req, res, '/admin.html');

  if (!pathname.startsWith('/api/')) {
    return serveStatic(req, res, pathname);
  }

  try {
    const user = authenticate(req);

    if (method === 'POST' && pathname === '/api/signup') return await handleSignup(req, res);
    if (method === 'POST' && pathname === '/api/login') return await handleLogin(req, res);
    if (method === 'POST' && pathname === '/api/forgot') return await handleForgot(req, res);
    if (method === 'POST' && pathname === '/api/reset') return await handleReset(req, res);
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

    if (method === 'POST' && pathname === '/api/stripe/webhook') return await payments.handleWebhook(req, res);
    if (method === 'POST' && pathname === '/api/stripe/connect') return await payments.handleConnect(req, res, user);
    if (method === 'GET' && pathname === '/api/stripe/status') return await payments.handleStatus(req, res, user);
    if (method === 'POST' && (m = pathname.match(/^\/api\/bookings\/(\d+)\/pay$/))) return await payments.handlePay(req, res, user, Number(m[1]));
    if (method === 'POST' && (m = pathname.match(/^\/api\/bookings\/(\d+)\/confirm$/))) return await payments.handleConfirm(req, res, user, Number(m[1]));

    if (method === 'GET' && pathname === '/api/favorites') return handleListFavorites(req, res, user);
    if (method === 'POST' && pathname === '/api/favorites') return await handleAddFavorite(req, res, user);
    if (method === 'DELETE' && (m = pathname.match(/^\/api\/favorites\/(\d+)$/))) return handleRemoveFavorite(req, res, user, Number(m[1]));

    if (method === 'GET' && (m = pathname.match(/^\/api\/availability\/(\d+)$/))) return handleListAvailability(req, res, Number(m[1]));
    if (method === 'POST' && pathname === '/api/availability') return await handleAddAvailability(req, res, user);
    if (method === 'DELETE' && (m = pathname.match(/^\/api\/availability\/(\d+)$/))) return handleDeleteAvailability(req, res, user, Number(m[1]));

    if (method === 'POST' && pathname === '/api/admin/verify') return await handleSetVerified(req, res, url.searchParams);
    if (method === 'GET' && pathname === '/api/admin/users') return await handleAdminUsers(req, res, url.searchParams);
    if (method === 'GET' && pathname === '/api/admin/users.csv') return await handleAdminUsersCsv(req, res, url.searchParams);

    send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    send(res, 500, { error: err.message || 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Shootsy API + web app running at http://localhost:${PORT}`);
});
