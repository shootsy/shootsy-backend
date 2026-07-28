// Shootsy backend — zero npm dependencies (Node 22.5+ built-ins only).
// Run with: node server.js
// Listens on PORT env var or 3000.

const http = require('node:http');
const crypto = require('node:crypto');
const db = require('./db');

const PORT = process.env.PORT || 3000;

// ---------- helpers ----------

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(check));
}

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

function sendJSON(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  });
  res.end(data);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = '';
    req.on('data', (c) => (chunks += c));
    req.on('end', () => {
      if (!chunks) return resolve({});
      try {
        resolve(JSON.parse(chunks));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function getAuthUser(req) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const row = db
    .prepare('SELECT user_id FROM sessions WHERE token = ?')
    .get(token);
  if (!row) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
}

function publicUser(u) {
  if (!u) return null;
  return { id: u.id, email: u.email, role: u.role, name: u.name, city: u.city };
}

function creatorWithProfile(userRow) {
  const profile = db
    .prepare('SELECT * FROM creator_profiles WHERE user_id = ?')
    .get(userRow.id) || {};
  return {
    ...publicUser(userRow),
    bio: profile.bio || '',
    contentTypes: profile.content_types || '',
    portfolioLinks: JSON.parse(profile.portfolio_links || '[]'),
    rate: profile.rate || '',
    avgRating: profile.avg_rating || 0,
    reviewCount: profile.review_count || 0,
  };
}

// ---------- route handlers ----------

async function handleSignup(req, res) {
  const body = await readBody(req);
  const { email, password, role, name, city } = body;
  if (!email || !password || !role || !name) {
    return sendJSON(res, 400, { error: 'email, password, role, name are required' });
  }
  if (!['client', 'creator'].includes(role)) {
    return sendJSON(res, 400, { error: "role must be 'client' or 'creator'" });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return sendJSON(res, 409, { error: 'email already registered' });

  const password_hash = hashPassword(password);
  const info = db
    .prepare(
      'INSERT INTO users (email, password_hash, role, name, city) VALUES (?, ?, ?, ?, ?)'
    )
    .run(email, password_hash, role, name, city || null);
  const userId = Number(info.lastInsertRowid);

  if (role === 'creator') {
    db.prepare('INSERT INTO creator_profiles (user_id) VALUES (?)').run(userId);
  }

  const token = makeToken();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, userId);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  sendJSON(res, 201, { token, user: publicUser(user) });
}

async function handleLogin(req, res) {
  const body = await readBody(req);
  const { email, password } = body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return sendJSON(res, 401, { error: 'invalid email or password' });
  }
  const token = makeToken();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
  sendJSON(res, 200, { token, user: publicUser(user) });
}

function handleListCreators(req, res, query) {
  let rows = db.prepare("SELECT * FROM users WHERE role = 'creator'").all();
  const search = (query.get('search') || '').toLowerCase();
  const city = (query.get('city') || '').toLowerCase();
  let creators = rows.map(creatorWithProfile);
  if (search) {
    creators = creators.filter(
      (c) =>
        c.name.toLowerCase().includes(search) ||
        c.contentTypes.toLowerCase().includes(search) ||
        c.bio.toLowerCase().includes(search)
    );
  }
  if (city) {
    creators = creators.filter((c) => (c.city || '').toLowerCase().includes(city));
  }
  sendJSON(res, 200, { creators });
}

function handleGetCreator(req, res, id) {
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'creator'").get(id);
  if (!user) return sendJSON(res, 404, { error: 'creator not found' });
  sendJSON(res, 200, { creator: creatorWithProfile(user) });
}

async function handleUpdateMe(req, res, currentUser) {
  if (currentUser.role !== 'creator') {
    return sendJSON(res, 403, { error: 'only creators have a profile to edit' });
  }
  const body = await readBody(req);
  const { bio, contentTypes, portfolioLinks, rate } = body;
  db.prepare(
    `UPDATE creator_profiles SET
       bio = COALESCE(?, bio),
       content_types = COALESCE(?, content_types),
       portfolio_links = COALESCE(?, portfolio_links),
       rate = COALESCE(?, rate)
     WHERE user_id = ?`
  ).run(
    bio ?? null,
    contentTypes ?? null,
    portfolioLinks ? JSON.stringify(portfolioLinks) : null,
    rate ?? null,
    currentUser.id
  );
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(currentUser.id);
  sendJSON(res, 200, { creator: creatorWithProfile(user) });
}

async function handleCreateBooking(req, res, currentUser) {
  if (currentUser.role !== 'client') {
    return sendJSON(res, 403, { error: 'only clients can request bookings' });
  }
  const body = await readBody(req);
  const { creatorId, shootDate, details } = body;
  const creator = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'creator'").get(creatorId);
  if (!creator) return sendJSON(res, 404, { error: 'creator not found' });

  const info = db
    .prepare(
      'INSERT INTO bookings (client_id, creator_id, shoot_date, details) VALUES (?, ?, ?, ?)'
    )
    .run(currentUser.id, creatorId, shootDate || null, details || null);
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(Number(info.lastInsertRowid));
  sendJSON(res, 201, { booking });
}

function handleListBookings(req, res, currentUser) {
  const rows = db
    .prepare(
      'SELECT * FROM bookings WHERE client_id = ? OR creator_id = ? ORDER BY created_at DESC'
    )
    .all(currentUser.id, currentUser.id);
  sendJSON(res, 200, { bookings: rows });
}

function getBookingForUser(id, currentUser) {
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (!booking) return null;
  if (booking.client_id !== currentUser.id && booking.creator_id !== currentUser.id) {
    return undefined; // not authorized
  }
  return booking;
}

function handleBookingAction(req, res, currentUser, id, action) {
  const booking = getBookingForUser(id, currentUser);
  if (booking === null) return sendJSON(res, 404, { error: 'booking not found' });
  if (booking === undefined) return sendJSON(res, 403, { error: 'not your booking' });

  if (action === 'accept' || action === 'decline') {
    if (currentUser.id !== booking.creator_id) {
      return sendJSON(res, 403, { error: 'only the creator can respond to this request' });
    }
    const newStatus = action === 'accept' ? 'accepted' : 'declined';
    db.prepare('UPDATE bookings SET status = ? WHERE id = ?').run(newStatus, id);
  } else if (action === 'complete') {
    if (booking.status !== 'accepted') {
      return sendJSON(res, 400, { error: 'booking must be accepted before it can be completed' });
    }
    db.prepare("UPDATE bookings SET status = 'completed' WHERE id = ?").run(id);
  }
  const updated = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  sendJSON(res, 200, { booking: updated });
}

async function handlePostMessage(req, res, currentUser, bookingId) {
  const booking = getBookingForUser(bookingId, currentUser);
  if (booking === null) return sendJSON(res, 404, { error: 'booking not found' });
  if (booking === undefined) return sendJSON(res, 403, { error: 'not your booking' });

  const body = await readBody(req);
  if (!body.text) return sendJSON(res, 400, { error: 'text is required' });

  const info = db
    .prepare('INSERT INTO messages (booking_id, sender_id, text) VALUES (?, ?, ?)')
    .run(bookingId, currentUser.id, body.text);
  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(Number(info.lastInsertRowid));
  sendJSON(res, 201, { message });
}

function handleListMessages(req, res, currentUser, bookingId) {
  const booking = getBookingForUser(bookingId, currentUser);
  if (booking === null) return sendJSON(res, 404, { error: 'booking not found' });
  if (booking === undefined) return sendJSON(res, 403, { error: 'not your booking' });

  const rows = db
    .prepare('SELECT * FROM messages WHERE booking_id = ? ORDER BY created_at ASC')
    .all(bookingId);
  sendJSON(res, 200, { messages: rows });
}

async function handlePostReview(req, res, currentUser, bookingId) {
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId);
  if (!booking) return sendJSON(res, 404, { error: 'booking not found' });
  if (booking.client_id !== currentUser.id) {
    return sendJSON(res, 403, { error: 'only the client can leave a review' });
  }
  if (booking.status !== 'completed') {
    return sendJSON(res, 400, { error: 'booking must be completed before it can be reviewed' });
  }
  const existing = db.prepare('SELECT id FROM reviews WHERE booking_id = ?').get(bookingId);
  if (existing) return sendJSON(res, 409, { error: 'this booking already has a review' });

  const body = await readBody(req);
  const rating = Number(body.rating);
  if (!rating || rating < 1 || rating > 5) {
    return sendJSON(res, 400, { error: 'rating must be an integer 1-5' });
  }

  db.prepare(
    'INSERT INTO reviews (booking_id, creator_id, client_id, rating, text) VALUES (?, ?, ?, ?, ?)'
  ).run(bookingId, booking.creator_id, currentUser.id, rating, body.text || '');

  // Roll up the new average rating onto the creator's profile.
  const agg = db
    .prepare('SELECT AVG(rating) as avg, COUNT(*) as count FROM reviews WHERE creator_id = ?')
    .get(booking.creator_id);
  db.prepare(
    'UPDATE creator_profiles SET avg_rating = ?, review_count = ? WHERE user_id = ?'
  ).run(agg.avg, agg.count, booking.creator_id);

  sendJSON(res, 201, { ok: true, avgRating: agg.avg, reviewCount: agg.count });
}

// ---------- router ----------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const parts = url.pathname.split('/').filter(Boolean); // e.g. ['api','bookings','3','accept']

  if (req.method === 'OPTIONS') {
    return sendJSON(res, 204, {});
  }

  try {
    if (parts[0] !== 'api') return sendJSON(res, 404, { error: 'not found' });

    // Public routes
    if (parts[1] === 'signup' && req.method === 'POST') return await handleSignup(req, res);
    if (parts[1] === 'login' && req.method === 'POST') return await handleLogin(req, res);
    if (parts[1] === 'creators' && req.method === 'GET' && parts.length === 2)
      return handleListCreators(req, res, url.searchParams);
    if (parts[1] === 'creators' && req.method === 'GET' && parts.length === 3)
      return handleGetCreator(req, res, Number(parts[2]));

    // Everything past this point requires auth
    const currentUser = getAuthUser(req);
    if (!currentUser) return sendJSON(res, 401, { error: 'missing or invalid auth token' });

    if (parts[1] === 'creators' && parts[2] === 'me' && req.method === 'PUT')
      return await handleUpdateMe(req, res, currentUser);

    if (parts[1] === 'bookings' && parts.length === 2 && req.method === 'POST')
      return await handleCreateBooking(req, res, currentUser);
    if (parts[1] === 'bookings' && parts.length === 2 && req.method === 'GET')
      return handleListBookings(req, res, currentUser);

    if (parts[1] === 'bookings' && parts.length === 4 && parts[3] === 'messages') {
      const bookingId = Number(parts[2]);
      if (req.method === 'POST') return await handlePostMessage(req, res, currentUser, bookingId);
      if (req.method === 'GET') return handleListMessages(req, res, currentUser, bookingId);
    }

    if (parts[1] === 'bookings' && parts.length === 4 && ['accept', 'decline', 'complete'].includes(parts[3]) && req.method === 'POST') {
      return handleBookingAction(req, res, currentUser, Number(parts[2]), parts[3]);
    }

    if (parts[1] === 'bookings' && parts.length === 4 && parts[3] === 'review' && req.method === 'POST') {
      return await handlePostReview(req, res, currentUser, Number(parts[2]));
    }

    return sendJSON(res, 404, { error: 'not found' });
  } catch (err) {
    console.error(err);
    return sendJSON(res, 500, { error: 'server error', detail: String(err.message || err) });
  }
});

server.listen(PORT, () => {
  console.log(`Shootsy backend listening on http://localhost:${PORT}`);
});