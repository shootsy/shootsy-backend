// Stripe Connect payments for Shootsy. No npm dependency: talks to the Stripe REST API with fetch.
// Model: client pays Shootsy (Checkout), money is held on the platform, and after the client
// confirms the shoot (or 48h passes) Shootsy transfers 80% to the creator's connected account.
const crypto = require('node:crypto');
const db = require('./db');
const { readJsonBody, send } = require('./utils');
const mailer = require('./mailer');

const COMMISSION = 0.20;
const AUTO_RELEASE_MS = 48 * 60 * 60 * 1000;
const CURRENCY = 'gbp';

const secretKey = () => process.env.STRIPE_SECRET_KEY || '';
const publicUrl = () => (process.env.PUBLIC_URL || 'https://shootsy.co.uk').replace(/\/$/, '');
const enabled = () => !!secretKey();

// Migrations
try { db.exec(`ALTER TABLE creator_profiles ADD COLUMN stripe_account_id TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE bookings ADD COLUMN price_pence INTEGER DEFAULT 0`); } catch (e) {}
try { db.exec(`ALTER TABLE bookings ADD COLUMN payment_status TEXT DEFAULT 'unpaid'`); } catch (e) {}
try { db.exec(`ALTER TABLE bookings ADD COLUMN payment_intent TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE bookings ADD COLUMN completed_at TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE bookings ADD COLUMN released_at TEXT`); } catch (e) {}

function flatten(obj, prefix, out) {
  out = out || [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}[${k}]` : k;
    if (v === undefined || v === null) continue;
    if (typeof v === 'object') flatten(v, key, out);
    else out.push([key, String(v)]);
  }
  return out;
}

async function stripe(method, path, params, idempotencyKey) {
  const headers = { Authorization: `Bearer ${secretKey()}` };
  let body;
  if (params) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(flatten(params)).toString();
  }
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  const r = await fetch(`https://api.stripe.com${path}`, { method, headers, body });
  const data = await r.json();
  if (!r.ok) {
    const msg = (data && data.error && data.error.message) || 'Stripe error';
    throw new Error(msg);
  }
  return data;
}

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', c => { size += c.length; if (size > 1_000_000) { reject(new Error('Body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function verifySignature(raw, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(header.split(',').map(p => p.split('=')));
  const t = parts.t, sig = parts.v1;
  if (!t || !sig) return false;
  if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${t}.${raw}`).digest('hex');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(sig, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function accountReady(accountId) {
  if (!accountId) return false;
  try {
    const a = await stripe('GET', `/v1/accounts/${accountId}`);
    return !!(a.charges_enabled && a.payouts_enabled);
  } catch (e) { return false; }
}

// ----- creator onboarding -----

// POST /api/stripe/connect  (creator) -> { url } to Stripe's hosted onboarding
async function handleConnect(req, res, user) {
  if (!enabled()) return send(res, 503, { error: 'Payments are not switched on yet' });
  if (!user || user.role !== 'creator') return send(res, 403, { error: 'Creators only' });
  let prof = db.prepare('SELECT stripe_account_id FROM creator_profiles WHERE user_id = ?').get(user.id);
  if (!prof) {
    db.prepare('INSERT INTO creator_profiles (user_id) VALUES (?)').run(user.id);
    prof = {};
  }
  let acct = prof.stripe_account_id;
  if (!acct) {
    const a = await stripe('POST', '/v1/accounts', {
      type: 'express',
      country: 'GB',
      email: user.email,
      capabilities: { transfers: { requested: true } },
      business_type: 'individual',
      metadata: { shootsy_user_id: user.id },
    });
    acct = a.id;
    db.prepare('UPDATE creator_profiles SET stripe_account_id = ? WHERE user_id = ?').run(acct, user.id);
  }
  const link = await stripe('POST', '/v1/account_links', {
    account: acct,
    refresh_url: `${publicUrl()}/app.html?stripe=refresh`,
    return_url: `${publicUrl()}/app.html?stripe=done`,
    type: 'account_onboarding',
  });
  send(res, 200, { url: link.url });
}

// GET /api/stripe/status (creator) -> { enabled, connected, ready }
async function handleStatus(req, res, user) {
  if (!user) return send(res, 401, { error: 'Not authenticated' });
  if (user.role !== 'creator') return send(res, 200, { enabled: enabled() });
  const prof = db.prepare('SELECT stripe_account_id FROM creator_profiles WHERE user_id = ?').get(user.id);
  const acct = prof && prof.stripe_account_id;
  send(res, 200, { enabled: enabled(), connected: !!acct, ready: enabled() ? await accountReady(acct) : false });
}

// ----- client payment -----

// POST /api/bookings/:id/pay (client) -> { url } to Stripe Checkout
async function handlePay(req, res, user, id) {
  if (!enabled()) return send(res, 503, { error: 'Payments are not switched on yet' });
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (!b) return send(res, 404, { error: 'Booking not found' });
  if (!user || user.id !== b.client_id) return send(res, 403, { error: 'Only the client can pay' });
  if (b.status !== 'accepted') return send(res, 400, { error: 'The creator needs to accept the booking first' });
  if (b.payment_status !== 'unpaid') return send(res, 400, { error: 'This booking is already paid' });
  const prof = db.prepare('SELECT rate, stripe_account_id FROM creator_profiles WHERE user_id = ?').get(b.creator_id);
  const pence = Math.round(((prof && prof.rate) || 0) * 100);
  if (pence < 100) return send(res, 400, { error: 'This creator has not set a price yet' });
  if (!(await accountReady(prof.stripe_account_id))) {
    return send(res, 400, { error: 'This creator has not finished setting up payouts yet' });
  }
  const creator = db.prepare('SELECT name FROM users WHERE id = ?').get(b.creator_id);
  db.prepare('UPDATE bookings SET price_pence = ? WHERE id = ?').run(pence, id);
  const session = await stripe('POST', '/v1/checkout/sessions', {
    mode: 'payment',
    customer_email: user.email,
    client_reference_id: String(id),
    success_url: `${publicUrl()}/app.html?paid=${id}`,
    cancel_url: `${publicUrl()}/app.html?cancelled=${id}`,
    line_items: [{
      quantity: 1,
      price_data: { currency: CURRENCY, unit_amount: pence, product_data: { name: `Shoot with ${creator.name}` } },
    }],
    metadata: { booking_id: id },
    payment_intent_data: { transfer_group: `booking_${id}`, metadata: { booking_id: id } },
  });
  send(res, 200, { url: session.url });
}

// POST /api/stripe/webhook
async function handleWebhook(req, res) {
  const raw = await readRaw(req);
  if (!verifySignature(raw, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)) {
    return send(res, 400, { error: 'Bad signature' });
  }
  const event = JSON.parse(raw);
  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    const bookingId = Number(s.metadata && s.metadata.booking_id);
    if (bookingId && s.payment_status === 'paid') {
      const r = db.prepare("UPDATE bookings SET payment_status = 'paid', payment_intent = ? WHERE id = ? AND payment_status = 'unpaid'")
        .run(s.payment_intent, bookingId);
      if (r.changes) mailer.bookingPaid(db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId));
    }
  }
  send(res, 200, { received: true });
}

// ----- release payout -----

async function releasePayout(bookingId) {
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId);
  if (!b || b.payment_status !== 'paid' || !b.payment_intent) throw new Error('Nothing to release');
  const prof = db.prepare('SELECT stripe_account_id FROM creator_profiles WHERE user_id = ?').get(b.creator_id);
  if (!prof || !prof.stripe_account_id) throw new Error('Creator has no payout account');
  const pi = await stripe('GET', `/v1/payment_intents/${b.payment_intent}`);
  const payout = b.price_pence - Math.round(b.price_pence * COMMISSION);
  // Claim the booking first so two requests can't both pay out.
  const claim = db.prepare("UPDATE bookings SET payment_status = 'releasing' WHERE id = ? AND payment_status = 'paid'").run(bookingId);
  if (!claim.changes) throw new Error('Already being released');
  try {
    await stripe('POST', '/v1/transfers', {
      amount: payout,
      currency: CURRENCY,
      destination: prof.stripe_account_id,
      source_transaction: pi.latest_charge,
      transfer_group: `booking_${bookingId}`,
      metadata: { booking_id: bookingId },
    }, `shootsy-release-${bookingId}`);
  } catch (e) {
    db.prepare("UPDATE bookings SET payment_status = 'paid' WHERE id = ?").run(bookingId);
    throw e;
  }
  db.prepare("UPDATE bookings SET payment_status = 'released', released_at = ? WHERE id = ?")
    .run(new Date().toISOString(), bookingId);
  mailer.payoutReleased(db.prepare('SELECT * FROM bookings WHERE id = ?').get(bookingId));
}

// POST /api/bookings/:id/confirm (client)
async function handleConfirm(req, res, user, id) {
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (!b) return send(res, 404, { error: 'Booking not found' });
  if (!user || user.id !== b.client_id) return send(res, 403, { error: 'Only the client can confirm' });
  if (b.status !== 'completed') return send(res, 400, { error: 'The creator has not marked this shoot as done yet' });
  if (b.payment_status !== 'paid') return send(res, 400, { error: 'Nothing to release for this booking' });
  await releasePayout(id);
  send(res, 200, { ok: true });
}

function autoRelease() {
  if (!enabled()) return;
  const cutoff = new Date(Date.now() - AUTO_RELEASE_MS).toISOString();
  const due = db.prepare(
    "SELECT id FROM bookings WHERE status = 'completed' AND payment_status = 'paid' AND completed_at IS NOT NULL AND completed_at < ?"
  ).all(cutoff);
  for (const row of due) {
    releasePayout(row.id).catch(e => console.error('Auto-release failed for booking', row.id, e.message));
  }
}
setInterval(autoRelease, 60 * 60 * 1000).unref();

module.exports = { handleConnect, handleStatus, handlePay, handleWebhook, handleConfirm, COMMISSION, enabled };
