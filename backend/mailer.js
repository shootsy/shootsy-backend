// Email helpers (via Resend; needs RESEND_API_KEY on the server).
// A failed email must never break the request that triggered it.
const db = require('./db');

const SITE = () => (process.env.PUBLIC_URL || 'https://shootsy.co.uk').replace(/\/$/, '');

function escHtml(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const MAIL_FROM = () => process.env.NOTIFY_FROM || 'Shootsy <onboarding@resend.dev>';

// Emails to ordinary users only go out once a verified sending domain is configured.
const canEmailUsers = () => !/resend\.dev/i.test(MAIL_FROM());

function sendEmail(to, subject, html, extra) {
  const key = process.env.RESEND_API_KEY;
  if (!key) { console.log('Email skipped (no RESEND_API_KEY):', subject); return; }
  fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
    body: JSON.stringify(Object.assign({ from: MAIL_FROM(), to: [to], subject, html }, extra || {})),
  }).then(async r => {
    if (!r.ok) console.error('Email to', to, 'failed:', r.status, await r.text().catch(() => ''));
  }).catch(e => console.error('Email error:', e.message));
}

function notifyOwner(subject, html) {
  const recipients = (process.env.NOTIFY_EMAIL || 'daisymccarthy92@outlook.com,hello@shootsy.co.uk')
    .split(',').map(s => s.trim()).filter(Boolean);
  recipients.forEach(to => sendEmail(to, subject, html));
}

// Branded wrapper used by every transactional email.
function brandedEmail({ heading, paragraphs, ctaText, ctaUrl, footer }) {
  const body = paragraphs.map(p => `<p style="margin:0 0 14px">${p}</p>`).join('');
  const cta = ctaText
    ? `<p style="margin:6px 0 22px"><a href="${escHtml(ctaUrl)}" style="background:#E22E72;color:#ffffff;text-decoration:none;padding:12px 22px;border-radius:999px;font-weight:bold;display:inline-block">${escHtml(ctaText)}</a></p>`
    : '';
  return `<div style="background:#FDF1F5;padding:24px 12px;font-family:Arial,Helvetica,sans-serif;color:#170F26">
    <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:20px;overflow:hidden;border:1px solid #F6DCE7">
      <div style="background:#E22E72;padding:22px 26px;color:#ffffff;font-size:26px;font-weight:bold">Shootsy</div>
      <div style="padding:26px;font-size:15px;line-height:1.6">
        <h2 style="margin:0 0 12px;font-size:22px">${escHtml(heading)}</h2>
        ${body}
        ${cta}
        <p style="margin:14px 0 0">Daisy x<br><span style="color:#3E3352">Founder, Shootsy</span></p>
      </div>
    </div>
    <p style="text-align:center;font-size:12px;color:#3E3352;margin:14px 0 0">${escHtml(footer || 'You are getting this because you have a Shootsy account.')}<br>SHOOTSY LTD, registered in England and Wales, company number 17450268.</p>
  </div>`;
}

function first(name) { return String(name || '').trim().split(/\s+/)[0] || 'there'; }

function fmtWhen(iso) {
  try {
    return new Date(iso).toLocaleString('en-GB', { dateStyle: 'full', timeStyle: 'short', timeZone: 'Europe/London' });
  } catch (e) { return String(iso || ''); }
}

// Send a transactional email to a user by id. Skipped silently if emails to users are not enabled.
function mailUser(userId, subject, opts) {
  try {
    if (!canEmailUsers()) return;
    const u = db.prepare('SELECT email FROM users WHERE id = ?').get(userId);
    if (!u || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(u.email)) return;
    sendEmail(u.email, subject, brandedEmail(opts), { reply_to: 'hello@shootsy.co.uk' });
  } catch (e) { console.error('mailUser error:', e.message); }
}

// ----- booking lifecycle emails -----
const APP = () => SITE() + '/app.html';
const nameOf = id => (db.prepare('SELECT name FROM users WHERE id = ?').get(id) || {}).name || 'Someone';

function bookingRequested(b) {
  mailUser(b.creator_id, `New booking request from ${first(nameOf(b.client_id))}`, {
    heading: `You have a new booking request, ${first(nameOf(b.creator_id))}!`,
    paragraphs: [
      `<strong>${escHtml(nameOf(b.client_id))}</strong> would like to book you.`,
      `<strong>When:</strong> ${escHtml(fmtWhen(b.session_datetime))}<br><strong>Where:</strong> ${escHtml(b.location || 'Not set yet')}` +
        (b.notes ? `<br><strong>Notes:</strong> ${escHtml(b.notes)}` : ''),
      'Log in to accept or decline. Clients like a quick reply.',
    ],
    ctaText: 'View request', ctaUrl: APP(),
  });
}

function bookingAnswered(b, status) {
  const creator = nameOf(b.creator_id);
  if (status === 'accepted') {
    mailUser(b.client_id, `${first(creator)} accepted your booking`, {
      heading: 'Good news, your booking was accepted!',
      paragraphs: [
        `<strong>${escHtml(creator)}</strong> has accepted your shoot on ${escHtml(fmtWhen(b.session_datetime))}.`,
        'The next step is to pay to secure your booking. Your payment is held safely and only released to the creator after your shoot.',
      ],
      ctaText: 'Pay now', ctaUrl: APP(),
    });
  } else if (status === 'declined') {
    mailUser(b.client_id, `${first(creator)} can't do your booking`, {
      heading: 'Your booking request was declined',
      paragraphs: [
        `Unfortunately <strong>${escHtml(creator)}</strong> can't take your shoot on ${escHtml(fmtWhen(b.session_datetime))}.`,
        'There are plenty of other creators on Shootsy. Have another look and send a new request.',
      ],
      ctaText: 'Find another creator', ctaUrl: APP(),
    });
  }
}

function bookingCancelled(b) {
  mailUser(b.creator_id, 'A booking was cancelled', {
    heading: 'Booking cancelled',
    paragraphs: [
      `<strong>${escHtml(nameOf(b.client_id))}</strong> has cancelled the shoot planned for ${escHtml(fmtWhen(b.session_datetime))}.`,
    ],
    ctaText: 'View bookings', ctaUrl: APP(),
  });
}

function bookingPaid(b) {
  mailUser(b.creator_id, `${first(nameOf(b.client_id))} has paid for your shoot`, {
    heading: 'Payment received!',
    paragraphs: [
      `<strong>${escHtml(nameOf(b.client_id))}</strong> has paid for your shoot on ${escHtml(fmtWhen(b.session_datetime))}.`,
      'The money is held safely by Shootsy and sent to you after the shoot, once you mark it as completed and the client confirms.',
    ],
    ctaText: 'View booking', ctaUrl: APP(),
  });
  mailUser(b.client_id, 'Payment received, your booking is secured', {
    heading: 'You are all booked in!',
    paragraphs: [
      `Thanks, we have your payment for your shoot with <strong>${escHtml(nameOf(b.creator_id))}</strong> on ${escHtml(fmtWhen(b.session_datetime))}.`,
      'Your money is held safely and only released to the creator after the shoot.',
    ],
    ctaText: 'View booking', ctaUrl: APP(),
  });
}

function bookingCompleted(b) {
  mailUser(b.client_id, 'How did your shoot go?', {
    heading: 'Your shoot is marked as done',
    paragraphs: [
      `<strong>${escHtml(nameOf(b.creator_id))}</strong> has marked your shoot as completed.`,
      'If everything went well, please confirm it so we can pay your creator. If we don\'t hear from you within 48 hours, the payment is released automatically. If something went wrong, email hello@shootsy.co.uk within 48 hours and we\'ll look into it.',
    ],
    ctaText: 'Confirm my shoot', ctaUrl: APP(),
  });
}

function payoutReleased(b) {
  mailUser(b.creator_id, 'Your payout is on its way', {
    heading: 'Payout released!',
    paragraphs: [
      `Your payment for the shoot with <strong>${escHtml(nameOf(b.client_id))}</strong> has been released to your Stripe account.`,
      'Stripe will pay it into your bank account on your payout schedule.',
    ],
    ctaText: 'View booking', ctaUrl: APP(),
  });
}

module.exports = {
  SITE, escHtml, MAIL_FROM, canEmailUsers, sendEmail, notifyOwner, brandedEmail, mailUser, first,
  bookingRequested, bookingAnswered, bookingCancelled, bookingPaid, bookingCompleted, payoutReleased,
};
