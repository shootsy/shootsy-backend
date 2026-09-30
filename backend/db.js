// Real SQLite database using Node's built-in node:sqlite module — no npm install required.
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

// DB file path can be overridden with SHOOTSY_DB_PATH (useful on filesystems that don't
// support SQLite locking, e.g. some synced/network mounts). Defaults to ./data/shootsy.db.
let dbPath = process.env.SHOOTSY_DB_PATH;
if (!dbPath) {
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  dbPath = path.join(dataDir, 'shootsy.db');
}

const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('client','creator')),
    name TEXT NOT NULL,
    city TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS creator_profiles (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    bio TEXT DEFAULT '',
    content_type TEXT DEFAULT 'both',
    rate REAL DEFAULT 0,
    portfolio TEXT DEFAULT '[]',
    rating_avg REAL DEFAULT 0,
    rating_count INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL REFERENCES users(id),
    creator_id INTEGER NOT NULL REFERENCES users(id),
    session_datetime TEXT NOT NULL,
    location TEXT,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','completed','cancelled')),
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER NOT NULL REFERENCES bookings(id),
    sender_id INTEGER NOT NULL REFERENCES users(id),
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER UNIQUE NOT NULL REFERENCES bookings(id),
    creator_id INTEGER NOT NULL REFERENCES users(id),
    client_id INTEGER NOT NULL REFERENCES users(id),
    rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comment TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
  );
`);

module.exports = db;
