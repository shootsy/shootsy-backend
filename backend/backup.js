// Daily copy of the SQLite database, kept next to it on the persistent disk (last 7 days).
// This protects against bad edits and corruption. Pair it with Render's disk snapshots,
// which protect against losing the disk itself.
const path = require('node:path');
const fs = require('node:fs');
const db = require('./db');

const KEEP = 7;
const dbPath = process.env.SHOOTSY_DB_PATH || path.join(__dirname, 'data', 'shootsy.db');
const dir = path.join(path.dirname(dbPath), 'backups');

function runBackup() {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const stamp = new Date().toISOString().slice(0, 10);
    const target = path.join(dir, `shootsy-${stamp}.db`);
    if (!fs.existsSync(target)) {
      db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
      console.log('Backup written:', target);
    }
    const files = fs.readdirSync(dir).filter(f => /^shootsy-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
    files.slice(0, Math.max(0, files.length - KEEP)).forEach(f => fs.unlinkSync(path.join(dir, f)));
  } catch (e) {
    console.error('Backup failed:', e.message);
  }
}

setTimeout(runBackup, 15_000).unref();
setInterval(runBackup, 24 * 60 * 60 * 1000).unref();

module.exports = { runBackup };
