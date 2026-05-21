const fs = require('fs');
const path = require('path');

const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const IS_VERCEL = !!process.env.VERCEL;
const STORAGE_BASE = IS_VERCEL && !DATABASE_URL ? '/tmp' : path.join(__dirname, '..');
const DB_FILE = path.join(STORAGE_BASE, 'users.json');

let sqlClient = null;
let schemaReady = null;

function usePostgres() {
  return !!DATABASE_URL;
}

function readFileDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [] }), { mode: 0o600 });
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeFileDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
}

async function getSql() {
  if (!schemaReady) {
    schemaReady = (async () => {
      const postgres = require('postgres');
      const ssl =
        DATABASE_URL.includes('localhost') || DATABASE_URL.includes('127.0.0.1')
          ? false
          : 'require';
      sqlClient = postgres(DATABASE_URL, {
        ssl,
        max: 1,
        idle_timeout: 20,
        connect_timeout: 10
      });
      await sqlClient`
        CREATE TABLE IF NOT EXISTS users (
          id          TEXT PRIMARY KEY,
          name        TEXT NOT NULL,
          email       TEXT NOT NULL UNIQUE,
          password    TEXT NOT NULL,
          api_key_enc TEXT NOT NULL DEFAULT '',
          created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `;
      return sqlClient;
    })();
  }
  return schemaReady;
}

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    password: row.password,
    apiKeyEnc: row.api_key_enc || '',
    createdAt: row.created_at instanceof Date
      ? row.created_at.toISOString()
      : String(row.created_at || '')
  };
}

async function findByEmail(email) {
  const normalized = email.toLowerCase().trim();
  if (usePostgres()) {
    const sql = await getSql();
    const rows = await sql`
      SELECT id, name, email, password, api_key_enc, created_at
      FROM users WHERE email = ${normalized} LIMIT 1
    `;
    return rowToUser(rows[0]);
  }
  const db = readFileDB();
  return db.users.find(u => u.email === normalized) || null;
}

async function findById(id) {
  if (usePostgres()) {
    const sql = await getSql();
    const rows = await sql`
      SELECT id, name, email, password, api_key_enc, created_at
      FROM users WHERE id = ${id} LIMIT 1
    `;
    return rowToUser(rows[0]);
  }
  const db = readFileDB();
  return db.users.find(u => u.id === id) || null;
}

async function createUser(user) {
  if (usePostgres()) {
    const sql = await getSql();
    await sql`
      INSERT INTO users (id, name, email, password, api_key_enc, created_at)
      VALUES (
        ${user.id},
        ${user.name},
        ${user.email},
        ${user.password},
        ${user.apiKeyEnc || ''},
        ${user.createdAt}
      )
    `;
    return;
  }
  const db = readFileDB();
  db.users.push(user);
  writeFileDB(db);
}

async function updateApiKeyEnc(id, apiKeyEnc) {
  if (usePostgres()) {
    const sql = await getSql();
    await sql`
      UPDATE users SET api_key_enc = ${apiKeyEnc} WHERE id = ${id}
    `;
    return;
  }
  const db = readFileDB();
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) throw new Error('User not found');
  db.users[idx].apiKeyEnc = apiKeyEnc;
  delete db.users[idx].apiKey;
  writeFileDB(db);
}

async function migrateFileUsers(encryptValue) {
  if (!usePostgres() || !fs.existsSync(DB_FILE)) return;
  const db = readFileDB();
  if (!db.users?.length) return;

  const sql = await getSql();
  const existing = await sql`SELECT email FROM users`;
  const existingEmails = new Set(existing.map(r => r.email));

  for (const user of db.users) {
    const email = user.email?.toLowerCase?.().trim?.() || user.email;
    if (!email || existingEmails.has(email)) continue;

    let apiKeyEnc = user.apiKeyEnc || '';
    if (typeof user.apiKey === 'string' && user.apiKey.trim()) {
      apiKeyEnc = encryptValue(user.apiKey.trim());
    }

    await sql`
      INSERT INTO users (id, name, email, password, api_key_enc, created_at)
      VALUES (
        ${user.id},
        ${user.name},
        ${email},
        ${user.password},
        ${apiKeyEnc},
        ${user.createdAt || new Date().toISOString()}
      )
      ON CONFLICT (email) DO NOTHING
    `;
    existingEmails.add(email);
  }
}

function bootstrapFileStorage() {
  if (usePostgres()) return;
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [] }), { mode: 0o600 });
  }
}

function getStorageMode() {
  return usePostgres() ? 'postgres' : 'file';
}

module.exports = {
  bootstrapFileStorage,
  createUser,
  findByEmail,
  findById,
  getStorageMode,
  migrateFileUsers,
  readFileDB,
  updateApiKeyEnc,
  usePostgres,
  writeFileDB
};
