const express = require('express');
const multer  = require('multer');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { parse }    = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const axios   = require('axios');

require('dotenv').config({ path: path.join(__dirname, '.env.local') });
require('dotenv').config();

const app = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const IS_VERCEL = !!process.env.VERCEL;
const STORAGE_BASE = IS_VERCEL ? '/tmp' : __dirname;
const DB_FILE    = path.join(STORAGE_BASE, 'users.json');
const RESULTS_DIR = path.join(STORAGE_BASE, 'results');
const USERDATA_ENC_KEY = process.env.USERDATA_ENC_KEY || '';

if (!JWT_SECRET || !JWT_SECRET.trim()) {
  throw new Error('Missing required env var: JWT_SECRET');
}
if (!USERDATA_ENC_KEY || !USERDATA_ENC_KEY.trim()) {
  throw new Error('Missing required env var: USERDATA_ENC_KEY');
}

const derivedDataKey = crypto.createHash('sha256')
  .update(USERDATA_ENC_KEY)
  .digest();

// Bootstrap storage
if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE))     fs.writeFileSync(DB_FILE, JSON.stringify({ users: [] }));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 } // 20 MB
});

// ── Temp in-memory stores ──────────────────────────────────────────────────────
const csvStore = {};  // fileId  → { records, uploadedAt }
const jobs     = {};  // jobId   → { status, progress, total, processed, errors, outputId? }

// ── DB helpers ─────────────────────────────────────────────────────────────────
const readDB  = ()     => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const writeDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });

function encryptValue(plainText) {
  if (!plainText) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', derivedDataKey, iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

function decryptValue(payload) {
  if (!payload) return '';
  try {
    if (!String(payload).startsWith('v1:')) return '';
    const [, ivB64, tagB64, dataB64] = String(payload).split(':');
    if (!ivB64 || !tagB64 || !dataB64) return '';
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      derivedDataKey,
      Buffer.from(ivB64, 'base64')
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(dataB64, 'base64')),
      decipher.final()
    ]);
    return plain.toString('utf8');
  } catch {
    return '';
  }
}

function secureAndMigrateDB(db) {
  let changed = false;
  db.users = (db.users || []).map(user => {
    const next = { ...user };
    if (typeof next.apiKey === 'string' && next.apiKey.trim()) {
      next.apiKeyEnc = encryptValue(next.apiKey.trim());
      delete next.apiKey;
      changed = true;
    } else if ('apiKey' in next) {
      delete next.apiKey;
      changed = true;
    }
    if (typeof next.apiKeyEnc !== 'string') {
      next.apiKeyEnc = '';
      changed = true;
    }
    return next;
  });
  return { db, changed };
}

function getDecryptedApiKey(user) {
  return decryptValue(user?.apiKeyEnc || '');
}

function readDBSecure() {
  const db = readDB();
  const secured = secureAndMigrateDB(db);
  if (secured.changed) writeDB(secured.db);
  return secured.db;
}

// Migrate legacy plaintext apiKey fields as server boots.
readDBSecure();

// ── Auth middleware ────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Auth routes ────────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const db = readDBSecure();
  if (db.users.find(u => u.email === email.toLowerCase().trim()))
    return res.status(400).json({ error: 'Email already registered' });

  const user = {
    id:        `u_${Date.now()}`,
    name:      name.trim(),
    email:     email.toLowerCase().trim(),
    password:  await bcrypt.hash(password, 12),
    apiKeyEnc: '',
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  writeDB(db);

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const db   = readDBSecure();
  const user = db.users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !await bcrypt.compare(password, user.password))
    return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// ── User routes ────────────────────────────────────────────────────────────────

app.get('/api/user/profile', auth, (req, res) => {
  const db   = readDBSecure();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const apiKey = getDecryptedApiKey(user);
  res.json({
    id:        user.id,
    name:      user.name,
    email:     user.email,
    hasApiKey: !!apiKey,
    apiKeyMasked: apiKey
      ? apiKey.substring(0, 6) + '••••••••' + apiKey.slice(-4)
      : ''
  });
});

app.post('/api/user/apikey', auth, (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey?.trim()) return res.status(400).json({ error: 'API key cannot be empty' });

  const db  = readDBSecure();
  const idx = db.users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  db.users[idx].apiKeyEnc = encryptValue(apiKey.trim());
  delete db.users[idx].apiKey;
  writeDB(db);
  res.json({ success: true, message: 'API key saved' });
});

// ── CSV upload ─────────────────────────────────────────────────────────────────

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  if (!req.file.originalname.toLowerCase().endsWith('.csv'))
    return res.status(400).json({ error: 'Only .csv files are accepted' });

  try {
    const content = req.file.buffer.toString('utf8');
    const records = parse(content, {
      columns:             true,
      skip_empty_lines:    true,
      bom:                 true,
      trim:                true,
      relax_column_count:  true
    });

    if (records.length === 0)
      return res.status(400).json({ error: 'CSV has no data rows' });

    const fileId = `f_${req.user.id}_${Date.now()}`;
    csvStore[fileId] = { records, uploadedAt: Date.now() };

    // Expire old entries (> 1 hour)
    const cutoff = Date.now() - 3_600_000;
    Object.keys(csvStore).forEach(k => {
      if (csvStore[k].uploadedAt < cutoff) delete csvStore[k];
    });

    res.json({
      fileId,
      columns:   Object.keys(records[0]),
      totalRows: records.length,
      preview:   records.slice(0, 5)
    });
  } catch (err) {
    res.status(400).json({ error: 'Failed to parse CSV: ' + err.message });
  }
});

// ── Start processing job ───────────────────────────────────────────────────────

app.post('/api/process', auth, (req, res) => {
  const { fileId, phoneColumn, rps: rawRps } = req.body;
  if (!fileId || !phoneColumn)
    return res.status(400).json({ error: 'fileId and phoneColumn are required' });

  // Clamp rps to 1–120; default 8 for free-tier safety
  const rps = Math.min(120, Math.max(1, parseInt(rawRps) || 8));

  const db   = readDBSecure();
  const user = db.users.find(u => u.id === req.user.id);
  const apiKey = getDecryptedApiKey(user);
  if (!apiKey)
    return res.status(400).json({ error: 'Please save your NumlookupAPI key first' });

  const csvData = csvStore[fileId];
  if (!csvData)
    return res.status(400).json({ error: 'File not found or expired — please re-upload' });

  const jobId = `job_${req.user.id}_${Date.now()}`;
  jobs[jobId] = {
    status:      'processing',
    progress:    0,
    total:       csvData.records.length,
    processed:   0,
    errors:      0,
    rps,
    concurrency: calcConcurrency(rps)
  };

  runJob(jobId, csvData.records, phoneColumn, apiKey, rps);

  res.json({ jobId, total: csvData.records.length, rps, concurrency: calcConcurrency(rps) });
});

// ── Poll progress ──────────────────────────────────────────────────────────────

app.get('/api/progress/:jobId', auth, (req, res) => {
  const { jobId } = req.params;
  if (!jobId.startsWith(`job_${req.user.id}_`))
    return res.status(403).json({ error: 'Access denied' });

  const job = jobs[jobId];
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json(job);
});

// ── Download result ────────────────────────────────────────────────────────────

app.get('/api/download/:jobId', auth, (req, res) => {
  const { jobId } = req.params;
  if (!jobId.startsWith(`job_${req.user.id}_`))
    return res.status(403).json({ error: 'Access denied' });

  const job = jobs[jobId];
  if (!job || job.status !== 'done')
    return res.status(400).json({ error: 'Job not ready or not found' });

  const filePath = path.join(RESULTS_DIR, `${jobId}.csv`);
  if (!fs.existsSync(filePath))
    return res.status(404).json({ error: 'Result file has expired' });

  res.download(filePath, 'phone_validation_results.csv');
});

// ── Helpers ────────────────────────────────────────────────────────────────────

const sleep = ms => new Promise(r => setTimeout(r, ms));

/**
 * How many concurrent workers to spin up for a given rps target.
 * Each worker sleeps  (concurrency / rps * 1000) ms between requests,
 * so aggregate throughput = concurrency / delay_s = rps.  ✓
 */
function calcConcurrency(rps) {
  if (rps <=  5) return 1;
  if (rps <= 15) return 3;
  if (rps <= 30) return 5;
  if (rps <= 60) return 10;
  return 15; // 61–120 rps
}

// ── Async job runner ───────────────────────────────────────────────────────────

async function runJob(jobId, records, phoneColumn, apiKey, rps = 8) {
  const concurrency = calcConcurrency(rps);
  // Each worker fires 1 request every (concurrency/rps) seconds
  const workerDelay = Math.round((concurrency / rps) * 1000);

  // Pre-allocate result array to keep row order intact
  const results    = new Array(records.length).fill(null);
  let processed    = 0;
  let errors       = 0;
  let nextIndex    = 0;   // shared cursor — JS is single-threaded, no mutex needed

  async function worker() {
    while (nextIndex < records.length) {
      const i      = nextIndex++;
      const record = records[i];
      const phone  = record[phoneColumn]?.toString().trim() || '';

      const enriched = {
        ...record,
        valid:                '',
        formatted_number:     '',
        local_format:         '',
        international_format: '',
        country_prefix:       '',
        country_code:         '',
        country_name:         '',
        location:             '',
        carrier:              '',
        line_type:            ''
      };

      if (phone) {
        try {
          const { data } = await axios.get(
            `https://api.numlookupapi.com/v1/validate/${encodeURIComponent(phone)}`,
            { params: { apikey: apiKey }, timeout: 15_000 }
          );
          enriched.valid                = data.valid === true ? 'true' : 'false';
          enriched.formatted_number     = data.number              || '';
          enriched.local_format         = data.local_format         || '';
          enriched.international_format = data.international_format || '';
          enriched.country_prefix       = data.country_prefix       || '';
          enriched.country_code         = data.country_code         || '';
          enriched.country_name         = data.country_name         || '';
          enriched.location             = data.location             || '';
          enriched.carrier              = data.carrier              || '';
          enriched.line_type            = data.line_type            || '';
          processed++;
        } catch (err) {
          const msg = err.response?.data?.error?.info
                   || err.response?.data?.error
                   || err.message
                   || 'API error';
          enriched.valid            = 'error';
          enriched.formatted_number = String(msg);
          errors++;
        }
      } else {
        enriched.valid = 'no_phone';
        errors++;
      }

      results[i] = enriched;

      // Update progress (shared write — safe because JS event loop is single-threaded)
      const done = processed + errors;
      jobs[jobId].progress  = Math.round((done / records.length) * 100);
      jobs[jobId].processed = processed;
      jobs[jobId].errors    = errors;

      // Pace this worker so aggregate throughput ≈ rps
      if (nextIndex < records.length) await sleep(workerDelay);
    }
  }

  // Launch all workers concurrently and wait for all to finish
  await Promise.all(Array.from({ length: concurrency }, worker));

  try {
    const csv      = stringify(results, { header: true });
    const filePath = path.join(RESULTS_DIR, `${jobId}.csv`);
    fs.writeFileSync(filePath, csv);

    jobs[jobId].status   = 'done';
    jobs[jobId].outputId = jobId;

    // Auto-delete result file after 2 hours
    setTimeout(() => {
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      delete jobs[jobId];
    }, 7_200_000);
  } catch (err) {
    jobs[jobId].status       = 'error';
    jobs[jobId].errorMessage = 'Failed to write result: ' + err.message;
  }
}

if (!IS_VERCEL) {
  app.listen(PORT, () => {
    console.log(`\n  PhoneVerify running → http://localhost:${PORT}\n`);
  });
}

module.exports = app;
