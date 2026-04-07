const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// CONFIG
// ============================================================================
const PORT = process.env.PORT || 3000;
const ADMIN_PWD = process.env.ADMIN_PWD || 'admin888';
const ADMIN_TOKEN_SECRET = process.env.ADMIN_SECRET || 'na-secret-' + crypto.randomBytes(8).toString('hex');
const CODE_EXPIRY_HOURS = parseInt(process.env.CODE_EXPIRY_HOURS || '24');

// ============================================================================
// JSON FILE DATABASE
// ============================================================================
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_FILE = path.join(DATA_DIR, 'db.json');

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('DB load error, resetting:', e.message);
  }
  // Default structure
  return {
    codes: [
      { code: 'BP-DEMO1', type: 'basic', used: false, createdAt: new Date().toISOString(), activatedAt: null, expiresAt: null, sessionToken: null, batchId: 'demo' },
      { code: 'AP-DEMO1', type: 'advanced', used: false, createdAt: new Date().toISOString(), activatedAt: null, expiresAt: null, sessionToken: null, batchId: 'demo' }
    ],
    results: []
  };
}

function saveDB(data) {
  // Atomic write: write to temp file then rename
  const tmpFile = DB_FILE + '.tmp';
  fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmpFile, DB_FILE);
}

// Load on startup
let db = loadDB();
// Save initial if file doesn't exist
if (!fs.existsSync(DB_FILE)) saveDB(db);

console.log(`Database loaded: ${db.codes.length} codes, ${db.results.length} results`);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateAdminToken() {
  const payload = Date.now().toString();
  const hmac = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(payload).digest('hex');
  return payload + '.' + hmac;
}

function verifyAdminToken(token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const hmac = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(parts[0]).digest('hex');
  if (hmac !== parts[1]) return false;
  const age = Date.now() - parseInt(parts[0]);
  return age < 12 * 60 * 60 * 1000; // 12 hours
}

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!verifyAdminToken(token)) {
    return res.status(401).json({ error: '未授权，请重新登录' });
  }
  next();
}

function generateCodeStr(type) {
  const prefix = type === 'basic' ? 'BP' : 'AP';
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return `${prefix}-${code}`;
}

function isExpired(expiresAt) {
  if (!expiresAt) return false;
  return new Date(expiresAt) < new Date();
}

// ============================================================================
// PUBLIC API - Code Verification
// ============================================================================

app.post('/api/verify-code', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ valid: false, error: '请输入兑换码' });

  db = loadDB(); // Reload for freshness
  const row = db.codes.find(c => c.code === code.toUpperCase().trim());

  if (!row) {
    return res.json({ valid: false, error: '兑换码不存在，请检查输入' });
  }

  if (row.used && row.sessionToken) {
    // Check if still within expiry window (allow re-entry)
    if (row.expiresAt && !isExpired(row.expiresAt)) {
      return res.json({
        valid: true,
        type: row.type,
        code: row.code,
        sessionToken: row.sessionToken,
        expiresAt: row.expiresAt,
        resumed: true
      });
    }
    return res.json({ valid: false, error: '此兑换码已被使用且已过期' });
  }

  // Activate the code
  const sessionToken = generateToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CODE_EXPIRY_HOURS * 60 * 60 * 1000);

  row.used = true;
  row.activatedAt = now.toISOString();
  row.expiresAt = expiresAt.toISOString();
  row.sessionToken = sessionToken;
  saveDB(db);

  return res.json({
    valid: true,
    type: row.type,
    code: row.code,
    sessionToken,
    expiresAt: expiresAt.toISOString(),
    resumed: false
  });
});

app.post('/api/check-session', (req, res) => {
  const { sessionToken } = req.body;
  if (!sessionToken) return res.json({ valid: false });

  db = loadDB();
  const row = db.codes.find(c => c.sessionToken === sessionToken);
  if (!row) return res.json({ valid: false });

  if (row.expiresAt && !isExpired(row.expiresAt)) {
    return res.json({
      valid: true,
      type: row.type,
      code: row.code,
      expiresAt: row.expiresAt
    });
  }

  return res.json({ valid: false, error: '会话已过期' });
});

app.post('/api/save-results', (req, res) => {
  const { sessionToken, results } = req.body;
  if (!sessionToken || !results) return res.status(400).json({ error: '参数缺失' });

  db = loadDB();
  const row = db.codes.find(c => c.sessionToken === sessionToken);
  if (!row) return res.status(403).json({ error: '无效会话' });

  if (row.expiresAt && isExpired(row.expiresAt)) {
    return res.status(403).json({ error: '会话已过期' });
  }

  // Upsert result
  const existingIdx = db.results.findIndex(r => r.code === row.code);
  const resultEntry = {
    code: row.code,
    sessionToken,
    overall: results.overall,
    grade: results.grade,
    risk: results.risk,
    dimensions: results.dimensions,
    completedAt: new Date().toISOString()
  };

  if (existingIdx >= 0) {
    db.results[existingIdx] = resultEntry;
  } else {
    db.results.push(resultEntry);
  }
  saveDB(db);

  return res.json({ success: true });
});

app.post('/api/get-results', (req, res) => {
  const { sessionToken } = req.body;
  if (!sessionToken) return res.status(400).json({ error: '参数缺失' });

  db = loadDB();
  const code = db.codes.find(c => c.sessionToken === sessionToken);
  if (!code) return res.status(403).json({ error: '无效会话' });

  const result = db.results.find(r => r.code === code.code);
  if (!result) return res.json({ found: false });

  return res.json({
    found: true,
    overall: result.overall,
    grade: result.grade,
    risk: result.risk,
    dimensions: result.dimensions
  });
});

// ============================================================================
// ADMIN API
// ============================================================================

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PWD) {
    return res.json({ success: true, token: generateAdminToken() });
  }
  return res.json({ success: false, error: '密码错误' });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  db = loadDB();
  const total = db.codes.length;
  const used = db.codes.filter(c => c.used).length;
  const expired = db.codes.filter(c => c.used && c.expiresAt && isExpired(c.expiresAt)).length;
  const active = db.codes.filter(c => c.used && c.expiresAt && !isExpired(c.expiresAt)).length;
  const completed = db.results.length;
  const basicTotal = db.codes.filter(c => c.type === 'basic').length;
  const advancedTotal = db.codes.filter(c => c.type === 'advanced').length;

  return res.json({
    total, used, unused: total - used, expired, active, completed,
    basicTotal, advancedTotal,
    usageRate: total > 0 ? Math.round((used / total) * 100) : 0
  });
});

app.get('/api/admin/codes', adminAuth, (req, res) => {
  db = loadDB();
  const page = parseInt(req.query.page || '1');
  const limit = parseInt(req.query.limit || '50');
  const filter = req.query.filter || 'all';
  const offset = (page - 1) * limit;

  let filtered = db.codes;
  if (filter === 'used') filtered = filtered.filter(c => c.used);
  else if (filter === 'unused') filtered = filtered.filter(c => !c.used);
  else if (filter === 'expired') filtered = filtered.filter(c => c.used && c.expiresAt && isExpired(c.expiresAt));
  else if (filter === 'active') filtered = filtered.filter(c => c.used && c.expiresAt && !isExpired(c.expiresAt));

  // Sort newest first
  filtered = [...filtered].reverse();
  const total = filtered.length;
  const page_codes = filtered.slice(offset, offset + limit);

  return res.json({
    codes: page_codes.map(c => {
      const result = db.results.find(r => r.code === c.code);
      return {
        code: c.code,
        type: c.type,
        used: c.used,
        createdAt: c.createdAt,
        activatedAt: c.activatedAt,
        expiresAt: c.expiresAt,
        expired: c.expiresAt ? isExpired(c.expiresAt) : false,
        resultGrade: result ? result.grade : null,
        resultScore: result ? result.overall : null,
        resultTime: result ? result.completedAt : null
      };
    }),
    total,
    page,
    totalPages: Math.ceil(total / limit)
  });
});

app.post('/api/admin/codes/generate', adminAuth, (req, res) => {
  const { type, count } = req.body;
  if (!type || !count || count < 1 || count > 500) {
    return res.status(400).json({ error: '参数错误，数量1-500' });
  }
  if (!['basic', 'advanced'].includes(type)) {
    return res.status(400).json({ error: '类型错误' });
  }

  db = loadDB();
  const batchId = crypto.randomBytes(8).toString('hex');
  const generated = [];
  const existingCodes = new Set(db.codes.map(c => c.code));
  let attempts = 0;

  while (generated.length < count && attempts < count * 3) {
    const code = generateCodeStr(type);
    if (!existingCodes.has(code)) {
      db.codes.push({
        code,
        type,
        used: false,
        createdAt: new Date().toISOString(),
        activatedAt: null,
        expiresAt: null,
        sessionToken: null,
        batchId
      });
      existingCodes.add(code);
      generated.push(code);
    }
    attempts++;
  }

  saveDB(db);

  return res.json({
    success: true,
    count: generated.length,
    codes: generated,
    batchId
  });
});

app.get('/api/admin/codes/export', (req, res) => {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!verifyAdminToken(token)) {
    return res.status(401).json({ error: '未授权' });
  }

  db = loadDB();
  let csv = '\uFEFF兑换码,类型,状态,创建时间,激活时间,过期时间,测评等级,测评分数,完成时间\n';
  db.codes.forEach(c => {
    const status = !c.used ? '未使用' : (c.expiresAt && isExpired(c.expiresAt) ? '已过期' : '使用中');
    const type = c.type === 'basic' ? '基础版(48题)' : '高级版(100题)';
    const result = db.results.find(r => r.code === c.code);
    csv += `${c.code},${type},${status},${c.createdAt || ''},${c.activatedAt || ''},${c.expiresAt || ''},${result ? result.grade + '级' : ''},${result ? result.overall : ''},${result ? result.completedAt : ''}\n`;
  });

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename=codes_${new Date().toISOString().slice(0, 10)}.csv`);
  res.send(csv);
});

app.delete('/api/admin/codes/:code', adminAuth, (req, res) => {
  db = loadDB();
  const code = req.params.code;
  db.codes = db.codes.filter(c => c.code !== code);
  db.results = db.results.filter(r => r.code !== code);
  saveDB(db);
  return res.json({ success: true });
});

// ============================================================================
// FALLBACK - SPA
// ============================================================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================================
// START
// ============================================================================
app.listen(PORT, () => {
  console.log(`Neural Architect Assessment Server running on port ${PORT}`);
  console.log(`Admin password: ${ADMIN_PWD.slice(0, 3)}${'*'.repeat(ADMIN_PWD.length - 3)}`);
  console.log(`Code expiry: ${CODE_EXPIRY_HOURS} hours`);
});
