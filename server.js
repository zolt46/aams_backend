const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');

require('./config/loadEnv').loadEnv();

const app = express();
const port = process.env.PORT || 3000;
const path = require('path');

app.set('trust proxy', 1);

function sanitizeHttpsUrl(value, { allowPath = true, allowHttp = false } = {}) {
  if (!value) return '';
  const raw = String(value).trim();
  if (!raw) return '';
  let parsed;
  try {
    parsed = new URL(raw);
  } catch (_) {
    return '';
  }
  const protocol = parsed.protocol.toLowerCase();
  if (protocol === 'https:') {
    // ok
  } else if (allowHttp && protocol === 'http:') {
    // explicitly allowed (dev only)
  } else {
    return '';
  }

  parsed.hash = '';
  parsed.search = '';
  if (!allowPath) {
    parsed.pathname = '/';
  }

  const pathname = allowPath ? parsed.pathname.replace(/\/$/, '') : '';
  const origin = parsed.origin;
  if (!origin) return '';
  return allowPath ? `${origin}${pathname}` : origin;
}

function sanitizeOrigins(value) {
  if (!value) return [];
  return String(value)
    .split(/[,\s]+/)
    .map((entry) => sanitizeHttpsUrl(entry, { allowPath: false }))
    .filter(Boolean);
}

const rawCorsOrigins =
  process.env.CORS_ALLOW_ORIGINS ||
  process.env.CORS_ALLOWED_ORIGINS ||
  process.env.ALLOWED_ORIGINS ||
  '';
const corsOrigins = sanitizeOrigins(rawCorsOrigins);
const allowAllOrigins = corsOrigins.length === 0;
if (allowAllOrigins) {
  console.warn('[config] CORS_ALLOW_ORIGINS not set; defaulting to allow all origins.');
}

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }
    const normalized = sanitizeHttpsUrl(origin, { allowPath: false });
    if (!normalized) {
      return callback(new Error('Origin not allowed by CORS policy'));
    }
    if (allowAllOrigins || corsOrigins.includes(normalized)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed by CORS policy'));
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'x-bridge-token',
    'x-fp-token'
  ],
  maxAge: 86400
};

const loginTickets = new Map(); // key: site, val: { person_id, name, is_admin, exp, used:false }
const now = () => Date.now();
const TICKET_TTL_MS = 1_000; // 10초

 
const SESSION_COOKIE_ENABLED =
  (process.env.SESSION_COOKIE_ENABLED || process.env.AAMS_SESSION_ENABLED || '0') === '1';
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'aams_session';
const SESSION_COOKIE_DOMAIN = process.env.SESSION_COOKIE_DOMAIN || undefined;
const SESSION_COOKIE_PATH = process.env.SESSION_COOKIE_PATH || '/';
const sessionMaxAgeRaw = Number(process.env.SESSION_COOKIE_MAX_AGE || 7 * 24 * 60 * 60 * 1000);
const SESSION_COOKIE_MAX_AGE = Number.isFinite(sessionMaxAgeRaw) && sessionMaxAgeRaw > 0
  ? sessionMaxAgeRaw
  : 7 * 24 * 60 * 60 * 1000;
const SESSION_COOKIE_SECURE = (process.env.SESSION_COOKIE_SECURE || '1') !== '0';
const rawSameSite = (process.env.SESSION_COOKIE_SAMESITE || 'none').toLowerCase();
const allowedSameSite = new Set(['lax', 'strict', 'none']);
const SESSION_COOKIE_SAME_SITE = allowedSameSite.has(rawSameSite) ? rawSameSite : 'none';
const SESSION_COOKIE_HTTP_ONLY = (process.env.SESSION_COOKIE_HTTP_ONLY || '1') !== '0';

 
const sessionStore = new Map();

function generateSessionId() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return crypto.randomBytes(32).toString('hex');
}

function registerSession(payload) {
  const sessionId = generateSessionId();
  const exp = now() + SESSION_COOKIE_MAX_AGE;
  const record = {
    id: sessionId,
    userId: payload.userId,
    personId: payload.personId,
    name: payload.name,
    isAdmin: payload.isAdmin,
    exp
  };
  sessionStore.set(sessionId, record);
  return record;
}

function getSession(sessionId) {
  if (!sessionId) return null;
  const record = sessionStore.get(sessionId);
  if (!record) return null;
  if (record.exp && record.exp < now()) {
    sessionStore.delete(sessionId);
    return null;
  }
  return record;
}

function destroySession(sessionId) {
  if (!sessionId) return false;
  return sessionStore.delete(sessionId);
}

function cleanupExpiredSessions(reference = now()) {
  for (const [id, record] of sessionStore.entries()) {
    if (!record?.exp) continue;
    if (record.exp <= reference) {
      sessionStore.delete(id);
    }
  }
}

function parseCookies(header = '') {
  return header
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, entry) => {
      const sep = entry.indexOf('=');
      if (sep === -1) return acc;
      const key = entry.slice(0, sep).trim();
      const val = entry.slice(sep + 1).trim();
      if (!key) return acc;
      try {
        acc[key] = decodeURIComponent(val);
      } catch (_) {
        acc[key] = val;
      }
      return acc;
    }, {});
}

function extractSessionId(req) {
  if (!SESSION_COOKIE_ENABLED) return null;
  const header = req.headers?.cookie;
  if (!header) return null;
  const cookies = parseCookies(header);
  return cookies[SESSION_COOKIE_NAME] || null;
}

function attachSession(req, _res, next) {
  if (!SESSION_COOKIE_ENABLED) return next();
  const sessionId = extractSessionId(req);
  if (!sessionId) return next();
  const record = getSession(sessionId);
  if (!record) return next();
  req.session = {
    id: record.id,
    userId: record.userId,
    personId: record.personId,
    name: record.name,
    isAdmin: record.isAdmin
  };
  return next();
}

if (SESSION_COOKIE_ENABLED) {
  const interval = setInterval(() => cleanupExpiredSessions(now()), 30 * 60 * 1000);
  if (typeof interval.unref === 'function') {
    interval.unref();
  }
}

const fetchFallback = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
async function fetchWithFallback(url, options) {
  if (typeof fetch === 'function') {
    return fetch(url, options);
  }
  return fetchFallback(url, options);
}

function pruneEmpty(value) {
  if (Array.isArray(value)) {
    const arr = value
      .map((entry) => pruneEmpty(entry))
      .filter((entry) => {
        if (entry === undefined || entry === null) return false;
        if (typeof entry === 'object' && !Array.isArray(entry) && !Object.keys(entry).length) return false;
        return true;
      });
    return arr.length ? arr : undefined;
  }

  if (value && typeof value === 'object' && value.constructor === Object) {
    const obj = Object.entries(value).reduce((acc, [key, val]) => {
      const next = pruneEmpty(val);
      if (next !== undefined) {
        acc[key] = next;
      }
      return acc;
    }, {});
    return Object.keys(obj).length ? obj : undefined;
  }

  if (value === undefined || value === null || value === '') {
    return undefined;
  }

  return value;
}

function httpError(status, message) {
  const err = new Error(message);
  err.statusCode = status;
  return err;
}

function toJsonNotes(obj) {
  if (!obj) return null;
  try { return JSON.stringify(obj); }
  catch { return null; }
}

function trimSlash(value = '') {
  return value ? String(value).replace(/\/+$/, '') : '';
}

function normalizeBaseUrl(value, { allowHttp = false } = {}) {
  const sanitized = sanitizeHttpsUrl(value, { allowHttp });
  return sanitized ? trimSlash(sanitized) : '';
}

const allowInsecureBridge = (process.env.ALLOW_INSECURE_LOCAL_BRIDGE || '') === '1';
const rawLocalBridgeUrl =
  process.env.LOCAL_BRIDGE_URL ||
  process.env.ROBOT_BRIDGE_URL ||
  process.env.FP_LOCAL_BRIDGE_URL ||
  '';
const LOCAL_BRIDGE_URL = normalizeBaseUrl(rawLocalBridgeUrl, { allowHttp: allowInsecureBridge });
if (!LOCAL_BRIDGE_URL && rawLocalBridgeUrl) {
  console.warn(
    '[config] LOCAL_BRIDGE_URL ignored because it must be an HTTPS endpoint. Set ALLOW_INSECURE_LOCAL_BRIDGE=1 for development.'
  );
}
const LOCAL_BRIDGE_TOKEN = process.env.LOCAL_BRIDGE_TOKEN || process.env.ROBOT_BRIDGE_TOKEN || '';
const ROBOT_EVENT_TOKEN = process.env.ROBOT_SITE_TOKEN || process.env.FP_SITE_TOKEN || '';
const PUBLIC_API_BASE = normalizeBaseUrl(process.env.PUBLIC_API_BASE || process.env.ROBOT_EVENT_BASE || '');
const DEFAULT_ROBOT_EVENT_URL = normalizeBaseUrl(
  process.env.ROBOT_EVENT_URL ||
    (PUBLIC_API_BASE ? `${PUBLIC_API_BASE}/api/robot/event` : ''),
  { allowHttp: false }
);

 
const allowInsecureBridgeHints = (process.env.ALLOW_INSECURE_BRIDGE_HINTS || '') === '1';

if (SESSION_COOKIE_ENABLED && SESSION_COOKIE_SAME_SITE === 'none' && !SESSION_COOKIE_SECURE) {
  console.warn('[config] SESSION_COOKIE_SECURE=0 is incompatible with SameSite=None. Cookie will not be set over HTTPS.');
}

async function fetchLocalBridge(pathname, options = {}, { timeoutMs = 5000 } = {}) {
  if (!LOCAL_BRIDGE_URL) {
    throw httpError(503, '로컬 브릿지가 설정되지 않았습니다');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = Object.assign({}, options.headers || {});
    const url = `${LOCAL_BRIDGE_URL}${pathname}`;
    const res = await fetchWithFallback(url, {
      ...options,
      headers,
      signal: controller.signal
    });
    return res;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw httpError(504, '로컬 브릿지 응답 지연');
    }
    throw httpError(503, `로컬 브릿지 연결 실패: ${err.message || err}`);
  } finally {
    clearTimeout(timer);
  }
}

async function checkLocalBridgeHealth() {
  const headers = { Accept: 'application/json' };
  if (LOCAL_BRIDGE_TOKEN) headers['x-bridge-token'] = LOCAL_BRIDGE_TOKEN;
  const res = await fetchLocalBridge('/health', { method: 'GET', headers }, { timeoutMs: 2500 });
  if (!res.ok) {
    throw httpError(503, `로컬 브릿지 헬스체크 실패: HTTP ${res.status}`);
  }
  try {
    return await res.json();
  } catch (_) {
    return null;
  }
}

app.use(express.static(path.join(__dirname))); // ★ 이 줄 추가

// CORS 설정: 환경 변수 기반 화이트리스트, 기본값은 개발 편의를 위해 허용
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use((err, req, res, next) => {
  if (err && err.message === 'Origin not allowed by CORS policy') {
    return res.status(403).json({ error: 'cors_not_allowed' });
  }
  return next(err);
});

// ⬇⬇ 추가: 프론트에서 보내는 JSON 바디를 파싱 (POST/PUT에 필수)
app.use(express.json());
app.use(attachSession);

// 데이터베이스 연결 설정
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function ensureDatabaseColumns() {
  const statements = [
    `ALTER TABLE requests ADD COLUMN IF NOT EXISTS status_reason TEXT`,
    `CREATE TABLE IF NOT EXISTS fp_templates (
       sensor_id INTEGER PRIMARY KEY,
       person_id INTEGER NOT NULL REFERENCES personnel(id) ON DELETE CASCADE,
       site TEXT NOT NULL DEFAULT 'default',
       last_enrolled TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
     )`,
    `ALTER TABLE fp_templates ADD COLUMN IF NOT EXISTS site TEXT`,
    `ALTER TABLE fp_templates ALTER COLUMN site SET DEFAULT 'default'`,
    `ALTER TABLE fp_templates ADD COLUMN IF NOT EXISTS last_enrolled TIMESTAMPTZ`,
    `ALTER TABLE fp_templates ALTER COLUMN last_enrolled SET DEFAULT CURRENT_TIMESTAMP`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_templates_person ON fp_templates(person_id)`
  ];
  for (const sql of statements) {
    try {
      await pool.query(sql);
    } catch (err) {
      console.error('[schema] ensure failed:', sql, err.message || err);
    }
  }
}

const schemaReady = ensureDatabaseColumns();

// 헬스체크
app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/health/db', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT current_database() AS db,
             current_user       AS db_user,
             (SELECT count(*) FROM firearms)   AS firearms_total,
             (SELECT count(*) FROM ammunition) AS ammo_total
    `);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'db health failed' }); }
});

// === Login API (임시-평문비교) ===
app.post('/api/login', async (req, res) => {
  try {
    const { user_id, password } = req.body || {};
    if (!user_id || !password) {
      return res.status(400).json({ error: 'missing user_id or password' });
    }

    const q = `
      SELECT id, name, user_id, password_hash, is_admin, rank, unit, position
      FROM personnel
      WHERE user_id = $1
      LIMIT 1
    `;
    const { rows } = await pool.query(q, [user_id]);
    if (!rows.length) return res.status(401).json({ error: 'invalid credentials' });

    const u = rows[0];

    // ⚠️ 임시: 평문 비교 (최종 배포 전 해시 검증으로 교체)
    if (String(u.password_hash) !== String(password)) {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    let sessionMeta = null;
    if (SESSION_COOKIE_ENABLED) {
      const session = registerSession({
        userId: u.id,
        personId: u.id,
        name: u.name,
        isAdmin: !!u.is_admin
      });
      sessionMeta = { exp: session.exp };
      res.cookie(SESSION_COOKIE_NAME, session.id, {
        httpOnly: SESSION_COOKIE_HTTP_ONLY,
        secure: SESSION_COOKIE_SECURE,
        sameSite: SESSION_COOKIE_SAME_SITE,
        domain: SESSION_COOKIE_DOMAIN,
        path: SESSION_COOKIE_PATH,
        maxAge: SESSION_COOKIE_MAX_AGE
      });
    }

    const payload = {
      id: u.id,
      name: u.name,
      user_id: u.user_id,
      is_admin: u.is_admin,
      rank: u.rank,
      unit: u.unit,
      position: u.position
    };
    if (sessionMeta) {
      payload.session = {
        expires_at: new Date(sessionMeta.exp).toISOString()
      };
    }

    return res.json(payload);
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'login failed' });
  }
});

app.post('/api/logout', (req, res) => {
  if (SESSION_COOKIE_ENABLED) {
    const sessionId = extractSessionId(req);
    if (sessionId) {
      destroySession(sessionId);
    }
    res.clearCookie(SESSION_COOKIE_NAME, {
      httpOnly: SESSION_COOKIE_HTTP_ONLY,
      secure: SESSION_COOKIE_SECURE,
      sameSite: SESSION_COOKIE_SAME_SITE,
      domain: SESSION_COOKIE_DOMAIN,
      path: SESSION_COOKIE_PATH
    });
  }
  res.json({ ok: true });
});


// ====================== Personnel API ======================

// 목록 조회 (프론트가 사용 중)
app.get('/api/personnel', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id, name, rank, military_id, unit, position,
        user_id, is_admin, contact, last_modified, notes
      FROM personnel
      ORDER BY id DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching personnel data:', err);
    res.status(500).json({ error: 'Failed to fetch personnel data' });
  }
});

// ⬇⬇ 추가: 단건 조회(선택사항, 디버깅/확인용)
app.get('/api/personnel/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, rank, military_id, unit, position,
              user_id, is_admin, contact, last_modified, notes,
              password_hash
       FROM personnel WHERE id=$1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching personnel item:', err);
    res.status(500).json({ error: 'Failed to fetch item' });
  }
});

// ⬇⬇ 추가: 신규 추가 (프론트의 “추가 → 저장”)
app.post('/api/personnel', async (req, res) => {
  const {
    name, rank, military_id, unit, position,
    user_id, password_hash, is_admin, contact, notes
  } = req.body;

  // 간단 검증 (필수값)
  const required = { name, rank, military_id, unit, position, user_id, password_hash };
  for (const [k, v] of Object.entries(required)) {
    if (v === undefined || v === null || String(v).trim() === '') {
      return res.status(400).json({ error: `missing field: ${k}` });
    }
  }

  try {
    const q = `
      INSERT INTO personnel
        (name, rank, military_id, unit, position, user_id,
         password_hash, is_admin, contact, notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      RETURNING id, name, rank, military_id, unit, position,
                user_id, is_admin, contact, last_modified, notes`;
    const { rows } = await pool.query(q, [
      name, rank, military_id, unit, position, user_id,
      password_hash, !!is_admin, contact ?? null, notes ?? null
    ]);
    res.json(rows[0]);
  } catch (err) {
    // UNIQUE 제약 위반 처리 (23505)
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'duplicate key (military_id or user_id)' });
    }
    console.error('Error inserting personnel:', err);
    res.status(500).json({ error: 'insert failed' });
  }
});

// ⬇⬇ 추가: 수정 (프론트의 “수정 → 저장”)
app.put('/api/personnel/:id', async (req, res) => {
  const id = req.params.id;
  const {
    name, rank, military_id, unit, position,
    user_id, password_hash, is_admin, contact, notes
  } = req.body;

  // 간단 검증
  const required = { name, rank, military_id, unit, position, user_id };
  for (const [k, v] of Object.entries(required)) {
    if (v === undefined || v === null || String(v).trim() === '') {
      return res.status(400).json({ error: `missing field: ${k}` });
    }
  }

  try {
    // 비밀번호가 비었거나 undefined인 경우, 컬럼 업데이트 생략
    const passGiven = (password_hash !== undefined && password_hash !== null && String(password_hash) !== '');
    let q, args;
    if (passGiven) {
      q = `
        UPDATE personnel SET
          name=$1, rank=$2, military_id=$3, unit=$4, position=$5,
          user_id=$6, password_hash=$7, is_admin=$8, contact=$9, notes=$10,
          last_modified=CURRENT_TIMESTAMP
        WHERE id=$11
        RETURNING id, name, rank, military_id, unit, position,
                  user_id, is_admin, contact, last_modified, notes`;
      args = [name, rank, military_id, unit, position, user_id, password_hash, !!is_admin, contact ?? null, notes ?? null, id];
    } else {
      q = `
        UPDATE personnel SET
          name=$1, rank=$2, military_id=$3, unit=$4, position=$5,
          user_id=$6, is_admin=$7, contact=$8, notes=$9,
          last_modified=CURRENT_TIMESTAMP
        WHERE id=$10
        RETURNING id, name, rank, military_id, unit, position,
                  user_id, is_admin, contact, last_modified, notes`;
      args = [name, rank, military_id, unit, position, user_id, !!is_admin, contact ?? null, notes ?? null, id];
    }
    const { rows } = await pool.query(q, args);

    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'duplicate key (military_id or user_id)' });
    }
    console.error('Error updating personnel:', err);
    res.status(500).json({ error: 'update failed' });
  }
});

// ⬇⬇ 추가: 삭제 (프론트의 “삭제” - 선택 n건을 개별 호출)
app.delete('/api/personnel/:id', async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM personnel WHERE id=$1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true });
  } catch (err) {
    // 🔴 FK 위반: firearms.owner_id가 이 personnel.id를 참조하면 삭제 불가
    if (err && err.code === '23503') {
      return res.status(409).json({
        error: 'conflict_foreign_key',
        message: '해당 인원에게 배정된 총기가 있어 삭제할 수 없습니다. 총기 배정을 해제(재배정/삭제)한 뒤 다시 시도하세요.'
      });
    }
    console.error('Error deleting personnel:', err);
    res.status(500).json({ error: 'delete failed' });
  }
});


// ===== Firearms API =====

// 목록 조회 (JOIN: 프론트가 owner_* 그대로 사용)
// ===== Firearms API (검색/가용 필터 지원) =====
// 총기 검색: 상태 필터 + 예약 중(제출/승인)인 총기는 제외
app.get('/api/firearms', async (req,res)=>{
  try{
    const q = (req.query.q||'').trim();
    const status = (req.query.status||'').trim(); // '불입' or '불출' or ''
    const limit = Math.min(parseInt(req.query.limit||'50',10)||50, 100);
    const requesterId = parseInt(req.query.requester_id||'0',10) || null;
    const ownerId     = parseInt(req.query.owner_id||'0',10) || null;
    const idEq        = parseInt(req.query.id||'0',10) || null;
    const hideReserved= String(req.query.hide_reserved||'').trim()==='1';

    let ownerClause = '';
    let args = [q, status];
    if (ownerId) {
      ownerClause = ` AND f.owner_id = $${args.length+1}`; args.push(ownerId);
    } else if (requesterId) {
      const u=await pool.query(`SELECT is_admin, unit FROM personnel WHERE id=$1`,[requesterId]);
      const isAdmin = !!(u.rowCount && u.rows[0].is_admin);
      if(!isAdmin){
        ownerClause = ` AND f.owner_id = $${args.length+1}`; args.push(requesterId);
      }
    }

    if (idEq) {
      const { rows } = await pool.query(`
        SELECT f.id, f.firearm_number, f.firearm_type, f.status, f.storage_locker,
          EXISTS(
            SELECT 1
            FROM request_items ri JOIN requests r ON r.id=ri.request_id
            WHERE ri.item_type='FIREARM' AND ri.firearm_id=f.id
              AND r.status IN ('SUBMITTED','APPROVED')
          ) AS reserved
        FROM firearms f
        WHERE f.id=$1
      `,[idEq]);
      return res.json(rows);
    }

    // ★ 리스트에도 reserved 컬럼 포함
    const { rows } = await pool.query(`
      SELECT f.id, f.firearm_number, f.firearm_type, f.status, f.storage_locker,
        EXISTS(
          SELECT 1
          FROM request_items ri JOIN requests r ON r.id=ri.request_id
          WHERE ri.item_type='FIREARM' AND ri.firearm_id=f.id
            AND r.status IN ('SUBMITTED','APPROVED')
        ) AS reserved
      FROM firearms f
      WHERE ($1 = '' OR f.firearm_number ILIKE '%'||$1||'%' OR f.firearm_type ILIKE '%'||$1||'%')
        AND ($2 = '' OR f.status = $2)
        ${ownerClause}
        ${hideReserved ? `AND NOT EXISTS (
            SELECT 1 FROM request_items ri JOIN requests r ON r.id=ri.request_id
            WHERE ri.item_type='FIREARM' AND ri.firearm_id=f.id AND r.status IN ('SUBMITTED','APPROVED')
          )` : ``}
      ORDER BY f.firearm_number
      LIMIT $${args.length+1}
    `,[...args, limit]);

    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({error:'firearms search failed'}); }
});



// 단건 조회(선택)
app.get('/api/firearms/:id', async (req, res) => {
  try {
    const q = `
      SELECT
        f.id, f.owner_id,
        p.name AS owner_name, p.rank AS owner_rank, p.military_id AS owner_military_id,
        p.unit AS owner_unit, p.position AS owner_position,
        f.firearm_type, f.firearm_number, f.storage_locker, f.status, f.last_change, f.notes
      FROM firearms f
      LEFT JOIN personnel p ON f.owner_id = p.id
      WHERE f.id=$1
    `;
    const { rows } = await pool.query(q, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching firearm item:', err);
    res.status(500).json({ error: 'Failed to fetch item' });
  }
});

// 추가 (firearm_number UNIQUE)
app.post('/api/firearms', async (req, res) => {
  const { owner_id, firearm_type, firearm_number, storage_locker, status, notes } = req.body;

  const required = { owner_id, firearm_type, firearm_number, storage_locker, status };
  for (const [k, v] of Object.entries(required)) {
    if (v === undefined || v === null || String(v).trim() === '') {
      return res.status(400).json({ error: `missing field: ${k}` });
    }
  }

  try {
    const q = `
      INSERT INTO firearms
        (owner_id, firearm_type, firearm_number, storage_locker, status, notes)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING id
    `;
    const { rows } = await pool.query(q, [
      owner_id, firearm_type, firearm_number, storage_locker, status, notes ?? null
    ]);
    res.json({ id: rows[0].id });
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'duplicate key (firearm_number)' });
    }
    console.error('Error inserting firearm:', err);
    res.status(500).json({ error: 'insert failed' });
  }
});

// 현황(리스트) 전용: 소유자·군번·보관함·비고까지 모두 포함 + 검색/상태필터 지원
app.get('/api/firearms_full', async (req,res)=>{
  try{
    const q = (req.query.q||'').trim();
    const status = (req.query.status||'').trim(); // '' | '불입' | '불출'
    const { rows } = await pool.query(`
      SELECT
        f.id, f.owner_id,
        p.name AS owner_name, p.rank AS owner_rank, p.military_id AS owner_military_id,
        p.unit AS owner_unit, p.position AS owner_position,
        f.firearm_type, f.firearm_number, f.storage_locker, f.status, f.last_change, f.notes
      FROM firearms f
      LEFT JOIN personnel p ON p.id = f.owner_id
      WHERE ($1 = '' OR
             f.firearm_number ILIKE '%'||$1||'%' OR
             f.firearm_type   ILIKE '%'||$1||'%' OR
             p.name           ILIKE '%'||$1||'%' OR
             p.military_id    ILIKE '%'||$1||'%' OR
             p.unit           ILIKE '%'||$1||'%' OR
             p.position       ILIKE '%'||$1||'%')
        AND ($2 = '' OR f.status = $2)
      ORDER BY f.id DESC
    `,[q,status]);
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({error:'firearms_full failed'}); }
});

// 수정
app.put('/api/firearms/:id', async (req, res) => {
  const id = req.params.id;
  const { owner_id, firearm_type, firearm_number, storage_locker, status, notes } = req.body;

  const required = { owner_id, firearm_type, firearm_number, storage_locker, status };
  for (const [k, v] of Object.entries(required)) {
    if (v === undefined || v === null || String(v).trim() === '') {
      return res.status(400).json({ error: `missing field: ${k}` });
    }
  }

  try {
    const q = `
      UPDATE firearms SET
        owner_id=$1, firearm_type=$2, firearm_number=$3, storage_locker=$4,
        status=$5, notes=$6, last_change=CURRENT_TIMESTAMP
      WHERE id=$7
      RETURNING id
    `;
    const { rows } = await pool.query(q, [
      owner_id, firearm_type, firearm_number, storage_locker, status, notes ?? null, id
    ]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ id: rows[0].id });
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'duplicate key (firearm_number)' });
    }
    console.error('Error updating firearm:', err);
    res.status(500).json({ error: 'update failed' });
  }
});

// 삭제
app.delete('/api/firearms/:id', async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM firearms WHERE id=$1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err && err.code === '23503') {
      return res.status(409).json({
        error: 'conflict_foreign_key',
        message: '요청/이력에서 해당 총기를 참조 중이라 삭제할 수 없습니다.'
      });
    }
    console.error('Error deleting firearm:', err);
    res.status(500).json({ error: 'delete failed' });
  }
});



// ===== Ammunition API =====

// 목록 조회
// ===== Ammunition API (검색 지원) =====
// 탄약 검색: 가용재고(available = quantity - 예약)까지 리턴
app.get('/api/ammunition', async (req,res)=>{
  try{
    const q = (req.query.q||'').trim();
    const limit = Math.min(parseInt(req.query.limit||'50',10)||50, 100);

    const { rows } = await pool.query(`
      SELECT a.id, a.ammo_name, a.ammo_category, a.quantity, a.storage_locker, a.status,
        (a.quantity - COALESCE((
          SELECT SUM(ri.quantity)
          FROM request_items ri JOIN requests r ON r.id=ri.request_id
          WHERE ri.item_type='AMMO' AND ri.ammo_id=a.id
            AND r.request_type='DISPATCH'
            AND r.status IN ('SUBMITTED','APPROVED')
        ),0))::int AS available
      FROM ammunition a
      WHERE ($1='' OR a.ammo_name ILIKE '%'||$1||'%' OR a.ammo_category ILIKE '%'||$1||'%')
      ORDER BY a.ammo_name
      LIMIT $2
    `,[q, limit]);

    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({error:'ammunition search failed'}); }
});


// 단건 조회(선택)
app.get('/api/ammunition/:id', async (req, res) => {
  try {
    const q = `
      SELECT
        id, ammo_name, ammo_category, quantity, storage_locker,
        status, last_change, notes
      FROM ammunition
      WHERE id=$1
    `;
    const { rows } = await pool.query(q, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching ammunition item:', err);
    res.status(500).json({ error: 'Failed to fetch item' });
  }
});

// 추가
app.post('/api/ammunition', async (req, res) => {
  const { ammo_name, ammo_category, quantity, storage_locker, status, notes } = req.body;

  const required = { ammo_name, ammo_category, quantity, storage_locker, status };
  for (const [k, v] of Object.entries(required)) {
    if (v === undefined || v === null || String(v).trim?.() === '') {
      return res.status(400).json({ error: `missing field: ${k}` });
    }
  }
  const qnum = Number(quantity);
  if (!Number.isInteger(qnum) || qnum < 0) {
    return res.status(400).json({ error: 'quantity must be a non-negative integer' });
  }

  try {
    const q = `
      INSERT INTO ammunition
        (ammo_name, ammo_category, quantity, storage_locker, status, notes)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING id
    `;
    const { rows } = await pool.query(q, [
      ammo_name, ammo_category, qnum, storage_locker, status, notes ?? null
    ]);
    res.json({ id: rows[0].id });
  } catch (err) {
    console.error('Error inserting ammunition:', err);
    res.status(500).json({ error: 'insert failed' });
  }
});

// 수정
app.put('/api/ammunition/:id', async (req, res) => {
  const id = req.params.id;
  const { ammo_name, ammo_category, quantity, storage_locker, status, notes } = req.body;

  const required = { ammo_name, ammo_category, quantity, storage_locker, status };
  for (const [k, v] of Object.entries(required)) {
    if (v === undefined || v === null || String(v).trim?.() === '') {
      return res.status(400).json({ error: `missing field: ${k}` });
    }
  }
  const qnum = Number(quantity);
  if (!Number.isInteger(qnum) || qnum < 0) {
    return res.status(400).json({ error: 'quantity must be a non-negative integer' });
  }

  try {
    const q = `
      UPDATE ammunition SET
        ammo_name=$1, ammo_category=$2, quantity=$3,
        storage_locker=$4, status=$5, notes=$6, last_change=CURRENT_TIMESTAMP
      WHERE id=$7
      RETURNING id
    `;
    const { rows } = await pool.query(q, [
      ammo_name, ammo_category, qnum, storage_locker, status, notes ?? null, id
    ]);
    if (!rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ id: rows[0].id });
  } catch (err) {
    console.error('Error updating ammunition:', err);
    res.status(500).json({ error: 'update failed' });
  }
});

// 삭제
app.delete('/api/ammunition/:id', async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM ammunition WHERE id=$1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting ammunition:', err);
    res.status(500).json({ error: 'delete failed' });
  }
});


  /* ===========================================
  * 워크센터 API (신청/승인/집행/로그)
  * =========================================== */

  // 트랜잭션 헬퍼
  async function withTx(run){
    await schemaReady;
    const client = await pool.connect();
    try{
      await client.query('BEGIN');
      const result = await run(client);
      await client.query('COMMIT');
      return result;
    }catch(e){
      await client.query('ROLLBACK');
      throw e;
    }finally{
      client.release();
    }
  }

    function mergeDispatchPayload(primary, fallback) {
    const a = pruneEmpty(primary);
    const b = pruneEmpty(fallback);
    if (!a && !b) return undefined;
    if (!a) return b;
    if (!b) return a;

    const includes = pruneEmpty({
      ...(b.includes || {}),
      ...(a.includes || {})
    });

    const firearm = pruneEmpty({
      ...(b.firearm || {}),
      ...(a.firearm || {})
    });

    const ammo = Array.isArray(a.ammo) && a.ammo.length
      ? a.ammo
      : (Array.isArray(b.ammo) && b.ammo.length ? b.ammo : undefined);

    return pruneEmpty({
      ...b,
      ...a,
      includes,
      firearm,
      ammo
    });
  }

  async function buildDispatchPayloadFromDb(client, requestRow, incomingDispatch) {
    const items = (await client.query(`
      SELECT ri.*, 
             f.firearm_number, f.firearm_type, f.storage_locker AS firearm_storage_locker,
             a.ammo_name, a.ammo_category, a.storage_locker AS ammo_storage_locker
        FROM request_items ri
        LEFT JOIN firearms f   ON f.id = ri.firearm_id
        LEFT JOIN ammunition a ON a.id = ri.ammo_id
       WHERE ri.request_id = $1
       ORDER BY ri.id
    `, [requestRow.id])).rows;

    const firearmItems = items.filter((row) => String(row.item_type || '').toUpperCase() === 'FIREARM');
    const ammoItems = items.filter((row) => String(row.item_type || '').toUpperCase() === 'AMMO');
    const primaryFirearm = firearmItems[0] || null;

    const includes = {
      firearm: firearmItems.length > 0,
      ammo: ammoItems.length > 0
    };

    const lockerFromDb = primaryFirearm?.firearm_storage_locker
      || requestRow.storage_locker
      || null;
    const locationFromDb = requestRow.location
      || null;

    const ammoPayload = ammoItems
      .map((entry) => pruneEmpty({
        id: entry.ammo_id || entry.id || null,
        name: entry.ammo_name || null,
        category: entry.ammo_category || null,
        qty: entry.quantity || entry.qty || null,
        locker: entry.ammo_storage_locker || null
      })) || [];

    const dispatchFromDb = pruneEmpty({
      request_id: requestRow.id,
      site_id: requestRow.site_id || requestRow.site || null,
      type: requestRow.request_type || requestRow.type || null,
      mode: includes.firearm && includes.ammo
        ? 'firearm_and_ammo'
        : (includes.firearm ? 'firearm_only' : (includes.ammo ? 'ammo_only' : 'none')),
      includes,
      firearm: primaryFirearm ? pruneEmpty({
        id: primaryFirearm.firearm_id || primaryFirearm.id || null,
        code: primaryFirearm.firearm_number || null,
        type: primaryFirearm.firearm_type || null,
        locker: primaryFirearm.firearm_storage_locker || requestRow.storage_locker || null
      }) : undefined,
      ammo: ammoPayload && ammoPayload.length ? ammoPayload : undefined,
      locker: lockerFromDb || null,
      location: locationFromDb || null,
      purpose: requestRow.purpose || null,
      requested_at: requestRow.requested_at || requestRow.created_at || null,
      approved_at: requestRow.approved_at || null,
      status: requestRow.status || null
    });

    const mergedDispatch = mergeDispatchPayload(incomingDispatch, dispatchFromDb);

    const itemsPayload = pruneEmpty(items.map((entry) => ({
      id: entry.id || null,
      item_type: entry.item_type || null,
      quantity: entry.quantity || null,
      firearm_id: entry.firearm_id || null,
      ammo_id: entry.ammo_id || null,
      firearm: entry.firearm_id ? pruneEmpty({
        id: entry.firearm_id,
        number: entry.firearm_number || null,
        type: entry.firearm_type || null,
        locker: entry.firearm_storage_locker || null
      }) : undefined,
      ammo: entry.ammo_id ? pruneEmpty({
        id: entry.ammo_id,
        name: entry.ammo_name || null,
        category: entry.ammo_category || null,
        locker: entry.ammo_storage_locker || null
      }) : undefined
    })));

    const forward = pruneEmpty({
      url: DEFAULT_ROBOT_EVENT_URL || null,
      token: ROBOT_EVENT_TOKEN || null,
      site: requestRow.site_id || requestRow.site || null
    });

    return { dispatch: mergedDispatch, items: itemsPayload, forward };
  }

  function buildRobotDispatchPayload({ request, executor, executedBy, dispatch, eventId, items, forward }) {
    const requestSummary = pruneEmpty({
      id: request.id,
      requester_id: request.requester_id,
      request_type: request.request_type || request.type || null,
      status: request.status || null,
      site_id: request.site_id || request.site || null,
      locker: dispatch?.locker || request.storage_locker || null,
      location: request.location || dispatch?.location || null,
      scheduled_at: request.scheduled_at || null,
      purpose: request.purpose || null,
      requested_at: request.requested_at || request.created_at || null,
      approved_at: request.approved_at || null
    });

        const forwardDefault = pruneEmpty({
      url: DEFAULT_ROBOT_EVENT_URL || null,
      token: ROBOT_EVENT_TOKEN || null,
      site: request.site_id || request.site || null
    });

    const forwardConfig = pruneEmpty({
      ...(forwardDefault || {}),
      ...(forward || {})
    });

    return pruneEmpty({
      requestId: request.id,
      executionEventId: eventId,
      executedBy: executedBy || null,
      executor: executor || null,
      dispatch,
      items,
      request: requestSummary,
      type: request.request_type || null,
      mode: dispatch?.mode || null,
      site: dispatch?.site_id || request.site_id || request.site || null,
      status: request.status || null,
      timestamp: new Date().toISOString(),
      forward: forwardConfig
    });
  }

  async function finalizeRequestExecution(client, requestRow, executedBy, { notes = null, statusReason = null, eventId = null } = {}) {
    const id = requestRow.id;
    const eventType = requestRow.request_type || requestRow.type || 'EXECUTION';
    let execId = eventId || null;

    if (eventId) {
      await client.query(
        `UPDATE execution_events
            SET executed_by=$2,
                event_type=$3,
                notes=$4,
                executed_at=now()
          WHERE id=$1`,
        [eventId, executedBy, eventType, notes]
      );
    } else {
      const ev = await client.query(
        `INSERT INTO execution_events(request_id, executed_by, event_type, notes)
         VALUES($1,$2,$3,$4) RETURNING id`,
        [id, executedBy, eventType, notes]
      );
      execId = ev.rows[0].id;
    }

    const items = await client.query(
      `SELECT item_type, firearm_id, ammo_id, quantity
       FROM request_items WHERE request_id=$1`,
      [id]
    );

    for (const it of items.rows) {
      if (it.item_type === 'FIREARM') {
        const fq = await client.query(`SELECT id,status FROM firearms WHERE id=$1 FOR UPDATE`, [it.firearm_id]);
        if (!fq.rowCount) throw new Error('총기 없음');
        const from = fq.rows[0].status;
        const to = (requestRow.request_type === 'DISPATCH' ? '불출' : '불입');
        await client.query(`UPDATE firearms SET status=$1, last_change=now() WHERE id=$2`, [to, it.firearm_id]);
        await client.query(
          `INSERT INTO firearm_status_changes(execution_id, firearm_id, from_status, to_status)
           VALUES($1,$2,$3,$4)`,
          [execId, it.firearm_id, from, to]
        );
      } else if (it.item_type === 'AMMO') {
        const aq = await client.query(`SELECT id, quantity FROM ammunition WHERE id=$1 FOR UPDATE`, [it.ammo_id]);
        if (!aq.rowCount) throw new Error('탄약 없음');
        const before = aq.rows[0].quantity;
        const delta = (requestRow.request_type === 'DISPATCH' ? -it.quantity : +it.quantity);
        const after = before + delta;
        if (after < 0) throw new Error('탄약 재고 음수 불가');
        await client.query(`UPDATE ammunition SET quantity=$1, last_change=now() WHERE id=$2`, [after, it.ammo_id]);
        await client.query(
          `INSERT INTO ammo_movements(execution_id, ammo_id, delta, before_qty, after_qty)
           VALUES($1,$2,$3,$4,$5)`,
          [execId, it.ammo_id, delta, before, after]
        );
      }
    }

    await client.query(`UPDATE requests SET status='EXECUTED', status_reason=$2, updated_at=now() WHERE id=$1`, [id, statusReason || null]);
    return { eventId: execId };
  }

  async function sendRobotDispatch(payload) {
    if (!LOCAL_BRIDGE_URL) {
      return { ok: false, skipped: true, error: 'bridge_unconfigured' };
    }
    try {
      const headers = { 'content-type': 'application/json' };
      if (LOCAL_BRIDGE_TOKEN) headers['x-bridge-token'] = LOCAL_BRIDGE_TOKEN;
      const res = await fetchLocalBridge('/robot/execute', {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });
      let data = null;
      try { data = await res.json(); } catch (_) { data = null; }
      if (!res.ok || (data && data.ok === false)) {
        return { ok: false, status: res.status, data, error: data?.error || data?.message || `HTTP ${res.status}` };
      }
      return { ok: true, data };
    } catch (err) {
      return { ok: false, error: err.message || String(err), status: err.statusCode || err.status || undefined };
    }
  }

  async function handleRobotEvent({ requestId, status, job, site }) {
    const normalized = String(status || job?.status || '').toLowerCase();
    const eventId = job?.eventId || job?.executionEventId || job?.execution_event_id || null;
    const message = job?.message || '';
    const stage = job?.stage || '';
    const notesPayload = toJsonNotes({ stage: normalized, job, site });

    if (!normalized) {
      return;
    }

    if (normalized === 'accepted' || normalized === 'queued' || normalized === 'dispatched') {
      await withTx(async (client) => {
        await client.query(`UPDATE requests SET status_reason=$2, updated_at=now() WHERE id=$1`, [requestId, message || '장비 명령 대기 중']);
        if (eventId) {
          await client.query(`UPDATE execution_events SET notes=$1 WHERE id=$2`, [notesPayload, eventId]);
        }
      });
      return;
    }

    if (normalized === 'progress' || normalized === 'executing' || normalized === 'running') {
      await withTx(async (client) => {
        await client.query(`UPDATE requests SET status_reason=$2, updated_at=now() WHERE id=$1`, [requestId, message || stage || '장비 동작 중']);
        if (eventId) {
          await client.query(`UPDATE execution_events SET notes=$1 WHERE id=$2`, [notesPayload, eventId]);
        }
      });
      return;
    }

    if (normalized === 'success' || normalized === 'succeeded' || normalized === 'completed') {
      await withTx(async (client) => {
        const rq = await client.query(`SELECT * FROM requests WHERE id=$1 FOR UPDATE`, [requestId]);
        if (!rq.rowCount) throw httpError(404, 'request_not_found');
        const requestRow = rq.rows[0];
        if (requestRow.status === 'EXECUTED') {
          const completionNotes = toJsonNotes({ stage: 'completed', job, site });
          if (eventId) {
            await client.query(`UPDATE execution_events SET notes=$1 WHERE id=$2`, [completionNotes, eventId]);
          }
          return;
        }

        const execReq = eventId
          ? await client.query(`SELECT id, executed_by FROM execution_events WHERE id=$1`, [eventId])
          : await client.query(`SELECT id, executed_by FROM execution_events WHERE request_id=$1 ORDER BY executed_at DESC LIMIT 1`, [requestId]);
        const execRow = execReq.rowCount ? execReq.rows[0] : null;
        const executedBy = job?.executedBy || job?.executorId || execRow?.executed_by || null;
        const completionNotes = toJsonNotes({ stage: 'completed', job, site });
        const successReason = job?.message
          || (job?.summary?.actionLabel ? `${job.summary.actionLabel} 완료` : '장비 제어가 정상적으로 완료되었습니다.');

        const primaryEventId = execRow?.id || eventId || null;

        await finalizeRequestExecution(client, requestRow, executedBy, {
          notes: completionNotes,
          statusReason: successReason,
          eventId: primaryEventId
        });

        if (primaryEventId && (!execRow || primaryEventId !== execRow.id)) {
          await client.query(`UPDATE execution_events SET notes=$1 WHERE id=$2`, [completionNotes, primaryEventId]);
        }
      });
      return;
    }

    if (normalized === 'error' || normalized === 'failed' || normalized === 'timeout') {
      const reason = message || stage || '장비 오류';
      await withTx(async (client) => {
        await client.query(`UPDATE requests SET status='APPROVED', status_reason=$2, updated_at=now() WHERE id=$1`, [requestId, reason]);
        if (eventId) {
          await client.query(`UPDATE execution_events SET notes=$1 WHERE id=$2`, [notesPayload, eventId]);
        }
      });
      return;
    }
  }


  // 1) 신청 생성
// 1) 신청 생성 (원자성 + 서버측 필수검증)
app.post('/api/requests', async (req,res)=>{
  try{
    const { requester_id, request_type, purpose, location, scheduled_at, notes, items=[] } = req.body;

    // 서버측 필수검증
    const miss=[];
    if(!requester_id) miss.push('requester_id');
    if(!request_type) miss.push('request_type');
    if(!scheduled_at) miss.push('scheduled_at');
    if(!purpose) miss.push('purpose');
    if(!location) miss.push('location');
    if(!Array.isArray(items) || items.length===0) miss.push('items');
    if(miss.length) return res.status(400).json({error:`missing fields: ${miss.join(', ')}`});

    await withTx(async(client)=>{
      // 요청자 권한 확인
      const who = await client.query(`SELECT is_admin FROM personnel WHERE id=$1`, [requester_id]);
      if(!who.rowCount) throw new Error('요청자 없음');
      const isAdmin = !!who.rows[0].is_admin;

      // 요청 생성
      const r = await client.query(
        `INSERT INTO requests(requester_id,request_type,purpose,location,scheduled_at,notes)
         VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
        [requester_id, request_type, purpose, location, scheduled_at, notes ?? null]
      );
      const reqId = r.rows[0].id;

      // 1) 클라이언트가 보낸 아이템 먼저 처리 (FIREARM/AMMO)
      for(const it of items){
        if(it.type==='FIREARM'){
          // 해당 총기 행 잠금 + 중복 신청 존재 여부 체크
          const fq = await client.query(
            `SELECT id, status, owner_id FROM firearms WHERE id=$1 FOR UPDATE`,
            [it.firearm_id || it.id]
          );
          if(!fq.rowCount) throw new Error('총기를 찾을 수 없습니다');
          const f = fq.rows[0];
          if(!isAdmin && f.owner_id !== requester_id) {
            throw new Error('일반 사용자는 본인 총기만 신청할 수 있습니다');
          }

          // 이미 제출/승인 대기 중인 신청이 있으면 차단
          const dup = await client.query(`
            SELECT 1
            FROM request_items ri JOIN requests r2 ON r2.id=ri.request_id
            WHERE ri.item_type='FIREARM' AND ri.firearm_id=$1
              AND r2.status IN ('SUBMITTED','APPROVED')
            LIMIT 1
          `,[f.id]);
          if(dup.rowCount) throw new Error('해당 총기에 진행 중인 다른 신청이 있습니다');

          await client.query(
            `INSERT INTO request_items(request_id,item_type,firearm_id) VALUES($1,'FIREARM',$2)`,
            [reqId, f.id]
          );

        // 자동 탄약 추가: 근무/경계 목적 + DISPATCH이며, AMMO 라인이 아직 없을 때
        if (request_type === 'DISPATCH'
            && /(근무|경계)/.test(String(purpose||''))
            && !items.some(x => x.type === 'AMMO')) {

          // '공포탄' 카테고리 & '5.56mm' 품명(포함) 중 재고 많은 것 1개 선택
          const am = await client.query(`
            SELECT id, quantity
            FROM ammunition
            WHERE ammo_category = '공포탄'
              AND ammo_name ILIKE '%5.56mm%'
            ORDER BY quantity DESC
            LIMIT 1
          `);
          if (am.rowCount) {
            const ammo = am.rows[0];

            // 예약 포함 가용재고 계산(동시성 보호를 위해 행 잠금)
            const av = await client.query(`
              SELECT (a.quantity - COALESCE((
                SELECT SUM(ri.quantity)
                FROM request_items ri JOIN requests r2 ON r2.id = ri.request_id
                WHERE ri.item_type='AMMO' AND ri.ammo_id=a.id
                  AND r2.request_type='DISPATCH'
                  AND r2.status IN ('SUBMITTED','APPROVED')
              ),0))::int AS available
              FROM ammunition a
              WHERE a.id=$1
              FOR UPDATE
            `,[ammo.id]);

            const available = Math.max(0, av.rows[0].available|0);
            const wantQty  = 30;                 // 기본값 (원하면 조정: 10/20/30 등)
            const qty      = Math.min(wantQty, available);

            if (qty > 0) {
              await client.query(
                `INSERT INTO request_items(request_id,item_type,ammo_id,quantity)
                VALUES($1,'AMMO',$2,$3)`,
                [reqId, ammo.id, qty]
              );
            }
          }
        }

        // ---------- 자동 탄약 추가: 불입(return) 처리 ----------
        /*
          조건:
            - request_type 이 'RETURN' (또는 서버에서 불입을 의미하는 값) 일 것
            - purpose 에 '근무' 또는 '경계' 가 포함될 것
            - 요청에 이미 AMMO 항목이 없을 것
          동작:
            - ammunition 테이블에서 카테고리 '공포탄' & ammo_name에 '5.56mm' 포함된 품목 중
              재고/가용 기준으로 하나 선택하여 request_items에 삽입 (qty = 기본 wantQty 또는 실제 수량)
        */
        if ((request_type === 'RETURN' || request_type === 'INCOMING')
          && /(근무|경계)/.test(String(purpose||''))
          && !items.some(x => x.type === 'AMMO')) {

          // 동일한 선택 로직: 공포탄 + 5.56mm 포함 항목 중 재고 많은 것 선택
          const am = await client.query(`
            SELECT id, quantity
            FROM ammunition
            WHERE ammo_category = '공포탄'
              AND ammo_name ILIKE '%5.56mm%'
            ORDER BY quantity DESC
            LIMIT 1
          `);
          if (am.rowCount) {
            const ammo = am.rows[0];

            // FOR UPDATE로 잠금 후, (반납이므로 재고 확인은 필수 아님 — 하지만 여전히 안전하게 현재 qty 확인)
            const av = await client.query(`
              SELECT a.quantity
              FROM ammunition a
              WHERE a.id=$1
              FOR UPDATE
            `,[ammo.id]);

            const currentQty = (av.rowCount ? (av.rows[0].quantity|0) : (ammo.quantity|0));
            const wantQty = 30; // 기본 반납 수량 (필요 시 변경)
            // 반납은 재고 제한이 아니라 반납 수량으로 처리(마이너스가 아닌 양으로 처리)
            const qty = Math.min(wantQty, Math.max(1, wantQty)); // 최소 1로 강제

            // Insert as AMMO item. 마킹을 위해 ident에 '_auto_return' 표시 추가하거나 별도 컬럼이 있다면 사용
            await client.query(
              `INSERT INTO request_items(request_id, item_type, ammo_id, quantity)
              VALUES($1,'AMMO',$2,$3)`,
              [reqId, ammo.id, qty]
            );
          }
        }



        } else if(it.type==='AMMO'){
          if(!isAdmin) throw new Error('일반 사용자는 탄약을 신청할 수 없습니다');
          const aq = await client.query(`
            SELECT a.id, a.quantity,
                   (a.quantity - COALESCE((
                      SELECT SUM(ri.quantity)
                      FROM request_items ri JOIN requests r2 ON r2.id=ri.request_id
                      WHERE ri.item_type='AMMO' AND ri.ammo_id=a.id
                        AND r2.request_type='DISPATCH'
                        AND r2.status IN ('SUBMITTED','APPROVED')
                   ),0))::int AS available
            FROM ammunition a
            WHERE a.id=$1
            FOR UPDATE
          `,[it.ammo_id || it.id]);
          if(!aq.rowCount) throw new Error('탄약을 찾을 수 없습니다');
          const a = aq.rows[0];
          const qty = parseInt(it.qty,10);
          if(!Number.isInteger(qty) || qty<=0) throw new Error('탄약 수량이 올바르지 않습니다');

          // 제출 시점에 예약 포함 가용재고로 검증(과예약 방지)
          if(request_type==='DISPATCH' && qty>a.available)
            throw new Error(`재고 부족(예약 포함): 보유 ${a.quantity}, 가용 ${a.available}`);

          await client.query(
            `INSERT INTO request_items(request_id,item_type,ammo_id,quantity)
             VALUES($1,'AMMO',$2,$3)`,
            [reqId, a.id, qty]
          );
        }else{
          throw new Error('알 수 없는 항목 타입');
        }
      }

      // 2) ✅ 자동 탄약 추가는 "요청당 1회"만 (루프 밖)
      const isDuty = /(근무|경계)/.test(String(purpose||''));
      const hasAmmoAlready = (await client.query(
        `SELECT 1 FROM request_items WHERE request_id=$1 AND item_type='AMMO' LIMIT 1`,
        [reqId]
      )).rowCount > 0;

      if (!hasAmmoAlready && isDuty) {
        if (request_type === 'DISPATCH') {
          // 공포탄 5.56mm 중 재고 많은 것 1개 선택 + 가용재고 확인
          const am = await client.query(`
            SELECT id FROM ammunition
            WHERE ammo_category='공포탄' AND ammo_name ILIKE '%5.56mm%'
            ORDER BY quantity DESC LIMIT 1`);
          if (am.rowCount) {
            const ammoId = am.rows[0].id;
            const av = await client.query(`
              SELECT (a.quantity - COALESCE((
                SELECT SUM(ri.quantity)
                FROM request_items ri JOIN requests r2 ON r2.id=ri.request_id
                WHERE ri.item_type='AMMO' AND ri.ammo_id=a.id
                  AND r2.request_type='DISPATCH'
                  AND r2.status IN ('SUBMITTED','APPROVED')
              ),0))::int AS available
              FROM ammunition a WHERE a.id=$1 FOR UPDATE`, [ammoId]);
            const qty = Math.min(30, Math.max(0, av.rows[0].available|0));
            if (qty > 0) {
              await client.query(
                `INSERT INTO request_items(request_id,item_type,ammo_id,quantity)
                 VALUES($1,'AMMO',$2,$3)`, [reqId, ammoId, qty]);
            }
          }
        } else if (request_type === 'RETURN' || request_type === 'INCOMING') {
          const am = await client.query(`
            SELECT id FROM ammunition
            WHERE ammo_category='공포탄' AND ammo_name ILIKE '%5.56mm%'
            ORDER BY quantity DESC LIMIT 1`);
          if (am.rowCount) {
            await client.query(
              `INSERT INTO request_items(request_id,item_type,ammo_id,quantity)
               VALUES($1,'AMMO',$2,$3)`, [reqId, am.rows[0].id, 30]);
          }
        }
      }

      res.json({ok:true, id:reqId});
    });
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});


  // 2) 신청 목록
  // 2) 신청 목록 (확장: requester_id, related_owner_id, since_id)
app.get('/api/requests', async (req, res) => {
  try {
    const { status, type } = req.query;
    const requester_id = parseInt(req.query.requester_id || '0', 10) || null;
    const related_owner_id = parseInt(req.query.related_owner_id || '0', 10) || null;

    let sql = `
      SELECT r.*, p.name AS requester_name
      FROM requests r
      LEFT JOIN personnel p ON p.id=r.requester_id
      WHERE 1=1`;
    const args = [];
    if (status) { args.push(status); sql += ` AND r.status=$${args.length}`; }
    if (type) { args.push(type); sql += ` AND r.request_type=$${args.length}`; }
    if (requester_id) { args.push(requester_id); sql += ` AND r.requester_id=$${args.length}`; }
    if (related_owner_id) {
      args.push(related_owner_id);
      sql += `
        AND EXISTS (
          SELECT 1
          FROM request_items ri
          JOIN firearms f ON f.id=ri.firearm_id
          WHERE ri.request_id=r.id
            AND ri.item_type='FIREARM'
            AND f.owner_id=$${args.length}
        )`;
    }
    sql += ` ORDER BY r.id DESC LIMIT 400`;
    const { rows } = await pool.query(sql, args);
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'list failed' });
  }
});



  // 내가 '요청자'이거나, 내 총기(소유)와 관련된 모든 요청
  app.get('/api/requests/for_user/:uid', async (req,res)=>{
    try{
      const uid = parseInt(req.params.uid,10);
      const { rows } = await pool.query(`
        SELECT DISTINCT r.*, p.name AS requester_name
        FROM requests r
        LEFT JOIN personnel p ON p.id=r.requester_id
        LEFT JOIN request_items ri ON ri.request_id=r.id
        LEFT JOIN firearms f ON f.id=ri.firearm_id
        WHERE r.requester_id=$1 OR (ri.item_type='FIREARM' AND f.owner_id=$1)
        ORDER BY r.id DESC
        LIMIT 400
      `,[uid]);
      res.json(rows);
    }catch(e){ console.error(e); res.status(500).json({error:'for_user failed'}); }
  });



  // 3) 신청 상세 (라인 포함)
  app.get('/api/requests/:id', async (req,res)=>{
    try{
      const id = req.params.id;
      const detail = await withTx(async (client) => {
        const rq = await client.query(`
          SELECT r.*, p.name AS requester_name
          FROM requests r
          LEFT JOIN personnel p ON p.id=r.requester_id
          WHERE r.id=$1
        `,[id]);
        if(!rq.rowCount) throw httpError(404, 'not found');
        const request = rq.rows[0];

        const items = (await client.query(`
          SELECT ri.*,
                f.firearm_number, f.firearm_type, f.storage_locker AS firearm_storage_locker,
                a.ammo_name, a.ammo_category, a.storage_locker AS ammo_storage_locker
          FROM request_items ri
          LEFT JOIN firearms   f ON f.id=ri.firearm_id
          LEFT JOIN ammunition a ON a.id=ri.ammo_id
          WHERE ri.request_id=$1
          ORDER BY ri.id
        `,[id])).rows;

        const approvals = (await client.query(`
          SELECT ap.*, per.name AS approver_name
          FROM approvals ap
          LEFT JOIN personnel per ON per.id=ap.approver_id
          WHERE ap.request_id=$1
          ORDER BY ap.decided_at
        `,[id])).rows;

        const executions = (await client.query(`
          SELECT e.*, per.name AS executed_by_name
          FROM execution_events e
          LEFT JOIN personnel per ON per.id=e.executed_by
          WHERE e.request_id=$1
          ORDER BY e.executed_at
        `,[id])).rows;

        const dispatchInfo = await buildDispatchPayloadFromDb(client, request, null);

        return { request, items, approvals, executions, dispatch: dispatchInfo?.dispatch || null };
      });

      res.json(detail);
    }catch(e){
      if (e?.statusCode === 404) return res.status(404).json({error:'not found'});
      console.error(e);
      res.status(500).json({error:'detail failed'});
    }
  });

    app.post('/api/requests/:id/cancel', async (req,res)=>{
    try{
      const id = req.params.id;
      const actor_id = (req.body && req.body.actor_id!=null)
        ? parseInt(req.body.actor_id, 10)
        : null;
      await withTx(async(client)=>{
        const r = await client.query(`SELECT requester_id, status FROM requests WHERE id=$1 FOR UPDATE`, [id]);
        if(!r.rowCount) return res.status(404).json({error:'not found'});
        const row = r.rows[0];

        let isAdmin=false;
        if(actor_id){
          const u=await client.query(`SELECT is_admin FROM personnel WHERE id=$1`,[actor_id]);
          isAdmin = !!(u.rowCount && u.rows[0].is_admin);
        }
        if(actor_id && Number(row.requester_id)!==Number(actor_id) && !isAdmin){
          return res.status(403).json({error:'forbidden'});
        }
        if(row.status==='EXECUTED') return res.status(400).json({error:'already executed'});
        // 👇 일반 사용자는 제출/거부에서만 취소 허용
        if(!isAdmin && !['SUBMITTED','REJECTED'].includes(row.status)){
          return res.status(400).json({error:'user_cancel_not_allowed'});
        }
        if(row.status==='CANCELLED') return res.json({ok:true, status:'CANCELLED'});

        await client.query(`UPDATE requests SET status='CANCELLED', updated_at=now() WHERE id=$1`, [id]);

        res.json({ ok:true, status:'CANCELLED' });
      });
    }catch(e){ console.error(e); res.status(500).json({error:'cancel failed'}); }
  });

app.delete('/api/requests/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    // ★ 쿼리파라미터 우선 사용, 바디는 호환용(있으면)
    const actorId = parseInt(req.query.actor_id || req.body?.actor_id || '0', 10);
    if (!actorId) return res.status(400).json({ error: 'actor_id required' });

    await withTx(async (client) => {
      // 요청 존재/상태 확인
      const rq = await client.query(`SELECT id, requester_id, status FROM requests WHERE id=$1 FOR UPDATE`, [id]);
      if (!rq.rowCount) return res.status(404).json({ error: 'not found' });
      const { requester_id, status } = rq.rows[0];

      // 권한: 관리자이거나, 본인 요청이면 허용
      const u = await client.query(`SELECT is_admin FROM personnel WHERE id=$1`, [actorId]);
      const isAdmin = !!(u.rowCount && u.rows[0].is_admin);
     // ✨ 정책 변경: 삭제는 "관리자 & REJECTED 상태"만 허용
     if (!isAdmin) return res.status(403).json({ error: 'admin only delete' });
     if (status !== 'REJECTED') {
       return res.status(400).json({ error: 'only REJECTED can be deleted' });
     }

      // 여기서 실제 삭제 (자식행은 FK ON DELETE CASCADE 가정)
      await client.query(`DELETE FROM requests WHERE id=$1`, [id]);

      res.json({ ok: true });
    });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: String(e.message || e) });
  }
});




// 승인: 총기 상태 토글·탄약 증감 즉시 반영 + 집행로그
// 승인: 재고/상태는 절대 건드리지 않음. '승인됨'만 남김.
app.post('/api/requests/:id/approve', async (req,res)=>{
  try{
    const id = req.params.id;
    const approver_id = req.body?.approver_id || null;

    await withTx(async(client)=>{
      const rq = await client.query(`SELECT * FROM requests WHERE id=$1 FOR UPDATE`,[id]);
      if(!rq.rowCount) return res.status(404).json({error:'not found'});
      const r = rq.rows[0];
      if(r.status!=='SUBMITTED') return res.status(400).json({error:'not submitted'});


      // ✅ 같은 요청의 기존 'APPROVE' 기록은 제거 → 최신 1건만 유지
      await client.query(
        `DELETE FROM approvals WHERE request_id=$1 AND decision='APPROVE'`,
        [id]
      );

      await client.query(`
        INSERT INTO approvals(request_id,approver_id,decision,decided_at,reason)
        VALUES($1,$2,'APPROVE',now(),NULL)
      `,[id, approver_id]);

      await client.query(`UPDATE requests SET status='APPROVED', updated_at=now() WHERE id=$1`,[id]);

      res.json({ok:true});
    });
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});




app.post('/api/requests/:id/reject', async (req,res)=>{
  try{
    const id = req.params.id;
    const { approver_id, reason } = req.body||{};
    await withTx(async(client)=>{
      const rq=await client.query(`SELECT * FROM requests WHERE id=$1 FOR UPDATE`,[id]);
      if(!rq.rowCount) return res.status(404).json({error:'not found'});
      const r=rq.rows[0];
      if(r.status!=='SUBMITTED') return res.status(400).json({error:'not submitted'});


      // ✅ 같은 요청의 기존 'REJECT' 기록은 제거 → 최신 1건만 유지
      await client.query(
        `DELETE FROM approvals WHERE request_id=$1 AND decision='REJECT'`,
        [id]
      );

      await client.query(`
        INSERT INTO approvals(request_id,approver_id,decision,decided_at,reason)
        VALUES($1,$2,'REJECT',now(),$3)
      `,[id, approver_id||null, reason||null]);

      await client.query(`UPDATE requests SET status='REJECTED', updated_at=now() WHERE id=$1`,[id]);

      res.json({ok:true});
    });
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});


// 집행: 로컬 로봇 브릿지로 명령을 위임하고 진행 상황을 트래킹
app.post('/api/requests/:id/execute', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const executed_by = req.body?.executed_by || null;
  const dispatchPayload = req.body?.dispatch || null;

  try {

    const queued = await withTx(async (client) => {
      const rq = await client.query(`SELECT * FROM requests WHERE id=$1 FOR UPDATE`, [id]);
      if (!rq.rowCount) throw httpError(404, 'not found');
      const requestRow = rq.rows[0];
      const statusKey = String(requestRow.status || '').toUpperCase();
      if (statusKey !== 'APPROVED') {
        throw httpError(400, 'not approved');
      }

      const { dispatch, items, forward } = await buildDispatchPayloadFromDb(client, requestRow, dispatchPayload);
      if (!dispatch) {
        throw httpError(400, '장비 제어 데이터가 부족합니다');
      }

      await client.query(`UPDATE requests SET status_reason='장비 명령 준비 중', updated_at=now() WHERE id=$1`, [id]);
      const eventType = requestRow.request_type || requestRow.type || 'DISPATCH';
      const queuedNotes = toJsonNotes({ stage: 'queued', dispatch });
      const ev = await client.query(
        `INSERT INTO execution_events(request_id, executed_by, event_type, notes)
         VALUES($1,$2,$3,$4) RETURNING id`,
        [id, executed_by, eventType, queuedNotes]
      );

      let executor = null;
      if (executed_by) {
        const ex = await client.query(`SELECT id, name, rank, unit, position FROM personnel WHERE id=$1`, [executed_by]);
        executor = ex.rowCount ? ex.rows[0] : null;
      }
      return { request: requestRow, eventId: ev.rows[0].id, executor, dispatch, items, forward };
    });

    const payload = buildRobotDispatchPayload({
      request: queued.request,
      executor: queued.executor,
      executedBy: executed_by,
      dispatch: queued.dispatch,
      eventId: queued.eventId,
      items: queued.items,
      forward: queued.forward
    });

        let manualRequired = true;
    let autoDispatched = false;
    let bridgeHealth = null;
    let bridgeError = null;

    if (LOCAL_BRIDGE_URL) {
      try {
        bridgeHealth = await checkLocalBridgeHealth();
        const autoResult = await sendRobotDispatch(payload);
        if (autoResult.ok) {
          manualRequired = false;
          autoDispatched = true;
        } else {
          bridgeError = new Error(autoResult.error || 'auto_dispatch_failed');
          bridgeError.statusCode = autoResult.status || 503;
        }
      } catch (bridgeErr) {
        bridgeError = bridgeErr instanceof Error ? bridgeErr : new Error(String(bridgeErr));
      }
    }

    if (bridgeError) {
      console.warn('robot auto dispatch unavailable', bridgeError);
    }

    const stageNotes = toJsonNotes({
      stage: 'queued',
      dispatch: queued.dispatch,
      payload: manualRequired ? payload : null,
      manual: manualRequired,
      autoDispatched,
      bridge: {
        configured: !!LOCAL_BRIDGE_URL,
        health: bridgeHealth || null,
        error: bridgeError ? (bridgeError.message || String(bridgeError)) : null
      }
    });

    await withTx(async (client) => {
      await client.query(`UPDATE execution_events SET notes=$1 WHERE id=$2`, [stageNotes, queued.eventId]);
      if (bridgeError) {
        await client.query(`UPDATE requests SET status_reason=$2, updated_at=now() WHERE id=$1`, [
          id,
          bridgeError.message || '로컬 브릿지 확인 필요'
        ]);
      }
    });

    return res.json({
      ok: true,
      status: queued.request.status || 'APPROVED',
      status_reason: bridgeError
        ? (bridgeError.message || '로컬 브릿지 확인 필요')
        : '장비 명령 준비 중',
      payload,
      request_id: id,
      event_id: queued.eventId,
      dispatch: queued.dispatch,
      items: queued.items,
      bridge: {
        configured: !!LOCAL_BRIDGE_URL,
        autoDispatched,
        manualRequired,
        health: bridgeHealth || null,
        error: bridgeError ? (bridgeError.message || String(bridgeError)) : null
      }
    });
  } catch (e) {
    const status = e?.statusCode || 500;
    console.error('execute error:', e);
    return res.status(status).json({ ok: false, error: e.message || 'execute_failed' });
  }
});

app.post('/api/requests/:id/execute_complete', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const actorId = req.body?.actor_id || null;
  const eventId = req.body?.event_id || null;
  const result = req.body?.result || null;
  const statusReasonRaw = req.body?.status_reason;

  try {
    const completion = await withTx(async (client) => {
      const rq = await client.query(`SELECT * FROM requests WHERE id=$1 FOR UPDATE`, [id]);
      if (!rq.rowCount) throw httpError(404, 'not found');
      const requestRow = rq.rows[0];

      if (requestRow.status === 'EXECUTED') {
        return { already: true, request: requestRow, statusReason: requestRow.status_reason || null };
      }

      if (String(requestRow.status || '').toUpperCase() !== 'APPROVED') {
        throw httpError(400, 'not approved');
      }

      const reason = (typeof statusReasonRaw === 'string' && statusReasonRaw.trim())
        ? statusReasonRaw.trim()
        : (result?.message
          || (result?.summary?.actionLabel ? `${result.summary.actionLabel} 완료` : '장비 제어가 정상적으로 완료되었습니다.'));

      let safeResult = result;
      if (result && typeof result === 'object') {
        try {
          safeResult = JSON.parse(JSON.stringify(result));
          if (safeResult?.payload?.forward) {
            delete safeResult.payload.forward.token;
          }
          if (safeResult?.forward) {
            delete safeResult.forward.token;
          }
        } catch (_) {
          safeResult = result;
        }
      }

      const notes = toJsonNotes({ stage: 'completed', job: safeResult });

      const finalize = await finalizeRequestExecution(client, requestRow, actorId, {
        notes,
        statusReason: reason,
        eventId
      });

      return { eventId: finalize.eventId, statusReason: reason };
    });

    return res.json({
      ok: true,
      status: 'EXECUTED',
      event_id: completion.eventId || eventId || null,
      status_reason: completion.statusReason || statusReasonRaw || null,
      already: !!completion.already
    });
  } catch (e) {
    const status = e?.statusCode || 500;
    console.error('execute_complete error:', e);
    return res.status(status).json({ ok: false, error: e.message || 'execute_complete_failed' });
  }
});

app.post('/api/requests/:id/dispatch_fail', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const reasonRaw = req.body?.reason;
  const actorId = req.body?.actor_id || null;
  const reason = (typeof reasonRaw === 'string' && reasonRaw.trim()) ? reasonRaw.trim() : '로컬 브릿지 오류';

  try {
    await withTx(async (client) => {
      const rq = await client.query(`SELECT status FROM requests WHERE id=$1 FOR UPDATE`, [id]);
      if (!rq.rowCount) throw httpError(404, 'not found');
      const statusKey = String(rq.rows[0].status || '').toUpperCase();
      if (statusKey !== 'APPROVED') {
        throw httpError(400, 'not dispatch_pending');
      }

      await client.query(`UPDATE requests SET status='APPROVED', status_reason=$2, updated_at=now() WHERE id=$1`, [id, reason]);

      const ev = await client.query(`SELECT id FROM execution_events WHERE request_id=$1 ORDER BY id DESC LIMIT 1`, [id]);
      if (ev.rowCount) {
        await client.query(`UPDATE execution_events SET notes=$1 WHERE id=$2`, [
          toJsonNotes({ stage: 'failed', reason, manual: true, actorId }),
          ev.rows[0].id
        ]);
      }
    });

    return res.json({ ok: true });
  } catch (e) {
    const status = e?.statusCode || 500;
    console.error('dispatch_fail error:', e);
    return res.status(status).json({ ok: false, error: e.message || 'dispatch_fail_failed' });
  }
});

// 재오픈: APPROVED/REJECTED/선택적으로 CANCELLED -> SUBMITTED 로 되돌림
app.post('/api/requests/:id/reopen', async (req,res)=>{
  try{
    const id = req.params.id;
    const actor_id = req.body?.actor_id || null;

    await withTx(async(client)=>{
      // 권한: 관리자만
      if(!actor_id) return res.status(400).json({error:'actor_id required'});
      const u=await client.query(`SELECT is_admin FROM personnel WHERE id=$1`,[actor_id]);
      if(!(u.rowCount && u.rows[0].is_admin)) return res.status(403).json({error:'forbidden'});

      const rq=await client.query(`SELECT status FROM requests WHERE id=$1 FOR UPDATE`,[id]);
      if(!rq.rowCount) return res.status(404).json({error:'not found'});
      const st=rq.rows[0].status;
      if(!['APPROVED','REJECTED','CANCELLED'].includes(st)) return res.status(400).json({error:'not reopenable'});

      await client.query(`UPDATE requests SET status='SUBMITTED', updated_at=now() WHERE id=$1`,[id]);
      // 간단 감사로그(원한다면 별도 audit 테이블 구성)
      await client.query(`
        INSERT INTO approvals(request_id, approver_id, decision, decided_at, reason)
        VALUES ($1, $2, 'REOPEN', now(), 'reopen to SUBMITTED')
      `, [id, actor_id]);

      res.json({ok:true});
    });
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});


// 요청 단일 타임라인(신청/승인/거부/집행/취소/재오픈) 일괄 조회
app.get('/api/requests/:id/timeline', async (req,res)=>{
  try{
    const id = parseInt(req.params.id,10);
    const { rows } = await pool.query(`
      SELECT * FROM (
        -- A) 요청 생성/상태 변경
        SELECT r.id AS request_id, r.created_at AS event_time, r.requester_id AS actor_id,
               'REQUEST_CREATED' AS event_type, r.status AS status, r.notes
        FROM requests r WHERE r.id=$1
        UNION ALL
        SELECT r.id, r.updated_at, NULL, 'REQUEST_UPDATED', r.status, NULL
        FROM requests r WHERE r.id=$1

        -- B) 승인/거부/재오픈
        UNION ALL
        SELECT a.request_id, a.decided_at, a.approver_id,
              CASE WHEN a.decision='APPROVE' THEN 'APPROVED'
                   WHEN a.decision='REJECT'  THEN 'REJECTED'
                   WHEN a.decision='REOPEN'  THEN 'REOPENED'
                   WHEN a.decision='CANCEL'  THEN 'CANCELLED' END AS event_type,
               NULL, a.reason
        FROM approvals a WHERE a.request_id=$1

        -- C) 집행
        UNION ALL
        SELECT e.request_id, e.executed_at, e.executed_by,
               CASE WHEN e.event_type='DISPATCH' THEN 'EXEC_DISPATCH'
                    WHEN e.event_type='RETURN'   THEN 'EXEC_RETURN' END,
               NULL, e.notes
        FROM execution_events e WHERE e.request_id=$1
      ) t
      ORDER BY event_time NULLS LAST
    `,[id]);
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({error:'timeline failed'}); }
});



  // 6) 집행 로그 (총기/탄약 변화까지 집계)
  app.get('/api/executions', async (req,res)=>{
    try{
      const et = req.query.event_type || null;
      const sql = `
        SELECT v.*,
          COALESCE(json_agg(DISTINCT jsonb_build_object('firearm_id',fsc.firearm_id,'from_status',fsc.from_status,'to_status',fsc.to_status,'firearm_number',fr.firearm_number)) FILTER (WHERE fsc.id IS NOT NULL), '[]') AS firearm_changes,
          COALESCE(json_agg(DISTINCT jsonb_build_object('ammo_id',am.ammo_id,'delta',am.delta,'before_qty',am.before_qty,'after_qty',am.after_qty,'ammo_name',a.ammo_name)) FILTER (WHERE am.id IS NOT NULL), '[]') AS ammo_moves
        FROM v_execution_summary v
        LEFT JOIN firearm_status_changes fsc ON fsc.execution_id=v.execution_id
        LEFT JOIN firearms fr ON fr.id=fsc.firearm_id
        LEFT JOIN ammo_movements am ON am.execution_id=v.execution_id
        LEFT JOIN ammunition a ON a.id=am.ammo_id
        WHERE ($1::text IS NULL OR v.event_type=$1)
        GROUP BY v.execution_id, v.event_type, v.executed_at, v.executed_by, v.executed_by_name, v.request_id, v.notes
        ORDER BY v.executed_at DESC
        LIMIT 400`;
      const { rows } = await pool.query(sql, [et]);
      res.json(rows);
    }catch(e){ console.error(e); res.status(500).json({error:'exec list failed'}); }
  });


  /* ======================================================
 * Duty Roster API
 * ====================================================== */

function kTypeKR(t){ return t==='DISPATCH'?'불출':(t==='RETURN'?'불입':t); }

// 공통: 요청 생성(+ 항목)
async function createRequestWithItems(client, {requester_id, type, purpose, location, scheduled_at, items}) {
  const r = await client.query(
    `INSERT INTO requests(requester_id,request_type,purpose,location,scheduled_at)
     VALUES($1,$2,$3,$4,$5) RETURNING id`,
    [requester_id, type, purpose, location, scheduled_at]
  );
  const reqId = r.rows[0].id;
  for (const it of items) {
    if (it.type==='FIREARM') {
      await client.query(
        `INSERT INTO request_items(request_id,item_type,firearm_id)
         VALUES($1,'FIREARM',$2)`, [reqId, it.firearm_id]
      );
    } else if (it.type==='AMMO') {
      await client.query(
        `INSERT INTO request_items(request_id,item_type,ammo_id,quantity)
         VALUES($1,'AMMO',$2,$3)`, [reqId, it.ammo_id, it.quantity]
      );
    }
  }
  return reqId;
}

// 공통: 요청 자동 승인(+집행)
async function approveAndMaybeExecute(client, {request_id, approver_id, doExecute=false}) {
  // ✅ 승인 로그에 decided_at 명시
  await client.query(
    `INSERT INTO approvals(request_id, approver_id, decision, decided_at, reason)
     VALUES ($1, $2, 'APPROVE', now(), 'auto by roster')`,
    [request_id, approver_id]
  );

  // 요청 상태 → APPROVED
  await client.query(
    `UPDATE requests SET status='APPROVED', updated_at=now() WHERE id=$1`,
    [request_id]
  );

  if (!doExecute) return;

  // 집행 이벤트
  const rq = await client.query(`SELECT request_type FROM requests WHERE id=$1`, [request_id]);
  const rtype = rq.rows[0].request_type; // DISPATCH or RETURN

  const ev = await client.query(
    `INSERT INTO execution_events(request_id, executed_by, event_type, notes)
     VALUES ($1, $2, $3, $4) RETURNING id`,
    [request_id, approver_id, rtype, 'EXECUTE: inventory committed by roster']
  );
  const execId = ev.rows[0].id;

  // 항목별 실제 재고/상태 반영
  const items = await client.query(
    `SELECT item_type, firearm_id, ammo_id, quantity
     FROM request_items WHERE request_id=$1`,
    [request_id]
  );

  for (const it of items.rows) {
    if (it.item_type === 'FIREARM') {
      const fq = await client.query(`SELECT id, status FROM firearms WHERE id=$1 FOR UPDATE`, [it.firearm_id]);
      const from = fq.rows[0].status;
      const to   = (rtype === 'DISPATCH' ? '불출' : '불입');

      await client.query(
        `UPDATE firearms SET status=$1, last_change=now() WHERE id=$2`,
        [to, it.firearm_id]
      );
      await client.query(
        `INSERT INTO firearm_status_changes(execution_id, firearm_id, from_status, to_status)
         VALUES ($1, $2, $3, $4)`,
        [execId, it.firearm_id, from, to]
      );

    } else if (it.item_type === 'AMMO') {
      const aq = await client.query(`SELECT id, quantity FROM ammunition WHERE id=$1 FOR UPDATE`, [it.ammo_id]);
      const before = aq.rows[0].quantity;
      const delta  = (rtype === 'DISPATCH' ? -it.quantity : +it.quantity);
      const after  = before + delta;
      if (after < 0) throw new Error('탄약 재고 음수 불가');

      await client.query(
        `UPDATE ammunition SET quantity=$1, last_change=now() WHERE id=$2`,
        [after, it.ammo_id]
      );
      await client.query(
        `INSERT INTO ammo_movements(execution_id, ammo_id, delta, before_qty, after_qty)
         VALUES ($1, $2, $3, $4, $5)`,
        [execId, it.ammo_id, delta, before, after]
      );
    }
  }

  await client.query(
    `UPDATE requests SET status='EXECUTED', updated_at=now() WHERE id=$1`,
    [request_id]
  );
}


/* Posts/Shifts 기본값 조회 */
app.get('/api/duty/posts', async (req,res)=>{
  const { rows } = await pool.query(`SELECT * FROM duty_posts ORDER BY id`);
  res.json(rows);
});
app.get('/api/duty/shifts', async (req,res)=>{
  const { rows } = await pool.query(`SELECT * FROM duty_shifts ORDER BY start_time`);
  res.json(rows);
});

/* 1) 로스터 생성(+배정 등록) */
app.post('/api/duty/rosters', async (req,res)=>{
  try{
    const { duty_date, created_by, auto_approve=false, auto_execute=true, notes, assignments=[] } = req.body;
    if(!duty_date || !created_by) return res.status(400).json({error:'missing duty_date or created_by'});
    if(!Array.isArray(assignments) || !assignments.length) return res.status(400).json({error:'no assignments'});

    const result = await withTx(async(client)=>{
      const r = await client.query(
        `INSERT INTO duty_rosters(duty_date, status, created_by, auto_approve, auto_execute, notes)
         VALUES($1,'DRAFT',$2,$3,$4,$5) RETURNING id`,
        [duty_date, created_by, !!auto_approve, !!auto_execute, notes ?? null]
      );
      const rosterId = r.rows[0].id;

      for(const a of assignments){
        await client.query(
          `INSERT INTO duty_assignments
           (roster_id, post_id, shift_id, slot_no, personnel_id, firearm_id, ammo_category, ammo_qty)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
          [rosterId, a.post_id, a.shift_id, a.slot_no||1, a.personnel_id||null, a.firearm_id||null, a.ammo_category||null, a.ammo_qty||0]
        );
      }
      return rosterId;
    });
    res.json({ok:true, id:result});
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});

/* 2) Publish: 자동 불출요청(+옵션: 자동승인/집행) & RETURN 예약 */
app.post('/api/duty/rosters/:id/publish', async (req,res)=>{
  try{
    const rosterId = req.params.id;
    const { approver_id } = req.body; // 관리자
    await withTx(async(client)=>{
      const roq = await client.query(`SELECT * FROM duty_rosters WHERE id=$1 FOR UPDATE`, [rosterId]);
      if(!roq.rowCount) throw new Error('roster not found');
      const roster = roq.rows[0];

      // 상태 전환
      if (roster.status!=='DRAFT') throw new Error('already published');
      await client.query(`UPDATE duty_rosters SET status='PUBLISHED' WHERE id=$1`, [rosterId]);

      // 불출 생성
      const asg = await client.query(`
        SELECT da.*, dp.requires_firearm, dp.requires_ammo, dp.default_ammo_category,
               ds.start_time, ds.end_time
        FROM duty_assignments da
        JOIN duty_posts  dp ON dp.id=da.post_id
        JOIN duty_shifts ds ON ds.id=da.shift_id
        WHERE da.roster_id=$1
      `,[rosterId]);

      for(const a of asg.rows){
        if(!a.personnel_id) continue; // 빈 슬롯은 스킵
        const items = [];
        // FIREARM(필요시)
        if(a.requires_firearm && a.firearm_id){
          // 현재 총기 상태 확인 및 예약 중복 검사
          const fq = await client.query(`
            SELECT id,status FROM firearms WHERE id=$1 FOR UPDATE`, [a.firearm_id]);
          if(!fq.rowCount) throw new Error('firearm not found');
          if(fq.rows[0].status!=='불입') throw new Error('불출 불가(현재 불입 아님)');

          const dup = await client.query(`
            SELECT 1
            FROM request_items ri JOIN requests r ON r.id=ri.request_id
            WHERE ri.item_type='FIREARM' AND ri.firearm_id=$1
              AND r.status IN ('SUBMITTED','APPROVED')`, [a.firearm_id]);
          if(dup.rowCount) throw new Error('해당 총기 진행중 신청 있음');

          items.push({type:'FIREARM', firearm_id:a.firearm_id});
        }
        // AMMO(필요시)
        if(a.requires_ammo && a.ammo_category && a.ammo_qty>0){
          // 같은 카테고리 중 우선순위 1개 선택(간단화: 가장 재고 많은 탄약)
          const am = await client.query(`
            SELECT id, quantity
            FROM ammunition
            WHERE ammo_category=$1
            ORDER BY quantity DESC
            LIMIT 1
          `,[a.ammo_category]);
          if(!am.rowCount) throw new Error('탄약 카테고리 재고 없음');
          const ammo = am.rows[0];

          // 가용확인(예약 포함)
          const av = await client.query(`
            SELECT (a.quantity - COALESCE((
              SELECT SUM(ri.quantity)
              FROM request_items ri JOIN requests r2 ON r2.id=ri.request_id
              WHERE ri.item_type='AMMO' AND ri.ammo_id=a.id
                AND r2.request_type='DISPATCH'
                AND r2.status IN ('SUBMITTED','APPROVED')
            ),0))::int AS available
            FROM ammunition a WHERE a.id=$1
          `,[ammo.id]);
          if(a.ammo_qty > av.rows[0].available) throw new Error('탄약 가용 부족');

          items.push({type:'AMMO', ammo_id:ammo.id, quantity:a.ammo_qty});
        }

        if(items.length){
          // 불출 요청 생성 (목적/장소 간단 값)
          const reqId = await createRequestWithItems(client, {
            requester_id: a.personnel_id,
            type: 'DISPATCH',
            purpose: `근무 불출(${roster.duty_date})`,
            location: '근무지',
            scheduled_at: `${roster.duty_date} ${a.start_time}`,
            items
          });
          await client.query(
            `INSERT INTO duty_requests(assignment_id, phase, request_id)
             VALUES($1,'DISPATCH',$2)`, [a.id, reqId]
          );

          // 자동승인/집행
          if(roster.auto_approve){
            await approveAndMaybeExecute(client, {
              request_id: reqId,
              approver_id,
              doExecute: roster.auto_execute
            });
          }

          // 반납 예약(RETURN) 생성 (자동승인/집행은 complete에서 일괄 실행)
          const retId = await createRequestWithItems(client, {
            requester_id: a.personnel_id,
            type: 'RETURN',
            purpose: `근무 반납(${roster.duty_date})`,
            location: '무기고',
            scheduled_at: `${roster.duty_date} ${a.end_time}`,
            items
          });
          await client.query(
            `INSERT INTO duty_requests(assignment_id, phase, request_id)
             VALUES($1,'RETURN',$2)`, [a.id, retId]
          );
        }
      }
    });
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});

/* 3) 완료 처리: RETURN 자동 승인/집행 */
app.post('/api/duty/rosters/:id/complete', async (req,res)=>{
  try{
    const rosterId = req.params.id;
    const { approver_id } = req.body;

    await withTx(async(client)=>{
      const roq = await client.query(`SELECT * FROM duty_rosters WHERE id=$1 FOR UPDATE`, [rosterId]);
      if(!roq.rowCount) throw new Error('roster not found');
      const roster = roq.rows[0];
      if (roster.status!=='PUBLISHED' && roster.status!=='LOCKED') throw new Error('invalid status');

      const rqs = await client.query(`
        SELECT dr.request_id
        FROM duty_requests dr
        JOIN requests r ON r.id=dr.request_id
        WHERE dr.phase='RETURN' AND r.status IN ('SUBMITTED','APPROVED')
          AND dr.assignment_id IN (SELECT id FROM duty_assignments WHERE roster_id=$1)
      `,[rosterId]);

      for (const row of rqs.rows) {
        // RETURN 승인/집행
        await approveAndMaybeExecute(client, {
          request_id: row.request_id,
          approver_id,
          doExecute: true
        });
      }

      await client.query(`UPDATE duty_rosters SET status='COMPLETED' WHERE id=$1`, [rosterId]);
    });
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});

/* 4) 서명 */
app.post('/api/duty/assignments/:id/sign', async (req,res)=>{
  try{
    const id = req.params.id;
    const { signed_by, signature_text } = req.body;
    if(!signed_by) return res.status(400).json({error:'missing signed_by'});

    const { rowCount } = await pool.query(
      `UPDATE duty_assignments
       SET sign_by=$1, sign_at=now(), signature=$2
       WHERE id=$3`, [signed_by, signature_text ?? null, id]
    );
    if(!rowCount) return res.status(404).json({error:'not found'});
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});

/* 5) 조회 (일자별) */
app.get('/api/duty/rosters', async (req,res)=>{
  try{
    const date = req.query.date;
    if(!date) return res.status(400).json({error:'missing date'});
    const ro = await pool.query(`SELECT * FROM duty_rosters WHERE duty_date=$1 ORDER BY id DESC LIMIT 1`, [date]);
    if(!ro.rowCount) return res.json({ roster:null, assignments:[] });

    const roster = ro.rows[0];
    const asg = await pool.query(`
      SELECT da.*, dp.name AS post_name, ds.name AS shift_name, ds.start_time, ds.end_time,
             p.name AS person_name, p.rank AS person_rank, p.military_id AS person_military_id,
             f.firearm_number
      FROM duty_assignments da
      JOIN duty_posts  dp ON dp.id=da.post_id
      JOIN duty_shifts ds ON ds.id=da.shift_id
      LEFT JOIN personnel p ON p.id=da.personnel_id
      LEFT JOIN firearms f  ON f.id=da.firearm_id
      WHERE da.roster_id=$1
      ORDER BY dp.name, ds.start_time, da.slot_no
    `,[roster.id]);

    res.json({ roster, assignments: asg.rows });
  }catch(e){ console.error(e); res.status(500).json({error:'query failed'}); }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

app.post('/api/robot/event', async (req, res) => {
  try {
    const token = req.get('x-robot-token') || req.get('x-fp-token');
    if (ROBOT_EVENT_TOKEN) {
      if (!token || token !== ROBOT_EVENT_TOKEN) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
      }
    }
    const { job = {}, site = 'default', status } = req.body || {};
    const requestId = job?.requestId || job?.request_id;
    const effectiveStatus = status || job?.status;
    if (!requestId) return res.status(400).json({ ok: false, error: 'missing requestId' });
    if (!effectiveStatus) return res.status(400).json({ ok: false, error: 'missing status' });
    await handleRobotEvent({ requestId, status: effectiveStatus, job, site });
    return res.json({ ok: true });
  } catch (e) {
    console.error('robot event error:', e);
    res.status(500).json({ ok: false, error: e.message || 'robot_event_failed' });
  }
});


// 로컬 브릿지 → Render (지문 이벤트 적재)
// server.js 하단에 추가/완성
const sseClients = new Map(); // site -> Set(res)
const lastEvent  = new Map(); // site -> last json
const bridgePresence = new Map(); // site -> { hints, addresses, hostname, port, lastSeen, base }
const BRIDGE_PRESENCE_TTL_MS = Number(process.env.BRIDGE_PRESENCE_TTL_MS || 5 * 60 * 1000);

function pruneBridgePresence(now = Date.now()) {
  for (const [site, info] of bridgePresence.entries()) {
    if (!info) {
      bridgePresence.delete(site);
      continue;
    }
    const age = now - (info.lastSeenTs || 0);
    if (age > BRIDGE_PRESENCE_TTL_MS) {
      bridgePresence.delete(site);
    }
  }
}
function pushToSse(site, payload){
  const set = sseClients.get(site);
  if (!set) return;
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) { try { res.write(data); } catch(_){} }
}

app.post('/api/fp/event', async (req, res) => {
  try {
    const token = req.get('x-fp-token');
    if (token !== process.env.FP_SITE_TOKEN) {
      return res.status(401).json({ ok:false, error:'unauthorized' });
    }
    const { site = 'default', data } = req.body || {};
    if (!data) return res.status(400).json({ ok:false, error:'missing data' });

    if (data?.type === 'bridge_presence') {
      const nowTs = Date.now();
      pruneBridgePresence(nowTs);
      const hints = Array.isArray(data.urlHints)
        ? data.urlHints
            .map((value) => {
              try {
                return String(value).trim();
              } catch {
                return null;
              }
            })
            .map((value) =>
              value ? sanitizeHttpsUrl(value, { allowHttp: allowInsecureBridgeHints }) : ''
            )
            .filter(Boolean)
        : [];
      const addresses = Array.isArray(data.addresses)
        ? data.addresses.map((entry) => {
            if (!entry) return null;
            const out = {};
            if (entry.address) out.address = String(entry.address);
            if (entry.interface) out.interface = String(entry.interface);
            if (entry.family) out.family = String(entry.family);
            if (entry.scopeid !== undefined && entry.scopeid !== null) out.scopeid = entry.scopeid;
            if (entry.internal !== undefined) out.internal = !!entry.internal;
            if (entry.mac) out.mac = String(entry.mac);
            if (entry.netmask) out.netmask = String(entry.netmask);
            return Object.keys(out).length ? out : null;
          }).filter(Boolean)
        : [];
      const hostname = typeof data.hostname === 'string' ? data.hostname.trim() : '';
      const rawBase = typeof data.base === 'string' ? data.base.trim() : '';
      const base = rawBase
        ? sanitizeHttpsUrl(rawBase, { allowHttp: allowInsecureBridgeHints })
        : '';
      const port = Number(data.port) || null;
      const entry = {
        site,
        urlHints: hints,
        addresses,
        hostname: hostname || null,
        base: base || null,
        port,
        lastSeen: new Date(nowTs).toISOString(),
        lastSeenTs: nowTs,
        reason: data.reason || null,
        source: 'forward',
        forwardedFor: req.get('x-forwarded-for') || req.ip || null
      };
      bridgePresence.set(site, entry);
      return res.json({ ok: true });
    }

    // 매핑 해석 (identify 성공시에만)
    let resolved = null;
    if (data.ok === true && data.type === 'identify' && Number.isInteger(data.matchId)) {
      const q = `SELECT t.person_id, p.name, p.is_admin
                 FROM fp_templates t JOIN personnel p ON p.id=t.person_id
                 WHERE t.sensor_id=$1 AND t.site=$2 LIMIT 1`;
      const r = await pool.query(q, [data.matchId, site]);
      if (r.rowCount) {
        const row = r.rows[0];
        resolved = { person_id: row.person_id, name: row.name, is_admin: !!row.is_admin };
        if (data.ok === true && data.type === 'identify' && resolved?.person_id) {
          loginTickets.set(site, {
            person_id: resolved.person_id,
            name: resolved.name,
            is_admin: !!resolved.is_admin,
            exp: now() + TICKET_TTL_MS,
            used: false,
            issued_at: now()
          });
        }
      }
    }

    const payload = { site, data, resolved, received_at: new Date().toISOString() };
    lastEvent.set(site, payload);
    pushToSse(site, payload);

    return res.json({ ok:true });
  } catch (e) {
    console.error('fp/event error:', e);
    res.status(500).json({ ok:false, error:'fp_event_failed' });
  }
});

app.get('/api/fp/bridge/hints', (req, res) => {
  const site = String(req.query.site || 'default');
  const allRaw = String(req.query.all || '').toLowerCase();
  const includeAll = allRaw === '1' || allRaw === 'true' || allRaw === 'yes';
  const maxAgeMsRaw = Number(req.query.maxAgeMs || req.query.max_age_ms || 0);
  const effectiveTtl = Number.isFinite(maxAgeMsRaw) && maxAgeMsRaw > 0 ? maxAgeMsRaw : BRIDGE_PRESENCE_TTL_MS;
  const nowTs = Date.now();
  pruneBridgePresence(nowTs);

  const isFresh = (info) => !!info && (nowTs - (info.lastSeenTs || 0)) <= effectiveTtl;
  const sanitize = (siteKey, info) => ({
    site: siteKey,
    hints: Array.isArray(info?.urlHints) ? info.urlHints : [],
    addresses: Array.isArray(info?.addresses) ? info.addresses : [],
    hostname: info?.hostname || null,
    base: info?.base || null,
    port: info?.port || null,
    last_seen: info?.lastSeen || null,
    reason: info?.reason || null
  });

  if (includeAll) {
    const entries = [];
    for (const [key, value] of bridgePresence.entries()) {
      if (!isFresh(value)) continue;
      entries.push(sanitize(key, value));
    }
    return res.json({ ok: true, ttlMs: effectiveTtl, sites: entries });
  }

  const entry = bridgePresence.get(site);
  if (!isFresh(entry)) {
    return res.json({
      ok: false,
      site,
      hints: [],
      addresses: [],
      hostname: null,
      base: null,
      port: null,
      last_seen: null,
      reason: null,
      ttlMs: effectiveTtl
    });
  }

  return res.json({ ok: true, ttlMs: effectiveTtl, ...sanitize(site, entry) });
});


// UI ← Render (SSE 실시간 스트림)
// SSE 스트림: /api/fp/stream?site=site-01
app.get('/api/fp/stream', (req, res) => {
  const site = (req.query.site || 'default');

  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  if (!sseClients.has(site)) sseClients.set(site, new Set());
  const set = sseClients.get(site);
  set.add(res);

  // 🔴 초기 lastEvent 1건 밀어주던 코드를 완전히 제거했습니다.

  // heartbeat
  const hb = setInterval(() => { try { res.write(':\n\n'); } catch (_) {} }, 30000);

  req.on('close', () => {
    clearInterval(hb);
    try { set.delete(res); } catch (_){}
  });
});


// 최근 1건 폴링 용(테스트/디버깅)
app.get('/api/fp/last', (req, res) => {
  const site = (req.query.site || 'default');
  res.json(lastEvent.get(site) || null);
});


// 매핑 등록: sensor_id ↔ person_id
app.post('/api/fp/map', async (req, res) => {
  const { sensor_id, person_id } = req.body || {};
  const siteRaw = typeof req.body?.site === 'string' ? req.body.site : '';
  const site = siteRaw.trim() || 'default';

  if (!Number.isInteger(sensor_id) || sensor_id <= 0 || !Number.isInteger(person_id) || person_id <= 0) {
    return res.status(400).json({ error: 'bad sensor_id or person_id' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM fp_templates WHERE person_id=$1 AND sensor_id <> $2', [person_id, sensor_id]);
    const { rows: upsertRows } = await client.query(
      `INSERT INTO fp_templates(sensor_id, person_id, site, last_enrolled)
       VALUES($1,$2,$3, CURRENT_TIMESTAMP)
       ON CONFLICT (sensor_id) DO UPDATE
         SET person_id=EXCLUDED.person_id,
             site=EXCLUDED.site,
             last_enrolled=CURRENT_TIMESTAMP
       RETURNING sensor_id, person_id, site, last_enrolled`,
      [sensor_id, person_id, site]
    );
    const { rows: detailRows } = await client.query(
      `SELECT t.sensor_id, t.person_id, t.site, t.last_enrolled,
              p.name, p.rank, p.unit, p.position, p.user_id, p.military_id, p.is_admin, p.contact
       FROM fp_templates t LEFT JOIN personnel p ON p.id=t.person_id
       WHERE t.sensor_id = $1`,
      [sensor_id]
    );
    await client.query('COMMIT');
    res.json({ ok: true, mapping: detailRows[0] || upsertRows[0] });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('fp map upsert failed:', e);
    res.status(500).json({ error: 'map_upsert_failed' });
  } finally {
    client.release();
  }
});

// 매핑 조회(관리툴에서 볼 때)
app.get('/api/fp/map', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT t.sensor_id, t.site, t.person_id, t.last_enrolled,
              p.name, p.rank, p.unit, p.position, p.user_id, p.military_id, p.is_admin, p.contact
       FROM fp_templates t LEFT JOIN personnel p ON p.id=t.person_id
       ORDER BY t.sensor_id`
    );
    res.json(rows);
  } catch (err) {
    console.error('fp map fetch failed:', err);
    res.status(500).json({ error: 'map_fetch_failed' });
  }
});

app.get('/api/fp/assignments', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         p.id AS person_id,
         p.name,
         p.rank,
         p.unit,
         p.position,
         p.user_id,
         p.military_id,
         p.contact,
         p.is_admin,
         t.sensor_id,
         t.site,
         t.last_enrolled
       FROM personnel p
       LEFT JOIN fp_templates t ON t.person_id = p.id
       ORDER BY p.name, p.id`
    );
    res.json(rows);
  } catch (err) {
    console.error('fp assignments fetch failed:', err);
    res.status(500).json({ error: 'assignments_fetch_failed' });
  }
});

app.delete('/api/fp/map/:sensorId', async (req, res) => {
  const sensorId = Number.parseInt(req.params.sensorId, 10);
  if (!Number.isInteger(sensorId) || sensorId <= 0) {
    return res.status(400).json({ error: 'bad_sensor_id' });
  }
  try {
    const { rowCount } = await pool.query('DELETE FROM fp_templates WHERE sensor_id=$1', [sensorId]);
    if (!rowCount) {
      return res.status(404).json({ error: 'not_found' });
    }
    res.json({ ok: true, deleted: rowCount });
  } catch (err) {
    console.error('fp map delete failed:', err);
    res.status(500).json({ error: 'delete_failed' });
  }
});

app.delete('/api/fp/person/:personId', async (req, res) => {
  const personId = Number.parseInt(req.params.personId, 10);
  if (!Number.isInteger(personId) || personId <= 0) {
    return res.status(400).json({ error: 'bad_person_id' });
  }
  try {
    const { rowCount } = await pool.query('DELETE FROM fp_templates WHERE person_id=$1', [personId]);
    if (!rowCount) {
      return res.status(404).json({ error: 'not_found' });
    }
    res.json({ ok: true, deleted: rowCount });
  } catch (err) {
    console.error('fp person delete failed:', err);
    res.status(500).json({ error: 'delete_failed' });
  }
});

app.delete('/api/fp/map', async (req, res) => {
  const siteRaw = typeof req.query.site === 'string' ? req.query.site : '';
  const site = siteRaw.trim();
  try {
    let rowCount = 0;
    if (site) {
      ({ rowCount } = await pool.query('DELETE FROM fp_templates WHERE site=$1', [site]));
    } else {
      ({ rowCount } = await pool.query('DELETE FROM fp_templates'));
    }
    res.json({ ok: true, deleted: rowCount });
  } catch (err) {
    console.error('fp map clear failed:', err);
    res.status(500).json({ error: 'clear_failed' });
  }
});


// 1) 티켓 상태 확인(사용하지 않음) – 선택
app.get('/api/fp/ticket', (req,res)=>{
  const site = req.query.site || 'default';
  const t = loginTickets.get(site);
  if (!t || t.used || t.exp < now()) return res.json({ ok:false });
  res.json({ ok:true, person_id:t.person_id, name:t.name, is_admin:t.is_admin, exp:t.exp });
});

// 2) 티켓 소비(원샷) – UI는 이걸 먼저 때림
app.post('/api/fp/claim', (req, res) => {
  const site = req.body?.site || 'default';
  const after = Number(req.body?.after || 0);
  const adminOnly = !!req.body?.adminOnly;

  const t = loginTickets.get(site);
  if (!t || t.used || t.exp < Date.now()) return res.json({ ok:false });
  if (after && !(t.issued_at > after)) return res.json({ ok:false });
  if (adminOnly && !t.is_admin) return res.json({ ok:false }); // ← 관리자 필터
  t.used = true;
  res.json({ ok:true, person_id: t.person_id, name: t.name, is_admin: t.is_admin });
});

app.post('/api/fp/invalidate', (req,res)=>{
  const site = (req.body && req.body.site) || 'default';
  loginTickets.delete(site);
  res.json({ ok:true });
});
