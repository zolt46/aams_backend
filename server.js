const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const path = require('path');

app.use(express.static(path.join(__dirname))); // ★ 이 줄 추가

// CORS 설정: 모든 도메인에서의 요청을 허용
app.use(cors());

// ⬇⬇ 추가: 프론트에서 보내는 JSON 바디를 파싱 (POST/PUT에 필수)
app.use(express.json());

// 데이터베이스 연결 설정
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

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

    // 필요한 최소 정보만 프론트에 전달
    return res.json({
      id: u.id,
      name: u.name,
      user_id: u.user_id,
      is_admin: u.is_admin,
      rank: u.rank,
      unit: u.unit,
      position: u.position,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'login failed' });
  }
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

    // requester_id가 들어오면 is_admin 여부를 확인해 비관리자면 owner 제한
    let ownerClause = '';
    let args = [q, status];
    if (requesterId) {
      const r = await pool.query(`SELECT is_admin FROM personnel WHERE id=$1`, [requesterId]);
      const isAdmin = !!(r.rowCount && r.rows[0].is_admin);
      if (!isAdmin) { ownerClause = ` AND f.owner_id = $${args.length+1}`; args.push(requesterId); }
    }
    args.push(limit);

    const { rows } = await pool.query(`
      SELECT f.id, f.firearm_number, f.firearm_type, f.status
      FROM firearms f
      WHERE ($1 = '' OR f.firearm_number ILIKE '%'||$1||'%' OR f.firearm_type ILIKE '%'||$1||'%')
        AND ($2 = '' OR f.status = $2)
        ${ownerClause}
        AND NOT EXISTS (
          SELECT 1
          FROM request_items ri
          JOIN requests r ON r.id = ri.request_id
          WHERE ri.item_type='FIREARM'
            AND ri.firearm_id = f.id
            AND r.status IN ('SUBMITTED','APPROVED')
        )
      ORDER BY f.firearm_number
      LIMIT $${args.length}
    `, args);

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
      SELECT a.id, a.ammo_name, a.ammo_category, a.quantity,
            a.storage_locker, a.status, a.last_change, a.notes,
             (a.quantity - COALESCE((
               SELECT SUM(ri.quantity)
               FROM request_items ri
               JOIN requests r2 ON r2.id=ri.request_id
               WHERE ri.item_type='AMMO'
                 AND ri.ammo_id=a.id
                 AND r2.request_type='DISPATCH'
                 AND r2.status IN ('SUBMITTED','APPROVED')
             ),0))::int AS available
      FROM ammunition a
      WHERE ($1 = '' OR a.ammo_name ILIKE '%'||$1||'%' OR a.ammo_category ILIKE '%'||$1||'%')
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

      // 아이템 처리
      for(const it of items){
        if(it.type==='FIREARM'){
          // 해당 총기 행 잠금 + 중복 신청 존재 여부 체크
          const fq = await client.query(`SELECT id,status FROM firearms WHERE id=$1 FOR UPDATE`, [it.firearm_id || it.id]);
          if(!fq.rowCount) throw new Error('총기를 찾을 수 없습니다');
          const f = fq.rows[0];
          if(!isAdmin && f.owner_id !== requester_id) {
            throw new Error('일반 사용자는 본인 총기만 신청할 수 있습니다');
          }

          // 요청유형과 현재상태 호환성
          if(request_type==='DISPATCH' && f.status!=='불입')
            throw new Error(`불출 불가: 현재 상태가 '${f.status}' (불입만 가능)`);
          if(request_type==='RETURN' && f.status!=='불출')
            throw new Error(`불입 불가: 현재 상태가 '${f.status}' (불출만 가능)`);

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

      res.json({ok:true, id:reqId});
    });
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});


  // 2) 신청 목록
  app.get('/api/requests', async (req,res)=>{
    try{
      const { status, type } = req.query;
      let sql = `SELECT r.*, p.name AS requester_name
                FROM requests r LEFT JOIN personnel p ON p.id=r.requester_id
                WHERE 1=1`;
      const args=[];
      if(status){ args.push(status); sql += ` AND r.status=$${args.length}`; }
      if(type){   args.push(type);   sql += ` AND r.request_type=$${args.length}`; }
      sql += ` ORDER BY r.id DESC LIMIT 400`;
      const { rows } = await pool.query(sql, args);
      res.json(rows);
    }catch(e){ console.error(e); res.status(500).json({error:'list failed'}); }
  });

  // 3) 신청 상세 (라인 포함)
  app.get('/api/requests/:id', async (req,res)=>{
    try{
      const id = req.params.id;
      const { rows } = await pool.query(`
        SELECT r.*, p.name AS requester_name
        FROM requests r
        LEFT JOIN personnel p ON p.id=r.requester_id
        WHERE r.id=$1
      `,[id]);
      if(!rows.length) return res.status(404).json({error:'not found'});
      const request = rows[0];

      const items = (await pool.query(`
        SELECT ri.*,
              f.firearm_number, f.firearm_type,
              a.ammo_name, a.ammo_category
        FROM request_items ri
        LEFT JOIN firearms   f ON f.id=ri.firearm_id
        LEFT JOIN ammunition a ON a.id=ri.ammo_id
        WHERE ri.request_id=$1
        ORDER BY ri.id
      `,[id])).rows;

      const approvals = (await pool.query(`
        SELECT ap.*, per.name AS approver_name
        FROM approvals ap
        LEFT JOIN personnel per ON per.id=ap.approver_id
        WHERE ap.request_id=$1
        ORDER BY ap.decided_at
      `,[id])).rows;

      const executions = (await pool.query(`
        SELECT e.*, per.name AS executed_by_name
        FROM execution_events e
        LEFT JOIN personnel per ON per.id=e.executed_by
        WHERE e.request_id=$1
        ORDER BY e.executed_at
      `,[id])).rows;

      res.json({ request, items, approvals, executions });
    }catch(e){ console.error(e); res.status(500).json({error:'detail failed'}); }
  });

    app.post('/api/requests/:id/cancel', async (req,res)=>{
    try{
      const id = req.params.id;
      const actor_id = req.body?.actor_id || null;
      await withTx(async(client)=>{
        const r = await client.query(`SELECT requester_id, status FROM requests WHERE id=$1`, [id]);
        if(!r.rowCount) return res.status(404).json({error:'not found'});
        const row = r.rows[0];

        let isAdmin=false;
        if(actor_id){
          const u=await client.query(`SELECT is_admin FROM personnel WHERE id=$1`,[actor_id]);
          isAdmin = !!(u.rowCount && u.rows[0].is_admin);
        }
        if(actor_id && row.requester_id!==actor_id && !isAdmin){
          return res.status(403).json({error:'forbidden'});
        }
        if(row.status==='EXECUTED') return res.status(400).json({error:'already executed'});
        if(row.status==='CANCELLED') return res.json({ok:true, status:'CANCELLED'});

        await client.query(`UPDATE requests SET status='CANCELLED', updated_at=now() WHERE id=$1`, [id]);
        res.json({ok:true, status:'CANCELLED'});
      });
    }catch(e){ console.error(e); res.status(500).json({error:'cancel failed'}); }
  });

  app.delete('/api/requests/:id', async (req,res)=>{
  try{
    const id = req.params.id;
    const actor_id = req.body?.actor_id ?? req.query.actor_id ?? null;
    await withTx(async(client)=>{
      const r = await client.query(`SELECT requester_id, status FROM requests WHERE id=$1`, [id]);
      if(!r.rowCount) return res.status(404).json({error:'not found'});
      const row = r.rows[0];

      let isAdmin=false;
      if(actor_id){
        const u=await client.query(`SELECT is_admin FROM personnel WHERE id=$1`,[actor_id]);
        isAdmin = !!(u.rowCount && u.rows[0].is_admin);
      }
      if(actor_id && row.requester_id!==actor_id && !isAdmin){
        return res.status(403).json({error:'forbidden'});
      }
      if(row.status==='EXECUTED') return res.status(400).json({error:'cannot delete executed'});

      await client.query(`DELETE FROM requests WHERE id=$1`, [id]);
      res.json({ok:true, deleted:true});
    });
  }catch(e){ console.error(e); res.status(500).json({error:'delete failed'}); }
});



// 승인: 총기 상태 토글·탄약 증감 즉시 반영 + 집행로그
app.post('/api/requests/:id/approve', async (req,res)=>{
  try{
    const id = req.params.id;
    const approver_id = req.body?.approver_id;

    await withTx(async(client)=>{
      const rq = await client.query(`SELECT * FROM requests WHERE id=$1 FOR UPDATE`,[id]);
      if(!rq.rowCount) return res.status(404).json({error:'not found'});
      const r = rq.rows[0];
      if(r.status!=='SUBMITTED') return res.status(400).json({error:'not submitted'});

      await client.query(`
        INSERT INTO approvals(request_id,approver_id,decision,reason)
        VALUES($1,$2,'APPROVE',NULL)
      `,[id, approver_id||null]);

      const items = (await client.query(`
        SELECT ri.*, f.status AS f_status, f.firearm_number, a.quantity AS a_qty
        FROM request_items ri
        LEFT JOIN firearms   f ON f.id=ri.firearm_id
        LEFT JOIN ammunition a ON a.id=ri.ammo_id
        WHERE ri.request_id=$1
        ORDER BY ri.id
      `,[id])).rows;

      const exec = await client.query(`
        INSERT INTO execution_events(request_id, executed_by, event_type, notes)
        VALUES($1,$2,$3,$4) RETURNING id
      `,[id, approver_id||null, r.request_type, 'AUTO: inventory committed at approval']);
      const execution_id = exec.rows[0].id;

      if(r.request_type==='DISPATCH'){
        // 총기: 불입 → 불출
        for(const it of items.filter(x=>x.item_type==='FIREARM')){
          const fq = await client.query(`SELECT id,status FROM firearms WHERE id=$1 FOR UPDATE`,[it.firearm_id]);
          if(!fq.rowCount) throw new Error('총기 없음');
          const cur = fq.rows[0].status;
          if(cur!=='불입') throw new Error(`불출 승인 불가: 현재 상태 ${cur}`);
          await client.query(`UPDATE firearms SET status='불출', last_change=now() WHERE id=$1`,[it.firearm_id]);
          await client.query(`INSERT INTO firearm_status_changes(execution_id,firearm_id,from_status,to_status)
                              VALUES($1,$2,$3,$4)`,[execution_id, it.firearm_id, cur, '불출']);
        }
        // 탄약: 차감
        for(const it of items.filter(x=>x.item_type==='AMMO')){
          const aq = await client.query(`SELECT id, quantity FROM ammunition WHERE id=$1 FOR UPDATE`,[it.ammo_id]);
          if(!aq.rowCount) throw new Error('탄약 없음');
          const before=aq.rows[0].quantity, after=before - it.quantity;
          if(after<0) throw new Error('재고 부족(승인 시)');
          await client.query(`UPDATE ammunition SET quantity=$1, last_change=now() WHERE id=$2`,[after, it.ammo_id]);
          await client.query(`INSERT INTO ammo_movements(execution_id, ammo_id, delta, before_qty, after_qty)
                              VALUES($1,$2,$3,$4,$5)`,[execution_id, it.ammo_id, -it.quantity, before, after]);
        }
      }else{ // RETURN
        // 총기: 불출 → 불입
        for(const it of items.filter(x=>x.item_type==='FIREARM')){
          const fq = await client.query(`SELECT id,status FROM firearms WHERE id=$1 FOR UPDATE`,[it.firearm_id]);
          if(!fq.rowCount) throw new Error('총기 없음');
          const cur=fq.rows[0].status;
          if(cur!=='불출') throw new Error(`불입 승인 불가: 현재 상태 ${cur}`);
          await client.query(`UPDATE firearms SET status='불입', last_change=now() WHERE id=$1`,[it.firearm_id]);
          await client.query(`INSERT INTO firearm_status_changes(execution_id,firearm_id,from_status,to_status)
                              VALUES($1,$2,$3,$4)`,[execution_id, it.firearm_id, cur, '불입']);
        }
        // 탄약: 증가
        for(const it of items.filter(x=>x.item_type==='AMMO')){
          const aq = await client.query(`SELECT id, quantity FROM ammunition WHERE id=$1 FOR UPDATE`,[it.ammo_id]);
          if(!aq.rowCount) throw new Error('탄약 없음');
          const before=aq.rows[0].quantity, after=before + it.quantity;
          await client.query(`UPDATE ammunition SET quantity=$1, last_change=now() WHERE id=$2`,[after, it.ammo_id]);
          await client.query(`INSERT INTO ammo_movements(execution_id, ammo_id, delta, before_qty, after_qty)
                              VALUES($1,$2,$3,$4,$5)`,[execution_id, it.ammo_id, +it.quantity, before, after]);
        }
      }

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

      await client.query(`
        INSERT INTO approvals(request_id,approver_id,decision,reason)
        VALUES($1,$2,'REJECT',$3)
      `,[id, approver_id||null, reason||null]);

      await client.query(`UPDATE requests SET status='REJECTED', updated_at=now() WHERE id=$1`,[id]);

      res.json({ok:true});
    });
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
});


  // 5) 집행(요청유형 기반으로 자동 DISPATCH/RETURN)
 app.post('/api/requests/:id/execute', async (req,res)=>{
  try{
    const id = req.params.id;
    const executed_by = req.body?.executed_by || null;
    await withTx(async(client)=>{
      const rq=await client.query(`SELECT * FROM requests WHERE id=$1 FOR UPDATE`,[id]);
      if(!rq.rowCount) return res.status(404).json({error:'not found'});
      const r=rq.rows[0];
      if(r.status!=='APPROVED') return res.status(400).json({error:'not approved'});

      // 재고/상태는 승인 시 이미 반영되었음. 집행 이벤트/상태만 갱신.
      await client.query(`
        INSERT INTO execution_events(request_id, executed_by, event_type, notes)
        VALUES($1,$2,$3,$4)
      `,[id, executed_by, r.request_type, 'MARK EXECUTED']);

      await client.query(`UPDATE requests SET status='EXECUTED', updated_at=now() WHERE id=$1`,[id]);
      res.json({ok:true});
    });
  }catch(e){ console.error(e); res.status(400).json({error:String(e.message||e)}); }
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
  // 승인
  await client.query(
    `INSERT INTO approvals(request_id,approver_id,decision,reason)
     VALUES($1,$2,'APPROVE','auto by roster')`, [request_id, approver_id]
  );
  await client.query(`UPDATE requests SET status='APPROVED', updated_at=now() WHERE id=$1`, [request_id]);

  if (!doExecute) return;

  // 집행 이벤트
  const rq = await client.query(`SELECT request_type FROM requests WHERE id=$1`, [request_id]);
  const rtype = rq.rows[0].request_type; // DISPATCH/RETURN
  const ev = await client.query(
    `INSERT INTO execution_events(request_id, executed_by, event_type)
     VALUES($1,$2,$3) RETURNING id`,
    [request_id, approver_id, rtype]
  );
  const execId = ev.rows[0].id;

  // 항목별 실제 재고/상태 반영
  const items = await client.query(
    `SELECT item_type, firearm_id, ammo_id, quantity
     FROM request_items WHERE request_id=$1`, [request_id]
  );
  for (const it of items.rows) {
    if (it.item_type==='FIREARM') {
      const fq = await client.query(`SELECT id,status FROM firearms WHERE id=$1 FOR UPDATE`, [it.firearm_id]);
      const from = fq.rows[0].status;
      const to   = (rtype==='DISPATCH'?'불출':'불입');
      await client.query(
        `UPDATE firearms SET status=$1, last_change=now() WHERE id=$2`,
        [to, it.firearm_id]
      );
      await client.query(
        `INSERT INTO firearm_status_changes(execution_id, firearm_id, from_status, to_status)
         VALUES($1,$2,$3,$4)`,
        [execId, it.firearm_id, from, to]
      );
    } else if (it.item_type==='AMMO') {
      const aq = await client.query(`SELECT id, quantity FROM ammunition WHERE id=$1 FOR UPDATE`, [it.ammo_id]);
      const before = aq.rows[0].quantity;
      const delta  = (rtype==='DISPATCH' ? -it.quantity : +it.quantity);
      const after  = before + delta;
      if (after < 0) throw new Error('탄약 재고 음수 불가');
      await client.query(`UPDATE ammunition SET quantity=$1, last_change=now() WHERE id=$2`, [after, it.ammo_id]);
      await client.query(
        `INSERT INTO ammo_movements(execution_id, ammo_id, delta, before_qty, after_qty)
         VALUES($1,$2,$3,$4,$5)`,
        [execId, it.ammo_id, delta, before, after]
      );
    }
  }
  await client.query(`UPDATE requests SET status='EXECUTED', updated_at=now() WHERE id=$1`, [request_id]);
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
