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
              user_id, is_admin, contact, last_modified, notes
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
    const q = `
      UPDATE personnel SET
        name=$1, rank=$2, military_id=$3, unit=$4, position=$5,
        user_id=$6, password_hash=$7, is_admin=$8, contact=$9, notes=$10,
        last_modified=CURRENT_TIMESTAMP
      WHERE id=$11
      RETURNING id, name, rank, military_id, unit, position,
                user_id, is_admin, contact, last_modified, notes`;
    const { rows } = await pool.query(q, [
      name, rank, military_id, unit, position,
      user_id, password_hash ?? '', !!is_admin, contact ?? null, notes ?? null,
      id
    ]);
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

    const { rows } = await pool.query(`
      SELECT f.id, f.firearm_number, f.firearm_type, f.status
      FROM firearms f
      WHERE ($1 = '' OR f.firearm_number ILIKE '%'||$1||'%' OR f.firearm_type ILIKE '%'||$1||'%')
        AND ($2 = '' OR f.status = $2)
        AND NOT EXISTS (
          SELECT 1
          FROM request_items ri
          JOIN requests r ON r.id = ri.request_id
          WHERE ri.item_type='FIREARM'
            AND ri.firearm_id = f.id
            AND r.status IN ('SUBMITTED','APPROVED')
        )
      ORDER BY f.firearm_number
      LIMIT $3
    `,[q, status, limit]);

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



app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
