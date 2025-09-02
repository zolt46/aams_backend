const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

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
app.get('/api/firearms', async (req, res) => {
  try {
    const q = `
      SELECT
        f.id,
        f.owner_id,
        p.name         AS owner_name,
        p.rank         AS owner_rank,
        p.military_id  AS owner_military_id,
        p.unit         AS owner_unit,
        p.position     AS owner_position,
        f.firearm_type,
        f.firearm_number,
        f.storage_locker,
        f.status,
        f.last_change,
        f.notes
      FROM firearms f
      LEFT JOIN personnel p ON f.owner_id = p.id
      ORDER BY f.id DESC
    `;
    const { rows } = await pool.query(q);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching firearms data:', err);
    res.status(500).json({ error: 'Failed to fetch firearms data' });
  }
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
    console.error('Error deleting firearm:', err);
    res.status(500).json({ error: 'delete failed' });
  }
});



// ===== Ammunition API =====

// 목록 조회
app.get('/api/ammunition', async (req, res) => {
  try {
    const q = `
      SELECT
        id, ammo_name, ammo_category, quantity, storage_locker,
        status, last_change, notes
      FROM ammunition
      ORDER BY id DESC
    `;
    const { rows } = await pool.query(q);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching ammunition data:', err);
    res.status(500).json({ error: 'Failed to fetch ammunition data' });
  }
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


/* ===== AAMS Workcenter API (patch) ===== */
// utils
async function withTx(run){
  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    const r = await run(client);
    await client.query('COMMIT');
    return r;
  }catch(e){
    await client.query('ROLLBACK'); throw e;
  }finally{ client.release(); }
}

// 1) Create request
app.post('/api/requests', async (req,res)=>{
  try{
    const { requester_id, request_type, purpose, location, scheduled_at, notes, items=[] } = req.body;
    const r = await pool.query(
      `INSERT INTO requests(requester_id,request_type,purpose,location,scheduled_at,notes)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
      [requester_id, request_type, purpose, location, scheduled_at, notes]
    );
    const reqId = r.rows[0].id;
    for(const it of items){
      if(it.type==='FIREARM'){
        const q = await pool.query(`SELECT id FROM firearms WHERE firearm_number=$1`, [it.ident]);
        if(!q.rowCount) continue;
        await pool.query(
          `INSERT INTO request_items(request_id,item_type,firearm_id) VALUES($1,'FIREARM',$2)`,
          [reqId, q.rows[0].id]
        );
      }else if(it.type==='AMMO'){
        const q = await pool.query(`SELECT id, ammo_category FROM ammunition WHERE ammo_name=$1`, [it.ident]);
        if(!q.rowCount) continue;
        await pool.query(
          `INSERT INTO request_items(request_id,item_type,ammo_id,quantity,ammo_category) VALUES($1,'AMMO',$2,$3,$4)`,
          [reqId, q.rows[0].id, it.qty||0, q.rows[0].ammo_category]
        );
      }
    }
    res.json({ ok:true, id:reqId });
  }catch(e){ console.error(e); res.status(500).json({error:'create failed'}); }
});

// 2) List requests
app.get('/api/requests', async (req,res)=>{
  try{
    const { status, type } = req.query;
    let sql = `SELECT r.*, p.name AS requester_name FROM requests r
               LEFT JOIN personnel p ON p.id=r.requester_id WHERE 1=1`;
    const args=[];
    if(status){ args.push(status); sql+=` AND r.status = $${args.length}`; }
    if(type){ args.push(type); sql+=` AND r.request_type = $${args.length}`; }
    sql += ` ORDER BY r.id DESC LIMIT 200`;
    const rows = (await pool.query(sql, args)).rows;
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({error:'list failed'}); }
});

// 3) Get request detail
app.get('/api/requests/:id', async (req,res)=>{
  try{
    const { rows } = await pool.query(`SELECT * FROM requests WHERE id=$1`, [req.params.id]);
    if(!rows.length) return res.status(404).json({error:'not found'});
    const items = (await pool.query(`SELECT * FROM request_items WHERE request_id=$1`, [req.params.id])).rows;
    res.json({ ...rows[0], items });
  }catch(e){ console.error(e); res.status(500).json({error:'detail failed'}); }
});

// 4) Approve / Reject
app.post('/api/requests/:id/approve', async (req,res)=>{
  try{
    const approver_id = req.body?.approver_id || 1; // TODO: replace with real auth
    await withTx(async(client)=>{
      await client.query(`INSERT INTO approvals(request_id, approver_id, decision) VALUES($1,$2,'APPROVE')`, [req.params.id, approver_id]);
      await client.query(`UPDATE requests SET status='APPROVED', updated_at=now() WHERE id=$1`, [req.params.id]);
    });
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:'approve failed'}); }
});

app.post('/api/requests/:id/reject', async (req,res)=>{
  try{
    const { reason, approver_id } = req.body||{};
    await withTx(async(client)=>{
      await client.query(`INSERT INTO approvals(request_id, approver_id, decision, reason) VALUES($1,$2,'REJECT',$3)`, [req.params.id, approver_id||1, reason||null]);
      await client.query(`UPDATE requests SET status='REJECTED', updated_at=now() WHERE id=$1`, [req.params.id]);
    });
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:'reject failed'}); }
});

// 5) Execute (DISPATCH/RETURN)
app.post('/api/requests/:id/execute', async (req,res)=>{
  try{
    const { event_type='DISPATCH', executed_by } = req.body||{};
    const exec_by = executed_by || 1; // TODO: replace with real auth
    const reqId = req.params.id;
    await withTx(async(client)=>{
      // precheck: request approved
      const r = await client.query(`SELECT status FROM requests WHERE id=$1`, [reqId]);
      if(!r.rowCount || r.rows[0].status!=='APPROVED') throw new Error('not approved');

      const exec = await client.query(`INSERT INTO execution_events(request_id,executed_by,event_type) VALUES($1,$2,$3) RETURNING id, executed_at`, [reqId, exec_by, event_type]);
      const execId = exec.rows[0].id;

      const items = (await client.query(`SELECT * FROM request_items WHERE request_id=$1`, [reqId])).rows;

      for(const it of items){
        if(it.item_type==='FIREARM'){
          // lock row
          const cur = await client.query(`SELECT id,status,firearm_number FROM firearms WHERE id=$1 FOR UPDATE`, [it.firearm_id]);
          if(!cur.rowCount) throw new Error('firearm not found');
          const from = cur.rows[0].status;
          const to = (event_type==='DISPATCH') ? '불출' : '보관';
          if(event_type==='DISPATCH' && from==='불출') throw new Error('already dispatched');
          await client.query(`INSERT INTO firearm_status_changes(execution_id,firearm_id,from_status,to_status) VALUES($1,$2,$3,$4)`,
            [execId, it.firearm_id, from, to]);
          await client.query(`UPDATE firearms SET status=$1, last_change=now() WHERE id=$2`, [to, it.firearm_id]);
        }else{
          const cur = await client.query(`SELECT id,quantity,ammo_name FROM ammunition WHERE id=$1 FOR UPDATE`, [it.ammo_id]);
          if(!cur.rowCount) throw new Error('ammo not found');
          const before = cur.rows[0].quantity;
          const delta = (event_type==='DISPATCH') ? -(it.quantity||0) : +(it.quantity||0);
          const after = before + delta;
          if(after<0) throw new Error('insufficient ammo');
          await client.query(`INSERT INTO ammo_movements(execution_id,ammo_id,delta,before_qty,after_qty) VALUES($1,$2,$3,$4,$5)`,
            [execId, it.ammo_id, delta, before, after]);
          await client.query(`UPDATE ammunition SET quantity=$1, last_change=now() WHERE id=$2`, [after, it.ammo_id]);
        }
      }
      await client.query(`UPDATE requests SET status='EXECUTED', updated_at=now() WHERE id=$1`, [reqId]);
    });
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(400).json({error:'execute failed', detail:String(e)}); }
});

// 6) Execution summaries (for logs view)
app.get('/api/executions', async (req,res)=>{
  try{
    const et = req.query.event_type || null;
    const base = `SELECT v.*, 
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
      LIMIT 200`;
    const rows=(await pool.query(base, [et])).rows;
    res.json(rows);
  }catch(e){ console.error(e); res.status(500).json({error:'exec list failed'}); }
});
/* ===== End patch ===== */



app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
