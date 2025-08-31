const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// CORS 설정: 모든 도메인에서의 요청을 허용
app.use(cors());

// 데이터베이스 연결 설정
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// API 엔드포인트: 인원 현황
app.get('/api/personnel', async (req, res) => {
    try {
        const result = await pool.query('SELECT name, rank, military_id, unit, position, user_id, is_admin, contact, last_modified, notes FROM personnel');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching personnel data:', err);
        res.status(500).json({ error: 'Failed to fetch personnel data' });
    }
});

// API 엔드포인트: 총기 현황
app.get('/api/firearms', async (req, res) => {
    try {
        const query = `
            SELECT 
                p.name AS owner_name,
                p.rank AS owner_rank,
                p.military_id AS owner_military_id,
                p.unit AS owner_unit,
                p.position AS owner_position,
                f.firearm_type,
                f.firearm_number,
                f.storage_locker,
                f.status,
                f.last_change,
                f.notes
            FROM firearms f
            LEFT JOIN personnel p ON f.owner_id = p.id
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching firearms data:', err);
        res.status(500).json({ error: 'Failed to fetch firearms data' });
    }
});

// API 엔드포인트: 탄약 현황
app.get('/api/ammunition', async (req, res) => {
    try {
        const result = await pool.query('SELECT ammo_name, ammo_category, quantity, storage_locker, status, last_change, notes FROM ammunition');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching ammunition data:', err);
        res.status(500).json({ error: 'Failed to fetch ammunition data' });
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});