-- requests / request_items
CREATE TABLE IF NOT EXISTS requests (
  id SERIAL PRIMARY KEY,
  requester_id INTEGER NOT NULL REFERENCES personnel(id),
  request_type VARCHAR(20) NOT NULL CHECK (request_type IN ('DISPATCH','RETURN')),
  purpose VARCHAR(50) NOT NULL,
  location VARCHAR(100) NOT NULL,
  scheduled_at TIMESTAMPTZ,
  status VARCHAR(20) NOT NULL DEFAULT 'SUBMITTED'
    CHECK (status IN ('SUBMITTED','APPROVED','REJECTED','EXECUTED','CANCELLED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  notes TEXT
);

CREATE TABLE IF NOT EXISTS request_items (
  id SERIAL PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  item_type VARCHAR(10) NOT NULL CHECK (item_type IN ('FIREARM','AMMO')),
  firearm_id INTEGER REFERENCES firearms(id),
  ammo_id INTEGER REFERENCES ammunition(id),
  ammo_category VARCHAR(255),
  quantity INTEGER,
  UNIQUE (request_id, item_type, firearm_id, ammo_id)
);



-- approvals
CREATE TABLE IF NOT EXISTS approvals (
  id SERIAL PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  approver_id INTEGER NOT NULL REFERENCES personnel(id),
  decision VARCHAR(10) NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
  reason TEXT,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);



-- execution & movements
CREATE TABLE IF NOT EXISTS execution_events (
  id SERIAL PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  executed_by INTEGER NOT NULL REFERENCES personnel(id),
  executed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_type VARCHAR(20) NOT NULL CHECK (event_type IN ('DISPATCH','RETURN')),
  notes TEXT
);

CREATE TABLE IF NOT EXISTS ammo_movements (
  id SERIAL PRIMARY KEY,
  execution_id INTEGER NOT NULL REFERENCES execution_events(id) ON DELETE CASCADE,
  ammo_id INTEGER NOT NULL REFERENCES ammunition(id),
  delta INTEGER NOT NULL,
  before_qty INTEGER NOT NULL,
  after_qty  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS firearm_status_changes (
  id SERIAL PRIMARY KEY,
  execution_id INTEGER NOT NULL REFERENCES execution_events(id) ON DELETE CASCADE,
  firearm_id INTEGER NOT NULL REFERENCES firearms(id),
  from_status VARCHAR(50) NOT NULL,
  to_status   VARCHAR(50) NOT NULL
);




-- 실행 로그 뷰
CREATE OR REPLACE VIEW v_execution_summary AS
SELECT e.id AS execution_id, e.event_type, e.executed_at, e.executed_by,
       p.name AS executed_by_name, e.request_id, e.notes
FROM execution_events e
LEFT JOIN personnel p ON p.id=e.executed_by;


-- 인덱스
CREATE INDEX IF NOT EXISTS idx_requests_status_type_created  ON requests(status, request_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_requests_requester            ON requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_request_items_reqid           ON request_items(request_id);
CREATE INDEX IF NOT EXISTS idx_exec_events_type_time         ON execution_events(event_type, executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ammunition_name               ON ammunition(ammo_name);

-- 무결성 제약
ALTER TABLE ammunition    ADD CONSTRAINT IF NOT EXISTS chk_ammo_nonneg CHECK (quantity >= 0);
ALTER TABLE request_items ADD CONSTRAINT IF NOT EXISTS chk_line_qty    CHECK (item_type='AMMO' AND quantity>0 OR item_type='FIREARM');
ALTER TABLE request_items ADD CONSTRAINT IF NOT EXISTS chk_line_type_refs CHECK (
  (item_type='FIREARM' AND firearm_id IS NOT NULL AND ammo_id IS NULL)
  OR
  (item_type='AMMO' AND ammo_id IS NOT NULL AND firearm_id IS NULL)
);


