const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 15000,
  max: 10
});

// ========== 初始化数据库表 ==========
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 用户表
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'sub',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // 兼容旧表：增加列配置字段
    try {
      await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS col_config JSONB DEFAULT \'{}\'');
    } catch (e) { /* 已存在则忽略 */ }

    // 子账号权限表（一个子账号=一套配置：多选客户+日期范围+列权限+导入/导出总开关）
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_permissions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        customer_name VARCHAR(200),
        customers JSONB DEFAULT '[]',
        date_start DATE,
        date_end DATE,
        allowed_columns JSONB DEFAULT '[]',
        can_import BOOLEAN DEFAULT FALSE,
        can_export BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // 兼容旧表：增加 customers 字段
    try {
      await client.query('ALTER TABLE user_permissions ADD COLUMN IF NOT EXISTS customers JSONB DEFAULT \'[]\'');
    } catch (e) { /* 已存在则忽略 */ }

    // 作业记录表
    await client.query(`
      CREATE TABLE IF NOT EXISTS spray_records (
        id SERIAL PRIMARY KEY,
        customer_name VARCHAR(200) NOT NULL,
        record_date DATE NOT NULL,
        device VARCHAR(200),
        brand VARCHAR(100),
        car_series VARCHAR(100),
        car_model VARCHAR(100),
        parts TEXT,
        board_count INTEGER DEFAULT 0,
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        duration_min NUMERIC(10,2) DEFAULT 0,
        clear_paint_g NUMERIC(10,2) DEFAULT 0,
        color_paint_g NUMERIC(10,2) DEFAULT 0,
        pearl_paint_g NUMERIC(10,2) DEFAULT 0,
        primer_paint_g NUMERIC(10,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 去重唯一索引：同客户同日期同品牌车系车型部件起始时间视为同一条记录
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_spray_records_unique
      ON spray_records (customer_name, record_date, COALESCE(brand,''), COALESCE(car_series,''), COALESCE(car_model,''), COALESCE(parts,''), COALESCE(start_time, '1970-01-01'));
    `);

    await client.query(`CREATE INDEX IF NOT EXISTS idx_spray_records_customer ON spray_records (customer_name);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_spray_records_date ON spray_records (record_date);`);

    // 客户汇总表（存储Excel汇总表中的额外统计字段）
    await client.query(`
      CREATE TABLE IF NOT EXISTS customer_stats (
        id SERIAL PRIMARY KEY,
        customer_name VARCHAR(200) UNIQUE NOT NULL,
        vehicle_count INTEGER DEFAULT 0,
        board_count INTEGER DEFAULT 0,
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        visit_count INTEGER DEFAULT 0,
        whole_car_download INTEGER DEFAULT 0,
        whole_part_download INTEGER DEFAULT 0,
        separate_part_download INTEGER DEFAULT 0,
        whole_track_download INTEGER DEFAULT 0,
        separate_track_download INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await client.query('COMMIT');
    console.log('数据库表初始化完成');

    // 创建初始管理员
    await ensureAdminUser();
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('数据库初始化失败:', err.message);
    throw err;
  } finally {
    client.release();
  }
}

async function ensureAdminUser() {
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD;
  if (!adminPass) {
    console.warn('未设置 ADMIN_PASSWORD，跳过初始管理员创建');
    return;
  }
  const existing = await pool.query('SELECT id FROM users WHERE username = $1', [adminUser]);
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash(adminPass, 10);
    await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')",
      [adminUser, hash]
    );
    console.log(`初始管理员已创建: ${adminUser}`);
  }
}

// ========== 用户相关 ==========
async function getUserByUsername(username) {
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  return result.rows[0] || null;
}

async function getUserById(id) {
  const result = await pool.query('SELECT id, username, role, is_active, created_at FROM users WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function verifyPassword(user, password) {
  return bcrypt.compare(password, user.password_hash);
}

async function listUsers() {
  const result = await pool.query(`
    SELECT u.id, u.username, u.role, u.is_active, u.created_at,
           COALESCE(json_agg(json_build_object(
             'id', p.id, 'customer_name', p.customer_name,
             'customers', COALESCE(p.customers, '[]'::jsonb),
             'date_start', p.date_start, 'date_end', p.date_end,
             'allowed_columns', p.allowed_columns,
             'can_import', p.can_import, 'can_export', p.can_export
           )) FILTER (WHERE p.id IS NOT NULL), '[]') AS permissions
    FROM users u
    LEFT JOIN user_permissions p ON p.user_id = u.id
    GROUP BY u.id
    ORDER BY u.role = 'admin' DESC, u.created_at ASC
  `);
  return result.rows;
}

async function createUser(username, password, role = 'sub') {
  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role, is_active, created_at',
    [username, hash, role]
  );
  return result.rows[0];
}

async function updateUser(id, { password, is_active, role }) {
  const sets = [];
  const vals = [];
  let idx = 1;
  if (password !== undefined) {
    const hash = await bcrypt.hash(password, 10);
    sets.push(`password_hash = $${idx++}`);
    vals.push(hash);
  }
  if (is_active !== undefined) { sets.push(`is_active = $${idx++}`); vals.push(is_active); }
  if (role !== undefined) { sets.push(`role = $${idx++}`); vals.push(role); }
  if (sets.length === 0) return null;
  vals.push(id);
  const result = await pool.query(
    `UPDATE users SET ${sets.join(', ')} WHERE id = $${idx} RETURNING id, username, role, is_active`,
    vals
  );
  return result.rows[0] || null;
}

async function deleteUser(id) {
  const result = await pool.query('DELETE FROM users WHERE id = $1 AND role != $2 RETURNING id', [id, 'admin']);
  return result.rowCount > 0;
}

// ========== 权限相关 ==========
async function getUserPermissions(userId) {
  const result = await pool.query(
    'SELECT * FROM user_permissions WHERE user_id = $1 ORDER BY id',
    [userId]
  );
  return result.rows;
}

async function addPermission(userId, perm) {
  const customers = Array.isArray(perm.customers) ? perm.customers : [];
  const result = await pool.query(
    `INSERT INTO user_permissions (user_id, customer_name, customers, date_start, date_end, allowed_columns, can_import, can_export)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
    [userId, perm.customer_name || null, JSON.stringify(customers),
     perm.date_start || null, perm.date_end || null,
     JSON.stringify(perm.allowed_columns || []), perm.can_import ? true : false, perm.can_export ? true : false]
  );
  return result.rows[0];
}

async function updatePermission(id, perm) {
  const customers = Array.isArray(perm.customers) ? perm.customers : [];
  const result = await pool.query(
    `UPDATE user_permissions SET customer_name=$2, customers=$3, date_start=$4, date_end=$5,
       allowed_columns=$6, can_import=$7, can_export=$8 WHERE id=$1 RETURNING *`,
    [id, perm.customer_name || null, JSON.stringify(customers),
     perm.date_start || null, perm.date_end || null,
     JSON.stringify(perm.allowed_columns || []), perm.can_import ? true : false, perm.can_export ? true : false]
  );
  return result.rows[0] || null;
}

async function deletePermission(id) {
  const result = await pool.query('DELETE FROM user_permissions WHERE id = $1 RETURNING id', [id]);
  return result.rowCount > 0;
}

// 检查用户是否有权访问某客户在某日期范围的数据
async function checkUserAccess(userId, customerName, date) {
  const user = await getUserById(userId);
  if (!user || !user.is_active) return false;
  if (user.role === 'admin') return true;

  const perms = await getUserPermissions(userId);
  if (perms.length === 0) return false;

  // 一个子账号只有一套配置，取第一条
  const p = perms[0];
  // 客户匹配：customers数组为空=全部客户
  const customers = Array.isArray(p.customers) ? p.customers : (p.customer_name ? [p.customer_name] : []);
  if (customers.length > 0 && !customers.includes(customerName)) return false;
  // 日期匹配
  if (date) {
    const d = new Date(date);
    if (p.date_start && d < new Date(p.date_start)) return false;
    if (p.date_end && d > new Date(p.date_end)) return false;
  }
  return true;
}

// 获取用户可访问的客户列表和日期范围
async function getUserAccessScope(userId) {
  const user = await getUserById(userId);
  if (!user) return { customers: [], dateStart: null, dateEnd: null, canImport: false, canExport: false, allowedColumns: null };
  if (user.role === 'admin') {
    return { customers: null, dateStart: null, dateEnd: null, canImport: true, canExport: true, allowedColumns: null };
  }
  const perms = await getUserPermissions(userId);
  if (perms.length === 0) {
    return { customers: [], dateStart: null, dateEnd: null, canImport: false, canExport: false, allowedColumns: null };
  }
  // 一个子账号只有一套配置，取第一条
  const p = perms[0];
  // 客户列表：优先从 customers 数组读取；兼容旧数据从 customer_name 读取
  let customers = null;
  if (Array.isArray(p.customers) && p.customers.length > 0) {
    customers = p.customers;
  } else if (p.customer_name) {
    customers = [p.customer_name];
  }
  const hasAllCustomer = customers === null;
  // 列权限：空数组或null表示全部列
  let allowedColumns = null;
  if (Array.isArray(p.allowed_columns) && p.allowed_columns.length > 0) {
    allowedColumns = p.allowed_columns;
  }
  return {
    customers: hasAllCustomer ? null : customers,
    dateStart: p.date_start || null,
    dateEnd: p.date_end || null,
    canImport: p.can_import ? true : false,
    canExport: p.can_export ? true : false,
    allowedColumns
  };
}

// ========== 作业记录相关 ==========

// 批量UPSERT（追加合并去重）
async function upsertRecords(records) {
  if (records.length === 0) return { inserted: 0, updated: 0 };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let inserted = 0, updated = 0;
    for (const r of records) {
      const result = await client.query(`
        INSERT INTO spray_records
          (customer_name, record_date, device, brand, car_series, car_model, parts, board_count,
           start_time, end_time, duration_min, clear_paint_g, color_paint_g, pearl_paint_g, primer_paint_g)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        ON CONFLICT (customer_name, record_date, COALESCE(brand,''), COALESCE(car_series,''),
                      COALESCE(car_model,''), COALESCE(parts,''), COALESCE(start_time, '1970-01-01'))
        DO UPDATE SET
          device = EXCLUDED.device,
          board_count = EXCLUDED.board_count,
          end_time = EXCLUDED.end_time,
          duration_min = EXCLUDED.duration_min,
          clear_paint_g = EXCLUDED.clear_paint_g,
          color_paint_g = EXCLUDED.color_paint_g,
          pearl_paint_g = EXCLUDED.pearl_paint_g,
          primer_paint_g = EXCLUDED.primer_paint_g
        RETURNING (xmax = 0) AS is_new
      `, [
        r.customer_name, r.record_date, r.device || null, r.brand || null,
        r.car_series || null, r.car_model || null, r.parts || null,
        r.board_count || 0, r.start_time || null, r.end_time || null,
        r.duration_min || 0, r.clear_paint_g || 0, r.color_paint_g || 0,
        r.pearl_paint_g || 0, r.primer_paint_g || 0
      ]);
      if (result.rows[0].is_new) inserted++;
      else updated++;
    }
    await client.query('COMMIT');
    return { inserted, updated };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// 批量更新客户汇总统计
async function upsertCustomerStats(statsList) {
  for (const s of statsList) {
    await pool.query(`
      INSERT INTO customer_stats
        (customer_name, vehicle_count, board_count, start_time, end_time, visit_count,
         whole_car_download, whole_part_download, separate_part_download,
         whole_track_download, separate_track_download, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP)
      ON CONFLICT (customer_name) DO UPDATE SET
        vehicle_count = EXCLUDED.vehicle_count,
        board_count = EXCLUDED.board_count,
        start_time = EXCLUDED.start_time,
        end_time = EXCLUDED.end_time,
        visit_count = EXCLUDED.visit_count,
        whole_car_download = EXCLUDED.whole_car_download,
        whole_part_download = EXCLUDED.whole_part_download,
        separate_part_download = EXCLUDED.separate_part_download,
        whole_track_download = EXCLUDED.whole_track_download,
        separate_track_download = EXCLUDED.separate_track_download,
        updated_at = CURRENT_TIMESTAMP
    `, [
      s.customer_name, s.vehicle_count || 0, s.board_count || 0,
      s.start_time || null, s.end_time || null, s.visit_count || 0,
      s.whole_car_download || 0, s.whole_part_download || 0,
      s.separate_part_download || 0, s.whole_track_download || 0,
      s.separate_track_download || 0
    ]);
  }
}

// 获取所有客户名称列表
async function listCustomers() {
  const result = await pool.query(
    'SELECT DISTINCT customer_name FROM spray_records ORDER BY customer_name'
  );
  return result.rows.map(r => r.customer_name);
}

// 获取客户汇总数据（含从明细实时聚合的统计 + 汇总表额外字段）
async function getCustomerOverview(scope = null) {
  let where = '';
  const params = [];
  if (scope && scope.customers) {
    params.push(scope.customers);
    where = `WHERE r.customer_name = ANY($${params.length}::text[])`;
    if (scope.dateStart) { params.push(scope.dateStart); where += ` AND r.record_date >= $${params.length}`; }
    if (scope.dateEnd) { params.push(scope.dateEnd); where += ` AND r.record_date <= $${params.length}`; }
  } else if (scope && scope.dateStart) {
    params.push(scope.dateStart);
    where = `WHERE r.record_date >= $${params.length}`;
    if (scope.dateEnd) { params.push(scope.dateEnd); where += ` AND r.record_date <= $${params.length}`; }
  }

  const result = await pool.query(`
    SELECT
      r.customer_name,
      COUNT(*) AS furnace,
      COALESCE(SUM(r.board_count),0) AS board_count,
      COALESCE(SUM(r.duration_min),0) AS duration_min,
      COALESCE(SUM(r.clear_paint_g),0) AS clear_paint_g,
      COALESCE(SUM(r.color_paint_g),0) AS color_paint_g,
      COALESCE(SUM(r.pearl_paint_g),0) AS pearl_paint_g,
      COALESCE(SUM(r.primer_paint_g),0) AS primer_paint_g,
      MIN(r.start_time) AS first_time,
      MAX(r.end_time) AS last_time,
      cs.vehicle_count, cs.visit_count, cs.whole_car_download,
      cs.whole_part_download, cs.separate_part_download,
      cs.whole_track_download, cs.separate_track_download
    FROM spray_records r
    LEFT JOIN customer_stats cs ON cs.customer_name = r.customer_name
    ${where}
    GROUP BY r.customer_name, cs.vehicle_count, cs.visit_count, cs.whole_car_download,
             cs.whole_part_download, cs.separate_part_download,
             cs.whole_track_download, cs.separate_track_download
    ORDER BY r.customer_name
  `, params);
  return result.rows;
}

// 获取某客户的作业明细
async function getCustomerRecords(customerName, scope = null) {
  let where = 'WHERE customer_name = $1';
  const params = [customerName];
  if (scope && scope.dateStart) { params.push(scope.dateStart); where += ` AND record_date >= $${params.length}`; }
  if (scope && scope.dateEnd) { params.push(scope.dateEnd); where += ` AND record_date <= $${params.length}`; }

  const result = await pool.query(`
    SELECT * FROM spray_records ${where} ORDER BY record_date DESC, start_time DESC
  `, params);
  return result.rows;
}

// 获取某客户按日期聚合的数据
async function getCustomerDailyAggregate(customerName, scope = null) {
  let where = 'WHERE customer_name = $1';
  const params = [customerName];
  if (scope && scope.dateStart) { params.push(scope.dateStart); where += ` AND record_date >= $${params.length}`; }
  if (scope && scope.dateEnd) { params.push(scope.dateEnd); where += ` AND record_date <= $${params.length}`; }

  const result = await pool.query(`
    SELECT
      record_date,
      COUNT(*) AS furnace,
      COALESCE(SUM(board_count),0) AS board_count,
      COALESCE(SUM(duration_min),0) AS duration_min,
      COALESCE(SUM(clear_paint_g),0) AS clear_paint_g,
      COALESCE(SUM(color_paint_g),0) AS color_paint_g,
      COALESCE(SUM(pearl_paint_g),0) AS pearl_paint_g,
      COALESCE(SUM(primer_paint_g),0) AS primer_paint_g,
      MIN(start_time) AS first_start,
      MAX(end_time) AS last_end
    FROM spray_records
    ${where}
    GROUP BY record_date
    ORDER BY record_date DESC
  `, params);
  return result.rows;
}

// 获取部件统计（拆分多部件后按出现次数）
async function getPartsStats(customerName = null, scope = null) {
  let where = 'WHERE parts IS NOT NULL AND parts != \'\'';
  const params = [];
  if (customerName) { params.push(customerName); where += ` AND customer_name = $${params.length}`; }
  if (scope && scope.customers) { params.push(scope.customers); where += ` AND customer_name = ANY($${params.length}::text[])`; }
  if (scope && scope.dateStart) { params.push(scope.dateStart); where += ` AND record_date >= $${params.length}`; }
  if (scope && scope.dateEnd) { params.push(scope.dateEnd); where += ` AND record_date <= $${params.length}`; }

  // 在SQL中拆分部件：先按换行和逗号替换为下划线，再按下划线拆分
  const result = await pool.query(`
    WITH split_parts AS (
      SELECT
        regexp_split_to_table(
          regexp_replace(
            regexp_replace(parts, E'[\\n\\r]+', '_', 'g'),
            ',', '_', 'g'
          ),
          '_'
        ) AS part_name
      FROM spray_records
      ${where}
    )
    SELECT TRIM(part_name) AS part_name, COUNT(*) AS count
    FROM split_parts
    WHERE TRIM(part_name) != ''
    GROUP BY TRIM(part_name)
    ORDER BY count DESC, part_name
  `, params);
  return result.rows;
}

// 清空某客户数据（用于覆盖模式）
async function deleteCustomerRecords(customerName) {
  await pool.query('DELETE FROM spray_records WHERE customer_name = $1', [customerName]);
  await pool.query('DELETE FROM customer_stats WHERE customer_name = $1', [customerName]);
}

// 获取总记录数
async function getTotalRecords() {
  const result = await pool.query('SELECT COUNT(*) FROM spray_records');
  return parseInt(result.rows[0].count);
}

// ========== 用户列配置（关联账号，登录后拉取） ==========
async function getUserColConfig(userId) {
  const result = await pool.query('SELECT col_config FROM users WHERE id = $1', [userId]);
  if (result.rows.length === 0) return {};
  return result.rows[0].col_config || {};
}

async function saveUserColConfig(userId, config) {
  const result = await pool.query(
    'UPDATE users SET col_config = $1 WHERE id = $2 RETURNING id',
    [JSON.stringify(config || {}), userId]
  );
  return result.rowCount > 0;
}

module.exports = {
  pool, initDB,
  // 用户
  getUserByUsername, getUserById, verifyPassword, listUsers,
  createUser, updateUser, deleteUser,
  getUserColConfig, saveUserColConfig,
  // 权限
  getUserPermissions, addPermission, updatePermission, deletePermission,
  checkUserAccess, getUserAccessScope,
  // 记录
  upsertRecords, upsertCustomerStats, listCustomers, getCustomerOverview,
  getCustomerRecords, getCustomerDailyAggregate, getPartsStats,
  deleteCustomerRecords, getTotalRecords
};
