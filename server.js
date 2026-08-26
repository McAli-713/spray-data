const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const ExcelJS = require('exceljs');
require('dotenv').config();

// ========== 上传文件存储目录 ==========
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  console.log('上传目录已创建:', UPLOAD_DIR);
}

// ========== 水印图片生成（可选依赖 canvas，未安装则跳过背景图水印） ==========
let canvasLib = null;
try { canvasLib = require('canvas'); } catch(e) { canvasLib = null; }

// ========== Excel 文件加密（可选依赖 xlsx-populate，未安装则仅工作表保护） ==========
let xlsxPopulate = null;
try { xlsxPopulate = require('xlsx-populate'); } catch(e) { xlsxPopulate = null; }
const EXCEL_PROTECT_PASSWORD = process.env.EXCEL_PROTECT_PASSWORD || '53931526';
// 将 exceljs 生成的 buffer 用 xlsx-populate 加文件打开密码
async function encryptWorkbookBuffer(buffer, password) {
  if (!xlsxPopulate) return buffer;
  try {
    const wb = await xlsxPopulate.fromDataAsync(buffer);
    return await wb.outputAsync({ password });
  } catch(e) {
    console.warn('Excel文件加密失败，返回未加密文件:', e.message);
    return buffer;
  }
}

function generateWatermarkImage(text) {
  if (!canvasLib) return null;
  try {
    const { createCanvas } = canvasLib;
    const w = 500, h = 250;
    const cv = createCanvas(w, h);
    const ctx = cv.getContext('2d');
    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(w / 2, h / 2);
    ctx.rotate(-30 * Math.PI / 180);
    ctx.font = 'bold 32px "Microsoft YaHei", sans-serif';
    ctx.fillStyle = 'rgba(128, 128, 128, 0.12)';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, 0, 0);
    ctx.restore();
    return cv.toBuffer('image/png');
  } catch(e) {
    console.warn('生成水印图片失败:', e.message);
    return null;
  }
}

// ========== 全局进程错误防护（防止未捕获异常导致进程崩溃、连接被关闭） ==========
process.on('uncaughtException', (err) => {
  console.error('⚠️ 未捕获异常:', err.message, err.stack);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️ 未处理的Promise拒绝:', reason);
});

const {
  initDB, ensureUploadRecordsTable, getUserByUsername, getUserById, verifyPassword, listUsers,
  createUser, updateUser, deleteUser,
  getUserColConfig, saveUserColConfig,
  getUserPermissions, addPermission, updatePermission, deletePermission,
  getUserAccessScope,
  upsertRecords, upsertCustomerStats, listCustomers, getCustomerOverview,
  getCustomerRecords, getCustomerDailyAggregate, getPartsStats,
  deleteCustomerRecords, getTotalRecords,
  createUploadRecord, listUploadRecords, getUploadRecordById
} = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES = '12h';

app.set('trust proxy', 1);

// 安全响应头
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(cors({ origin: false }));
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// 文件上传配置（磁盘存储，保留原始文件供下载）
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const timestamp = Date.now();
      const random = Math.random().toString(36).substring(2, 8);
      const ext = path.extname(file.originalname);
      cb(null, `upload_${timestamp}_${random}${ext}`);
    }
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.originalname.match(/\.(xlsx|xls)$/i)) cb(null, true);
    else cb(new Error('仅支持 .xlsx / .xls 文件'));
  }
});

// ========== 启动检查 ==========
if (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 6) {
  console.error('启动失败：必须设置 ADMIN_PASSWORD 环境变量（至少6位）');
  process.exit(1);
}

initDB().then(() => ensureUploadRecordsTable()).catch(err => {
  console.error('数据库初始化失败:', err.message);
  process.exit(1);
});

// ========== 工具函数 ==========
function serverError(res, err, context) {
  console.error(context + ':', err);
  res.status(500).json({ error: '服务器内部错误，请稍后重试' });
}

// ========== JWT 认证中间件 ==========
function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未登录或登录已过期' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.username = decoded.username;
    req.role = decoded.role;
    next();
  } catch (e) {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

function adminRequired(req, res, next) {
  if (req.role !== 'admin') {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
}

// 登录速率限制
const loginFailures = new Map();
const RATE_WINDOW = 15 * 60 * 1000;
const RATE_MAX = 10;
function recordLoginFail(ip) {
  const now = Date.now();
  const ex = loginFailures.get(ip);
  if (ex && now - ex.first < RATE_WINDOW) ex.count++;
  else loginFailures.set(ip, { count: 1, first: now });
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginFailures) if (now - r.first >= RATE_WINDOW) loginFailures.delete(ip);
}, 60000);

// ========== 认证接口 ==========
app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  const fail = loginFailures.get(ip);
  if (fail && fail.count >= RATE_MAX && Date.now() - fail.first < RATE_WINDOW) {
    const retry = Math.ceil((RATE_WINDOW - (Date.now() - fail.first)) / 1000);
    return res.status(429).json({ error: `登录尝试过多，请 ${retry} 秒后再试` });
  }

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码必填' });

  try {
    const user = await getUserByUsername(username);
    if (!user || !user.is_active) {
      recordLoginFail(ip);
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    const valid = await verifyPassword(user, password);
    if (!valid) {
      recordLoginFail(ip);
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    loginFailures.delete(ip);
    const token = jwt.sign({ userId: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    serverError(res, err, '登录失败');
  }
});

app.get('/api/me', authRequired, async (req, res) => {
  try {
    const user = await getUserById(req.userId);
    const scope = await getUserAccessScope(req.userId);
    res.json({ user, scope });
  } catch (err) {
    serverError(res, err, '获取用户信息失败');
  }
});

// ========== 用户管理（管理员） ==========
app.get('/api/users', authRequired, adminRequired, async (req, res) => {
  try {
    const users = await listUsers();
    res.json(users);
  } catch (err) {
    serverError(res, err, '获取用户列表失败');
  }
});

app.post('/api/users', authRequired, adminRequired, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码必填' });
    if (password.length < 6) return res.status(400).json({ error: '密码至少6位' });
    const existing = await getUserByUsername(username);
    if (existing) return res.status(400).json({ error: '用户名已存在' });
    const user = await createUser(username, password, role || 'sub');
    res.json(user);
  } catch (err) {
    serverError(res, err, '创建用户失败');
  }
});

app.put('/api/users/:id', authRequired, adminRequired, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { password, is_active, role } = req.body;
    const user = await updateUser(id, { password, is_active, role });
    if (!user) return res.status(404).json({ error: '用户不存在' });
    res.json(user);
  } catch (err) {
    serverError(res, err, '更新用户失败');
  }
});

app.delete('/api/users/:id', authRequired, adminRequired, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (id === req.userId) return res.status(400).json({ error: '不能删除自己' });
    const ok = await deleteUser(id);
    if (!ok) return res.status(404).json({ error: '用户不存在或为管理员' });
    res.json({ success: true });
  } catch (err) {
    serverError(res, err, '删除用户失败');
  }
});

// ========== 权限管理 ==========
app.get('/api/users/:id/permissions', authRequired, adminRequired, async (req, res) => {
  try {
    const perms = await getUserPermissions(parseInt(req.params.id));
    res.json(perms);
  } catch (err) {
    serverError(res, err, '获取权限失败');
  }
});

app.post('/api/users/:id/permissions', authRequired, adminRequired, async (req, res) => {
  try {
    const perm = await addPermission(parseInt(req.params.id), req.body);
    res.json(perm);
  } catch (err) {
    serverError(res, err, '添加权限失败');
  }
});

app.put('/api/permissions/:pid', authRequired, adminRequired, async (req, res) => {
  try {
    const perm = await updatePermission(parseInt(req.params.pid), req.body);
    if (!perm) return res.status(404).json({ error: '权限不存在' });
    res.json(perm);
  } catch (err) {
    serverError(res, err, '更新权限失败');
  }
});

app.delete('/api/permissions/:pid', authRequired, adminRequired, async (req, res) => {
  try {
    const ok = await deletePermission(parseInt(req.params.pid));
    if (!ok) return res.status(404).json({ error: '权限不存在' });
    res.json({ success: true });
  } catch (err) {
    serverError(res, err, '删除权限失败');
  }
});

// ========== Excel 上传导入 ==========
// 字段别名映射
const FIELD_ALIAS = {
  '时间': 'record_date', '日期': 'record_date', '作业时间': 'record_date', '生产日期': 'record_date',
  '设备': 'device',
  '品牌': 'brand',
  '车系': 'car_series',
  '车型': 'car_model',
  '部件': 'parts', '部件名称': 'parts',
  '板件数量': 'board_count', '板件数': 'board_count', '板件': 'board_count', '数量': 'board_count', '件数': 'board_count',
  '起始时间': 'start_time',
  '结束时间': 'end_time',
  '时长(min)': 'duration_min', '时长': 'duration_min', '作业时长': 'duration_min', '耗时': 'duration_min', '时长(分钟)': 'duration_min',
  '清漆用量(g)': 'clear_paint_g', '清漆耗量': 'clear_paint_g', '清漆用量': 'clear_paint_g', '清漆': 'clear_paint_g',
  '色漆用量(g)': 'color_paint_g', '色漆耗量': 'color_paint_g', '色漆用量': 'color_paint_g', '色漆': 'color_paint_g',
  '珍珠用量(g)': 'pearl_paint_g', '珍珠耗量': 'pearl_paint_g', '珍珠用量': 'pearl_paint_g', '珍珠': 'pearl_paint_g',
  '底漆用量()': 'primer_paint_g', '底漆耗量': 'primer_paint_g', '底漆用量': 'primer_paint_g', '底漆': 'primer_paint_g'
};

function normalizeField(key) {
  const trimmed = String(key).trim();
  if (FIELD_ALIAS[trimmed]) return FIELD_ALIAS[trimmed];
  const noParen = trimmed.replace(/\s*\([^)]*\)\s*$/, '').trim();
  return FIELD_ALIAS[noParen] || trimmed;
}

function parseDateValue(val) {
  if (!val && val !== 0) return null;
  if (val instanceof Date) return val;
  if (typeof val === 'number') {
    const d = new Date((val - 25569) * 86400 * 1000);
    return isNaN(d) ? null : d;
  }
  const s = String(val).trim();
  if (!s) return null;
  const d = new Date(s.replace(/-/g, '/'));
  return isNaN(d) ? null : d;
}

function num(v) {
  if (v === null || v === undefined || v === '') return 0;
  const n = parseFloat(v);
  return isNaN(n) ? 0 : n;
}

app.post('/api/upload', authRequired, upload.single('file'), async (req, res) => {
  try {
    // 权限检查
    const scope = await getUserAccessScope(req.userId);
    if (!scope.canImport && req.role !== 'admin') {
      // 权限不足时删除已上传的文件
      if (req.file) try { fs.unlinkSync(req.file.path); } catch(e) {}
      return res.status(403).json({ error: '您没有导入数据的权限' });
    }
    if (!req.file) return res.status(400).json({ error: '请选择文件' });

    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(req.file.path);

    const allRecords = [];
    const allStats = [];
    const customersInFile = new Set();

    for (const sheetName of workbook.worksheets.map(ws => ws.name)) {
      const ws = workbook.getWorksheet(sheetName);
      if (!ws || ws.rowCount < 2) continue;

      // 汇总表
      if (sheetName === '汇总表') {
        const headerRow = ws.getRow(1);
        const headers = {};
        headerRow.eachCell((cell, col) => { headers[normalizeField(cell.value)] = col; });
        for (let i = 2; i <= ws.rowCount; i++) {
          const row = ws.getRow(i);
          const customerName = row.getCell(headers['device'] || 1)?.value;
          if (!customerName) continue;
          customersInFile.add(String(customerName));
          allStats.push({
            customer_name: String(customerName),
            vehicle_count: num(row.getCell(headers['车辆数量'] || 2)?.value),
            board_count: num(row.getCell(headers['板件数量'] || 3)?.value),
            start_time: parseDateValue(row.getCell(headers['起始时间'] || 4)?.value),
            end_time: parseDateValue(row.getCell(headers['结束时间'] || 5)?.value),
            visit_count: num(row.getCell(headers['访问次数'] || 6)?.value),
            whole_car_download: num(row.getCell(headers['整车下载次数'] || 7)?.value),
            whole_part_download: num(row.getCell(headers['整车部件下载次数'] || 8)?.value),
            separate_part_download: num(row.getCell(headers['分离件部件下载次数'] || 9)?.value),
            whole_track_download: num(row.getCell(headers['整车轨迹下载次数'] || 10)?.value),
            separate_track_download: num(row.getCell(headers['分离件轨迹下载次数'] || 11)?.value)
          });
        }
        continue;
      }

      // 客户明细表
      const headerRow = ws.getRow(1);
      const headers = {};
      headerRow.eachCell((cell, col) => {
        const field = normalizeField(cell.value);
        headers[field] = col;
      });

      // 必须有时间列
      if (!headers['record_date']) continue;

      const customerName = sheetName;
      customersInFile.add(customerName);

      for (let i = 2; i <= ws.rowCount; i++) {
        const row = ws.getRow(i);
        const recordDate = parseDateValue(row.getCell(headers['record_date'])?.value);
        if (!recordDate) continue;

        const record = {
          customer_name: customerName,
          record_date: recordDate,
          device: headers['device'] ? String(row.getCell(headers['device'])?.value || '') : customerName,
          brand: headers['brand'] ? String(row.getCell(headers['brand'])?.value || '') : '',
          car_series: headers['car_series'] ? String(row.getCell(headers['car_series'])?.value || '') : '',
          car_model: headers['car_model'] ? String(row.getCell(headers['car_model'])?.value || '') : '',
          parts: headers['parts'] ? String(row.getCell(headers['parts'])?.value || '').trim() : '',
          board_count: headers['board_count'] ? num(row.getCell(headers['board_count'])?.value) : 0,
          start_time: headers['start_time'] ? parseDateValue(row.getCell(headers['start_time'])?.value) : null,
          end_time: headers['end_time'] ? parseDateValue(row.getCell(headers['end_time'])?.value) : null,
          duration_min: headers['duration_min'] ? num(row.getCell(headers['duration_min'])?.value) : 0,
          clear_paint_g: headers['clear_paint_g'] ? num(row.getCell(headers['clear_paint_g'])?.value) : 0,
          color_paint_g: headers['color_paint_g'] ? num(row.getCell(headers['color_paint_g'])?.value) : 0,
          pearl_paint_g: headers['pearl_paint_g'] ? num(row.getCell(headers['pearl_paint_g'])?.value) : 0,
          primer_paint_g: headers['primer_paint_g'] ? num(row.getCell(headers['primer_paint_g'])?.value) : 0
        };
        allRecords.push(record);
      }
    }

    // 追加合并去重
    const result = await upsertRecords(allRecords);
    if (allStats.length > 0) await upsertCustomerStats(allStats);

    // 记录上传历史
    let uploadRecord = null;
    try {
      uploadRecord = await createUploadRecord({
        filename: req.file.filename,
        originalFilename: req.file.originalname,
        filePath: req.file.path,
        fileSize: req.file.size,
        uploaderId: req.userId,
        uploaderUsername: req.username,
        insertedCount: result.inserted,
        updatedCount: result.updated,
        customers: [...customersInFile]
      });
    } catch(e) { console.warn('上传记录入库失败:', e.message); }

    res.json({
      success: true,
      message: `导入完成：新增 ${result.inserted} 条，更新 ${result.updated} 条，涉及 ${customersInFile.size} 个客户`,
      inserted: result.inserted,
      updated: result.updated,
      customers: [...customersInFile],
      totalRecords: await getTotalRecords(),
      uploadId: uploadRecord ? uploadRecord.id : null
    });
  } catch (err) {
    console.error('Excel导入失败:', err);
    // 解析失败时删除已上传的文件
    if (req.file) try { fs.unlinkSync(req.file.path); } catch(e) {}
    res.status(500).json({ error: 'Excel解析失败：' + err.message });
  }
});

// ========== 上传记录管理（管理员） ==========
app.get('/api/uploads', authRequired, adminRequired, async (req, res) => {
  try {
    const records = await listUploadRecords(200);
    res.json(records);
  } catch (err) {
    serverError(res, err, '获取上传记录失败');
  }
});

app.get('/api/uploads/:id/download', authRequired, adminRequired, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const record = await getUploadRecordById(id);
    if (!record) return res.status(404).json({ error: '上传记录不存在' });
    if (!fs.existsSync(record.file_path)) {
      return res.status(404).json({ error: '原始文件已不存在（可能因服务器重启丢失）' });
    }
    res.download(record.file_path, record.original_filename);
  } catch (err) {
    serverError(res, err, '下载文件失败');
  }
});

// ========== 数据查询接口 ==========

// 客户列表
app.get('/api/customers', authRequired, async (req, res) => {
  try {
    const scope = await getUserAccessScope(req.userId);
    let customers = await listCustomers();
    if (scope.customers) {
      customers = customers.filter(c => scope.customers.includes(c));
    }
    res.json(customers);
  } catch (err) {
    serverError(res, err, '获取客户列表失败');
  }
});

// 客户总览（汇总）
app.get('/api/overview', authRequired, async (req, res) => {
  try {
    const scope = await getUserAccessScope(req.userId);
    const data = await getCustomerOverview(scope);
    res.json(data);
  } catch (err) {
    serverError(res, err, '获取客户总览失败');
  }
});

// 某客户作业明细
app.get('/api/records/:customer', authRequired, async (req, res) => {
  try {
    const customerName = req.params.customer;
    const scope = await getUserAccessScope(req.userId);
    // 权限检查
    if (scope.customers && !scope.customers.includes(customerName)) {
      return res.status(403).json({ error: '无权访问该客户数据' });
    }
    const records = await getCustomerRecords(customerName, scope);
    res.json(records);
  } catch (err) {
    serverError(res, err, '获取作业明细失败');
  }
});

// 某客户按日期聚合
app.get('/api/daily/:customer', authRequired, async (req, res) => {
  try {
    const customerName = req.params.customer;
    const scope = await getUserAccessScope(req.userId);
    if (scope.customers && !scope.customers.includes(customerName)) {
      return res.status(403).json({ error: '无权访问该客户数据' });
    }
    const data = await getCustomerDailyAggregate(customerName, scope);
    res.json(data);
  } catch (err) {
    serverError(res, err, '获取日聚合数据失败');
  }
});

// 部件统计
app.get('/api/parts-stats', authRequired, async (req, res) => {
  try {
    const customer = req.query.customer || null;
    const scope = await getUserAccessScope(req.userId);
    if (customer && scope.customers && !scope.customers.includes(customer)) {
      return res.status(403).json({ error: '无权访问该客户数据' });
    }
    const data = await getPartsStats(customer, scope);
    res.json(data);
  } catch (err) {
    serverError(res, err, '获取部件统计失败');
  }
});

// ========== 导出接口 ==========
app.get('/api/export/:customer', authRequired, async (req, res) => {
  try {
    const customerName = req.params.customer;
    const scope = await getUserAccessScope(req.userId);
    if (!scope.canExport && req.role !== 'admin') {
      return res.status(403).json({ error: '您没有导出数据的权限' });
    }
    if (scope.customers && !scope.customers.includes(customerName)) {
      return res.status(403).json({ error: '无权访问该客户数据' });
    }
    const records = await getCustomerRecords(customerName, scope);
    const workbook = new ExcelJS.Workbook();
    const ws = workbook.addWorksheet(customerName.substring(0, 30));
    // 基本数据列（默认导出）
    const baseCols = [
      { header: '喷涂时间', key: 'record_date', width: 12 },
      { header: '设备', key: 'device', width: 18 },
      { header: '品牌', key: 'brand', width: 12 },
      { header: '车系', key: 'car_series', width: 14 },
      { header: '车型', key: 'car_model', width: 18 },
      { header: '部件', key: 'parts', width: 30 },
      { header: '板件数量', key: 'board_count', width: 10 },
      { header: '起始时间', key: 'start_time', width: 20 },
      { header: '结束时间', key: 'end_time', width: 20 }
    ];
    // 可选数据列（按列设置导出）
    const optionalCols = {
      duration_min: { header: '时长(min)', key: 'duration_min', width: 12 },
      clear_paint_g: { header: '清漆用量(g)', key: 'clear_paint_g', width: 12 },
      color_paint_g: { header: '色漆用量(g)', key: 'color_paint_g', width: 12 },
      pearl_paint_g: { header: '珍珠用量(g)', key: 'pearl_paint_g', width: 12 },
      primer_paint_g: { header: '底漆用量()', key: 'primer_paint_g', width: 12 }
    };
    const exportColsParam = req.query.columns;
    let selectedOptional = Object.keys(optionalCols);
    if (exportColsParam) {
      selectedOptional = exportColsParam.split(',').filter(k => optionalCols[k]);
    }
    ws.columns = [...baseCols, ...selectedOptional.map(k => optionalCols[k])];
    const totalCols = ws.columns.length;
    // 表头行（第1行）
    const headerRow = ws.getRow(1);
    headerRow.font = { bold: true };
    headerRow.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE0E0E0' } };
    headerRow.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    // 数据从第2行开始
    records.forEach(r => {
      ws.addRow({
        ...r,
        record_date: r.record_date ? new Date(r.record_date).toISOString().split('T')[0] : '',
        start_time: r.start_time ? new Date(r.start_time).toLocaleString('zh-CN') : '',
        end_time: r.end_time ? new Date(r.end_time).toLocaleString('zh-CN') : ''
      });
    });

    // ========== Excel 安全加固：工作表保护（禁止修改，允许浏览/选择/复制/打印） ==========
    // 1. 工作表保护
    ws.protection = {
      sheet: true,
      password: EXCEL_PROTECT_PASSWORD,
      objects: true,
      scenarios: true,
      formatCells: false,
      formatColumns: false,
      formatRows: false,
      insertColumns: false,
      insertRows: false,
      insertHyperlinks: false,
      deleteColumns: false,
      deleteRows: false,
      sort: false,
      autoFilter: false,
      pivotTables: false,
      selectLockedCells: true,
      selectUnlockedCells: true
    };
    // 确保所有单元格默认锁定
    ws.eachRow({ includeEmpty: false }, row => {
      row.eachCell({ includeEmpty: false }, cell => {
        cell.protection = { locked: true };
      });
    });

    // 2. 页眉水印（打印时可见）
    const headerStr = `&C&"宋体,Regular"&9&K808080机密・云曲线`;
    ws.headerFooter = {
      oddHeader: headerStr,
      evenHeader: headerStr,
      firstHeader: headerStr,
      differentFirst: false,
      differentOddEven: false
    };

    // 3. 工作表背景图水印
    const wmBuffer = generateWatermarkImage('CURVEROBOT 机密');
    if (wmBuffer) {
      try {
        const imageId = workbook.addImage({ buffer: wmBuffer, extension: 'png' });
        ws.background = imageId;
      } catch(e) {
        console.warn('设置背景图水印失败:', e.message);
      }
    }

    // 4. 工作簿结构保护
    try {
      workbook.security = {
        workbookStructure: true,
        windows: true,
        password: EXCEL_PROTECT_PASSWORD
      };
    } catch(e) { /* 兼容旧版ExcelJS */ }
    const xlsxBuffer = await workbook.xlsx.writeBuffer();
    // 不再加密文件打开密码，仅保留工作表保护防止修改
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(customerName)}_${Date.now()}.xlsx`);
    res.setHeader('Content-Length', xlsxBuffer.length);
    res.end(xlsxBuffer);
  } catch (err) {
    serverError(res, err, '导出失败');
  }
});

// ========== 批量导出 Excel（多客户，每个客户一个工作表，文件加密） ==========
app.post('/api/export/batch', authRequired, async (req, res) => {
  try {
    const { customers, columns } = req.body || {};
    const scope = await getUserAccessScope(req.userId);
    if (!scope.canExport && req.role !== 'admin') {
      return res.status(403).json({ error: '您没有导出数据的权限' });
    }
    if (!customers || !Array.isArray(customers) || customers.length === 0) {
      return res.status(400).json({ error: '请至少选择一个客户' });
    }
    // 权限过滤
    const allowedCustomers = scope.customers
      ? customers.filter(c => scope.customers.includes(c))
      : customers;
    if (allowedCustomers.length === 0) {
      return res.status(403).json({ error: '无权访问所选客户数据' });
    }
    const workbook = new ExcelJS.Workbook();
    // 列定义
    const baseCols = [
      { header: '喷涂时间', key: 'record_date', width: 12 },
      { header: '设备', key: 'device', width: 18 },
      { header: '品牌', key: 'brand', width: 12 },
      { header: '车系', key: 'car_series', width: 14 },
      { header: '车型', key: 'car_model', width: 18 },
      { header: '部件', key: 'parts', width: 30 },
      { header: '板件数量', key: 'board_count', width: 10 },
      { header: '起始时间', key: 'start_time', width: 20 },
      { header: '结束时间', key: 'end_time', width: 20 }
    ];
    const optionalCols = {
      duration_min: { header: '时长(min)', key: 'duration_min', width: 12 },
      clear_paint_g: { header: '清漆用量(g)', key: 'clear_paint_g', width: 12 },
      color_paint_g: { header: '色漆用量(g)', key: 'color_paint_g', width: 12 },
      pearl_paint_g: { header: '珍珠用量(g)', key: 'pearl_paint_g', width: 12 },
      primer_paint_g: { header: '底漆用量()', key: 'primer_paint_g', width: 12 }
    };
    let selectedOptional = Object.keys(optionalCols);
    if (columns && Array.isArray(columns)) {
      selectedOptional = columns.filter(k => optionalCols[k]);
    }
    const allCols = [...baseCols, ...selectedOptional.map(k => optionalCols[k])];
    const headerStr = `&C&"宋体,Regular"&9&K808080机密・云曲线`;
    for (const customerName of allowedCustomers) {
      const records = await getCustomerRecords(customerName, scope);
      const sheetName = customerName.substring(0, 31);
      const ws = workbook.addWorksheet(sheetName);
      ws.columns = allCols;
      const totalCols = ws.columns.length;
      // 表头行（第1行）
      const headerRow = ws.getRow(1);
      headerRow.font = { bold: true };
      headerRow.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE0E0E0' } };
      headerRow.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
      // 数据行
      records.forEach(r => {
        ws.addRow({
          ...r,
          record_date: r.record_date ? new Date(r.record_date).toISOString().split('T')[0] : '',
          start_time: r.start_time ? new Date(r.start_time).toLocaleString('zh-CN') : '',
          end_time: r.end_time ? new Date(r.end_time).toLocaleString('zh-CN') : ''
        });
      });
      // 工作表保护：禁止编辑，允许选择/复制/打印
      ws.protection = {
        sheet: true,
        password: EXCEL_PROTECT_PASSWORD,
        objects: true,
        scenarios: true,
        formatCells: false,
        formatColumns: false,
        formatRows: false,
        insertColumns: false,
        insertRows: false,
        insertHyperlinks: false,
        deleteColumns: false,
        deleteRows: false,
        sort: false,
        autoFilter: false,
        pivotTables: false,
        selectLockedCells: true,
        selectUnlockedCells: true
      };
      ws.eachRow({ includeEmpty: false }, row => {
        row.eachCell({ includeEmpty: false }, cell => {
          cell.protection = { locked: true };
        });
      });
      // 页眉水印
      ws.headerFooter = {
        oddHeader: headerStr,
        evenHeader: headerStr,
        firstHeader: headerStr,
        differentFirst: false,
        differentOddEven: false
      };
    }
    // 工作簿结构保护
    try {
      workbook.security = {
        workbookStructure: true,
        windows: true,
        password: EXCEL_PROTECT_PASSWORD
      };
    } catch(e) { /* 兼容旧版 */ }
    // 生成 buffer（不再加密文件打开密码，仅保留工作表保护）
    const xlsxBuffer = await workbook.xlsx.writeBuffer();
    const filename = `云曲线数据导出_${Date.now()}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
    res.setHeader('Content-Length', xlsxBuffer.length);
    res.end(xlsxBuffer);
  } catch (err) {
    serverError(res, err, '批量导出失败');
  }
});
// ========== 导出记录日志（JSON文件存储，管理员可查看所有用户导出记录） ==========
const EXPORT_LOG_FILE = path.join(__dirname, 'export_logs.json');
function readExportLogs() {
  try {
    if (fs.existsSync(EXPORT_LOG_FILE)) {
      return JSON.parse(fs.readFileSync(EXPORT_LOG_FILE, 'utf-8'));
    }
  } catch(e) { console.warn('读取导出记录失败:', e.message); }
  return [];
}
function writeExportLogs(logs) {
  try { fs.writeFileSync(EXPORT_LOG_FILE, JSON.stringify(logs, null, 2), 'utf-8'); }
  catch(e) { console.warn('写入导出记录失败:', e.message); }
}
app.post('/api/export-log', authRequired, async (req, res) => {
  try {
    const { type, customers } = req.body || {};
    const logs = readExportLogs();
    logs.unshift({
      id: Date.now(),
      user_id: req.userId,
      username: req.username,
      role: req.role,
      type: type || '未知',
      customers: Array.isArray(customers) ? customers : [],
      customer_count: Array.isArray(customers) ? customers.length : 0,
      exported_at: new Date().toISOString()
    });
    // 最多保留500条
    if (logs.length > 500) logs.length = 500;
    writeExportLogs(logs);
    res.json({ success: true });
  } catch (err) {
    serverError(res, err, '记录导出日志失败');
  }
});
app.get('/api/export-log', authRequired, adminRequired, async (req, res) => {
  try {
    const logs = readExportLogs();
    res.json(logs);
  } catch (err) {
    serverError(res, err, '获取导出记录失败');
  }
});

// ========== 用户列配置（关联账号） ==========
app.get('/api/col-config', authRequired, async (req, res) => {
  try {
    const config = await getUserColConfig(req.userId);
    res.json(config || {});
  } catch (err) {
    serverError(res, err, '获取列配置失败');
  }
});
app.put('/api/col-config', authRequired, async (req, res) => {
  try {
    const config = req.body || {};
    await saveUserColConfig(req.userId, config);
    res.json({ success: true });
  } catch (err) {
    serverError(res, err, '保存列配置失败');
  }
});

// 健康检查
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// 页面路由
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/', (req, res) => res.redirect('/login'));

// ========== 全局错误处理中间件（必须在所有路由之后、listen之前） ==========
// 处理 multer 上传错误及其他所有未捕获的路由错误
app.use((err, req, res, next) => {
  console.error('❌ 全局错误捕获:', err.message, err.stack);
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: '文件过大，最大支持 50MB' });
  }
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({ error: '上传字段名错误，请使用 file 字段' });
  }
  if (err.message && err.message.includes('仅支持')) {
    return res.status(400).json({ error: err.message });
  }
  res.status(500).json({ error: '服务器处理请求时出错：' + err.message });
});

app.listen(PORT, () => {
  console.log(`喷涂数据管理平台运行在端口 ${PORT}`);
  console.log(`登录页: http://localhost:${PORT}/login`);
  console.log(`管理后台: http://localhost:${PORT}/admin`);
  console.log(`数据看板: http://localhost:${PORT}/dashboard`);
});
