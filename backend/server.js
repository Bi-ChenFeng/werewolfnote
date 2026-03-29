const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const pool = require('./db');
const app = express();

app.use(cors());
app.use(express.json());

// ── 中间件：验证 JWT ────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token 无效' });
  }
}

// ── 注册 ────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (rows.length > 0) return res.status(400).json({ error: '用户名已存在' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
    res.json({ message: '注册成功' });
  } catch (e) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// ── 登录 ────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(401).json({ error: '用户名或密码错误' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: '用户名或密码错误' });
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: user.username });
  } catch (e) {
    res.status(500).json({ error: '服务器错误' });
  }
});

// ── 保存对局 ────────────────────────────────────────────────────────────────
app.post('/api/games', auth, async (req, res) => {
  const { title, board_type, data } = req.body;
  try {
    const [result] = await pool.query(
      'INSERT INTO games (user_id, title, board_type, data) VALUES (?, ?, ?, ?)',
      [req.user.id, title || '未命名对局', board_type || '', JSON.stringify(data)]
    );
    res.json({ id: result.insertId, message: '保存成功' });
  } catch (e) {
    res.status(500).json({ error: '保存失败' });
  }
});

// ── 获取历史记录列表 ────────────────────────────────────────────────────────
app.get('/api/games', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, title, board_type, created_at, JSON_UNQUOTE(JSON_EXTRACT(data, "$.gameResult")) as game_result FROM games WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: '获取失败' });
  }
});

// ── 获取某局详情 ────────────────────────────────────────────────────────────
app.get('/api/games/:id', auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM games WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: '未找到' });
    const game = rows[0];
    game.data = JSON.parse(game.data);
    res.json(game);
  } catch (e) {
    res.status(500).json({ error: '获取失败' });
  }
});

// ── 删除对局 ────────────────────────────────────────────────────────────────
app.delete('/api/games/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM games WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ message: '删除成功' });
  } catch (e) {
    res.status(500).json({ error: '删除失败' });
  }
});

// ── 修改密码 ────────────────────────────────────────────────────────────────
app.post('/api/change-password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const user = rows[0];
    const ok = await bcrypt.compare(oldPassword, user.password_hash);
    if (!ok) return res.status(401).json({ error: '当前密码错误' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
    res.json({ message: '修改成功' });
  } catch { res.status(500).json({ error: '服务器错误' }); }
});

// ── 管理员接口 ───────────────────────────────────────────────────────────────
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin_werewolf_2024';

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (secret !== ADMIN_SECRET) return res.status(403).json({ error: '无权限' });
  next();
}

app.post('/api/admin/login', (req, res) => {
  const { secret } = req.body;
  if (secret === ADMIN_SECRET) res.json({ ok: true });
  else res.status(403).json({ error: '密码错误' });
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const [rows] = await pool.query('SELECT id, username, created_at, (SELECT COUNT(*) FROM games WHERE user_id = users.id) as game_count FROM users ORDER BY created_at DESC');
  res.json(rows);
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ message: '已删除' });
});

app.get('/api/admin/games', adminAuth, async (req, res) => {
  const [rows] = await pool.query('SELECT g.id, g.title, g.board_type, g.created_at, u.username FROM games g JOIN users u ON g.user_id = u.id ORDER BY g.created_at DESC');
  res.json(rows);
});

app.delete('/api/admin/games/:id', adminAuth, async (req, res) => {
  await pool.query('DELETE FROM games WHERE id = ?', [req.params.id]);
  res.json({ message: '已删除' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`服务器运行在 http://localhost:${PORT}`));
