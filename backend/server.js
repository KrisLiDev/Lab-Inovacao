require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10kb' }));
const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const PERFIS = ['usuario', 'gestor', 'administrador'];

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'smart_automation',
  waitForConnections: true,
  connectionLimit: 10
});

// CORS (permite o site do GitHub Pages chamar a API)
app.use((req, res, next) => {
  const o = req.headers.origin;
  if (o && ORIGINS.includes(o)) {
    res.set({ 'Access-Control-Allow-Origin': o, Vary: 'Origin',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS' });
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------- TOTP (RFC 6238), compatível com Google Authenticator ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function novoSegredo() {
  let bits = '', s = '';
  for (const x of crypto.randomBytes(20)) bits += x.toString(2).padStart(8, '0');
  for (let i = 0; i < 160; i += 5) s += B32[parseInt(bits.slice(i, i + 5), 2)];
  return s;
}
function b32dec(s) {
  let bits = '';
  for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0');
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, t) {
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac('sha1', b32dec(secret)).update(c).digest();
  const o = h[19] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6).padStart(6, '0');
}
const codigoOk = (secret, code) => [-30000, 0, 30000].some(d => totp(secret, Date.now() + d) === code);

// ---------- Sessões no banco ----------
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const tokenDe = req => (req.headers.authorization || '').replace(/^Bearer /, '');
async function criarSessao(idUsuario, minutos, mfaTemp) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query(
    'INSERT INTO sessao (token_hash, id_usuario, expira_em, mfa_ok, mfa_temp) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), 0, ?)',
    [sha(token), idUsuario, minutos, mfaTemp || null]);
  return token;
}
async function sessaoDe(req) {
  const t = tokenDe(req);
  if (!t) return null;
  const [r] = await pool.query(
    `SELECT s.*, u.nome, u.email, u.perfil, u.mfa_secret FROM sessao s
     JOIN usuario u ON u.id_usuario = s.id_usuario WHERE s.token_hash = ? AND s.expira_em > NOW()`, [sha(t)]);
  return r[0] || null;
}
const h = fn => (req, res, next) => fn(req, res, next).catch(e => { console.error(e); res.status(500).json({ erro: 'Erro interno do servidor.' }); });
const auth = (...perfis) => h(async (req, res, next) => {
  const s = await sessaoDe(req);
  if (!s || !s.mfa_ok) return res.status(401).json({ erro: 'Não autenticado.' });
  if (perfis.length && !perfis.includes(s.perfil)) return res.status(403).json({ erro: 'Acesso negado para o seu perfil.' });
  req.s = s; next();
});

// Limite simples de tentativas de login por IP
const tentativas = new Map();
function limite(req, res, next) {
  const k = req.ip, agora = Date.now(), v = tentativas.get(k) || { n: 0, t: agora };
  if (agora - v.t > 15 * 60000) { v.n = 0; v.t = agora; }
  if (++v.n > 20) return res.status(429).json({ erro: 'Muitas tentativas. Aguarde alguns minutos.' });
  tentativas.set(k, v); next();
}

// ---------- Rotas ----------
app.get('/api/saude', (req, res) => res.json({ ok: true }));

app.post('/api/cadastro', limite, h(async (req, res) => {
  const nome = String(req.body.nome || '').trim(), email = String(req.body.email || '').trim().toLowerCase(), senha = String(req.body.senha || '');
  if (!nome || nome.length > 100 || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ erro: 'Informe nome e e-mail válidos.' });
  if (senha.length < 8) return res.status(400).json({ erro: 'A senha precisa ter ao menos 8 caracteres.' });
  const [e] = await pool.query('SELECT 1 FROM usuario WHERE email = ?', [email]);
  if (e.length) return res.status(409).json({ erro: 'E-mail já cadastrado.' });
  await pool.query('INSERT INTO usuario (nome, email, senha_hash, perfil) VALUES (?, ?, ?, ?)', [nome, email, await bcrypt.hash(senha, 10), 'usuario']);
  res.status(201).json({ ok: true });
}));

app.post('/api/login', limite, h(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), senha = String(req.body.senha || '');
  const [r] = await pool.query('SELECT * FROM usuario WHERE email = ?', [email]);
  const u = r[0];
  if (!u || !(await bcrypt.compare(senha, u.senha_hash))) return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
  const setup = !u.mfa_secret, temp = setup ? novoSegredo() : null;
  const token = await criarSessao(u.id_usuario, 5, temp);
  const codigoDemo = process.env.DEMO_MFA === 'true' ? totp(u.mfa_secret || temp, Date.now()) : undefined;
  res.json({ token, setup, secret: temp, codigoDemo,
    otpauth: setup ? `otpauth://totp/SmartAutomation:${encodeURIComponent(u.email)}?secret=${temp}&issuer=SmartAutomation` : null });
}));

app.post('/api/mfa', limite, h(async (req, res) => {
  const s = await sessaoDe(req);
  if (!s || s.mfa_ok) return res.status(401).json({ erro: 'Sessão expirada. Faça login novamente.', reiniciar: true });
  const secret = s.mfa_secret || s.mfa_temp, tent = s.tentativas + 1;
  await pool.query('UPDATE sessao SET tentativas = ? WHERE token_hash = ?', [tent, s.token_hash]);
  const cod = String(req.body.codigo || '').replace(/\D/g, '');
  if (cod.length === 6 && codigoOk(secret, cod)) {
    if (!s.mfa_secret) await pool.query('UPDATE usuario SET mfa_secret = ? WHERE id_usuario = ?', [secret, s.id_usuario]);
    await pool.query('UPDATE sessao SET mfa_ok = 1, mfa_temp = NULL, expira_em = DATE_ADD(NOW(), INTERVAL 30 MINUTE) WHERE token_hash = ?', [s.token_hash]);
    return res.json({ ok: true });
  }
  if (tent >= 3) {
    await pool.query('DELETE FROM sessao WHERE token_hash = ?', [s.token_hash]);
    return res.status(401).json({ erro: 'Muitas tentativas. Faça login novamente.', reiniciar: true });
  }
  res.status(401).json({ erro: `Código inválido. Tentativas restantes: ${3 - tent}.` });
}));

app.get('/api/perfil', auth(), (req, res) => res.json({ nome: req.s.nome, email: req.s.email, perfil: req.s.perfil, id: req.s.id_usuario }));

app.get('/api/resumo', auth('gestor', 'administrador'), h(async (req, res) => {
  const [r] = await pool.query('SELECT perfil, COUNT(*) AS total FROM usuario GROUP BY perfil');
  res.json(Object.fromEntries(r.map(x => [x.perfil, Number(x.total)])));
}));

app.get('/api/usuarios', auth('administrador'), h(async (req, res) => {
  const [r] = await pool.query('SELECT id_usuario AS id, nome, email, perfil, (mfa_secret IS NOT NULL) AS mfa FROM usuario ORDER BY id_usuario');
  res.json(r.map(x => ({ ...x, mfa: !!x.mfa })));
}));

app.patch('/api/usuarios/:id/perfil', auth('administrador'), h(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.s.id_usuario) return res.status(400).json({ erro: 'Você não pode alterar o próprio perfil.' });
  if (!PERFIS.includes(req.body.perfil)) return res.status(400).json({ erro: 'Perfil inválido.' });
  await pool.query('UPDATE usuario SET perfil = ? WHERE id_usuario = ?', [req.body.perfil, id]);
  res.json({ ok: true });
}));

app.post('/api/usuarios/:id/reset-mfa', auth('administrador'), h(async (req, res) => {
  const id = Number(req.params.id);
  await pool.query('UPDATE usuario SET mfa_secret = NULL WHERE id_usuario = ?', [id]);
  if (id !== req.s.id_usuario) await pool.query('DELETE FROM sessao WHERE id_usuario = ?', [id]);
  res.json({ ok: true });
}));

app.delete('/api/usuarios/:id', auth('administrador'), h(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.s.id_usuario) return res.status(400).json({ erro: 'Você não pode excluir a própria conta.' });
  await pool.query('DELETE FROM usuario WHERE id_usuario = ?', [id]);
  res.json({ ok: true });
}));

app.post('/api/logout', h(async (req, res) => {
  const t = tokenDe(req);
  if (t) await pool.query('DELETE FROM sessao WHERE token_hash = ?', [sha(t)]);
  res.json({ ok: true });
}));

// Serve o site (somente estes arquivos) quando rodando tudo no mesmo servidor
const raiz = path.join(__dirname, '..');
app.get(['/', '/index.html'], (q, r) => r.sendFile(path.join(raiz, 'index.html')));
for (const f of ['style.css', 'script.js', 'config.js']) app.get('/' + f, (q, r) => r.sendFile(path.join(raiz, f)));

async function criarDemo() {
  const demos = [['Gestor Demo', 'gestor@smart.com', 'Gestor@123', 'gestor'], ['Admin Demo', 'admin@smart.com', 'Admin@123', 'administrador']];
  for (const [nome, email, senha, perfil] of demos) {
    const [e] = await pool.query('SELECT 1 FROM usuario WHERE email = ?', [email]);
    if (!e.length) await pool.query('INSERT INTO usuario (nome, email, senha_hash, perfil) VALUES (?, ?, ?, ?)', [nome, email, await bcrypt.hash(senha, 10), perfil]);
  }
}

(async () => {
  try {
    await pool.query('SELECT 1');
    if (process.env.SEED_DEMO !== 'false') await criarDemo();
  } catch (e) {
    console.error('Falha ao conectar no MySQL. Confira o arquivo .env e se o schema.sql foi executado.\n', e.message);
    process.exit(1);
  }
  setInterval(() => pool.query('DELETE FROM sessao WHERE expira_em < NOW()').catch(() => {}), 10 * 60000);
  app.listen(process.env.PORT || 3000, () => console.log('Smart Automation rodando na porta ' + (process.env.PORT || 3000)));
})();
