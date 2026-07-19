const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, '[]');
if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, '{}');

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return [];
  }
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

// Сессии сохраняются в файле, поэтому вход не сбрасывается при перезапуске сервера.
function readSessionsFile() {
  try {
    const raw = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  } catch (e) {
    return {};
  }
}
let sessions = new Map(Object.entries(readSessionsFile()));

function saveSessions() {
  const obj = Object.fromEntries(sessions);
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(obj, null, 2));
}

function createSession(username) {
  const token = makeToken();
  sessions.set(token, username);
  saveSessions();
  return token;
}

function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const username = token && sessions.get(token);
  if (!username) {
    return res.status(401).json({ error: 'Не авторизован. Войдите заново.' });
  }
  req.username = username;
  next();
}

// --- Регистрация ---
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  const uname = (username || '').trim().toLowerCase();

  if (!uname || /\s/.test(uname) || uname.length > 30) {
    return res.status(400).json({ error: 'Некорректное имя пользователя.' });
  }
  if (!password || password.length < 4) {
    return res.status(400).json({ error: 'Пароль должен быть не короче 4 символов.' });
  }

  const users = readJson(USERS_FILE);
  if (users.find(u => u.username === uname)) {
    return res.status(409).json({ error: 'Это имя уже занято.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  users.push({ username: uname, salt, hash, createdAt: Date.now() });
  writeJson(USERS_FILE, users);

  const token = createSession(uname);
  res.json({ token, username: uname });
});
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const uname = (username || '').trim().toLowerCase();

  const users = readJson(USERS_FILE);
  const user = users.find(u => u.username === uname);
  if (!user) {
    return res.status(401).json({ error: 'Пользователь не найден.' });
  }
  const hash = hashPassword(password || '', user.salt);
  if (hash !== user.hash) {
    return res.status(401).json({ error: 'Неверный пароль.' });
  }

  const token = createSession(uname);
  res.json({ token, username: uname });
});

// --- Проверка токена (для автоматического входа при открытии страницы) ---
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.username });
});

// --- Список всех пользователей (чтобы было видно, кому можно писать) ---
app.get('/api/users', requireAuth, (req, res) => {
  const users = readJson(USERS_FILE);
  res.json(users.map(u => u.username).filter(u => u !== req.username));
});

// --- Список чатов: с кем уже была переписка, отсортировано по последнему сообщению ---
app.get('/api/conversations', requireAuth, (req, res) => {
  const messages = readJson(MESSAGES_FILE);
  const byPartner = new Map();

  for (const m of messages) {
    let partner = null;
    if (m.from === req.username) partner = m.to;
    else if (m.to === req.username) partner = m.from;
    else continue;

    const existing = byPartner.get(partner);
    if (!existing || m.time > existing.time) {
      byPartner.set(partner, { username: partner, lastText: m.text, time: m.time, lastFromMe: m.from === req.username });
    }
  }

  const list = Array.from(byPartner.values()).sort((a, b) => b.time - a.time);
  res.json(list);
});

// --- Отправка сообщения ---
app.post('/api/messages', requireAuth, (req, res) => {
  const { to, text } = req.body || {};
  const recipient = (to || '').trim().toLowerCase();
  const content = (text || '').trim();

  if (!recipient || !content) {
    return res.status(400).json({ error: 'Нужны получатель и текст сообщения.' });
  }
  const users = readJson(USERS_FILE);
  if (!users.find(u => u.username === recipient)) {
    return res.status(404).json({ error: 'Такого пользователя не существует.' });
  }

  const messages = readJson(MESSAGES_FILE);
  const msg = { from: req.username, to: recipient, text: content, time: Date.now() };
  messages.push(msg);
  writeJson(MESSAGES_FILE, messages);
  res.json(msg);
});

// --- Получение переписки с конкретным пользователем ---
app.get('/api/messages/:withUser', requireAuth, (req, res) => {
  const other = (req.params.withUser || '').trim().toLowerCase();
  const messages = readJson(MESSAGES_FILE);
  const thread = messages.filter(m =>
    (m.from === req.username && m.to === other) ||
    (m.from === other && m.to === req.username)
  );
  res.json(thread);
});

app.listen(PORT, () => {
  console.log(`Мессенджер запущен: http://localhost:${PORT}`);
});
