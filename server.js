const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, '[]');

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

// In-memory sessions: token -> username. Lost on server restart (re-login needed).
const sessions = new Map();

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

  const token = makeToken();
  sessions.set(token, uname);
  res.json({ token, username: uname });
});

// --- Вход ---
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

  const token = makeToken();
  sessions.set(token, uname);
  res.json({ token, username: uname });
});

// --- Список пользователей (чтобы было видно, кому можно писать) ---
app.get('/api/users', requireAuth, (req, res) => {
  const users = readJson(USERS_FILE);
  res.json(users.map(u => u.username).filter(u => u !== req.username));
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
