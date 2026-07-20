require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('ОШИБКА: не задана переменная окружения MONGODB_URI. Добавьте её в настройках сервиса (Render → Environment) со строкой подключения из MongoDB Atlas.');
  process.exit(1);
}

let db;
let users, messages, sessions;

async function start() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db('simple_messenger');
  users = db.collection('users');
  messages = db.collection('messages');
  sessions = db.collection('sessions');

  // Индексы для скорости и уникальности имён пользователей.
  await users.createIndex({ username: 1 }, { unique: true });
  await messages.createIndex({ from: 1, to: 1, time: 1 });
  await messages.createIndex({ id: 1 }, { unique: true });
  await sessions.createIndex({ token: 1 }, { unique: true });

  app.listen(PORT, () => {
    console.log(`Мессенджер запущен: http://localhost:${PORT}`);
  });
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}
function makeId() {
  return crypto.randomBytes(8).toString('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Не авторизован. Войдите заново.' });

    const session = await sessions.findOne({ token });
    if (!session) return res.status(401).json({ error: 'Не авторизован. Войдите заново.' });

    req.username = session.username;
    next();
  } catch (e) {
    res.status(500).json({ error: 'Ошибка сервера.' });
  }
}

// --- Регистрация ---
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const uname = (username || '').trim().toLowerCase();

    if (!uname || /\s/.test(uname) || uname.length > 30) {
      return res.status(400).json({ error: 'Некорректное имя пользователя.' });
    }
    if (!password || password.length < 4) {
      return res.status(400).json({ error: 'Пароль должен быть не короче 4 символов.' });
    }

    const existing = await users.findOne({ username: uname });
    if (existing) {
      return res.status(409).json({ error: 'Это имя уже занято.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    await users.insertOne({ username: uname, salt, hash, createdAt: Date.now() });

    const token = makeToken();
    await sessions.insertOne({ token, username: uname, createdAt: Date.now() });
    res.json({ token, username: uname });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера при регистрации.' });
  }
});

// --- Вход ---
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const uname = (username || '').trim().toLowerCase();

    const user = await users.findOne({ username: uname });
    if (!user) {
      return res.status(401).json({ error: 'Пользователь не найден.' });
    }
    const hash = hashPassword(password || '', user.salt);
    if (hash !== user.hash) {
      return res.status(401).json({ error: 'Неверный пароль.' });
    }

    const token = makeToken();
    await sessions.insertOne({ token, username: uname, createdAt: Date.now() });
    res.json({ token, username: uname });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера при входе.' });
  }
});

// --- Проверка токена (для автоматического входа при открытии страницы) ---
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.username });
});

// --- Список всех пользователей (чтобы было видно, кому можно писать) ---
app.get('/api/users', requireAuth, async (req, res) => {
  const list = await users.find({ username: { $ne: req.username } }).project({ username: 1, _id: 0 }).toArray();
  res.json(list.map(u => u.username));
});

// --- Список чатов: с кем уже была переписка, отсортировано по последнему сообщению ---
app.get('/api/conversations', requireAuth, async (req, res) => {
  const all = await messages.find({ $or: [{ from: req.username }, { to: req.username }] }).toArray();
  const byPartner = new Map();

  for (const m of all) {
    const partner = m.from === req.username ? m.to : m.from;
    const existing = byPartner.get(partner);
    if (!existing || m.time > existing.time) {
      byPartner.set(partner, { username: partner, lastText: m.text, time: m.time, lastFromMe: m.from === req.username });
    }
  }

  const list = Array.from(byPartner.values()).sort((a, b) => b.time - a.time);
  res.json(list);
});

// --- Отправка сообщения ---
app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { to, text } = req.body || {};
    const recipient = (to || '').trim().toLowerCase();
    const content = (text || '').trim();

    if (!recipient || !content) {
      return res.status(400).json({ error: 'Нужны получатель и текст сообщения.' });
    }
    const recipientExists = await users.findOne({ username: recipient });
    if (!recipientExists) {
      return res.status(404).json({ error: 'Такого пользователя не существует.' });
    }

    const msg = { id: makeId(), from: req.username, to: recipient, text: content, time: Date.now() };
    await messages.insertOne(msg);
    delete msg._id;
    res.json(msg);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера при отправке сообщения.' });
  }
});

// --- Получение переписки с конкретным пользователем ---
app.get('/api/messages/:withUser', requireAuth, async (req, res) => {
  const other = (req.params.withUser || '').trim().toLowerCase();
  const thread = await messages.find({
    $or: [
      { from: req.username, to: other },
      { from: other, to: req.username }
    ]
  }).sort({ time: 1 }).project({ _id: 0 }).toArray();
  res.json(thread);
});

// --- Удаление одного сообщения (для всех) — может только автор сообщения ---
app.delete('/api/messages/single/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const msg = await messages.findOne({ id });
  if (!msg) {
    return res.status(404).json({ error: 'Сообщение не найдено.' });
  }
  if (msg.from !== req.username) {
    return res.status(403).json({ error: 'Удалить можно только своё сообщение.' });
  }
  await messages.deleteOne({ id });
  res.json({ deleted: id });
});

// --- Удаление всего чата с конкретным пользователем (для всех) ---
app.delete('/api/conversations/:withUser', requireAuth, async (req, res) => {
  const other = (req.params.withUser || '').trim().toLowerCase();
  await messages.deleteMany({
    $or: [
      { from: req.username, to: other },
      { from: other, to: req.username }
    ]
  });
  res.json({ deletedWith: other });
});

start().catch(err => {
  console.error('Не удалось подключиться к базе данных:', err.message);
  process.exit(1);
});
