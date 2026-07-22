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

const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();

let db;
let users, messages, sessions, contacts, bugreports;

async function start() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db('simple_messenger');
  users = db.collection('users');
  messages = db.collection('messages');
  sessions = db.collection('sessions');
  contacts = db.collection('contacts');
  bugreports = db.collection('bugreports');

  // Индексы для скорости и уникальности имён пользователей.
  await users.createIndex({ username: 1 }, { unique: true });
  await messages.createIndex({ from: 1, to: 1, time: 1 });
  await messages.createIndex({ id: 1 }, { unique: true });
  await sessions.createIndex({ token: 1 }, { unique: true });
  await contacts.createIndex({ owner: 1, contact: 1 }, { unique: true });
  await bugreports.createIndex({ time: -1 });

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

// Лимиты для медиафайлов в сообщениях (в символах base64-строки, это чуть больше исходного размера файла).
const MAX_IMAGE_B64 = 3_500_000;   // ~2.5 МБ картинки после сжатия на клиенте
const MAX_VIDEO_B64 = 11_000_000;  // ~8 МБ видео

app.use(express.json({ limit: '15mb' }));
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
app.get('/api/me', requireAuth, async (req, res) => {
  const user = await users.findOne({ username: req.username }, { projection: { nickname: 1, avatar: 1, lastSeen: 1, _id: 0 } });
  res.json({
    username: req.username,
    nickname: (user && user.nickname) || null,
    avatar: (user && user.avatar) || null,
    lastSeen: (user && user.lastSeen) || null,
    isAdmin: !!ADMIN_USERNAME && req.username === ADMIN_USERNAME
  });
});

// --- "Пульс": обновляет отметку "был(а) в сети только что" ---
app.post('/api/heartbeat', requireAuth, async (req, res) => {
  const now = Date.now();
  await users.updateOne({ username: req.username }, { $set: { lastSeen: now } });
  res.json({ lastSeen: now });
});

// --- Смена логина (имени для входа) — требует подтверждения паролем ---
app.patch('/api/account/username', requireAuth, async (req, res) => {
  try {
    const { newUsername, password } = req.body || {};
    const clean = (newUsername || '').trim().toLowerCase();

    if (!clean || /\s/.test(clean) || clean.length > 30) {
      return res.status(400).json({ error: 'Некорректный логин.' });
    }
    if (!password) {
      return res.status(400).json({ error: 'Введите текущий пароль для подтверждения.' });
    }

    const user = await users.findOne({ username: req.username });
    if (!user) return res.status(404).json({ error: 'Пользователь не найден.' });

    const hash = hashPassword(password, user.salt);
    if (hash !== user.hash) {
      return res.status(401).json({ error: 'Неверный пароль.' });
    }

    if (clean === req.username) {
      return res.json({ username: clean });
    }

    const taken = await users.findOne({ username: clean });
    if (taken) {
      return res.status(409).json({ error: 'Этот логин уже занят.' });
    }

    const oldUsername = req.username;
    await users.updateOne({ username: oldUsername }, { $set: { username: clean } });
    await messages.updateMany({ from: oldUsername }, { $set: { from: clean } });
    await messages.updateMany({ to: oldUsername }, { $set: { to: clean } });
    await sessions.updateMany({ username: oldUsername }, { $set: { username: clean } });
    await contacts.updateMany({ owner: oldUsername }, { $set: { owner: clean } });
    await contacts.updateMany({ contact: oldUsername }, { $set: { contact: clean } });

    res.json({ username: clean });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера при смене логина.' });
  }
});

// --- Смена своего ника и/или аватарки (отображаемое имя) ---
app.patch('/api/profile', requireAuth, async (req, res) => {
  const { nickname, avatar } = req.body || {};
  const update = {};

  if (nickname !== undefined) {
    const nick = (nickname || '').trim();
    if (nick.length > 40) {
      return res.status(400).json({ error: 'Ник слишком длинный.' });
    }
    update.nickname = nick || null;
  }

  if (avatar !== undefined) {
    if (avatar === null || avatar === '') {
      update.avatar = null;
    } else {
      if (typeof avatar !== 'string' || !avatar.startsWith('data:image/')) {
        return res.status(400).json({ error: 'Аватарка должна быть картинкой.' });
      }
      if (avatar.length > 600000) {
        return res.status(400).json({ error: 'Картинка слишком большая. Попробуйте другую или уменьшите её.' });
      }
      update.avatar = avatar;
    }
  }

  await users.updateOne({ username: req.username }, { $set: update });
  const user = await users.findOne({ username: req.username }, { projection: { nickname: 1, avatar: 1, _id: 0 } });
  res.json({ username: req.username, nickname: (user && user.nickname) || null, avatar: (user && user.avatar) || null });
});

// --- Публичная информация о другом пользователе (ник, аватарка, был(а) в сети) ---
app.get('/api/profile/:username', requireAuth, async (req, res) => {
  const uname = (req.params.username || '').trim().toLowerCase();
  const user = await users.findOne({ username: uname }, { projection: { username: 1, nickname: 1, avatar: 1, lastSeen: 1, _id: 0 } });
  if (!user) return res.status(404).json({ error: 'Пользователь не найден.' });
  res.json(user);
});

// --- Моя личная подпись (алиас) для конкретного собеседника: чтение ---
app.get('/api/contacts/:contact', requireAuth, async (req, res) => {
  const contact = (req.params.contact || '').trim().toLowerCase();
  const doc = await contacts.findOne({ owner: req.username, contact });
  res.json({ contact, alias: (doc && doc.alias) || null });
});

// --- Моя личная подпись (алиас) для конкретного собеседника: запись ---
app.patch('/api/contacts/:contact', requireAuth, async (req, res) => {
  const contact = (req.params.contact || '').trim().toLowerCase();
  const { alias } = req.body || {};
  const clean = (alias || '').trim();

  const contactExists = await users.findOne({ username: contact });
  if (!contactExists) {
    return res.status(404).json({ error: 'Пользователь не найден.' });
  }

  if (!clean) {
    await contacts.deleteOne({ owner: req.username, contact });
    return res.json({ contact, alias: null });
  }
  if (clean.length > 40) {
    return res.status(400).json({ error: 'Подпись слишком длинная.' });
  }
  await contacts.updateOne(
    { owner: req.username, contact },
    { $set: { alias: clean } },
    { upsert: true }
  );
  res.json({ contact, alias: clean });
});

// --- Поиск пользователей по видимому имени (нику), с запасным вариантом по логину ---
app.get('/api/users/search', requireAuth, async (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.json([]);

  const all = await users.find({ username: { $ne: req.username } })
    .project({ username: 1, nickname: 1, avatar: 1, _id: 0 })
    .toArray();

  const results = all.filter(u => {
    const nick = (u.nickname || '').toLowerCase();
    const uname = u.username.toLowerCase();
    return nick.includes(q) || uname.includes(q);
  }).slice(0, 25);

  res.json(results);
});

// --- Список чатов: с кем уже была переписка, отсортировано по последнему сообщению ---
app.get('/api/conversations', requireAuth, async (req, res) => {
  const all = await messages.find({ $or: [{ from: req.username }, { to: req.username }] }).toArray();
  const byPartner = new Map();

  for (const m of all) {
    const partner = m.from === req.username ? m.to : m.from;
    const existing = byPartner.get(partner);
    if (!existing || m.time > existing.time) {
      let preview = m.text;
      if (!preview && m.mediaType === 'image') preview = '📷 Фото';
      if (!preview && m.mediaType === 'video') preview = '🎥 Видео';
      byPartner.set(partner, { username: partner, lastText: preview, time: m.time, lastFromMe: m.from === req.username });
    }
  }

  const partners = Array.from(byPartner.keys());
  const [partnerUsers, myContacts] = await Promise.all([
    users.find({ username: { $in: partners } }).project({ username: 1, nickname: 1, avatar: 1, lastSeen: 1, _id: 0 }).toArray(),
    contacts.find({ owner: req.username, contact: { $in: partners } }).project({ contact: 1, alias: 1, _id: 0 }).toArray()
  ]);
  const nicknameByUser = new Map(partnerUsers.map(u => [u.username, u.nickname || null]));
  const avatarByUser = new Map(partnerUsers.map(u => [u.username, u.avatar || null]));
  const lastSeenByUser = new Map(partnerUsers.map(u => [u.username, u.lastSeen || null]));
  const aliasByUser = new Map(myContacts.map(c => [c.contact, c.alias || null]));

  const list = Array.from(byPartner.values()).map(c => ({
    ...c,
    nickname: nicknameByUser.get(c.username) || null,
    avatar: avatarByUser.get(c.username) || null,
    lastSeen: lastSeenByUser.get(c.username) || null,
    alias: aliasByUser.get(c.username) || null
  })).sort((a, b) => b.time - a.time);

  res.json(list);
});

// --- Отправка сообщения (текст и/или фото/видео) ---
app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { to, text, mediaType, mediaData } = req.body || {};
    const recipient = (to || '').trim().toLowerCase();
    const content = (text || '').trim();

    if (!recipient) {
      return res.status(400).json({ error: 'Нужен получатель.' });
    }

    const hasMedia = !!mediaData;
    if (!content && !hasMedia) {
      return res.status(400).json({ error: 'Нужен текст или файл.' });
    }

    let cleanMediaType = null;
    if (hasMedia) {
      if (mediaType !== 'image' && mediaType !== 'video') {
        return res.status(400).json({ error: 'Неподдерживаемый тип файла.' });
      }
      if (typeof mediaData !== 'string' || !mediaData.startsWith(`data:${mediaType}/`)) {
        return res.status(400).json({ error: 'Файл повреждён или не того типа.' });
      }
      const limit = mediaType === 'image' ? MAX_IMAGE_B64 : MAX_VIDEO_B64;
      if (mediaData.length > limit) {
        return res.status(400).json({ error: mediaType === 'image' ? 'Картинка слишком большая.' : 'Видео слишком большое (максимум примерно 8 МБ).' });
      }
      cleanMediaType = mediaType;
    }

    const recipientExists = await users.findOne({ username: recipient });
    if (!recipientExists) {
      return res.status(404).json({ error: 'Такого пользователя не существует.' });
    }

    const msg = { id: makeId(), from: req.username, to: recipient, text: content, time: Date.now() };
    if (hasMedia) { msg.mediaType = cleanMediaType; msg.mediaData = mediaData; }
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

// --- Реакции на сообщение (эмодзи) — доступно и автору, и получателю ---
const ALLOWED_REACTIONS = ['❤️', '👍', '😂', '😮', '😢', '🙏'];
app.post('/api/messages/:id/reaction', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { emoji } = req.body || {};

    if (emoji !== null && !ALLOWED_REACTIONS.includes(emoji)) {
      return res.status(400).json({ error: 'Недопустимая реакция.' });
    }

    const msg = await messages.findOne({ id });
    if (!msg) {
      return res.status(404).json({ error: 'Сообщение не найдено.' });
    }
    if (msg.from !== req.username && msg.to !== req.username) {
      return res.status(403).json({ error: 'Нет доступа к этому сообщению.' });
    }

    const existing = Array.isArray(msg.reactions) ? msg.reactions : [];
    const prev = existing.find(r => r.user === req.username);
    const reactions = existing.filter(r => r.user !== req.username);
    // Повторный клик по той же реакции — снимает её; иначе ставит/заменяет.
    if (!prev || prev.emoji !== emoji) {
      reactions.push({ user: req.username, emoji });
    }

    await messages.updateOne({ id }, { $set: { reactions } });
    res.json({ id, reactions });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера при установке реакции.' });
  }
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

// --- Отправка баг-репорта ---
app.post('/api/bugreports', requireAuth, async (req, res) => {
  const { text } = req.body || {};
  const clean = (text || '').trim();
  if (!clean) {
    return res.status(400).json({ error: 'Опишите проблему перед отправкой.' });
  }
  if (clean.length > 3000) {
    return res.status(400).json({ error: 'Слишком длинное описание (максимум 3000 символов).' });
  }
  const report = {
    id: makeId(),
    from: req.username,
    text: clean,
    time: Date.now(),
    userAgent: (req.body && req.body.userAgent) ? String(req.body.userAgent).slice(0, 300) : null
  };
  await bugreports.insertOne(report);
  res.json({ ok: true });
});

// --- Просмотр баг-репортов (только для админа) ---
app.get('/api/admin/bugreports', requireAuth, async (req, res) => {
  if (!ADMIN_USERNAME || req.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: 'Доступ только для администратора.' });
  }
  const list = await bugreports.find({}).sort({ time: -1 }).project({ _id: 0 }).toArray();
  res.json(list);
});

// --- Удаление баг-репорта (только для админа) ---
app.delete('/api/admin/bugreports/:id', requireAuth, async (req, res) => {
  if (!ADMIN_USERNAME || req.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: 'Доступ только для администратора.' });
  }
  await bugreports.deleteOne({ id: req.params.id });
  res.json({ deleted: req.params.id });
});

start().catch(err => {
  console.error('Не удалось подключиться к базе данных:', err.message);
  process.exit(1);
});
