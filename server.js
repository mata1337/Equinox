const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const path = require('path');
const Datastore = require('nedb-promises');

const app = express();
const PORT = process.env.PORT || 3000;

const db = {
  users:      Datastore.create({ filename: './data/users.db',      autoload: true }),
  invites:    Datastore.create({ filename: './data/invites.db',    autoload: true }),
  threads:    Datastore.create({ filename: './data/threads.db',    autoload: true }),
  posts:      Datastore.create({ filename: './data/posts.db',      autoload: true }),
  categories: Datastore.create({ filename: './data/categories.db', autoload: true }),
  counter:    Datastore.create({ filename: './data/counter.db',    autoload: true }),
  shoutbox:   Datastore.create({ filename: './data/shoutbox.db',   autoload: true }),
  roulette:   Datastore.create({ filename: './data/roulette.db',   autoload: true }),
};

// Categories where only admins/owner can post threads (but all can read)
const ADMIN_ONLY_CATS = ['cat1', 'cat2', 'cat3', 'cat4'];
// Categories where everyone can post
const OPEN_CATS = ['cat5'];

async function getNextUID() {
  let c = await db.counter.findOne({ _id: 'uid' });
  if (!c) { await db.counter.insert({ _id: 'uid', value: 0 }); c = { value: 0 }; }
  const next = c.value + 1;
  await db.counter.update({ _id: 'uid' }, { $set: { value: next } });
  return next;
}

async function seed() {
  const cats = await db.categories.find({});
  if (!cats.length) {
    await db.categories.insert([
      { _id: 'cat1', name: 'Announcements',  desc: 'Official news & updates from staff', icon: 'ti-speakerphone', color: '#e8702a', adminOnly: true,  order: 1 },
      { _id: 'cat2', name: 'Our Products',   desc: 'Feature overviews, showcases & releases', icon: 'ti-package', color: '#6c8ef5', adminOnly: true,  order: 2 },
      { _id: 'cat3', name: 'News & Updates', desc: 'CS2 news, patch notes, game updates', icon: 'ti-news',    color: '#34d399', adminOnly: true,  order: 3 },
      { _id: 'cat4', name: 'Support',        desc: 'Get help, report bugs, read FAQs',   icon: 'ti-help-circle', color: '#a78bfa', adminOnly: false, order: 4 },
      { _id: 'cat5', name: 'Off-Topic',      desc: 'General chat — anything goes',       icon: 'ti-messages', color: '#5a6475', adminOnly: false, order: 5 },
    ]);
  }
  const owner = await db.users.findOne({ role: 'owner' });
  if (!owner) {
    const hash = await bcrypt.hash('Mata12', 10);
    const uid = await getNextUID(); // uid = 1
    await db.users.insert({
      uid, username: 'Admin', email: 'owner@equinox.gg',
      password: hash, role: 'owner',
      createdAt: Date.now(), posts: 0, invitesLeft: 999,
    });
    await db.invites.insert({ code: 'EQUINOX-BETA', createdBy: uid, used: false, createdAt: Date.now() });
    console.log('Owner: username=Admin password=Mata12  |  Invite: EQUINOX-BETA');
  }
}
seed();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname)));
app.use(session({
  secret: 'equinox-v2-secret-xk92',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const auth = (req, res, next) => req.session.uid ? next() : res.status(401).json({ error: 'Not logged in' });
const adminAuth = (req, res, next) => ['owner','admin'].includes(req.session.role) ? next() : res.status(403).json({ error: 'Forbidden' });
const ownerAuth = (req, res, next) => req.session.role === 'owner' ? next() : res.status(403).json({ error: 'Owner only' });

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password, inviteCode } = req.body;
  if (!username || !email || !password || !inviteCode) return res.json({ error: 'All fields required' });
  if (username.length < 3 || username.length > 20) return res.json({ error: 'Username: 3–20 characters' });
  if (password.length < 6) return res.json({ error: 'Password: min. 6 characters' });
  if (!/^[a-zA-Z0-9_\-]+$/.test(username)) return res.json({ error: 'Username: letters, numbers, _ and - only' });

  const invite = await db.invites.findOne({ code: inviteCode.toUpperCase(), used: false });
  if (!invite) return res.json({ error: 'Invalid or already used invite code' });

  const exists = await db.users.findOne({ $or: [
    { username: { $regex: new RegExp('^'+username+'$','i') } }, { email }
  ]});
  if (exists) return res.json({ error: 'Username or email already taken' });

  const hash = await bcrypt.hash(password, 10);
  const uid = await getNextUID();
  await db.users.insert({ uid, username, email, password: hash, role: 'member', createdAt: Date.now(), posts: 0, invitesLeft: 0 });
  await db.invites.update({ code: inviteCode.toUpperCase() }, { $set: { used: true, usedBy: uid, usedAt: Date.now() } });
  res.json({ ok: true });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.users.findOne({ username: { $regex: new RegExp('^'+username+'$','i') } });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.json({ error: 'Invalid credentials' });
  req.session.uid = user.uid; req.session.username = user.username; req.session.role = user.role;
  res.json({ ok: true, uid: user.uid, username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', async (req, res) => {
  if (!req.session.uid) return res.json({ loggedIn: false });
  const user = await db.users.findOne({ uid: req.session.uid });
  if (!user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, uid: user.uid, username: user.username, role: user.role, invitesLeft: user.invitesLeft });
});

// ── SHOUTBOX ──────────────────────────────────────────────────────────────────
app.get('/api/shoutbox', async (req, res) => {
  const msgs = await db.shoutbox.find({}).sort({ createdAt: -1 }).limit(30);
  res.json(msgs.reverse());
});

app.post('/api/shoutbox', auth, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim().length < 1 || content.trim().length > 300)
    return res.json({ error: 'Message 1–300 chars' });
  const msg = {
    _id: uuidv4(), content: content.trim(),
    authorUid: req.session.uid, authorName: req.session.username, authorRole: req.session.role,
    createdAt: Date.now()
  };
  await db.shoutbox.insert(msg);
  // Keep only last 100
  const all = await db.shoutbox.find({}).sort({ createdAt: 1 });
  if (all.length > 100) {
    const toDelete = all.slice(0, all.length - 100);
    for (const m of toDelete) await db.shoutbox.remove({ _id: m._id });
  }
  res.json({ ok: true, msg });
});

app.delete('/api/shoutbox/:id', adminAuth, async (req, res) => {
  await db.shoutbox.remove({ _id: req.params.id });
  res.json({ ok: true });
});

// ── ROULETTE ──────────────────────────────────────────────────────────────────
app.post('/api/roulette/spin', auth, async (req, res) => {
  const existing = await db.roulette.findOne({ uid: req.session.uid, date: new Date().toDateString() });
  if (existing) return res.json({ error: 'Already spun today', wonInvite: existing.wonInvite, inviteCode: existing.inviteCode });
  const wonInvite = Math.random() < 0.05;
  let inviteCode = null;
  if (wonInvite) {
    inviteCode = 'EQX-' + Math.random().toString(36).slice(2,6).toUpperCase() + '-' + Math.random().toString(36).slice(2,6).toUpperCase();
    await db.invites.insert({ code: inviteCode, createdBy: 'roulette', used: false, createdAt: Date.now() });
  }
  await db.roulette.insert({ uid: req.session.uid, date: new Date().toDateString(), wonInvite, inviteCode, createdAt: Date.now() });
  res.json({ ok: true, wonInvite, inviteCode });
});

app.get('/api/roulette/status', auth, async (req, res) => {
  const e = await db.roulette.findOne({ uid: req.session.uid, date: new Date().toDateString() });
  res.json({ played: !!e, wonInvite: e?.wonInvite, inviteCode: e?.inviteCode });
});

// ── INVITES ───────────────────────────────────────────────────────────────────
app.post('/api/invites/create', adminAuth, async (req, res) => {
  const code = 'EQX-' + Math.random().toString(36).slice(2,6).toUpperCase() + '-' + Math.random().toString(36).slice(2,6).toUpperCase();
  await db.invites.insert({ code, createdBy: req.session.uid, used: false, createdAt: Date.now() });
  res.json({ ok: true, code });
});

app.get('/api/invites/mine', adminAuth, async (req, res) => {
  const invites = await db.invites.find({ createdBy: req.session.uid }).sort({ createdAt: -1 });
  res.json({ invites });
});

app.get('/api/invites/all', adminAuth, async (req, res) => {
  const invites = await db.invites.find({}).sort({ createdAt: -1 }).limit(50);
  res.json({ invites });
});

// ── CATEGORIES ────────────────────────────────────────────────────────────────
app.get('/api/categories', async (req, res) => {
  const cats = await db.categories.find({}).sort({ order: 1 });
  const result = await Promise.all(cats.map(async c => {
    const threadCount = await db.threads.count({ categoryId: c._id });
    const postCount   = await db.posts.count({ categoryId: c._id });
    const last = await db.threads.find({ categoryId: c._id }).sort({ lastPostAt: -1 }).limit(1);
    return { ...c, threadCount, postCount, lastThread: last[0] || null };
  }));
  res.json(result);
});

// ── THREADS ───────────────────────────────────────────────────────────────────
app.get('/api/threads/:catId', async (req, res) => {
  const threads = await db.threads.find({ categoryId: req.params.catId }).sort({ pinned: -1, lastPostAt: -1 });
  res.json(threads);
});

app.post('/api/threads', auth, async (req, res) => {
  const { categoryId, title, content } = req.body;
  if (!title || !content || title.trim().length < 3) return res.json({ error: 'Title and content required' });
  const cat = await db.categories.findOne({ _id: categoryId });
  if (!cat) return res.json({ error: 'Category not found' });
  // Check permissions
  if (cat.adminOnly && !['owner','admin'].includes(req.session.role))
    return res.json({ error: 'Only staff can post in this category' });
  const id = uuidv4(), now = Date.now();
  await db.threads.insert({
    _id: id, categoryId, title: title.trim(), content: content.trim(),
    authorUid: req.session.uid, authorName: req.session.username, authorRole: req.session.role,
    createdAt: now, lastPostAt: now, lastPostBy: req.session.username, replyCount: 0, views: 0, pinned: false
  });
  await db.users.update({ uid: req.session.uid }, { $inc: { posts: 1 } });
  res.json({ ok: true, id, categoryId });
});

app.get('/api/thread/:id', async (req, res) => {
  const thread = await db.threads.findOne({ _id: req.params.id });
  if (!thread) return res.status(404).json({ error: 'Not found' });
  await db.threads.update({ _id: req.params.id }, { $inc: { views: 1 } });
  const posts = await db.posts.find({ threadId: req.params.id }).sort({ createdAt: 1 });
  const cat   = await db.categories.findOne({ _id: thread.categoryId });
  res.json({ thread, posts, category: cat });
});

app.post('/api/thread/:id/reply', auth, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim().length < 2) return res.json({ error: 'Too short' });
  const thread = await db.threads.findOne({ _id: req.params.id });
  if (!thread) return res.json({ error: 'Thread not found' });
  const cat = await db.categories.findOne({ _id: thread.categoryId });
  if (cat?.adminOnly && !['owner','admin'].includes(req.session.role))
    return res.json({ error: 'Only staff can reply in this category' });
  const now = Date.now();
  await db.posts.insert({
    threadId: req.params.id, categoryId: thread.categoryId, content: content.trim(),
    authorUid: req.session.uid, authorName: req.session.username, authorRole: req.session.role,
    createdAt: now
  });
  await db.threads.update({ _id: req.params.id }, { $inc: { replyCount: 1 }, $set: { lastPostAt: now, lastPostBy: req.session.username } });
  await db.users.update({ uid: req.session.uid }, { $inc: { posts: 1 } });
  res.json({ ok: true });
});

app.delete('/api/thread/:id', adminAuth, async (req, res) => {
  await db.threads.remove({ _id: req.params.id });
  await db.posts.remove({ threadId: req.params.id }, { multi: true });
  res.json({ ok: true });
});

app.post('/api/thread/:id/pin', adminAuth, async (req, res) => {
  const t = await db.threads.findOne({ _id: req.params.id });
  if (!t) return res.json({ error: 'Not found' });
  await db.threads.update({ _id: req.params.id }, { $set: { pinned: !t.pinned } });
  res.json({ ok: true, pinned: !t.pinned });
});

// ── STATS ─────────────────────────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  const [users, threads, posts] = await Promise.all([db.users.count({}), db.threads.count({}), db.posts.count({})]);
  const latest = await db.users.find({}).sort({ createdAt: -1 }).limit(1);
  const onlineUsers = await db.users.find({}).sort({ uid: 1 }).limit(20); // simplified
  res.json({ users, threads, posts, latestMember: latest[0]?.username });
});

// ── ADMIN ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await db.users.find({}).sort({ uid: 1 });
  res.json(users.map(u => ({ uid: u.uid, username: u.username, role: u.role, email: u.email, posts: u.posts, createdAt: u.createdAt })));
});

app.post('/api/admin/setrole', adminAuth, async (req, res) => {
  const { targetUid, role } = req.body;
  if (!['member','media_partner','admin','owner'].includes(role)) return res.json({ error: 'Invalid role' });
  if (['owner','admin'].includes(role) && req.session.role !== 'owner') return res.json({ error: 'Owner only' });
  const target = await db.users.findOne({ uid: parseInt(targetUid) });
  if (!target) return res.json({ error: 'User not found' });
  if (target.role === 'owner' && req.session.role !== 'owner') return res.json({ error: 'Cannot modify owner' });
  await db.users.update({ uid: parseInt(targetUid) }, { $set: { role } });
  res.json({ ok: true });
});

app.delete('/api/admin/user/:uid', ownerAuth, async (req, res) => {
  const uid = parseInt(req.params.uid);
  const t = await db.users.findOne({ uid });
  if (!t) return res.json({ error: 'Not found' });
  if (t.role === 'owner') return res.json({ error: 'Cannot delete owner' });
  await db.users.remove({ uid });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Equinox v2 on port ${PORT}`));
