const bcrypt = require('bcryptjs');
const { db } = require('./firebase');
const USERS = db.collection('users');
const LOGS = db.collection('logs'); 

async function signUp(email, password) {
  const existing = await USERS.where('email', '==', email).get();
  if (!existing.empty) throw new Error('Email already in use');

  const hash = await bcrypt.hash(password, 10);

  const ref = await USERS.add({
    email,
    passwordHash: hash,
    createdAt: new Date(),
  });

  await LOGS.add({
    type: 'signup',
    userId: ref.id,
    email,
    timestamp: new Date(),
  });

  return { id: ref.id, email };
}

async function login(email, password) {
  const snapshot = await USERS.where('email', '==', email).limit(1).get();
  if (snapshot.empty) throw new Error('Invalid email or password');

  const doc = snapshot.docs[0];
  const data = doc.data();
  const ok = await bcrypt.compare(password, data.passwordHash);
  if (!ok) throw new Error('Invalid email or password');

  return { id: doc.id, email: data.email };
}

function requireAuth(req, res, next) {
  if (req.user) return next();
  return res.redirect('/login');
}

function setSession(res, user) {
  res.cookie('uid', user.id, { httpOnly: true });
}
function clearSession(res) {
  res.clearCookie('uid');
}

module.exports = { signUp, login, requireAuth, setSession, clearSession };
