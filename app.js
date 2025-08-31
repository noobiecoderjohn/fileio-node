const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const { db, bucket } = require('./firebase');
const { signUp, login, requireAuth, setSession, clearSession } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(async (req, _res, next) => {
  const uid = req.cookies?.uid;
  if (!uid) return next();

  try {
    const doc = await db.collection('users').doc(uid).get();
    if (doc.exists) req.user = { id: doc.id, ...doc.data() };
  } catch {}
  next();
});

const upload = multer({ storage: multer.memoryStorage() });

app.get('/', (req, res) => {
  return res.render('index', { user: req.user });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await signUp(email, password);
    setSession(res, user);
    return res.redirect('/dashboard');
  } catch (e) {
    return res.status(400).render('signup', { error: e.message || 'Signup failed' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await login(email, password);
    setSession(res, user);
    return res.redirect('/dashboard');
  } catch (e) {
    return res.status(400).render('login', { error: e.message || 'Login failed' });
  }
});

app.post('/logout', (req, res) => {
  clearSession(res);
  res.redirect('/');
});

app.get('/dashboard', requireAuth, async (req, res) => {
  const uploadsSnap = await db.collection('uploads')
    .where('userId', '==', req.user.id)
    .orderBy('uploadedAt', 'desc')
    .limit(20)
    .get();

  const uploads = uploadsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
  res.render('dashboard', { user: req.user, uploads, error: null, message: null });
});

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) {
    const uploadsSnap = await db.collection('uploads')
      .where('userId', '==', req.user.id)
      .orderBy('uploadedAt', 'desc')
      .limit(20)
      .get();
    const uploads = uploadsSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    return res.status(400).render('dashboard', { user: req.user, uploads, error: 'No file selected', message: null });
  }

  try {
    const getFolderForFile = (mimetype) => {
      if (mimetype.startsWith('image/')) return 'images';
      if (mimetype === 'application/pdf') return 'documents';
      if (mimetype === 'application/vnd.openxmlformats-officedocument.presentationml.presentation') return 'documents';
      if (mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') return 'documents';
      if (mimetype.startsWith('video/')) return 'videos';
      return 'others';
    };
    
    const folder = getFolderForFile(req.file.mimetype);
    const filename = `${folder}/${req.user.id}/${Date.now()}-${uuidv4()}-${req.file.originalname}`;
    const file = bucket.file(filename);

    await file.save(req.file.buffer, {
      contentType: req.file.mimetype,
      metadata: { metadata: { uploadedBy: req.user.id } },
      resumable: false,
    });

    const [url] = await file.getSignedUrl({
      action: 'read',
      expires: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    const meta = {
      userId: req.user.id,
      filename: req.file.originalname,
      storagePath: filename,
      folder,
      mimeType: req.file.mimetype,
      size: req.file.size,
      signedUrl: url,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      uploadedAt: new Date(),
    };
    await db.collection('uploads').add(meta);

    const uploadsSnap = await db.collection('uploads')
      .where('userId', '==', req.user.id)
      .orderBy('uploadedAt', 'desc')
      .limit(20)
      .get();
    const uploads = uploadsSnap.docs.map(d => ({ id: d.id, ...d.data() }));

    return res.render('dashboard', { user: req.user, uploads, error: null, message: 'Upload successful!' });
  } catch (e) {
    console.error(e);

    const uploadsSnap = await db.collection('uploads')
      .where('userId', '==', req.user.id)
      .orderBy('uploadedAt', 'desc')
      .limit(20)
      .get();
    const uploads = uploadsSnap.docs.map(d => ({ id: d.id, ...d.data() }));

    return res.status(500).render('dashboard', { user: req.user, uploads, error: 'Upload failed', message: null });
  }
});

app.post('/delete/:id', requireAuth, async (req, res) => {
  try {
    const docRef = db.collection('uploads').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) return res.redirect('/dashboard');

    const data = doc.data();

    if (data.userId !== req.user.id) return res.redirect('/dashboard');

    if (data.storagePath) {
      await bucket.file(data.storagePath).delete({ ignoreNotFound: true });
    }

    await docRef.delete();

    res.redirect('/dashboard');
  } catch (e) {
    console.error(e);
    res.redirect('/dashboard');
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
