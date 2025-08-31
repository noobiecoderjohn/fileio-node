const admin = require('firebase-admin');
const serviceAccount = require('./johnny-7f628-firebase-adminsdk-fbsvc-41a84400a6.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: 'johnny-7f628.firebasestorage.app',
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

module.exports = { db, bucket, admin };
