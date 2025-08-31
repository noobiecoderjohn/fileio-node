const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const clamav = require('clamav.js');
const db = require('./firebase');

async function scanFile(filePath) {
  return new Promise((resolve, reject) => {
    const port = 3310; // ClamAV default
    const host = '127.0.0.1';
    clamav.ping(port, host, 1000, function(err) {
      if (err) return reject(new Error('ClamAV not reachable'));
      clamav.scanFile(filePath, port, host, function(err, object, malicious) {
        if (err) return reject(err);
        if (malicious) return reject(new Error(`File contains malware: ${object}`));
        resolve(true);
      });
    });
  });
}

async function uploadFile(userId, filePath, expires = '1w') {
  try {
    // Scan before upload
    await scanFile(filePath);
    console.log('File passed malware scan');

    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));

    const response = await axios.post(`https://file.io/?expires=${expires}`, form, {
      headers: form.getHeaders(),
    });

    console.log('File uploaded successfully!');
    console.log('Share this link:', response.data.link);

    await db.collection('uploads').add({
      userId,
      link: response.data.link,
      expiry: response.data.expiry,
      uploadedAt: new Date()
    });

    console.log('File metadata saved to Firestore');
  } catch (error) {
    console.error('Upload failed:', error.message);
  }
}

module.exports = uploadFile;
