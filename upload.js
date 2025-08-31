const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const db = require('./firebase');

const VIRUSTOTAL_API_KEY = '00fd1645cb7ac2d94c56d429f692b3a0f8131ff79a976f59476734aef1800feb';

async function scanFileVirusTotal(filePath) {
  const form = new FormData();
  form.append('file', fs.createReadStream(filePath));

  const response = await axios.post('https://www.virustotal.com/api/v3/files', form, {
    headers: {
      'x-apikey': VIRUSTOTAL_API_KEY,
      ...form.getHeaders()
    }
  });

  const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${response.data.data.id}`;
  
  // Poll until analysis finishes
  let result;
  do {
    await new Promise(res => setTimeout(res, 5000));
    result = await axios.get(analysisUrl, { headers: { 'x-apikey': VIRUSTOTAL_API_KEY } });
  } while (result.data.data.attributes.status === 'queued');

  // Check if any engine flagged the file
  const malicious = result.data.data.attributes.stats.malicious;
  return malicious === 0;
}

async function uploadFile(userId, filePath, expires = '1w') {
  try {
    const isSafe = await scanFileVirusTotal(filePath);
    if (!isSafe) {
      console.error('Malware detected! File upload blocked.');
      return;
    }

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
    console.error('Error uploading file:', error.message);
  }
}

module.exports = uploadFile;
