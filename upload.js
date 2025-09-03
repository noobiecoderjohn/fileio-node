const axios = require('axios');
const FormData = require('form-data');

const VIRUSTOTAL_API_KEY = '00fd1645cb7ac2d94c56d429f692b3a0f8131ff79a976f59476734aef1800feb';

/**
 * Scan a file buffer with VirusTotal
 * @param {Buffer} fileBuffer
 * @param {string} fileName
 * @returns {Promise<boolean>} true if file is safe
 */
async function scanFileVirusTotal(fileBuffer, fileName) {
  const form = new FormData();
  form.append('file', fileBuffer, fileName);

  // Upload file to VirusTotal
  const uploadResp = await axios.post('https://www.virustotal.com/api/v3/files', form, {
    headers: { 'x-apikey': VIRUSTOTAL_API_KEY, ...form.getHeaders() },
  });

  const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${uploadResp.data.data.id}`;

  // Poll until analysis finishes
  let result;
  do {
    await new Promise((res) => setTimeout(res, 5000));
    result = await axios.get(analysisUrl, {
      headers: { 'x-apikey': VIRUSTOTAL_API_KEY },
    });
  } while (result.data.data.attributes.status !== 'completed');

  const stats = result.data.data.attributes.stats;
  console.log('VirusTotal stats:', stats);

  return stats.malicious === 0 && stats.suspicious === 0;
}

module.exports = { scanFileVirusTotal };
