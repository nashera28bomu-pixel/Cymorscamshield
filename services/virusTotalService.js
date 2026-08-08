const axios = require('axios');

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { skipped: true };
  try {
    const submit = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      { headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const analysisId = submit.data.data.id;
    for (let i = 0; i < 5; i++) {
      await new Promise(r => setTimeout(r, 2500));
      const { data } = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey },
      });
      if (data.data.attributes.status === 'completed') {
        const s = data.data.attributes.stats;
        return { malicious: s.malicious, suspicious: s.suspicious, harmless: s.harmless, undetected: s.undetected };
      }
    }
    return { pending: true };
  } catch {
    return { error: true };
  }
}

module.exports = { checkVirusTotal };
