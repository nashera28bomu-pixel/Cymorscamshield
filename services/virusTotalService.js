const axios = require('axios');

function toUrlId(url) {
  return Buffer.from(url).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function summarizeResults(lastResults = {}) {
  const flaggedBy = [];
  for (const [engine, data] of Object.entries(lastResults)) {
    if (data.category === 'malicious' || data.category === 'suspicious') {
      flaggedBy.push({ engine, category: data.category, result: data.result || data.category });
    }
  }
  return flaggedBy;
}

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { skipped: true };

  try {
    // 1. Try to fetch an existing cached report first (fast path)
    const urlId = toUrlId(url);
    try {
      const existing = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': apiKey },
        timeout: 8000,
      });
      const attrs = existing.data.data.attributes;
      const stats = attrs.last_analysis_stats;
      const ageHours = (Date.now() - attrs.last_analysis_date * 1000) / 3600000;
      if (stats && ageHours < 72) {
        return {
          malicious: stats.malicious,
          suspicious: stats.suspicious,
          harmless: stats.harmless,
          undetected: stats.undetected,
          categories: attrs.categories || {},
          reputation: attrs.reputation ?? null,
          flaggedBy: summarizeResults(attrs.last_analysis_results),
          totalTimesSubmitted: attrs.times_submitted || 1,
          fromCache: true,
        };
      }
    } catch (e) {
      // not found in cache — fall through to submit fresh scan
    }

    // 2. Submit for a fresh scan
    const submit = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      { headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 8000 }
    );
    const analysisId = submit.data.data.id;

    // 3. Poll for completion (up to ~24s)
    for (let i = 0; i < 8; i++) {
      await new Promise(r => setTimeout(r, 3000));
      const { data } = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey },
        timeout: 8000,
      });
      if (data.data.attributes.status === 'completed') {
        const s = data.data.attributes.stats;
        const flaggedBy = summarizeResults(data.data.attributes.results);
        return {
          malicious: s.malicious,
          suspicious: s.suspicious,
          harmless: s.harmless,
          undetected: s.undetected,
          categories: {},
          reputation: null,
          flaggedBy,
          totalTimesSubmitted: 1,
          fromCache: false,
        };
      }
    }
    return { pending: true };
  } catch (err) {
    return { error: true };
  }
}

module.exports = { checkVirusTotal };
