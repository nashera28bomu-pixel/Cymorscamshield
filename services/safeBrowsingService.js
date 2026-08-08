const axios = require('axios');

async function checkSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) return { flagged: false, skipped: true };
  try {
    const { data } = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: 'cymor-scam-shield', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }
    );
    const matches = data.matches || [];
    return { flagged: matches.length > 0, threats: matches.map(m => m.threatType) };
  } catch (err) {
    return { flagged: false, error: true };
  }
}

module.exports = { checkSafeBrowsing };
