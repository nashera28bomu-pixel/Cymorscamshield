const KNOWN_BRANDS = [
  { name: 'Safaricom', domain: 'safaricom.co.ke' },
  { name: 'M-Pesa', domain: 'mpesa.co.ke' },
  { name: 'KRA', domain: 'kra.go.ke' },
  { name: 'NTSA', domain: 'ntsa.go.ke' },
  { name: 'HELB', domain: 'helb.co.ke' },
  { name: 'Equity Bank', domain: 'equitybank.co.ke' },
  { name: 'KCB', domain: 'kcbgroup.com' },
  { name: 'eCitizen', domain: 'ecitizen.go.ke' },
];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
  return dp[m][n];
}

function checkLookalike(domain) {
  let closest = null;
  let minDist = Infinity;
  for (const brand of KNOWN_BRANDS) {
    const dist = levenshtein(domain.toLowerCase(), brand.domain.toLowerCase());
    if (dist < minDist) { minDist = dist; closest = brand; }
  }
  const isSuspicious = closest && minDist > 0 && minDist <= 3 && domain.toLowerCase() !== closest.domain.toLowerCase();
  return {
    suspicious: isSuspicious,
    mimics: isSuspicious ? closest.name : null,
    realDomain: isSuspicious ? closest.domain : null,
  };
}

module.exports = { checkLookalike, KNOWN_BRANDS };
