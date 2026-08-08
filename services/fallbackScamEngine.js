const SUSPICIOUS_KEYWORDS = [
  'verify', 'bonus', 'reward', 'winner', 'prize', 'urgent', 'suspended',
  'confirm', 'login-', 'secure-', 'account-update', 'free-money', 'claim',
  'mpesa-bonus', 'reversal', 'refund', 'gift', 'promo',
];

const SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorte.st',
];

function isIpAddress(hostname) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function runFallbackAnalysis(url, hostname) {
  const findings = [];
  let score = 0;

  if (isIpAddress(hostname)) {
    score += 25;
    findings.push({
      status: 'fail',
      result: 'Raw IP address used as domain',
      reason: 'This link uses a raw IP address instead of a proper domain name. Legitimate businesses almost never link customers directly to an IP address — this is a common technique to avoid domain-based blocklists.',
    });
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 12;
    findings.push({
      status: 'warn',
      result: `${hyphenCount} hyphens in domain`,
      reason: 'The domain contains an unusually high number of hyphens, a pattern often used to create convincing-looking fake brand names (e.g. "safaricom-bonus-account.com").',
    });
  }

  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount >= 3) {
    score += 10;
    findings.push({
      status: 'warn',
      result: `${subdomainCount} subdomain levels`,
      reason: 'This link has an unusually deep subdomain structure, which is sometimes used to disguise the true destination or bypass basic filtering.',
    });
  }

  if (SHORTENER_DOMAINS.some(d => hostname.includes(d))) {
    score += 15;
    findings.push({
      status: 'warn',
      result: 'URL shortener detected',
      reason: 'This link uses a URL shortening service, which hides the real destination until you click. Scammers frequently use shorteners to bypass link-preview warnings.',
    });
  }

  const lowerUrl = url.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(k => lowerUrl.includes(k));
  if (matchedKeywords.length > 0) {
    score += Math.min(matchedKeywords.length * 8, 24);
    findings.push({
      status: 'fail',
      result: `Contains: ${matchedKeywords.join(', ')}`,
      reason: `The link text contains word patterns commonly used in scam campaigns (${matchedKeywords.join(', ')}). Genuine service links rarely need urgency or reward language in the URL itself.`,
    });
  }

  if (hostname.length > 35) {
    score += 8;
    findings.push({
      status: 'warn',
      result: `${hostname.length} characters`,
      reason: 'This domain name is unusually long, a pattern sometimes used to bury a fake brand name within a longer string to look more official.',
    });
  }

  if (findings.length === 0) {
    findings.push({
      status: 'pass',
      result: 'No suspicious patterns found',
      reason: 'No suspicious keywords, IP-based hosting, excessive hyphens, or shortener usage were detected in the link structure itself.',
    });
  }

  return { score: Math.min(score, 100), findings };
}

module.exports = { runFallbackAnalysis };
