const axios = require('axios');
const cheerio = require('cheerio');
const crypto = require('crypto');

const BRAND_KEYWORDS = [
  { name: 'Safaricom', domain: 'safaricom.co.ke', terms: ['safaricom', 'm-pesa', 'mpesa'] },
  { name: 'KRA', domain: 'kra.go.ke', terms: ['kra', 'kenya revenue authority', 'itax'] },
  { name: 'NTSA', domain: 'ntsa.go.ke', terms: ['ntsa', 'national transport'] },
  { name: 'HELB', domain: 'helb.co.ke', terms: ['helb', 'higher education loans'] },
  { name: 'Equity Bank', domain: 'equitybank.co.ke', terms: ['equity bank', 'equitel'] },
  { name: 'KCB', domain: 'kcbgroup.com', terms: ['kcb bank', 'kcb group'] },
  { name: 'eCitizen', domain: 'ecitizen.go.ke', terms: ['ecitizen'] },
];

const SENSITIVE_FIELD_PATTERNS = /pin|mpesa|atm|cvv|otp|passcode|password|ssn|national.?id/i;

async function fetchPageWithRedirects(url) {
  const chain = [];
  let response;
  try {
    response = await axios.get(url, {
      timeout: 10000,
      maxRedirects: 10,
      validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CymorScamShield/1.0)' },
      beforeRedirect: (options, { headers }) => {
        chain.push(options.href);
      },
    });
  } catch (err) {
    return { error: true, message: err.message };
  }
  return { response, chain };
}

function hashText(text) {
  return crypto.createHash('sha256').update(text.trim().toLowerCase()).digest('hex');
}

async function analyzeContent(url, hostname) {
  const findings = [];
  let score = 0;

  const fetchResult = await fetchPageWithRedirects(url);
  if (fetchResult.error) {
    findings.push({
      status: 'warn',
      result: 'Page unreachable',
      reason: `The page could not be loaded for content inspection (${fetchResult.message}). This alone isn't proof of anything malicious — the site may simply be down or blocking automated requests — but it means content-level checks couldn't run.`,
    });
    return { score: 5, findings, pageChecked: false };
  }

  const { response, chain } = fetchResult;
  const finalUrl = response.request?.res?.responseUrl || url;
  const finalHostname = finalUrl.replace(/^https?:\/\//, '').split('/')[0];

  // Redirect chain check
  if (chain.length > 0) {
    const uniqueDomains = new Set(chain.map(u => { try { return new URL(u).hostname; } catch { return u; } }));
    uniqueDomains.add(finalHostname);
    if (uniqueDomains.size > 2) {
      score += 15;
      findings.push({
        status: 'warn',
        result: `${uniqueDomains.size} domains in redirect chain`,
        reason: `This link redirects through ${uniqueDomains.size} different domains before reaching its final destination (${finalHostname}). Long redirect chains are commonly used to obscure the true destination and evade link scanners.`,
      });
    } else if (finalHostname !== hostname) {
      score += 8;
      findings.push({
        status: 'warn',
        result: `Redirects to ${finalHostname}`,
        reason: `The link you were given (${hostname}) redirects to a different domain (${finalHostname}). Always check that the final destination matches what you expect before entering any information.`,
      });
    }
  }

  if (!response || response.status >= 400) {
    findings.push({
      status: 'warn',
      result: `HTTP ${response?.status || 'error'}`,
      reason: 'The page returned an error or could not be fully retrieved, so form and content analysis could not be completed.',
    });
    return { score: score + 5, findings, pageChecked: false };
  }

  const html = typeof response.data === 'string' ? response.data : '';
  if (!html) {
    findings.push({ status: 'warn', result: 'No content returned', reason: 'The page returned no readable HTML content to analyze.' });
    return { score: score + 5, findings, pageChecked: false };
  }

  const $ = cheerio.load(html);
  const pageText = $('body').text().toLowerCase();
  const pageTitle = $('title').text().trim();

  // Login/password form + action domain check
  const forms = $('form').toArray();
  let hasPasswordField = false;
  let externalFormAction = null;
  let sensitiveFieldNames = [];

  forms.forEach(form => {
    const $form = $(form);
    if ($form.find('input[type="password"]').length > 0) hasPasswordField = true;
    $form.find('input').each((_, input) => {
      const name = ($(input).attr('name') || $(input).attr('id') || '').toLowerCase();
      if (SENSITIVE_FIELD_PATTERNS.test(name)) sensitiveFieldNames.push(name);
    });
    const action = $form.attr('action');
    if (action && /^https?:\/\//i.test(action)) {
      try {
        const actionHost = new URL(action).hostname;
        if (actionHost && actionHost !== finalHostname) externalFormAction = actionHost;
      } catch {}
    }
  });

  if (externalFormAction) {
    score += 35;
    findings.push({
      status: 'fail',
      result: `Form submits to ${externalFormAction}`,
      reason: `This page contains a form that submits data to a completely different domain (${externalFormAction}) than the one you're viewing (${finalHostname}). This is one of the clearest signs of a phishing page — legitimate sites process their own forms on their own domain.`,
    });
  }

  if (sensitiveFieldNames.length > 0) {
    score += 25;
    findings.push({
      status: 'fail',
      result: `Fields: ${[...new Set(sensitiveFieldNames)].join(', ')}`,
      reason: `The page has input fields specifically named for sensitive data (${[...new Set(sensitiveFieldNames)].join(', ')}). No legitimate website should ask you to type your M-Pesa PIN, ATM PIN, CVV, or OTP into a web form — these should never leave your banking app or SIM menu.`,
    });
  } else if (hasPasswordField) {
    findings.push({
      status: 'warn',
      result: 'Login form present',
      reason: 'This page contains a password login form. This is normal for many legitimate sites, but only enter credentials if you are certain you reached this page intentionally and the domain is correct.',
    });
  }

  // Brand keyword vs domain mismatch
  const matchedBrand = BRAND_KEYWORDS.find(b => b.terms.some(t => pageText.includes(t) || pageTitle.toLowerCase().includes(t)));
  if (matchedBrand && !finalHostname.includes(matchedBrand.domain.split('.')[0])) {
    score += 30;
    findings.push({
      status: 'fail',
      result: `Mentions "${matchedBrand.name}" but hosted on ${finalHostname}`,
      reason: `This page's content repeatedly references "${matchedBrand.name}", but it is not hosted on ${matchedBrand.name}'s official domain (${matchedBrand.domain}). This is a strong sign of a cloned or impersonation page built to look like a trusted brand.`,
    });
  }

  // External resource ratio (lazy-cloned pages load most assets from the real site)
  const resourceTags = $('img[src], script[src], link[href]').toArray();
  let externalCount = 0;
  resourceTags.forEach(tag => {
    const src = $(tag).attr('src') || $(tag).attr('href');
    if (src && /^https?:\/\//i.test(src)) {
      try {
        const resHost = new URL(src).hostname;
        if (resHost !== finalHostname && !resHost.includes('cdnjs') && !resHost.includes('googleapis') && !resHost.includes('gstatic')) {
          externalCount++;
        }
      } catch {}
    }
  });
  if (resourceTags.length > 4 && externalCount / resourceTags.length > 0.5) {
    score += 12;
    findings.push({
      status: 'warn',
      result: `${externalCount}/${resourceTags.length} resources external`,
      reason: `Most of this page's images, scripts, and styles are loaded directly from other domains rather than its own. This pattern is common in quickly-cloned phishing pages, where attackers copy the page's HTML but don't bother re-hosting the original site's assets.`,
    });
  }

  // Template reuse detection (basic content hash)
  const contentHash = hashText(pageText.slice(0, 2000));

  if (findings.length === 0) {
    findings.push({
      status: 'pass',
      result: 'No content-level red flags',
      reason: 'The page content was inspected for suspicious login forms, brand impersonation, and cloned assets — nothing suspicious was found at the content level.',
    });
  }

  return { score: Math.min(score, 100), findings, pageChecked: true, contentHash, finalHostname };
}

module.exports = { analyzeContent };
