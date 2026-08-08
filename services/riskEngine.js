function computeRisk({ whois, ssl, safeBrowsing, lookalike, virusTotal, fallback }) {
  let score = 0;
  const reasons = [];
  const checks = [];

  // Domain age
  if (whois.ageDays !== null) {
    if (whois.ageDays < 30) {
      score += 30;
      reasons.push(`Domain was registered only ${whois.ageDays} day(s) ago. Scam sites are typically created days before a campaign launches and abandoned right after, so extreme newness is one of the strongest scam indicators.`);
      checks.push({ name: 'Domain Age', result: `${whois.ageDays} days old`, status: 'fail' });
    } else if (whois.ageDays < 180) {
      score += 12;
      reasons.push(`Domain is relatively new — registered ${whois.ageDays} days ago. Legitimate banks, telcos, and government portals almost always run on domains that are years old, so a young domain warrants some caution.`);
      checks.push({ name: 'Domain Age', result: `${whois.ageDays} days old`, status: 'warn' });
    } else {
      reasons.push(`Domain has been registered for ${whois.ageDays} days, which is a mature, established age. Scam domains are rarely kept alive this long since they get reported and taken down quickly.`);
      checks.push({ name: 'Domain Age', result: `${whois.ageDays} days old`, status: 'pass' });
    }
  } else {
    score += 5;
    reasons.push('Domain registration date could not be verified through public records. This alone is not necessarily suspicious, but it removes one useful signal from the assessment.');
    checks.push({ name: 'Domain Age', result: 'Unable to verify', status: 'warn' });
  }

  // SSL
  if (!ssl.valid || ssl.expired) {
    score += 20;
    reasons.push('This site has no valid SSL certificate, or its certificate has expired. Legitimate financial and government sites always use valid, current encryption — its absence means any data you enter could be exposed or the site is not properly maintained.');
    checks.push({ name: 'SSL Certificate', result: ssl.error ? 'Could not connect' : 'Invalid / Expired', status: 'fail' });
  } else {
    reasons.push(`This site has a valid SSL certificate${ssl.issuer ? ` issued by ${ssl.issuer}` : ''}, meaning traffic between you and the site is encrypted. This is a good baseline, though scammers can also obtain free SSL certificates, so it should not be trusted on its own.`);
    checks.push({ name: 'SSL Certificate', result: 'Valid', status: 'pass' });
  }

  // Google Safe Browsing
  if (safeBrowsing.flagged) {
    score += 40;
    reasons.push(`This link is already flagged by Google Safe Browsing for: ${safeBrowsing.threats.join(', ')}. It has been independently reported and confirmed harmful by a global threat intelligence database used by browsers worldwide.`);
    checks.push({ name: 'Google Safe Browsing', result: 'Flagged', status: 'fail' });
  } else if (!safeBrowsing.skipped) {
    reasons.push('Google Safe Browsing, the database Chrome and most browsers use to block known-dangerous sites, has no record of this link being harmful.');
    checks.push({ name: 'Google Safe Browsing', result: 'Clean', status: 'pass' });
  } else {
    checks.push({ name: 'Google Safe Browsing', result: 'Not configured', status: 'warn' });
  }

  // Brand impersonation
  if (lookalike.suspicious) {
    score += 25;
    reasons.push(`This domain closely resembles "${lookalike.realDomain}" (the official ${lookalike.mimics} site) but is not an exact match. Registering near-identical domains is a classic impersonation tactic used to trick people into believing they're on the real, trusted site.`);
    checks.push({ name: 'Brand Impersonation', result: `Mimics ${lookalike.mimics}`, status: 'fail' });
  } else {
    reasons.push('This domain was checked against known Kenyan brands (Safaricom, M-Pesa, KRA, NTSA, HELB, banks, eCitizen) and does not closely resemble any of them, so it does not appear to be impersonating a trusted institution.');
    checks.push({ name: 'Brand Impersonation', result: 'No known brand match', status: 'pass' });
  }

  // VirusTotal (detailed) or fallback engine
  let vtUsable = virusTotal && !virusTotal.skipped && !virusTotal.error && !virusTotal.pending;

  if (vtUsable) {
    const total = (virusTotal.malicious || 0) + (virusTotal.suspicious || 0) + (virusTotal.harmless || 0) + (virusTotal.undetected || 0);
    if (virusTotal.malicious > 0) {
      score += 45;
      const vendorList = virusTotal.flaggedBy.slice(0, 6).map(f => `${f.engine} (${f.category})`).join(', ');
      reasons.push(`${virusTotal.malicious} out of ${total} independent security vendors on VirusTotal flagged this URL as malicious${vendorList ? `, including: ${vendorList}` : ''}. This is one of the most reliable signals available, reflecting real-world detections across dozens of antivirus and threat-intelligence engines rather than a single source.`);
      checks.push({ name: 'VirusTotal (70+ engines)', result: `${virusTotal.malicious} flagged malicious`, status: 'fail' });
    } else if (virusTotal.suspicious > 0) {
      score += 18;
      reasons.push(`${virusTotal.suspicious} security vendor(s) on VirusTotal marked this URL as suspicious, though not confirmed malicious. This warrants caution even though it isn't a definitive verdict.`);
      checks.push({ name: 'VirusTotal (70+ engines)', result: `${virusTotal.suspicious} suspicious`, status: 'warn' });
    } else {
      reasons.push(`VirusTotal aggregates results from over 70 independent antivirus and security engines. All of them — ${virusTotal.harmless + virusTotal.undetected} in total — returned a clean result for this link, which is a strong positive signal.`);
      checks.push({ name: 'VirusTotal (70+ engines)', result: 'Clean across all vendors', status: 'pass' });
    }
    if (virusTotal.categories && Object.keys(virusTotal.categories).length > 0) {
      const cats = [...new Set(Object.values(virusTotal.categories))].slice(0, 3).join(', ');
      reasons.push(`Security vendors categorize this site as: ${cats}.`);
    }
  } else {
    // Fallback engine takes over
    const fb = fallback;
    score += Math.round(fb.score * 0.5); // weighted lower than a real multi-engine scan
    fb.findings.forEach(f => reasons.push(f.reason));
    const worstStatus = fb.findings.some(f => f.status === 'fail') ? 'fail' : fb.findings.some(f => f.status === 'warn') ? 'warn' : 'pass';
    checks.push({
      name: 'Pattern Analysis (fallback)',
      result: virusTotal?.pending ? 'VT still processing — used backup engine' : virusTotal?.error ? 'VT unavailable — used backup engine' : 'VT not configured — used backup engine',
      status: worstStatus,
    });
  }

  score = Math.min(score, 100);
  let verdict = 'LOW RISK', emoji = '🟢';
  if (score >= 60) { verdict = 'HIGH RISK'; emoji = '🔴'; }
  else if (score >= 30) { verdict = 'MEDIUM RISK'; emoji = '🟡'; }

  const conclusion = buildConclusion(score, verdict);

  return { score, verdict, emoji, reasons, checks, conclusion };
}

function buildConclusion(score, verdict) {
  if (verdict === 'HIGH RISK') {
    return `This link shows strong, multiple indicators of being a scam or malicious site. Do not enter any personal details, PINs, passwords, or payment information. Do not click further links from the same sender. If you already entered information, change your passwords and contact your bank or Safaricom immediately.`;
  }
  if (verdict === 'MEDIUM RISK') {
    return `This link has some warning signs but nothing conclusive. Proceed only with caution: avoid entering sensitive information (PINs, passwords, card details) unless you can independently confirm the site is legitimate — for example, by checking the official website or contacting the company directly through a known phone number. When in doubt, don't click.`;
  }
  return `This link passed all major checks with no significant red flags. It appears safe based on current data. As with any link, avoid sharing your PIN or password unless you're certain of who's asking, since even legitimate-looking sites can be compromised.`;
}

module.exports = { computeRisk };
