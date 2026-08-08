function computeRisk({ whois, ssl, safeBrowsing, lookalike, virusTotal }) {
  let score = 0;
  const reasons = [];
  const checks = [];

  if (whois.ageDays !== null) {
    if (whois.ageDays < 30) {
      score += 30;
      reasons.push(`Domain was registered only ${whois.ageDays} day(s) ago. Scam sites are typically created days before a campaign launches and abandoned right after, so extreme newness is one of the strongest scam indicators.`);
      checks.push({ name: 'Domain Age', result: `${whois.ageDays} days old`, status: 'fail' });
    } else if (whois.ageDays < 180) {
      score += 12;
      reasons.push(`Domain is relatively new — registered ${whois.ageDays} days ago. Legitimate banks, telcos, and government portals almost always run on domains that are years old.`);
      checks.push({ name: 'Domain Age', result: `${whois.ageDays} days old`, status: 'warn' });
    } else {
      checks.push({ name: 'Domain Age', result: `${whois.ageDays} days old`, status: 'pass' });
    }
  } else {
    score += 5;
    checks.push({ name: 'Domain Age', result: 'Unable to verify', status: 'warn' });
  }

  if (!ssl.valid || ssl.expired) {
    score += 20;
    reasons.push('This site has no valid SSL certificate, or its certificate has expired. Legitimate financial and government sites always use valid, current encryption — its absence means any data you enter could be exposed or the site is not properly maintained.');
    checks.push({ name: 'SSL Certificate', result: ssl.error ? 'Could not connect' : 'Invalid / Expired', status: 'fail' });
  } else {
    checks.push({ name: 'SSL Certificate', result: 'Valid', status: 'pass' });
  }

  if (safeBrowsing.flagged) {
    score += 40;
    reasons.push(`This link is already flagged by Google Safe Browsing for: ${safeBrowsing.threats.join(', ')}. It has been independently reported and confirmed harmful by a global threat intelligence database used by browsers worldwide.`);
    checks.push({ name: 'Google Safe Browsing', result: 'Flagged', status: 'fail' });
  } else if (!safeBrowsing.skipped) {
    checks.push({ name: 'Google Safe Browsing', result: 'Clean', status: 'pass' });
  } else {
    checks.push({ name: 'Google Safe Browsing', result: 'Not configured', status: 'warn' });
  }

  if (lookalike.suspicious) {
    score += 25;
    reasons.push(`This domain closely resembles "${lookalike.realDomain}" (the official ${lookalike.mimics} site) but is not an exact match. Registering near-identical domains is a classic impersonation tactic used to trick people into believing they're on the real, trusted site.`);
    checks.push({ name: 'Brand Impersonation', result: `Mimics ${lookalike.mimics}`, status: 'fail' });
  } else {
    checks.push({ name: 'Brand Impersonation', result: 'No known brand match', status: 'pass' });
  }

  if (virusTotal && !virusTotal.skipped && !virusTotal.error && !virusTotal.pending) {
    const total = (virusTotal.malicious || 0) + (virusTotal.suspicious || 0) + (virusTotal.harmless || 0) + (virusTotal.undetected || 0);
    if (virusTotal.malicious > 0) {
      score += 45;
      reasons.push(`${virusTotal.malicious} out of ${total} independent security vendors on VirusTotal have flagged this URL as malicious. This is one of the most reliable signals available, since it reflects real-world detections across dozens of antivirus and threat-intelligence engines, not a single source.`);
      checks.push({ name: 'VirusTotal (70+ engines)', result: `${virusTotal.malicious} flagged malicious`, status: 'fail' });
    } else if (virusTotal.suspicious > 0) {
      score += 18;
      reasons.push(`${virusTotal.suspicious} security vendor(s) on VirusTotal marked this URL as suspicious, though not confirmed malicious. Treat with caution and avoid entering personal or payment information.`);
      checks.push({ name: 'VirusTotal (70+ engines)', result: `${virusTotal.suspicious} suspicious`, status: 'warn' });
    } else {
      checks.push({ name: 'VirusTotal (70+ engines)', result: 'Clean across all vendors', status: 'pass' });
    }
  } else {
    checks.push({
      name: 'VirusTotal (70+ engines)',
      result: virusTotal?.pending ? 'Scan still processing' : virusTotal?.error ? 'Check failed' : 'Not configured',
      status: 'warn',
    });
  }

  score = Math.min(score, 100);
  let verdict = 'LOW RISK', emoji = '🟢';
  if (score >= 60) { verdict = 'HIGH RISK'; emoji = '🔴'; }
  else if (score >= 30) { verdict = 'MEDIUM RISK'; emoji = '🟡'; }

  if (reasons.length === 0) {
    reasons.push('No red flags were detected across domain age, SSL certificate validity, threat databases, brand impersonation, and multi-engine malware scanning. This does not guarantee full safety — always stay cautious with links asking for money or personal details.');
  }

  return { score, verdict, emoji, reasons, checks };
}

module.exports = { computeRisk };
