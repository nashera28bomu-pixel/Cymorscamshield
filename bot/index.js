const { Telegraf, Markup } = require('telegraf');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const User = require('../models/User');
const ScanHistory = require('../models/ScanHistory');
const ScamReport = require('../models/ScamReport');
const { getDomainAge } = require('../services/whoisService');
const { checkSSL } = require('../services/sslService');
const { checkSafeBrowsing } = require('../services/safeBrowsingService');
const { checkLookalike } = require('../services/lookalikeService');
const { checkVirusTotal } = require('../services/virusTotalService');
const { runFallbackAnalysis } = require('../services/fallbackScamEngine');
const { computeRisk } = require('../services/riskEngine');
const { analyzeScreenshot } = require('../services/visionService');
const { generateScanPDF } = require('../services/pdfService');

const bot = new Telegraf(process.env.BOT_TOKEN);
const ADMIN_ID = process.env.ADMIN_TELEGRAM_ID;

function extractUrl(text) {
  const match = text.match(/https?:\/\/[^\s]+/i);
  if (match) return match[0];
  const domainMatch = text.match(/([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?)/);
  return domainMatch ? `https://${domainMatch[0]}` : null;
}

async function getOrCreateUser(ctx) {
  const telegramId = String(ctx.from.id);
  let user = await User.findOne({ telegramId });
  if (!user) {
    let referredBy = null;
    if (ctx.startPayload && ctx.startPayload.startsWith('ref_')) {
      referredBy = ctx.startPayload.replace('ref_', '');
    }
    user = await User.create({
      telegramId,
      username: ctx.from.username || null,
      firstName: ctx.from.first_name || '',
      isAdmin: telegramId === ADMIN_ID,
      referredBy,
    });
    if (referredBy && referredBy !== telegramId) {
      await User.updateOne({ telegramId: referredBy }, { $inc: { referralCount: 1 } });
    }
  }
  return user;
}

bot.start(async (ctx) => {
  const user = await getOrCreateUser(ctx);
  await ctx.replyWithMarkdown(`🛡️ *CYMOR SCAM SHIELD*

Welcome, ${user.firstName || 'friend'}!

Your ID: \`${user.telegramId}\`
Username: @${user.username || 'Not set'}
Status: 🆓 ${user.status}
Checks Used: ${user.checksUsed}

I scan links, websites, and screenshots to tell you — clearly — if something's a scam. No jargon, just straight answers with reasons.

📎 Send a link or forward a screenshot to get started
📋 Type /menu to see all commands

Built by *Legendary Smiley Cymor* 🇰🇪`);
});

bot.command('menu', async (ctx) => {
  await ctx.replyWithMarkdown(`📋 *Cymor Scam Shield — Commands*

/check <link> — Scan a link
/history — Your last 10 checks
/report <link> — Flag something as a scam
/referral — Get your invite link
/status — Your usage stats
/help — How this works

Or just paste a link or forward a screenshot directly — no command needed.`);
});

bot.command('help', async (ctx) => {
  await ctx.replyWithMarkdown(`ℹ️ *How Cymor Scam Shield works*

Every link is checked across:
• Domain age
• SSL certificate validity
• Google Safe Browsing threat database
• VirusTotal — 70+ security vendor engines (with a built-in pattern-analysis backup if VirusTotal is ever unavailable)
• Brand impersonation (lookalike domains)

Every result comes with plain-language reasons for *every* check — not just the bad ones — plus a clear conclusion telling you whether to trust the link, and a full PDF report.

Forward a screenshot of a suspicious WhatsApp/SMS message and I'll analyze the text and any links in it too.`);
});

async function runFullCheck(rawInput) {
  const url = extractUrl(rawInput) || rawInput;
  const hostname = url.replace(/^https?:\/\//, '').split('/')[0];

  const [whois, ssl, safeBrowsing, virusTotal] = await Promise.all([
    getDomainAge(hostname),
    checkSSL(hostname),
    checkSafeBrowsing(url),
    checkVirusTotal(url),
  ]);
  const lookalike = checkLookalike(hostname);

  const vtUsable = virusTotal && !virusTotal.skipped && !virusTotal.error && !virusTotal.pending;
  const fallback = vtUsable ? null : runFallbackAnalysis(url, hostname);

  const result = computeRisk({ whois, ssl, safeBrowsing, lookalike, virusTotal, fallback });
  return { url, result };
}

async function handleCheck(ctx, rawInput) {
  const user = await getOrCreateUser(ctx);
  await ctx.reply('🔍 Checking... this takes a few seconds.');

  try {
    const { url, result } = await runFullCheck(rawInput);

    await ScanHistory.create({
      telegramId: user.telegramId,
      type: 'link',
      input: url,
      score: result.score,
      verdict: result.verdict,
      reasons: result.reasons,
      checks: result.checks,
      conclusion: result.conclusion,
    });

    user.checksUsed += 1;
    await user.save();

    const reasonsText = result.reasons.map((r, i) => `${i + 1}. ${r}`).join('\n\n');

    await ctx.replyWithMarkdown(`${result.emoji} *${result.verdict}* — ${result.score}/100

🔗 ${url}

*Why:*
${reasonsText}

*Conclusion:*
${result.conclusion}`, Markup.inlineKeyboard([
      Markup.button.callback('📄 Get PDF Report', `pdf_${user.telegramId}`),
    ]));

    if (user.checksUsed % 3 === 0) {
      await ctx.replyWithMarkdown(`🎉 You've made ${user.checksUsed} checks! Help others stay safe —

Share Cymor Scam Shield with your groups:
🔗 https://t.me/${ctx.botInfo.username}?start=ref_${user.telegramId}`);
    }
  } catch (err) {
    console.error(err);
    await ctx.reply('⚠️ Something went wrong checking that link. Please try again.');
  }
}

bot.command('check', async (ctx) => {
  const input = ctx.message.text.split(' ').slice(1).join(' ').trim();
  if (!input) return ctx.reply('Usage: /check <link>');
  await handleCheck(ctx, input);
});

bot.on('text', async (ctx) => {
  const text = ctx.message.text;
  if (text.startsWith('/')) return;
  const url = extractUrl(text);
  if (url) await handleCheck(ctx, url);
  else await ctx.reply('Send me a link (e.g. https://example.com) or forward a screenshot to check it. Type /menu for commands.');
});

bot.on('photo', async (ctx) => {
  const user = await getOrCreateUser(ctx);
  await ctx.reply('🔍 Analyzing screenshot...');
  try {
    const photo = ctx.message.photo[ctx.message.photo.length - 1];
    const fileLink = await ctx.telegram.getFileLink(photo.file_id);
    const response = await axios.get(fileLink.href, { responseType: 'arraybuffer' });
    const base64 = Buffer.from(response.data).toString('base64');

    const analysis = await analyzeScreenshot(base64, 'image/jpeg');

    await ScanHistory.create({
      telegramId: user.telegramId,
      type: 'screenshot',
      input: 'screenshot',
      score: analysis.riskScore,
      verdict: analysis.verdict,
      reasons: analysis.reasons,
      checks: [],
    });

    user.checksUsed += 1;
    await user.save();

    const emoji = analysis.riskScore >= 60 ? '🔴' : analysis.riskScore >= 30 ? '🟡' : '🟢';
    const reasonsText = analysis.reasons.map((r, i) => `${i + 1}. ${r}`).join('\n\n');

    await ctx.replyWithMarkdown(`${emoji} *${analysis.verdict}* — ${analysis.riskScore}/100

*Why:*
${reasonsText}${analysis.urlsFound?.length ? `\n\n🔗 Links found: ${analysis.urlsFound.join(', ')}\nSend me any of these directly for a full report.` : ''}`);

    if (user.checksUsed % 3 === 0) {
      await ctx.replyWithMarkdown(`🎉 You've made ${user.checksUsed} checks! Share Cymor Scam Shield:
https://t.me/${ctx.botInfo.username}?start=ref_${user.telegramId}`);
    }
  } catch (err) {
    console.error(err);
    await ctx.reply('⚠️ Could not analyze that screenshot. Please try again.');
  }
});

bot.action(/pdf_(.+)/, async (ctx) => {
  const telegramId = ctx.match[1];
  const lastScan = await ScanHistory.findOne({ telegramId, type: 'link' }).sort({ createdAt: -1 });
  if (!lastScan) return ctx.answerCbQuery('No scan found.');

  await ctx.answerCbQuery('Generating PDF...');
  const emoji = lastScan.score >= 60 ? '🔴' : lastScan.score >= 30 ? '🟡' : '🟢';
  const result = {
    score: lastScan.score,
    verdict: lastScan.verdict,
    emoji,
    reasons: lastScan.reasons,
    checks: lastScan.checks,
    conclusion: lastScan.conclusion || 'Review the findings above to decide whether to trust this link.',
  };

  const filePath = path.join('/tmp', `scan_${Date.now()}.pdf`);
  await generateScanPDF({ url: lastScan.input, result, scanDate: new Date().toLocaleString(), filePath });

  await ctx.replyWithDocument({ source: filePath, filename: 'Cymor_Scam_Shield_Report.pdf' });
  fs.unlink(filePath, () => {});
});

bot.command('history', async (ctx) => {
  const telegramId = String(ctx.from.id);
  const scans = await ScanHistory.find({ telegramId }).sort({ createdAt: -1 }).limit(10);
  if (!scans.length) return ctx.reply('No scan history yet.');
  const text = scans.map((s, i) => {
    const emoji = s.score >= 60 ? '🔴' : s.score >= 30 ? '🟡' : '🟢';
    return `${i + 1}. ${emoji} ${s.verdict} (${s.score}/100) — ${s.input.slice(0, 40)}`;
  }).join('\n');
  await ctx.reply(`📜 Your last ${scans.length} checks:\n\n${text}`);
});

bot.command('report', async (ctx) => {
  const input = ctx.message.text.split(' ').slice(1).join(' ').trim();
  if (!input) return ctx.reply('Usage: /report <link>');
  await ScamReport.create({ reportedUrl: input, reportedBy: String(ctx.from.id) });
  await ctx.reply('✅ Thanks for reporting. This helps improve detection for everyone.');
});

bot.command('referral', async (ctx) => {
  const user = await getOrCreateUser(ctx);
  await ctx.replyWithMarkdown(`🔗 *Your referral link:*
https://t.me/${ctx.botInfo.username}?start=ref_${user.telegramId}

People invited: *${user.referralCount}*`);
});

bot.command('status', async (ctx) => {
  const user = await getOrCreateUser(ctx);
  await ctx.replyWithMarkdown(`📊 *Your Stats*

Status: ${user.status}
Checks used: ${user.checksUsed}
Referrals: ${user.referralCount}
Member since: ${user.createdAt.toDateString()}`);
});

bot.command('broadcast', async (ctx) => {
  if (String(ctx.from.id) !== ADMIN_ID) return;
  const message = ctx.message.text.split(' ').slice(1).join(' ').trim();
  if (!message) return ctx.reply('Usage: /broadcast <message>');

  const users = await User.find({});
  let sent = 0, failed = 0;
  for (const u of users) {
    try {
      await ctx.telegram.sendMessage(u.telegramId, `📢 ${message}`);
      sent++;
    } catch {
      failed++;
    }
  }
  await ctx.reply(`Broadcast complete.\nSent: ${sent}\nFailed: ${failed}`);
});

module.exports = { bot };
