# Cymor Scam Shield

A Telegram bot that checks links and screenshots for scam indicators,
built by Legendary Smiley Cymor.

## Deploy to Render

1. Push this repo to GitHub.
2. Create a new Web Service on Render, connect the repo.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add the environment variables below.
6. Deploy. The bot sets its own webhook on boot using RENDER_EXTERNAL_URL.

## Environment Variables

| Variable | Required | How to get it |
|---|---|---|
| `BOT_TOKEN` | Yes | Message @BotFather on Telegram → /newbot → copy the token |
| `MONGODB_URI` | Yes | MongoDB Atlas → Connect → Drivers → copy connection string |
| `ADMIN_TELEGRAM_ID` | Yes | Message @userinfobot on Telegram to get your numeric ID |
| `GEMINI_API_KEY` | Yes (for screenshot check) | Google AI Studio → Get API Key |
| `GOOGLE_SAFE_BROWSING_KEY` | Optional but recommended | Google Cloud Console → enable Safe Browsing API → create API key |
| `RENDER_EXTERNAL_URL` | Yes | Auto-provided by Render as `https://your-app.onrender.com` — set this manually to your Render URL after first deploy |
| `PORT` | No | Defaults to 3000, Render sets this automatically |

## Commands
- `/start` — welcome + stats
- `/menu` — command list
- `/check <link>` — scan a link
- `/history` — last 10 checks
- `/report <link>` — flag a scam manually
- `/referral` — get invite link
- `/status` — usage stats
- `/broadcast <message>` — admin only, sends to all users
- Send a link or forward a screenshot directly — no command needed

## Notes
- Domain age check uses RDAP (free, no key required).
- SSL check connects directly via Node's `tls` module — no key required.
- Every 3rd check triggers a referral share prompt automatically.
- PDF reports are generated on demand via the "Get PDF Report" button and are not stored — they're deleted from `/tmp` right after sending.
