require('dotenv').config();
const express = require('express');
const connectDB = require('./config/db');
const { bot } = require('./bot');

const app = express();
app.use(express.json());

connectDB();

const WEBHOOK_PATH = `/webhook/${process.env.BOT_TOKEN}`;
app.use(bot.webhookCallback(WEBHOOK_PATH));

app.get('/', (req, res) => res.send('Cymor Scam Shield is running.'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  if (process.env.RENDER_EXTERNAL_URL) {
    await bot.telegram.setWebhook(`${process.env.RENDER_EXTERNAL_URL}${WEBHOOK_PATH}`);
    console.log('Webhook set');
  }
});
