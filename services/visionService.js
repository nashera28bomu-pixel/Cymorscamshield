const axios = require('axios');

async function analyzeScreenshot(base64Image, mimeType) {
  const apiKey = process.env.GEMINI_API_KEY;
  const prompt = `You are a scam-detection assistant for Kenyan users. Analyze this screenshot (WhatsApp/SMS/website screenshot). Identify: 1) Any suspicious language patterns (urgency, requests for PIN/money, fake prizes, fake sender names). 2) Any URLs visible in the image. 3) An overall risk assessment. Respond ONLY with raw JSON, no markdown formatting: {"riskScore": 0-100, "verdict": "LOW RISK" or "MEDIUM RISK" or "HIGH RISK", "reasons": ["detailed reason 1", "detailed reason 2"], "urlsFound": ["url1"]}`;

  const { data } = await axios.post(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
    {
      contents: [{
        parts: [
          { text: prompt },
          { inline_data: { mime_type: mimeType, data: base64Image } },
        ],
      }],
    }
  );

  const text = data.candidates[0].content.parts[0].text;
  const clean = text.replace(/```json|```/g, '').trim();
  return JSON.parse(clean);
}

module.exports = { analyzeScreenshot };
