const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  telegramId: String,
  type: { type: String, enum: ['link', 'screenshot'], default: 'link' },
  input: String,
  score: Number,
  verdict: String,
  reasons: [String],
  checks: Array,
}, { timestamps: true });

module.exports = mongoose.model('ScanHistory', scanSchema);
