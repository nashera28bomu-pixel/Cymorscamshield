const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, unique: true },
  username: String,
  firstName: String,
  status: { type: String, default: 'Free User' },
  checksUsed: { type: Number, default: 0 },
  referredBy: { type: String, default: null },
  referralCount: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
