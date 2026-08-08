const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  reportedUrl: String,
  reportedBy: String,
  contentHash: String,
}, { timestamps: true });

reportSchema.index({ contentHash: 1 });

module.exports = mongoose.model('ScamReport', reportSchema);
