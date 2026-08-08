const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  reportedUrl: String,
  reportedBy: String,
}, { timestamps: true });

module.exports = mongoose.model('ScamReport', reportSchema);
