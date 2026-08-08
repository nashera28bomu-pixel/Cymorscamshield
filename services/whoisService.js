const axios = require('axios');

async function getDomainAge(domain) {
  try {
    const { data } = await axios.get(`https://rdap.org/domain/${domain}`, { timeout: 8000 });
    const registration = data.events?.find(e => e.eventAction === 'registration');
    if (!registration) return { ageDays: null, registered: null };
    const registeredDate = new Date(registration.eventDate);
    const ageDays = Math.floor((Date.now() - registeredDate) / 86400000);
    return { ageDays, registered: registeredDate.toISOString().split('T')[0] };
  } catch (err) {
    return { ageDays: null, registered: null, error: true };
  }
}

module.exports = { getDomainAge };
