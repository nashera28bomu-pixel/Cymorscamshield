const tls = require('tls');

function checkSSL(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 8000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const valid = socket.authorized;
      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      const expired = validTo ? validTo < new Date() : true;
      resolve({ valid, expired, issuer: cert.issuer?.O || 'Unknown', validTo: cert.valid_to || null });
      socket.end();
    });
    socket.on('error', () => resolve({ valid: false, expired: true, error: true }));
    socket.on('timeout', () => { socket.destroy(); resolve({ valid: false, expired: true, error: true, timeout: true }); });
  });
}

module.exports = { checkSSL };
