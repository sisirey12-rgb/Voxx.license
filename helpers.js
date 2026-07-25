const crypto = require('crypto');

function generateKeyString() {
  const group = () => crypto.randomBytes(4).toString('hex').toUpperCase();
  return [group(), group(), group(), group()].join('-');
}

function addDaysISO(fromISO, days) {
  const d = new Date(fromISO);
  d.setDate(d.getDate() + Number(days));
  return d.toISOString();
}

function nowISO() {
  return new Date().toISOString();
}

function daysLeft(expiresAtISO) {
  return Math.ceil((new Date(expiresAtISO) - new Date()) / 86400000);
}

// Derives a display status from stored fields + current time.
function computeStatus(lic) {
  if (lic.status === 'revoked') return 'revoked';
  if (daysLeft(lic.expires_at) < 0) return 'expired';
  if (daysLeft(lic.expires_at) <= 5) return 'expiring';
  return 'active';
}

module.exports = { generateKeyString, addDaysISO, nowISO, daysLeft, computeStatus };
