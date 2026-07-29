const crypto = require('crypto');

function generateKeyString() {
  const len = 8 + Math.floor(Math.random() * 3); // 8, 9, or 10 hex chars
  const bytesNeeded = Math.ceil(len / 2);
  const suffix = crypto.randomBytes(bytesNeeded).toString('hex').toUpperCase().slice(0, len);
  return `VOXX-${suffix}`;
}

// Long random secret for a reseller's X-Reseller-Token — not shown in the
// generated-key format, so it can't be confused with a license key.
function generateResellerToken() {
  return `rsl_${crypto.randomBytes(24).toString('hex')}`;
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

// Wraps an async Express route handler so a thrown/rejected error is passed
// to next(err) instead of becoming an unhandled rejection that can crash
// the whole process. Use as: router.get('/x', asyncHandler(async (req,res)=>{...}))
function asyncHandler(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

module.exports = { generateKeyString, generateResellerToken, addDaysISO, nowISO, daysLeft, computeStatus, asyncHandler };
