// Public status check — no hwid required, and never reveals any device IDs.
router.post('/status', async (req, res) => {
  const { license_key } = req.body || {};
  if (!license_key) return res.json({ valid: false, reason: 'license_key_required' });

  const licResult = await db.execute({
    sql: 'SELECT * FROM licenses WHERE license_key = ?',
    args: [license_key],
  });
  const lic = licResult.rows[0];
  if (!lic) return res.json({ valid: false, reason: 'invalid_key' });

  const status = computeStatus(lic);
  if (status === 'revoked') return res.json({ valid: false, reason: 'revoked' });
  if (status === 'expired') return res.json({ valid: false, reason: 'expired', expires_at: lic.expires_at });

  const boundResult = await db.execute({
    sql: 'SELECT COUNT(*) as count FROM license_devices WHERE license_key = ?',
    args: [license_key],
  });
  const boundCount = Number(boundResult.rows[0]?.count || 0);

  res.json({
    valid: true,
    bound: boundCount > 0,
    expires_at: lic.expires_at,
    days_left: daysLeft(lic.expires_at),
  });
});
