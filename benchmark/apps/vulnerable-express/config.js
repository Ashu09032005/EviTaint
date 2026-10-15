// Contains a hardcoded secret (CWE-798) for the secret detector.
module.exports = {
  port: 3000,
  // VULN secret: synthetic high-entropy value, not a real provider token
  stripeSecret: 'evitaint-demo-key-7f3c9a2b',
  // SAFE: read from env with harmless placeholder fallback
  dbPassword: process.env.DB_PASSWORD || 'changeme',
};
