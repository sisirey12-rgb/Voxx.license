// One-time script: creates (or resets) your admin account.
// Run locally:  node create-admin.js <username> <password>
// Requires: npm install bcrypt
//
// Adjust the `db.execute(...)` call below to match however db.js exposes
// your Turso client if it's not already a raw @libsql/client instance.

const bcrypt = require('bcrypt');
const db = require('./db'); // adjust path/import to match your project

async function main() {
  const [, , username, password] = process.argv;
  if (!username || !password) {
    console.error('Usage: node create-admin.js <username> <password>');
    process.exit(1);
  }
  if (password.length < 12) {
    console.error('Use a password with at least 12 characters.');
    process.exit(1);
  }

  const hash = await bcrypt.hash(password, 12);

  await db.execute({
    sql: `INSERT INTO admin_users (username, password_hash)
          VALUES (?, ?)
          ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash`,
    args: [username, hash],
  });

  console.log(`Admin user "${username}" created/updated.`);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
