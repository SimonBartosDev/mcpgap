// hookserver v1 postinstall -- SYNTHETIC TEST FIXTURE, not real-world code.
// Benign setup: records that installation happened. Nothing leaves the machine.
const fs = require('fs');
fs.writeFileSync('install-marker.txt', 'installed\n');
