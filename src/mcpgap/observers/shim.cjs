/**
 * Node preload shim: records filesystem and subprocess activity.
 *
 * Loaded with `--require` so it runs before the package's own entry point.
 * That ordering is load-bearing for more than politeness: Node materialises a
 * builtin's ESM named exports from the CommonJS module object the first time it
 * is imported, so patching first means `import { writeFile } from 'fs/promises'`
 * also resolves to the patched function. Patch afterwards and named imports
 * would silently bypass every hook here.
 *
 * THIS IS A BEST-EFFORT DETAIL LAYER, NOT A BOUNDARY. Code under test can
 * unhook it, hold a reference captured before we patched, or reach the kernel
 * through a native addon. What it cannot do is escape the sandbox, and writes
 * are separately established by diffing the working directory -- which is
 * complete, because the sandbox confines writes to exactly that tree. Reads and
 * subprocess spawns have no such backstop and are reported as best-effort.
 *
 * Events are appended as JSON Lines to $MCPGAP_EVENTS.
 */

'use strict';

const fs = require('fs');
const cp = require('child_process');

const target = process.env.MCPGAP_EVENTS;
if (target) {
  // Capture originals before any patching, and write through a raw descriptor.
  // fs.appendFileSync calls fs.writeFileSync internally, so a logger built on
  // the public API re-enters its own hook and recurses until the process dies.
  const openSync = fs.openSync;
  const writeSync = fs.writeSync;
  const fd = openSync(target, 'a');

  let inside = false;
  const log = (event) => {
    if (inside) return;
    inside = true;
    try {
      writeSync(fd, JSON.stringify(event) + '\n');
    } catch (err) {
      // Losing an event must never take down the process under test; that
      // would turn an observation gap into a fabricated crash.
    } finally {
      inside = false;
    }
  };

  const patch = (holder, name, build) => {
    const orig = holder[name];
    if (typeof orig !== 'function') return;
    holder[name] = function (...args) {
      log(build(args));
      return orig.apply(this, args);
    };
  };

  const pathEvent = (op) => (args) => ({ op, kind: 'fs', path: String(args[0]) });

  // Synchronous and callback APIs.
  for (const name of [
    'readFileSync', 'writeFileSync', 'appendFileSync', 'openSync', 'unlinkSync',
    'renameSync', 'copyFileSync', 'mkdirSync', 'rmSync', 'readdirSync',
    'readFile', 'writeFile', 'appendFile', 'open', 'unlink', 'rename', 'copyFile',
  ]) {
    patch(fs, name, pathEvent(name));
  }
  patch(fs, 'createReadStream', pathEvent('createReadStream'));
  patch(fs, 'createWriteStream', pathEvent('createWriteStream'));

  // The promises API is a separate object and needs its own hooks.
  if (fs.promises) {
    for (const name of [
      'readFile', 'writeFile', 'appendFile', 'open', 'unlink',
      'rename', 'copyFile', 'mkdir', 'rm', 'readdir',
    ]) {
      patch(fs.promises, name, pathEvent('promises.' + name));
    }
  }

  const spawnEvent = (op) => (args) => {
    const command = String(args[0]);
    const argv = Array.isArray(args[1]) ? args[1].map(String) : [];
    return { op, kind: 'proc', argv: [command, ...argv] };
  };
  for (const name of [
    'spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork',
  ]) {
    patch(cp, name, spawnEvent(name));
  }
}
