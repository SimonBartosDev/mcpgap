#!/usr/bin/env node
/**
 * noteserver v1.0.0 -- a SYNTHETIC, NON-MALICIOUS MCP server used as a test
 * fixture. Nothing here is real-world code and nothing here is hostile.
 *
 * It exists because postmark-mcp, the real acceptance fixture, touches no files
 * and spawns no subprocesses. Against it, the filesystem and subprocess
 * recorders correctly report nothing -- which is indistinguishable from a
 * recorder that is silently broken. This server does write files and spawn
 * processes, so "we observed nothing" can be told apart from "we observe
 * nothing".
 *
 * v1 is the honest baseline: `saveNote` writes exactly the file the caller
 * named, `readNote` reads exactly that file. v2 keeps the same declared tool
 * surface and adds behaviour the manifest does not mention.
 *
 * Zero dependencies, raw JSON-RPC over stdio, so the fixture needs no install
 * and runs instantly.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const NOTES_DIR = path.join(process.cwd(), 'notes');

const TOOLS = [
  {
    name: 'saveNote',
    description: 'Save a note to disk under the given name.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Note name' },
        body: { type: 'string', description: 'Note contents' },
      },
      required: ['name', 'body'],
    },
  },
  {
    name: 'readNote',
    description: 'Read a previously saved note.',
    inputSchema: {
      type: 'object',
      properties: { name: { type: 'string', description: 'Note name' } },
      required: ['name'],
    },
  },
];

function safeName(name) {
  return String(name).replace(/[^A-Za-z0-9._-]/g, '_');
}

function saveNote({ name, body }) {
  fs.mkdirSync(NOTES_DIR, { recursive: true });
  const file = path.join(NOTES_DIR, safeName(name) + '.txt');
  fs.writeFileSync(file, String(body));
  return `saved ${file}`;
}

function readNote({ name }) {
  const file = path.join(NOTES_DIR, safeName(name) + '.txt');
  if (!fs.existsSync(file)) return 'no such note';
  return fs.readFileSync(file, 'utf8');
}

const HANDLERS = { saveNote, readNote };

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

function fail(id, message) {
  process.stdout.write(
    JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message } }) + '\n'
  );
}

function handle(message) {
  const { id, method, params } = message;
  if (method === 'initialize') {
    respond(id, {
      protocolVersion: (params && params.protocolVersion) || '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'noteserver', version: '1.0.0' },
    });
    return;
  }
  if (method === 'tools/list') {
    respond(id, { tools: TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const handler = HANDLERS[params && params.name];
    if (!handler) return fail(id, `unknown tool: ${params && params.name}`);
    try {
      const text = handler((params && params.arguments) || {});
      respond(id, { content: [{ type: 'text', text: String(text) }] });
    } catch (err) {
      fail(id, err && err.message ? err.message : String(err));
    }
    return;
  }
  if (id !== undefined) fail(id, `unsupported method: ${method}`);
}

let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    if (!line) continue;
    try {
      handle(JSON.parse(line));
    } catch (err) {
      // Ignore unparseable input rather than dying mid-conversation.
    }
  }
});
process.stdin.resume();
