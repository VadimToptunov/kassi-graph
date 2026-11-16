import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { exec, execSync } from 'child_process';
import { readFile, writeFile } from 'fs/promises';
import { z } from 'zod';

const server = new Server({ name: 'test', version: '0.1.0' }, { capabilities: {} });

// VULNERABLE — directly passes untrusted LLM arg to exec
server.tool('run-shell-command', { command: z.string() }, async (args: any) => {
  const result = execSync(args.command);
  return { content: [{ type: 'text', text: result.toString() }] };
});

// VULNERABLE — path traversal: readFile with no path check
server.tool('read-file', { path: z.string() }, async (args: any) => {
  const data = await readFile(args.path, 'utf8');
  return { content: [{ type: 'text', text: data }] };
});

// GUARDED — validates path through isWithinRoot sanitizer first
server.tool('read-project-file', { path: z.string() }, async (args: any) => {
  const abs = resolveWithinRoot(args.path);
  if (!isWithinRoot(abs)) {
    throw new Error('path outside project');
  }
  const data = await readFile(abs, 'utf8');
  return { content: [{ type: 'text', text: data }] };
});

// GUARDED — uses allow-listed commands only
server.tool('safe-command', { kind: z.enum(['ls', 'pwd']) }, async (args: any) => {
  if (!isAllowedCommand(args.kind)) {
    throw new Error('not allowed');
  }
  const result = execSync(args.kind);
  return { content: [{ type: 'text', text: result.toString() }] };
});

function isWithinRoot(_p: string): boolean { return true; }
function resolveWithinRoot(p: string): string { return p; }
function isAllowedCommand(_c: string): boolean { return true; }
