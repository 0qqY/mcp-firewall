import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { evaluateToolCall } from '../src/engine.js';
import { compilePolicy, PolicyError } from '../src/policy.js';

const top = mkdtempSync(join(tmpdir(), 'mcpfw-paths-'));
const root = join(top, 'project');
const outside = join(top, 'outside');
mkdirSync(join(root, 'docs'), { recursive: true });
mkdirSync(outside);
writeFileSync(join(root, 'docs', 'a.md'), 'a');
writeFileSync(join(outside, 'secret.txt'), 's');

const policy = compilePolicy(
  {
    tools: {
      rules: [
        {
          match: 'read_file',
          action: 'allow',
          paths: { arguments: ['path', 'paths'], base: root, allow: [root], deny: ['**/.ssh', '**/.env', '**/*.pem'] },
        },
      ],
    },
  },
  top,
);
const read = (path: unknown) => evaluateToolCall(policy, 'read_file', { path });
const allowed = (path: unknown) => read(path).allowed;
const insensitive = process.platform === 'win32' || process.platform === 'darwin';

test('paths inside the allowed root pass, absolute or relative to the base', () => {
  assert.equal(allowed(join(root, 'docs', 'a.md')), true);
  assert.equal(allowed('docs/a.md'), true);
  assert.equal(allowed(join(root, 'new', 'not-yet.txt')), true);
  assert.equal(allowed(pathToFileURL(join(root, 'docs', 'a.md')).href), true);
});

test('traversal is resolved before matching, in every spelling', () => {
  assert.equal(allowed(join(root, 'docs', '..', '..', 'outside', 'secret.txt')), false);
  assert.equal(allowed('../outside/secret.txt'), false);
  assert.equal(allowed('docs/%2e%2e/%2e%2e/outside/secret.txt'), false);
  assert.equal(allowed('docs/%252e%252e/%252e%252e/outside/secret.txt'), false);
  assert.equal(allowed('docs%2f..%2f..%2foutside%2fsecret.txt'), false);
  assert.equal(allowed(pathToFileURL(join(outside, 'secret.txt')).href), false);
  assert.match(read('../outside/secret.txt').reason ?? '', /outside the allowed paths/);
});

test('deny patterns match a directory and everything below it', () => {
  assert.equal(allowed(join(root, '.ssh', 'id_rsa')), false);
  assert.equal(allowed(join(root, 'docs', '.env')), false);
  assert.equal(allowed(join(root, 'keys', 'server.pem')), false);
  assert.equal(allowed(join(root, 'docs', '.environment')), true);
  assert.equal(allowed(join(root, '.SSH', 'id_rsa')), !insensitive);
  assert.match(read(join(root, '.ssh', 'id_rsa')).reason ?? '', /denied by path '\*\*\/\.ssh'/);
});

test('a link inside the root that points outside is followed', () => {
  const link = join(root, 'link');
  symlinkSync(outside, link, 'junction');
  assert.equal(allowed(join(link, 'secret.txt')), false);
  assert.equal(allowed('link/secret.txt'), false);
});

test('every value of a list argument is checked, and non-paths are refused', () => {
  assert.equal(evaluateToolCall(policy, 'read_file', { paths: ['docs/a.md', '../outside/secret.txt'] }).allowed, false);
  assert.equal(evaluateToolCall(policy, 'read_file', { paths: ['docs/a.md'] }).allowed, true);
  assert.equal(allowed(42), false);
  assert.equal(allowed('docs/a.md\u0000.txt'), false);
  assert.equal(allowed('docs/a.md%00.txt'), false);
  assert.equal(evaluateToolCall(policy, 'read_file', {}).allowed, true);
});

test('Windows spellings of the same file are canonicalized', { skip: process.platform !== 'win32' }, () => {
  assert.equal(allowed(join(root, 'docs', '.env.')), false);
  assert.equal(allowed(join(root, 'docs', '.env  ')), false);
  assert.equal(allowed(join(root, 'docs', '.env::$DATA')), false);
  assert.equal(allowed(join(root, '.ssh.', 'id_rsa')), false);
  assert.equal(allowed(`\\\\?\\${join(root, 'docs', '..', '..', 'outside', 'secret.txt')}`), false);
  assert.equal(allowed(`\\\\?\\${join(root, 'docs', 'a.md')}`), true);
  assert.equal(allowed(root.replace(/\\/g, '/') + '/docs/a.md'), true);
  assert.equal(allowed('\\\\.\\pipe\\docs'), false);
  assert.equal(allowed('\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\x'), false);
  assert.equal(allowed('\\\\.\\PhysicalDrive0'), false);
  assert.equal(allowed('\\\\.\\C:'), false);
});

test('UNC paths are refused without contacting the host', { skip: process.platform !== 'win32' }, () => {
  const started = Date.now();
  assert.equal(allowed('\\\\attacker.invalid\\share\\x'), false);
  assert.equal(allowed('//attacker.invalid/share/x'), false);
  assert.equal(allowed('\\\\?\\UNC\\attacker.invalid\\share\\x'), false);
  assert.equal(allowed('file://attacker.invalid/share/x'), false);
  assert.ok(Date.now() - started < 200, 'no network lookup');
});

test('Windows 8.3 short names resolve to the long name', { skip: process.platform !== 'win32' || !existsSync('C:\\PROGRA~1') }, () => {
  const p = compilePolicy(
    { tools: { rules: [{ match: 'read_file', action: 'allow', paths: { arguments: ['path'], deny: ['C:/Program Files'] } }] } },
    top,
  );
  assert.equal(evaluateToolCall(p, 'read_file', { path: 'C:\\PROGRA~1\\x.txt' }).allowed, false);
  assert.equal(evaluateToolCall(p, 'read_file', { path: join(root, 'docs', 'a.md') }).allowed, true);
});

test('a paths block must name its arguments', () => {
  assert.throws(() => compilePolicy({ tools: { rules: [{ match: 'x', action: 'allow', paths: { allow: ['/a'] } }] } }, top), PolicyError);
});
