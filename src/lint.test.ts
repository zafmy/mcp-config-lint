import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lintFiles, packagePinProblem, stripJsonComments, type Finding } from './lint.js';

// Fake token shapes, built at runtime so no secret scanner flags this file.
const GH = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
const ANT = 'sk-ant-' + 'api03-' + 'Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2';

const onPath = (cmd: string) => ['node', 'npx', 'uvx', 'docker', 'pnpm', '/usr/local/bin/npx'].includes(cmd);
const lint = (servers: unknown, file = '.mcp.json') => lintFiles([{ file, text: JSON.stringify({ mcpServers: servers }) }], onPath);
const rules = (f: Finding[]) => f.map((x) => `${x.server ?? '-'}:${x.rule}`);

test('stripJsonComments drops // and /* */ comments but keeps them inside strings', () => {
  const text = '{\n  // a server\n  "url": "http://x/y", /* inline */ "a": "/* not a comment */"\n}';
  assert.deepEqual(JSON.parse(stripJsonComments(text)), { url: 'http://x/y', a: '/* not a comment */' });
  assert.deepEqual(JSON.parse(stripJsonComments('{"a": "q\\"//still string"}')), { a: 'q"//still string' });
});

test('a clean, pinned config has no findings', () => {
  const r = lint({
    fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2026.1.14', '/tmp'] },
    gh: { command: 'docker', args: ['run', '-i', '--rm', '-e', 'GITHUB_TOKEN', 'ghcr.io/github/github-mcp-server'], env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' } },
    remote: { type: 'http', url: 'https://mcp.example.com/mcp', headers: { Authorization: 'Bearer ${env:API_TOKEN}' } },
  });
  assert.deepEqual(r.findings, []);
  assert.equal(r.servers, 3);
});

test('literal secrets in env, args and headers are errors, and the value is never echoed', () => {
  const r = lint({
    a: { command: 'node', args: ['server.js'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: GH } },
    b: { command: 'node', args: ['server.js', `--api-key=${ANT}`] },
    c: { command: 'node', args: ['server.js', '--token', 'hunter2hunter2'] },
    d: { url: 'https://mcp.example.com', headers: { Authorization: `Bearer ${GH}` } },
    e: { command: 'node', args: ['s.js'], env: { DB_PASSWORD: 'correct-horse-battery' } },
  });
  assert.deepEqual(rules(r.findings), ['a:secret', 'b:secret', 'c:secret', 'd:secret', 'e:secret']);
  assert.ok(r.findings.every((f) => f.severity === 'error'));
  const out = JSON.stringify(r);
  for (const s of [GH, ANT, 'hunter2hunter2', 'correct-horse-battery']) assert.ok(!out.includes(s), `leaked ${s.slice(0, 6)}`);
});

test('references, placeholders, paths and non-secret keys are not flagged as secrets', () => {
  const r = lint({
    a: {
      command: 'node',
      args: ['s.js', '--token', '${TOKEN}'],
      env: {
        API_KEY: '$API_KEY', GITHUB_TOKEN: '${input:gh}', OPENAI_API_KEY: '<your-key-here>', SLACK_TOKEN: 'your_token_here',
        PRIVATE_KEY_PATH: '/Users/me/.ssh/id_ed25519', LOG_LEVEL: 'debug-verbose-mode', AUTH_MODE: 'disabled',
      },
    },
  });
  assert.deepEqual(r.findings, []);
});

test('packagePinProblem accepts exact versions and git refs, rejects tags and ranges', () => {
  for (const ok of ['pkg@1.2.3', '@scope/pkg@0.4.0-beta.1', 'github:zafmy/mcp-smoke#v0.1.0', 'git+https://github.com/a/b.git#4302ded'])
    assert.equal(packagePinProblem('npm', ok), undefined, ok);
  assert.match(packagePinProblem('npm', 'pkg')!, /no version/);
  assert.match(packagePinProblem('npm', '@scope/pkg')!, /no version/);
  assert.match(packagePinProblem('npm', 'pkg@latest')!, /latest/);
  assert.match(packagePinProblem('npm', 'pkg@^1.2.0')!, /\^1\.2\.0/);
  assert.match(packagePinProblem('npm', 'github:a/b')!, /no ref/);
  for (const ok of ['mcp-server-fetch==2025.4.7', 'mcp-server-fetch@2025.4.7', 'git+https://github.com/a/b@v1.0.0'])
    assert.equal(packagePinProblem('python', ok), undefined, ok);
  assert.match(packagePinProblem('python', 'mcp-server-fetch')!, /no version/);
  assert.match(packagePinProblem('python', 'mcp-server-fetch>=1.0')!, />=1\.0/);
  // uvx accepts @latest; a word after @ or == is not a version (PEP 440 versions start with a digit).
  for (const tag of ['mcp-server-fetch@latest', 'mcp-server-fetch@dev', 'mcp-server-fetch==latest'])
    assert.match(packagePinProblem('python', tag)!, /can change/, tag);
  assert.match(packagePinProblem('python', 'pkg@latest')!, /like pkg@1\.2\.3/);
  for (const ok of ['mcp-server-fetch[cli]==1.2.3', 'pkg==1!2.0', 'pkg==1.0.post1', 'pkg==v1.2.3', 'pkg@V1.0'])
    assert.equal(packagePinProblem('python', ok), undefined, ok);
});

test('package runners are checked for unpinned packages, wherever the package sits in args', () => {
  const r = lint({
    npx: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory'] },
    npxPath: { command: '/usr/local/bin/npx', args: ['--yes', 'some-mcp@latest'] },
    npxP: { command: 'npx', args: ['-p', 'some-mcp@1.0.0', 'some-mcp-bin'] },
    dlx: { command: 'pnpm', args: ['dlx', 'some-mcp'] },
    uvx: { command: 'uvx', args: ['mcp-server-fetch'] },
    uvxFrom: { command: 'uvx', args: ['--from', 'git+https://github.com/a/b', 'b-server'] },
    pinned: { command: 'uvx', args: ['mcp-server-time==2025.9.25'] },
    local: { command: 'npx', args: ['./dist/index.js'] },
  });
  assert.deepEqual(rules(r.findings), ['npx:unpinned', 'npxPath:unpinned', 'dlx:unpinned', 'uvx:unpinned', 'uvxFrom:unpinned']);
  assert.ok(r.findings.every((f) => f.severity === 'warning'));
});

test('missing commands, missing command/url, and plain http to a remote host are reported', () => {
  const r = lint({
    gone: { command: 'definitely-not-installed-mcp', args: [] },
    abs: { command: '/nope/bin/server' },
    empty: { args: ['x'] },
    notObj: 'npx foo',
    http: { url: 'http://mcp.example.com/sse' },
    local: { url: 'http://localhost:3000/mcp' },
    loop2: { url: 'http://127.0.0.2:3000/mcp' },
    subLocal: { url: 'http://app.localhost/mcp' },
    v6: { url: 'http://[::1]:8080/mcp' },
    notLoop: { url: 'http://127.example.com/mcp' },
    fakeLocal: { url: 'http://localhost.evil.com/mcp' },
  });
  assert.deepEqual(rules(r.findings), ['gone:command-not-found', 'abs:command-not-found', 'empty:invalid-server', 'notObj:invalid-server', 'http:insecure-url', 'notLoop:insecure-url', 'fakeLocal:insecure-url']);
});

test('broken files and missing server maps are errors; VS Code "servers" key and JSONC are supported', () => {
  const r = lintFiles([
    { file: 'bad.json', text: `{ "mcpServers": { "a": { "env": { "K": "${GH}" ` },
    { file: 'none.json', text: '{ "theme": "dark" }' },
    { file: '.vscode/mcp.json', text: '{ // comment\n "servers": { "x": { "command": "node", "args": ["a.js"] } } }' },
  ], onPath);
  assert.deepEqual(r.findings.map((f) => `${f.file}:${f.rule}`), ['bad.json:invalid-json', 'none.json:no-servers']);
  // JSON.parse errors can quote the text around the problem; the report must not.
  assert.match(r.findings[0].message, /line 1, column \d+/);
  assert.ok(!JSON.stringify(r).includes(GH));
  assert.equal(r.servers, 1);
});

test('the same server name twice for one client is a warning; across different clients it is fine', () => {
  const s = JSON.stringify({ mcpServers: { github: { command: 'node', args: ['a.js'] } } });
  const r = lintFiles([
    { file: '.mcp.json', text: s },
    { file: '~/.claude.json', text: s },
    { file: '.cursor/mcp.json', text: s },
    { file: '~/Library/Application Support/Claude/claude_desktop_config.json', text: s },
  ], onPath);
  assert.deepEqual(rules(r.findings), ['github:duplicate-name']);
  assert.match(r.findings[0].message, /Claude Code.*\.mcp\.json.*~\/\.claude\.json/);
});

test('a command string with arguments in it is split, flagged, and still checked', () => {
  const r = lint({ docs: { command: 'npx mcp-remote https://mcp.example.com/sse' } }, '.cursor/mcp.json');
  assert.deepEqual(rules(r.findings), ['docs:command-has-args', 'docs:unpinned']);
  assert.match(r.findings[1].message, /"mcp-remote" has no version/);
  const s = lint({ x: { command: `node server.js --token ${GH}` } });
  assert.deepEqual(rules(s.findings), ['x:command-has-args', 'x:secret']);
});

const cli = fileURLToPath(new URL('./index.js', import.meta.url));
const run = (cwd: string, ...args: string[]) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8' });

test('cli: exit 0 clean, 1 on error, warnings fail only with --strict, 2 on bad usage', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcl-'));
  const write = (servers: unknown) => writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: servers }));

  write({ a: { command: process.execPath, args: ['a.js'] } });
  assert.equal(run(dir).status, 0);

  write({ a: { command: 'npx', args: ['-y', 'some-mcp'] } });
  assert.equal(run(dir).status, 0);
  assert.equal(run(dir, '--strict').status, 1);
  assert.equal(run(dir, '--strict', '--ignore', 'unpinned').status, 0);
  assert.equal(run(dir, '--ignore', 'no-such-rule').status, 2);

  write({ a: { command: process.execPath, env: { GITHUB_TOKEN: GH } } });
  const r = run(dir, '--json');
  assert.equal(r.status, 1);
  assert.ok(!r.stdout.includes(GH));
  assert.equal(JSON.parse(r.stdout).findings[0].rule, 'secret');

  assert.equal(run(dir, 'missing.json').status, 2);
  assert.equal(run(mkdtempSync(join(tmpdir(), 'mcl-empty-'))).status, 2);
  assert.equal(run(dir, '--nope').status, 2);
});

test('cli: finds project configs by default (.mcp.json, .cursor, .vscode)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcl-'));
  mkdirSync(join(dir, '.cursor'));
  mkdirSync(join(dir, '.vscode'));
  writeFileSync(join(dir, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { a: { command: process.execPath } } }));
  writeFileSync(join(dir, '.vscode', 'mcp.json'), JSON.stringify({ servers: { b: { command: process.execPath } } }));
  const r = JSON.parse(run(dir, '--json').stdout);
  assert.equal(r.files.length, 2);
  assert.equal(r.servers, 2);
});
