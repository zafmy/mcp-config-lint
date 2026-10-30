import { statSync } from 'node:fs';
import { basename, delimiter, join } from 'node:path';

export const RULES = ['secret', 'unpinned', 'command-not-found', 'command-has-args', 'insecure-url', 'invalid-server', 'invalid-json', 'no-servers', 'duplicate-name'] as const;
export type Severity = 'error' | 'warning';
export type Finding = { file: string; server?: string; rule: string; severity: Severity; message: string };
export type Result = { files: string[]; servers: number; findings: Finding[] };
export type ConfigFile = { file: string; text: string; optional?: boolean };
// Says whether a server's command would start. Injected so tests don't depend on the machine's PATH.
export type Resolve = (command: string) => boolean;

type Issue = Omit<Finding, 'file' | 'server'>;
type Ecosystem = 'npm' | 'python';
type Runner = { eco: Ecosystem; sub?: string; pkgFlags: string[]; valueFlags: string[] };

// Real token formats. Matching any of these is a secret whatever the key is called.
const TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{40,}|sk-(?:ant-|proj-)?[\w-]{20,}|xox[abprs]-[\w-]{10,}|AKIA[0-9A-Z]{16}|glpat-[\w-]{20,}|AIza[\w-]{35}|npm_[A-Za-z0-9]{36})/;
const SECRET_NAME = /token|secret|passw(?:or)?d|passphrase|api[-_]?key|access[-_]?key|private[-_]?key|authorization|cookie/i;
const PLACEHOLDER = /^(?:<[^>]*>|your[\W_].*|x{3,}|\*{3,}|changeme|replace[\W_]?me|todo|\.{3})$/i;
const PATH_LIKE = /^(?:\/|~\/|\.\.?\/|[A-Za-z]:\\)/;
const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$/;

const NPX: Runner = { eco: 'npm', pkgFlags: ['-p', '--package'], valueFlags: ['-c', '--call', '--cache', '--registry'] };
const RUNNERS: Record<string, Runner> = {
  npx: NPX,
  bunx: NPX,
  pnpx: NPX,
  npm: { ...NPX, sub: 'exec' },
  pnpm: { ...NPX, sub: 'dlx' },
  yarn: { ...NPX, sub: 'dlx' },
  uvx: { eco: 'python', pkgFlags: ['--from'], valueFlags: ['-p', '--python', '--with', '--index', '--index-url', '--extra-index-url'] },
  pipx: { eco: 'python', sub: 'run', pkgFlags: ['--spec'], valueFlags: ['--python', '--index-url', '--pip-args'] },
};

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const err = (rule: string, message: string): Issue => ({ rule, severity: 'error', message });
const warn = (rule: string, message: string): Issue => ({ rule, severity: 'warning', message });

// JSONC (VS Code's mcp.json allows comments). Strings are copied untouched so "http://x" survives.
export function stripJsonComments(text: string): string {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const start = i++;
      while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      out += text.slice(start, i + 1);
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? text.length : end + 1;
      out += ' ';
    } else {
      out += c;
    }
  }
  return out;
}

// A value counts as a literal secret unless it is a ${VAR}/$VAR reference, a placeholder, a path or too short.
function isLiteralSecret(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const v = value.trim().replace(/^(?:Bearer|Basic|Token)\s+/i, '');
  if (v.includes('${') || /^\$[A-Za-z_]\w*$/.test(v)) return false;
  return v.length >= 8 && !PLACEHOLDER.test(v) && !PATH_LIKE.test(v);
}

const secretPair = (name: string, value: unknown) =>
  (typeof value === 'string' && TOKEN.test(value)) || (SECRET_NAME.test(name) && isLiteralSecret(value));

// Never echo the value: the report itself ends up in CI logs.
const secret = (where: string) => err('secret', `${where} holds a literal secret; read it from the environment (for example "\${VAR}") instead of writing it in the config`);

function argSecrets(args: string[]): Issue[] {
  const issues: Issue[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const assign = /^-{0,2}([\w.-]+)=(.*)$/s.exec(a);
    const flag = /^-{1,2}([\w.-]+)$/.exec(a);
    if (TOKEN.test(a) || (assign && secretPair(assign[1], assign[2]))) {
      issues.push(secret(`argument ${i + 1}`));
    } else if (flag && SECRET_NAME.test(flag[1]) && i + 1 < args.length && !args[i + 1].startsWith('-') && isLiteralSecret(args[i + 1])) {
      issues.push(secret(`argument ${i + 2} (value of ${a})`));
      i++;
    }
  }
  return issues;
}

function mapSecrets(map: unknown, label: string): Issue[] {
  if (!isObject(map)) return [];
  return Object.entries(map).filter(([k, v]) => secretPair(k, v)).map(([k]) => secret(`${label} ${k}`));
}

// The package a runner would download, or undefined when the args run something local.
function packageSpec(args: string[], runner: Runner): string | undefined {
  let rest = args;
  if (runner.sub) {
    if (rest[0] !== runner.sub) return undefined;
    rest = rest.slice(1);
  }
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    for (const f of runner.pkgFlags) {
      if (a === f) return rest[i + 1];
      if (a.startsWith(`${f}=`)) return a.slice(f.length + 1);
    }
    if (runner.valueFlags.includes(a)) i++;
    else if (!a.startsWith('-')) return a;
  }
  return undefined;
}

const isLocal = (spec: string) => PATH_LIKE.test(spec) || spec.startsWith('file:');

// Why a package spec can resolve to different code tomorrow, or undefined when it is pinned.
export function packagePinProblem(eco: Ecosystem, spec: string): string | undefined {
  const isGit = eco === 'npm' ? /^(?:github:|gitlab:|bitbucket:|git[+:])|^[\w-]+\/[\w.-]+(?:#|$)/.test(spec) : spec.startsWith('git+');
  if (isGit) {
    const pinned = eco === 'npm' ? spec.includes('#') : (spec.split('/').pop() ?? '').includes('@');
    return pinned ? undefined : `"${spec}" has no ref, so it runs whatever the default branch holds; pin a tag or commit`;
  }
  if (eco === 'npm') {
    if (/^https?:/.test(spec)) return undefined;
    const at = spec.lastIndexOf('@');
    if (at <= 0) return `"${spec}" has no version, so every start can run a new release; pin it like ${spec}@1.2.3`;
    const version = spec.slice(at + 1);
    return EXACT_SEMVER.test(version) ? undefined : `"${spec}" uses "${version}", which can change; pin an exact version like @1.2.3`;
  }
  const exact = /^([\w.-]+)(?:\[[^\]]*\])?(==|@)([\w.!+-]+)$/.exec(spec);
  // PEP 440 versions start with a digit (an optional v is normalised away); anything else, like uvx's @latest, is a moving tag.
  if (exact) {
    const [, name, op, version] = exact;
    return /^v?\d/i.test(version) ? undefined : `"${spec}" uses "${version}", which can change; pin an exact version like ${op === '@' ? `${name}@` : '=='}1.2.3`;
  }
  if (/[<>=!~]/.test(spec)) return `"${spec}" allows a range; pin an exact version like ==1.2.3`;
  return `"${spec}" has no version, so every start can run a new release; pin it like ${spec}==1.2.3`;
}

function commandIssues(command: string, args: string[], resolve: Resolve): Issue[] {
  const issues: Issue[] = [];
  if (!resolve(command)) {
    issues.push(warn('command-not-found', `command "${command}" was not found on this machine's PATH`));
  }
  const runner = RUNNERS[basename(command).replace(/\.(?:cmd|exe|bat)$/i, '')];
  const spec = runner && packageSpec(args, runner);
  const problem = spec && !isLocal(spec) ? packagePinProblem(runner.eco, spec) : undefined;
  if (problem) issues.push(warn('unpinned', problem));
  return issues;
}

// localhost, any *.localhost name, 127.0.0.0/8 and ::1 never leave the machine (RFC 6761, RFC 1122).
const isLoopback = (host: string) =>
  host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);

function urlIssues(url: string): Issue[] {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return [err('invalid-server', `"url" is not a valid URL`)];
  }
  const issues: Issue[] = [];
  for (const [k, v] of u.searchParams) if (secretPair(k, v)) issues.push(secret(`url parameter ${k}`));
  if (u.username || u.password) issues.push(secret('url credentials'));
  if (u.protocol === 'http:' && !isLoopback(u.hostname)) {
    issues.push(warn('insecure-url', `${u.host} is reached over plain http, so requests and any auth headers travel unencrypted; use https`));
  }
  return issues;
}

export function lintServer(server: unknown, resolve: Resolve): Issue[] {
  if (!isObject(server)) return [err('invalid-server', 'server entry must be an object')];
  const { command, args = [], env, url, headers } = server;
  if (!Array.isArray(args) || args.some((a) => typeof a !== 'string')) return [err('invalid-server', '"args" must be an array of strings')];
  const mapped = [...mapSecrets(env, 'env'), ...mapSecrets(headers, 'header')];
  if (typeof command === 'string' && command) {
    // "npx some-mcp" in one string: some clients run it through a shell, others look for a file with that name.
    const inline = args.length === 0 && /\s/.test(command.trim()) && !resolve(command);
    const [cmd, ...rest] = inline ? command.trim().split(/\s+/) : [command, ...args];
    const note = inline ? [warn('command-has-args', '"command" also holds its arguments; some clients treat the whole string as one file name, so move them to "args"')] : [];
    return [...note, ...mapped, ...argSecrets(rest), ...commandIssues(cmd, rest, resolve)];
  }
  const secrets = [...mapped, ...argSecrets(args)];
  if (typeof url === 'string') return [...secrets, ...urlIssues(url)];
  return [...secrets, err('invalid-server', 'needs a "command" (stdio server) or a "url" (remote server)')];
}

// JSON.parse messages can quote the surrounding text, which may be a secret. Report the position only.
function parseError(text: string, e: unknown): string {
  const pos = Number(/position (\d+)/.exec(String(e))?.[1]);
  if (!Number.isFinite(pos)) return 'not valid JSON (comments are fine, trailing commas are not)';
  const lines = text.slice(0, pos).split('\n');
  return `not valid JSON at line ${lines.length}, column ${lines.at(-1)!.length + 1}`;
}

function serverMap(f: ConfigFile): { servers: Record<string, unknown> } | { finding: Finding } {
  const at = (rule: string, message: string) => ({ finding: { file: f.file, ...err(rule, message) } });
  let data: unknown;
  try {
    data = JSON.parse(stripJsonComments(f.text));
  } catch (e) {
    return at('invalid-json', parseError(f.text, e));
  }
  // Claude Code, Claude Desktop and Cursor use "mcpServers"; VS Code uses "servers".
  const servers = isObject(data) ? (data.mcpServers ?? data.servers) : undefined;
  if (servers === undefined) return f.optional ? { servers: {} } : at('no-servers', 'no "mcpServers" or "servers" object');
  return isObject(servers) ? { servers } : at('no-servers', 'the server list must be an object keyed by server name');
}

// Which app reads a config file. The same server name in two apps is normal; within one app, one entry hides the other.
function clientOf(file: string): string {
  const f = file.replaceAll('\\', '/');
  if (/(?:^|\/)\.(?:mcp|claude)\.json$/.test(f)) return 'Claude Code';
  if (f.endsWith('claude_desktop_config.json')) return 'Claude Desktop';
  if (/(?:^|\/)\.cursor\/mcp\.json$/.test(f)) return 'Cursor';
  if (/(?:^|\/)\.vscode\/mcp\.json$/.test(f)) return 'VS Code';
  return f;
}

export function lintFiles(files: ConfigFile[], resolve: Resolve = resolveCommand): Result {
  const findings: Finding[] = [];
  const seen = new Map<string, string[]>();
  let count = 0;
  for (const f of files) {
    const parsed = serverMap(f);
    if ('finding' in parsed) {
      findings.push(parsed.finding);
      continue;
    }
    for (const [name, server] of Object.entries(parsed.servers)) {
      count++;
      const key = `${clientOf(f.file)}\0${name}`;
      seen.set(key, [...(seen.get(key) ?? []), f.file]);
      findings.push(...lintServer(server, resolve).map((i) => ({ file: f.file, server: name, ...i })));
    }
  }
  for (const [key, where] of seen) {
    const [client, name] = key.split('\0');
    if (where.length > 1) {
      findings.push({ file: where[0], server: name, ...warn('duplicate-name', `"${name}" is defined for ${client} in ${where.join(' and ')}; one silently overrides the other`) });
    }
  }
  return { files: files.map((f) => f.file), servers: count, findings };
}

const isFile = (p: string) => {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
};

export const resolveCommand: Resolve = (command) => {
  if (/[\\/]/.test(command)) return isFile(command);
  const exts = process.platform === 'win32' ? ['', ...(process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';')] : [''];
  return (process.env.PATH ?? '').split(delimiter).some((dir) => dir && exts.some((e) => isFile(join(dir, command + e))));
};
