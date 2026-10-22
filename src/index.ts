#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { lintFiles, RULES, type ConfigFile, type Finding } from './lint.js';

const PROJECT_CONFIGS = ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json'];
const USAGE = `Usage: mcp-config-lint [--json] [--strict] [--user] [--ignore <rule>]... [file...]

With no files, lints the MCP configs in the current folder: ${PROJECT_CONFIGS.join(', ')}.
  --user    also lint your user configs (Claude Code, Claude Desktop, Cursor)
  --strict  fail on warnings too
  --ignore  skip a rule; repeatable. Rules: ${RULES.join(', ')}
  --json    print the report as JSON, for agents and scripts

Exit codes: 0 no errors, 1 an error (or a warning with --strict), 2 bad usage or no config found.`;

const die = (msg: string): never => {
  process.stderr.write(`mcp-config-lint: ${msg}\n\n${USAGE}\n`);
  process.exit(2);
};

function readArgs() {
  try {
    return parseArgs({
      allowPositionals: true,
      options: {
        json: { type: 'boolean', default: false },
        strict: { type: 'boolean', default: false },
        user: { type: 'boolean', default: false },
        ignore: { type: 'string', multiple: true, default: [] },
        help: { type: 'boolean', short: 'h', default: false },
      },
    });
  } catch (e) {
    return die(e instanceof Error ? e.message : String(e));
  }
}

function userConfigs(): string[] {
  const home = homedir();
  const desktop = {
    darwin: join(home, 'Library', 'Application Support', 'Claude'),
    win32: join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'Claude'),
  }[process.platform as string] ?? join(home, '.config', 'Claude');
  return [join(home, '.claude.json'), join(desktop, 'claude_desktop_config.json'), join(home, '.cursor', 'mcp.json')];
}

const read = (file: string, optional = false): ConfigFile => {
  try {
    return { file: file.replace(homedir(), '~'), text: readFileSync(file, 'utf8'), optional };
  } catch (e) {
    return die(`cannot read ${file}: ${e instanceof Error ? e.message : String(e)}`);
  }
};

const { values, positionals } = readArgs();
if (values.help) {
  process.stdout.write(`${USAGE}\n`);
  process.exit(0);
}

// User configs often hold only app settings, so a missing server list there is not an error.
const files = positionals.length
  ? positionals.map((f) => read(f))
  : [
    ...PROJECT_CONFIGS.filter((f) => existsSync(f)).map((f) => read(f)),
    ...(values.user ? userConfigs().filter((f) => existsSync(f)).map((f) => read(f, true)) : []),
  ];
if (!files.length) die(`no MCP config found here${values.user ? ' or in your user configs' : ''}; pass a file${values.user ? '' : ' or use --user'}`);

const ignored = new Set<string>(values.ignore);
for (const rule of ignored) if (!(RULES as readonly string[]).includes(rule)) die(`unknown rule "${rule}"`);
const linted = lintFiles(files);
const result = { ...linted, findings: linted.findings.filter((f) => !ignored.has(f.rule)) };
const errors = result.findings.filter((f) => f.severity === 'error').length;
const warnings = result.findings.length - errors;
const ok = errors === 0 && (!values.strict || warnings === 0);

function text(): string {
  const lines: string[] = [];
  for (const file of result.files) {
    const mine = result.findings.filter((f) => f.file === file);
    lines.push(`${mine.length ? '✖' : '✔'} ${file}`);
    lines.push(...mine.map((f: Finding) => `  ${f.severity === 'error' ? 'error' : 'warn '} ${f.server ? `${f.server}: ` : ''}${f.message} [${f.rule}]`));
  }
  lines.push(`${result.files.length} file(s), ${result.servers} server(s): ${errors} error(s), ${warnings} warning(s)`);
  return lines.join('\n');
}

const out = values.json ? JSON.stringify({ ok, ...result }, null, 2) : text();
process.stdout.write(`${out}\n`, () => process.exit(ok ? 0 : 1));
