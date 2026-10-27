# mcp-config-lint

[![CI](https://github.com/zafmy/mcp-config-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/zafmy/mcp-config-lint/actions/workflows/ci.yml)

Check your MCP client configs before your agent runs them. It finds tokens pasted into `.mcp.json`, servers that pull an unpinned package from npm or PyPI on every start, commands that won't start, and remote servers on plain http.

It reads files only. It makes no network calls, runs none of your servers, needs no API key or model, and has no runtime dependencies. It never prints a secret's value, so the report is safe to paste into a CI log or an issue.

```text
$ npx -y github:zafmy/mcp-config-lint
✖ .mcp.json
  error github: env GITHUB_PERSONAL_ACCESS_TOKEN holds a literal secret; read it from the environment (for example "${VAR}") instead of writing it in the config [secret]
  warn  github: "@modelcontextprotocol/server-github" has no version, so every start can run a new release; pin it like @modelcontextprotocol/server-github@1.2.3 [unpinned]
  warn  fetch: "command" also holds its arguments; some clients treat the whole string as one file name, so move them to "args" [command-has-args]
  warn  fetch: "mcp-server-fetch" has no version, so every start can run a new release; pin it like mcp-server-fetch==1.2.3 [unpinned]
  warn  notes: mcp.example.com is reached over plain http, so requests and any auth headers travel unencrypted; use https [insecure-url]
1 file(s), 3 server(s): 1 error(s), 4 warning(s)
```

## Use

```bash
npx -y github:zafmy/mcp-config-lint            # project configs in this folder
npx -y github:zafmy/mcp-config-lint --user     # plus your user-level configs
npx -y github:zafmy/mcp-config-lint path/to/mcp.json
```

With no files it lints the project configs in the current folder: `.mcp.json` (Claude Code), `.cursor/mcp.json` (Cursor) and `.vscode/mcp.json` (VS Code). `--user` adds `~/.claude.json`, the Claude Desktop config and `~/.cursor/mcp.json`. Comments in the JSON are fine, since VS Code allows them.

| Option | What it does |
|---|---|
| `--user` | Also lint your user-level configs |
| `--strict` | Fail on warnings too, not only errors |
| `--ignore <rule>` | Skip a rule. Repeat it to skip more than one |
| `--json` | Print the report as JSON, for agents and scripts |

Exit codes: `0` no errors, `1` an error (or a warning with `--strict`), `2` bad usage or no config found.

## Rules

| Rule | Level | What it catches |
|---|---|---|
| `secret` | error | A token or password written straight into `env`, `headers`, `args`, or the URL. It matches known token formats (GitHub, Anthropic, OpenAI, Slack, AWS, GitLab, Google, npm) anywhere, plus any literal value under a name like `*_TOKEN`, `*_API_KEY` or `*PASSWORD`. A `${VAR}` reference, a placeholder like `<your-key>`, or a file path is fine |
| `unpinned` | warning | `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx` or `pipx run` fetching a package with no exact version (`pkg`, `pkg@latest`, `pkg@^1`, `pkg>=1`), or a git source with no ref. Whoever controls that package controls your agent's tools on the next start |
| `command-not-found` | warning | The command isn't on this machine's `PATH`, or the absolute path doesn't exist |
| `command-has-args` | warning | `"command": "npx some-mcp"` with the arguments packed into one string. It is still checked for secrets and pinning |
| `insecure-url` | warning | A remote server reached over `http://` to anything other than a loopback host (`localhost`, `*.localhost`, `127.x.x.x`, `[::1]`) |
| `duplicate-name` | warning | The same server name twice for one client, for example in both `.mcp.json` and `~/.claude.json`, where one silently hides the other. The same name in two different apps is fine |
| `invalid-server` | error | An entry with neither `command` nor `url`, non-string `args`, or a malformed URL |
| `invalid-json` / `no-servers` | error | A file that isn't valid JSON, or has no `mcpServers`/`servers` object. It reports the line and column only, never the text around the error |

Whether `${VAR}` gets expanded depends on the client. Claude Code expands `${VAR}` in `.mcp.json`, and VS Code supports `${env:VAR}` and `${input:...}`. If your client doesn't expand variables, start the server from a small wrapper script that reads the secret from your OS keychain.

## In CI

```yaml
- run: npx -y github:zafmy/mcp-config-lint#v0.1.0 --strict --ignore command-not-found
```

Skip `command-not-found` in CI, because the runner won't have the tools your editor uses. Pin a release tag or commit, for the same reason this tool exists.

## Scope

It covers the three config formats above, checks each file on its own terms, and stays offline. It does not fix anything, check whether a pinned version is safe, or look inside the servers. For that, run [mcp-smoke](https://github.com/zafmy/mcp-smoke) against the server itself.

## Develop

```bash
npm install
npm test
```

## License

MIT
