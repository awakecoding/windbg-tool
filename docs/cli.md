# CLI guide

`windbg-tool.exe` can act as a local discovery tool, a daemon-backed TTD client, a DbgEng helper, and a WinDbg launcher/updater.

## How the CLI is organized

- **Discovery commands** do not require the daemon: `discover`, `cli-schema`, `recipes`, `tools`, `schema`, `trace-list`, `symbols inspect`
- **Replay commands** usually talk to the local daemon and operate on a `session_id` and `cursor_id`
- **Recording commands** use the separately installed Microsoft `TTD.exe` recorder and do not require the daemon
- **Canonical agent debugging commands** start with `debug`, `triage`, `symbols doctor`, and `breakpoint plan`
- **Platform helper commands** cover DbgEng, remote debugging doctors/plans, live-launch probing, and WinDbg installation

## Common replay workflow

Start or reuse the local daemon:

```powershell
target\debug\windbg-tool.exe daemon ensure
```

Open a trace and create a cursor in one step:

```powershell
target\debug\windbg-tool.exe open C:\path\to\trace.run --binary-path C:\path\to\binary.exe
```

Rediscover active sessions and cursors later:

```powershell
target\debug\windbg-tool.exe sessions
```

Use the returned handles with analysis commands:

```powershell
target\debug\windbg-tool.exe info --session 1
target\debug\windbg-tool.exe debug snapshot --session 1 --cursor 1
target\debug\windbg-tool.exe position set --session 1 --cursor 1 --position 50
target\debug\windbg-tool.exe registers --session 1 --cursor 1
target\debug\windbg-tool.exe disasm --session 1 --cursor 1
target\debug\windbg-tool.exe memory strings --session 1 --cursor 1 --address 0x12345678 --size 256 --encoding both
```

`open` is the preferred starting point because it loads the trace, creates a cursor, and optionally seeks to a position in one response. `debug snapshot` is the canonical cross-backend snapshot for agents; `context snapshot` remains available as the legacy TTD-focused snapshot.

## Record a trace

`trace record` launches a target with the Microsoft `TTD.exe` command-line recorder, waits for it to exit, and emits the resulting `.run` path. It uses TTD's documented `-noUI -out <path> -launch <target command line>` invocation; the target command line is passed directly, not through a shell. Because TTD recording requires elevation, it runs TTD directly from an elevated terminal or automatically invokes Windows 11 `sudo` when it is configured for the synchronous **Input Closed** or **Inline** mode. Force New Window mode is rejected because it returns before the recorder completes.

Install the standalone TTD recorder with `winget install --id Microsoft.TimeTravelDebugging`, then open a new elevated terminal so `ttd.exe` is on `PATH`. You can also set `TTD_EXE` or pass `--ttd-exe`. `trace record` always passes TTD's `-accepteula` option.

```powershell
target\debug\windbg-tool.exe --compact trace record `
  --output C:\traces\rdm.run `
  --command-line '"C:\apps\RemoteDesktopManager.exe" /AutoCloseAfter:10'
```

The output directory must already exist and the `.run` path must not already exist. `--max-file-mb` bounds trace growth; combine it with `--ring` to retain only the most recent recording window. TTD traces include process-memory data and should be handled as sensitive artifacts.

To enable synchronous sudo recording, choose **Input Closed** or **Inline** in **Settings > System > Advanced > Enable sudo**, or from an elevated terminal run:

```powershell
sudo config --enable disableInput
```

## Canonical agent debugging commands

Use `debug capabilities` before choosing actions. With no subject it returns a backend matrix for TTD cursors, daemon-owned live/dump targets, and remote process-server plans. With `--session/--cursor` or `--target`, it includes selected-subject status/evidence where available.

```powershell
target\debug\windbg-tool.exe --compact debug capabilities
target\debug\windbg-tool.exe --compact debug capabilities --session 1 --cursor 1
target\debug\windbg-tool.exe --compact debug capabilities --target 1
```

Use `debug snapshot` for bounded, sectioned context capture. Each section has independent status, duration, truncation, diagnostics, and the primitive follow-up command. TTD subjects use `--session` and `--cursor`; live or dump subjects use `--target`.

```powershell
target\debug\windbg-tool.exe --compact debug snapshot --session 1 --cursor 1 --include stack --include current_disassembly
target\debug\windbg-tool.exe --compact debug snapshot --target 1 --max-frames 16 --max-modules 32
```

Use `triage <kind>` for evidence plus hypotheses rather than a verdict-only answer:

```powershell
target\debug\windbg-tool.exe --compact triage crash --session 1 --cursor 1
target\debug\windbg-tool.exe --compact triage hang --target 1
```

Use `symbols doctor` and `breakpoint plan` when an agent needs to validate names/source paths or dry-run a mutation:

```powershell
target\debug\windbg-tool.exe --compact symbols doctor --session 1 --cursor 1 --address 0x7ff600001000
target\debug\windbg-tool.exe --compact breakpoint plan --target 1 --address 0x7ff600001000
target\debug\windbg-tool.exe --compact breakpoint plan --session 1 --cursor 1 --address 0x12345678 --kind write --size 8 --direction previous
```

## Remote debugging doctors and plans

`remote doctor`, `remote status`, and `remote plan` are read-only helpers for DbgEng process-server style workflows. TCP connect probing is opt-in because it can be visible to network monitoring.

```powershell
target\debug\windbg-tool.exe --compact remote doctor --transport tcp:port=5005
target\debug\windbg-tool.exe --compact remote status --server target-host --transport tcp:port=5005 --probe-connect --timeout-ms 1000
target\debug\windbg-tool.exe --compact remote plan --server target-host --transport tcp:port=5005
```

## Optional agent action log

Set `WINDBG_TOOL_ACTION_LOG` to append one JSONL entry per CLI invocation. By default entries include only the command path, success status, exit code, and duration; raw arguments are redacted. Set `WINDBG_TOOL_ACTION_LOG_FULL=1` only when full command-line logging is safe for your environment.

```powershell
$env:WINDBG_TOOL_ACTION_LOG = "D:\logs\windbg-tool-actions.jsonl"
target\debug\windbg-tool.exe --compact debug capabilities
target\debug\windbg-tool.exe --compact debug log summarize --path D:\logs\windbg-tool-actions.jsonl
```

## Session and cursor basics

- `session_id` identifies the loaded trace
- `cursor_id` identifies a replay cursor inside that trace
- Many commands accept `-s` for `--session` and `-c` for `--cursor`
- `position set` accepts either a structured position, a WinDbg-style `HEX:HEX` string, or a percentage from `0` to `100`

## Output shaping

CLI output is JSON by default. These flags make it easier to script:

- `--compact` for single-line JSON
- `--field <dot.path>` to extract one field
- `--raw` to print scalar values without JSON quotes
- `--envelope` or `WINDBG_TOOL_ENVELOPE=1` to wrap success and failure output in a stable agent contract

Example:

```powershell
target\debug\windbg-tool.exe --field session_id --raw open C:\path\to\trace.run
target\debug\windbg-tool.exe --compact registers --session 1 --cursor 1
target\debug\windbg-tool.exe --compact --envelope sessions
```

In envelope mode, successful commands return `{ "schema_version": 1, "ok": true, "data": ... }`. `--field` selects from `data`, so `--envelope --field session_id --raw open ...` still prints the raw session id. Failures return `{ "schema_version": 1, "ok": false, "error": ... }` and ignore `--field`/`--raw` so agents always receive the full error reason.

Structured error codes use stable exit codes:

| Code | Exit | Retryable |
| --- | ---: | --- |
| `invalid_argument` | 2 | false |
| `daemon_unavailable` | 3 | true |
| `daemon_error` | 4 | depends on cause |
| `session_not_found` | 5 | false |
| `cursor_not_found` | 6 | false |
| `timeout` | 7 | true |
| `tool_error` | 8 | depends on cause |
| `internal` | 1 | false |

Daemon connection failures include the selected pipe and a hint to run `windbg-tool daemon ensure`.

## CLI schema discovery

Use `cli-schema` for machine-readable command paths, arguments, possible values, defaults, conflicts, and command metadata:

```powershell
target\debug\windbg-tool.exe --compact cli-schema
target\debug\windbg-tool.exe --compact cli-schema memory read
```

The schema includes curated metadata where available and inferred metadata for other leaf commands. Bounded collection outputs include additive `returned`, `limit`, and `truncated` fields when the command has a fixed result budget.

## Command groups worth learning first

| Goal | Commands |
| --- | --- |
| Discover capabilities | `discover`, `cli-schema [command...]`, `recipes`, `tools`, `schema <tool>` |
| Canonical agent context | `debug capabilities`, `debug snapshot`, `triage <kind>`, `symbols doctor`, `breakpoint plan`, `debug log summarize` |
| Manage daemon/session state | `daemon ensure`, `daemon status`, `sessions`, `open`, `load`, `close`, `info` |
| Capture a new trace | `trace record --output <trace.run> --command-line <target-command-line>` |
| Move through a trace | `cursor create`, `position get`, `position set`, `step`, `replay to`, `replay watch-memory`, `sweep watch-memory` |
| Inspect trace metadata | `threads`, `modules`, `exceptions`, `keyframes`, `timeline events`, `module info`, `module audit` |
| Inspect runtime state | `registers`, `register-context`, `active-threads`, `command-line`, `architecture state` |
| Inspect code and memory | `disasm`, `memory read`, `memory dump`, `memory strings`, `memory dps`, `memory classify`, `memory chase`, `object vtable` |
| Symbol and source triage | `symbols doctor`, `symbols diagnose`, `symbols inspect`, `symbols exports`, `symbols nearest`, `source resolve` |
| WinDbg, live, dump, and remote helpers | `remote explain`, `remote doctor`, `remote status`, `remote plan`, `remote server-command`, `remote connect-command`, `dbgeng server`, `live capabilities`, `dump create`, `dump open`, `dump inspect`, `target dump`, `windbg status` |

## Useful non-replay commands

These are good starting points even before you have a trace open:

```powershell
target\debug\windbg-tool.exe discover
target\debug\windbg-tool.exe recipes
target\debug\windbg-tool.exe debug capabilities
target\debug\windbg-tool.exe remote doctor --transport tcp:port=5005
target\debug\windbg-tool.exe symbols inspect C:\Windows\System32\notepad.exe
target\debug\windbg-tool.exe windbg status
```

## Working with multiple workspaces

Use `--pipe \\.\pipe\windbg-tool-custom` or set `WINDBG_TOOL_PIPE` to isolate concurrent daemon instances. The legacy `TTD_MCP_PIPE` variable is also honored.

## Next docs

- For MCP setup and tool flow, see [mcp.md](mcp.md)
- For build, native runtime, and local test details, see [development.md](development.md)
