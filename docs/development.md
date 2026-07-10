# Development and advanced setup

This page keeps the deeper setup and contributor-oriented material out of the main README while preserving the details needed to build and work on the project.

## Workspace structure

| Path | Purpose |
| --- | --- |
| `Cargo.toml` | Workspace root |
| `crates\windbg-tool` | Main CLI binary crate |
| `crates\windbg-ttd` | MCP server, daemon, replay facade, and tool definitions |
| `crates\windbg-dbgeng` | DbgEng process-server and live-launch helpers |
| `crates\windbg-install` | WinDbg package install/update/launch support |
| `xtask` | Developer workflow commands |
| `native\ttd-replay-bridge` | C++ bridge to the TTD Replay API |
| `scripts\Get-TtdReplayRuntime.ps1` | Runtime acquisition helper |
| `docs\architecture.md` | Architecture notes and layering details |

## Build and check commands

Run these from the repository root:

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p windbg-tool
```

## Dependency and native setup

Use a Visual Studio Developer PowerShell, or another environment where `nuget`, `cmake`, `msbuild`, and `powershell` are available:

```powershell
cargo xtask doctor
cargo xtask deps
cargo xtask native-build
```

`cargo xtask deps`:

- restores native NuGet packages into `target\nuget`
- stages `dbghelp.dll`, `symsrv.dll`, and `srcsrv.dll` into `target\symbol-runtime`
- stages DbgEng runtime DLLs into `target\dbgeng-runtime`
- downloads `TTDReplay.dll` and `TTDReplayCPU.dll` into `target\ttd-runtime`

`cargo xtask native-build` configures and builds the C++ bridge under `target\native\ttd-replay-bridge`.

For release packaging, use explicit target architecture inputs so the Rust binary, native bridge, and staged debugger runtime DLLs all match:

```powershell
$env:RUSTFLAGS = "-C target-feature=+crt-static"
rustup target add x86_64-pc-windows-msvc
cargo xtask deps --arch amd64
cargo xtask native-build --arch amd64 --static-crt
cargo build -p windbg-tool --release --target x86_64-pc-windows-msvc
cargo xtask package --arch amd64 --target x86_64-pc-windows-msvc --profile release --out target\package\windbg-tool-x64
```

Use `--arch arm64` with `--target aarch64-pc-windows-msvc` for the Windows ARM64 package. Architecture-specific dependency staging uses `target\runtime\<arch>\...`, while the legacy no-argument `cargo xtask deps`, `cargo xtask native-build`, and `cargo xtask package` commands keep using the existing host-architecture directories.

Release packages statically link the MSVC C runtime into Rust code with `RUSTFLAGS=-C target-feature=+crt-static` and into the native bridge with `cargo xtask native-build --static-crt`. WinDbg, DbgEng, symbol, and TTD replay runtime DLLs remain dynamic dependencies and are copied into the package directory.

For a development build that uses architecture-specific staged DbgEng DLLs, set the process-local runtime directory before using a live DbgEng command:

```powershell
$env:WINDBG_DBGENG_RUNTIME_DIR = (Resolve-Path target\runtime\amd64\dbgeng-runtime)
target\debug\windbg-tool.exe live capabilities
```

The live backend securely preloads `dbgeng.dll` from this directory (or from beside `windbg-tool.exe` in a package) so its dependent DLLs resolve from the matching runtime set. It does not alter global DLL-search or security policy.

Cross-compiling the ARM64 package from an x64 machine requires the Visual Studio ARM64 MSVC toolset and an `x64_arm64` developer environment for the native bridge and Rust crates that compile C/C++ code.

### Publishing a GitHub Release

Run the **Windows packages** workflow with **Run workflow** and enter an unprefixed semantic version such as `0.1.0`. After both package matrix jobs complete, the workflow creates the `v0.1.0` tag at the commit selected for the dispatch and publishes a GitHub Release containing:

- `windbg-tool-x64.zip`
- `windbg-tool-arm64.zip`

Select **dry_run** to build both ZIPs, validate their contents, validate the version, and confirm that the tag is available without creating a tag or GitHub Release. The workflow rejects existing tags and invalid versions rather than replacing a release. Each ZIP contains the statically linked Rust executable and native bridge plus the required dynamic TTD Replay, DbgEng, and symbol runtime DLLs.

To smoke-test the packaged MCP server:

```powershell
cargo xtask mcp-smoke
```

## Native dependencies

Native package restore is driven by `native\ttd-replay-bridge\packages.config`.

Important packages:

- `Microsoft.TimeTravelDebugging.Apis`
- `Microsoft.Debugging.Platform.SymSrv`
- `Microsoft.Debugging.Platform.SrcSrv`
- `Microsoft.Debugging.Platform.DbgEng`

Runtime replay still depends on `TTDReplay.dll` and `TTDReplayCPU.dll` from the WinDbg/TTD distribution.

## Symbols

When neither `_NT_SYMBOL_PATH` nor `_NT_ALT_SYMBOL_PATH` is set, the TTD replay default symbol path is equivalent to:

```text
srv*.ttd-symbol-cache*https://msdl.microsoft.com/download/symbols
```

The project keeps symbol/runtime setup repo-local and process-local. It does not write debugger registry keys or machine-wide symbol environment values. For TTD and DbgEng sessions, explicit paths take precedence over `_NT_SYMBOL_PATH`; `_NT_SYMBOL_PATH` is searched before `_NT_ALT_SYMBOL_PATH`; and explicit cache settings take precedence over `_NT_SYMCACHE_PATH`. If none sets a cache, TTD uses `.ttd-symbol-cache` and DbgEng uses `.windbg-symbol-cache`.

## Sample trace fixture

The repository keeps a reusable sample trace archive at `traces\ping.7z`. Extracted contents under `traces\ping\` are local-only and ignored by git.

After extraction, the fixture layout is:

```text
traces\ping\ping01.run
traces\ping\ping01.idx
traces\ping\ping.exe
```

If `7z` or `7zz` is not on `PATH`, set `TTD_TEST_7Z` to the extractor path.

## Local replay tests

Strict local replay checks:

```powershell
$env:TTD_RUNTIME_DIR = "D:\dev\windbg-tool\target\ttd-runtime"
$env:TTD_MCP_EXPECT_NATIVE_REPLAY = "1"
cargo test -p windbg-ttd --test ping_trace
cargo test -p windbg-tool --test daemon_cli
```

To force a custom trace instead of the committed archive fixture, set `TTD_TEST_TRACE` to a `.run` file path.

## Hygiene and safety

- Treat `.run`, `.idx`, `.ttd`, `.pdb`, `.dll`, and `.exe` artifacts as local-only unless explicitly requested otherwise
- Do not commit extracted traces or downloaded Microsoft runtime binaries
- Keep reusable trace fixtures compressed as `.7z`

## Related docs

- [README.md](../README.md)
- [architecture.md](architecture.md)
- [cli.md](cli.md)
- [mcp.md](mcp.md)
