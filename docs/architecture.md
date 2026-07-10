# Architecture

`windbg-tool` is a Windows-first WinDbg automation workspace. Its single executable hosts the `windbg-ttd` MCP server/daemon/client commands, plus broader WinDbg helpers such as DbgEng process-server launch, one-shot live DbgEng launch, WinDbg package install/update/launch, local diagnostic recipes, remote debugging command generation, unified trace timelines, target capability discovery, PE/PDB/export symbol readiness diagnostics, source path resolution, explicit architecture-state discovery, x64 disassembly, read-only module/object/vtable inspection, stack recovery, memory classification/string/pointer views, and agent-ready context snapshots.

The TTD replay surface is split into three layers:

1. Rust MCP server over stdio using the official `rmcp` Rust MCP SDK. This owns MCP protocol transport, tool schemas, session ids, validation, symbol-path settings, and packaging workflow.
2. Safe Rust replay facade. This keeps TTD positions, sessions, cursors, memory reads, modules, threads, and exceptions in serializable Rust types.
3. Native C++ replay bridge. This is a narrow C ABI over Microsoft's C++ TTD Replay API from `Microsoft.TimeTravelDebugging.Apis`.

The C++ bridge exists because the public TTD API is C++-oriented. Rust should not bind directly to TTD C++ vtables, STL helpers, or lifetime rules. The bridge exposes opaque handles and simple POD values.

## Dependencies

Build-time SDK inputs come from NuGet:

- `Microsoft.TimeTravelDebugging.Apis` for headers and import libraries.
- `Microsoft.Debugging.Platform.SymSrv` for Microsoft symbol-server compatible downloads.
- `Microsoft.Debugging.Platform.SrcSrv` for source-server support alongside public symbols.
- `Microsoft.Debugging.Platform.DbgEng` for DbgEng process-server headers, import libraries, and redistributable runtime DLLs.

Runtime replay requires `TTDReplay.dll` and `TTDReplayCPU.dll`. Microsoft samples acquire these from the WinDbg/TTD MSIX distribution rather than a separate public NuGet package. Use:

```powershell
cargo xtask deps
```

or run [scripts/Get-TtdReplayRuntime.ps1](../scripts/Get-TtdReplayRuntime.ps1) directly.

The native replay bridge has a CMake project at [native/ttd-replay-bridge/CMakeLists.txt](../native/ttd-replay-bridge/CMakeLists.txt). `cargo xtask native-build` configures it against the restored `Microsoft.TimeTravelDebugging.Apis` package and emits the bridge under `target/native/ttd-replay-bridge`. Release packaging can pass `--arch amd64` or `--arch arm64` plus `--static-crt` so cross-compiled packages use the matching native bridge and statically link the MSVC runtime.

Live managed breakpoints use a separate [CoreCLR DAC bridge](../native/coreclr-dac-bridge/CMakeLists.txt), never the TTD bridge. It is a narrow C ABI that receives the active DbgEng client, hosts a version- and architecture-matched `mscordaccore.dll`, and implements `ICLRDataTarget` using DbgEng module, memory, thread, and context services. It uses the stable CLR metadata import contract to compare exact raw ECMA-335 `MethodDef` signature bytes when the caller selects an overload, while reporting bounded token/signature diagnostics for name matches. It resolves metadata through a method definition, then obtains the matching method instance after code-generation notification; only that instance supplies the JIT-native breakpoint address. Its opt-in `ICLRDataTarget2` implementation uses DbgEng's active process handle solely for the CLR-requested JIT-notification-table allocation; the CLR then owns that allocation. It exposes only opaque handles and POD output for module/method resolution, CLR notification registration, and representative generated-code addresses. It does not attach `ICorDebug`, load SOS, invoke debugger extension commands, hollow the process, or inject managed code. The x64 bridge is staged separately under `target/native/coreclr-dac-bridge`; the target DAC remains runtime-provided and is not redistributed.

## Symbols

The default symbol path is equivalent to:

```text
srv*.ttd-symbol-cache*https://msdl.microsoft.com/download/symbols
```

`cargo xtask deps` stages `dbghelp.dll`, `symsrv.dll`, and `srcsrv.dll` from Microsoft Debugging Platform NuGet packages into `target/symbol-runtime`, and stages DbgEng process-server runtime DLLs into `target/dbgeng-runtime`. Architecture-explicit release staging uses `target/runtime/<arch>/...` to keep x64 and ARM64 DLLs separate. Keep this repo-local and process-local; do not set machine-wide `_NT_SYMBOL_PATH` or write debugger registry keys as part of normal server operation. If `_NT_SYMBOL_PATH` is already set in the server process environment, use it as a fallback only when the MCP request does not provide explicit `symbols.symbol_paths`.

Callers can provide additional binary paths, symbol paths, and a symbol cache directory when loading a trace. Public symbols are useful for module/function names. Private symbols are needed for richer function signatures and local details.

The Rust facade resolves caller settings into a process-local symbol configuration before opening a trace. That resolved configuration includes the symbol path, image path, cache directory, and symbol runtime directory, and the native bridge open ABI accepts those fields directly.

## Current State

The Rust MCP server uses `rmcp` for stdio MCP protocol handling, and the native bridge boundary is scaffolded, built, and wired for the first native replay slices. The server can advertise tools, validate inputs, load a trace through `ttd_mcp_open_trace`, read `ttd_mcp_trace_info`, enumerate trace-wide threads/modules/exceptions/keyframes, list cursor-local module snapshots, list module and thread lifecycle events, create cursors, get/set cursor positions including TTD thread-scoped seeking, list active cursor threads with runtime PCs, step or trace cursors forward/backward, read compact and x64 scalar/SIMD cursor register/thread state, read bounded guest memory with selectable TTD query policies, query trace-backed memory ranges and provenance-rich memory buffers at a cursor, replay to memory watchpoints, and extract the process command line from PEB process parameters. The CLI discovery layer also exposes TimDbg-inspired recipes, remote-debugging command generation, one-shot `live launch`, DbgHelp-backed `dump create`, daemon-backed `target dump`, `target capabilities`, `timeline events`, `symbols diagnose`/`symbols inspect`/`symbols exports`/`symbols nearest`, `source resolve`, `architecture state`, `module audit`, x64 `disasm`, `object vtable`, `stack recover`, `memory strings`, `memory dps`, `memory chase`, and a `context snapshot` command that composes daemon/session/cursor state, architecture, current disassembly, nearest-export fallback, and a bounded timeline into a single JSON object for agent skills. The next implementation step is to expand deeper PDB line/source diagnostics, daemon-backed live sessions, real unwind metadata, live/dump disassembly support, and callback-backed bounded replay sweeps for call tracing and event collection.
