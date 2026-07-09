use anyhow::{bail, ensure, Context};
use serde_json::{json, Value};
use std::env;
use std::ffi::OsString;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use windbg_dbgeng::{
    live_launch_initial_break, open_dump_session, start_process_server, write_process_dump,
    DumpKind, DumpOpenOptions, DumpWriteOptions, LiveLaunchEnd, LiveLaunchOptions,
    ProcessDumpOptions, ProcessServerOptions,
};
use windbg_install::WindbgManager;

use super::output::{print_value, OutputOptions};
use super::{
    CliDumpKind, DbgEngServerArgs, DumpCreateArgs, DumpInspectArgs, LiveLaunchArgs,
    TraceRecordArgs, WindbgCommand,
};

pub(super) fn run_dbgeng_server(
    args: DbgEngServerArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let result = start_process_server(ProcessServerOptions {
        transport: args.transport,
    })?;
    print_value(serde_json::to_value(result)?, output)
}

pub(super) fn run_live_launch(args: LiveLaunchArgs, output: &OutputOptions) -> anyhow::Result<()> {
    let end = match args.end.as_str() {
        "detach" => LiveLaunchEnd::Detach,
        "terminate" => LiveLaunchEnd::Terminate,
        other => bail!("unsupported live launch end action: {other}"),
    };
    let result = live_launch_initial_break(LiveLaunchOptions {
        command_line: args.command_line,
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        end,
    })?;
    print_value(
        json!({
            "result": result,
            "session_persistence": "one_shot",
            "notes": [
                "This is the first live DbgEng primitive, not the daemon-backed live session manager.",
                "Use --end detach to leave the process running or --end terminate for disposable test targets."
            ]
        }),
        output,
    )
}

pub(super) fn run_trace_record(
    args: TraceRecordArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let plan = trace_record_plan(&args)?;
    let status = command_from_trace_record_plan(&plan)
        .status()
        .with_context(|| format!("launching TTD recorder {}", plan.ttd_exe.display()))?;
    ensure!(
        status.success(),
        "TTD recorder exited with {}",
        status
            .code()
            .map_or_else(|| "no exit code".to_string(), |code| code.to_string())
    );
    ensure!(
        plan.output.is_file(),
        "TTD recorder completed without creating {}",
        plan.output.display()
    );

    let artifact_paths = trace_artifact_paths(&plan.output);
    print_value(
        json!({
            "recorder": plan.ttd_exe,
            "output": plan.output,
            "command_line": plan.command_line,
            "exit_code": status.code(),
            "artifacts": artifact_paths,
            "notes": [
                "TTD recording is invasive and can significantly slow the target process.",
                "The trace is finalized after the launched target exits.",
                "TTD traces can contain sensitive process-memory data."
            ]
        }),
        output,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceRecordPlan {
    ttd_exe: PathBuf,
    output: PathBuf,
    command_line: String,
    recorder_args: Vec<OsString>,
}

fn trace_record_plan(args: &TraceRecordArgs) -> anyhow::Result<TraceRecordPlan> {
    ensure!(
        !args.command_line.trim().is_empty(),
        "--command-line must not be empty"
    );
    ensure!(
        args.output
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("run")),
        "--output must name a .run trace file"
    );
    let output_parent = args
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure!(
        output_parent.is_dir(),
        "trace output directory does not exist: {}",
        output_parent.display()
    );
    ensure!(
        !args.output.exists(),
        "trace output already exists: {}",
        args.output.display()
    );

    let ttd_exe = resolve_ttd_exe(args.ttd_exe.as_deref())?;
    let mut recorder_args = vec![
        OsString::from("-noUI"),
        OsString::from("-out"),
        args.output.as_os_str().to_os_string(),
    ];
    if args.accept_eula {
        recorder_args.push(OsString::from("-accepteula"));
    }
    if args.children {
        recorder_args.push(OsString::from("-children"));
    }
    if let Some(max_file_mb) = args.max_file_mb {
        ensure!(max_file_mb > 0, "--max-file-mb must be greater than zero");
        recorder_args.push(OsString::from("-maxFile"));
        recorder_args.push(OsString::from(max_file_mb.to_string()));
    }
    if args.ring {
        recorder_args.push(OsString::from("-ring"));
    }
    recorder_args.push(OsString::from("-launch"));

    Ok(TraceRecordPlan {
        ttd_exe,
        output: args.output.clone(),
        command_line: args.command_line.clone(),
        recorder_args,
    })
}

fn command_from_trace_record_plan(plan: &TraceRecordPlan) -> Command {
    let mut command = Command::new(&plan.ttd_exe);
    command.args(&plan.recorder_args);
    // TTD requires its target command line after -launch. raw_arg preserves the caller's
    // Windows command-line quoting without introducing a shell.
    command.raw_arg(&plan.command_line);
    command
}

fn resolve_ttd_exe(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return validate_ttd_exe(path);
    }
    if let Some(path) = env::var_os("TTD_EXE") {
        return validate_ttd_exe(Path::new(&path));
    }
    find_executable_on_path("ttd.exe").context(
        "could not find TTD.exe; install the Microsoft Time Travel Debugging command-line utility, add it to PATH, set TTD_EXE, or pass --ttd-exe",
    )
}

fn validate_ttd_exe(path: &Path) -> anyhow::Result<PathBuf> {
    ensure!(
        path.is_file(),
        "TTD recorder executable does not exist: {}",
        path.display()
    );
    Ok(path.to_path_buf())
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn trace_artifact_paths(output: &Path) -> Vec<PathBuf> {
    let mut artifacts = vec![output.to_path_buf()];
    let index = output.with_extension("idx");
    if index.exists() {
        artifacts.push(index);
    }
    artifacts
}

pub(super) fn run_dump_create(args: DumpCreateArgs, output: &OutputOptions) -> anyhow::Result<()> {
    let result = write_process_dump(ProcessDumpOptions {
        process_id: args.process_id,
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        write: DumpWriteOptions {
            path: args.output,
            kind: cli_dump_kind(args.kind),
            overwrite: args.overwrite,
        },
    })?;
    print_value(
        json!({
            "result": result,
            "session_persistence": "one_shot",
            "notes": [
                "DbgHelp writes the dump from a process handle using the Microsoft Debugging Platform runtime staged by cargo xtask deps."
            ]
        }),
        output,
    )
}

pub(super) fn run_dump_inspect(
    args: DumpInspectArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let session = open_dump_session(DumpOpenOptions { path: args.path })?;
    print_value(
        json!({
            "target": session.summary(),
            "modules": session.modules()?,
            "threads": session.threads()?,
            "registers": session.core_registers()?,
            "frames": session.stack_trace(args.max_frames)?,
        }),
        output,
    )
}

fn cli_dump_kind(kind: CliDumpKind) -> DumpKind {
    match kind {
        CliDumpKind::Mini => DumpKind::Mini,
        CliDumpKind::Full => DumpKind::Full,
    }
}

pub(super) fn live_capabilities() -> Value {
    json!({
        "implemented": [
            "dbgeng server",
            "live launch --command-line <cmd> --end detach|terminate",
            "live start --command-line <cmd>",
            "live attach --process-id <pid>",
            "dump create --process-id <pid> --output <path>",
            "dump inspect <path>",
            "target dump --target <id> --output <path>",
            "target list/status/wait/continue/step for live targets",
            "target threads/modules/registers/memory/stack/disasm/symbol/source for live targets"
        ],
        "partial": [
            {
                "feature": "live launch",
                "status": "one_shot_initial_event",
                "notes": "Launches under DbgEng, waits for the initial event, reports execution status, then detaches or terminates."
            },
            {
                "feature": "dump creation",
                "status": "dbghelp_minidump_writer",
                "notes": "Creates mini or full process dumps through DbgHelp from the Microsoft Debugging Platform runtime, either one-shot from a process id or from a daemon-owned live target."
            },
            {
                "feature": "daemon-backed live sessions",
                "status": "persistent_core_control",
                "notes": "Daemon-owned live targets now cover launch, attach, status, event wait, continue, step-into, modules, threads, registers, memory, stack, symbol/source lookup, disassembly, and breakpoints."
            }
        ],
        "gaps": [
            "structured debug event polling",
            "step-over/step-out controls",
            "module/symbol reload management",
            "exception filtering and event callbacks",
            "richer debugger output capture"
        ],
        "safety": [
            "Live debugging mutates target execution state.",
            "Commands that launch or attach are explicit and are not hidden behind read-only names."
        ]
    })
}

pub(super) fn breakpoint_capabilities() -> Value {
    json!({
        "implemented": [
            "memory watchpoint",
            "replay watch-memory",
            "sweep watch-memory",
            "breakpoint list --target <id>",
            "breakpoint set --target <id> --address <addr>",
            "breakpoint remove --target <id> --breakpoint-id <id>"
        ],
        "partial": [
            {
                "feature": "TTD multi-hit memory watchpoint sweeps",
                "status": "bounded_foreground_sweep",
                "command": "sweep watch-memory",
                "bounds": ["--max-hits"],
                "notes": "Collects repeated first-hit memory watchpoints by advancing the cursor one step after each hit."
            },
            {
                "feature": "live breakpoint manager",
                "status": "core_code_and_data_breakpoints",
                "commands": [
                    "breakpoint list",
                    "breakpoint set",
                    "breakpoint remove"
                ],
                "notes": "Live DbgEng targets support code breakpoints and data breakpoints with read/write/execute access masks."
            }
        ],
        "gaps": [
            "source and symbol breakpoints",
            "position watchpoints",
            "call/return trace jobs",
            "breakpoint enable/disable without remove"
        ],
        "safe_next_steps": [
            "Use memory watchpoint for one hit.",
            "Use sweep watch-memory for bounded repeated TTD data-access hits.",
            "Use target status and target wait to inspect live targets around breakpoint hits."
        ]
    })
}

pub(super) fn datamodel_capabilities() -> Value {
    json!({
        "implemented": [
            "structured JSON command output",
            "discover.command_metadata",
            "recipes",
            "context snapshot",
            "architecture state",
            "datamodel eval --target <id> --expression <expr>"
        ],
        "partial": [
            {
                "feature": "DbgEng expression evaluation",
                "status": "scalar_expression_bridge",
                "notes": "Daemon-owned live and dump targets can evaluate basic DbgEng expressions and return structured scalar results."
            },
            {
                "feature": "data-model-like discovery",
                "status": "JSON manifests and command metadata",
                "notes": "Commands expose stable structured data, but do not yet bridge full DbgEng dx or TargetModel object graphs."
            }
        ],
        "gaps": [
            "DbgEng dx expression evaluation",
            "Debugger data model object projection",
            "Microsoft.Debugging.TargetModel.SDK component hosting",
            "dx object expansion and formatting",
            "data-model-aware synthetic providers"
        ],
        "recommended_abstractions": [
            "memory",
            "registers",
            "modules",
            "symbols",
            "threads",
            "events",
            "stack",
            "disassembly",
            "breakpoints"
        ]
    })
}

pub(super) fn run_windbg_command(
    command: WindbgCommand,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    match command {
        WindbgCommand::Status(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.status(true)?)?, output)
        }
        WindbgCommand::Install(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.install(args.force)?)?, output)
        }
        WindbgCommand::Update(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(serde_json::to_value(manager.update()?)?, output)
        }
        WindbgCommand::Path(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            print_value(json!({ "dbgx_path": manager.dbgx_path()? }), output)
        }
        WindbgCommand::Run(args) => {
            let _ = args.json;
            let manager = WindbgManager::new(args.install_dir)?;
            let installed = manager.install(false)?;
            let status = Command::new(&installed.dbgx_path)
                .args(&args.args)
                .status()
                .with_context(|| format!("launching {}", installed.dbgx_path.display()))?;
            print_value(
                json!({
                    "dbgx_path": installed.dbgx_path,
                    "success": status.success(),
                    "exit_code": status.code(),
                }),
                output,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn record_args(output: PathBuf) -> TraceRecordArgs {
        TraceRecordArgs {
            output,
            command_line: r#""C:\Program Files\App\app.exe" --flag "two words""#.to_string(),
            ttd_exe: Some(env::current_exe().unwrap()),
            accept_eula: true,
            children: true,
            max_file_mb: Some(128),
            ring: true,
        }
    }

    fn test_directory() -> PathBuf {
        env::temp_dir().join(format!(
            "windbg-tool-record-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn trace_record_plan_uses_documented_ttd_arguments() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");

        let plan = trace_record_plan(&record_args(output.clone())).unwrap();

        assert_eq!(plan.output, output);
        assert_eq!(
            plan.recorder_args,
            vec![
                "-noUI",
                "-out",
                output.to_string_lossy().as_ref(),
                "-accepteula",
                "-children",
                "-maxFile",
                "128",
                "-ring",
                "-launch",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        );
        assert_eq!(plan.command_line, record_args(output).command_line);

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trace_record_plan_rejects_existing_or_non_run_output() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let existing = temp.join("capture.run");
        fs::write(&existing, []).unwrap();
        assert!(trace_record_plan(&record_args(existing)).is_err());
        assert!(trace_record_plan(&record_args(temp.join("capture.ttd"))).is_err());
        fs::remove_dir_all(temp).unwrap();
    }
}
