use anyhow::{bail, ensure, Context};
use serde_json::{json, Value};
use std::env;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use windbg_dbgeng::{
    launch_live_session, live_launch_initial_break, open_dump_session, start_process_server,
    write_process_dump, BreakpointInfo, DebuggerSession, DumpKind, DumpOpenOptions,
    DumpWriteOptions, LiveInitialStop, LiveLaunchEnd, LiveLaunchOptions, LiveLaunchSessionOptions,
    ManagedCodeAvailability, ModuleInfo, ProcessDumpOptions, ProcessServerOptions,
};
use windbg_install::WindbgManager;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, UpdateProcThreadAttribute,
    WaitForInputIdle, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, STARTUPINFOEXW,
};

use super::output::{print_value, OutputOptions};
use super::{
    CliDumpKind, DbgEngServerArgs, DumpCreateArgs, DumpInspectArgs, LiveLaunchArgs,
    LiveManagedBreakArgs, LiveStartupBreakArgs, TraceRecordArgs, TraceRecordProfile,
    TraceReplayCpuSupport, WindbgCommand,
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

pub(super) fn run_live_startup_break(
    args: LiveStartupBreakArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let end = parse_live_launch_end(&args.end)?;
    let breakpoint_spec = startup_breakpoint_spec(&args)?;
    let module_load_filter = args
        .wait_for_module
        .as_deref()
        .map(validate_module_load_filter)
        .transpose()?;
    let session = launch_live_session(LiveLaunchSessionOptions {
        command_line: args.command_line.clone(),
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        initial_stop: LiveInitialStop::SoftwareBreakpoint,
    })?;

    let result = (|| {
        let initial_event = session.summary();
        let module_load = module_load_filter
            .as_deref()
            .map(|module| {
                session
                    .execute_command(&format!("sxe ld:{module}"))
                    .with_context(|| format!("configuring DbgEng to stop when {module} loads"))?;
                let continued = session.continue_execution()?;
                let wait = session.wait_for_event(args.wait_timeout_ms)?;
                let event = session
                    .last_event()
                    .context("reading the requested DbgEng module-load event")?;
                ensure!(
                    event.event_name == "load_module" && event.module_base.is_some(),
                    "DbgEng did not stop on the requested {module} module-load event"
                );
                Ok::<_, anyhow::Error>(json!({
                    "module": module,
                    "continued": continued,
                    "wait": wait,
                    "event": event
                }))
            })
            .transpose()?;
        let requested_breakpoint = match breakpoint_spec {
            StartupBreakpointSpec::InitialBreak => None,
            _ => Some(set_startup_breakpoint(&session, &breakpoint_spec)?),
        };
        let continued_to_breakpoint = requested_breakpoint
            .is_some()
            .then(|| session.continue_execution())
            .transpose()?;
        let event = requested_breakpoint
            .is_some()
            .then(|| session.wait_for_event(args.wait_timeout_ms))
            .transpose()?
            .unwrap_or_else(|| session.execution_status());
        let registers = session.core_registers()?;
        let instruction_offset = registers.instruction_offset;
        let context = live_stop_context(&session, registers, args.max_frames)?;
        let configured_breakpoint = match requested_breakpoint.as_ref() {
            Some(requested) => session
                .list_breakpoints()?
                .into_iter()
                .find(|breakpoint| breakpoint.id == requested.id),
            None => None,
        };
        let breakpoint_hit = instruction_offset
            .zip(
                configured_breakpoint
                    .as_ref()
                    .map(|breakpoint| breakpoint.offset),
            )
            .is_some_and(|(instruction_offset, breakpoint_offset)| {
                event.name.as_deref() == Some("break") && instruction_offset == breakpoint_offset
            });

        Ok(json!({
            "workflow": "live_startup_break",
            "command_line": args.command_line,
            "breakpoint_spec": breakpoint_spec,
            "initial_event": initial_event,
            "module_load": module_load,
            "continued_to_breakpoint": continued_to_breakpoint,
            "event": event,
            "breakpoint": {
                "requested": requested_breakpoint,
                "configured": configured_breakpoint,
                "hit": breakpoint_hit,
                "hit_evidence": if breakpoint_hit {
                    "current instruction pointer equals the configured breakpoint offset"
                } else if matches!(breakpoint_spec, StartupBreakpointSpec::InitialBreak) {
                    "the initial DbgEng process break was intentionally captured without setting a code breakpoint"
                } else {
                    "DbgEng stopped, but its current instruction pointer did not match the configured breakpoint offset"
                }
            },
            "context": context,
            "end": end
        }))
    })();

    let cleanup = match end {
        LiveLaunchEnd::Detach => session.detach(),
        LiveLaunchEnd::Terminate => session.terminate(),
    };
    match (result, cleanup) {
        (Ok(result), Ok(())) => print_value(result, output),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("failed to end the live debug session"),
    }
}

pub(super) fn run_live_managed_break(
    args: LiveManagedBreakArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    const CORECLR_MODULE: &str = "coreclr.dll";
    const CLR_NOTIFICATION_EXCEPTION: u32 = 0xe044_4143;
    const CLR_NOTIFICATION_FILTER: &str = "clrn";

    let end = parse_live_launch_end(&args.end)?;
    let managed_module = validate_managed_module(&args.managed_module)?;
    let method = validate_managed_breakpoint_token(&args.method, "--method")?;
    let session = launch_live_session(LiveLaunchSessionOptions {
        command_line: args.command_line.clone(),
        initial_break_timeout_ms: args.initial_break_timeout_ms,
        initial_stop: LiveInitialStop::CreateProcessEvent,
    })?;

    let result = (|| {
        let initial_event = session.summary();
        session
            .execute_command(&format!("sxe ld:{CORECLR_MODULE}"))
            .context("configuring the non-invasive CoreCLR module-load stop")?;
        session
            .execute_command(&format!("sxe {CLR_NOTIFICATION_FILTER}"))
            .context("configuring CLR code-generation notification handling")?;

        let continued_to_coreclr = session.continue_execution()?;
        let coreclr_wait = session
            .wait_for_event(args.wait_timeout_ms)
            .context("waiting for CoreCLR to load")?;
        let coreclr_event = session
            .last_event()
            .context("reading the CoreCLR module-load event")?;
        ensure!(
            coreclr_wait.name.as_deref() == Some("break")
                && coreclr_event.event_name == "load_module"
                && coreclr_event.module_base.is_some(),
            "DbgEng did not stop on the requested CoreCLR module-load event"
        );

        let modules_after_coreclr_load = session.modules()?;
        let coreclr_module = find_loaded_module(&modules_after_coreclr_load, CORECLR_MODULE)?;
        let coreclr_path = module_image_path(coreclr_module, "CoreCLR")?;
        let mut dac = session
            .open_coreclr_dac_bridge(&coreclr_path, args.allow_runtime_write)
            .context("initializing the exact-version CoreCLR DAC bridge")?;
        dac.enable_module_load_notifications()
            .context("requesting CLR managed-module load notifications")?;

        session
            .execute_command(&format!("sxe ld:{managed_module}"))
            .with_context(|| {
                format!("configuring the managed-module load stop for {managed_module}")
            })?;
        let continued_to_managed_module = session.continue_execution()?;
        let managed_module_wait = session
            .wait_for_event(args.wait_timeout_ms)
            .with_context(|| format!("waiting for managed module {managed_module} to load"))?;
        let managed_module_event = session
            .last_event()
            .context("reading the managed module-load event")?;
        ensure!(
            managed_module_wait.name.as_deref() == Some("break")
                && managed_module_event.event_name == "load_module"
                && managed_module_event.module_base.is_some(),
            "DbgEng did not stop on the requested managed module-load event"
        );
        let modules_after_managed_load = session.modules()?;
        let loaded_managed_module =
            find_loaded_module(&modules_after_managed_load, &managed_module)?;
        let managed_module_path = module_image_path(loaded_managed_module, "managed assembly")?;
        let managed_module_observation = wait_for_managed_module_in_dac(
            &session,
            &dac,
            &managed_module_path,
            args.wait_timeout_ms,
            CLR_NOTIFICATION_EXCEPTION,
        )?;
        let (resolved_method, availability) = dac
            .resolve_and_notify(&managed_module_path, &method)
            .with_context(|| {
                format!(
                    "resolving {method} in the selected managed module {managed_module} through the DAC"
                )
            })?;

        let (code_notification, generated_method) = match availability {
            ManagedCodeAvailability::Available => (None, resolved_method.clone()),
            ManagedCodeAvailability::PendingJit => {
                let continued = session.continue_execution()?;
                let wait = session
                    .wait_for_event(args.wait_timeout_ms)
                    .context("waiting for the requested CLR code-generation notification")?;
                let event = session
                    .last_event()
                    .context("reading the CLR code-generation notification")?;
                ensure!(
                    wait.name.as_deref() == Some("break")
                        && event.event_name == "exception"
                        && event
                            .exception
                            .as_ref()
                            .is_some_and(|exception| exception.code == CLR_NOTIFICATION_EXCEPTION),
                    "DbgEng did not stop on the requested CLR code-generation notification"
                );
                let generated = dac.refresh_method_code().context(
                    "refreshing the selected method after its CLR code-generation notification",
                )?;
                ensure!(
                    generated.representative_entry_address.is_some(),
                    "the CLR notification did not produce a representative native entry address"
                );
                (
                    Some(json!({
                        "exception_code": format!("0x{CLR_NOTIFICATION_EXCEPTION:08X}"),
                        "continued": continued,
                        "wait": wait,
                        "event": event,
                        "selected_method_code_available": true
                    })),
                    generated,
                )
            }
        };
        ensure!(
            generated_method.token == resolved_method.token,
            "the DAC returned generated code for a different MethodDef token"
        );
        let native_entry_address = generated_method
            .representative_entry_address
            .context("the selected managed method has no generated native entry address")?;
        let hardware_breakpoint = session.add_data_breakpoint(
            native_entry_address,
            1,
            windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_BREAK_EXECUTE,
        )?;
        let continued_to_hardware_breakpoint = if code_notification.is_some() {
            session.continue_execution_handled()?
        } else {
            session.continue_execution()?
        };
        let hardware_wait = session
            .wait_for_event(args.wait_timeout_ms)
            .context("waiting for the managed hardware execute breakpoint")?;
        let hardware_event = session
            .last_event()
            .context("reading the managed hardware execute-breakpoint event")?;
        let registers = session.core_registers()?;
        let hardware_breakpoint_hit = hardware_wait.name.as_deref() == Some("break")
            && hardware_event.event_name == "breakpoint"
            && hardware_event.breakpoint_id == Some(hardware_breakpoint.id)
            && registers.instruction_offset == Some(native_entry_address);
        let context = live_stop_context(&session, registers, args.max_frames)?;
        Ok(json!({
            "workflow": "live_managed_break_dac",
            "command_line": args.command_line,
            "initial_event": initial_event,
            "coreclr_module_load": {
                "module": CORECLR_MODULE,
                "continued": continued_to_coreclr,
                "wait": coreclr_wait,
                "event": coreclr_event,
                "loaded_module": coreclr_module,
                "runtime": dac.runtime_info()
            },
            "managed_module_load": {
                "managed_module": managed_module,
                "continued_to_dbgeng_load_event": continued_to_managed_module,
                "dbgeng_load_wait": managed_module_wait,
                "dbgeng_load_event": managed_module_event,
                "observation": managed_module_observation,
                "loaded_module": loaded_managed_module
            },
            "managed_resolution": {
                "method_request": method,
                "resolved_method": resolved_method,
                "method_after_code_generation": generated_method,
                "runtime_writes_explicitly_allowed": args.allow_runtime_write,
                "exact_overload_signature_selection": false,
                "private_methods_supported": true
            },
            "code_generation": {
                "notification_filter": CLR_NOTIFICATION_FILTER,
                "notification": code_notification,
                "representative_native_entry_address": format!("0x{native_entry_address:X}")
            },
            "managed_breakpoint": {
                "kind": "hardware_execute",
                "configured": hardware_breakpoint,
                "continued": continued_to_hardware_breakpoint,
                "wait": hardware_wait,
                "event": hardware_event,
                "hit": hardware_breakpoint_hit,
                "hit_evidence": if hardware_breakpoint_hit {
                    "the DbgEng hardware breakpoint event ID and current instruction pointer both match the DAC-mapped native entry for the selected MethodDef"
                } else {
                    "the selected MethodDef was resolved by the DAC, but DbgEng did not report a matching hardware execute breakpoint hit"
                }
            },
            "context": context,
            "limitations": [
                "This vertical slice requires one unambiguous metadata method name; exact overload signature selection is not yet implemented.",
                "The breakpoint covers the DAC representative entry address. Generic instantiations, tiered recompilation, ReadyToRun entry indirection, and re-JIT/unload transitions require additional validation."
            ],
            "end": end
        }))
    })();

    let cleanup = match end {
        LiveLaunchEnd::Detach => session.detach(),
        LiveLaunchEnd::Terminate => session.terminate(),
    };
    match (result, cleanup) {
        (Ok(result), Ok(())) => print_value(result, output),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error).context("failed to end the live debug session"),
    }
}

fn validate_module_load_filter(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "--wait-for-module must not be empty");
    ensure!(
        value
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || matches!(character, '.' | '_' | '-')),
        "--wait-for-module must be a module basename"
    );
    Ok(value.to_string())
}

fn live_stop_context(
    session: &DebuggerSession,
    registers: windbg_dbgeng::CoreRegisterState,
    max_frames: u32,
) -> anyhow::Result<Value> {
    let instruction_offset = registers.instruction_offset;
    let current_module = instruction_offset
        .map(|address| session.module_by_offset(address))
        .transpose()?
        .flatten();
    let current_symbol = instruction_offset
        .map(|address| session.symbol_by_offset(address))
        .transpose()?
        .flatten();
    let stack = match session.stack_trace(max_frames) {
        Ok(frames) => json!({
            "status": "ok",
            "frames": frames,
            "frame_limit": max_frames
        }),
        Err(error) => json!({
            "status": "error",
            "error": error.to_string(),
            "frames": [],
            "frame_limit": max_frames
        }),
    };
    Ok(json!({
        "target": session.summary(),
        "registers": registers,
        "instruction_pointer": instruction_offset,
        "current_module": current_module,
        "current_symbol": current_symbol,
        "stack": stack
    }))
}

fn validate_managed_breakpoint_token(value: &str, argument: &str) -> anyhow::Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{argument} must not be empty");
    ensure!(
        value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '$' | '`')
        }),
        "{argument} contains unsupported characters"
    );
    Ok(value.to_string())
}

fn validate_managed_module(value: &str) -> anyhow::Result<String> {
    let path = validate_module_load_filter(value)?;
    ensure!(
        Path::new(&path)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("dll") || extension.eq_ignore_ascii_case("exe")
            }),
        "--managed-module must be a managed .dll or .exe basename"
    );
    Ok(path)
}

fn module_image_path(module: &ModuleInfo, role: &str) -> anyhow::Result<PathBuf> {
    [
        module.loaded_image_name.as_deref(),
        module.image_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .with_context(|| {
        format!("DbgEng did not report an accessible {role} image path for the selected module")
    })
}

fn wait_for_managed_module_in_dac(
    session: &DebuggerSession,
    dac: &windbg_dbgeng::CoreClrDacBridge,
    managed_module_path: &Path,
    wait_timeout_ms: u32,
    clr_notification_exception: u32,
) -> anyhow::Result<Value> {
    const MAX_CLR_NOTIFICATIONS: usize = 64;

    let deadline = Instant::now() + Duration::from_millis(u64::from(wait_timeout_ms));
    let mut notifications = Vec::new();
    let mut continue_as_handled = false;
    for attempt in 1..=MAX_CLR_NOTIFICATIONS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for the CLR to register the selected managed module"
        );
        let remaining_ms = remaining.as_millis().clamp(1, u128::from(u32::MAX)) as u32;
        let continued = if continue_as_handled {
            session.continue_execution_handled()?
        } else {
            session.continue_execution()?
        };
        let wait = session
            .wait_for_event(remaining_ms)
            .context("waiting for the next CLR managed-module notification")?;
        let event = session
            .last_event()
            .context("reading the CLR managed-module notification")?;
        let is_clr_notification = event.event_name == "exception"
            && event
                .exception
                .as_ref()
                .is_some_and(|exception| exception.code == clr_notification_exception);
        ensure!(
            wait.name.as_deref() == Some("break") && is_clr_notification,
            "DbgEng stopped before the CLR registered the selected managed module"
        );
        let module_available = dac.is_module_loaded(managed_module_path)?;
        notifications.push(json!({
            "attempt": attempt,
            "continued": continued,
            "wait": wait,
            "event": event,
            "module_available": module_available
        }));
        if module_available {
            return Ok(json!({
                "notification_exception_code": format!("0x{clr_notification_exception:08X}"),
                "notifications": notifications,
                "module_available": true
            }));
        }
        continue_as_handled = true;
    }

    bail!(
        "the CLR emitted {MAX_CLR_NOTIFICATIONS} notifications without registering the selected managed module"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StartupBreakpointSpec {
    InitialBreak,
    Address { address: u64 },
    ModuleOffset { module: String, offset: u64 },
    Symbol { expression: String },
}

fn startup_breakpoint_spec(args: &LiveStartupBreakArgs) -> anyhow::Result<StartupBreakpointSpec> {
    let selections = usize::from(args.initial_break)
        + usize::from(args.address.is_some())
        + usize::from(args.module_offset.is_some())
        + usize::from(args.symbol.is_some());
    ensure!(
        selections == 1,
        "specify exactly one of --initial-break, --address, --module with --module-offset, or --symbol"
    );
    if args.initial_break {
        return Ok(StartupBreakpointSpec::InitialBreak);
    }
    if let Some(address) = args.address.as_deref() {
        return Ok(StartupBreakpointSpec::Address {
            address: parse_debug_address(address)?,
        });
    }
    if let Some(offset) = args.module_offset.as_deref() {
        return Ok(StartupBreakpointSpec::ModuleOffset {
            module: args
                .module
                .clone()
                .context("--module-offset requires --module")?,
            offset: parse_debug_address(offset)?,
        });
    }
    let expression = args
        .symbol
        .as_deref()
        .context("a startup breakpoint specification is required")?
        .trim();
    ensure!(!expression.is_empty(), "--symbol must not be empty");
    Ok(StartupBreakpointSpec::Symbol {
        expression: expression.to_string(),
    })
}

fn set_startup_breakpoint(
    session: &DebuggerSession,
    spec: &StartupBreakpointSpec,
) -> anyhow::Result<BreakpointInfo> {
    match spec {
        StartupBreakpointSpec::InitialBreak => {
            bail!("initial-break capture does not create a code breakpoint")
        }
        StartupBreakpointSpec::Address { address } => session.add_code_breakpoint(*address),
        StartupBreakpointSpec::ModuleOffset { module, offset } => {
            let modules = session.modules()?;
            let module = find_loaded_module(&modules, module)?;
            let address = module
                .base_address
                .checked_add(*offset)
                .context("module base plus breakpoint offset overflowed")?;
            session.add_code_breakpoint(address)
        }
        StartupBreakpointSpec::Symbol { expression } => {
            session.add_code_breakpoint_expression(expression)
        }
    }
}

fn find_loaded_module<'a>(
    modules: &'a [ModuleInfo],
    requested_module: &str,
) -> anyhow::Result<&'a ModuleInfo> {
    modules
        .iter()
        .find(|module| {
            [
                module.module_name.as_deref(),
                module.image_name.as_deref(),
                module.loaded_image_name.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|candidate| module_name_matches(candidate, requested_module))
        })
        .with_context(|| format!("module '{requested_module}' is not loaded at the initial break"))
}

fn module_name_matches(candidate: &str, requested: &str) -> bool {
    candidate.eq_ignore_ascii_case(requested)
        || Path::new(candidate)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(requested))
}

fn parse_debug_address(value: &str) -> anyhow::Result<u64> {
    let value = value.trim();
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    };
    parsed.with_context(|| {
        format!("invalid address '{value}'; use decimal or 0x-prefixed hexadecimal")
    })
}

fn parse_live_launch_end(value: &str) -> anyhow::Result<LiveLaunchEnd> {
    match value {
        "detach" => Ok(LiveLaunchEnd::Detach),
        "terminate" => Ok(LiveLaunchEnd::Terminate),
        other => bail!("unsupported live launch end action: {other}"),
    }
}

pub(super) fn run_trace_record(
    args: TraceRecordArgs,
    output: &OutputOptions,
) -> anyhow::Result<()> {
    let mut plan = trace_record_plan(&args)?;
    let launcher = trace_record_launcher()?;
    if args.disable_user_shadow_stack {
        plan.target = TraceRecordTarget::Attach {
            process_id: launch_target_with_shadow_stacks_disabled(&plan.command_line)?,
        };
    }
    let started = Instant::now();
    let execution = execute_trace_recording(&plan, &launcher)?;
    let status = execution.status;
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
    let diagnostics = trace_record_diagnostics(&plan, started.elapsed())?;
    let completion_note = if plan.capture.record_for_seconds.is_some() {
        "The bounded stop finalizes TTD recording without terminating the target process."
    } else {
        "The trace is finalized after the launched target exits."
    };
    print_value(
        json!({
            "recorder": plan.ttd_exe,
            "output": plan.output,
            "command_line": plan.command_line,
            "recording_mode": plan.target.name(),
            "target_process_id": plan.target.process_id(),
            "exit_code": status.code(),
            "elevation": launcher.name(),
            "capture": trace_capture_value(&plan.capture),
            "lifecycle": {
                "record_for_seconds": plan.capture.record_for_seconds,
                "stopped_after_limit": execution.stopped_after_limit,
                "stop_exit_code": execution.stop_exit_code,
            },
            "artifacts": artifact_paths,
            "diagnostics": diagnostics,
            "notes": [
                "TTD recording is invasive and can significantly slow the target process.",
                completion_note,
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
    target: TraceRecordTarget,
    capture: TraceCaptureSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceCaptureSettings {
    profile: Option<TraceRecordProfile>,
    modules: Vec<String>,
    max_file_mb: Option<u32>,
    ring: bool,
    replay_cpu_support: Option<TraceReplayCpuSupport>,
    num_vcpu: Option<u32>,
    record_for_seconds: Option<u32>,
}

struct TraceRecordExecution {
    status: ExitStatus,
    stopped_after_limit: bool,
    stop_exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceRecordTarget {
    Launch,
    Attach { process_id: u32 },
}

impl TraceRecordTarget {
    fn name(&self) -> &'static str {
        match self {
            Self::Launch => "launch",
            Self::Attach { .. } => "attach_after_cet_disabled_launch",
        }
    }

    fn process_id(&self) -> Option<u32> {
        match self {
            Self::Launch => None,
            Self::Attach { process_id } => Some(*process_id),
        }
    }
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
    ensure!(
        args.profile.is_none() || (args.max_file_mb.is_none() && !args.ring),
        "--profile cannot be combined with --max-file-mb or --ring"
    );
    if let Some(record_for_seconds) = args.record_for_seconds {
        ensure!(
            record_for_seconds > 0,
            "--record-for-seconds must be greater than zero"
        );
        ensure!(
            args.disable_user_shadow_stack,
            "--record-for-seconds requires --disable-user-shadow-stack so windbg-tool knows the target PID"
        );
    }

    let ttd_exe = resolve_ttd_exe(args.ttd_exe.as_deref())?;
    let mut recorder_args = vec![
        OsString::from("-noUI"),
        OsString::from("-out"),
        args.output.as_os_str().to_os_string(),
        OsString::from("-accepteula"),
    ];
    let (max_file_mb, ring) = trace_size_settings(args)?;
    let modules = args
        .modules
        .iter()
        .map(|module| validate_ttd_module_name(module))
        .collect::<anyhow::Result<Vec<_>>>()?;

    if args.children {
        recorder_args.push(OsString::from("-children"));
    }
    for module in &modules {
        recorder_args.push(OsString::from("-module"));
        recorder_args.push(OsString::from(module));
    }
    if let Some(max_file_mb) = max_file_mb {
        recorder_args.push(OsString::from("-maxFile"));
        recorder_args.push(OsString::from(max_file_mb.to_string()));
    }
    if ring {
        recorder_args.push(OsString::from("-ring"));
    }
    if let Some(replay_cpu_support) = args.replay_cpu_support {
        recorder_args.push(OsString::from("-replayCpuSupport"));
        recorder_args.push(OsString::from(replay_cpu_support.ttd_value()));
    }
    if let Some(num_vcpu) = args.num_vcpu {
        ensure!(num_vcpu > 0, "--num-vcpu must be greater than zero");
        recorder_args.push(OsString::from("-numVCpu"));
        recorder_args.push(OsString::from(num_vcpu.to_string()));
    }
    Ok(TraceRecordPlan {
        ttd_exe,
        output: args.output.clone(),
        command_line: args.command_line.clone(),
        recorder_args,
        target: TraceRecordTarget::Launch,
        capture: TraceCaptureSettings {
            profile: args.profile,
            modules,
            max_file_mb,
            ring,
            replay_cpu_support: args.replay_cpu_support,
            num_vcpu: args.num_vcpu,
            record_for_seconds: args.record_for_seconds,
        },
    })
}

fn trace_size_settings(args: &TraceRecordArgs) -> anyhow::Result<(Option<u32>, bool)> {
    if let Some(profile) = args.profile {
        return Ok(match profile {
            TraceRecordProfile::Startup => (Some(1024), false),
            TraceRecordProfile::Recent => (Some(2048), true),
        });
    }

    if let Some(max_file_mb) = args.max_file_mb {
        ensure!(max_file_mb > 0, "--max-file-mb must be greater than zero");
    }
    ensure!(
        !args.ring || args.max_file_mb.is_some(),
        "--ring requires --max-file-mb"
    );
    Ok((args.max_file_mb, args.ring))
}

fn validate_ttd_module_name(module: &str) -> anyhow::Result<String> {
    let module = module.trim();
    ensure!(!module.is_empty(), "--module must not be empty");
    ensure!(
        !module.contains(['\\', '/']),
        "--module must be a native module basename, not a path: {module}"
    );
    Ok(module.to_string())
}

fn trace_capture_value(capture: &TraceCaptureSettings) -> Value {
    json!({
        "profile": capture.profile.map(TraceRecordProfile::name),
        "modules": capture.modules,
        "max_file_mb": capture.max_file_mb,
        "ring": capture.ring,
        "replay_cpu_support": capture.replay_cpu_support.map(TraceReplayCpuSupport::ttd_value),
        "num_vcpu": capture.num_vcpu,
        "record_for_seconds": capture.record_for_seconds,
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TtdSidecarSummary {
    allocated_vcpus: Option<u32>,
    running_threads: Option<u32>,
    simulation_duration_ms: Option<u64>,
    recording_engine_initialized: bool,
    tracing_started: bool,
    tracing_completed: bool,
    trace_dumped: bool,
}

fn trace_record_diagnostics(plan: &TraceRecordPlan, elapsed: Duration) -> anyhow::Result<Value> {
    let metadata = std::fs::metadata(&plan.output)
        .with_context(|| format!("reading trace metadata from {}", plan.output.display()))?;
    let trace_size_bytes = metadata.len();
    let elapsed_ms = elapsed.as_millis() as u64;
    let write_rate_mib_per_second = if elapsed.is_zero() {
        None
    } else {
        Some((trace_size_bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64())
    };
    let sidecar_path = plan.output.with_extension("out");
    let (sidecar, sidecar_read_error) = match std::fs::read_to_string(&sidecar_path) {
        Ok(contents) => (Some(parse_ttd_sidecar(&contents)), None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(error) => (None, Some(error.to_string())),
    };
    let mut warnings = Vec::new();
    if let Some(rate) = write_rate_mib_per_second {
        if rate >= 32.0 {
            warnings.push(format!(
                "Trace growth is high at {rate:.1} MiB/s; use --max-file-mb, --ring, --record-for-seconds, or --module to bound future captures."
            ));
        }
    }
    if trace_size_bytes >= 1024 * 1024 * 1024 {
        warnings.push(
            "The trace exceeds 1 GiB. Keep it local and use bounded capture settings for exploratory recordings."
                .to_string(),
        );
    }
    if plan.capture.ring {
        warnings.push(
            "Ring mode retains only the newest portion of the recording once the size limit is reached."
                .to_string(),
        );
    }
    if let Some(sidecar) = sidecar.as_ref() {
        if !sidecar.recording_engine_initialized || !sidecar.trace_dumped {
            warnings.push(
                "TTD sidecar did not confirm both recording-engine initialization and trace finalization; inspect the .out file before relying on this capture."
                    .to_string(),
            );
        }
    }

    Ok(json!({
        "trace_size_bytes": trace_size_bytes,
        "trace_size_mib": trace_size_bytes as f64 / 1024.0 / 1024.0,
        "elapsed_ms": elapsed_ms,
        "write_rate_mib_per_second": write_rate_mib_per_second,
        "sidecar": {
            "path": sidecar_path,
            "available": sidecar.is_some(),
            "read_error": sidecar_read_error,
            "allocated_vcpus": sidecar.as_ref().and_then(|summary| summary.allocated_vcpus),
            "running_threads": sidecar.as_ref().and_then(|summary| summary.running_threads),
            "simulation_duration_ms": sidecar.as_ref().and_then(|summary| summary.simulation_duration_ms),
            "recording_engine_initialized": sidecar.as_ref().map(|summary| summary.recording_engine_initialized),
            "tracing_started": sidecar.as_ref().map(|summary| summary.tracing_started),
            "tracing_completed": sidecar.as_ref().map(|summary| summary.tracing_completed),
            "trace_dumped": sidecar.as_ref().map(|summary| summary.trace_dumped),
        },
        "warnings": warnings,
    }))
}

fn parse_ttd_sidecar(contents: &str) -> TtdSidecarSummary {
    let mut summary = TtdSidecarSummary {
        recording_engine_initialized: contents
            .contains("RecordingEngine initialization successful."),
        tracing_started: contents.contains("Tracing started at:"),
        tracing_completed: contents.contains("Tracing completed at:"),
        trace_dumped: contents.contains("Trace dumped to "),
        ..Default::default()
    };
    for line in contents.lines() {
        if let Some(values) = line.strip_prefix("Allocated processors:") {
            if let Some((vcpus, threads)) = values.split_once(", running threads:") {
                summary.allocated_vcpus = vcpus.trim().parse().ok();
                summary.running_threads = threads.trim_end_matches('.').trim().parse().ok();
            }
        }
        if line.starts_with("Simulation time of ") {
            summary.simulation_duration_ms = line
                .rsplit_once(':')
                .and_then(|(_, duration)| duration.trim().strip_suffix("ms."))
                .and_then(|duration| duration.parse().ok());
        }
    }
    summary
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceRecordLauncher {
    Direct,
    Sudo {
        executable: PathBuf,
        working_directory: PathBuf,
        mode: WindowsSudoMode,
    },
}

impl TraceRecordLauncher {
    fn name(&self) -> &'static str {
        match self {
            Self::Direct => "already_elevated",
            Self::Sudo {
                mode: WindowsSudoMode::Inline,
                ..
            } => "windows_sudo_inline",
            Self::Sudo {
                mode: WindowsSudoMode::DisableInput,
                ..
            } => "windows_sudo_disable_input",
            Self::Sudo {
                mode: WindowsSudoMode::ForceNewWindow,
                ..
            } => "windows_sudo_force_new_window",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsSudoMode {
    DisableInput,
    Inline,
    ForceNewWindow,
}

fn trace_record_launcher() -> anyhow::Result<TraceRecordLauncher> {
    if current_process_is_elevated()? {
        return Ok(TraceRecordLauncher::Direct);
    }

    let (sudo, mode) = find_enabled_sudo()?.context(
        "TTD recording requires elevation, but Windows sudo is unavailable or disabled; run windbg-tool from an elevated terminal or enable sudo in Settings > System > Advanced",
    )?;
    if mode == WindowsSudoMode::ForceNewWindow {
        bail!(
            "Windows sudo is configured for Force New Window mode, which cannot synchronously wait for TTD recording; run windbg-tool from an elevated terminal or configure sudo for Input Closed or Inline mode in Settings > System > Advanced"
        );
    }
    let working_directory =
        env::current_dir().context("resolving the current working directory")?;
    Ok(TraceRecordLauncher::Sudo {
        executable: sudo,
        working_directory,
        mode,
    })
}

fn command_from_trace_record_plan(
    plan: &TraceRecordPlan,
    launcher: &TraceRecordLauncher,
) -> Command {
    let mut command = ttd_command(&plan.ttd_exe, launcher);
    command.args(&plan.recorder_args);
    match plan.target {
        TraceRecordTarget::Launch => {
            command.arg("-launch");
            // TTD requires its target command line after -launch. raw_arg preserves the caller's
            // Windows command-line quoting without introducing a shell.
            command.raw_arg(&plan.command_line);
        }
        TraceRecordTarget::Attach { process_id } => {
            command.arg("-attach").arg(process_id.to_string());
        }
    }
    command
}

fn ttd_command(ttd_exe: &Path, launcher: &TraceRecordLauncher) -> Command {
    match launcher {
        TraceRecordLauncher::Direct => Command::new(ttd_exe),
        TraceRecordLauncher::Sudo {
            executable,
            working_directory,
            mode,
        } => {
            let mut command = Command::new(executable);
            command
                .arg("--preserve-env")
                .arg("--chdir")
                .arg(working_directory);
            match mode {
                WindowsSudoMode::DisableInput => {
                    command.arg("--disable-input");
                }
                WindowsSudoMode::Inline => {
                    command.arg("--inline");
                }
                WindowsSudoMode::ForceNewWindow => {
                    unreachable!("asynchronous sudo mode is rejected")
                }
            }
            command.arg(ttd_exe);
            command
        }
    }
}

fn execute_trace_recording(
    plan: &TraceRecordPlan,
    launcher: &TraceRecordLauncher,
) -> anyhow::Result<TraceRecordExecution> {
    let mut child = command_from_trace_record_plan(plan, launcher)
        .spawn()
        .with_context(|| format!("launching TTD recorder {}", plan.ttd_exe.display()))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(child.wait());
    });

    let Some(record_for_seconds) = plan.capture.record_for_seconds else {
        return Ok(TraceRecordExecution {
            status: receiver
                .recv()
                .context("waiting for the TTD recorder process")??,
            stopped_after_limit: false,
            stop_exit_code: None,
        });
    };

    match receiver.recv_timeout(Duration::from_secs(record_for_seconds.into())) {
        Ok(status) => Ok(TraceRecordExecution {
            status: status.context("waiting for the TTD recorder process")?,
            stopped_after_limit: false,
            stop_exit_code: None,
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let process_id = plan
                .target
                .process_id()
                .context("--record-for-seconds requires a trace target with a known process id")?;
            let stop_status = command_from_ttd_stop(&plan.ttd_exe, launcher, process_id)
                .status()
                .context("stopping the bounded TTD recording")?;
            ensure!(
                stop_status.success(),
                "TTD recorder stop request exited with {}; the recording may still be active",
                stop_status
                    .code()
                    .map_or_else(|| "no exit code".to_string(), |code| code.to_string())
            );
            Ok(TraceRecordExecution {
                status: receiver
                    .recv()
                    .context("waiting for TTD trace finalization after the stop request")??,
                stopped_after_limit: true,
                stop_exit_code: stop_status.code(),
            })
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            bail!("TTD recorder wait worker disconnected unexpectedly")
        }
    }
}

fn command_from_ttd_stop(
    ttd_exe: &Path,
    launcher: &TraceRecordLauncher,
    process_id: u32,
) -> Command {
    let mut command = ttd_command(ttd_exe, launcher);
    command
        .arg("-accepteula")
        .arg("-stop")
        .arg(process_id.to_string());
    command
}

const CET_USER_SHADOW_STACKS_ALWAYS_OFF: u64 = 0x0000_0000_2000_0000;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x0002_0007;
const WAIT_FAILED: u32 = u32::MAX;

fn launch_target_with_shadow_stacks_disabled(command_line: &str) -> anyhow::Result<u32> {
    let mut attribute_list_size = 0usize;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST::default(),
            1,
            0,
            &mut attribute_list_size,
        );
    }
    ensure!(
        attribute_list_size > 0,
        "allocating the process mitigation attribute list"
    );
    let mut attribute_list_storage =
        vec![0usize; attribute_list_size.div_ceil(std::mem::size_of::<usize>())];
    let attribute_list = LPPROC_THREAD_ATTRIBUTE_LIST(attribute_list_storage.as_mut_ptr().cast());
    let mut mitigation_policy = [0u64, CET_USER_SHADOW_STACKS_ALWAYS_OFF];
    let mut startup = STARTUPINFOEXW::default();
    let mut process_information = PROCESS_INFORMATION::default();
    let mut command_line = wide_null(command_line);
    let current_directory =
        env::current_dir().context("resolving the current working directory")?;
    let current_directory = wide_null(current_directory.as_os_str());

    unsafe {
        InitializeProcThreadAttributeList(attribute_list, 1, 0, &mut attribute_list_size)
            .context("initializing the process mitigation attribute list")?;
        let update = UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            Some(mitigation_policy.as_mut_ptr().cast()),
            std::mem::size_of_val(&mitigation_policy),
            None,
            None,
        );
        if let Err(error) = update {
            DeleteProcThreadAttributeList(attribute_list);
            return Err(error).context("setting the per-process CET mitigation");
        }

        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attribute_list;
        let created = CreateProcessW(
            None,
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            PCWSTR(current_directory.as_ptr()),
            &startup.StartupInfo,
            &mut process_information,
        );
        DeleteProcThreadAttributeList(attribute_list);
        created.context("launching the target with CET shadow stacks disabled")?;
        let input_idle = WaitForInputIdle(process_information.hProcess, 10_000);
        CloseHandle(process_information.hThread).context("closing the target thread handle")?;
        CloseHandle(process_information.hProcess).context("closing the target process handle")?;
        ensure!(
            input_idle != WAIT_FAILED,
            "waiting for the target process to initialize"
        );
    }

    Ok(process_information.dwProcessId)
}

fn wide_null(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn current_process_is_elevated() -> anyhow::Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("opening the current process token")?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0;
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token).context("closing the current process token")?;
        result.context("querying the current process elevation")?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn find_enabled_sudo() -> anyhow::Result<Option<(PathBuf, WindowsSudoMode)>> {
    let Some(sudo) = find_executable_on_path("sudo.exe") else {
        return Ok(None);
    };
    let output = Command::new(&sudo)
        .arg("config")
        .output()
        .context("checking Windows sudo configuration")?;
    ensure!(
        output.status.success(),
        "Windows sudo configuration check failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mode = parse_windows_sudo_mode(&String::from_utf8_lossy(&output.stdout)).context(
        "Windows sudo returned an unrecognized configuration; run `sudo config` to inspect it",
    )?;
    Ok(Some((sudo, mode)))
}

fn parse_windows_sudo_mode(output: &str) -> Option<WindowsSudoMode> {
    let normalized = output.to_ascii_lowercase().replace([' ', '-'], "");
    if normalized.contains("forcenewwindow") {
        Some(WindowsSudoMode::ForceNewWindow)
    } else if normalized.contains("disableinput") || normalized.contains("inputclosed") {
        Some(WindowsSudoMode::DisableInput)
    } else if normalized.contains("inline") || normalized.contains("normal") {
        Some(WindowsSudoMode::Inline)
    } else {
        None
    }
}

fn resolve_ttd_exe(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        return validate_ttd_exe(path);
    }
    if let Some(path) = env::var_os("TTD_EXE") {
        return validate_ttd_exe(Path::new(&path));
    }
    find_executable_on_path("ttd.exe").context(ttd_not_found_message())
}

fn ttd_not_found_message() -> &'static str {
    "could not find TTD.exe; install it with `winget install --id Microsoft.TimeTravelDebugging`, then open a new elevated terminal. Alternatively, add it to PATH, set TTD_EXE, or pass --ttd-exe"
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
    let sidecar = output.with_extension("out");
    if sidecar.exists() {
        artifacts.push(sidecar);
    }
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
            "live startup-break --command-line <cmd> --initial-break|--address <addr>|--module <name> --module-offset <rva>|--symbol <expr>",
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
                "feature": "startup breakpoint workflow",
                "status": "one_shot_structured_context",
                "notes": "Launches at the initial break, sets an absolute, module-RVA, or deferred symbol-expression code breakpoint, then reports bounded hit evidence, thread/IP/module/register/stack context."
            },
            {
                "feature": "managed method breakpoint workflow",
                "status": "x64_coreclr_dac_vertical_slice",
                "notes": "Uses a matching CoreCLR DAC through the active DbgEng client, resolves one unambiguous metadata method, requests CLR code generation, and then sets a DbgEng hardware execute breakpoint. CLR notification writes require --allow-runtime-write and an approved test VM."
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
            "source breakpoints and persistent daemon symbol breakpoints",
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
            children: true,
            modules: vec![
                "RemoteDesktopManager_x64.exe".to_string(),
                "coreclr.dll".to_string(),
            ],
            max_file_mb: Some(128),
            ring: true,
            replay_cpu_support: Some(TraceReplayCpuSupport::MostAggressive),
            num_vcpu: Some(16),
            profile: None,
            record_for_seconds: None,
            disable_user_shadow_stack: false,
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
                "-module",
                "RemoteDesktopManager_x64.exe",
                "-module",
                "coreclr.dll",
                "-maxFile",
                "128",
                "-ring",
                "-replayCpuSupport",
                "MostAggressive",
                "-numVCpu",
                "16",
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

    #[test]
    fn trace_record_profiles_resolve_bounded_capture_settings() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");
        let mut args = record_args(output);
        args.children = false;
        args.modules.clear();
        args.max_file_mb = None;
        args.ring = false;
        args.replay_cpu_support = None;
        args.num_vcpu = None;
        args.profile = Some(TraceRecordProfile::Startup);

        let startup = trace_record_plan(&args).unwrap();
        assert_eq!(startup.capture.max_file_mb, Some(1024));
        assert!(!startup.capture.ring);
        assert_eq!(startup.capture.profile, Some(TraceRecordProfile::Startup));

        args.profile = Some(TraceRecordProfile::Recent);
        let recent = trace_record_plan(&args).unwrap();
        assert_eq!(recent.capture.max_file_mb, Some(2048));
        assert!(recent.capture.ring);

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trace_record_plan_rejects_module_paths_and_zero_vcpus() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");
        let mut args = record_args(output);
        args.modules = vec![r"C:\Windows\System32\kernel32.dll".to_string()];
        assert!(trace_record_plan(&args).is_err());

        args.modules = vec!["kernel32.dll".to_string()];
        args.num_vcpu = Some(0);
        assert!(trace_record_plan(&args).is_err());

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trace_record_plan_rejects_unbounded_profile_conflicts_and_invalid_duration() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let output = temp.join("capture.run");
        let mut args = record_args(output);
        args.profile = Some(TraceRecordProfile::Startup);
        assert!(trace_record_plan(&args).is_err());

        args.profile = None;
        args.max_file_mb = None;
        args.ring = false;
        args.record_for_seconds = Some(0);
        assert!(trace_record_plan(&args).is_err());

        args.record_for_seconds = Some(10);
        assert!(trace_record_plan(&args).is_err());

        args.disable_user_shadow_stack = true;
        assert_eq!(
            trace_record_plan(&args).unwrap().capture.record_for_seconds,
            Some(10)
        );

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn ttd_sidecar_parser_extracts_recording_summary() {
        let summary = parse_ttd_sidecar(
            "Allocated processors:55, running threads:16.\n\
             RecordingEngine initialization successful.\n\
             Tracing started at: Thu Jul  9 20:04:35 2026 (UTC)\n\
             Simulation time of '' (x64): 188031ms.\n\
             Tracing completed at: Thu Jul  9 20:07:43 2026 (UTC)\n\
             Trace dumped to C:\\trace\\capture.run\n",
        );

        assert_eq!(
            summary,
            TtdSidecarSummary {
                allocated_vcpus: Some(55),
                running_threads: Some(16),
                simulation_duration_ms: Some(188031),
                recording_engine_initialized: true,
                tracing_started: true,
                tracing_completed: true,
                trace_dumped: true,
            }
        );
    }

    #[test]
    fn ttd_stop_command_uses_the_target_process_id() {
        let command = command_from_ttd_stop(
            Path::new(r"C:\tools\TTD.exe"),
            &TraceRecordLauncher::Direct,
            4242,
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            command.get_program(),
            Path::new(r"C:\tools\TTD.exe").as_os_str()
        );
        assert_eq!(arguments, ["-accepteula", "-stop", "4242"]);
    }

    #[test]
    fn sudo_launcher_wraps_ttd_and_preserves_working_directory() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let plan = trace_record_plan(&record_args(temp.join("capture.run"))).unwrap();
        let launcher = TraceRecordLauncher::Sudo {
            executable: PathBuf::from(r"C:\Windows\System32\sudo.exe"),
            working_directory: PathBuf::from(r"D:\work"),
            mode: WindowsSudoMode::DisableInput,
        };

        let command = command_from_trace_record_plan(&plan, &launcher);
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            command.get_program(),
            Path::new(r"C:\Windows\System32\sudo.exe").as_os_str()
        );
        assert_eq!(
            arguments[..6],
            [
                "--preserve-env",
                "--chdir",
                r"D:\work",
                "--disable-input",
                plan.ttd_exe.to_string_lossy().as_ref(),
                "-noUI",
            ]
        );
        assert_eq!(launcher.name(), "windows_sudo_disable_input");

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn cet_compatibility_mode_records_by_target_attach() {
        let temp = test_directory();
        fs::create_dir_all(&temp).unwrap();
        let mut plan = trace_record_plan(&record_args(temp.join("capture.run"))).unwrap();
        plan.target = TraceRecordTarget::Attach { process_id: 4242 };

        let command = command_from_trace_record_plan(&plan, &TraceRecordLauncher::Direct);
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(arguments[arguments.len() - 2..], ["-attach", "4242"]);
        assert_eq!(plan.target.name(), "attach_after_cet_disabled_launch");
        assert_eq!(plan.target.process_id(), Some(4242));

        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn parses_windows_sudo_modes() {
        assert_eq!(
            parse_windows_sudo_mode("Sudo is currently in Force New Window mode"),
            Some(WindowsSudoMode::ForceNewWindow)
        );
        assert_eq!(
            parse_windows_sudo_mode("Sudo is currently in Input Closed mode"),
            Some(WindowsSudoMode::DisableInput)
        );
        assert_eq!(
            parse_windows_sudo_mode("Sudo is currently in Inline mode"),
            Some(WindowsSudoMode::Inline)
        );
    }

    #[test]
    fn ttd_not_found_message_includes_official_install_command() {
        assert!(
            ttd_not_found_message().contains("winget install --id Microsoft.TimeTravelDebugging")
        );
    }

    #[test]
    fn matches_loaded_module_by_basename_or_full_path() {
        let modules = [ModuleInfo {
            base_address: 0x140000000,
            module_name: Some("RemoteDesktopManager_x64".to_string()),
            image_name: Some(
                r"C:\Temp\windbg-tool-ttd\rdm\RemoteDesktopManager_x64.exe".to_string(),
            ),
            loaded_image_name: None,
            symbol_file: None,
        }];

        assert_eq!(
            find_loaded_module(&modules, "remotedesktopmanager_x64.exe")
                .unwrap()
                .base_address,
            0x140000000
        );
        assert_eq!(
            find_loaded_module(
                &modules,
                r"C:\Temp\windbg-tool-ttd\rdm\RemoteDesktopManager_x64.exe"
            )
            .unwrap()
            .base_address,
            0x140000000
        );
    }

    #[test]
    fn parses_decimal_and_hexadecimal_breakpoint_addresses() {
        assert_eq!(parse_debug_address("0x140001000").unwrap(), 0x140001000);
        assert_eq!(parse_debug_address("4096").unwrap(), 4096);
        assert!(parse_debug_address("not-an-address").is_err());
    }

    #[test]
    fn startup_breakpoint_requires_exactly_one_location_kind() {
        let args = LiveStartupBreakArgs {
            command_line: "target.exe".to_string(),
            initial_break: false,
            address: Some("0x140001000".to_string()),
            module: Some("target.exe".to_string()),
            module_offset: Some("0x1000".to_string()),
            symbol: None,
            wait_for_module: None,
            initial_break_timeout_ms: 5000,
            wait_timeout_ms: 10000,
            max_frames: 16,
            end: "terminate".to_string(),
        };
        assert!(startup_breakpoint_spec(&args).is_err());

        let symbol_args = LiveStartupBreakArgs {
            initial_break: false,
            address: None,
            module: None,
            module_offset: None,
            symbol: Some("target!entry".to_string()),
            ..args
        };
        assert_eq!(
            startup_breakpoint_spec(&symbol_args).unwrap(),
            StartupBreakpointSpec::Symbol {
                expression: "target!entry".to_string()
            }
        );

        let initial_break_args = LiveStartupBreakArgs {
            initial_break: true,
            symbol: None,
            ..symbol_args
        };
        assert_eq!(
            startup_breakpoint_spec(&initial_break_args).unwrap(),
            StartupBreakpointSpec::InitialBreak
        );
    }

    #[test]
    fn validates_managed_breakpoint_metadata_tokens() {
        assert_eq!(
            validate_managed_breakpoint_token(
                "Devolutions.RemoteDesktopManager.Program.Main",
                "--method"
            )
            .unwrap(),
            "Devolutions.RemoteDesktopManager.Program.Main"
        );
        assert_eq!(
            validate_managed_breakpoint_token("Outer+Inner.Method`1", "--method").unwrap(),
            "Outer+Inner.Method`1"
        );
        assert!(validate_managed_breakpoint_token("Program.Main;qd", "--method").is_err());
        assert!(validate_managed_breakpoint_token(r#"Program.Main""#, "--method").is_err());
    }

    #[test]
    fn validates_managed_module_basename() {
        assert_eq!(
            validate_managed_module("RemoteDesktopManager.dll").unwrap(),
            "RemoteDesktopManager.dll"
        );
        assert!(validate_managed_module("RemoteDesktopManager").is_err());
        assert!(validate_managed_module(r#"RemoteDesktopManager.dll;qd"#).is_err());
    }
}
