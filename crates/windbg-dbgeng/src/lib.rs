use anyhow::{bail, Context};
use serde::Serialize;
use std::{
    env,
    path::{Path, PathBuf},
};

pub const MICROSOFT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";
pub const NT_SYMBOL_PATH_ENV: &str = "_NT_SYMBOL_PATH";
pub const NT_ALT_SYMBOL_PATH_ENV: &str = "_NT_ALT_SYMBOL_PATH";
pub const NT_SYMCACHE_PATH_ENV: &str = "_NT_SYMCACHE_PATH";
const DEFAULT_DBGENG_SYMBOL_CACHE: &str = ".windbg-symbol-cache";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardSymbolEnvironment {
    pub symbol_path: Option<String>,
    pub symcache_dir: Option<PathBuf>,
}

impl StandardSymbolEnvironment {
    pub fn from_process() -> Self {
        Self::from_values(
            env_path(NT_SYMBOL_PATH_ENV),
            env_path(NT_ALT_SYMBOL_PATH_ENV),
            env::var_os(NT_SYMCACHE_PATH_ENV).map(PathBuf::from),
        )
    }

    pub fn from_values(
        symbol_path: Option<String>,
        alternate_symbol_path: Option<String>,
        symcache_dir: Option<PathBuf>,
    ) -> Self {
        let symbol_path = [symbol_path, alternate_symbol_path]
            .into_iter()
            .flatten()
            .filter(|path| !path.is_empty())
            .collect::<Vec<_>>()
            .join(";");
        Self {
            symbol_path: (!symbol_path.is_empty()).then_some(symbol_path),
            symcache_dir: symcache_dir.filter(|path| !path.as_os_str().is_empty()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDbgEngSymbolPath {
    pub symbol_path: String,
    pub symbol_cache_dir: PathBuf,
}

pub fn resolve_dbgeng_symbol_path() -> ResolvedDbgEngSymbolPath {
    resolve_dbgeng_symbol_path_with_environment(
        StandardSymbolEnvironment::from_process(),
        Path::new(DEFAULT_DBGENG_SYMBOL_CACHE),
    )
}

pub fn resolve_dbgeng_symbol_path_with_environment(
    environment: StandardSymbolEnvironment,
    default_cache_dir: &Path,
) -> ResolvedDbgEngSymbolPath {
    let symbol_cache_dir = environment
        .symcache_dir
        .unwrap_or_else(|| default_cache_dir.to_path_buf());
    let mut paths = environment.symbol_path.into_iter().collect::<Vec<_>>();
    if !paths
        .iter()
        .any(|path| path.contains(MICROSOFT_SYMBOL_SERVER))
    {
        paths.push(format!(
            "srv*{}*{}",
            symbol_cache_dir.to_string_lossy(),
            MICROSOFT_SYMBOL_SERVER
        ));
    }
    ResolvedDbgEngSymbolPath {
        symbol_path: paths.join(";"),
        symbol_cache_dir,
    }
}

fn env_path(name: &str) -> Option<String> {
    env::var_os(name).and_then(|value| {
        let value = value.to_string_lossy().trim().to_string();
        (!value.is_empty()).then_some(value)
    })
}

#[derive(Debug, Clone)]
pub struct ProcessServerOptions {
    pub transport: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessServerResult {
    pub transport: String,
    pub exited: bool,
}

#[derive(Debug, Clone)]
pub struct LiveLaunchOptions {
    pub command_line: String,
    pub initial_break_timeout_ms: u32,
    pub end: LiveLaunchEnd,
}

#[derive(Debug, Clone)]
pub struct LiveLaunchSessionOptions {
    pub command_line: String,
    pub initial_break_timeout_ms: u32,
}

#[derive(Debug, Clone)]
pub struct LiveAttachOptions {
    pub process_id: u32,
    pub initial_break_timeout_ms: u32,
}

#[derive(Debug, Clone)]
pub struct DumpOpenOptions {
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct DumpWriteOptions {
    pub path: PathBuf,
    pub kind: DumpKind,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct ProcessDumpOptions {
    pub process_id: u32,
    pub initial_break_timeout_ms: u32,
    pub write: DumpWriteOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpKind {
    Mini,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveLaunchEnd {
    Detach,
    Terminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebuggerSessionKind {
    Live,
    Dump,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveLaunchResult {
    pub command_line: String,
    pub initial_break_timeout_ms: u32,
    pub wait_succeeded: bool,
    pub execution_status: Option<u32>,
    pub execution_status_name: Option<String>,
    pub symbol_path: String,
    pub end: LiveLaunchEnd,
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpWriteResult {
    pub path: PathBuf,
    pub kind: DumpKind,
    pub qualifier: u32,
    pub format_flags: u32,
    pub overwrite: bool,
    pub target: String,
    pub process_id: Option<u32>,
    pub detached: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerExecutionStatus {
    pub raw: Option<u32>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerSessionSummary {
    pub kind: DebuggerSessionKind,
    pub target: String,
    pub process_id: Option<u32>,
    pub dump_path: Option<PathBuf>,
    pub processor_type: Option<u32>,
    pub processor_name: Option<String>,
    pub execution_status: DebuggerExecutionStatus,
    pub symbol_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoreRegisterState {
    pub thread_system_id: Option<u32>,
    pub instruction_offset: Option<u64>,
    pub stack_offset: Option<u64>,
    pub frame_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryReadResult {
    pub address: u64,
    pub requested_size: u32,
    pub bytes_read: u32,
    pub complete: bool,
    pub data: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub engine_id: u32,
    pub system_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub base_address: u64,
    pub module_name: Option<String>,
    pub image_name: Option<String>,
    pub loaded_image_name: Option<String>,
    pub symbol_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolInfo {
    pub address: u64,
    pub name: String,
    pub displacement: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceLocation {
    pub address: u64,
    pub file: String,
    pub line: u32,
    pub displacement: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackFrameInfo {
    pub instruction_offset: u64,
    pub return_offset: u64,
    pub frame_offset: u64,
    pub stack_offset: u64,
    pub frame_number: u32,
    pub inline_frame: bool,
    pub params: [u64; 4],
    pub symbol: Option<SymbolInfo>,
    pub source: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisassemblyLine {
    pub address: u64,
    pub next_address: u64,
    pub text: String,
    pub symbol: Option<SymbolInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisassemblyResult {
    pub start_address: u64,
    pub lines: Vec<DisassemblyLine>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BreakpointInfo {
    pub id: u32,
    pub offset: u64,
    pub break_type: u32,
    pub flags: u32,
    pub enabled: bool,
    pub data_size: u32,
    pub data_access_type: u32,
    pub match_thread: Option<u32>,
    pub command: Option<String>,
    pub offset_expression: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluationResult {
    pub expression: String,
    pub value_type: u32,
    pub value_type_name: String,
    pub unsigned_value: Option<u64>,
    pub signed_value: Option<i64>,
    pub float64_value: Option<f64>,
}

pub fn start_process_server(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    start_process_server_impl(options)
}

pub fn live_launch_initial_break(options: LiveLaunchOptions) -> anyhow::Result<LiveLaunchResult> {
    live_launch_initial_break_impl(options)
}

pub fn launch_live_session(options: LiveLaunchSessionOptions) -> anyhow::Result<DebuggerSession> {
    launch_live_session_impl(options)
}

pub fn attach_live_session(options: LiveAttachOptions) -> anyhow::Result<DebuggerSession> {
    attach_live_session_impl(options)
}

pub fn open_dump_session(options: DumpOpenOptions) -> anyhow::Result<DebuggerSession> {
    open_dump_session_impl(options)
}

pub fn write_process_dump(options: ProcessDumpOptions) -> anyhow::Result<DumpWriteResult> {
    write_process_dump_impl(options)
}

#[cfg(windows)]
pub struct DebuggerSession {
    kind: DebuggerSessionKind,
    target: String,
    process_id: Option<u32>,
    dump_path: Option<PathBuf>,
    client: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugClient5,
    control: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl5,
    data_spaces: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugDataSpaces4,
    registers: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugRegisters,
    symbols: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSymbols5,
    system_objects: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSystemObjects,
    symbol_path: String,
}

#[cfg(windows)]
unsafe impl Send for DebuggerSession {}

#[cfg(not(windows))]
pub struct DebuggerSession;

#[cfg(windows)]
impl DebuggerSession {
    pub fn summary(&self) -> DebuggerSessionSummary {
        DebuggerSessionSummary {
            kind: self.kind,
            target: self.target.clone(),
            process_id: self.current_process_system_id().ok().or(self.process_id),
            dump_path: self.dump_path.clone(),
            processor_type: self.processor_type().ok(),
            processor_name: self.processor_name().ok(),
            execution_status: self.execution_status(),
            symbol_path: self.symbol_path.clone(),
        }
    }

    pub fn kind(&self) -> DebuggerSessionKind {
        self.kind
    }

    pub fn execution_status(&self) -> DebuggerExecutionStatus {
        let raw = unsafe { self.control.GetExecutionStatus().ok() };
        DebuggerExecutionStatus {
            raw,
            name: raw.map(status_name),
        }
    }

    pub fn wait_for_event(&self, timeout_ms: u32) -> anyhow::Result<DebuggerExecutionStatus> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_STATUS_TIMEOUT, DEBUG_WAIT_DEFAULT,
        };

        let wait = unsafe { self.control.WaitForEvent(DEBUG_WAIT_DEFAULT, timeout_ms) };
        let status = self.execution_status();
        match wait {
            Ok(()) => Ok(status),
            Err(_) if status.raw == Some(DEBUG_STATUS_TIMEOUT) => Ok(status),
            Err(error) => Err(error.into()),
        }
    }

    pub fn continue_execution(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STATUS_GO;

        unsafe {
            self.control.SetExecutionStatus(DEBUG_STATUS_GO)?;
        }
        Ok(self.execution_status())
    }

    pub fn step_into(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STATUS_STEP_INTO;

        unsafe {
            self.control.SetExecutionStatus(DEBUG_STATUS_STEP_INTO)?;
        }
        Ok(self.execution_status())
    }

    pub fn detach(&self) -> anyhow::Result<()> {
        unsafe {
            self.client.DetachProcesses()?;
        }
        Ok(())
    }

    pub fn terminate(&self) -> anyhow::Result<()> {
        unsafe {
            self.client.TerminateProcesses()?;
        }
        Ok(())
    }

    pub fn write_dump(&self, options: DumpWriteOptions) -> anyhow::Result<DumpWriteResult> {
        if self.kind != DebuggerSessionKind::Live {
            bail!("DbgEng dump writing requires a live target session");
        }
        let process_id = self
            .current_process_system_id()
            .ok()
            .or(self.process_id)
            .context("no process id is available for this live target")?;
        write_process_dump_file(process_id, self.target.clone(), false, options)
    }

    pub fn core_registers(&self) -> anyhow::Result<CoreRegisterState> {
        let instruction_offset = unsafe { self.registers.GetInstructionOffset().ok() };
        let stack_offset = unsafe { self.registers.GetStackOffset().ok() };
        let frame_offset = unsafe { self.registers.GetFrameOffset().ok() };

        Ok(CoreRegisterState {
            thread_system_id: self.current_thread_system_id().ok(),
            instruction_offset,
            stack_offset,
            frame_offset,
        })
    }

    pub fn read_memory(&self, address: u64, size: u32) -> anyhow::Result<MemoryReadResult> {
        let mut buffer = vec![0u8; size as usize];
        let mut bytes_read = 0u32;
        unsafe {
            self.data_spaces.ReadVirtual(
                address,
                buffer.as_mut_ptr() as _,
                size,
                Some(&mut bytes_read),
            )?;
        }
        buffer.truncate(bytes_read as usize);
        Ok(MemoryReadResult {
            address,
            requested_size: size,
            bytes_read,
            complete: bytes_read == size,
            data: encode_hex(&buffer),
        })
    }

    pub fn threads(&self) -> anyhow::Result<Vec<ThreadInfo>> {
        let count = unsafe { self.system_objects.GetNumberThreads()? };
        let mut engine_ids = vec![0u32; count as usize];
        let mut system_ids = vec![0u32; count as usize];
        unsafe {
            self.system_objects.GetThreadIdsByIndex(
                0,
                count,
                Some(engine_ids.as_mut_ptr()),
                Some(system_ids.as_mut_ptr()),
            )?;
        }
        Ok(engine_ids
            .into_iter()
            .zip(system_ids)
            .map(|(engine_id, system_id)| ThreadInfo {
                engine_id,
                system_id,
            })
            .collect())
    }

    pub fn modules(&self) -> anyhow::Result<Vec<ModuleInfo>> {
        let mut loaded = 0u32;
        let mut unloaded = 0u32;
        unsafe {
            self.symbols.GetNumberModules(&mut loaded, &mut unloaded)?;
        }
        let mut modules = Vec::with_capacity(loaded as usize);
        for index in 0..loaded {
            let base_address = unsafe { self.symbols.GetModuleByIndex(index)? };
            modules.push(ModuleInfo {
                base_address,
                module_name: self.module_name_string(
                    windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_MODULE,
                    index,
                    base_address,
                ),
                image_name: self.module_name_string(
                    windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_IMAGE,
                    index,
                    base_address,
                ),
                loaded_image_name: self.module_name_string(
                    windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_LOADED_IMAGE,
                    index,
                    base_address,
                ),
                symbol_file: self.module_name_string(
                    windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_SYMBOL_FILE,
                    index,
                    base_address,
                ),
            });
        }
        Ok(modules)
    }

    pub fn module_by_offset(&self, address: u64) -> anyhow::Result<Option<ModuleInfo>> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_GETMOD_NO_UNLOADED_MODULES;

        let mut index = 0u32;
        let mut base_address = 0u64;
        let result = unsafe {
            self.symbols.GetModuleByOffset2(
                address,
                0,
                DEBUG_GETMOD_NO_UNLOADED_MODULES,
                Some(&mut index),
                Some(&mut base_address),
            )
        };
        if result.is_err() {
            return Ok(None);
        }
        Ok(Some(self.module_info(index, base_address)))
    }

    pub fn symbol_by_offset(&self, address: u64) -> anyhow::Result<Option<SymbolInfo>> {
        self.try_symbol_by_offset(address)
    }

    pub fn source_by_offset(&self, address: u64) -> anyhow::Result<Option<SourceLocation>> {
        let mut line = 0u32;
        let mut displacement = 0u64;
        let file = match read_wide_string(|buffer, size| unsafe {
            self.symbols.GetLineByOffsetWide(
                address,
                Some(&mut line),
                Some(buffer),
                size,
                Some(&mut displacement),
            )
        }) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        Ok(Some(SourceLocation {
            address,
            file,
            line,
            displacement,
        }))
    }

    pub fn stack_trace(&self, max_frames: u32) -> anyhow::Result<Vec<StackFrameInfo>> {
        let registers = self.core_registers()?;
        let frame_offset = registers.frame_offset.unwrap_or(0);
        let stack_offset = registers.stack_offset.unwrap_or(0);
        let instruction_offset = registers.instruction_offset.unwrap_or(0);
        let mut frames = vec![
            windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STACK_FRAME::default();
            max_frames as usize
        ];
        let mut filled = 0u32;
        unsafe {
            self.control.GetStackTrace(
                frame_offset,
                stack_offset,
                instruction_offset,
                &mut frames,
                Some(&mut filled),
            )?;
        }
        frames.truncate(filled as usize);
        Ok(frames
            .into_iter()
            .map(|frame| StackFrameInfo {
                instruction_offset: frame.InstructionOffset,
                return_offset: frame.ReturnOffset,
                frame_offset: frame.FrameOffset,
                stack_offset: frame.StackOffset,
                frame_number: frame.FrameNumber,
                inline_frame: frame.Virtual.as_bool(),
                params: frame.Params,
                symbol: self
                    .try_symbol_by_offset(frame.InstructionOffset)
                    .ok()
                    .flatten(),
                source: self
                    .source_by_offset(frame.InstructionOffset)
                    .ok()
                    .flatten(),
            })
            .collect())
    }

    pub fn disassemble(
        &self,
        address: Option<u64>,
        count: u32,
    ) -> anyhow::Result<DisassemblyResult> {
        let start_address = match address {
            Some(value) => value,
            None => self
                .core_registers()?
                .instruction_offset
                .context("no current instruction offset is available for this target")?,
        };
        let mut next_address = start_address;
        let mut lines = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut end_offset = 0u64;
            let text = read_wide_string(|buffer, size| unsafe {
                self.control
                    .DisassembleWide(next_address, 0, Some(buffer), size, &mut end_offset)
            })?;
            lines.push(DisassemblyLine {
                address: next_address,
                next_address: end_offset,
                text: text.trim().to_string(),
                symbol: self.try_symbol_by_offset(next_address).ok().flatten(),
            });
            if end_offset == next_address {
                break;
            }
            next_address = end_offset;
        }
        Ok(DisassemblyResult {
            start_address,
            lines,
        })
    }

    pub fn list_breakpoints(&self) -> anyhow::Result<Vec<BreakpointInfo>> {
        let count = unsafe { self.control.GetNumberBreakpoints()? };
        let mut breakpoints = Vec::with_capacity(count as usize);
        for index in 0..count {
            let breakpoint = unsafe { self.control.GetBreakpointByIndex2(index)? };
            breakpoints.push(self.breakpoint_info(&breakpoint)?);
        }
        Ok(breakpoints)
    }

    pub fn add_code_breakpoint(&self, address: u64) -> anyhow::Result<BreakpointInfo> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_ANY_ID, DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED,
        };

        let breakpoint = unsafe {
            self.control
                .AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)?
        };
        unsafe {
            breakpoint.SetOffset(address)?;
            breakpoint.AddFlags(DEBUG_BREAKPOINT_ENABLED)?;
        }
        self.breakpoint_info(&breakpoint)
    }

    pub fn add_code_breakpoint_expression(
        &self,
        expression: &str,
    ) -> anyhow::Result<BreakpointInfo> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_ANY_ID, DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED,
        };

        let mut expression_wide = expression.encode_utf16().collect::<Vec<_>>();
        expression_wide.push(0);
        let breakpoint = unsafe {
            self.control
                .AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID)?
        };
        unsafe {
            breakpoint.SetOffsetExpressionWide(PCWSTR(expression_wide.as_ptr()))?;
            breakpoint.AddFlags(DEBUG_BREAKPOINT_ENABLED)?;
        }
        self.breakpoint_info(&breakpoint)
    }

    pub fn add_data_breakpoint(
        &self,
        address: u64,
        size: u32,
        access_type: u32,
    ) -> anyhow::Result<BreakpointInfo> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_ANY_ID, DEBUG_BREAKPOINT_DATA, DEBUG_BREAKPOINT_ENABLED,
        };

        let breakpoint = unsafe {
            self.control
                .AddBreakpoint2(DEBUG_BREAKPOINT_DATA, DEBUG_ANY_ID)?
        };
        unsafe {
            breakpoint.SetOffset(address)?;
            breakpoint.SetDataParameters(size, access_type)?;
            breakpoint.AddFlags(DEBUG_BREAKPOINT_ENABLED)?;
        }
        self.breakpoint_info(&breakpoint)
    }

    pub fn remove_breakpoint(&self, breakpoint_id: u32) -> anyhow::Result<()> {
        let breakpoint = unsafe { self.control.GetBreakpointById2(breakpoint_id)? };
        unsafe {
            self.control.RemoveBreakpoint2(&breakpoint)?;
        }
        Ok(())
    }

    pub fn evaluate(&self, expression: &str) -> anyhow::Result<EvaluationResult> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_VALUE_FLOAT64, DEBUG_VALUE_INT64,
        };

        let mut value =
            windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_VALUE::default();
        let mut expression_wide = expression.encode_utf16().collect::<Vec<_>>();
        expression_wide.push(0);
        unsafe {
            self.control.EvaluateWide(
                PCWSTR(expression_wide.as_ptr()),
                DEBUG_VALUE_INT64,
                &mut value,
                None,
            )?;
        }
        let (unsigned_value, signed_value, float64_value) = unsafe {
            match value.Type {
                DEBUG_VALUE_INT64 => {
                    let raw = value.Anonymous.Anonymous.I64;
                    (Some(raw), Some(raw as i64), None)
                }
                DEBUG_VALUE_FLOAT64 => (None, None, Some(value.Anonymous.F64)),
                _ => (None, None, None),
            }
        };
        Ok(EvaluationResult {
            expression: expression.to_string(),
            value_type: value.Type,
            value_type_name: debug_value_type_name(value.Type).to_string(),
            unsigned_value,
            signed_value,
            float64_value,
        })
    }

    fn current_process_system_id(&self) -> anyhow::Result<u32> {
        Ok(unsafe { self.system_objects.GetCurrentProcessSystemId()? })
    }

    fn current_thread_system_id(&self) -> anyhow::Result<u32> {
        Ok(unsafe { self.system_objects.GetCurrentThreadSystemId()? })
    }

    fn processor_type(&self) -> anyhow::Result<u32> {
        Ok(unsafe { self.control.GetActualProcessorType()? })
    }

    fn processor_name(&self) -> anyhow::Result<String> {
        let processor_type = self.processor_type()?;
        read_wide_string(|buffer, size| unsafe {
            self.control
                .GetProcessorTypeNamesWide(processor_type, None, None, Some(buffer), size)
        })
    }

    fn module_name_string(&self, which: u32, index: u32, base_address: u64) -> Option<String> {
        read_wide_string(|buffer, size| unsafe {
            self.symbols
                .GetModuleNameStringWide(which, index, base_address, Some(buffer), size)
        })
        .ok()
    }

    fn module_info(&self, index: u32, base_address: u64) -> ModuleInfo {
        ModuleInfo {
            base_address,
            module_name: self.module_name_string(
                windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_MODULE,
                index,
                base_address,
            ),
            image_name: self.module_name_string(
                windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_IMAGE,
                index,
                base_address,
            ),
            loaded_image_name: self.module_name_string(
                windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_LOADED_IMAGE,
                index,
                base_address,
            ),
            symbol_file: self.module_name_string(
                windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODNAME_SYMBOL_FILE,
                index,
                base_address,
            ),
        }
    }

    fn try_symbol_by_offset(&self, address: u64) -> anyhow::Result<Option<SymbolInfo>> {
        let mut displacement = 0u64;
        let name = match read_wide_string(|buffer, size| unsafe {
            self.symbols
                .GetNameByOffsetWide(address, Some(buffer), size, Some(&mut displacement))
        }) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        Ok(Some(SymbolInfo {
            address,
            name,
            displacement,
        }))
    }

    fn breakpoint_info(
        &self,
        breakpoint: &windows::Win32::System::Diagnostics::Debug::Extensions::IDebugBreakpoint2,
    ) -> anyhow::Result<BreakpointInfo> {
        let mut parameters =
            windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_BREAKPOINT_PARAMETERS::default();
        unsafe {
            breakpoint.GetParameters(&mut parameters)?;
        }
        Ok(BreakpointInfo {
            id: parameters.Id,
            offset: unsafe { breakpoint.GetOffset().unwrap_or(parameters.Offset) },
            break_type: parameters.BreakType,
            flags: parameters.Flags,
            enabled: parameters.Flags
                & windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_BREAKPOINT_ENABLED
                != 0,
            data_size: parameters.DataSize,
            data_access_type: parameters.DataAccessType,
            match_thread: (parameters.MatchThread
                != windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_ANY_ID)
                .then_some(parameters.MatchThread),
            command: read_wide_string(|buffer, size| unsafe {
                breakpoint.GetCommandWide(Some(buffer), size)
            })
            .ok(),
            offset_expression: read_wide_string(|buffer, size| unsafe {
                breakpoint.GetOffsetExpressionWide(Some(buffer), size)
            })
            .ok(),
        })
    }
}

#[cfg(not(windows))]
impl DebuggerSession {
    pub fn summary(&self) -> DebuggerSessionSummary {
        DebuggerSessionSummary {
            kind: DebuggerSessionKind::Live,
            target: "unsupported".to_string(),
            process_id: None,
            dump_path: None,
            processor_type: None,
            processor_name: None,
            execution_status: DebuggerExecutionStatus {
                raw: None,
                name: None,
            },
            symbol_path: resolve_dbgeng_symbol_path().symbol_path,
        }
    }

    pub fn kind(&self) -> DebuggerSessionKind {
        DebuggerSessionKind::Live
    }

    pub fn execution_status(&self) -> DebuggerExecutionStatus {
        DebuggerExecutionStatus {
            raw: None,
            name: None,
        }
    }

    pub fn wait_for_event(&self, _timeout_ms: u32) -> anyhow::Result<DebuggerExecutionStatus> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn continue_execution(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn step_into(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn detach(&self) -> anyhow::Result<()> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn terminate(&self) -> anyhow::Result<()> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn write_dump(&self, _options: DumpWriteOptions) -> anyhow::Result<DumpWriteResult> {
        anyhow::bail!("DbgEng dump writing is only supported on Windows")
    }

    pub fn core_registers(&self) -> anyhow::Result<CoreRegisterState> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn read_memory(&self, _address: u64, _size: u32) -> anyhow::Result<MemoryReadResult> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn threads(&self) -> anyhow::Result<Vec<ThreadInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn modules(&self) -> anyhow::Result<Vec<ModuleInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn module_by_offset(&self, _address: u64) -> anyhow::Result<Option<ModuleInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn symbol_by_offset(&self, _address: u64) -> anyhow::Result<Option<SymbolInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn source_by_offset(&self, _address: u64) -> anyhow::Result<Option<SourceLocation>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn stack_trace(&self, _max_frames: u32) -> anyhow::Result<Vec<StackFrameInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn disassemble(
        &self,
        _address: Option<u64>,
        _count: u32,
    ) -> anyhow::Result<DisassemblyResult> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn list_breakpoints(&self) -> anyhow::Result<Vec<BreakpointInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn add_code_breakpoint(&self, _address: u64) -> anyhow::Result<BreakpointInfo> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn add_code_breakpoint_expression(
        &self,
        _expression: &str,
    ) -> anyhow::Result<BreakpointInfo> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn add_data_breakpoint(
        &self,
        _address: u64,
        _size: u32,
        _access_type: u32,
    ) -> anyhow::Result<BreakpointInfo> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn remove_breakpoint(&self, _breakpoint_id: u32) -> anyhow::Result<()> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn evaluate(&self, _expression: &str) -> anyhow::Result<EvaluationResult> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }
}

fn status_name(status: u32) -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_STATUS_BREAK, DEBUG_STATUS_GO, DEBUG_STATUS_GO_HANDLED,
            DEBUG_STATUS_GO_NOT_HANDLED, DEBUG_STATUS_NO_DEBUGGEE, DEBUG_STATUS_STEP_INTO,
            DEBUG_STATUS_STEP_OVER, DEBUG_STATUS_TIMEOUT,
        };

        match status {
            DEBUG_STATUS_GO => "go",
            DEBUG_STATUS_GO_HANDLED => "go_handled",
            DEBUG_STATUS_GO_NOT_HANDLED => "go_not_handled",
            DEBUG_STATUS_STEP_INTO => "step_into",
            DEBUG_STATUS_STEP_OVER => "step_over",
            DEBUG_STATUS_BREAK => "break",
            DEBUG_STATUS_NO_DEBUGGEE => "no_debuggee",
            DEBUG_STATUS_TIMEOUT => "timeout",
            _ => "unknown",
        }
        .to_string()
    }
    #[cfg(not(windows))]
    {
        let _ = status;
        "unknown".to_string()
    }
}

#[cfg(windows)]
fn start_process_server_impl(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DebugCreate, IDebugClient5, DEBUG_CLASS_USER_WINDOWS,
    };
    use windows::Win32::System::Threading::INFINITE;

    let mut transport = options.transport.encode_utf16().collect::<Vec<_>>();
    transport.push(0);

    let client: IDebugClient5 = unsafe { DebugCreate()? };
    unsafe {
        client.StartProcessServerWide(
            DEBUG_CLASS_USER_WINDOWS,
            PCWSTR(transport.as_ptr()),
            None,
        )?;
        client.WaitForProcessServerEnd(INFINITE)?;
    }

    Ok(ProcessServerResult {
        transport: options.transport,
        exited: true,
    })
}

#[cfg(windows)]
fn live_launch_initial_break_impl(options: LiveLaunchOptions) -> anyhow::Result<LiveLaunchResult> {
    let session = launch_live_session_impl(LiveLaunchSessionOptions {
        command_line: options.command_line.clone(),
        initial_break_timeout_ms: options.initial_break_timeout_ms,
    })?;
    let execution_status = session.execution_status();
    let symbol_path = session.symbol_path.clone();
    match options.end {
        LiveLaunchEnd::Detach => session.detach()?,
        LiveLaunchEnd::Terminate => session.terminate()?,
    }

    Ok(LiveLaunchResult {
        command_line: options.command_line,
        initial_break_timeout_ms: options.initial_break_timeout_ms,
        wait_succeeded: true,
        execution_status: execution_status.raw,
        execution_status_name: execution_status.name,
        symbol_path,
        end: options.end,
    })
}

#[cfg(windows)]
fn launch_live_session_impl(options: LiveLaunchSessionOptions) -> anyhow::Result<DebuggerSession> {
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DebugCreate, IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters,
        IDebugSymbols5, IDebugSystemObjects, DEBUG_PROCESS_ONLY_THIS_PROCESS,
    };

    let mut command_line = options.command_line.encode_utf16().collect::<Vec<_>>();
    command_line.push(0);

    let client: IDebugClient5 = unsafe { DebugCreate()? };
    let control: IDebugControl5 = client.cast()?;
    let data_spaces: IDebugDataSpaces4 = client.cast()?;
    let registers: IDebugRegisters = client.cast()?;
    let symbols: IDebugSymbols5 = client.cast()?;
    let system_objects: IDebugSystemObjects = client.cast()?;
    let symbol_path = configure_dbgeng_symbol_path(&symbols)?;
    unsafe {
        client.CreateProcessWide(
            0,
            PCWSTR(command_line.as_ptr()),
            DEBUG_PROCESS_ONLY_THIS_PROCESS,
        )?;
        control.WaitForEvent(
            windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_WAIT_DEFAULT,
            options.initial_break_timeout_ms,
        )?;
    }

    Ok(DebuggerSession {
        kind: DebuggerSessionKind::Live,
        target: options.command_line,
        process_id: None,
        dump_path: None,
        client,
        control,
        data_spaces,
        registers,
        symbols,
        system_objects,
        symbol_path,
    })
}

#[cfg(windows)]
fn attach_live_session_impl(options: LiveAttachOptions) -> anyhow::Result<DebuggerSession> {
    use windows::core::Interface;
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DebugCreate, IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters,
        IDebugSymbols5, IDebugSystemObjects, DEBUG_ATTACH_DEFAULT, DEBUG_WAIT_DEFAULT,
    };

    let client: IDebugClient5 = unsafe { DebugCreate()? };
    let control: IDebugControl5 = client.cast()?;
    let data_spaces: IDebugDataSpaces4 = client.cast()?;
    let registers: IDebugRegisters = client.cast()?;
    let symbols: IDebugSymbols5 = client.cast()?;
    let system_objects: IDebugSystemObjects = client.cast()?;
    let symbol_path = configure_dbgeng_symbol_path(&symbols)?;
    unsafe {
        client.AttachProcess(0, options.process_id, DEBUG_ATTACH_DEFAULT)?;
        control.WaitForEvent(DEBUG_WAIT_DEFAULT, options.initial_break_timeout_ms)?;
    }

    Ok(DebuggerSession {
        kind: DebuggerSessionKind::Live,
        target: format!("pid:{}", options.process_id),
        process_id: Some(options.process_id),
        dump_path: None,
        client,
        control,
        data_spaces,
        registers,
        symbols,
        system_objects,
        symbol_path,
    })
}

#[cfg(windows)]
fn open_dump_session_impl(options: DumpOpenOptions) -> anyhow::Result<DebuggerSession> {
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DebugCreate, IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters,
        IDebugSymbols5, IDebugSystemObjects, DEBUG_WAIT_DEFAULT,
    };

    let path_string = options.path.to_string_lossy().to_string();
    let mut path = path_string.encode_utf16().collect::<Vec<_>>();
    path.push(0);

    let client: IDebugClient5 = unsafe { DebugCreate()? };
    let control: IDebugControl5 = client.cast()?;
    let data_spaces: IDebugDataSpaces4 = client.cast()?;
    let registers: IDebugRegisters = client.cast()?;
    let symbols: IDebugSymbols5 = client.cast()?;
    let system_objects: IDebugSystemObjects = client.cast()?;
    let symbol_path = configure_dbgeng_symbol_path(&symbols)?;
    unsafe {
        client.OpenDumpFileWide(PCWSTR(path.as_ptr()), 0)?;
        control.WaitForEvent(DEBUG_WAIT_DEFAULT, 5000)?;
    }

    Ok(DebuggerSession {
        kind: DebuggerSessionKind::Dump,
        target: path_string,
        process_id: None,
        dump_path: Some(options.path),
        client,
        control,
        data_spaces,
        registers,
        symbols,
        system_objects,
        symbol_path,
    })
}

#[cfg(windows)]
fn configure_dbgeng_symbol_path(
    symbols: &windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSymbols5,
) -> anyhow::Result<String> {
    use windows::core::PCWSTR;

    let symbol_config = resolve_dbgeng_symbol_path();
    let mut symbol_path = symbol_config.symbol_path.encode_utf16().collect::<Vec<_>>();
    symbol_path.push(0);
    unsafe {
        symbols
            .SetSymbolPathWide(PCWSTR(symbol_path.as_ptr()))
            .context("setting the DbgEng symbol path")?;
    }
    Ok(symbol_config.symbol_path)
}

#[cfg(windows)]
fn write_process_dump_impl(options: ProcessDumpOptions) -> anyhow::Result<DumpWriteResult> {
    let _ = options.initial_break_timeout_ms;
    write_process_dump_file(
        options.process_id,
        format!("pid:{}", options.process_id),
        false,
        options.write,
    )
}

#[cfg(windows)]
fn read_wide_string<F>(mut reader: F) -> anyhow::Result<String>
where
    F: FnMut(&mut [u16], Option<*mut u32>) -> windows::core::Result<()>,
{
    let mut capacity = 256usize;
    loop {
        let mut buffer = vec![0u16; capacity];
        let mut needed = 0u32;
        reader(&mut buffer, Some(&mut needed))?;
        if needed == 0 || (needed as usize) <= buffer.len() {
            return Ok(decode_utf16(&buffer));
        }
        capacity = needed as usize;
    }
}

#[cfg(windows)]
fn decode_utf16(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

fn debug_value_type_name(value_type: u32) -> &'static str {
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_VALUE_FLOAT64, DEBUG_VALUE_INT64, DEBUG_VALUE_INVALID,
        };

        match value_type {
            DEBUG_VALUE_INVALID => "invalid",
            DEBUG_VALUE_INT64 => "int64",
            DEBUG_VALUE_FLOAT64 => "float64",
            _ => "other",
        }
    }
    #[cfg(not(windows))]
    {
        let _ = value_type;
        "other"
    }
}

const DEBUG_DUMP_SMALL_VALUE: u32 = 1024;
const DEBUG_DUMP_DEFAULT_VALUE: u32 = 1025;
const DEBUG_FORMAT_DEFAULT_VALUE: u32 = 0x0000_0000;
const DEBUG_FORMAT_NO_OVERWRITE_VALUE: u32 = 0x8000_0000;

fn dump_kind_qualifier(kind: DumpKind) -> u32 {
    match kind {
        DumpKind::Mini => DEBUG_DUMP_SMALL_VALUE,
        DumpKind::Full => DEBUG_DUMP_DEFAULT_VALUE,
    }
}

fn dump_format_flags(overwrite: bool) -> u32 {
    if overwrite {
        DEBUG_FORMAT_DEFAULT_VALUE
    } else {
        DEBUG_FORMAT_NO_OVERWRITE_VALUE
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

#[cfg(windows)]
fn write_process_dump_file(
    process_id: u32,
    target: String,
    detached: bool,
    options: DumpWriteOptions,
) -> anyhow::Result<DumpWriteResult> {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{
        MiniDumpWithDataSegs, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo,
        MiniDumpWithHandleData, MiniDumpWithProcessThreadData, MiniDumpWithThreadInfo,
        MiniDumpWithUnloadedModules, MiniDumpWriteDump, MINIDUMP_TYPE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    if !options.overwrite && options.path.exists() {
        bail!("dump output already exists: {}", options.path.display());
    }

    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            process_id,
        )?
    };
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(options.overwrite)
        .create_new(!options.overwrite)
        .open(&options.path)
        .with_context(|| format!("failed to create dump file: {}", options.path.display()))?;

    let dump_type = match options.kind {
        DumpKind::Mini => MINIDUMP_TYPE(0),
        DumpKind::Full => {
            MiniDumpWithFullMemory
                | MiniDumpWithHandleData
                | MiniDumpWithUnloadedModules
                | MiniDumpWithProcessThreadData
                | MiniDumpWithFullMemoryInfo
                | MiniDumpWithThreadInfo
                | MiniDumpWithDataSegs
        }
    };

    let write_result = unsafe {
        MiniDumpWriteDump(
            process,
            process_id,
            HANDLE(file.as_raw_handle()),
            dump_type,
            None,
            None,
            None,
        )
    };
    unsafe {
        CloseHandle(process)?;
    }
    if let Err(error) = write_result {
        return Err(error).context("MiniDumpWriteDump failed");
    }
    drop(file);
    let metadata = std::fs::metadata(&options.path)
        .with_context(|| format!("dump file was not created: {}", options.path.display()))?;
    if metadata.len() == 0 {
        bail!("created an empty dump file: {}", options.path.display());
    }
    Ok(DumpWriteResult {
        path: options.path,
        kind: options.kind,
        qualifier: dump_kind_qualifier(options.kind),
        format_flags: dump_format_flags(options.overwrite),
        overwrite: options.overwrite,
        target,
        process_id: Some(process_id),
        detached,
    })
}

#[cfg(not(windows))]
fn start_process_server_impl(options: ProcessServerOptions) -> anyhow::Result<ProcessServerResult> {
    let _ = options;
    anyhow::bail!("DbgEng process servers are only supported on Windows")
}

#[cfg(not(windows))]
fn live_launch_initial_break_impl(options: LiveLaunchOptions) -> anyhow::Result<LiveLaunchResult> {
    let _ = options;
    anyhow::bail!("DbgEng live launch is only supported on Windows")
}

#[cfg(not(windows))]
fn launch_live_session_impl(options: LiveLaunchSessionOptions) -> anyhow::Result<DebuggerSession> {
    let _ = options;
    anyhow::bail!("DbgEng live launch is only supported on Windows")
}

#[cfg(not(windows))]
fn attach_live_session_impl(options: LiveAttachOptions) -> anyhow::Result<DebuggerSession> {
    let _ = options;
    anyhow::bail!("DbgEng live attach is only supported on Windows")
}

#[cfg(not(windows))]
fn open_dump_session_impl(options: DumpOpenOptions) -> anyhow::Result<DebuggerSession> {
    let _ = options;
    anyhow::bail!("DbgEng dump sessions are only supported on Windows")
}

#[cfg(not(windows))]
fn write_process_dump_impl(options: ProcessDumpOptions) -> anyhow::Result<DumpWriteResult> {
    let _ = options;
    anyhow::bail!("DbgEng dump writing is only supported on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_dump_kinds_to_dbgeng_qualifiers() {
        assert_eq!(dump_kind_qualifier(DumpKind::Mini), 1024);
        assert_eq!(dump_kind_qualifier(DumpKind::Full), 1025);
    }

    #[test]
    fn uses_no_overwrite_by_default() {
        assert_eq!(dump_format_flags(false), 0x8000_0000);
        assert_eq!(dump_format_flags(true), 0);
    }

    #[test]
    fn standard_symbol_environment_preserves_windows_search_order() {
        let environment = StandardSymbolEnvironment::from_values(
            Some("srv*C:\\primary*https://symbols.example.test".to_string()),
            Some("C:\\alternate-symbols".to_string()),
            Some(PathBuf::from("C:\\symbol-cache")),
        );

        assert_eq!(
            environment.symbol_path.as_deref(),
            Some("srv*C:\\primary*https://symbols.example.test;C:\\alternate-symbols")
        );
        assert_eq!(
            environment.symcache_dir,
            Some(PathBuf::from("C:\\symbol-cache"))
        );
    }

    #[test]
    fn dbgeng_symbol_path_appends_public_server_using_environment_cache() {
        let resolved = resolve_dbgeng_symbol_path_with_environment(
            StandardSymbolEnvironment::from_values(
                Some("C:\\private-symbols".to_string()),
                Some("C:\\alternate-symbols".to_string()),
                Some(PathBuf::from("C:\\symbol-cache")),
            ),
            Path::new("unused-cache"),
        );

        assert_eq!(
            resolved.symbol_path,
            "C:\\private-symbols;C:\\alternate-symbols;srv*C:\\symbol-cache*https://msdl.microsoft.com/download/symbols"
        );
        assert_eq!(resolved.symbol_cache_dir, PathBuf::from("C:\\symbol-cache"));
    }

    #[test]
    fn dbgeng_symbol_path_does_not_duplicate_public_server() {
        let resolved = resolve_dbgeng_symbol_path_with_environment(
            StandardSymbolEnvironment::from_values(
                Some(format!("srv*C:\\cache*{MICROSOFT_SYMBOL_SERVER}")),
                None,
                Some(PathBuf::from("C:\\unused-cache")),
            ),
            Path::new("unused-cache"),
        );

        assert_eq!(
            resolved
                .symbol_path
                .matches(MICROSOFT_SYMBOL_SERVER)
                .count(),
            1
        );
    }
}
