use anyhow::{bail, ensure, Context};
use serde::Serialize;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::{
    env,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Instant,
};

#[cfg(windows)]
mod coreclr_dac;
#[cfg(windows)]
pub use coreclr_dac::{
    CoreClrDacBridge, ManagedCodeAvailability, ManagedMethodInfo, ManagedRuntimeInfo,
};

pub const MICROSOFT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";
pub const NT_SYMBOL_PATH_ENV: &str = "_NT_SYMBOL_PATH";
pub const NT_ALT_SYMBOL_PATH_ENV: &str = "_NT_ALT_SYMBOL_PATH";
pub const NT_SYMCACHE_PATH_ENV: &str = "_NT_SYMCACHE_PATH";
pub const DBGENG_RUNTIME_DIR_ENV: &str = "WINDBG_DBGENG_RUNTIME_DIR";
pub const MAX_VIRTUAL_MEMORY_MAP_REGIONS: u32 = 4096;
const DEFAULT_DBGENG_SYMBOL_CACHE: &str = ".windbg-symbol-cache";
const DBGENG_DLL_NAME: &str = "dbgeng.dll";
#[cfg(windows)]
const DBGENG_RUNTIME_COMPONENTS: [&str; 4] = [
    "dbgcore.dll",
    "dbghelp.dll",
    "dbgmodel.dll",
    DBGENG_DLL_NAME,
];
const DBGENG_WAIT_TIMEOUT_HRESULT: i32 = 1;

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

#[cfg(windows)]
fn dbgeng_runtime_dll(
    explicit_runtime_dir: Option<&Path>,
    executable_path: Option<&Path>,
) -> anyhow::Result<Option<PathBuf>> {
    if let Some(runtime_dir) = explicit_runtime_dir {
        let dll = runtime_dir.join(DBGENG_DLL_NAME);
        ensure!(
            dll.is_file(),
            "{DBGENG_RUNTIME_DIR_ENV} must name a directory containing {}",
            dll.display()
        );
        return Ok(Some(dll));
    }

    Ok(executable_path
        .and_then(Path::parent)
        .map(|directory| directory.join(DBGENG_DLL_NAME))
        .filter(|dll| dll.is_file()))
}

#[cfg(windows)]
fn load_library_from_path(
    path: &Path,
    component: &str,
) -> anyhow::Result<windows::Win32::Foundation::HMODULE> {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::{
        LoadLibraryExW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    };

    let mut path_wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    path_wide.push(0);
    unsafe {
        LoadLibraryExW(
            PCWSTR(path_wide.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    }
    .with_context(|| format!("loading {component} {}", path.display()))
}

#[cfg(windows)]
fn ensure_dbgeng_runtime_loaded() -> anyhow::Result<windows::Win32::Foundation::HMODULE> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::{
        LoadLibraryExW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    static LOAD_RESULT: OnceLock<Result<usize, String>> = OnceLock::new();

    let result = LOAD_RESULT.get_or_init(|| {
        (|| -> anyhow::Result<usize> {
            let explicit_runtime_dir = env::var_os(DBGENG_RUNTIME_DIR_ENV).map(PathBuf::from);
            let executable_path = env::current_exe().ok();
            let dll =
                dbgeng_runtime_dll(explicit_runtime_dir.as_deref(), executable_path.as_deref())?;
            let Some(dll) = dll else {
                let mut component_wide = "dbgeng.dll".encode_utf16().collect::<Vec<_>>();
                component_wide.push(0);
                let module = unsafe {
                    LoadLibraryExW(
                        PCWSTR(component_wide.as_ptr()),
                        None,
                        LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                    )
                }
                .context("loading DbgEng from the system runtime")?;
                return Ok(module.0 as usize);
            };
            let runtime_dir = dll
                .parent()
                .context("the selected DbgEng runtime DLL has no parent directory")?;
            // Load the version-matched companions before DbgEng so its imports resolve from the
            // staged runtime set instead of depending on ambient DLL-search state.
            for component_name in DBGENG_RUNTIME_COMPONENTS {
                let component = runtime_dir.join(component_name);
                ensure!(
                    component.is_file(),
                    "the selected DbgEng runtime is missing required component {}",
                    component.display()
                );
                let module = load_library_from_path(&component, "DbgEng runtime component")?;
                if component_name == DBGENG_DLL_NAME {
                    return Ok(module.0 as usize);
                }
            }
            unreachable!("the DbgEng runtime component list must include dbgeng.dll")
        })()
        .map_err(|error| format!("{error:#}"))
    });

    match result {
        Ok(module) => Ok(HMODULE(*module as *mut _)),
        Err(error) => bail!("{error}"),
    }
}

#[cfg(windows)]
fn enable_create_process_stop(
    control: &windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl5,
) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_EXECUTE_DEFAULT, DEBUG_OUTCTL_THIS_CLIENT,
    };

    let command = "sxe cpr\0".encode_utf16().collect::<Vec<_>>();
    unsafe {
        control.ExecuteWide(
            DEBUG_OUTCTL_THIS_CLIENT,
            PCWSTR(command.as_ptr()),
            DEBUG_EXECUTE_DEFAULT,
        )
    }
    .context("configuring DbgEng to stop on the create-process debug event")?;
    Ok(())
}

#[cfg(windows)]
fn create_debug_client(
) -> anyhow::Result<windows::Win32::System::Diagnostics::Debug::Extensions::IDebugClient5> {
    use std::ffi::c_void;
    use windows::core::{Interface, PCSTR};
    use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugClient5;
    use windows::Win32::System::LibraryLoader::GetProcAddress;

    type DebugCreateFn = unsafe extern "system" fn(
        *const windows::core::GUID,
        *mut *mut c_void,
    ) -> windows::core::HRESULT;

    let module = ensure_dbgeng_runtime_loaded()?;
    let procedure = unsafe { GetProcAddress(module, PCSTR(c"DebugCreate".as_ptr().cast())) }
        .context("the selected DbgEng runtime does not export DebugCreate")?;
    // GetProcAddress returns an untyped module export. DebugCreate has the documented
    // DbgEng ABI and the module is retained by ensure_dbgeng_runtime_loaded.
    let debug_create: DebugCreateFn = unsafe { std::mem::transmute(procedure) };
    let mut client = std::ptr::null_mut();
    unsafe { debug_create(&IDebugClient5::IID, &mut client) }
        .ok()
        .context("DbgEng DebugCreate failed")?;
    ensure!(
        !client.is_null(),
        "DbgEng DebugCreate succeeded without returning an IDebugClient5"
    );
    Ok(unsafe { IDebugClient5::from_raw(client) })
}

#[cfg(windows)]
fn enable_initial_break(
    control: &windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl5,
) -> anyhow::Result<()> {
    use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_ENGOPT_INITIAL_BREAK;

    unsafe { control.AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK) }
        .context("enabling the DbgEng initial-break engine option")?;
    Ok(())
}

#[cfg(windows)]
fn wait_for_initial_event(
    control: &windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl5,
    timeout_ms: u32,
    operation: &str,
) -> anyhow::Result<()> {
    use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_WAIT_DEFAULT;

    match unsafe { control.WaitForEvent(DEBUG_WAIT_DEFAULT, timeout_ms) } {
        Ok(()) => Ok(()),
        Err(error) if is_dbgeng_wait_timeout_hresult(error.code().0) => {
            bail!("DbgEng {operation} initial WaitForEvent timed out after {timeout_ms} ms")
        }
        Err(error) => Err(error).context(format!("DbgEng {operation} initial WaitForEvent failed")),
    }
}

fn is_dbgeng_wait_timeout_hresult(hresult: i32) -> bool {
    hresult == DBGENG_WAIT_TIMEOUT_HRESULT
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
    pub initial_stop: LiveInitialStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveInitialStop {
    SoftwareBreakpoint,
    CreateProcessEvent,
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
pub struct VirtualMemoryRegion {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protection: u32,
    pub region_size: u64,
    pub state: u32,
    pub protection: u32,
    pub kind: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualMemoryMap {
    pub source: String,
    pub status: String,
    pub region_limit: u32,
    pub regions: Vec<VirtualMemoryRegion>,
    pub truncated: bool,
    pub next_query_address: Option<u64>,
    pub query_error: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DebuggerOutputCaptureOptions {
    pub started_at: Instant,
    pub max_records: u32,
    pub max_chars_per_record: u32,
    pub max_total_chars: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerOutputRecord {
    pub elapsed_ms: u64,
    pub preceding_event_index: Option<usize>,
    pub mask: u32,
    pub categories: Vec<String>,
    pub text: String,
    pub text_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerOutputCaptureResult {
    pub status: String,
    pub source: String,
    pub records: Vec<DebuggerOutputRecord>,
    pub records_returned: usize,
    pub dropped_record_count: u32,
    pub dropped_text_char_count: u32,
    pub max_records: u32,
    pub max_chars_per_record: u32,
    pub max_total_chars: u32,
    pub detail: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerExceptionInfo {
    pub code: u32,
    pub flags: u32,
    pub address: u64,
    pub first_chance: bool,
    pub parameters: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerEventInfo {
    pub event_type: u32,
    pub event_name: String,
    pub process_system_id: u32,
    pub thread_system_id: u32,
    pub description: Option<String>,
    pub extra_information_size: u32,
    pub breakpoint_id: Option<u32>,
    pub exception: Option<DebuggerExceptionInfo>,
    pub module_base: Option<u64>,
    pub exit_code: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadContext {
    pub thread: ThreadInfo,
    pub registers: CoreRegisterState,
    pub current_module: Option<ModuleInfo>,
    pub current_symbol: Option<SymbolInfo>,
    pub stack: Vec<StackFrameInfo>,
    pub disassembly: Option<DisassemblyResult>,
    pub current_thread_preserved: bool,
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
const OUTPUT_CAPTURE_NO_EVENT_INDEX: usize = usize::MAX;
#[cfg(windows)]
const DEBUG_OUTPUT_DEBUGGEE_MASK: u32 = 0x0000_0080;
#[cfg(windows)]
const DEBUG_OUTPUT_DEBUGGEE_PROMPT_MASK: u32 = 0x0000_0100;

#[cfg(windows)]
struct DebuggerOutputCaptureShared {
    started_at: Instant,
    max_records: usize,
    max_chars_per_record: usize,
    max_total_chars: usize,
    preceding_event_index: AtomicUsize,
    state: Mutex<DebuggerOutputCaptureState>,
}

#[cfg(windows)]
#[derive(Default)]
struct DebuggerOutputCaptureState {
    records: Vec<DebuggerOutputRecord>,
    total_text_chars: usize,
    dropped_record_count: u32,
    dropped_text_char_count: u32,
}

#[cfg(windows)]
#[windows::core::implement(
    windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacksWide
)]
struct DebuggerOutputCallback {
    shared: Arc<DebuggerOutputCaptureShared>,
}

#[cfg(windows)]
impl windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacksWide_Impl
    for DebuggerOutputCallback_Impl
{
    fn Output(&self, mask: u32, text: &windows::core::PCWSTR) -> windows::core::Result<()> {
        if mask & (DEBUG_OUTPUT_DEBUGGEE_MASK | DEBUG_OUTPUT_DEBUGGEE_PROMPT_MASK) == 0 {
            return Ok(());
        }
        let text = unsafe { text.to_string() }
            .unwrap_or_else(|_| "<invalid UTF-16 DbgEng output>".to_string());
        self.shared.record(mask, text);
        Ok(())
    }
}

#[cfg(windows)]
impl DebuggerOutputCaptureShared {
    fn record(&self, mask: u32, text: String) {
        let original_chars = text.chars().count();
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        if state.records.len() >= self.max_records {
            state.dropped_record_count = state.dropped_record_count.saturating_add(1);
            state.dropped_text_char_count = state
                .dropped_text_char_count
                .saturating_add(saturating_u32(original_chars));
            return;
        }

        let remaining_total = self.max_total_chars.saturating_sub(state.total_text_chars);
        let retained_chars = original_chars
            .min(self.max_chars_per_record)
            .min(remaining_total);
        let text_truncated = retained_chars < original_chars;
        let retained_text = text.chars().take(retained_chars).collect::<String>();
        if text_truncated {
            state.dropped_text_char_count = state
                .dropped_text_char_count
                .saturating_add(saturating_u32(original_chars - retained_chars));
        }
        state.total_text_chars += retained_chars;
        let preceding_event_index = self.preceding_event_index.load(Ordering::Relaxed);
        state.records.push(DebuggerOutputRecord {
            elapsed_ms: duration_millis(self.started_at.elapsed()),
            preceding_event_index: (preceding_event_index != OUTPUT_CAPTURE_NO_EVENT_INDEX)
                .then_some(preceding_event_index),
            mask,
            categories: debug_output_categories(mask),
            text: retained_text,
            text_truncated,
        });
    }

    fn snapshot(&self, options: &DebuggerOutputCaptureOptions) -> DebuggerOutputCaptureResult {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return DebuggerOutputCaptureResult {
                    status: "unavailable".to_string(),
                    source: "dbgeng_output_callback".to_string(),
                    records: Vec::new(),
                    records_returned: 0,
                    dropped_record_count: 0,
                    dropped_text_char_count: 0,
                    max_records: options.max_records,
                    max_chars_per_record: options.max_chars_per_record,
                    max_total_chars: options.max_total_chars,
                    detail:
                        "The host-side output capture lock was poisoned; no output is returned."
                            .to_string(),
                }
            }
        };
        DebuggerOutputCaptureResult {
            status: "captured".to_string(),
            source: "dbgeng_output_callback".to_string(),
            records: state.records.clone(),
            records_returned: state.records.len(),
            dropped_record_count: state.dropped_record_count,
            dropped_text_char_count: state.dropped_text_char_count,
            max_records: options.max_records,
            max_chars_per_record: options.max_chars_per_record,
            max_total_chars: options.max_total_chars,
            detail: "Only DbgEng debuggee output categories are enabled. Records are bounded host-side and preceding_event_index identifies the latest retained lifecycle event when the callback entered; it is not a causal association.".to_string(),
        }
    }
}

#[cfg(windows)]
pub struct DebuggerOutputCapture {
    client: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugClient5,
    previous_callback:
        Option<windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacksWide>,
    previous_output_mask: u32,
    _callback: windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacksWide,
    shared: Arc<DebuggerOutputCaptureShared>,
    options: DebuggerOutputCaptureOptions,
    restored: bool,
}

#[cfg(windows)]
impl DebuggerOutputCapture {
    pub fn set_preceding_event_index(&self, index: Option<usize>) {
        self.shared.preceding_event_index.store(
            index.unwrap_or(OUTPUT_CAPTURE_NO_EVENT_INDEX),
            Ordering::Relaxed,
        );
    }

    pub fn finish(mut self) -> anyhow::Result<DebuggerOutputCaptureResult> {
        self.restore()?;
        Ok(self.shared.snapshot(&self.options))
    }

    fn restore(&mut self) -> anyhow::Result<()> {
        if self.restored {
            return Ok(());
        }
        unsafe {
            self.client
                .SetOutputCallbacksWide(self.previous_callback.as_ref())
                .context("restoring the previous DbgEng output callback")?;
            self.client
                .SetOutputMask(self.previous_output_mask)
                .context("restoring the previous DbgEng output mask")?;
        }
        self.restored = true;
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for DebuggerOutputCapture {
    fn drop(&mut self) {
        let _ = self.restore();
    }
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

    pub fn begin_debuggee_output_capture(
        &self,
        options: DebuggerOutputCaptureOptions,
    ) -> anyhow::Result<DebuggerOutputCapture> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugOutputCallbacksWide;

        ensure!(
            options.max_records > 0,
            "DbgEng output capture requires a positive record limit"
        );
        ensure!(
            options.max_chars_per_record > 0,
            "DbgEng output capture requires a positive per-record character limit"
        );
        ensure!(
            options.max_total_chars > 0,
            "DbgEng output capture requires a positive total character limit"
        );
        let previous_callback = unsafe { self.client.GetOutputCallbacksWide().ok() };
        let previous_output_mask = unsafe {
            self.client
                .GetOutputMask()
                .context("reading the current DbgEng output mask")?
        };
        let shared = Arc::new(DebuggerOutputCaptureShared {
            started_at: options.started_at,
            max_records: options.max_records as usize,
            max_chars_per_record: options.max_chars_per_record as usize,
            max_total_chars: options.max_total_chars as usize,
            preceding_event_index: AtomicUsize::new(OUTPUT_CAPTURE_NO_EVENT_INDEX),
            state: Mutex::new(DebuggerOutputCaptureState::default()),
        });
        let callback: IDebugOutputCallbacksWide = DebuggerOutputCallback {
            shared: Arc::clone(&shared),
        }
        .into();
        unsafe {
            self.client
                .SetOutputCallbacksWide(&callback)
                .context("installing the bounded DbgEng output callback")?;
            if let Err(error) = self.client.SetOutputMask(
                previous_output_mask
                    | DEBUG_OUTPUT_DEBUGGEE_MASK
                    | DEBUG_OUTPUT_DEBUGGEE_PROMPT_MASK,
            ) {
                let _ = self
                    .client
                    .SetOutputCallbacksWide(previous_callback.as_ref());
                return Err(error).context("enabling DbgEng debuggee output categories");
            }
        }
        Ok(DebuggerOutputCapture {
            client: self.client.clone(),
            previous_callback,
            previous_output_mask,
            _callback: callback,
            shared,
            options,
            restored: false,
        })
    }

    pub fn open_coreclr_dac_bridge(
        &self,
        coreclr_path: &Path,
        allow_target_writes: bool,
    ) -> anyhow::Result<CoreClrDacBridge> {
        CoreClrDacBridge::open(self, coreclr_path, allow_target_writes)
    }

    pub fn wait_for_event(&self, timeout_ms: u32) -> anyhow::Result<DebuggerExecutionStatus> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_STATUS_TIMEOUT, DEBUG_WAIT_DEFAULT,
        };

        let wait = unsafe { self.control.WaitForEvent(DEBUG_WAIT_DEFAULT, timeout_ms) };
        match wait {
            Ok(()) => Ok(self.execution_status()),
            // DbgEng documents S_FALSE as its bounded wait timeout result.
            Err(error) if is_dbgeng_wait_timeout_hresult(error.code().0) => {
                Ok(DebuggerExecutionStatus {
                    raw: Some(DEBUG_STATUS_TIMEOUT),
                    name: Some(status_name(DEBUG_STATUS_TIMEOUT)),
                })
            }
            Err(error) => Err(error).context("DbgEng WaitForEvent failed"),
        }
    }

    pub fn continue_execution(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STATUS_GO;

        unsafe {
            self.control.SetExecutionStatus(DEBUG_STATUS_GO)?;
        }
        Ok(self.execution_status())
    }

    pub fn continue_execution_handled(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STATUS_GO_HANDLED;

        unsafe {
            self.control.SetExecutionStatus(DEBUG_STATUS_GO_HANDLED)?;
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

    pub fn last_event(&self) -> anyhow::Result<DebuggerEventInfo> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_EVENT_BREAKPOINT, DEBUG_EVENT_EXCEPTION, DEBUG_EVENT_EXIT_PROCESS,
            DEBUG_EVENT_EXIT_THREAD, DEBUG_EVENT_LOAD_MODULE, DEBUG_EVENT_UNLOAD_MODULE,
            DEBUG_LAST_EVENT_INFO_BREAKPOINT, DEBUG_LAST_EVENT_INFO_EXCEPTION,
            DEBUG_LAST_EVENT_INFO_EXIT_PROCESS, DEBUG_LAST_EVENT_INFO_EXIT_THREAD,
            DEBUG_LAST_EVENT_INFO_LOAD_MODULE, DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE,
        };

        const MAX_EVENT_DESCRIPTION_CHARS: usize = 512;
        const MAX_EVENT_EXTRA_BYTES: usize = 512;

        let mut event_type = 0u32;
        let mut process_system_id = 0u32;
        let mut thread_system_id = 0u32;
        let mut extra_information = vec![0u8; MAX_EVENT_EXTRA_BYTES];
        let mut extra_information_used = 0u32;
        let mut description = vec![0u16; MAX_EVENT_DESCRIPTION_CHARS];
        let mut description_used = 0u32;
        unsafe {
            self.control.GetLastEventInformationWide(
                &mut event_type,
                &mut process_system_id,
                &mut thread_system_id,
                Some(extra_information.as_mut_ptr().cast()),
                extra_information.len() as u32,
                Some(&mut extra_information_used),
                Some(&mut description),
                Some(&mut description_used),
            )?;
        }
        ensure!(
            extra_information_used as usize <= extra_information.len(),
            "DbgEng last-event payload exceeds the bounded {MAX_EVENT_EXTRA_BYTES}-byte limit"
        );
        ensure!(
            description_used as usize <= description.len(),
            "DbgEng last-event description exceeds the bounded {MAX_EVENT_DESCRIPTION_CHARS}-character limit"
        );

        let description_len = description_used as usize;
        let description = &description[..description_len];
        let description_len = if description.last().is_some_and(|character| *character == 0) {
            description_len - 1
        } else {
            description_len
        };
        let description = String::from_utf16_lossy(&description[..description_len]);
        let description = (!description.is_empty()).then_some(description);
        let extra_information = &extra_information[..extra_information_used as usize];
        let breakpoint_id = (event_type == DEBUG_EVENT_BREAKPOINT)
            .then(|| read_event_info::<DEBUG_LAST_EVENT_INFO_BREAKPOINT>(extra_information))
            .flatten()
            .map(|info| info.Id);
        let exception = (event_type == DEBUG_EVENT_EXCEPTION)
            .then(|| read_event_info::<DEBUG_LAST_EVENT_INFO_EXCEPTION>(extra_information))
            .flatten()
            .map(|info| {
                let count = (info.ExceptionRecord.NumberParameters as usize)
                    .min(info.ExceptionRecord.ExceptionInformation.len());
                DebuggerExceptionInfo {
                    code: info.ExceptionRecord.ExceptionCode.0 as u32,
                    flags: info.ExceptionRecord.ExceptionFlags,
                    address: info.ExceptionRecord.ExceptionAddress,
                    first_chance: info.FirstChance != 0,
                    parameters: info.ExceptionRecord.ExceptionInformation[..count].to_vec(),
                }
            });
        let module_base = match event_type {
            DEBUG_EVENT_LOAD_MODULE => {
                read_event_info::<DEBUG_LAST_EVENT_INFO_LOAD_MODULE>(extra_information)
                    .map(|info| info.Base)
            }
            DEBUG_EVENT_UNLOAD_MODULE => {
                read_event_info::<DEBUG_LAST_EVENT_INFO_UNLOAD_MODULE>(extra_information)
                    .map(|info| info.Base)
            }
            _ => None,
        };
        let exit_code = match event_type {
            DEBUG_EVENT_EXIT_PROCESS => {
                read_event_info::<DEBUG_LAST_EVENT_INFO_EXIT_PROCESS>(extra_information)
                    .map(|info| info.ExitCode)
            }
            DEBUG_EVENT_EXIT_THREAD => {
                read_event_info::<DEBUG_LAST_EVENT_INFO_EXIT_THREAD>(extra_information)
                    .map(|info| info.ExitCode)
            }
            _ => None,
        };

        Ok(DebuggerEventInfo {
            event_type,
            event_name: event_type_name(event_type).to_string(),
            process_system_id,
            thread_system_id,
            description,
            extra_information_size: extra_information_used,
            breakpoint_id,
            exception,
            module_base,
            exit_code,
        })
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

    pub fn virtual_memory_map(&self, region_limit: u32) -> anyhow::Result<VirtualMemoryMap> {
        use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION64;

        ensure!(
            self.kind == DebuggerSessionKind::Live,
            "DbgEng QueryVirtual is only supported for live user-mode targets"
        );
        ensure!(
            region_limit > 0,
            "DbgEng virtual-memory map requires a positive region limit"
        );
        ensure!(
            region_limit <= MAX_VIRTUAL_MEMORY_MAP_REGIONS,
            "DbgEng virtual-memory map region limit must not exceed {MAX_VIRTUAL_MEMORY_MAP_REGIONS}"
        );

        let mut regions = Vec::with_capacity((region_limit as usize).min(256));
        let mut query_address = 0u64;
        loop {
            if regions.len() >= region_limit as usize {
                return Ok(VirtualMemoryMap {
                    source: "dbgeng_idata_spaces4_query_virtual".to_string(),
                    status: "bounded".to_string(),
                    region_limit,
                    regions,
                    truncated: true,
                    next_query_address: Some(query_address),
                    query_error: None,
                    detail: "The requested region limit was reached before the DbgEng virtual-address query completed.".to_string(),
                });
            }

            let mut info = MEMORY_BASIC_INFORMATION64::default();
            let query = unsafe { self.data_spaces.QueryVirtual(query_address, &mut info) };
            if let Err(error) = query {
                return Ok(VirtualMemoryMap {
                    source: "dbgeng_idata_spaces4_query_virtual".to_string(),
                    status: if regions.is_empty() {
                        "unavailable".to_string()
                    } else {
                        "partial_query_error".to_string()
                    },
                    region_limit,
                    regions,
                    truncated: true,
                    next_query_address: Some(query_address),
                    query_error: Some(error.to_string()),
                    detail: "DbgEng QueryVirtual did not return another region. The returned list is not claimed to cover the full address space.".to_string(),
                });
            }
            ensure!(
                info.RegionSize > 0,
                "DbgEng QueryVirtual returned a zero-sized region at 0x{query_address:X}"
            );
            regions.push(VirtualMemoryRegion {
                base_address: info.BaseAddress,
                allocation_base: info.AllocationBase,
                allocation_protection: info.AllocationProtect.0,
                region_size: info.RegionSize,
                state: info.State.0,
                protection: info.Protect.0,
                kind: info.Type.0,
            });
            let next_query_address = info
                .BaseAddress
                .checked_add(info.RegionSize)
                .filter(|next| *next > query_address);
            let Some(next_query_address) = next_query_address else {
                return Ok(VirtualMemoryMap {
                    source: "dbgeng_idata_spaces4_query_virtual".to_string(),
                    status: "address_space_exhausted".to_string(),
                    region_limit,
                    regions,
                    truncated: false,
                    next_query_address: None,
                    query_error: None,
                    detail: "DbgEng QueryVirtual reached the end of the representable virtual address range.".to_string(),
                });
            };
            query_address = next_query_address;
        }
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

    pub fn thread_context(
        &self,
        engine_thread_id: u32,
        max_frames: u32,
        disassembly_count: u32,
    ) -> anyhow::Result<ThreadContext> {
        ensure!(max_frames > 0, "max_frames must be greater than zero");
        ensure!(
            disassembly_count > 0,
            "disassembly_count must be greater than zero"
        );
        ensure!(
            engine_thread_id != u32::MAX,
            "engine_thread_id cannot be DEBUG_ANY_ID"
        );

        let previous_thread_id = unsafe { self.system_objects.GetCurrentThreadId()? };
        let changed_thread = previous_thread_id != engine_thread_id;
        if changed_thread {
            unsafe {
                self.system_objects.SetCurrentThreadId(engine_thread_id)?;
            }
        }

        let context = (|| {
            let registers = self.core_registers()?;
            let instruction_offset = registers.instruction_offset;
            let current_module = instruction_offset
                .map(|address| self.module_by_offset(address))
                .transpose()?
                .flatten();
            let current_symbol = instruction_offset
                .map(|address| self.symbol_by_offset(address))
                .transpose()?
                .flatten();
            let stack = self.stack_trace(max_frames)?;
            let disassembly = instruction_offset
                .map(|address| self.disassemble(Some(address), disassembly_count))
                .transpose()?;
            let system_id = self.current_thread_system_id()?;
            Ok(ThreadContext {
                thread: ThreadInfo {
                    engine_id: engine_thread_id,
                    system_id,
                },
                registers,
                current_module,
                current_symbol,
                stack,
                disassembly,
                current_thread_preserved: true,
            })
        })();

        let restore = changed_thread
            .then(|| unsafe { self.system_objects.SetCurrentThreadId(previous_thread_id) });
        match (context, restore) {
            (Ok(context), Some(Ok(()))) | (Ok(context), None) => Ok(context),
            (Ok(_), Some(Err(error))) => Err(error).context("failed to restore the current thread"),
            (Err(error), Some(Err(restore_error))) => Err(error).context(format!(
                "failed to inspect the requested thread and failed to restore the current thread: {restore_error}"
            )),
            (Err(error), _) => Err(error),
        }
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
            DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED,
        };

        let breakpoint = self.add_compatible_breakpoint(DEBUG_BREAKPOINT_CODE)?;
        unsafe {
            breakpoint.SetOffset(address).with_context(|| {
                format!("DbgEng could not set code breakpoint offset 0x{address:X}")
            })?;
            breakpoint
                .AddFlags(DEBUG_BREAKPOINT_ENABLED)
                .context("DbgEng could not enable code breakpoint")?;
        }
        self.breakpoint_info(&breakpoint)
    }

    pub fn add_code_breakpoint_expression(
        &self,
        expression: &str,
    ) -> anyhow::Result<BreakpointInfo> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_BREAKPOINT_CODE, DEBUG_BREAKPOINT_ENABLED,
        };

        let mut expression_wide = expression.encode_utf16().collect::<Vec<_>>();
        expression_wide.push(0);
        let breakpoint = self.add_compatible_breakpoint(DEBUG_BREAKPOINT_CODE)?;
        unsafe {
            breakpoint
                .SetOffsetExpressionWide(PCWSTR(expression_wide.as_ptr()))
                .with_context(|| {
                    format!("DbgEng could not set code breakpoint expression '{expression}'")
                })?;
            breakpoint
                .AddFlags(DEBUG_BREAKPOINT_ENABLED)
                .context("DbgEng could not enable code breakpoint")?;
        }
        self.breakpoint_info(&breakpoint)
    }

    pub fn execute_command(&self, command: &str) -> anyhow::Result<()> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_EXECUTE_DEFAULT, DEBUG_OUTCTL_THIS_CLIENT,
        };

        let mut command_wide = command.encode_utf16().collect::<Vec<_>>();
        command_wide.push(0);
        unsafe {
            self.control.ExecuteWide(
                DEBUG_OUTCTL_THIS_CLIENT,
                PCWSTR(command_wide.as_ptr()),
                DEBUG_EXECUTE_DEFAULT,
            )
        }
        .with_context(|| format!("executing DbgEng command '{command}'"))?;
        Ok(())
    }

    pub fn add_data_breakpoint(
        &self,
        address: u64,
        size: u32,
        access_type: u32,
    ) -> anyhow::Result<BreakpointInfo> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_BREAKPOINT_DATA, DEBUG_BREAKPOINT_ENABLED,
        };

        let breakpoint = self.add_compatible_breakpoint(DEBUG_BREAKPOINT_DATA)?;
        unsafe {
            breakpoint.SetOffset(address)?;
            breakpoint.SetDataParameters(size, access_type)?;
            breakpoint.AddFlags(DEBUG_BREAKPOINT_ENABLED)?;
        }
        self.breakpoint_info(&breakpoint)
    }

    pub fn add_hardware_execute_breakpoint(&self, address: u64) -> anyhow::Result<BreakpointInfo> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_BREAKPOINT_DATA, DEBUG_BREAKPOINT_ENABLED, DEBUG_BREAK_EXECUTE,
        };

        let breakpoint = self
            .add_compatible_breakpoint(DEBUG_BREAKPOINT_DATA)
            .context("DbgEng could not create a processor execute breakpoint")?;
        unsafe {
            breakpoint.SetOffset(address).with_context(|| {
                format!("DbgEng could not set processor execute breakpoint offset 0x{address:X}")
            })?;
            breakpoint
                .SetDataParameters(1, DEBUG_BREAK_EXECUTE)
                .context("DbgEng could not configure a one-byte processor execute breakpoint")?;
            breakpoint
                .AddFlags(DEBUG_BREAKPOINT_ENABLED)
                .context("DbgEng could not enable the processor execute breakpoint")?;
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

    fn add_compatible_breakpoint(
        &self,
        break_type: u32,
    ) -> anyhow::Result<windows::Win32::System::Diagnostics::Debug::Extensions::IDebugBreakpoint2>
    {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_ANY_ID;

        match unsafe { self.control.AddBreakpoint2(break_type, DEBUG_ANY_ID) } {
            Ok(breakpoint) => Ok(breakpoint),
            Err(modern_error) => unsafe {
                self.control
                    .AddBreakpoint(break_type, DEBUG_ANY_ID)
                    .and_then(|breakpoint| breakpoint.cast())
            }
            .with_context(|| {
                format!(
                    "DbgEng could not add breakpoint type {break_type}; AddBreakpoint2 failed first: {modern_error}"
                )
            }),
        }
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

#[cfg(windows)]
fn read_event_info<T: Copy>(bytes: &[u8]) -> Option<T> {
    (bytes.len() >= std::mem::size_of::<T>())
        .then(|| unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

fn event_type_name(event_type: u32) -> &'static str {
    match event_type {
        1 => "breakpoint",
        2 => "exception",
        4 => "create_thread",
        8 => "exit_thread",
        16 => "create_process",
        32 => "exit_process",
        64 => "load_module",
        128 => "unload_module",
        256 => "system_error",
        512 => "session_status",
        1024 => "change_debuggee_state",
        2048 => "change_engine_state",
        4096 => "change_symbol_state",
        8192 => "service_exception",
        _ => "unknown",
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

    pub fn last_event(&self) -> anyhow::Result<DebuggerEventInfo> {
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

    pub fn thread_context(
        &self,
        _engine_thread_id: u32,
        _max_frames: u32,
        _disassembly_count: u32,
    ) -> anyhow::Result<ThreadContext> {
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

    pub fn continue_execution_handled(&self) -> anyhow::Result<DebuggerExecutionStatus> {
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
        IDebugClient5, DEBUG_CLASS_USER_WINDOWS,
    };
    use windows::Win32::System::Threading::INFINITE;

    let mut transport = options.transport.encode_utf16().collect::<Vec<_>>();
    transport.push(0);

    let client: IDebugClient5 = create_debug_client()?;
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
        initial_stop: LiveInitialStop::SoftwareBreakpoint,
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
        IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters, IDebugSymbols5,
        IDebugSystemObjects, DEBUG_PROCESS_ONLY_THIS_PROCESS,
    };

    let mut command_line = options.command_line.encode_utf16().collect::<Vec<_>>();
    command_line.push(0);

    let client: IDebugClient5 = create_debug_client()?;
    let control: IDebugControl5 = client.cast().context("querying IDebugControl5")?;
    let data_spaces: IDebugDataSpaces4 = client.cast().context("querying IDebugDataSpaces4")?;
    let registers: IDebugRegisters = client.cast().context("querying IDebugRegisters")?;
    let symbols: IDebugSymbols5 = client.cast().context("querying IDebugSymbols5")?;
    let system_objects: IDebugSystemObjects =
        client.cast().context("querying IDebugSystemObjects")?;
    let symbol_path = configure_dbgeng_symbol_path(&symbols)?;
    match options.initial_stop {
        LiveInitialStop::SoftwareBreakpoint => enable_initial_break(&control)?,
        LiveInitialStop::CreateProcessEvent => enable_create_process_stop(&control)?,
    }
    unsafe {
        // DbgEng can mutate the command buffer; command_line is owned and remains live for the call.
        client
            .CreateProcessWide(
                0,
                PCWSTR(command_line.as_ptr()),
                DEBUG_PROCESS_ONLY_THIS_PROCESS,
            )
            .context("DbgEng CreateProcessWide failed")?;
    }
    let initial_stop = match options.initial_stop {
        LiveInitialStop::SoftwareBreakpoint => "software initial-break",
        LiveInitialStop::CreateProcessEvent => "create-process",
    };
    wait_for_initial_event(&control, options.initial_break_timeout_ms, initial_stop)?;

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
        IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters, IDebugSymbols5,
        IDebugSystemObjects, DEBUG_ATTACH_DEFAULT,
    };

    let client: IDebugClient5 = create_debug_client()?;
    let control: IDebugControl5 = client.cast().context("querying IDebugControl5")?;
    let data_spaces: IDebugDataSpaces4 = client.cast().context("querying IDebugDataSpaces4")?;
    let registers: IDebugRegisters = client.cast().context("querying IDebugRegisters")?;
    let symbols: IDebugSymbols5 = client.cast().context("querying IDebugSymbols5")?;
    let system_objects: IDebugSystemObjects =
        client.cast().context("querying IDebugSystemObjects")?;
    let symbol_path = configure_dbgeng_symbol_path(&symbols)?;
    enable_initial_break(&control)?;
    unsafe {
        client.AttachProcess(0, options.process_id, DEBUG_ATTACH_DEFAULT)?;
    }
    wait_for_initial_event(&control, options.initial_break_timeout_ms, "attach")?;

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
        IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters, IDebugSymbols5,
        IDebugSystemObjects, DEBUG_WAIT_DEFAULT,
    };

    let path_string = options.path.to_string_lossy().to_string();
    let mut path = path_string.encode_utf16().collect::<Vec<_>>();
    path.push(0);

    let client: IDebugClient5 = create_debug_client()?;
    let control: IDebugControl5 = client.cast().context("querying IDebugControl5")?;
    let data_spaces: IDebugDataSpaces4 = client.cast().context("querying IDebugDataSpaces4")?;
    let registers: IDebugRegisters = client.cast().context("querying IDebugRegisters")?;
    let symbols: IDebugSymbols5 = client.cast().context("querying IDebugSymbols5")?;
    let system_objects: IDebugSystemObjects =
        client.cast().context("querying IDebugSystemObjects")?;
    let symbol_path = configure_dbgeng_symbol_path(&symbols)?;
    unsafe {
        client.OpenDumpFileWide(PCWSTR(path.as_ptr()), 0)?;
        control
            .WaitForEvent(DEBUG_WAIT_DEFAULT, 5000)
            .context("DbgEng dump WaitForEvent failed")?;
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

fn duration_millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(windows)]
fn saturating_u32(value: usize) -> u32 {
    value.min(u32::MAX as usize) as u32
}

#[cfg(windows)]
fn debug_output_categories(mask: u32) -> Vec<String> {
    const OUTPUT_CATEGORIES: &[(u32, &str)] = &[
        (0x0000_0001, "normal"),
        (0x0000_0002, "error"),
        (0x0000_0004, "warning"),
        (0x0000_0008, "verbose"),
        (0x0000_0010, "prompt"),
        (0x0000_0020, "prompt_registers"),
        (0x0000_0040, "extension_warning"),
        (DEBUG_OUTPUT_DEBUGGEE_MASK, "debuggee"),
        (DEBUG_OUTPUT_DEBUGGEE_PROMPT_MASK, "debuggee_prompt"),
        (0x0000_0200, "symbols"),
        (0x0000_0400, "status"),
    ];
    let mut categories = OUTPUT_CATEGORIES
        .iter()
        .filter(|(flag, _)| mask & *flag != 0)
        .map(|(_, name)| (*name).to_string())
        .collect::<Vec<_>>();
    if categories.is_empty() {
        categories.push("unknown".to_string());
    }
    categories
}

#[cfg(windows)]
fn load_dbghelp_module() -> anyhow::Result<windows::Win32::Foundation::HMODULE> {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::{
        LoadLibraryExW, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    let explicit_runtime_dir = env::var_os(DBGENG_RUNTIME_DIR_ENV).map(PathBuf::from);
    let executable_path = env::current_exe().ok();
    if let Some(dbgeng) =
        dbgeng_runtime_dll(explicit_runtime_dir.as_deref(), executable_path.as_deref())?
    {
        let runtime_dir = dbgeng
            .parent()
            .context("the selected DbgEng runtime DLL has no parent directory")?;
        let dbghelp = runtime_dir.join("dbghelp.dll");
        ensure!(
            dbghelp.is_file(),
            "the selected DbgEng runtime is missing required component {}",
            dbghelp.display()
        );
        return load_library_from_path(&dbghelp, "DbgHelp runtime component");
    }

    let mut component_wide = "dbghelp.dll".encode_utf16().collect::<Vec<_>>();
    component_wide.push(0);
    unsafe {
        LoadLibraryExW(
            PCWSTR(component_wide.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    }
    .context("loading DbgHelp from the system runtime")
}

#[cfg(windows)]
fn write_process_dump_file(
    process_id: u32,
    target: String,
    detached: bool,
    options: DumpWriteOptions,
) -> anyhow::Result<DumpWriteResult> {
    use std::ffi::c_void;
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;
    use windows::core::{Error, PCSTR};
    use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{
        MiniDumpWithDataSegs, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo,
        MiniDumpWithHandleData, MiniDumpWithProcessThreadData, MiniDumpWithThreadInfo,
        MiniDumpWithUnloadedModules, MINIDUMP_TYPE,
    };
    use windows::Win32::System::LibraryLoader::GetProcAddress;
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

    type MiniDumpWriteDumpFn = unsafe extern "system" fn(
        HANDLE,
        u32,
        HANDLE,
        MINIDUMP_TYPE,
        *const c_void,
        *const c_void,
        *const c_void,
    ) -> BOOL;

    let dbghelp = load_dbghelp_module()?;
    let procedure = unsafe { GetProcAddress(dbghelp, PCSTR(c"MiniDumpWriteDump".as_ptr().cast())) }
        .context("the selected DbgHelp runtime does not export MiniDumpWriteDump")?;
    // GetProcAddress returns an untyped module export. MiniDumpWriteDump has the documented
    // DbgHelp ABI and the module remains loaded for the duration of this call.
    let mini_dump_write_dump: MiniDumpWriteDumpFn = unsafe { std::mem::transmute(procedure) };
    let write_result = unsafe {
        mini_dump_write_dump(
            process,
            process_id,
            HANDLE(file.as_raw_handle()),
            dump_type,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    unsafe {
        CloseHandle(process)?;
    }
    ensure!(
        write_result.as_bool(),
        "MiniDumpWriteDump failed: {}",
        Error::from_win32()
    );
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

    #[test]
    fn names_documented_dbgeng_event_types() {
        assert_eq!(event_type_name(1), "breakpoint");
        assert_eq!(event_type_name(2), "exception");
        assert_eq!(event_type_name(64), "load_module");
        assert_eq!(event_type_name(0xFFFF), "unknown");
    }

    #[test]
    fn recognizes_dbgeng_s_false_as_wait_timeout() {
        assert!(is_dbgeng_wait_timeout_hresult(1));
        assert!(!is_dbgeng_wait_timeout_hresult(0));
        assert!(!is_dbgeng_wait_timeout_hresult(-1));
    }

    #[cfg(windows)]
    #[test]
    fn explicit_dbgeng_runtime_overrides_an_adjacent_runtime() {
        use std::fs;

        let root =
            env::temp_dir().join(format!("windbg-dbgeng-runtime-test-{}", std::process::id()));
        let explicit_runtime = root.join("explicit");
        let executable = root.join("bin").join("windbg-tool.exe");
        let adjacent_runtime = executable.parent().unwrap().join(DBGENG_DLL_NAME);
        fs::create_dir_all(&explicit_runtime).unwrap();
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(explicit_runtime.join(DBGENG_DLL_NAME), []).unwrap();
        fs::write(&adjacent_runtime, []).unwrap();

        let resolved = dbgeng_runtime_dll(Some(&explicit_runtime), Some(&executable)).unwrap();

        let _ = fs::remove_dir_all(&root);
        assert_eq!(resolved, Some(explicit_runtime.join(DBGENG_DLL_NAME)));
    }
}
