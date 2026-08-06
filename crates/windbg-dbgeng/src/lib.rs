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
    env, fs,
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

pub const NT_SYMBOL_PATH_ENV: &str = "_NT_SYMBOL_PATH";
pub const NT_ALT_SYMBOL_PATH_ENV: &str = "_NT_ALT_SYMBOL_PATH";
pub const NT_SYMCACHE_PATH_ENV: &str = "_NT_SYMCACHE_PATH";
pub const DBGENG_RUNTIME_DIR_ENV: &str = "WINDBG_DBGENG_RUNTIME_DIR";
pub const MAX_VIRTUAL_MEMORY_MAP_REGIONS: u32 = 4096;
pub const MAX_THREAD_ACCOUNTING_THREADS: u32 = 128;
pub const MAX_MODULE_PARAMETER_QUERIES: usize = 128;
pub const MAX_BOUNDED_MODULE_ENUMERATION: u32 = 512;
pub const MAX_SYMBOL_ENTRY_OFFSET_REGIONS: usize = 16;
const DEFAULT_DBGENG_SYMBOL_CACHE: &str = ".windbg-symbol-cache";
const DBGENG_DLL_NAME: &str = "dbgeng.dll";
const DBGENG_RUNTIME_COMPONENTS: [&str; 4] = [
    "dbgcore.dll",
    "dbghelp.dll",
    "dbgmodel.dll",
    DBGENG_DLL_NAME,
];
const DBGENG_WAIT_TIMEOUT_HRESULT: i32 = 1;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DbgEngRuntimeComponent {
    pub name: String,
    pub path: PathBuf,
    pub machine: String,
    pub machine_raw: u16,
    pub image_version: String,
    pub image_timestamp: u32,
    pub file_size: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DbgEngRuntime {
    pub source: String,
    pub directory: Option<PathBuf>,
    pub architecture: Option<String>,
    pub components: Vec<DbgEngRuntimeComponent>,
    pub compatible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DbgEngRuntimeSource {
    ExplicitDirectory,
    AdjacentDirectory,
    System,
}

impl DbgEngRuntimeSource {
    fn name(self) -> &'static str {
        match self {
            Self::ExplicitDirectory => "explicit_runtime_directory",
            Self::AdjacentDirectory => "adjacent_executable_directory",
            Self::System => "system_runtime",
        }
    }
}

#[derive(Debug, Clone)]
struct SelectedDbgEngRuntime {
    source: DbgEngRuntimeSource,
    dbgeng_dll: Option<PathBuf>,
}

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
    let paths = environment.symbol_path.into_iter().collect::<Vec<_>>();
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

fn dbgeng_runtime_dll(
    explicit_runtime_dir: Option<&Path>,
    executable_path: Option<&Path>,
) -> anyhow::Result<Option<PathBuf>> {
    Ok(select_dbgeng_runtime(explicit_runtime_dir, executable_path)?.dbgeng_dll)
}

fn select_dbgeng_runtime(
    explicit_runtime_dir: Option<&Path>,
    executable_path: Option<&Path>,
) -> anyhow::Result<SelectedDbgEngRuntime> {
    if let Some(runtime_dir) = explicit_runtime_dir {
        let dll = runtime_dir.join(DBGENG_DLL_NAME);
        ensure!(
            dll.is_file(),
            "{DBGENG_RUNTIME_DIR_ENV} must name a directory containing {}",
            dll.display()
        );
        return Ok(SelectedDbgEngRuntime {
            source: DbgEngRuntimeSource::ExplicitDirectory,
            dbgeng_dll: Some(dll),
        });
    }

    let adjacent = executable_path
        .and_then(Path::parent)
        .map(|directory| directory.join(DBGENG_DLL_NAME))
        .filter(|dll| dll.is_file());
    Ok(SelectedDbgEngRuntime {
        source: if adjacent.is_some() {
            DbgEngRuntimeSource::AdjacentDirectory
        } else {
            DbgEngRuntimeSource::System
        },
        dbgeng_dll: adjacent,
    })
}

/// Inspects the exact DbgEng runtime selected by the normal loader without
/// loading any native DLL. Staged component architecture mismatches are rejected
/// before a session can bind to the engine.
pub fn inspect_dbgeng_runtime() -> anyhow::Result<DbgEngRuntime> {
    let explicit_runtime_dir = env::var_os(DBGENG_RUNTIME_DIR_ENV).map(PathBuf::from);
    let executable_path = env::current_exe().ok();
    let selected =
        select_dbgeng_runtime(explicit_runtime_dir.as_deref(), executable_path.as_deref())?;
    inspect_selected_dbgeng_runtime(&selected)
}

fn inspect_selected_dbgeng_runtime(
    selected: &SelectedDbgEngRuntime,
) -> anyhow::Result<DbgEngRuntime> {
    let Some(dbgeng_dll) = selected.dbgeng_dll.as_deref() else {
        return Ok(DbgEngRuntime {
            source: selected.source.name().to_string(),
            directory: None,
            architecture: None,
            components: Vec::new(),
            compatible: true,
        });
    };
    let directory = dbgeng_dll
        .parent()
        .context("the selected DbgEng runtime DLL has no parent directory")?;
    let components = DBGENG_RUNTIME_COMPONENTS
        .iter()
        .map(|name| inspect_dbgeng_runtime_component(&directory.join(name), name))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let machine_raw = components
        .first()
        .map(|component| component.machine_raw)
        .context("the selected DbgEng runtime has no components")?;
    ensure!(
        components
            .iter()
            .all(|component| component.machine_raw == machine_raw),
        "the selected DbgEng runtime mixes component architectures: {}",
        components
            .iter()
            .map(|component| format!("{}={}", component.name, component.machine))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(DbgEngRuntime {
        source: selected.source.name().to_string(),
        directory: Some(directory.to_path_buf()),
        architecture: Some(pe_machine_name(machine_raw).to_string()),
        components,
        compatible: true,
    })
}

fn inspect_dbgeng_runtime_component(
    path: &Path,
    name: &str,
) -> anyhow::Result<DbgEngRuntimeComponent> {
    ensure!(
        path.is_file(),
        "the selected DbgEng runtime is missing required component {}",
        path.display()
    );
    let bytes = fs::read(path)
        .with_context(|| format!("reading DbgEng runtime component {}", path.display()))?;
    ensure!(
        bytes.len() >= 0x40 && &bytes[..2] == b"MZ",
        "DbgEng runtime component {} is not a PE image",
        path.display()
    );
    let pe_offset =
        usize::try_from(read_u32(&bytes, 0x3c)?).context("converting DbgEng PE header offset")?;
    ensure!(
        bytes.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0"),
        "DbgEng runtime component {} has an invalid PE signature",
        path.display()
    );
    let machine_raw = read_u16(&bytes, pe_offset + 4)?;
    let image_timestamp = read_u32(&bytes, pe_offset + 8)?;
    let optional_header_offset = pe_offset + 24;
    let optional_magic = read_u16(&bytes, optional_header_offset)?;
    ensure!(
        optional_magic == 0x10b || optional_magic == 0x20b,
        "DbgEng runtime component {} has unsupported PE optional-header magic 0x{optional_magic:04X}",
        path.display()
    );
    let major_image_version = read_u16(&bytes, optional_header_offset + 44)?;
    let minor_image_version = read_u16(&bytes, optional_header_offset + 46)?;
    Ok(DbgEngRuntimeComponent {
        name: name.to_string(),
        path: path.to_path_buf(),
        machine: pe_machine_name(machine_raw).to_string(),
        machine_raw,
        image_version: format!("{major_image_version}.{minor_image_version}"),
        image_timestamp,
        file_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> anyhow::Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .context("PE image is truncated while reading a 16-bit field")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> anyhow::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .context("PE image is truncated while reading a 32-bit field")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn pe_machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x64",
        0xaa64 => "arm64",
        _ => "unknown",
    }
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
            let selected =
                select_dbgeng_runtime(explicit_runtime_dir.as_deref(), executable_path.as_deref())?;
            let Some(dll) = selected.dbgeng_dll.as_deref() else {
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
            inspect_selected_dbgeng_runtime(&selected)?;
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
    pub runtime: DbgEngRuntime,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoreRegisterState {
    pub thread_system_id: Option<u32>,
    pub instruction_offset: Option<u64>,
    pub stack_offset: Option<u64>,
    pub frame_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BugCheckData {
    pub code: u32,
    pub parameters: [u64; 4],
}

#[derive(Debug, Clone, Serialize)]
pub struct BugCheckDataResult {
    pub status: String,
    pub data: Option<BugCheckData>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpHeaderSnapshot {
    pub status: String,
    pub source: String,
    pub bytes_returned: u32,
    pub tail_status: String,
    pub signature: Option<u32>,
    pub valid_dump: Option<u32>,
    pub major_version: Option<u32>,
    pub minor_version: Option<u32>,
    pub directory_table_base: Option<u64>,
    pub pfn_database: Option<u64>,
    pub loaded_module_list: Option<u64>,
    pub active_process_head: Option<u64>,
    pub machine_image_type: Option<u32>,
    pub processor_count: Option<u32>,
    pub bugcheck_code: Option<u32>,
    pub bugcheck_parameters: Option<[u64; 4]>,
    pub embedded_exception_context: DumpHeaderEmbeddedExceptionContext,
    pub version_user: Option<String>,
    pub dump_type: Option<u32>,
    pub dump_type_name: Option<String>,
    pub required_dump_space_bytes: Option<u64>,
    pub system_time_filetime: Option<u64>,
    pub system_uptime_100ns: Option<u64>,
    pub comment: Option<String>,
    pub mini_dump_fields: Option<u32>,
    pub secondary_data_state: Option<u32>,
    pub product_type: Option<u32>,
    pub suite_mask: Option<u32>,
    pub writer_status: Option<u32>,
    pub kd_secondary_version: Option<u8>,
    pub attributes_raw: Option<u32>,
    pub attributes: Vec<String>,
    pub boot_id: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpHeaderEmbeddedExceptionContext {
    pub status: String,
    pub provenance_category: String,
    pub context_status: String,
    pub exception_record_status: String,
    pub context: Option<X64ExceptionContext>,
    pub exception_record: Option<TargetExceptionRecord>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpEventInventory {
    pub status: String,
    pub source: String,
    pub event_count: Option<u32>,
    pub current_event_index: Option<u32>,
    pub current_event_index_status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DumpDebuggerData {
    pub status: String,
    pub source: String,
    pub saved_context_address: Option<u64>,
    pub saved_context_status: String,
    pub saved_context: Option<X64ExceptionContext>,
    pub ki_bugcheck_data_address: Option<u64>,
    pub ki_bugcheck_data_status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub previous_record: u64,
    pub address: u64,
    pub parameter_count: u32,
    pub parameters: Vec<u64>,
    pub access_violation: Option<TargetAccessViolation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetAccessViolation {
    pub operation_raw: u64,
    pub operation: String,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetExceptionSnapshot {
    pub status: String,
    pub source: String,
    pub contract: TargetExceptionContract,
    pub stored_event: StoredEventInformation,
    pub thread_system_id: Option<u32>,
    pub thread_status: String,
    pub record: Option<TargetExceptionRecord>,
    pub record_status: String,
    pub context: Option<X64ExceptionContext>,
    pub context_status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetExceptionContract {
    pub status: String,
    pub source: String,
    pub debuggee_class: Option<u32>,
    pub debuggee_qualifier: Option<u32>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredEventInformation {
    pub status: String,
    pub source: String,
    pub event_type: Option<u32>,
    pub process_system_id: Option<u32>,
    pub thread_system_id: Option<u32>,
    pub context: Option<X64ExceptionContext>,
    pub context_status: String,
    pub extra_information_bytes_returned: Option<u32>,
    pub extra_information_status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackTraceResult {
    pub requested_frames: u32,
    pub returned_frames: u32,
    pub valid_frames: u32,
    pub status: String,
    pub stop_reason: Option<String>,
    pub frames: Vec<StackFrameInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64ExceptionRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64ContextSegmentSelectors {
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64ContextValidation {
    pub amd64_flag_present: bool,
    pub control_register_group_present: bool,
    pub integer_register_group_present: bool,
    pub raw_layout_offset_cross_check: bool,
    pub segment_selectors: X64ContextSegmentSelectors,
    pub cs_nonzero: bool,
    pub ss_nonzero: bool,
    pub eflags_reserved_bit_1_set: bool,
    pub interrupt_enable_flag: bool,
    pub rsp_mod_16: u8,
    pub selected_debugger_context_cr4: Option<u64>,
    pub selected_debugger_context_virtual_address_bits: Option<u8>,
    pub rip_canonical_for_selected_address_width: Option<bool>,
    pub rsp_canonical_for_selected_address_width: Option<bool>,
    pub control_registers_in_amd64_context: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64ExceptionContext {
    pub status: String,
    pub context_record_address: Option<u64>,
    pub requested_size: u32,
    pub bytes_read: u32,
    pub complete: bool,
    pub context_flags: Option<u32>,
    pub validation: Option<X64ContextValidation>,
    pub registers: Option<X64ExceptionRegisters>,
    pub stack: Option<StackTraceResult>,
    pub unwind_contexts: Option<X64ContextStackTrace>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64ContextStackTrace {
    pub status: String,
    pub source: String,
    pub requested_frames: u32,
    pub returned_frames: u32,
    pub frame_zero_matches_start_context: Option<bool>,
    pub frames: Vec<X64UnwindContextFrame>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64UnwindContextFrame {
    pub frame_number: u32,
    pub instruction_offset: u64,
    pub context_rip: Option<u64>,
    pub context_flags: Option<u32>,
    pub required_register_groups_present: bool,
    pub r8: Option<u64>,
    pub r14: Option<u64>,
    pub structural_effective_address: Option<u64>,
}

const X64_CONTEXT_SIZE: u32 = 0x4D0;
const CONTEXT_AMD64_FLAG: u32 = 0x0010_0000;
const CONTEXT_X64_REQUIRED_REGISTER_FLAGS: u32 = CONTEXT_AMD64_FLAG | 0x0000_0003;
const DUMP_HEADER64_SIZE: usize = 0x2000;
const DUMP_HEADER64_CONTEXT_RECORD_OFFSET: usize = 0x344;
const DUMP_HEADER64_CONTEXT_RECORD_SIZE: usize = 3000;
const EXCEPTION_RECORD64_SIZE: usize = 0x98;
const DUMP_HEADER64_EXCEPTION_OFFSET: usize =
    DUMP_HEADER64_CONTEXT_RECORD_OFFSET + DUMP_HEADER64_CONTEXT_RECORD_SIZE;

// The dump target's architecture can differ from the host build architecture. Keep this prefix
// independent of windows::CONTEXT so ARM64 builds can decode an AMD64 dump safely.
#[repr(C)]
#[derive(Clone, Copy)]
struct X64ContextPrefix {
    _homes: [u64; 6],
    context_flags: u32,
    _mxcsr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    _debug_registers: [u64; 6],
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
}

#[derive(Debug, Clone, Copy)]
struct X64ContextCriticalFields {
    context_flags: u32,
    seg_cs: u16,
    seg_ss: u16,
    eflags: u32,
    rsp: u64,
    r8: u64,
    r14: u64,
    rip: u64,
}

fn x64_context_prefix_from_bytes(bytes: &[u8]) -> Option<X64ContextPrefix> {
    (bytes.len() >= std::mem::size_of::<X64ContextPrefix>())
        // The source byte buffer is not guaranteed to be naturally aligned.
        .then(|| unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<X64ContextPrefix>()) })
}

fn x64_context_critical_fields_from_bytes(bytes: &[u8]) -> Option<X64ContextCriticalFields> {
    fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            bytes.get(offset..offset + 2)?.try_into().ok()?,
        ))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    }

    Some(X64ContextCriticalFields {
        context_flags: read_u32(bytes, 0x30)?,
        seg_cs: read_u16(bytes, 0x38)?,
        seg_ss: read_u16(bytes, 0x42)?,
        eflags: read_u32(bytes, 0x44)?,
        rsp: read_u64(bytes, 0x98)?,
        r8: read_u64(bytes, 0xb8)?,
        r14: read_u64(bytes, 0xe8)?,
        rip: read_u64(bytes, 0xf8)?,
    })
}

fn x64_context_validation(
    context: &X64ContextPrefix,
    bytes: &[u8],
    selected_address_width: Option<(u64, u8)>,
) -> X64ContextValidation {
    let raw_layout_offset_cross_check =
        x64_context_critical_fields_from_bytes(bytes).is_some_and(|raw| {
            raw.context_flags == context.context_flags
                && raw.seg_cs == context.seg_cs
                && raw.seg_ss == context.seg_ss
                && raw.eflags == context.eflags
                && raw.rsp == context.rsp
                && raw.r8 == context.r8
                && raw.r14 == context.r14
                && raw.rip == context.rip
        });
    let (selected_debugger_context_cr4, selected_debugger_context_virtual_address_bits) =
        selected_address_width
            .map(|(cr4, bits)| (Some(cr4), Some(bits)))
            .unwrap_or((None, None));
    let canonicality = selected_debugger_context_virtual_address_bits.map(|bits| {
        (
            x64_virtual_address_is_canonical(context.rip, bits),
            x64_virtual_address_is_canonical(context.rsp, bits),
        )
    });
    X64ContextValidation {
        amd64_flag_present: context.context_flags & CONTEXT_AMD64_FLAG != 0,
        control_register_group_present: context.context_flags & 0x1 != 0,
        integer_register_group_present: context.context_flags & 0x2 != 0,
        raw_layout_offset_cross_check,
        segment_selectors: X64ContextSegmentSelectors {
            cs: context.seg_cs,
            ds: context.seg_ds,
            es: context.seg_es,
            fs: context.seg_fs,
            gs: context.seg_gs,
            ss: context.seg_ss,
        },
        cs_nonzero: context.seg_cs != 0,
        ss_nonzero: context.seg_ss != 0,
        eflags_reserved_bit_1_set: context.eflags & 0x2 != 0,
        interrupt_enable_flag: context.eflags & 0x200 != 0,
        rsp_mod_16: (context.rsp & 0xf) as u8,
        selected_debugger_context_cr4,
        selected_debugger_context_virtual_address_bits,
        rip_canonical_for_selected_address_width: canonicality.map(|value| value.0),
        rsp_canonical_for_selected_address_width: canonicality.map(|value| value.1),
        control_registers_in_amd64_context: false,
        detail: "The fixed AMD64 CONTEXT offsets were independently decoded from the bounded byte buffer and compared with the C-compatible prefix. CS/SS and EFLAGS checks are structural sanity observations, not thread or CPU attribution. AMD64 CONTEXT does not contain CR3 or CR4; any selected-debugger CR4 is used only for canonical-address checks and does not establish the saved context's paging root.".to_string(),
    }
}

fn decode_x64_context_structural(
    context_record_address: Option<u64>,
    buffer: &[u8],
    bytes_read: u32,
    selected_address_width: Option<(u64, u8)>,
) -> X64ExceptionContext {
    let requested_size = X64_CONTEXT_SIZE;
    if buffer.len() < requested_size as usize {
        return X64ExceptionContext {
            status: "partial".to_string(),
            context_record_address,
            requested_size,
            bytes_read,
            complete: false,
            context_flags: None,
            validation: None,
            registers: None,
            stack: None,
            unwind_contexts: None,
            detail: format!(
                "The bounded source contains only {} of {requested_size} AMD64 CONTEXT bytes.",
                buffer.len()
            ),
        };
    }
    let context = x64_context_prefix_from_bytes(buffer)
        .expect("the complete x64 CONTEXT buffer must contain its documented prefix");
    let context_flags = context.context_flags;
    if context_flags & CONTEXT_X64_REQUIRED_REGISTER_FLAGS != CONTEXT_X64_REQUIRED_REGISTER_FLAGS {
        return X64ExceptionContext {
            status: "invalid".to_string(),
            context_record_address,
            requested_size,
            bytes_read,
            complete: true,
            context_flags: Some(context_flags),
            validation: None,
            registers: None,
            stack: None,
            unwind_contexts: None,
            detail: "The complete context record does not contain the AMD64 control and integer register groups required for register decoding.".to_string(),
        };
    }
    let registers = X64ExceptionRegisters {
        rax: context.rax,
        rbx: context.rbx,
        rcx: context.rcx,
        rdx: context.rdx,
        rsi: context.rsi,
        rdi: context.rdi,
        rbp: context.rbp,
        rsp: context.rsp,
        r8: context.r8,
        r9: context.r9,
        r10: context.r10,
        r11: context.r11,
        r12: context.r12,
        r13: context.r13,
        r14: context.r14,
        r15: context.r15,
        rip: context.rip,
        eflags: context.eflags,
    };
    X64ExceptionContext {
        status: "captured".to_string(),
        context_record_address,
        requested_size,
        bytes_read,
        complete: true,
        context_flags: Some(context_flags),
        validation: Some(x64_context_validation(
            &context,
            buffer,
            selected_address_width,
        )),
        registers: Some(registers),
        stack: None,
        unwind_contexts: None,
        detail: "Decoded a complete AMD64 CONTEXT record without using stack unwinding."
            .to_string(),
    }
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

#[derive(Debug, Clone, Serialize)]
pub struct VirtualAddressInspection {
    pub address: u64,
    pub target_kind: DebuggerSessionKind,
    pub virtual_to_physical_status: String,
    pub physical_address: Option<u64>,
    pub virtual_to_physical_detail: String,
    pub query_virtual_status: String,
    pub virtual_region: Option<VirtualMemoryRegion>,
    pub query_virtual_detail: String,
    pub page_table_walk: X64PageTableWalk,
    pub translation_physical_offsets: VirtualTranslationPhysicalOffsets,
    pub page_table_walk_cross_check: VirtualAddressTranslationCrossCheck,
    pub extension_command_bridge: ExtensionCommandBridgeStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualAddressTranslationCrossCheck {
    pub status: String,
    pub virtual_to_physical_address: Option<u64>,
    pub translation_physical_offsets_address: Option<u64>,
    pub page_table_walk_address: Option<u64>,
    pub virtual_to_physical_matches_page_table_walk: Option<bool>,
    pub translation_physical_offsets_matches_page_table_walk: Option<bool>,
    pub virtual_to_physical_matches_translation_physical_offsets: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VirtualTranslationPhysicalOffsets {
    pub status: String,
    pub reported_level_count: Option<u32>,
    pub physical_offsets: Vec<u64>,
    pub last_physical_offset: Option<u64>,
    pub final_physical_address: Option<u64>,
    pub final_physical_address_validation: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtensionCommandBridgeStatus {
    pub status: String,
    pub allowed_forms: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64PageTableWalk {
    pub status: String,
    pub address: u64,
    pub virtual_address_bits: Option<u8>,
    pub canonical: Option<bool>,
    pub directory_table_base: Option<u64>,
    pub root_physical_address: Option<u64>,
    pub entries: Vec<X64PageTableEntry>,
    pub final_mapping: Option<X64PageTableMapping>,
    pub provenance: X64PageTableProvenance,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64PageTableProvenance {
    pub selected_debugger_context_cr3: Option<u64>,
    pub selected_debugger_context_cr4: Option<u64>,
    pub la57_enabled_in_selected_debugger_context: Option<bool>,
    pub dump_header_directory_table_base: Option<u64>,
    pub selected_root_matches_dump_header: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64PageTableEntry {
    pub level: String,
    pub index: u16,
    pub entry_physical_address: u64,
    pub raw_value: u64,
    pub present: bool,
    pub writable: bool,
    pub user_accessible: bool,
    pub write_through: bool,
    pub cache_disabled: bool,
    pub accessed: bool,
    pub dirty: Option<bool>,
    pub large_page: bool,
    pub global: Option<bool>,
    pub no_execute: bool,
    pub page_frame_number: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct X64PageTableMapping {
    pub physical_address: u64,
    pub page_size: u64,
    pub page_size_name: String,
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
pub struct DebuggerRunResult {
    pub execution_status: DebuggerExecutionStatus,
    pub event: Option<DebuggerEventInfo>,
    pub event_error: Option<String>,
    pub debuggee_output: Option<DebuggerOutputCaptureResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub engine_id: u32,
    pub system_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadAccountingEntry {
    pub thread: ThreadInfo,
    pub basic_information_status: String,
    pub basic_information_size_bytes: Option<u32>,
    pub name_status: String,
    pub name: Option<String>,
    pub name_size_bytes: Option<u32>,
    pub valid_mask: Option<u32>,
    pub exit_status: Option<u32>,
    pub priority_class: Option<u32>,
    pub priority: Option<u32>,
    pub create_time_raw: Option<u64>,
    pub exit_time_raw: Option<u64>,
    pub kernel_time_raw: Option<u64>,
    pub user_time_raw: Option<u64>,
    pub kernel_time_ms: Option<f64>,
    pub user_time_ms: Option<f64>,
    pub start_offset: Option<u64>,
    pub affinity: Option<u64>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadAccountingSnapshot {
    pub source: String,
    pub status: String,
    pub counter_units: String,
    pub total_threads: Option<usize>,
    pub threads: Vec<ThreadAccountingEntry>,
    pub returned: usize,
    pub limit: u32,
    pub truncated: bool,
    pub detail: String,
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
pub struct ModuleDebugParameters {
    pub base_address: u64,
    pub image_size: u32,
    pub time_date_stamp: u32,
    pub checksum: u32,
    pub flags: u32,
    pub symbol_type: u32,
    pub symbol_type_name: String,
    pub image_name_size: u32,
    pub module_name_size: u32,
    pub loaded_image_name_size: u32,
    pub symbol_file_name_size: u32,
    pub mapped_image_name_size: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolEntryOffsetRegion {
    pub base_address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolEntryRange {
    pub source: String,
    pub status: String,
    pub address: u64,
    pub symbol_module_base: Option<u64>,
    pub symbol_offset: Option<u64>,
    pub symbol_size: Option<u32>,
    pub displacement: Option<u64>,
    pub symbol_tag: Option<u32>,
    pub symbol_flags: Option<u32>,
    pub symbol_token: Option<u32>,
    pub regions: Vec<SymbolEntryOffsetRegion>,
    pub regions_available: Option<u32>,
    pub regions_truncated: bool,
    pub detail: String,
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
    pub thread_data_offset: Option<u64>,
    pub registers: CoreRegisterState,
    pub current_module: Option<ModuleInfo>,
    pub current_symbol: Option<SymbolInfo>,
    pub stack: Vec<StackFrameInfo>,
    pub disassembly: Option<DisassemblyResult>,
    pub current_thread_preserved: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessorSnapshot {
    pub processor_index: u32,
    pub status: String,
    pub engine_thread_id: Option<u32>,
    pub system_thread_id: Option<u32>,
    pub thread_data_offset: Option<u64>,
    pub registers: Option<CoreRegisterState>,
    pub current_module: Option<ModuleInfo>,
    pub current_symbol: Option<SymbolInfo>,
    pub stack: Option<StackTraceResult>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessorSnapshotResult {
    pub source: String,
    pub status: String,
    pub logical_processor_count: Option<u32>,
    pub returned: usize,
    pub nonempty_saved_stack_count: usize,
    pub unwind_limited_stack_count: usize,
    pub max_frames_per_processor: u32,
    pub processors: Vec<ProcessorSnapshot>,
    pub current_thread_preserved: bool,
    pub detail: String,
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
    runtime: DbgEngRuntime,
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

const X64_PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

fn x64_virtual_address_is_canonical(address: u64, virtual_address_bits: u8) -> bool {
    debug_assert!(virtual_address_bits == 48 || virtual_address_bits == 57);
    let sign_bit = u32::from(virtual_address_bits - 1);
    let upper_bits = !0u64 << virtual_address_bits;
    let upper = address & upper_bits;
    let sign_extended_upper = if address & (1u64 << sign_bit) == 0 {
        0
    } else {
        upper_bits
    };
    upper == sign_extended_upper
}

fn x64_page_table_entry(
    level: &str,
    index: u16,
    entry_physical_address: u64,
    raw_value: u64,
) -> X64PageTableEntry {
    let supports_large_page = matches!(level, "PDPTE" | "PDE");
    let large_page = supports_large_page && raw_value & (1 << 7) != 0;
    let is_leaf = level == "PTE" || large_page;
    X64PageTableEntry {
        level: level.to_string(),
        index,
        entry_physical_address,
        raw_value,
        present: raw_value & 1 != 0,
        writable: raw_value & (1 << 1) != 0,
        user_accessible: raw_value & (1 << 2) != 0,
        write_through: raw_value & (1 << 3) != 0,
        cache_disabled: raw_value & (1 << 4) != 0,
        accessed: raw_value & (1 << 5) != 0,
        dirty: is_leaf.then_some(raw_value & (1 << 6) != 0),
        large_page,
        global: is_leaf.then_some(raw_value & (1 << 8) != 0),
        no_execute: raw_value & (1 << 63) != 0,
        page_frame_number: (raw_value & X64_PHYSICAL_ADDRESS_MASK) >> 12,
    }
}

fn x64_large_page_physical_address(raw_value: u64, address: u64, page_size: u64) -> u64 {
    let page_base_mask = X64_PHYSICAL_ADDRESS_MASK & !(page_size - 1);
    (raw_value & page_base_mask) | (address & (page_size - 1))
}

fn unavailable_x64_page_table_provenance() -> X64PageTableProvenance {
    X64PageTableProvenance {
        selected_debugger_context_cr3: None,
        selected_debugger_context_cr4: None,
        la57_enabled_in_selected_debugger_context: None,
        dump_header_directory_table_base: None,
        selected_root_matches_dump_header: None,
        detail: "The page-table walk did not obtain the selected debugger context's CR3/CR4. An AMD64 CONTEXT record does not contain CR3 or CR4, so it cannot independently provide this paging root.".to_string(),
    }
}

fn x64_page_table_provenance(
    selected_debugger_context_cr3: Option<u64>,
    selected_debugger_context_cr4: Option<u64>,
    dump_header_directory_table_base: Option<u64>,
) -> X64PageTableProvenance {
    let selected_root =
        selected_debugger_context_cr3.map(|value| value & X64_PHYSICAL_ADDRESS_MASK);
    let dump_header_root =
        dump_header_directory_table_base.map(|value| value & X64_PHYSICAL_ADDRESS_MASK);
    let selected_root_matches_dump_header = selected_root
        .zip(dump_header_root)
        .map(|(left, right)| left == right);
    let detail = match selected_root_matches_dump_header {
        Some(true) => "CR3 and CR4 come from DbgEng's currently selected captured context. The selected CR3 root matches the dump-header DirectoryTableBase after masking address-space identifiers, so this bounded manual walk is also rooted at the recorded header base. AMD64 CONTEXT does not preserve CR3/CR4, so that root match does not prove it was the P4 context's paging root at the fault instant.",
        Some(false) => "CR3 and CR4 come from DbgEng's currently selected captured context. The selected CR3 root differs from the dump-header DirectoryTableBase after masking address-space identifiers; this walk reports the selected-context root and must not be treated as a header-root or P4-context walk. AMD64 CONTEXT does not preserve CR3/CR4.",
        None => "CR3 and CR4 come from DbgEng's currently selected captured context. The dump header did not expose a comparable DirectoryTableBase. AMD64 CONTEXT does not preserve CR3/CR4, so this walk cannot establish the P4 context's paging root.",
    };
    X64PageTableProvenance {
        selected_debugger_context_cr3,
        selected_debugger_context_cr4,
        la57_enabled_in_selected_debugger_context: selected_debugger_context_cr4
            .map(|value| value & (1 << 12) != 0),
        dump_header_directory_table_base,
        selected_root_matches_dump_header,
        detail: detail.to_string(),
    }
}

fn virtual_address_translation_cross_check(
    virtual_to_physical_address: Option<u64>,
    translation_physical_offsets: &VirtualTranslationPhysicalOffsets,
    page_table_walk: &X64PageTableWalk,
) -> VirtualAddressTranslationCrossCheck {
    let page_table_walk_address = page_table_walk
        .final_mapping
        .as_ref()
        .map(|mapping| mapping.physical_address);
    let translation_physical_offsets_address = translation_physical_offsets.final_physical_address;
    let virtual_to_physical_matches_page_table_walk = virtual_to_physical_address
        .zip(page_table_walk_address)
        .map(|(left, right)| left == right);
    let translation_physical_offsets_matches_page_table_walk = translation_physical_offsets_address
        .zip(page_table_walk_address)
        .map(|(left, right)| left == right);
    let virtual_to_physical_matches_translation_physical_offsets = virtual_to_physical_address
        .zip(translation_physical_offsets_address)
        .map(|(left, right)| left == right);
    let comparisons = [
        virtual_to_physical_matches_page_table_walk,
        translation_physical_offsets_matches_page_table_walk,
        virtual_to_physical_matches_translation_physical_offsets,
    ];
    let status = if comparisons.iter().flatten().any(|matches| !matches) {
        "mismatch"
    } else if comparisons.iter().flatten().next().is_some() {
        "matched"
    } else {
        "unavailable"
    };
    VirtualAddressTranslationCrossCheck {
        status: status.to_string(),
        virtual_to_physical_address,
        translation_physical_offsets_address,
        page_table_walk_address,
        virtual_to_physical_matches_page_table_walk,
        translation_physical_offsets_matches_page_table_walk,
        virtual_to_physical_matches_translation_physical_offsets,
        detail: "DbgEng VirtualToPhysical, IDebugDataSpaces2 translation physical offsets when available, and the bounded raw physical page-table walk were compared for this preserved snapshot. Any agreement is a snapshot consistency check, not reconstruction of historical mapping state.".to_string(),
    }
}

fn validate_translation_physical_offsets(
    translation_physical_offsets: &mut VirtualTranslationPhysicalOffsets,
    virtual_to_physical_address: Option<u64>,
    page_table_walk: &X64PageTableWalk,
) {
    let Some(last_physical_offset) = translation_physical_offsets.last_physical_offset else {
        translation_physical_offsets.final_physical_address_validation =
            "no_offsets_returned".to_string();
        return;
    };
    let page_table_walk_address = page_table_walk
        .final_mapping
        .as_ref()
        .map(|mapping| mapping.physical_address);
    let matches_virtual_to_physical = virtual_to_physical_address
        .map(|address| address == last_physical_offset)
        .unwrap_or(false);
    let matches_page_table_walk = page_table_walk_address
        .map(|address| address == last_physical_offset)
        .unwrap_or(false);
    if matches_virtual_to_physical || matches_page_table_walk {
        translation_physical_offsets.final_physical_address = Some(last_physical_offset);
        translation_physical_offsets.final_physical_address_validation =
            match (matches_virtual_to_physical, matches_page_table_walk) {
                (true, true) => {
                    "validated_by_virtual_to_physical_and_manual_page_table_walk".to_string()
                }
                (true, false) => "validated_by_virtual_to_physical".to_string(),
                (false, true) => "validated_by_manual_page_table_walk".to_string(),
                (false, false) => unreachable!("the condition above requires a validation"),
            };
    } else {
        translation_physical_offsets.final_physical_address_validation =
            "unvalidated_raw_hierarchy_offset".to_string();
    }
}

fn unavailable_x64_page_table_walk(address: u64, detail: String) -> X64PageTableWalk {
    X64PageTableWalk {
        status: "unavailable".to_string(),
        address,
        virtual_address_bits: None,
        canonical: None,
        directory_table_base: None,
        root_physical_address: None,
        entries: Vec::new(),
        final_mapping: None,
        provenance: unavailable_x64_page_table_provenance(),
        detail,
    }
}

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
            runtime: self.runtime.clone(),
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

    pub fn step_over(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STATUS_STEP_OVER;

        unsafe {
            self.control.SetExecutionStatus(DEBUG_STATUS_STEP_OVER)?;
        }
        Ok(self.execution_status())
    }

    pub fn continue_and_wait(
        &self,
        timeout_ms: u32,
        output_options: Option<DebuggerOutputCaptureOptions>,
    ) -> anyhow::Result<DebuggerRunResult> {
        let capture = output_options
            .map(|options| self.begin_debuggee_output_capture(options))
            .transpose()?;
        let result: anyhow::Result<(
            DebuggerExecutionStatus,
            Option<DebuggerEventInfo>,
            Option<String>,
        )> = (|| {
            self.continue_execution()?;
            let execution_status = self.wait_for_event(timeout_ms)?;
            let (event, event_error) = if execution_status.name.as_deref() == Some("timeout") {
                (None, None)
            } else {
                match self.last_event() {
                    Ok(event) => (Some(event), None),
                    Err(error) => (None, Some(format!("{error:#}"))),
                }
            };
            Ok((execution_status, event, event_error))
        })();
        let debuggee_output = capture.map(DebuggerOutputCapture::finish).transpose()?;
        let (execution_status, event, event_error) = result?;
        Ok(DebuggerRunResult {
            execution_status,
            event,
            event_error,
            debuggee_output,
        })
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

    pub fn bugcheck_data(&self) -> BugCheckDataResult {
        let mut code = 0u32;
        let mut parameters = [0u64; 4];
        let result = unsafe {
            self.control.ReadBugCheckData(
                &mut code,
                &mut parameters[0],
                &mut parameters[1],
                &mut parameters[2],
                &mut parameters[3],
            )
        };
        match result {
            Ok(()) if code != 0 => BugCheckDataResult {
                status: "captured".to_string(),
                data: Some(BugCheckData { code, parameters }),
                detail: "DbgEng returned the target bugcheck code and four parameters.".to_string(),
            },
            Ok(()) => BugCheckDataResult {
                status: "not_present".to_string(),
                data: None,
                detail: "DbgEng reported no bugcheck data for the current target.".to_string(),
            },
            Err(error) => BugCheckDataResult {
                status: "unavailable".to_string(),
                data: None,
                detail: format!("DbgEng ReadBugCheckData failed: {error}"),
            },
        }
    }

    pub fn dump_debugger_data(&self, max_frames: u32) -> DumpDebuggerData {
        const DEBUG_DATA_SAVED_CONTEXT_ADDR: u32 = 40;
        const DEBUG_DATA_KI_BUGCHECK_DATA_ADDR: u32 = 136;

        let read_u64 = |index| {
            let mut value = 0u64;
            let mut bytes_returned = 0u32;
            let result = unsafe {
                self.data_spaces.ReadDebuggerData(
                    index,
                    (&mut value as *mut u64).cast(),
                    std::mem::size_of::<u64>() as u32,
                    Some(&mut bytes_returned),
                )
            };
            match result {
                Ok(()) if bytes_returned == std::mem::size_of::<u64>() as u32 => Ok(value),
                Ok(()) => Err(anyhow::anyhow!(
                    "DbgEng returned {bytes_returned} of {} bytes",
                    std::mem::size_of::<u64>()
                )),
                Err(error) => Err(anyhow::anyhow!(error)),
            }
        };

        let (saved_context_address, saved_context_status) =
            match read_u64(DEBUG_DATA_SAVED_CONTEXT_ADDR) {
                Ok(0) => (
                    None,
                    "not_present: DbgEng returned a null saved-context address".to_string(),
                ),
                Ok(address) => (Some(address), "captured".to_string()),
                Err(error) => (None, format!("unavailable: {error}")),
            };
        let saved_context = saved_context_address.map(|address| {
            if self.processor_type().ok() == Some(0x8664) {
                self.x64_exception_context(address, max_frames)
            } else {
                X64ExceptionContext {
                    status: "architecture_unsupported".to_string(),
                    context_record_address: Some(address),
                    requested_size: X64_CONTEXT_SIZE,
                    bytes_read: 0,
                    complete: false,
                    context_flags: None,
                    validation: None,
                    registers: None,
                    stack: None,
                    unwind_contexts: None,
                    detail: "DEBUG_DATA_SavedContextAddr returned a context address, but this inspector only decodes AMD64 CONTEXT records.".to_string(),
                }
            }
        });
        let (ki_bugcheck_data_address, ki_bugcheck_data_status) =
            match read_u64(DEBUG_DATA_KI_BUGCHECK_DATA_ADDR) {
                Ok(0) => (
                    None,
                    "not_present: DbgEng returned a null KiBugCheckData address".to_string(),
                ),
                Ok(address) => (Some(address), "captured".to_string()),
                Err(error) => (None, format!("unavailable: {error}")),
            };

        DumpDebuggerData {
            status: if saved_context_address.is_some() || ki_bugcheck_data_address.is_some() {
                "captured".to_string()
            } else {
                "unavailable".to_string()
            },
            source: "dbgeng_idebugdataspaces3_readdebuggerdata".to_string(),
            saved_context_address,
            saved_context_status,
            saved_context,
            ki_bugcheck_data_address,
            ki_bugcheck_data_status,
            detail: "ReadDebuggerData returns the documented address of the saved bugcheck context and the KiBugCheckData kernel variable. The saved-context address proves only that a context was saved during the bugcheck; it does not link that context to P3 or establish instruction-fault-time registers. KiBugCheckData is retained as an address-only root because no versioned public layout is decoded.".to_string(),
        }
    }

    pub fn dump_header(&self) -> DumpHeaderSnapshot {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugAdvanced2;

        let advanced: IDebugAdvanced2 = match self.client.cast() {
            Ok(advanced) => advanced,
            Err(error) => {
                return unavailable_dump_header(format!(
                    "DbgEng did not expose IDebugAdvanced2 for the documented dump-header request: {error}"
                ));
            }
        };
        let mut buffer = [0u8; DUMP_HEADER64_SIZE];
        let mut bytes_returned = 0u32;
        let result = unsafe {
            advanced.Request(
                21, // DEBUG_REQUEST_GET_DUMP_HEADER
                None,
                0,
                Some(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
                Some(&mut bytes_returned),
            )
        };
        match result {
            Ok(()) => {
                let usable_bytes = if bytes_returned == 0 {
                    buffer.len()
                } else {
                    (bytes_returned as usize).min(buffer.len())
                };
                dump_header_from_bytes(&buffer[..usable_bytes], bytes_returned)
            }
            Err(error) => unavailable_dump_header(format!(
                "DbgEng DEBUG_REQUEST_GET_DUMP_HEADER failed: {error}"
            )),
        }
    }

    pub fn dump_event_inventory(&self) -> DumpEventInventory {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl3;

        let control: IDebugControl3 = match self.client.cast() {
            Ok(control) => control,
            Err(error) => {
                return DumpEventInventory {
                    status: "unavailable".to_string(),
                    source: "dbgeng_idebugcontrol3_event_inventory".to_string(),
                    event_count: None,
                    current_event_index: None,
                    current_event_index_status: "unavailable".to_string(),
                    detail: format!(
                        "DbgEng did not expose IDebugControl3 for the bounded event inventory: {error}"
                    ),
                };
            }
        };
        let event_count = match unsafe { control.GetNumberEvents() } {
            Ok(event_count) => event_count,
            Err(error) => {
                return DumpEventInventory {
                    status: "unavailable".to_string(),
                    source: "dbgeng_idebugcontrol3_event_inventory".to_string(),
                    event_count: None,
                    current_event_index: None,
                    current_event_index_status: "unavailable".to_string(),
                    detail: format!("DbgEng GetNumberEvents failed: {error}"),
                };
            }
        };
        let (current_event_index, current_event_index_status, current_event_index_detail) =
            match unsafe { control.GetCurrentEventIndex() } {
                Ok(index) => (Some(index), "captured".to_string(), None),
                Err(error) => (
                    None,
                    "unavailable".to_string(),
                    Some(format!("DbgEng GetCurrentEventIndex failed: {error}")),
                ),
            };
        DumpEventInventory {
            status: "captured".to_string(),
            source: "dbgeng_idebugcontrol3_event_inventory".to_string(),
            event_count: Some(event_count),
            current_event_index,
            current_event_index_status,
            detail: current_event_index_detail.unwrap_or_else(|| "DbgEng returned bounded event-list metadata without selecting or replaying an event. Event enumeration does not expose a typed exception-record-to-context pointer relationship for this kernel dump, so no event is treated as P3/P4 linkage.".to_string()),
        }
    }

    fn stored_event_information(&self, max_frames: u32) -> StoredEventInformation {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl4;

        const MAX_STORED_EVENT_EXTRA_BYTES: usize = 512;

        let control: IDebugControl4 = match self.client.cast() {
            Ok(control) => control,
            Err(error) => {
                return StoredEventInformation {
                    status: "unavailable".to_string(),
                    source: "dbgeng_idebugcontrol4_get_stored_event_information".to_string(),
                    event_type: None,
                    process_system_id: None,
                    thread_system_id: None,
                    context: None,
                    context_status: "unavailable".to_string(),
                    extra_information_bytes_returned: None,
                    extra_information_status: "not_returned".to_string(),
                    detail: format!(
                        "DbgEng did not expose IDebugControl4 for the bounded stored-event probe: {error}"
                    ),
                };
            }
        };
        let mut event_type = 0u32;
        let mut process_system_id = 0u32;
        let mut thread_system_id = 0u32;
        let mut context_bytes = [0u8; X64_CONTEXT_SIZE as usize];
        let mut context_used = 0u32;
        let mut extra_information = [0u8; MAX_STORED_EVENT_EXTRA_BYTES];
        let mut extra_information_used = 0u32;
        let result = unsafe {
            control.GetStoredEventInformation(
                &mut event_type,
                &mut process_system_id,
                &mut thread_system_id,
                Some(context_bytes.as_mut_ptr().cast()),
                context_bytes.len() as u32,
                Some(&mut context_used),
                Some(extra_information.as_mut_ptr().cast()),
                extra_information.len() as u32,
                Some(&mut extra_information_used),
            )
        };
        let Err(error) = result else {
            let context_status = match (
                self.processor_type().ok(),
                context_used.min(context_bytes.len() as u32),
            ) {
                (Some(0x8664), 0) => "not_returned".to_string(),
                (Some(0x8664), used) if used < X64_CONTEXT_SIZE => {
                    format!("partial: {used} of {X64_CONTEXT_SIZE} bytes")
                }
                (Some(0x8664), _) => "captured".to_string(),
                _ => "architecture_unsupported".to_string(),
            };
            let context = (context_status == "captured").then(|| {
                self.decode_x64_exception_context(
                    None,
                    &context_bytes,
                    context_used.min(context_bytes.len() as u32),
                    max_frames,
                )
            });
            return StoredEventInformation {
                status: "captured".to_string(),
                source: "dbgeng_idebugcontrol4_get_stored_event_information".to_string(),
                event_type: Some(event_type),
                process_system_id: Some(process_system_id),
                thread_system_id: Some(thread_system_id),
                context,
                context_status,
                extra_information_bytes_returned: Some(extra_information_used),
                extra_information_status: if extra_information_used == 0 {
                    "not_returned".to_string()
                } else if extra_information_used <= extra_information.len() as u32 {
                    "present_not_decoded".to_string()
                } else {
                    format!(
                        "truncated_not_decoded: {extra_information_used} bytes exceed the {} byte limit",
                        extra_information.len()
                    )
                },
                detail: "DbgEng documents stored-event data as optional and typically present in user-mode minidumps. This bounded probe retains only returned identifiers, a complete AMD64 CONTEXT when present, and the extra-data byte count; unknown extra bytes are never decoded or treated as kernel exception provenance.".to_string(),
            };
        };
        StoredEventInformation {
            status: "unavailable".to_string(),
            source: "dbgeng_idebugcontrol4_get_stored_event_information".to_string(),
            event_type: None,
            process_system_id: None,
            thread_system_id: None,
            context: None,
            context_status: "unavailable".to_string(),
            extra_information_bytes_returned: None,
            extra_information_status: "not_returned".to_string(),
            detail: format!(
                "DbgEng GetStoredEventInformation did not expose a stored event for this target: {error}"
            ),
        }
    }

    fn target_exception_contract(&self) -> TargetExceptionContract {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_CLASS_USER_WINDOWS, DEBUG_DUMP_SMALL,
        };

        let mut debuggee_class = 0u32;
        let mut debuggee_qualifier = 0u32;
        match unsafe {
            self.control
                .GetDebuggeeType(&mut debuggee_class, &mut debuggee_qualifier)
        } {
            Ok(()) if debuggee_class == DEBUG_CLASS_USER_WINDOWS
                && debuggee_qualifier == DEBUG_DUMP_SMALL =>
            {
                TargetExceptionContract {
                    status: "verified_user_mode_minidump".to_string(),
                    source: "dbgeng_idebugcontrol_getdebuggeetype".to_string(),
                    debuggee_class: Some(debuggee_class),
                    debuggee_qualifier: Some(debuggee_qualifier),
                    detail: "DbgEng identified a user-mode minidump, the documented target scope for target-exception context, thread, and record requests.".to_string(),
                }
            }
            Ok(()) => TargetExceptionContract {
                status: "unsupported_debuggee_type".to_string(),
                source: "dbgeng_idebugcontrol_getdebuggeetype".to_string(),
                debuggee_class: Some(debuggee_class),
                debuggee_qualifier: Some(debuggee_qualifier),
                detail: "DbgEng target-exception requests are documented for user-mode minidumps only. Any returned data outside that verified target type remains an unlinked observation.".to_string(),
            },
            Err(error) => TargetExceptionContract {
                status: "unavailable".to_string(),
                source: "dbgeng_idebugcontrol_getdebuggeetype".to_string(),
                debuggee_class: None,
                debuggee_qualifier: None,
                detail: format!(
                    "DbgEng GetDebuggeeType failed, so the documented user-mode-minidump scope could not be verified: {error}"
                ),
            },
        }
    }

    pub fn target_exception_snapshot(&self, max_frames: u32) -> TargetExceptionSnapshot {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugAdvanced2;

        let contract = self.target_exception_contract();
        let stored_event = self.stored_event_information(max_frames);
        let advanced: IDebugAdvanced2 = match self.client.cast() {
            Ok(advanced) => advanced,
            Err(error) => {
                return TargetExceptionSnapshot {
                    status: "unavailable".to_string(),
                    source: "dbgeng_idebugadvanced2_target_exception_requests".to_string(),
                    contract,
                    stored_event,
                    thread_system_id: None,
                    thread_status: "unavailable".to_string(),
                    record: None,
                    record_status: "unavailable".to_string(),
                    context: None,
                    context_status: "unavailable".to_string(),
                    detail: format!(
                        "DbgEng did not expose IDebugAdvanced2 for target-exception requests: {error}"
                    ),
                };
            }
        };

        let mut thread_system_id = 0u32;
        let thread_status = match unsafe {
            advanced.Request(
                2, // DEBUG_REQUEST_TARGET_EXCEPTION_THREAD
                None,
                0,
                Some((&mut thread_system_id as *mut u32).cast()),
                std::mem::size_of::<u32>() as u32,
                None,
            )
        } {
            Ok(()) => "captured".to_string(),
            Err(error) => format!("unavailable: {error}"),
        };

        let mut record_bytes = [0u8; EXCEPTION_RECORD64_SIZE];
        let record_status = match unsafe {
            advanced.Request(
                3, // DEBUG_REQUEST_TARGET_EXCEPTION_RECORD
                None,
                0,
                Some(record_bytes.as_mut_ptr().cast()),
                record_bytes.len() as u32,
                None,
            )
        } {
            Ok(()) => "captured".to_string(),
            Err(error) => format!("unavailable: {error}"),
        };
        let record = (record_status == "captured")
            .then(|| target_exception_record_from_bytes(&record_bytes))
            .flatten();

        let mut context_bytes = [0u8; X64_CONTEXT_SIZE as usize];
        let mut context_size = 0u32;
        let context_status = if self.processor_type().ok() != Some(0x8664) {
            "architecture_unsupported".to_string()
        } else {
            match unsafe {
                advanced.Request(
                    1, // DEBUG_REQUEST_TARGET_EXCEPTION_CONTEXT
                    None,
                    0,
                    Some(context_bytes.as_mut_ptr().cast()),
                    context_bytes.len() as u32,
                    Some(&mut context_size),
                )
            } {
                Ok(()) => "captured".to_string(),
                Err(error) => format!("unavailable: {error}"),
            }
        };
        let context = if context_status == "captured" {
            let bytes_returned = if context_size == 0 {
                context_bytes.len() as u32
            } else {
                context_size.min(context_bytes.len() as u32)
            };
            Some(self.decode_x64_exception_context(
                None,
                &context_bytes[..bytes_returned as usize],
                bytes_returned,
                max_frames,
            ))
        } else {
            None
        };
        let captured_parts = [
            thread_status == "captured",
            record_status == "captured",
            context_status == "captured",
        ]
        .into_iter()
        .filter(|captured| *captured)
        .count();
        TargetExceptionSnapshot {
            status: match captured_parts {
                3 => "captured".to_string(),
                0 => "unavailable".to_string(),
                _ => "partial".to_string(),
            },
            source: "dbgeng_idebugadvanced2_target_exception_requests".to_string(),
            contract,
            stored_event,
            thread_system_id: (thread_status == "captured").then_some(thread_system_id),
            thread_status,
            record,
            record_status,
            context,
            context_status,
            detail: "DbgEng documents the target-exception requests for a stored event in a user-mode minidump. They are invoked here only as bounded capability probes; a returned thread identifies DbgEng's recorded exception thread, not a logical processor or historical writer. Their unavailability does not disprove the bounded structural P3/P4 candidates.".to_string(),
        }
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

    pub fn x64_exception_context(
        &self,
        context_record_address: u64,
        max_frames: u32,
    ) -> X64ExceptionContext {
        let requested_size = X64_CONTEXT_SIZE;
        let mut buffer = vec![0u8; requested_size as usize];
        let mut bytes_read = 0u32;
        let read_result = unsafe {
            self.data_spaces.ReadVirtual(
                context_record_address,
                buffer.as_mut_ptr() as _,
                requested_size,
                Some(&mut bytes_read),
            )
        };
        if let Err(error) = read_result {
            return X64ExceptionContext {
                status: "unavailable".to_string(),
                context_record_address: Some(context_record_address),
                requested_size,
                bytes_read,
                complete: false,
                context_flags: None,
                validation: None,
                registers: None,
                stack: None,
                unwind_contexts: None,
                detail: format!(
                    "DbgEng could not read the x64 exception context at 0x{context_record_address:X}: {error}"
                ),
            };
        }
        if bytes_read < requested_size {
            return X64ExceptionContext {
                status: "partial".to_string(),
                context_record_address: Some(context_record_address),
                requested_size,
                bytes_read,
                complete: false,
                context_flags: None,
                validation: None,
                registers: None,
                stack: None,
                unwind_contexts: None,
                detail: format!(
                    "The dump contains only {bytes_read} of {requested_size} bytes for the x64 CONTEXT record."
                ),
            };
        }

        self.decode_x64_exception_context(
            Some(context_record_address),
            &buffer,
            bytes_read,
            max_frames,
        )
    }

    pub fn x64_exception_record(
        &self,
        exception_record_address: u64,
    ) -> anyhow::Result<TargetExceptionRecord> {
        let mut buffer = [0u8; EXCEPTION_RECORD64_SIZE];
        let mut bytes_read = 0u32;
        unsafe {
            self.data_spaces.ReadVirtual(
                exception_record_address,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                Some(&mut bytes_read),
            )?;
        }
        ensure!(
            bytes_read == buffer.len() as u32,
            "DbgEng returned only {bytes_read} of {} bytes for the x64 EXCEPTION_RECORD",
            buffer.len()
        );
        target_exception_record_from_bytes(&buffer).context(
            "The complete x64 EXCEPTION_RECORD has an unsupported parameter count or layout",
        )
    }

    fn context_stack_trace(&self, start_context: &[u8], max_frames: u32) -> X64ContextStackTrace {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            IDebugControl4, DEBUG_STACK_FRAME,
        };

        if start_context.len() < X64_CONTEXT_SIZE as usize {
            return X64ContextStackTrace {
                status: "unavailable".to_string(),
                source: "dbgeng_idebugcontrol4_get_context_stack_trace".to_string(),
                requested_frames: max_frames,
                returned_frames: 0,
                frame_zero_matches_start_context: None,
                frames: Vec::new(),
                detail: format!(
                    "The bounded start context contains only {} of {X64_CONTEXT_SIZE} AMD64 CONTEXT bytes.",
                    start_context.len()
                ),
            };
        }
        if max_frames == 0 {
            return X64ContextStackTrace {
                status: "unavailable".to_string(),
                source: "dbgeng_idebugcontrol4_get_context_stack_trace".to_string(),
                requested_frames: max_frames,
                returned_frames: 0,
                frame_zero_matches_start_context: None,
                frames: Vec::new(),
                detail: "A positive frame limit is required for the bounded context stack trace."
                    .to_string(),
            };
        }
        let control: IDebugControl4 = match self.client.cast() {
            Ok(control) => control,
            Err(error) => {
                return X64ContextStackTrace {
                    status: "unavailable".to_string(),
                    source: "dbgeng_idebugcontrol4_get_context_stack_trace".to_string(),
                    requested_frames: max_frames,
                    returned_frames: 0,
                    frame_zero_matches_start_context: None,
                    frames: Vec::new(),
                    detail: format!(
                        "DbgEng did not expose IDebugControl4 for the bounded context stack trace: {error}"
                    ),
                };
            }
        };
        let mut stack_frames = vec![DEBUG_STACK_FRAME::default(); max_frames as usize];
        let mut frame_context_bytes = vec![0u8; max_frames as usize * X64_CONTEXT_SIZE as usize];
        let mut filled = 0u32;
        let result = unsafe {
            control.GetContextStackTrace(
                Some(start_context.as_ptr().cast()),
                X64_CONTEXT_SIZE,
                Some(&mut stack_frames),
                Some(frame_context_bytes.as_mut_ptr().cast()),
                frame_context_bytes.len() as u32,
                X64_CONTEXT_SIZE,
                Some(&mut filled),
            )
        };
        let Err(error) = result else {
            let returned_frames = filled.min(max_frames) as usize;
            stack_frames.truncate(returned_frames);
            let frames = stack_frames
                .iter()
                .enumerate()
                .map(|(index, frame)| {
                    let start = index * X64_CONTEXT_SIZE as usize;
                    let end = start + X64_CONTEXT_SIZE as usize;
                    let context = x64_context_prefix_from_bytes(&frame_context_bytes[start..end]);
                    let required_register_groups_present = context.is_some_and(|context| {
                        context.context_flags & CONTEXT_X64_REQUIRED_REGISTER_FLAGS
                            == CONTEXT_X64_REQUIRED_REGISTER_FLAGS
                    });
                    let (context_rip, context_flags, r8, r14) = context
                        .map(|context| {
                            (
                                Some(context.rip),
                                Some(context.context_flags),
                                Some(context.r8),
                                Some(context.r14),
                            )
                        })
                        .unwrap_or((None, None, None, None));
                    X64UnwindContextFrame {
                        frame_number: frame.FrameNumber,
                        instruction_offset: frame.InstructionOffset,
                        context_rip,
                        context_flags,
                        required_register_groups_present,
                        r8,
                        r14,
                        structural_effective_address: r8
                            .zip(r14)
                            .and_then(|(r8, r14)| r8.checked_add(r14)),
                    }
                })
                .collect::<Vec<_>>();
            let start = x64_context_prefix_from_bytes(start_context);
            let frame_zero_matches_start_context =
                start.zip(frames.first()).map(|(start, frame)| {
                    frame.context_rip == Some(start.rip)
                        && frame.r8 == Some(start.r8)
                        && frame.r14 == Some(start.r14)
                });
            return X64ContextStackTrace {
                status: "captured".to_string(),
                source: "dbgeng_idebugcontrol4_get_context_stack_trace".to_string(),
                requested_frames: max_frames,
                returned_frames: returned_frames as u32,
                frame_zero_matches_start_context,
                frames,
                detail: "DbgEng reconstructed these contexts by unwinding from the supplied saved CONTEXT. They are derived from that input, not an independent exception/trap-frame capture. Microsoft documents that volatile registers need not be restored by stack unwinding, so R8/R14 values after frame zero are never used as fault-time evidence.".to_string(),
            };
        };
        X64ContextStackTrace {
            status: "unavailable".to_string(),
            source: "dbgeng_idebugcontrol4_get_context_stack_trace".to_string(),
            requested_frames: max_frames,
            returned_frames: 0,
            frame_zero_matches_start_context: None,
            frames: Vec::new(),
            detail: format!("DbgEng GetContextStackTrace failed: {error}"),
        }
    }

    fn decode_x64_exception_context(
        &self,
        context_record_address: Option<u64>,
        buffer: &[u8],
        bytes_read: u32,
        max_frames: u32,
    ) -> X64ExceptionContext {
        let mut decoded = decode_x64_context_structural(
            context_record_address,
            buffer,
            bytes_read,
            self.selected_x64_address_width().ok(),
        );
        let Some(registers) = decoded.registers.as_ref() else {
            return decoded;
        };
        let stack =
            self.stack_trace_from_offsets(registers.rbp, registers.rsp, registers.rip, max_frames);
        let unwind_contexts = self.context_stack_trace(buffer, max_frames);
        let (status, detail) = match &stack {
            Ok(result) => (
                "captured".to_string(),
                format!(
                    "Decoded an x64 CONTEXT record and captured a {} stack walk.",
                    result.status
                ),
            ),
            Err(error) => (
                "context_captured_stack_unavailable".to_string(),
                format!(
                    "Decoded an x64 CONTEXT record, but DbgEng could not walk its stack: {error}"
                ),
            ),
        };
        decoded.status = status;
        decoded.stack = stack.ok();
        decoded.unwind_contexts = Some(unwind_contexts);
        decoded.detail = detail;
        decoded
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

    pub fn inspect_virtual_address(&self, address: u64) -> VirtualAddressInspection {
        use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION64;

        let (virtual_to_physical_status, physical_address, virtual_to_physical_detail) =
            match unsafe { self.data_spaces.VirtualToPhysical(address) } {
                Ok(physical_address) => (
                    "captured".to_string(),
                    Some(physical_address),
                    "DbgEng translated this virtual address to the physical address captured by the target.".to_string(),
                ),
                Err(error) => (
                    "unavailable".to_string(),
                    None,
                    format!("DbgEng VirtualToPhysical did not provide a translation: {error}"),
                ),
            };

        let mut info = MEMORY_BASIC_INFORMATION64::default();
        let (query_virtual_status, virtual_region, query_virtual_detail) = match unsafe {
            self.data_spaces.QueryVirtual(address, &mut info)
        } {
            Ok(()) => (
                "captured".to_string(),
                Some(VirtualMemoryRegion {
                    base_address: info.BaseAddress,
                    allocation_base: info.AllocationBase,
                    allocation_protection: info.AllocationProtect.0,
                    region_size: info.RegionSize,
                    state: info.State.0,
                    protection: info.Protect.0,
                    kind: info.Type.0,
                }),
                "DbgEng returned one MEMORY_BASIC_INFORMATION64 record for the supplied address."
                    .to_string(),
            ),
            Err(error) => (
                "unavailable".to_string(),
                None,
                format!("DbgEng QueryVirtual did not provide a region: {error}"),
            ),
        };

        let page_table_walk = self.walk_x64_page_tables(address);
        let mut translation_physical_offsets = self.virtual_translation_physical_offsets(address);
        validate_translation_physical_offsets(
            &mut translation_physical_offsets,
            physical_address,
            &page_table_walk,
        );
        let page_table_walk_cross_check = virtual_address_translation_cross_check(
            physical_address,
            &translation_physical_offsets,
            &page_table_walk,
        );
        VirtualAddressInspection {
            address,
            target_kind: self.kind,
            virtual_to_physical_status,
            physical_address,
            virtual_to_physical_detail,
            query_virtual_status,
            virtual_region,
            query_virtual_detail,
            page_table_walk,
            translation_physical_offsets,
            page_table_walk_cross_check,
            extension_command_bridge: ExtensionCommandBridgeStatus {
                status: "unsupported".to_string(),
                allowed_forms: vec![
                    "!pte <canonical-x64-address>".to_string(),
                    "!pool <canonical-x64-address>".to_string(),
                ],
                detail: "DbgEng IDebugControl::ExecuteWide executes synchronously on the owning debugger session. This wrapper has no safe, enforceable cancellation or timeout mechanism that can prevent a hung extension query without leaving the dump session in an indeterminate state. To preserve bounded, read-only analysis, no extension command is executed and no command output is claimed. The structured x64 page-table walker is the supported PTE diagnostic.".to_string(),
            },
            detail: "A captured virtual-to-physical translation proves only that DbgEng can translate the address in this snapshot. The bounded raw page-table walk separately reports the stored leaf R/W bit when it reaches a present leaf. Neither result reconstructs the PTE state, paging root, or write permission at the historical fault instant.".to_string(),
        }
    }

    fn virtual_translation_physical_offsets(
        &self,
        address: u64,
    ) -> VirtualTranslationPhysicalOffsets {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugDataSpaces2;

        const MAX_TRANSLATION_LEVELS: usize = 8;
        let data_spaces: IDebugDataSpaces2 = match self.data_spaces.cast() {
            Ok(data_spaces) => data_spaces,
            Err(error) => {
                return VirtualTranslationPhysicalOffsets {
                    status: "unavailable".to_string(),
                    reported_level_count: None,
                    physical_offsets: Vec::new(),
                    last_physical_offset: None,
                    final_physical_address: None,
                    final_physical_address_validation: "unavailable".to_string(),
                    detail: format!(
                        "DbgEng did not expose IDebugDataSpaces2 for translation physical offsets: {error}"
                    ),
                };
            }
        };
        let mut physical_offsets = [0u64; MAX_TRANSLATION_LEVELS];
        let mut reported_level_count = 0u32;
        let result = unsafe {
            data_spaces.GetVirtualTranslationPhysicalOffsets(
                address,
                Some(&mut physical_offsets),
                Some(&mut reported_level_count),
            )
        };
        match result {
            Ok(()) if reported_level_count == 0 => VirtualTranslationPhysicalOffsets {
                status: "invalid".to_string(),
                reported_level_count: Some(reported_level_count),
                physical_offsets: Vec::new(),
                last_physical_offset: None,
                final_physical_address: None,
                final_physical_address_validation: "unavailable".to_string(),
                detail: "DbgEng reported a successful translation-offset request with zero levels."
                    .to_string(),
            },
            Ok(()) if reported_level_count as usize > MAX_TRANSLATION_LEVELS => {
                VirtualTranslationPhysicalOffsets {
                    status: "partial".to_string(),
                    reported_level_count: Some(reported_level_count),
                    physical_offsets: physical_offsets.to_vec(),
                    last_physical_offset: physical_offsets.last().copied(),
                    final_physical_address: None,
                    final_physical_address_validation: "unavailable".to_string(),
                    detail: format!(
                        "DbgEng reported {reported_level_count} translation levels, exceeding the fixed bounded buffer of {MAX_TRANSLATION_LEVELS}; no final address is inferred."
                    ),
                }
            }
            Ok(()) => {
                let offsets = physical_offsets[..reported_level_count as usize].to_vec();
                VirtualTranslationPhysicalOffsets {
                    status: "captured".to_string(),
                    reported_level_count: Some(reported_level_count),
                    last_physical_offset: offsets.last().copied(),
                    final_physical_address: None,
                    final_physical_address_validation: "unvalidated_raw_hierarchy_offset"
                        .to_string(),
                    physical_offsets: offsets,
                    detail: "DbgEng IDebugDataSpaces2 returned raw physical paging-hierarchy offsets for this address. The final raw offset is not called a translated physical address unless it independently matches VirtualToPhysical or a completed bounded manual page-table walk.".to_string(),
                }
            }
            Err(error) => VirtualTranslationPhysicalOffsets {
                status: "unavailable".to_string(),
                reported_level_count: None,
                physical_offsets: Vec::new(),
                last_physical_offset: None,
                final_physical_address: None,
                final_physical_address_validation: "unavailable".to_string(),
                detail: format!(
                    "DbgEng GetVirtualTranslationPhysicalOffsets did not provide a translation: {error}"
                ),
            },
        }
    }

    fn selected_x64_address_width(&self) -> anyhow::Result<(u64, u8)> {
        let cr4 = self.evaluate("@cr4").and_then(|value| {
            value
                .unsigned_value
                .context("DbgEng evaluated @cr4 without an unsigned integer result")
        })?;
        Ok((cr4, if cr4 & (1 << 12) != 0 { 57 } else { 48 }))
    }

    fn walk_x64_page_tables(&self, address: u64) -> X64PageTableWalk {
        let dump_header_directory_table_base = self.dump_header().directory_table_base;
        let (cr4, virtual_address_bits) = match self.selected_x64_address_width() {
            Ok(value) => value,
            Err(error) => {
                return unavailable_x64_page_table_walk(
                    address,
                    format!("DbgEng could not read @cr4 to determine x64 address width: {error}"),
                )
            }
        };
        let canonical = x64_virtual_address_is_canonical(address, virtual_address_bits);
        if !canonical {
            return X64PageTableWalk {
                status: "noncanonical_address".to_string(),
                address,
                virtual_address_bits: Some(virtual_address_bits),
                canonical: Some(false),
                directory_table_base: None,
                root_physical_address: None,
                entries: Vec::new(),
                final_mapping: None,
                provenance: x64_page_table_provenance(
                    None,
                    Some(cr4),
                    dump_header_directory_table_base,
                ),
                detail: "The supplied virtual address is not canonical for the captured CR4.LA57 state; no physical page-table reads were attempted.".to_string(),
            };
        }
        let directory_table_base = match self.evaluate("@cr3").and_then(|value| {
            value
                .unsigned_value
                .context("DbgEng evaluated @cr3 without an unsigned integer result")
        }) {
            Ok(value) => value,
            Err(error) => {
                return unavailable_x64_page_table_walk(
                    address,
                    format!("DbgEng could not read @cr3 for the current captured processor context: {error}"),
                )
            }
        };
        let provenance = x64_page_table_provenance(
            Some(directory_table_base),
            Some(cr4),
            dump_header_directory_table_base,
        );
        let root_physical_address = directory_table_base & X64_PHYSICAL_ADDRESS_MASK;
        if root_physical_address == 0 {
            return X64PageTableWalk {
                status: "unavailable".to_string(),
                address,
                virtual_address_bits: Some(virtual_address_bits),
                canonical: Some(true),
                directory_table_base: Some(directory_table_base),
                root_physical_address: Some(root_physical_address),
                entries: Vec::new(),
                final_mapping: None,
                provenance,
                detail: "The captured CR3 does not contain a nonzero page-table physical base."
                    .to_string(),
            };
        }

        let levels: &[(&str, u32)] = if virtual_address_bits == 57 {
            &[
                ("PML5E", 48),
                ("PML4E", 39),
                ("PDPTE", 30),
                ("PDE", 21),
                ("PTE", 12),
            ]
        } else {
            &[("PML4E", 39), ("PDPTE", 30), ("PDE", 21), ("PTE", 12)]
        };
        let mut entries = Vec::with_capacity(levels.len());
        let mut table_physical_address = root_physical_address;
        for (level_index, (level, shift)) in levels.iter().enumerate() {
            let index = ((address >> shift) & 0x1ff) as u16;
            let Some(entry_physical_address) =
                table_physical_address.checked_add(u64::from(index) * 8)
            else {
                return unavailable_x64_page_table_walk(
                    address,
                    "The calculated physical page-table entry address overflowed.".to_string(),
                );
            };
            let raw_value = match self.read_physical_u64(entry_physical_address) {
                Ok(value) => value,
                Err(error) => {
                    return X64PageTableWalk {
                        status: "physical_read_unavailable".to_string(),
                        address,
                        virtual_address_bits: Some(virtual_address_bits),
                        canonical: Some(true),
                        directory_table_base: Some(directory_table_base),
                        root_physical_address: Some(root_physical_address),
                        entries,
                        final_mapping: None,
                        provenance: provenance.clone(),
                        detail: format!(
                            "DbgEng could not read the {level} physical entry at 0x{entry_physical_address:X}: {error}"
                        ),
                    }
                }
            };
            let entry = x64_page_table_entry(level, index, entry_physical_address, raw_value);
            if !entry.present {
                entries.push(entry);
                return X64PageTableWalk {
                    status: "nonpresent".to_string(),
                    address,
                    virtual_address_bits: Some(virtual_address_bits),
                    canonical: Some(true),
                    directory_table_base: Some(directory_table_base),
                    root_physical_address: Some(root_physical_address),
                    entries,
                    final_mapping: None,
                    provenance: provenance.clone(),
                    detail: format!("The captured {level} is not present. This is post-bugcheck snapshot evidence and does not establish an earlier transition."),
                };
            }

            let is_pdpt = *level == "PDPTE";
            let is_pd = *level == "PDE";
            if entry.large_page && (is_pdpt || is_pd) {
                let page_size = if is_pdpt { 1u64 << 30 } else { 1u64 << 21 };
                let physical_address =
                    x64_large_page_physical_address(raw_value, address, page_size);
                entries.push(entry);
                return X64PageTableWalk {
                    status: "captured".to_string(),
                    address,
                    virtual_address_bits: Some(virtual_address_bits),
                    canonical: Some(true),
                    directory_table_base: Some(directory_table_base),
                    root_physical_address: Some(root_physical_address),
                    entries,
                    final_mapping: Some(X64PageTableMapping {
                        physical_address,
                        page_size,
                        page_size_name: if is_pdpt { "1_gib" } else { "2_mib" }.to_string(),
                    }),
                    provenance: provenance.clone(),
                    detail: "The walker reached a present large-page mapping. Entries are preserved post-bugcheck state, not proof of the permission or lifetime state at the earlier fault instant.".to_string(),
                };
            }
            entries.push(entry);
            if level_index + 1 == levels.len() {
                let physical_address = (raw_value & X64_PHYSICAL_ADDRESS_MASK) | (address & 0xfff);
                return X64PageTableWalk {
                    status: "captured".to_string(),
                    address,
                    virtual_address_bits: Some(virtual_address_bits),
                    canonical: Some(true),
                    directory_table_base: Some(directory_table_base),
                    root_physical_address: Some(root_physical_address),
                    entries,
                    final_mapping: Some(X64PageTableMapping {
                        physical_address,
                        page_size: 4096,
                        page_size_name: "4_kib".to_string(),
                    }),
                    provenance: provenance.clone(),
                    detail: "The walker reached a present 4 KiB mapping. Entries are preserved post-bugcheck state, not proof of the permission or lifetime state at the earlier fault instant.".to_string(),
                };
            }
            table_physical_address = raw_value & X64_PHYSICAL_ADDRESS_MASK;
            if table_physical_address == 0 {
                return X64PageTableWalk {
                    status: "invalid_next_table".to_string(),
                    address,
                    virtual_address_bits: Some(virtual_address_bits),
                    canonical: Some(true),
                    directory_table_base: Some(directory_table_base),
                    root_physical_address: Some(root_physical_address),
                    entries,
                    final_mapping: None,
                    provenance,
                    detail: format!("The present {level} has a zero next-table physical base."),
                };
            }
        }
        unreachable!("the x64 page-table level list always ends in a PTE");
    }

    fn read_physical_u64(&self, physical_address: u64) -> anyhow::Result<u64> {
        let mut bytes = [0u8; std::mem::size_of::<u64>()];
        let mut bytes_read = 0u32;
        unsafe {
            self.data_spaces.ReadPhysical(
                physical_address,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                Some(&mut bytes_read),
            )?;
        }
        ensure!(
            bytes_read == bytes.len() as u32,
            "DbgEng returned only {bytes_read} of {} requested physical bytes",
            bytes.len()
        );
        Ok(u64::from_le_bytes(bytes))
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

    pub fn processor_snapshot(&self, max_frames: u32) -> anyhow::Result<ProcessorSnapshotResult> {
        ensure!(
            max_frames > 0,
            "DbgEng processor snapshots require at least one stack frame"
        );
        let logical_processor_count = unsafe { self.control.GetNumberProcessors()? };
        let mut processors = Vec::with_capacity(logical_processor_count as usize);
        let original_thread_id = unsafe { self.system_objects.GetCurrentThreadId()? };
        let mut current_thread_preserved = true;

        for processor_index in 0..logical_processor_count {
            if !current_thread_preserved {
                processors.push(ProcessorSnapshot {
                    processor_index,
                    status: "not_attempted".to_string(),
                    engine_thread_id: None,
                    system_thread_id: None,
                    thread_data_offset: None,
                    registers: None,
                    current_module: None,
                    current_symbol: None,
                    stack: None,
                    detail: Some(
                        "The snapshot stopped selecting threads after DbgEng did not preserve the original current thread."
                            .to_string(),
                    ),
                });
                continue;
            }
            let engine_thread_id = match unsafe {
                self.system_objects.GetThreadIdByProcessor(processor_index)
            } {
                Ok(id) => id,
                Err(error) => {
                    processors.push(ProcessorSnapshot {
                            processor_index,
                            status: "unavailable".to_string(),
                            engine_thread_id: None,
                            system_thread_id: None,
                            thread_data_offset: None,
                            registers: None,
                            current_module: None,
                            current_symbol: None,
                            stack: None,
                            detail: Some(format!(
                                "DbgEng did not expose an active thread for logical processor {processor_index}: {error}"
                            )),
                        });
                    continue;
                }
            };
            let snapshot = self.with_selected_thread(engine_thread_id, || {
                let registers = self.core_registers()?;
                let instruction_offset = registers.instruction_offset;
                let current_module =
                    instruction_offset.and_then(|address| self.module_by_offset(address).ok().flatten());
                let current_symbol =
                    instruction_offset.and_then(|address| self.symbol_by_offset(address).ok().flatten());
                let stack = self.stack_trace_result(max_frames)?;
                Ok(ProcessorSnapshot {
                    processor_index,
                    status: "captured".to_string(),
                    engine_thread_id: Some(engine_thread_id),
                    system_thread_id: self.current_thread_system_id().ok(),
                    thread_data_offset: unsafe {
                        self.system_objects.GetCurrentThreadDataOffset().ok()
                    },
                    registers: Some(registers),
                    current_module,
                    current_symbol,
                    stack: Some(stack),
                    detail: Some(
                        "The thread data offset is the documented DbgEng current-thread data offset. It is not decoded as a KTHREAD or PRCB layout."
                            .to_string(),
                    ),
                })
            });
            processors.push(match snapshot {
                Ok(snapshot) => snapshot,
                Err(error) => ProcessorSnapshot {
                    processor_index,
                    status: "unavailable".to_string(),
                    engine_thread_id: Some(engine_thread_id),
                    system_thread_id: None,
                    thread_data_offset: None,
                    registers: None,
                    current_module: None,
                    current_symbol: None,
                    stack: None,
                    detail: Some(format!(
                        "DbgEng could not capture the active-thread context for logical processor {processor_index}: {error:#}"
                    )),
                },
            });
            current_thread_preserved = unsafe {
                self.system_objects
                    .GetCurrentThreadId()
                    .map(|current| current == original_thread_id)
                    .unwrap_or(false)
            };
        }

        let unavailable = processors
            .iter()
            .filter(|processor| processor.status != "captured")
            .count();
        let nonempty_saved_stack_count = processors
            .iter()
            .filter_map(|processor| processor.stack.as_ref())
            .filter(|stack| stack.valid_frames > 0)
            .count();
        let unwind_limited_stack_count = processors
            .iter()
            .filter_map(|processor| processor.stack.as_ref())
            .filter(|stack| stack.valid_frames == 0)
            .count();
        Ok(ProcessorSnapshotResult {
            source: "dbgeng_idebugcontrol_getnumberprocessors_and_idebugsystemobjects_getthreadidbyprocessor"
                .to_string(),
            status: if processors.is_empty() || unavailable == processors.len() {
                "unavailable".to_string()
            } else if unavailable > 0 {
                "partial".to_string()
            } else {
                "captured".to_string()
            },
            logical_processor_count: Some(logical_processor_count),
            returned: processors.len(),
            nonempty_saved_stack_count,
            unwind_limited_stack_count,
            max_frames_per_processor: max_frames,
            processors,
            current_thread_preserved,
            detail: if current_thread_preserved {
                "Only DbgEng's exposed logical processor count was iterated. Each processor is associated with its active debugger thread by the documented GetThreadIdByProcessor API. The API does not establish that a saved bugcheck CONTEXT belongs to any particular processor. Any returned function name is DbgEng symbol resolution and is not itself proof of an identity-validated PDB.".to_string()
            } else {
                "The processor snapshot stopped selecting threads after its current-thread restoration check failed. Captured entries remain bounded observations, but the debugger's final thread selection was not preserved.".to_string()
            }
                .to_string(),
        })
    }

    pub fn thread_accounting_snapshot(
        &self,
        max_threads: u32,
    ) -> anyhow::Result<ThreadAccountingSnapshot> {
        use windows::core::Interface;
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            IDebugAdvanced2, DEBUG_SYSOBJINFO_THREAD_BASIC_INFORMATION,
            DEBUG_SYSOBJINFO_THREAD_NAME_WIDE, DEBUG_TBINFO_AFFINITY, DEBUG_TBINFO_EXIT_STATUS,
            DEBUG_TBINFO_PRIORITY, DEBUG_TBINFO_PRIORITY_CLASS, DEBUG_TBINFO_START_OFFSET,
            DEBUG_TBINFO_TIMES, DEBUG_THREAD_BASIC_INFORMATION,
        };

        ensure!(
            (1..=MAX_THREAD_ACCOUNTING_THREADS).contains(&max_threads),
            "DbgEng thread-accounting limit must be from 1 through {MAX_THREAD_ACCOUNTING_THREADS}"
        );
        let threads = self.threads()?;
        let total_threads = threads.len();
        let truncated = total_threads > max_threads as usize;
        let advanced: IDebugAdvanced2 = match self.client.cast() {
            Ok(advanced) => advanced,
            Err(error) => {
                return Ok(ThreadAccountingSnapshot {
                    source: "dbgeng_iddebugadvanced2_getsystemobjectinformation".to_string(),
                    status: "unavailable".to_string(),
                    counter_units: "100ns".to_string(),
                    total_threads: Some(total_threads),
                    threads: Vec::new(),
                    returned: 0,
                    limit: max_threads,
                    truncated,
                    detail: format!(
                        "DbgEng did not expose IDebugAdvanced2 for thread accounting: {error}"
                    ),
                });
            }
        };

        const MAX_THREAD_NAME_CHARS: usize = 128;
        let mut entries = Vec::with_capacity(total_threads.min(max_threads as usize));
        for thread in threads.into_iter().take(max_threads as usize) {
            let mut basic = DEBUG_THREAD_BASIC_INFORMATION::default();
            let mut basic_information_size_bytes = 0u32;
            let basic_result = unsafe {
                advanced.GetSystemObjectInformation(
                    DEBUG_SYSOBJINFO_THREAD_BASIC_INFORMATION,
                    0,
                    thread.engine_id,
                    Some((&mut basic as *mut DEBUG_THREAD_BASIC_INFORMATION).cast()),
                    std::mem::size_of::<DEBUG_THREAD_BASIC_INFORMATION>() as u32,
                    Some(&mut basic_information_size_bytes),
                )
            };

            let mut name_buffer = vec![0u16; MAX_THREAD_NAME_CHARS];
            let mut name_size_bytes = 0u32;
            let name_result = unsafe {
                advanced.GetSystemObjectInformation(
                    DEBUG_SYSOBJINFO_THREAD_NAME_WIDE,
                    0,
                    thread.engine_id,
                    Some(name_buffer.as_mut_ptr().cast()),
                    (name_buffer.len() * std::mem::size_of::<u16>()) as u32,
                    Some(&mut name_size_bytes),
                )
            };
            let basic_captured = basic_result.is_ok();
            let name_captured = name_result.is_ok();

            let mut errors = Vec::new();
            let basic_information_status = match &basic_result {
                Ok(()) => "captured".to_string(),
                Err(error) => {
                    errors.push(format!("basic_information: {error}"));
                    "unavailable".to_string()
                }
            };
            let (name_status, name) = match &name_result {
                Ok(()) => {
                    let capacity_bytes = (name_buffer.len() * std::mem::size_of::<u16>()) as u32;
                    let used_chars = if name_size_bytes == 0 {
                        name_buffer
                            .iter()
                            .position(|character| *character == 0)
                            .unwrap_or(name_buffer.len())
                    } else {
                        (name_size_bytes as usize / std::mem::size_of::<u16>())
                            .min(name_buffer.len())
                    };
                    let name_slice = &name_buffer[..used_chars];
                    let name_len = name_slice
                        .iter()
                        .position(|character| *character == 0)
                        .unwrap_or(name_slice.len());
                    let name = String::from_utf16_lossy(&name_slice[..name_len]);
                    (
                        if name_size_bytes > capacity_bytes {
                            "truncated".to_string()
                        } else if name.is_empty() {
                            "not_provided".to_string()
                        } else {
                            "captured".to_string()
                        },
                        (!name.is_empty()).then_some(name),
                    )
                }
                Err(error) => {
                    errors.push(format!("thread_name: {error}"));
                    ("unavailable".to_string(), None)
                }
            };
            let valid = basic.Valid;
            let has = |flag| basic_captured && valid & flag != 0;
            entries.push(ThreadAccountingEntry {
                thread,
                basic_information_status,
                basic_information_size_bytes: basic_captured
                    .then_some(basic_information_size_bytes),
                name_status,
                name,
                name_size_bytes: name_captured.then_some(name_size_bytes),
                valid_mask: basic_captured.then_some(valid),
                exit_status: has(DEBUG_TBINFO_EXIT_STATUS).then_some(basic.ExitStatus),
                priority_class: has(DEBUG_TBINFO_PRIORITY_CLASS).then_some(basic.PriorityClass),
                priority: has(DEBUG_TBINFO_PRIORITY).then_some(basic.Priority),
                create_time_raw: has(DEBUG_TBINFO_TIMES).then_some(basic.CreateTime),
                exit_time_raw: has(DEBUG_TBINFO_TIMES).then_some(basic.ExitTime),
                kernel_time_raw: has(DEBUG_TBINFO_TIMES).then_some(basic.KernelTime),
                user_time_raw: has(DEBUG_TBINFO_TIMES).then_some(basic.UserTime),
                kernel_time_ms: has(DEBUG_TBINFO_TIMES)
                    .then_some(basic.KernelTime as f64 / 10_000.0),
                user_time_ms: has(DEBUG_TBINFO_TIMES).then_some(basic.UserTime as f64 / 10_000.0),
                start_offset: has(DEBUG_TBINFO_START_OFFSET).then_some(basic.StartOffset),
                affinity: has(DEBUG_TBINFO_AFFINITY).then_some(basic.Affinity),
                errors,
            });
        }
        let unavailable_entries = entries
            .iter()
            .filter(|entry| entry.basic_information_status != "captured")
            .count();
        let status = if entries.is_empty() || unavailable_entries == entries.len() {
            "unavailable"
        } else if unavailable_entries > 0 || truncated {
            "partial"
        } else {
            "captured"
        };
        Ok(ThreadAccountingSnapshot {
            source: "dbgeng_iddebugadvanced2_getsystemobjectinformation".to_string(),
            status: status.to_string(),
            counter_units: "100ns".to_string(),
            total_threads: Some(total_threads),
            returned: entries.len(),
            threads: entries,
            limit: max_threads,
            truncated,
            detail: "Per-thread fields are returned only when their DEBUG_THREAD_BASIC_INFORMATION valid-mask bit is set. KernelTime and UserTime use 100 ns DbgEng counters; their millisecond projections were fixture-validated against a bounded CPU-burn run. They remain per-thread accounting samples, not lifecycle-gap causality.".to_string(),
        })
    }

    pub fn modules(&self) -> anyhow::Result<Vec<ModuleInfo>> {
        let mut loaded = 0u32;
        let mut unloaded = 0u32;
        unsafe {
            self.symbols.GetNumberModules(&mut loaded, &mut unloaded)?;
        }
        self.modules_by_loaded_count(loaded)
    }

    pub fn modules_bounded(&self, max_modules: u32) -> anyhow::Result<Vec<ModuleInfo>> {
        ensure!(
            max_modules > 0 && max_modules <= MAX_BOUNDED_MODULE_ENUMERATION,
            "DbgEng bounded module enumeration limit must be from one through {MAX_BOUNDED_MODULE_ENUMERATION}"
        );
        let mut loaded = 0u32;
        let mut unloaded = 0u32;
        unsafe {
            self.symbols.GetNumberModules(&mut loaded, &mut unloaded)?;
        }
        ensure!(
            loaded <= max_modules,
            "DbgEng target exposes {loaded} loaded modules, exceeding the bounded enumeration limit of {max_modules}"
        );
        self.modules_by_loaded_count(loaded)
    }

    fn modules_by_loaded_count(&self, loaded: u32) -> anyhow::Result<Vec<ModuleInfo>> {
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

    pub fn module_parameters(
        &self,
        base_addresses: &[u64],
    ) -> anyhow::Result<Vec<ModuleDebugParameters>> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_MODULE_PARAMETERS;

        ensure!(
            !base_addresses.is_empty(),
            "DbgEng module-parameter query requires at least one observed module base address"
        );
        ensure!(
            base_addresses.len() <= MAX_MODULE_PARAMETER_QUERIES,
            "DbgEng module-parameter query supports at most {MAX_MODULE_PARAMETER_QUERIES} module base addresses"
        );
        let mut parameters = vec![DEBUG_MODULE_PARAMETERS::default(); base_addresses.len()];
        unsafe {
            self.symbols.GetModuleParameters(
                base_addresses.len() as u32,
                Some(base_addresses.as_ptr()),
                0,
                parameters.as_mut_ptr(),
            )?;
        }
        Ok(parameters
            .into_iter()
            .map(|parameters| ModuleDebugParameters {
                base_address: parameters.Base,
                image_size: parameters.Size,
                time_date_stamp: parameters.TimeDateStamp,
                checksum: parameters.Checksum,
                flags: parameters.Flags,
                symbol_type: parameters.SymbolType,
                symbol_type_name: dbgeng_symbol_type_name(parameters.SymbolType).to_string(),
                image_name_size: parameters.ImageNameSize,
                module_name_size: parameters.ModuleNameSize,
                loaded_image_name_size: parameters.LoadedImageNameSize,
                symbol_file_name_size: parameters.SymbolFileNameSize,
                mapped_image_name_size: parameters.MappedImageNameSize,
            })
            .collect())
    }

    pub fn refresh_symbols(&self, module_name: &str) -> anyhow::Result<()> {
        ensure!(
            !module_name.is_empty()
                && module_name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "symbol refresh module name must be a non-empty basename"
        );
        self.execute_command(&format!(".reload /f {module_name}"))
    }

    pub fn configure_local_symbol_paths(
        &self,
        symbol_directories: &[PathBuf],
        image_directories: &[PathBuf],
    ) -> anyhow::Result<()> {
        use windows::core::PCWSTR;

        for path in symbol_directories {
            ensure!(
                !path.to_string_lossy().to_ascii_lowercase().contains("srv*"),
                "DbgEng local symbol paths must not contain a symbol-server expression"
            );
        }
        let symbol_path = symbol_directories
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(";");
        let image_path = image_directories
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(";");
        let mut symbol_path_wide = symbol_path.encode_utf16().collect::<Vec<_>>();
        symbol_path_wide.push(0);
        let mut image_path_wide = image_path.encode_utf16().collect::<Vec<_>>();
        image_path_wide.push(0);
        unsafe {
            self.symbols
                .SetSymbolPathWide(PCWSTR(symbol_path_wide.as_ptr()))
                .context("setting DbgEng local symbol path")?;
            self.symbols
                .SetImagePathWide(PCWSTR(image_path_wide.as_ptr()))
                .context("setting DbgEng local image path")?;
        }
        Ok(())
    }

    pub fn symbol_entry_range_by_offset(&self, address: u64) -> anyhow::Result<SymbolEntryRange> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::{
            DEBUG_MODULE_AND_ID, DEBUG_OFFSET_REGION, DEBUG_SYMBOL_ENTRY,
        };

        let mut id = DEBUG_MODULE_AND_ID::default();
        let mut displacement = 0u64;
        let mut entries = 0u32;
        unsafe {
            self.symbols.GetSymbolEntriesByOffset(
                address,
                0,
                Some(&mut id),
                Some(&mut displacement),
                1,
                Some(&mut entries),
            )?;
        }
        if entries == 0 {
            return Ok(SymbolEntryRange {
                source: "dbgeng_idebugsymbols5_symbol_entry".to_string(),
                status: "not_found".to_string(),
                address,
                symbol_module_base: None,
                symbol_offset: None,
                symbol_size: None,
                displacement: None,
                symbol_tag: None,
                symbol_flags: None,
                symbol_token: None,
                regions: Vec::new(),
                regions_available: Some(0),
                regions_truncated: false,
                detail: "DbgEng returned no symbol entry for the requested address.".to_string(),
            });
        }

        let mut entry = DEBUG_SYMBOL_ENTRY::default();
        unsafe {
            self.symbols.GetSymbolEntryInformation(&id, &mut entry)?;
        }
        let mut regions = vec![DEBUG_OFFSET_REGION::default(); MAX_SYMBOL_ENTRY_OFFSET_REGIONS];
        let mut regions_available = 0u32;
        unsafe {
            self.symbols.GetSymbolEntryOffsetRegions(
                &id,
                0,
                Some(regions.as_mut_slice()),
                Some(&mut regions_available),
            )?;
        }
        let returned = regions_available.min(MAX_SYMBOL_ENTRY_OFFSET_REGIONS as u32) as usize;
        regions.truncate(returned);
        Ok(SymbolEntryRange {
            source: "dbgeng_idebugsymbols5_symbol_entry".to_string(),
            status: "captured".to_string(),
            address,
            symbol_module_base: Some(entry.ModuleBase),
            symbol_offset: Some(entry.Offset),
            symbol_size: Some(entry.Size),
            displacement: Some(displacement),
            symbol_tag: Some(entry.Tag),
            symbol_flags: Some(entry.Flags),
            symbol_token: Some(entry.Token),
            regions: regions
                .into_iter()
                .map(|region| SymbolEntryOffsetRegion {
                    base_address: region.Base,
                    size: region.Size,
                })
                .collect(),
            regions_available: Some(regions_available),
            regions_truncated: regions_available > MAX_SYMBOL_ENTRY_OFFSET_REGIONS as u32,
            detail: "This is a bounded DbgEng symbol-entry offset-region query. It identifies debugger symbol coverage at an observed native address, but does not establish managed method execution. Symbol queries can trigger host-side symbol resolution I/O according to the configured symbol path.".to_string(),
        })
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
        Ok(self
            .stack_trace_from_offsets(frame_offset, stack_offset, instruction_offset, max_frames)?
            .frames)
    }

    pub fn stack_trace_result(&self, max_frames: u32) -> anyhow::Result<StackTraceResult> {
        let registers = self.core_registers()?;
        self.stack_trace_from_offsets(
            registers.frame_offset.unwrap_or(0),
            registers.stack_offset.unwrap_or(0),
            registers.instruction_offset.unwrap_or(0),
            max_frames,
        )
    }

    fn stack_trace_from_offsets(
        &self,
        frame_offset: u64,
        stack_offset: u64,
        instruction_offset: u64,
        max_frames: u32,
    ) -> anyhow::Result<StackTraceResult> {
        ensure!(
            max_frames > 0,
            "DbgEng stack walking requires at least one requested frame"
        );
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
        let frames = frames
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
            .collect::<Vec<_>>();
        let first_invalid = frames.iter().find(|frame| {
            frame.instruction_offset == 0
                || self
                    .module_by_offset(frame.instruction_offset)
                    .ok()
                    .flatten()
                    .is_none()
        });
        let valid_frames = match first_invalid {
            Some(frame) => frame.frame_number,
            None => frames.len() as u32,
        };
        let stop_reason = first_invalid.map(|frame| {
            format!(
                "frame {} has an instruction offset not mapped to a loaded module: 0x{:X}",
                frame.frame_number, frame.instruction_offset
            )
        });
        let status = if frames.is_empty() {
            "empty"
        } else if stop_reason.is_some() {
            "invalid_frame"
        } else if filled == max_frames {
            "frame_limit_reached"
        } else {
            "captured"
        };
        Ok(StackTraceResult {
            requested_frames: max_frames,
            returned_frames: filled,
            valid_frames,
            status: status.to_string(),
            stop_reason,
            frames,
        })
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

        self.with_selected_thread(engine_thread_id, || {
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
                thread_data_offset: unsafe {
                    self.system_objects.GetCurrentThreadDataOffset().ok()
                },
                registers,
                current_module,
                current_symbol,
                stack,
                disassembly,
                current_thread_preserved: true,
            })
        })
    }

    fn with_selected_thread<T>(
        &self,
        engine_thread_id: u32,
        inspect: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let previous_thread_id = unsafe { self.system_objects.GetCurrentThreadId()? };
        let changed_thread = previous_thread_id != engine_thread_id;
        if changed_thread {
            unsafe {
                self.system_objects.SetCurrentThreadId(engine_thread_id)?;
            }
        }

        let context = inspect();

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

    pub fn set_breakpoint_enabled(
        &self,
        breakpoint_id: u32,
        enabled: bool,
    ) -> anyhow::Result<BreakpointInfo> {
        use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_BREAKPOINT_ENABLED;

        let breakpoint = unsafe { self.control.GetBreakpointById2(breakpoint_id)? };
        unsafe {
            if enabled {
                breakpoint.AddFlags(DEBUG_BREAKPOINT_ENABLED)?;
            } else {
                breakpoint.RemoveFlags(DEBUG_BREAKPOINT_ENABLED)?;
            }
        }
        self.breakpoint_info(&breakpoint)
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
            runtime: inspect_dbgeng_runtime().unwrap_or(DbgEngRuntime {
                source: "unavailable".to_string(),
                directory: None,
                architecture: None,
                components: Vec::new(),
                compatible: false,
            }),
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

    pub fn step_over(&self) -> anyhow::Result<DebuggerExecutionStatus> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn continue_and_wait(
        &self,
        _timeout_ms: u32,
        _output_options: Option<DebuggerOutputCaptureOptions>,
    ) -> anyhow::Result<DebuggerRunResult> {
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

    pub fn dump_header(&self) -> DumpHeaderSnapshot {
        unavailable_dump_header("DbgEng sessions are only supported on Windows".to_string())
    }

    pub fn dump_debugger_data(&self, _max_frames: u32) -> DumpDebuggerData {
        DumpDebuggerData {
            status: "unavailable".to_string(),
            source: "dbgeng_idebugdataspaces3_readdebuggerdata".to_string(),
            saved_context_address: None,
            saved_context_status: "unavailable".to_string(),
            saved_context: None,
            ki_bugcheck_data_address: None,
            ki_bugcheck_data_status: "unavailable".to_string(),
            detail: "DbgEng sessions are only supported on Windows".to_string(),
        }
    }

    pub fn dump_event_inventory(&self) -> DumpEventInventory {
        DumpEventInventory {
            status: "unavailable".to_string(),
            source: "dbgeng_idebugcontrol3_event_inventory".to_string(),
            event_count: None,
            current_event_index: None,
            current_event_index_status: "unavailable".to_string(),
            detail: "DbgEng sessions are only supported on Windows".to_string(),
        }
    }

    pub fn target_exception_snapshot(&self, _max_frames: u32) -> TargetExceptionSnapshot {
        TargetExceptionSnapshot {
            status: "unavailable".to_string(),
            source: "dbgeng_idebugadvanced2_target_exception_requests".to_string(),
            contract: TargetExceptionContract {
                status: "unavailable".to_string(),
                source: "dbgeng_idebugcontrol_getdebuggeetype".to_string(),
                debuggee_class: None,
                debuggee_qualifier: None,
                detail: "DbgEng sessions are only supported on Windows".to_string(),
            },
            stored_event: StoredEventInformation {
                status: "unavailable".to_string(),
                source: "dbgeng_idebugcontrol4_get_stored_event_information".to_string(),
                event_type: None,
                process_system_id: None,
                thread_system_id: None,
                context: None,
                context_status: "unavailable".to_string(),
                extra_information_bytes_returned: None,
                extra_information_status: "not_returned".to_string(),
                detail: "DbgEng sessions are only supported on Windows".to_string(),
            },
            thread_system_id: None,
            thread_status: "unavailable".to_string(),
            record: None,
            record_status: "unavailable".to_string(),
            context: None,
            context_status: "unavailable".to_string(),
            detail: "DbgEng sessions are only supported on Windows".to_string(),
        }
    }

    pub fn read_memory(&self, _address: u64, _size: u32) -> anyhow::Result<MemoryReadResult> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn threads(&self) -> anyhow::Result<Vec<ThreadInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn processor_snapshot(&self, _max_frames: u32) -> anyhow::Result<ProcessorSnapshotResult> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn modules(&self) -> anyhow::Result<Vec<ModuleInfo>> {
        anyhow::bail!("DbgEng sessions are only supported on Windows")
    }

    pub fn modules_bounded(&self, _max_modules: u32) -> anyhow::Result<Vec<ModuleInfo>> {
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

    pub fn set_breakpoint_enabled(
        &self,
        _breakpoint_id: u32,
        _enabled: bool,
    ) -> anyhow::Result<BreakpointInfo> {
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
fn dbgeng_symbol_type_name(symbol_type: u32) -> &'static str {
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        DEBUG_SYMTYPE_CODEVIEW, DEBUG_SYMTYPE_COFF, DEBUG_SYMTYPE_DEFERRED, DEBUG_SYMTYPE_DIA,
        DEBUG_SYMTYPE_EXPORT, DEBUG_SYMTYPE_NONE, DEBUG_SYMTYPE_PDB, DEBUG_SYMTYPE_SYM,
    };

    match symbol_type {
        DEBUG_SYMTYPE_NONE => "none",
        DEBUG_SYMTYPE_COFF => "coff",
        DEBUG_SYMTYPE_CODEVIEW => "codeview",
        DEBUG_SYMTYPE_PDB => "pdb",
        DEBUG_SYMTYPE_EXPORT => "export",
        DEBUG_SYMTYPE_DEFERRED => "deferred",
        DEBUG_SYMTYPE_SYM => "sym",
        DEBUG_SYMTYPE_DIA => "dia",
        _ => "unknown",
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

    let runtime = inspect_dbgeng_runtime()?;
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
        runtime,
    })
}

#[cfg(windows)]
fn attach_live_session_impl(options: LiveAttachOptions) -> anyhow::Result<DebuggerSession> {
    use windows::core::Interface;
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters, IDebugSymbols5,
        IDebugSystemObjects, DEBUG_ATTACH_DEFAULT,
    };

    let runtime = inspect_dbgeng_runtime()?;
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
        runtime,
    })
}

#[cfg(windows)]
fn open_dump_session_impl(options: DumpOpenOptions) -> anyhow::Result<DebuggerSession> {
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::System::Diagnostics::Debug::Extensions::{
        IDebugClient5, IDebugControl5, IDebugDataSpaces4, IDebugRegisters, IDebugSymbols5,
        IDebugSystemObjects, DEBUG_WAIT_DEFAULT,
    };

    let runtime = inspect_dbgeng_runtime()?;
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
        runtime,
    })
}

#[cfg(windows)]
fn configure_dbgeng_symbol_path(
    symbols: &windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSymbols5,
) -> anyhow::Result<String> {
    use windows::core::PCWSTR;

    let symbol_config = resolve_dbgeng_symbol_path();
    ensure!(
        !symbol_config
            .symbol_path
            .to_ascii_lowercase()
            .contains("srv*"),
        "DbgEng symbol-server paths are disabled; use windbg-tool's Rust-native symbol prefetch instead"
    );
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

fn unavailable_dump_header_embedded_exception_context(
    detail: impl Into<String>,
) -> DumpHeaderEmbeddedExceptionContext {
    DumpHeaderEmbeddedExceptionContext {
        status: "unavailable".to_string(),
        provenance_category: "unavailable".to_string(),
        context_status: "unavailable".to_string(),
        exception_record_status: "unavailable".to_string(),
        context: None,
        exception_record: None,
        detail: detail.into(),
    }
}

fn dump_header_embedded_exception_context(
    bytes: &[u8],
    header_contract_valid: bool,
    machine_image_type: Option<u32>,
) -> DumpHeaderEmbeddedExceptionContext {
    if !header_contract_valid {
        return unavailable_dump_header_embedded_exception_context(
            "The DUMP_HEADER64 signature, valid-dump marker, or dump type was not validated, so its embedded ContextRecord and Exception bytes are withheld.",
        );
    }
    if machine_image_type != Some(0x8664) {
        return DumpHeaderEmbeddedExceptionContext {
            status: "architecture_unsupported".to_string(),
            provenance_category: "unavailable".to_string(),
            context_status: "architecture_unsupported".to_string(),
            exception_record_status: "architecture_unsupported".to_string(),
            context: None,
            exception_record: None,
            detail: "The documented DUMP_HEADER64 layout is present, but this inspector decodes its embedded ContextRecord and EXCEPTION_RECORD64 only for AMD64 targets.".to_string(),
        };
    }
    let Some(context_bytes) = bytes.get(
        DUMP_HEADER64_CONTEXT_RECORD_OFFSET
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + X64_CONTEXT_SIZE as usize,
    ) else {
        return unavailable_dump_header_embedded_exception_context(format!(
            "The validated DUMP_HEADER64 bytes do not include a complete AMD64 CONTEXT prefix at offset 0x{DUMP_HEADER64_CONTEXT_RECORD_OFFSET:X}."
        ));
    };
    let Some(exception_bytes) = bytes.get(
        DUMP_HEADER64_EXCEPTION_OFFSET..DUMP_HEADER64_EXCEPTION_OFFSET + EXCEPTION_RECORD64_SIZE,
    ) else {
        return unavailable_dump_header_embedded_exception_context(format!(
            "The validated DUMP_HEADER64 bytes do not include a complete EXCEPTION_RECORD64 at offset 0x{DUMP_HEADER64_EXCEPTION_OFFSET:X}."
        ));
    };
    let context = decode_x64_context_structural(None, context_bytes, X64_CONTEXT_SIZE, None);
    let context_status = context.status.clone();
    let exception_record = target_exception_record_from_bytes(exception_bytes);
    let exception_record_status = if exception_record.is_some() {
        "captured".to_string()
    } else {
        "invalid".to_string()
    };
    DumpHeaderEmbeddedExceptionContext {
        status: if context_status == "captured" && exception_record.is_some() {
            "captured".to_string()
        } else {
            "partial_or_invalid".to_string()
        },
        provenance_category: "direct_dbgeng_or_dump_field".to_string(),
        context_status,
        exception_record_status,
        context: Some(context),
        exception_record,
        detail: "DUMP_HEADER64 declares fixed ContextRecord and EXCEPTION_RECORD64 fields at validated offsets. They are direct dump-field observations, not a documented P3/P4 pointer relationship: Microsoft documents that KeInitializeCrashDumpHeader can create a header before memory is recorded and does not record active exception records. This inspector therefore never promotes these embedded fields to fault-time or P3/P4 linkage.".to_string(),
    }
}

fn unavailable_dump_header(detail: String) -> DumpHeaderSnapshot {
    DumpHeaderSnapshot {
        status: "unavailable".to_string(),
        source: "dbgeng_idebugadvanced2_debug_request_get_dump_header".to_string(),
        bytes_returned: 0,
        tail_status: "unavailable".to_string(),
        signature: None,
        valid_dump: None,
        major_version: None,
        minor_version: None,
        directory_table_base: None,
        pfn_database: None,
        loaded_module_list: None,
        active_process_head: None,
        machine_image_type: None,
        processor_count: None,
        bugcheck_code: None,
        bugcheck_parameters: None,
        embedded_exception_context: unavailable_dump_header_embedded_exception_context(
            "The dump header is unavailable, so its embedded ContextRecord and Exception fields cannot be inspected.",
        ),
        version_user: None,
        dump_type: None,
        dump_type_name: None,
        required_dump_space_bytes: None,
        system_time_filetime: None,
        system_uptime_100ns: None,
        comment: None,
        mini_dump_fields: None,
        secondary_data_state: None,
        product_type: None,
        suite_mask: None,
        writer_status: None,
        kd_secondary_version: None,
        attributes_raw: None,
        attributes: Vec::new(),
        boot_id: None,
        detail,
    }
}

fn dump_header_from_bytes(bytes: &[u8], bytes_returned: u32) -> DumpHeaderSnapshot {
    const HEADER_PREFIX_SIZE: usize = 0x1050;
    if bytes.len() < HEADER_PREFIX_SIZE {
        return unavailable_dump_header(format!(
            "DbgEng returned only {} bytes; the documented DUMP_HEADER64 fields through BootId require {HEADER_PREFIX_SIZE} bytes.",
            bytes.len()
        ));
    }
    let signature = read_u32_le(bytes, 0);
    let valid_dump = read_u32_le(bytes, 4);
    let machine_image_type = read_u32_le(bytes, 0x30);
    let dump_type = read_u32_le(bytes, 0xf94);
    let tail_valid = dump_type.and_then(dump_type_name).is_some();
    let header_contract_valid =
        tail_valid && signature == Some(0x4547_4150) && valid_dump == Some(0x3436_5544);
    let attributes_raw = tail_valid.then(|| read_u32_le(bytes, 0x1048)).flatten();
    DumpHeaderSnapshot {
        status: if tail_valid {
            "captured".to_string()
        } else {
            "captured_prefix_only".to_string()
        },
        source: "dbgeng_idebugadvanced2_debug_request_get_dump_header".to_string(),
        bytes_returned,
        tail_status: if tail_valid {
            "validated".to_string()
        } else {
            "unvalidated".to_string()
        },
        signature,
        valid_dump,
        major_version: read_u32_le(bytes, 8),
        minor_version: read_u32_le(bytes, 12),
        directory_table_base: read_u64_le(bytes, 0x10),
        pfn_database: read_u64_le(bytes, 0x18),
        loaded_module_list: read_u64_le(bytes, 0x20),
        active_process_head: read_u64_le(bytes, 0x28),
        machine_image_type,
        processor_count: read_u32_le(bytes, 0x34),
        bugcheck_code: read_u32_le(bytes, 0x38),
        bugcheck_parameters: [
            read_u64_le(bytes, 0x40),
            read_u64_le(bytes, 0x48),
            read_u64_le(bytes, 0x50),
            read_u64_le(bytes, 0x58),
        ]
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .and_then(|values| values.try_into().ok()),
        embedded_exception_context: dump_header_embedded_exception_context(
            bytes,
            header_contract_valid,
            machine_image_type,
        ),
        version_user: header_ascii(&bytes[0x60..0x80]),
        dump_type: tail_valid.then_some(dump_type).flatten(),
        dump_type_name: dump_type.and_then(dump_type_name).map(str::to_string),
        required_dump_space_bytes: tail_valid.then(|| read_u64_le(bytes, 0xf98)).flatten(),
        system_time_filetime: tail_valid.then(|| read_u64_le(bytes, 0xfa0)).flatten(),
        comment: tail_valid
            .then(|| header_ascii(&bytes[0xfa8..0x1028]))
            .flatten(),
        system_uptime_100ns: tail_valid.then(|| read_u64_le(bytes, 0x1028)).flatten(),
        mini_dump_fields: tail_valid.then(|| read_u32_le(bytes, 0x1030)).flatten(),
        secondary_data_state: tail_valid.then(|| read_u32_le(bytes, 0x1034)).flatten(),
        product_type: tail_valid.then(|| read_u32_le(bytes, 0x1038)).flatten(),
        suite_mask: tail_valid.then(|| read_u32_le(bytes, 0x103c)).flatten(),
        writer_status: tail_valid.then(|| read_u32_le(bytes, 0x1040)).flatten(),
        kd_secondary_version: tail_valid.then(|| bytes.get(0x1045).copied()).flatten(),
        attributes_raw,
        attributes: attributes_raw.map(dump_attribute_names).unwrap_or_default(),
        boot_id: tail_valid.then(|| read_u32_le(bytes, 0x104c)).flatten(),
        detail: if header_contract_valid {
            "The documented DUMP_HEADER64 bytes passed signature, valid-dump marker, and dump-type checks. SecondaryDataState is reported verbatim because the documented DbgEng request does not enumerate or define individual kernel blackbox stream identifiers or payload layouts.".to_string()
        } else {
            "DbgEng returned a header prefix whose signature and basic fields can be decoded, but the complete DUMP_HEADER64 contract did not pass signature, valid-dump marker, and dump-type validation. Embedded context/exception fields and tail fields are withheld rather than interpreting unvalidated bytes or assuming a dump-layout variant.".to_string()
        },
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(std::mem::size_of::<u32>())?)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(std::mem::size_of::<u64>())?)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
}

fn header_ascii(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = &bytes[..end];
    value
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        .then(|| String::from_utf8_lossy(value).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn dump_type_name(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("unknown"),
        1 => Some("full"),
        2 => Some("summary"),
        3 => Some("header"),
        4 => Some("triage"),
        5 => Some("bitmap_full"),
        6 => Some("bitmap_kernel"),
        7 => Some("automatic"),
        _ => None,
    }
}

fn dump_attribute_names(attributes: u32) -> Vec<String> {
    [
        (0, "hiber_crash"),
        (1, "dump_device_power_off"),
        (2, "insufficient_dumpfile_size"),
        (3, "kernel_generated_triage_dump"),
        (4, "live_dump_generated_dump"),
        (5, "generated_offline"),
        (6, "filter_dump_file"),
        (7, "early_boot_crash"),
        (8, "encrypted_dump_data"),
        (9, "decrypted_dump"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (attributes & (1 << bit) != 0).then_some(name.to_string()))
    .collect()
}

fn target_exception_record_from_bytes(bytes: &[u8]) -> Option<TargetExceptionRecord> {
    if bytes.len() < EXCEPTION_RECORD64_SIZE {
        return None;
    }
    let parameter_count = read_u32_le(bytes, 24)?;
    if parameter_count > 15 {
        return None;
    }
    let parameters = (0..parameter_count as usize)
        .map(|index| read_u64_le(bytes, 32 + index * std::mem::size_of::<u64>()))
        .collect::<Option<Vec<_>>>()?;
    let code = read_u32_le(bytes, 0)?;
    let access_violation = (code == 0xc000_0005 && parameters.len() >= 2).then(|| {
        let operation_raw = parameters[0];
        TargetAccessViolation {
            operation: match operation_raw {
                0 => "read",
                1 => "write",
                8 => "execute",
                _ => "unknown",
            }
            .to_string(),
            operation_raw,
            address: parameters[1],
        }
    });
    Some(TargetExceptionRecord {
        code,
        flags: read_u32_le(bytes, 4)?,
        previous_record: read_u64_le(bytes, 8)?,
        address: read_u64_le(bytes, 16)?,
        parameter_count,
        parameters,
        access_violation,
    })
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_runtime_directory(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!(
            "windbg-dbgeng-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    fn minimal_pe_image(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x100];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        bytes[0x88..0x8c].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0xc4..0xc6].copy_from_slice(&10_u16.to_le_bytes());
        bytes[0xc6..0xc8].copy_from_slice(&5_u16.to_le_bytes());
        bytes
    }

    fn write_runtime(directory: &Path, machine: u16) {
        fs::create_dir_all(directory).unwrap();
        for component in DBGENG_RUNTIME_COMPONENTS {
            fs::write(directory.join(component), minimal_pe_image(machine)).unwrap();
        }
    }

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
    fn x64_context_prefix_matches_the_documented_register_offset() {
        assert_eq!(std::mem::size_of::<X64ContextPrefix>(), 0x100);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, context_flags), 0x30);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, seg_cs), 0x38);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, seg_ss), 0x42);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, eflags), 0x44);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, rsp), 0x98);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, r8), 0xb8);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, r14), 0xe8);
        assert_eq!(std::mem::offset_of!(X64ContextPrefix, rip), 0xf8);
        assert_eq!(X64_CONTEXT_SIZE, 0x4D0);
        assert_eq!(CONTEXT_X64_REQUIRED_REGISTER_FLAGS, 0x0010_0003);
    }

    #[test]
    fn validates_serialized_amd64_context_offsets_independently() {
        let mut bytes = vec![0u8; X64_CONTEXT_SIZE as usize];
        bytes[0x30..0x34].copy_from_slice(&0x0010_001f_u32.to_le_bytes());
        bytes[0x38..0x3a].copy_from_slice(&0x10_u16.to_le_bytes());
        bytes[0x42..0x44].copy_from_slice(&0x18_u16.to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&0x202_u32.to_le_bytes());
        bytes[0x98..0xa0].copy_from_slice(&0xffff_f800_0000_1000_u64.to_le_bytes());
        bytes[0xb8..0xc0].copy_from_slice(&0xffff_8581_bd06_8cf0_u64.to_le_bytes());
        bytes[0xe8..0xf0].copy_from_slice(&0x20_u64.to_le_bytes());
        bytes[0xf8..0x100].copy_from_slice(&0xffff_f800_e439_70b0_u64.to_le_bytes());

        let context = x64_context_prefix_from_bytes(&bytes).unwrap();
        let validation = x64_context_validation(&context, &bytes, Some((0, 48)));

        assert_eq!(context.r8, 0xffff_8581_bd06_8cf0);
        assert_eq!(context.r14, 0x20);
        assert_eq!(context.rip, 0xffff_f800_e439_70b0);
        assert!(validation.raw_layout_offset_cross_check);
        assert!(validation.amd64_flag_present);
        assert!(validation.control_register_group_present);
        assert!(validation.integer_register_group_present);
        assert!(validation.cs_nonzero);
        assert!(validation.ss_nonzero);
        assert!(validation.eflags_reserved_bit_1_set);
        assert_eq!(validation.rsp_mod_16, 0);
        assert_eq!(
            validation.rip_canonical_for_selected_address_width,
            Some(true)
        );
        assert_eq!(
            validation.rsp_canonical_for_selected_address_width,
            Some(true)
        );
        assert!(!validation.control_registers_in_amd64_context);
    }

    #[test]
    fn decodes_documented_dump_header64_fields_at_fixed_offsets() {
        let mut bytes = vec![0u8; DUMP_HEADER64_SIZE];
        bytes[0..4].copy_from_slice(&0x4547_4150u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x3436_5544u32.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&0x8664u32.to_le_bytes());
        bytes[0x34..0x38].copy_from_slice(&24u32.to_le_bytes());
        bytes[0x38..0x3c].copy_from_slice(&0x1eu32.to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(&0xc000_0005u64.to_le_bytes());
        bytes[0x48..0x50].copy_from_slice(&0xffff_f800_e439_70b0u64.to_le_bytes());
        bytes[0x60..0x60 + 11].copy_from_slice(b"test build\0");
        bytes[0xf94..0xf98].copy_from_slice(&1u32.to_le_bytes());
        bytes[0xfa0..0xfa8].copy_from_slice(&123u64.to_le_bytes());
        bytes[0xfa8..0xfa8 + 14].copy_from_slice(b"captured dump\0");
        bytes[0x1028..0x1030].copy_from_slice(&456u64.to_le_bytes());
        bytes[0x1034..0x1038].copy_from_slice(&7u32.to_le_bytes());
        bytes[0x1048..0x104c].copy_from_slice(&((1u32 << 5) | (1 << 8)).to_le_bytes());
        bytes[0x104c..0x1050].copy_from_slice(&9u32.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x30
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x34]
            .copy_from_slice(&0x0010_001f_u32.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x38
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x3a]
            .copy_from_slice(&0x10_u16.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x42
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x44]
            .copy_from_slice(&0x18_u16.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x44
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x48]
            .copy_from_slice(&0x202_u32.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x98
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0xa0]
            .copy_from_slice(&0xffff_f800_0000_1000_u64.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0xb8
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0xc0]
            .copy_from_slice(&0x2000_u64.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0xe8
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0xf0]
            .copy_from_slice(&0x20_u64.to_le_bytes());
        bytes[DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0xf8
            ..DUMP_HEADER64_CONTEXT_RECORD_OFFSET + 0x100]
            .copy_from_slice(&0xffff_f800_e439_70b0_u64.to_le_bytes());
        bytes[DUMP_HEADER64_EXCEPTION_OFFSET..DUMP_HEADER64_EXCEPTION_OFFSET + 4]
            .copy_from_slice(&0xc000_0005u32.to_le_bytes());
        bytes[DUMP_HEADER64_EXCEPTION_OFFSET + 16..DUMP_HEADER64_EXCEPTION_OFFSET + 24]
            .copy_from_slice(&0xffff_f800_e439_70b0_u64.to_le_bytes());
        bytes[DUMP_HEADER64_EXCEPTION_OFFSET + 24..DUMP_HEADER64_EXCEPTION_OFFSET + 28]
            .copy_from_slice(&2u32.to_le_bytes());
        bytes[DUMP_HEADER64_EXCEPTION_OFFSET + 32..DUMP_HEADER64_EXCEPTION_OFFSET + 40]
            .copy_from_slice(&0u64.to_le_bytes());
        bytes[DUMP_HEADER64_EXCEPTION_OFFSET + 40..DUMP_HEADER64_EXCEPTION_OFFSET + 48]
            .copy_from_slice(&0x2020_u64.to_le_bytes());

        let header = dump_header_from_bytes(&bytes, DUMP_HEADER64_SIZE as u32);

        assert_eq!(header.status, "captured");
        assert_eq!(header.processor_count, Some(24));
        assert_eq!(header.bugcheck_code, Some(0x1e));
        assert_eq!(
            header.bugcheck_parameters,
            Some([0xc000_0005, 0xffff_f800_e439_70b0, 0, 0])
        );
        assert_eq!(header.version_user.as_deref(), Some("test build"));
        assert_eq!(header.dump_type_name.as_deref(), Some("full"));
        assert_eq!(header.system_time_filetime, Some(123));
        assert_eq!(header.system_uptime_100ns, Some(456));
        assert_eq!(header.comment.as_deref(), Some("captured dump"));
        assert_eq!(header.secondary_data_state, Some(7));
        assert_eq!(
            header.attributes,
            vec!["generated_offline", "encrypted_dump_data"]
        );
        assert_eq!(header.boot_id, Some(9));
        assert_eq!(header.embedded_exception_context.status, "captured");
        assert_eq!(
            header.embedded_exception_context.provenance_category,
            "direct_dbgeng_or_dump_field"
        );
        assert_eq!(
            header
                .embedded_exception_context
                .context
                .as_ref()
                .and_then(|context| context.registers.as_ref())
                .map(|registers| registers.rip),
            Some(0xffff_f800_e439_70b0)
        );
        assert_eq!(
            header
                .embedded_exception_context
                .exception_record
                .as_ref()
                .and_then(|record| record.access_violation.as_ref())
                .map(|access| access.address),
            Some(0x2020)
        );
    }

    #[test]
    fn decodes_documented_access_violation_record_without_guessing_operation() {
        let mut bytes = [0u8; EXCEPTION_RECORD64_SIZE];
        bytes[0..4].copy_from_slice(&0xc000_0005u32.to_le_bytes());
        bytes[16..24].copy_from_slice(&0xffff_f800_e439_70b0u64.to_le_bytes());
        bytes[24..28].copy_from_slice(&2u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&1u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&0xffff_8581_bd06_8d10u64.to_le_bytes());

        let record = target_exception_record_from_bytes(&bytes).unwrap();

        assert_eq!(record.parameter_count, 2);
        assert_eq!(record.access_violation.as_ref().unwrap().operation, "write");
        assert_eq!(
            record.access_violation.as_ref().unwrap().address,
            0xffff_8581_bd06_8d10
        );
        bytes[32..40].copy_from_slice(&7u64.to_le_bytes());
        assert_eq!(
            target_exception_record_from_bytes(&bytes)
                .unwrap()
                .access_violation
                .unwrap()
                .operation,
            "unknown"
        );
    }

    #[test]
    fn withholds_unvalidated_dump_header_tail() {
        let mut bytes = vec![0u8; DUMP_HEADER64_SIZE];
        bytes[0xf94..0xf98].copy_from_slice(&0x4547_4150u32.to_le_bytes());
        bytes[0x1034..0x1038].copy_from_slice(&7u32.to_le_bytes());

        let header = dump_header_from_bytes(&bytes, DUMP_HEADER64_SIZE as u32);

        assert_eq!(header.status, "captured_prefix_only");
        assert_eq!(header.tail_status, "unvalidated");
        assert_eq!(header.dump_type, None);
        assert_eq!(header.secondary_data_state, None);
        assert_eq!(header.embedded_exception_context.status, "unavailable");
    }

    #[test]
    fn standard_symbol_environment_preserves_windows_search_order() {
        let environment = StandardSymbolEnvironment::from_values(
            Some("C:\\primary-symbols".to_string()),
            Some("C:\\alternate-symbols".to_string()),
            Some(PathBuf::from("C:\\symbol-cache")),
        );

        assert_eq!(
            environment.symbol_path.as_deref(),
            Some("C:\\primary-symbols;C:\\alternate-symbols")
        );
        assert_eq!(
            environment.symcache_dir,
            Some(PathBuf::from("C:\\symbol-cache"))
        );
    }

    #[test]
    fn dbgeng_symbol_path_does_not_add_a_symbol_server() {
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
            "C:\\private-symbols;C:\\alternate-symbols"
        );
        assert_eq!(resolved.symbol_cache_dir, PathBuf::from("C:\\symbol-cache"));
    }

    #[test]
    fn dbgeng_symbol_path_preserves_explicit_caller_configuration() {
        let resolved = resolve_dbgeng_symbol_path_with_environment(
            StandardSymbolEnvironment::from_values(
                Some("C:\\caller-symbols".to_string()),
                None,
                Some(PathBuf::from("C:\\unused-cache")),
            ),
            Path::new("unused-cache"),
        );

        assert_eq!(resolved.symbol_path, "C:\\caller-symbols");
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

    #[test]
    fn explicit_dbgeng_runtime_overrides_an_adjacent_runtime() {
        let root = temporary_runtime_directory("selection");
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

    #[test]
    fn inspects_a_complete_matching_staged_runtime() {
        let directory = temporary_runtime_directory("valid");
        write_runtime(&directory, 0x8664);
        let selected = SelectedDbgEngRuntime {
            source: DbgEngRuntimeSource::ExplicitDirectory,
            dbgeng_dll: Some(directory.join(DBGENG_DLL_NAME)),
        };

        let runtime = inspect_selected_dbgeng_runtime(&selected).unwrap();

        let _ = fs::remove_dir_all(&directory);
        assert!(runtime.compatible);
        assert_eq!(runtime.architecture.as_deref(), Some("x64"));
        assert_eq!(runtime.components.len(), DBGENG_RUNTIME_COMPONENTS.len());
        assert!(runtime
            .components
            .iter()
            .all(|component| component.image_version == "10.5"));
    }

    #[test]
    fn rejects_a_runtime_missing_a_required_component() {
        let directory = temporary_runtime_directory("missing");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(DBGENG_DLL_NAME), minimal_pe_image(0x8664)).unwrap();
        let selected = SelectedDbgEngRuntime {
            source: DbgEngRuntimeSource::ExplicitDirectory,
            dbgeng_dll: Some(directory.join(DBGENG_DLL_NAME)),
        };

        let error = inspect_selected_dbgeng_runtime(&selected).unwrap_err();

        let _ = fs::remove_dir_all(&directory);
        assert!(error.to_string().contains("missing required component"));
    }

    #[test]
    fn rejects_a_malformed_runtime_component() {
        let directory = temporary_runtime_directory("malformed");
        write_runtime(&directory, 0x8664);
        fs::write(directory.join("dbghelp.dll"), b"not a PE").unwrap();
        let selected = SelectedDbgEngRuntime {
            source: DbgEngRuntimeSource::ExplicitDirectory,
            dbgeng_dll: Some(directory.join(DBGENG_DLL_NAME)),
        };

        let error = inspect_selected_dbgeng_runtime(&selected).unwrap_err();

        let _ = fs::remove_dir_all(&directory);
        assert!(error.to_string().contains("not a PE image"));
    }

    #[test]
    fn rejects_a_runtime_with_mixed_component_architectures() {
        let directory = temporary_runtime_directory("mixed-architecture");
        write_runtime(&directory, 0x8664);
        fs::write(directory.join("dbgmodel.dll"), minimal_pe_image(0x014c)).unwrap();
        let selected = SelectedDbgEngRuntime {
            source: DbgEngRuntimeSource::ExplicitDirectory,
            dbgeng_dll: Some(directory.join(DBGENG_DLL_NAME)),
        };

        let error = inspect_selected_dbgeng_runtime(&selected).unwrap_err();

        let _ = fs::remove_dir_all(&directory);
        assert!(error.to_string().contains("mixes component architectures"));
    }

    #[test]
    fn reports_system_runtime_without_staged_component_claims() {
        let selected = SelectedDbgEngRuntime {
            source: DbgEngRuntimeSource::System,
            dbgeng_dll: None,
        };

        let runtime = inspect_selected_dbgeng_runtime(&selected).unwrap();

        assert_eq!(runtime.source, "system_runtime");
        assert!(runtime.compatible);
        assert!(runtime.directory.is_none());
        assert!(runtime.components.is_empty());
    }

    #[test]
    fn validates_48_and_57_bit_canonical_addresses() {
        assert!(x64_virtual_address_is_canonical(0x0000_7fff_ffff_ffff, 48));
        assert!(x64_virtual_address_is_canonical(0xffff_8000_0000_0000, 48));
        assert!(!x64_virtual_address_is_canonical(0x0000_8000_0000_0000, 48));
        assert!(x64_virtual_address_is_canonical(0x00ff_ffff_ffff_ffff, 57));
        assert!(!x64_virtual_address_is_canonical(0x0100_0000_0000_0000, 57));
    }

    #[test]
    fn decodes_x64_page_table_entry_flags() {
        let entry = x64_page_table_entry("PTE", 42, 0x1_000, 0x8000_0000_1234_51e7);
        assert!(entry.present);
        assert!(entry.writable);
        assert!(entry.user_accessible);
        assert!(entry.accessed);
        assert_eq!(entry.dirty, Some(true));
        assert!(!entry.large_page);
        assert_eq!(entry.global, Some(true));
        assert!(entry.no_execute);
        assert_eq!(entry.page_frame_number, 0x12345);
    }

    #[test]
    fn large_page_address_masks_nx_and_page_offset_bits() {
        let address = 0xffff_8000_1234_5678;
        let raw_2mib_pde = 0x8000_0000_1234_5083;
        let raw_1gib_pdpte = 0x8000_0000_4000_0083;

        assert_eq!(
            x64_large_page_physical_address(raw_2mib_pde, address, 1 << 21),
            0x1220_0000 + (address & ((1 << 21) - 1))
        );
        assert_eq!(
            x64_large_page_physical_address(raw_1gib_pdpte, address, 1 << 30),
            0x4000_0000 + (address & ((1 << 30) - 1))
        );
    }

    #[test]
    fn reports_translation_match_and_mismatch_explicitly() {
        let mut walk = unavailable_x64_page_table_walk(0xffff_8000_0000_1000, "test".to_string());
        walk.final_mapping = Some(X64PageTableMapping {
            physical_address: 0x1234_5000,
            page_size: 4096,
            page_size_name: "4_kib".to_string(),
        });
        let offsets = VirtualTranslationPhysicalOffsets {
            status: "captured".to_string(),
            reported_level_count: Some(4),
            physical_offsets: vec![0x1000, 0x2000, 0x3000, 0x1234_5000],
            last_physical_offset: Some(0x1234_5000),
            final_physical_address: Some(0x1234_5000),
            final_physical_address_validation: "test".to_string(),
            detail: "test".to_string(),
        };

        let matched = virtual_address_translation_cross_check(Some(0x1234_5000), &offsets, &walk);
        assert_eq!(matched.status, "matched");
        assert_eq!(
            matched.virtual_to_physical_matches_page_table_walk,
            Some(true)
        );
        assert_eq!(
            matched.translation_physical_offsets_matches_page_table_walk,
            Some(true)
        );

        let mismatched =
            virtual_address_translation_cross_check(Some(0x1234_6000), &offsets, &walk);
        assert_eq!(mismatched.status, "mismatch");
        assert_eq!(
            mismatched.virtual_to_physical_matches_page_table_walk,
            Some(false)
        );
        assert_eq!(
            mismatched.virtual_to_physical_matches_translation_physical_offsets,
            Some(false)
        );
    }

    #[test]
    fn does_not_promote_an_unvalidated_translation_hierarchy_offset() {
        let walk = unavailable_x64_page_table_walk(0xffff_ffff_ffff_ffff, "test".to_string());
        let mut offsets = VirtualTranslationPhysicalOffsets {
            status: "captured".to_string(),
            reported_level_count: Some(5),
            physical_offsets: vec![0x1000, 0x1ff8, 0x2ff8, 0x3ff8, 0x4ff8],
            last_physical_offset: Some(0x4ff8),
            final_physical_address: None,
            final_physical_address_validation: "unvalidated_raw_hierarchy_offset".to_string(),
            detail: "test".to_string(),
        };

        validate_translation_physical_offsets(&mut offsets, None, &walk);

        assert_eq!(offsets.final_physical_address, None);
        assert_eq!(
            offsets.final_physical_address_validation,
            "unvalidated_raw_hierarchy_offset"
        );
    }
}
