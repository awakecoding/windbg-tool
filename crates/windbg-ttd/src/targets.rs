use anyhow::{bail, ensure, Context};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use windbg_dbgeng::{
    attach_live_session, launch_live_session, open_dump_session, BreakpointInfo, CoreRegisterState,
    DebuggerEventInfo, DebuggerExecutionStatus, DebuggerSession, DebuggerSessionKind,
    DebuggerSessionSummary, DisassemblyResult, DumpKind, DumpOpenOptions, DumpWriteOptions,
    DumpWriteResult, EvaluationResult, LiveAttachOptions, LiveInitialStop,
    LiveLaunchSessionOptions, MemoryReadResult, ModuleDebugParameters, ModuleInfo, SourceLocation,
    StackFrameInfo, SymbolEntryRange, SymbolInfo, ThreadAccountingSnapshot, ThreadContext,
    ThreadInfo, VirtualMemoryMap, MAX_MODULE_PARAMETER_QUERIES, MAX_THREAD_ACCOUNTING_THREADS,
    MAX_VIRTUAL_MEMORY_MAP_REGIONS,
};
use windbg_symbols::{
    image_matches, inspect_pe_image_identity, prefetch_image, prefetch_pdb, NativeImageStatus,
    NativeSymbolStatus, PeImageIdentity,
};

pub type TargetId = u64;

#[derive(Default)]
pub struct TargetRegistry {
    next_target_id: TargetId,
    targets: HashMap<TargetId, ManagedTarget>,
}

struct ManagedTarget {
    session: DebuggerSession,
    native_symbols: Value,
    native_symbol_options: Option<NativeSymbolOptions>,
}

#[derive(Clone)]
struct NativeSymbolOptions {
    cache_dir: PathBuf,
    image_paths: Vec<PathBuf>,
    offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LiveLaunchRequest {
    pub command_line: String,
    #[serde(default = "default_live_wait_timeout_ms")]
    pub initial_break_timeout_ms: u32,
    #[serde(default)]
    pub create_process_stop: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LiveAttachRequest {
    pub process_id: u32,
    #[serde(default = "default_live_wait_timeout_ms")]
    pub initial_break_timeout_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DumpOpenRequest {
    pub path: PathBuf,
    #[serde(default = "default_native_symbol_cache")]
    pub symbol_cache: PathBuf,
    #[serde(default)]
    pub image_paths: Vec<PathBuf>,
    #[serde(default)]
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetRequest {
    pub target_id: TargetId,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetWaitRequest {
    pub target_id: TargetId,
    #[serde(default = "default_live_wait_timeout_ms")]
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetMemoryReadRequest {
    pub target_id: TargetId,
    pub address: u64,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetMemoryMapRequest {
    pub target_id: TargetId,
    #[serde(default = "default_target_memory_map_regions")]
    #[schemars(
        range(min = 1, max = 4096),
        description = "Maximum DbgEng virtual-memory regions returned; must be from 1 through 4096."
    )]
    pub region_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetThreadAccountingRequest {
    pub target_id: TargetId,
    #[serde(default = "default_target_thread_accounting_threads")]
    #[schemars(
        range(min = 1, max = 128),
        description = "Maximum DbgEng threads returned; must be from 1 through 128."
    )]
    pub max_threads: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetModuleParametersRequest {
    pub target_id: TargetId,
    #[schemars(
        length(min = 1, max = 128),
        description = "Distinct DbgEng-observed module base addresses; at most 128."
    )]
    pub module_base_addresses: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetAddressRequest {
    pub target_id: TargetId,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetStackTraceRequest {
    pub target_id: TargetId,
    #[serde(default = "default_target_stack_frames")]
    pub max_frames: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetThreadContextRequest {
    pub target_id: TargetId,
    #[schemars(description = "DbgEng engine thread id returned by target_list_threads")]
    pub engine_thread_id: u32,
    #[serde(default = "default_target_stack_frames")]
    pub max_frames: u32,
    #[serde(default = "default_target_disasm_count")]
    pub disassembly_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetDisassembleRequest {
    pub target_id: TargetId,
    pub address: Option<u64>,
    #[serde(default = "default_target_disasm_count")]
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetExpressionRequest {
    pub target_id: TargetId,
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetWriteDumpRequest {
    pub target_id: TargetId,
    pub path: PathBuf,
    #[serde(default)]
    pub kind: TargetDumpKind,
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetDumpKind {
    #[default]
    Mini,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetBreakpointKind {
    Code,
    Read,
    Write,
    Execute,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetBreakpointSetRequest {
    pub target_id: TargetId,
    pub address: u64,
    #[serde(default)]
    pub kind: Option<TargetBreakpointKind>,
    pub size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TargetBreakpointRemoveRequest {
    pub target_id: TargetId,
    pub breakpoint_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetOpenedResponse {
    pub target_id: TargetId,
    pub target: DebuggerSessionSummary,
    pub native_symbols: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSummary {
    pub target_id: TargetId,
    pub target: DebuggerSessionSummary,
    pub native_symbols: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetListResponse {
    pub targets: Vec<TargetSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetClosedResponse {
    pub target_id: TargetId,
    pub closed: bool,
    pub detached: bool,
    pub terminated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetThreadList {
    pub target_id: TargetId,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetRegisterState {
    pub target_id: TargetId,
    pub registers: CoreRegisterState,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetEventResponse {
    pub target_id: TargetId,
    pub event: DebuggerEventInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetThreadContextResponse {
    pub target_id: TargetId,
    pub context: ThreadContext,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetMemoryReadResponse {
    pub target_id: TargetId,
    pub memory: MemoryReadResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetMemoryMapResponse {
    pub target_id: TargetId,
    pub memory_map: VirtualMemoryMap,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetThreadAccountingResponse {
    pub target_id: TargetId,
    pub thread_accounting: ThreadAccountingSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetModuleParametersResponse {
    pub target_id: TargetId,
    pub source: String,
    pub parameters: Vec<ModuleDebugParameters>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSymbolEntryRangeResponse {
    pub target_id: TargetId,
    pub symbol_entry_range: SymbolEntryRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetModuleList {
    pub target_id: TargetId,
    pub modules: Vec<ModuleInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSymbolResponse {
    pub target_id: TargetId,
    pub symbol: Option<SymbolInfo>,
    pub native_symbols: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSourceResponse {
    pub target_id: TargetId,
    pub source: Option<SourceLocation>,
    pub native_symbols: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetStackTraceResponse {
    pub target_id: TargetId,
    pub frames: Vec<StackFrameInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetDisassemblyResponse {
    pub target_id: TargetId,
    pub disassembly: DisassemblyResult,
    pub native_symbols: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetBreakpointList {
    pub target_id: TargetId,
    pub breakpoints: Vec<BreakpointInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetBreakpointChangeResponse {
    pub target_id: TargetId,
    pub breakpoint: Option<BreakpointInfo>,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetEvaluationResponse {
    pub target_id: TargetId,
    pub evaluation: EvaluationResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetWriteDumpResponse {
    pub target_id: TargetId,
    pub dump: DumpWriteResult,
}

impl TargetRegistry {
    pub fn list_targets(&self) -> TargetListResponse {
        let mut targets = self
            .targets
            .iter()
            .map(|(target_id, target)| TargetSummary {
                target_id: *target_id,
                target: target.session.summary(),
                native_symbols: target.native_symbols.clone(),
            })
            .collect::<Vec<_>>();
        targets.sort_by_key(|target| target.target_id);
        TargetListResponse { targets }
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub fn live_target_count(&self) -> usize {
        self.targets
            .values()
            .filter(|target| target.session.kind() == DebuggerSessionKind::Live)
            .count()
    }

    pub fn dump_target_count(&self) -> usize {
        self.targets
            .values()
            .filter(|target| target.session.kind() == DebuggerSessionKind::Dump)
            .count()
    }

    pub fn launch_live(
        &mut self,
        request: LiveLaunchRequest,
    ) -> anyhow::Result<TargetOpenedResponse> {
        let session = launch_live_session(LiveLaunchSessionOptions {
            command_line: request.command_line,
            initial_break_timeout_ms: request.initial_break_timeout_ms,
            initial_stop: if request.create_process_stop {
                LiveInitialStop::CreateProcessEvent
            } else {
                LiveInitialStop::SoftwareBreakpoint
            },
        })?;
        Ok(self.insert_target(session, Value::Null, None))
    }

    pub fn attach_live(
        &mut self,
        request: LiveAttachRequest,
    ) -> anyhow::Result<TargetOpenedResponse> {
        let session = attach_live_session(LiveAttachOptions {
            process_id: request.process_id,
            initial_break_timeout_ms: request.initial_break_timeout_ms,
        })?;
        Ok(self.insert_target(session, Value::Null, None))
    }

    pub fn open_dump(&mut self, request: DumpOpenRequest) -> anyhow::Result<TargetOpenedResponse> {
        let session = open_dump_session(DumpOpenOptions { path: request.path })?;
        let native_symbol_options = NativeSymbolOptions {
            cache_dir: request.symbol_cache,
            image_paths: request.image_paths,
            offline: request.offline,
        };
        let native_symbols = prefetch_dump_symbols(
            &session,
            None,
            &native_symbol_options.cache_dir,
            &native_symbol_options.image_paths,
            native_symbol_options.offline,
        );
        Ok(self.insert_target(session, native_symbols, Some(native_symbol_options)))
    }

    pub fn target_status(&self, request: TargetRequest) -> anyhow::Result<TargetSummary> {
        let target = self.target(request.target_id)?;
        Ok(TargetSummary {
            target_id: request.target_id,
            target: target.session.summary(),
            native_symbols: target.native_symbols.clone(),
        })
    }

    pub fn close_target(&mut self, request: TargetRequest) -> anyhow::Result<TargetClosedResponse> {
        let target = self
            .targets
            .remove(&request.target_id)
            .with_context(|| format!("unknown target id: {}", request.target_id))?;
        let detached = matches!(target.session.kind(), DebuggerSessionKind::Live);
        if detached {
            target.session.detach()?;
        }
        Ok(TargetClosedResponse {
            target_id: request.target_id,
            closed: true,
            detached,
            terminated: false,
        })
    }

    pub fn terminate_target(
        &mut self,
        request: TargetRequest,
    ) -> anyhow::Result<TargetClosedResponse> {
        let target = self
            .targets
            .remove(&request.target_id)
            .with_context(|| format!("unknown target id: {}", request.target_id))?;
        if target.session.kind() != DebuggerSessionKind::Live {
            bail!("target {} is not a live session", request.target_id);
        }
        target.session.terminate()?;
        Ok(TargetClosedResponse {
            target_id: request.target_id,
            closed: true,
            detached: false,
            terminated: true,
        })
    }

    pub fn wait_for_event(
        &self,
        request: TargetWaitRequest,
    ) -> anyhow::Result<DebuggerExecutionStatus> {
        self.target(request.target_id)?
            .session
            .wait_for_event(request.timeout_ms)
    }

    pub fn continue_execution(
        &self,
        request: TargetRequest,
    ) -> anyhow::Result<DebuggerExecutionStatus> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        target.session.continue_execution()
    }

    pub fn step_into(&self, request: TargetRequest) -> anyhow::Result<DebuggerExecutionStatus> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        target.session.step_into()
    }

    pub fn core_registers(&self, request: TargetRequest) -> anyhow::Result<TargetRegisterState> {
        let target = self.target(request.target_id)?;
        Ok(TargetRegisterState {
            target_id: request.target_id,
            registers: target.session.core_registers()?,
        })
    }

    pub fn last_event(&self, request: TargetRequest) -> anyhow::Result<TargetEventResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        Ok(TargetEventResponse {
            target_id: request.target_id,
            event: target.session.last_event()?,
        })
    }

    pub fn read_memory(
        &self,
        request: TargetMemoryReadRequest,
    ) -> anyhow::Result<TargetMemoryReadResponse> {
        let target = self.target(request.target_id)?;
        Ok(TargetMemoryReadResponse {
            target_id: request.target_id,
            memory: target.session.read_memory(request.address, request.size)?,
        })
    }

    pub fn memory_map(
        &self,
        request: TargetMemoryMapRequest,
    ) -> anyhow::Result<TargetMemoryMapResponse> {
        validate_target_memory_map_region_limit(request.region_limit)?;
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        Ok(TargetMemoryMapResponse {
            target_id: request.target_id,
            memory_map: target.session.virtual_memory_map(request.region_limit)?,
        })
    }

    pub fn list_threads(&self, request: TargetRequest) -> anyhow::Result<TargetThreadList> {
        let target = self.target(request.target_id)?;
        Ok(TargetThreadList {
            target_id: request.target_id,
            threads: target.session.threads()?,
        })
    }

    pub fn thread_accounting(
        &self,
        request: TargetThreadAccountingRequest,
    ) -> anyhow::Result<TargetThreadAccountingResponse> {
        validate_target_thread_accounting_limit(request.max_threads)?;
        let target = self.target(request.target_id)?;
        Ok(TargetThreadAccountingResponse {
            target_id: request.target_id,
            thread_accounting: target
                .session
                .thread_accounting_snapshot(request.max_threads)?,
        })
    }

    pub fn module_parameters(
        &self,
        request: TargetModuleParametersRequest,
    ) -> anyhow::Result<TargetModuleParametersResponse> {
        validate_target_module_parameter_bases(&request.module_base_addresses)?;
        let target = self.target(request.target_id)?;
        Ok(TargetModuleParametersResponse {
            target_id: request.target_id,
            source: "dbgeng_idebugsymbols5_getmoduleparameters".to_string(),
            parameters: target.session.module_parameters(&request.module_base_addresses)?,
            detail: "This bounded DbgEng symbol-readiness query applies only to supplied module base addresses. Its result describes debugger module metadata, not target timing; configured symbol paths can cause host-side symbol-resolution I/O.".to_string(),
        })
    }

    pub fn symbol_entry_range(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetSymbolEntryRangeResponse> {
        let target = self.target(request.target_id)?;
        Ok(TargetSymbolEntryRangeResponse {
            target_id: request.target_id,
            symbol_entry_range: target
                .session
                .symbol_entry_range_by_offset(request.address)?,
        })
    }

    pub fn list_modules(&self, request: TargetRequest) -> anyhow::Result<TargetModuleList> {
        let target = self.target(request.target_id)?;
        Ok(TargetModuleList {
            target_id: request.target_id,
            modules: target.session.modules()?,
        })
    }

    pub fn symbol_by_offset(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetSymbolResponse> {
        let target = self.target(request.target_id)?;
        let native_symbols = prefetch_target_address(target, request.address);
        Ok(TargetSymbolResponse {
            target_id: request.target_id,
            symbol: target.session.symbol_by_offset(request.address)?,
            native_symbols,
        })
    }

    pub fn source_by_offset(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetSourceResponse> {
        let target = self.target(request.target_id)?;
        let native_symbols = prefetch_target_address(target, request.address);
        Ok(TargetSourceResponse {
            target_id: request.target_id,
            source: target.session.source_by_offset(request.address)?,
            native_symbols,
        })
    }

    pub fn stack_trace(
        &self,
        request: TargetStackTraceRequest,
    ) -> anyhow::Result<TargetStackTraceResponse> {
        let target = self.target(request.target_id)?;
        Ok(TargetStackTraceResponse {
            target_id: request.target_id,
            frames: target.session.stack_trace(request.max_frames)?,
        })
    }

    pub fn thread_context(
        &self,
        request: TargetThreadContextRequest,
    ) -> anyhow::Result<TargetThreadContextResponse> {
        let target = self.target(request.target_id)?;
        Ok(TargetThreadContextResponse {
            target_id: request.target_id,
            context: target.session.thread_context(
                request.engine_thread_id,
                request.max_frames,
                request.disassembly_count,
            )?,
        })
    }

    pub fn disassemble(
        &self,
        request: TargetDisassembleRequest,
    ) -> anyhow::Result<TargetDisassemblyResponse> {
        let target = self.target(request.target_id)?;
        let native_symbols = request
            .address
            .and_then(|address| prefetch_target_address(target, address));
        Ok(TargetDisassemblyResponse {
            target_id: request.target_id,
            disassembly: target.session.disassemble(request.address, request.count)?,
            native_symbols,
        })
    }

    pub fn list_breakpoints(&self, request: TargetRequest) -> anyhow::Result<TargetBreakpointList> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        Ok(TargetBreakpointList {
            target_id: request.target_id,
            breakpoints: target.session.list_breakpoints()?,
        })
    }

    pub fn set_breakpoint(
        &self,
        request: TargetBreakpointSetRequest,
    ) -> anyhow::Result<TargetBreakpointChangeResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        let kind = request.kind.unwrap_or(TargetBreakpointKind::Code);
        let breakpoint = match kind {
            TargetBreakpointKind::Code => target.session.add_code_breakpoint(request.address)?,
            TargetBreakpointKind::Read => target.session.add_data_breakpoint(
                request.address,
                request.size.unwrap_or(1),
                BREAK_READ,
            )?,
            TargetBreakpointKind::Write => target.session.add_data_breakpoint(
                request.address,
                request.size.unwrap_or(1),
                BREAK_WRITE,
            )?,
            TargetBreakpointKind::Execute => target.session.add_data_breakpoint(
                request.address,
                request.size.unwrap_or(1),
                BREAK_EXECUTE,
            )?,
            TargetBreakpointKind::ReadWrite => target.session.add_data_breakpoint(
                request.address,
                request.size.unwrap_or(1),
                BREAK_READ | BREAK_WRITE,
            )?,
        };
        Ok(TargetBreakpointChangeResponse {
            target_id: request.target_id,
            breakpoint: Some(breakpoint),
            removed: false,
        })
    }

    pub fn remove_breakpoint(
        &self,
        request: TargetBreakpointRemoveRequest,
    ) -> anyhow::Result<TargetBreakpointChangeResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        target.session.remove_breakpoint(request.breakpoint_id)?;
        Ok(TargetBreakpointChangeResponse {
            target_id: request.target_id,
            breakpoint: None,
            removed: true,
        })
    }

    pub fn evaluate(
        &self,
        request: TargetExpressionRequest,
    ) -> anyhow::Result<TargetEvaluationResponse> {
        let target = self.target(request.target_id)?;
        Ok(TargetEvaluationResponse {
            target_id: request.target_id,
            evaluation: target.session.evaluate(&request.expression)?,
        })
    }

    pub fn write_dump(
        &self,
        request: TargetWriteDumpRequest,
    ) -> anyhow::Result<TargetWriteDumpResponse> {
        let target = self.target(request.target_id)?;
        ensure_live_target(request.target_id, &target.session)?;
        Ok(TargetWriteDumpResponse {
            target_id: request.target_id,
            dump: target.session.write_dump(DumpWriteOptions {
                path: request.path,
                kind: request.kind.into(),
                overwrite: request.overwrite,
            })?,
        })
    }

    fn insert_target(
        &mut self,
        session: DebuggerSession,
        native_symbols: Value,
        native_symbol_options: Option<NativeSymbolOptions>,
    ) -> TargetOpenedResponse {
        let target_id = self.allocate_target_id();
        let target = session.summary();
        self.targets.insert(
            target_id,
            ManagedTarget {
                session,
                native_symbols: native_symbols.clone(),
                native_symbol_options,
            },
        );
        TargetOpenedResponse {
            target_id,
            target,
            native_symbols,
        }
    }

    fn allocate_target_id(&mut self) -> TargetId {
        self.next_target_id += 1;
        self.next_target_id
    }

    fn target(&self, target_id: TargetId) -> anyhow::Result<&ManagedTarget> {
        self.targets
            .get(&target_id)
            .with_context(|| format!("unknown target id: {target_id}"))
    }
}

fn default_live_wait_timeout_ms() -> u32 {
    5000
}

fn default_native_symbol_cache() -> PathBuf {
    PathBuf::from(".windbg-symbol-cache")
}

fn prefetch_target_address(target: &ManagedTarget, address: u64) -> Option<Value> {
    target.native_symbol_options.as_ref().map(|options| {
        prefetch_dump_symbols(
            &target.session,
            Some(address),
            &options.cache_dir,
            &options.image_paths,
            options.offline,
        )
    })
}

fn prefetch_dump_symbols(
    session: &DebuggerSession,
    address_override: Option<u64>,
    cache_dir: &PathBuf,
    extra_image_paths: &[PathBuf],
    offline: bool,
) -> Value {
    let fault_address = address_override.or_else(|| {
        session
            .bugcheck_data()
            .data
            .and_then(|data| (data.code == 0x0000_003B).then_some(data.parameters[1]))
            .or_else(|| {
                session
                    .core_registers()
                    .ok()
                    .and_then(|registers| registers.instruction_offset)
            })
    });
    let Some(fault_address) = fault_address else {
        return json!({
            "status": "not_applicable",
            "detail": "No supported dump fault module was available for native symbol prefetch.",
            "offline": offline,
            "cache_dir": cache_dir,
        });
    };
    let Some(module) = session.module_by_offset(fault_address).ok().flatten() else {
        return json!({"status": "unavailable", "detail": "DbgEng could not map the fault address to a module."});
    };
    let Some(parameters) = session
        .module_parameters(&[module.base_address])
        .ok()
        .and_then(|mut values| values.pop())
    else {
        return json!({"status": "unavailable", "module": module, "detail": "DbgEng did not provide module identity metadata."});
    };
    let mut roots = extra_image_paths.to_vec();
    if let Some(system_root) = env::var_os("SystemRoot").map(PathBuf::from) {
        roots.push(system_root.join("System32"));
        roots.push(system_root.join("System32").join("drivers"));
    }
    let mut deduplicated_roots = Vec::new();
    for root in roots {
        if !deduplicated_roots.contains(&root) {
            deduplicated_roots.push(root);
        }
    }
    let mut image_names = Vec::new();
    for name in [
        module.image_name.as_deref(),
        module.loaded_image_name.as_deref(),
        module.symbol_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let Some(file_name) = Path::new(name).file_name().map(|name| name.to_owned()) else {
            continue;
        };
        if !image_names.contains(&file_name) {
            image_names.push(file_name);
        }
    }
    let Some(image_name) = image_names.first().and_then(|name| name.to_str()) else {
        return json!({
            "status": "unavailable",
            "module": module,
            "module_parameters": parameters,
            "detail": "DbgEng did not provide a usable module image filename for native prefetch.",
            "offline": offline,
            "cache_dir": cache_dir,
        });
    };
    let expected_image = match PeImageIdentity::new(
        image_name,
        parameters.time_date_stamp,
        parameters.image_size,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            return json!({
                "status": "unavailable",
                "module": module,
                "module_parameters": parameters,
                "detail": format!("The dump module image identity was invalid: {error:#}"),
                "offline": offline,
                "cache_dir": cache_dir,
            });
        }
    };

    let mut rejected = Vec::new();
    let mut selected_image = None;
    for root in &deduplicated_roots {
        for name in &image_names {
            let image_path = root.join(name);
            if !image_path.is_file() {
                continue;
            }
            match image_matches(&image_path, &expected_image) {
                Ok(true) => {
                    selected_image = Some((
                        image_path,
                        json!({
                            "status": NativeImageStatus::Local,
                            "detail": "Used the caller-provided or host-local image after validating its timestamp and SizeOfImage."
                        }),
                    ));
                    break;
                }
                Ok(false) => match inspect_pe_image_identity(&image_path) {
                    Ok(identity) => rejected.push(json!({
                        "image_path": image_path,
                        "status": "mismatch",
                        "observed_timestamp": identity.image_timestamp,
                        "expected_timestamp": parameters.time_date_stamp,
                        "observed_image_size": identity.image_size,
                        "expected_image_size": parameters.image_size,
                    })),
                    Err(error) => rejected.push(json!({
                        "image_path": image_path,
                        "status": "unreadable",
                        "detail": format!("{error:#}"),
                    })),
                },
                Err(error) => rejected.push(json!({
                    "image_path": image_path,
                    "status": "unreadable",
                    "detail": format!("{error:#}"),
                })),
            }
        }
        if selected_image.is_some() {
            break;
        }
    }
    let (image_path, image_prefetch) = match selected_image {
        Some(selected) => selected,
        None => match prefetch_image(expected_image, cache_dir, offline) {
            Ok(image) => match image.image_path.clone() {
                Some(path) => (path, json!(image)),
                None => {
                    return json!({
                        "status": match image.status {
                            NativeImageStatus::OfflineMissing => "offline_image_missing",
                            NativeImageStatus::Unavailable => "unavailable",
                            _ => "image_not_found",
                        },
                        "module": module,
                        "module_parameters": parameters,
                        "image_prefetch": image,
                        "cache_dir": cache_dir,
                        "offline": offline,
                        "image_search_paths": deduplicated_roots,
                        "rejected_images": rejected,
                    });
                }
            },
            Err(error) => {
                return json!({
                    "status": "failed",
                    "module": module,
                    "module_parameters": parameters,
                    "cache_dir": cache_dir,
                    "offline": offline,
                    "image_search_paths": deduplicated_roots,
                    "rejected_images": rejected,
                    "detail": format!("Rust-native image prefetch failed: {error:#}"),
                });
            }
        },
    };
    let image_directory = image_path
        .parent()
        .expect("validated PE image path has a parent")
        .to_path_buf();
    let prefetch = match prefetch_pdb(&image_path, cache_dir, offline) {
        Ok(result) => result,
        Err(error) => {
            return json!({
                "status": "failed",
                "module": module,
                "image_path": image_path,
                "image_prefetch": image_prefetch,
                "cache_dir": cache_dir,
                "offline": offline,
                "detail": format!("Rust-native PDB prefetch failed: {error:#}"),
            });
        }
    };
    let Some(pdb_path) = prefetch.pdb_path.as_ref() else {
        return json!({
            "status": prefetch.status,
            "module": module,
            "image_path": image_path,
            "image_prefetch": image_prefetch,
            "prefetch": prefetch,
            "offline": offline,
        });
    };
    let pdb_dir = pdb_path
        .parent()
        .expect("PDB path has parent")
        .to_path_buf();
    let reload = session
        .configure_local_symbol_paths(&[pdb_dir.clone()], &[image_directory])
        .and_then(|()| {
            module
                .module_name
                .as_deref()
                .context("DbgEng did not provide a fault-module name")
                .and_then(|name| session.refresh_symbols(name))
        });
    json!({
        "status": match prefetch.status {
            NativeSymbolStatus::Cached => "configured_from_cache",
            NativeSymbolStatus::Downloaded => "downloaded_and_configured",
            NativeSymbolStatus::OfflineMissing => "offline_missing",
            NativeSymbolStatus::Unavailable => "unavailable",
        },
        "module": module,
        "module_parameters": parameters,
        "image_path": image_path,
        "image_prefetch": image_prefetch,
        "pdb_directory": pdb_dir,
        "prefetch": prefetch,
        "forced_reload": match reload {
            Ok(()) => json!({"status": "loaded"}),
            Err(error) => json!({"status": "failed", "detail": format!("{error:#}")}),
        },
        "resolved_fault_symbol": session.symbol_by_offset(fault_address).ok().flatten(),
        "offline": offline,
    })
}

const BREAK_READ: u32 = 1;
const BREAK_WRITE: u32 = 2;
const BREAK_EXECUTE: u32 = 4;

fn default_target_stack_frames() -> u32 {
    32
}

fn default_target_memory_map_regions() -> u32 {
    256
}

fn default_target_thread_accounting_threads() -> u32 {
    32
}

fn validate_target_memory_map_region_limit(region_limit: u32) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_VIRTUAL_MEMORY_MAP_REGIONS).contains(&region_limit),
        "target memory-map region_limit must be from 1 through {MAX_VIRTUAL_MEMORY_MAP_REGIONS}"
    );
    Ok(())
}

fn validate_target_thread_accounting_limit(max_threads: u32) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_THREAD_ACCOUNTING_THREADS).contains(&max_threads),
        "target thread-accounting max_threads must be from 1 through {MAX_THREAD_ACCOUNTING_THREADS}"
    );
    Ok(())
}

fn validate_target_module_parameter_bases(base_addresses: &[u64]) -> anyhow::Result<()> {
    ensure!(
        !base_addresses.is_empty(),
        "target module-parameters requires at least one module base address"
    );
    ensure!(
        base_addresses.len() <= MAX_MODULE_PARAMETER_QUERIES,
        "target module-parameters supports at most {MAX_MODULE_PARAMETER_QUERIES} module base addresses"
    );
    let mut unique_bases = base_addresses.to_vec();
    unique_bases.sort_unstable();
    unique_bases.dedup();
    ensure!(
        unique_bases.len() == base_addresses.len(),
        "target module-parameters requires distinct module base addresses"
    );
    Ok(())
}

fn default_target_disasm_count() -> u32 {
    16
}

fn ensure_live_target(target_id: TargetId, session: &DebuggerSession) -> anyhow::Result<()> {
    if session.kind() != DebuggerSessionKind::Live {
        bail!("target {target_id} is not a live session")
    }
    Ok(())
}

impl From<TargetDumpKind> for DumpKind {
    fn from(kind: TargetDumpKind) -> Self {
        match kind {
            TargetDumpKind::Mini => DumpKind::Mini,
            TargetDumpKind::Full => DumpKind::Full,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_memory_map_region_limit_before_accessing_a_target() {
        assert!(validate_target_memory_map_region_limit(1).is_ok());
        assert!(validate_target_memory_map_region_limit(MAX_VIRTUAL_MEMORY_MAP_REGIONS).is_ok());
        assert!(validate_target_memory_map_region_limit(0).is_err());
        assert!(
            validate_target_memory_map_region_limit(MAX_VIRTUAL_MEMORY_MAP_REGIONS + 1).is_err()
        );
    }

    #[test]
    fn validates_thread_accounting_limit_before_accessing_a_target() {
        assert!(validate_target_thread_accounting_limit(1).is_ok());
        assert!(validate_target_thread_accounting_limit(MAX_THREAD_ACCOUNTING_THREADS).is_ok());
        assert!(validate_target_thread_accounting_limit(0).is_err());
        assert!(
            validate_target_thread_accounting_limit(MAX_THREAD_ACCOUNTING_THREADS + 1).is_err()
        );
    }

    #[test]
    fn validates_module_parameter_bases_before_accessing_a_target() {
        assert!(validate_target_module_parameter_bases(&[0x1000]).is_ok());
        assert!(validate_target_module_parameter_bases(&[]).is_err());
        assert!(validate_target_module_parameter_bases(&[0x1000, 0x1000]).is_err());
        assert!(validate_target_module_parameter_bases(
            &(0..=MAX_MODULE_PARAMETER_QUERIES as u64).collect::<Vec<_>>()
        )
        .is_err());
    }
}
