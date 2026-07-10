use anyhow::{bail, ensure, Context};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use windbg_dbgeng::{
    attach_live_session, launch_live_session, open_dump_session, BreakpointInfo, CoreRegisterState,
    DebuggerEventInfo, DebuggerExecutionStatus, DebuggerSession, DebuggerSessionKind,
    DebuggerSessionSummary, DisassemblyResult, DumpKind, DumpOpenOptions, DumpWriteOptions,
    DumpWriteResult, EvaluationResult, LiveAttachOptions, LiveInitialStop,
    LiveLaunchSessionOptions, MemoryReadResult, ModuleInfo, SourceLocation, StackFrameInfo,
    SymbolInfo, ThreadContext, ThreadInfo, VirtualMemoryMap, MAX_VIRTUAL_MEMORY_MAP_REGIONS,
};

pub type TargetId = u64;

#[derive(Default)]
pub struct TargetRegistry {
    next_target_id: TargetId,
    targets: HashMap<TargetId, ManagedTarget>,
}

struct ManagedTarget {
    session: DebuggerSession,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSummary {
    pub target_id: TargetId,
    pub target: DebuggerSessionSummary,
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
pub struct TargetModuleList {
    pub target_id: TargetId,
    pub modules: Vec<ModuleInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSymbolResponse {
    pub target_id: TargetId,
    pub symbol: Option<SymbolInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetSourceResponse {
    pub target_id: TargetId,
    pub source: Option<SourceLocation>,
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
        Ok(self.insert_target(session))
    }

    pub fn attach_live(
        &mut self,
        request: LiveAttachRequest,
    ) -> anyhow::Result<TargetOpenedResponse> {
        let session = attach_live_session(LiveAttachOptions {
            process_id: request.process_id,
            initial_break_timeout_ms: request.initial_break_timeout_ms,
        })?;
        Ok(self.insert_target(session))
    }

    pub fn open_dump(&mut self, request: DumpOpenRequest) -> anyhow::Result<TargetOpenedResponse> {
        let session = open_dump_session(DumpOpenOptions { path: request.path })?;
        Ok(self.insert_target(session))
    }

    pub fn target_status(&self, request: TargetRequest) -> anyhow::Result<TargetSummary> {
        let target = self.target(request.target_id)?;
        Ok(TargetSummary {
            target_id: request.target_id,
            target: target.session.summary(),
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
        Ok(TargetSymbolResponse {
            target_id: request.target_id,
            symbol: target.session.symbol_by_offset(request.address)?,
        })
    }

    pub fn source_by_offset(
        &self,
        request: TargetAddressRequest,
    ) -> anyhow::Result<TargetSourceResponse> {
        let target = self.target(request.target_id)?;
        Ok(TargetSourceResponse {
            target_id: request.target_id,
            source: target.session.source_by_offset(request.address)?,
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
        Ok(TargetDisassemblyResponse {
            target_id: request.target_id,
            disassembly: target.session.disassemble(request.address, request.count)?,
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

    fn insert_target(&mut self, session: DebuggerSession) -> TargetOpenedResponse {
        let target_id = self.allocate_target_id();
        let target = session.summary();
        self.targets.insert(target_id, ManagedTarget { session });
        TargetOpenedResponse { target_id, target }
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

const BREAK_READ: u32 = 1;
const BREAK_WRITE: u32 = 2;
const BREAK_EXECUTE: u32 = 4;

fn default_target_stack_frames() -> u32 {
    32
}

fn default_target_memory_map_regions() -> u32 {
    256
}

fn validate_target_memory_map_region_limit(region_limit: u32) -> anyhow::Result<()> {
    ensure!(
        (1..=MAX_VIRTUAL_MEMORY_MAP_REGIONS).contains(&region_limit),
        "target memory-map region_limit must be from 1 through {MAX_VIRTUAL_MEMORY_MAP_REGIONS}"
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
}
