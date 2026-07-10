use std::{
    env,
    ffi::{c_void, OsStr},
    mem,
    path::{Path, PathBuf},
    ptr::NonNull,
};

use anyhow::{bail, ensure, Context};
use libloading::Library;
use serde::Serialize;
use windows::core::Interface;

use crate::DebuggerSession;

const BRIDGE_DLL_NAME: &str = "windbg_coreclr_dac_bridge.dll";
const BRIDGE_DLL_ENV: &str = "WINDBG_CORECLR_DAC_BRIDGE_DLL";
const WINDBG_DAC_OK: u32 = 0;
const WINDBG_DAC_NOT_FOUND: u32 = 3;
const WINDBG_DAC_AMBIGUOUS: u32 = 4;
const WINDBG_DAC_CODE_UNAVAILABLE: u32 = 5;
const MAX_WIDE_CHARS: usize = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeRuntimeInfo {
    coreclr_path: [u16; MAX_WIDE_CHARS],
    dac_path: [u16; MAX_WIDE_CHARS],
    coreclr_version_ms: u32,
    coreclr_version_ls: u32,
    dac_version_ms: u32,
    dac_version_ls: u32,
}

impl Default for NativeRuntimeInfo {
    fn default() -> Self {
        // The C ABI consists entirely of integer fields and fixed UTF-16 buffers.
        unsafe { mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeMethodInfo {
    method_token: u32,
    matching_method_count: u32,
    representative_entry_address: u64,
    code_notification_flags: u32,
    code_available: u8,
    reserved: [u8; 3],
    resolved_method: [u16; MAX_WIDE_CHARS],
}

impl Default for NativeMethodInfo {
    fn default() -> Self {
        // The C ABI consists entirely of integer fields and a fixed UTF-16 buffer.
        unsafe { mem::zeroed() }
    }
}

type CreateBridge = unsafe extern "C" fn(
    debug_client: *mut c_void,
    coreclr_path: *const u16,
    allow_target_writes: u8,
    bridge: *mut *mut c_void,
    runtime_info: *mut NativeRuntimeInfo,
) -> u32;
type DestroyBridge = unsafe extern "C" fn(bridge: *mut c_void);
type EnableModuleLoadNotifications = unsafe extern "C" fn(bridge: *mut c_void) -> u32;
type IsModuleLoaded = unsafe extern "C" fn(
    bridge: *mut c_void,
    managed_module_path: *const u16,
    loaded: *mut u8,
) -> u32;
type ResolveAndNotify = unsafe extern "C" fn(
    bridge: *mut c_void,
    managed_module_path: *const u16,
    fully_qualified_method: *const u16,
    method_info: *mut NativeMethodInfo,
) -> u32;
type RefreshMethodCode =
    unsafe extern "C" fn(bridge: *mut c_void, method_info: *mut NativeMethodInfo) -> u32;
type LastError = unsafe extern "C" fn() -> *const u16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedRuntimeInfo {
    pub coreclr_path: PathBuf,
    pub dac_path: PathBuf,
    pub coreclr_file_version: (u32, u32),
    pub dac_file_version: (u32, u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedMethodInfo {
    pub token: u32,
    pub matching_method_count: u32,
    pub resolved_method: String,
    pub code_notification_flags: u32,
    pub representative_entry_address: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedCodeAvailability {
    Available,
    PendingJit,
}

pub struct CoreClrDacBridge {
    _library: Library,
    bridge: NonNull<c_void>,
    destroy: DestroyBridge,
    enable_module_load_notifications: EnableModuleLoadNotifications,
    is_module_loaded: IsModuleLoaded,
    resolve_and_notify: ResolveAndNotify,
    refresh_method_code: RefreshMethodCode,
    last_error: LastError,
    runtime_info: ManagedRuntimeInfo,
}

impl CoreClrDacBridge {
    pub fn open(
        session: &DebuggerSession,
        coreclr_path: &Path,
        allow_target_writes: bool,
    ) -> anyhow::Result<Self> {
        ensure!(
            coreclr_path.is_file(),
            "the selected CoreCLR module path does not exist: {}",
            coreclr_path.display()
        );

        let library_path = bridge_dll_path()?;
        let library = unsafe { Library::new(&library_path) }.with_context(|| {
            format!(
                "loading the CoreCLR DAC bridge from {}",
                library_path.display()
            )
        })?;

        let create = unsafe { load_symbol::<CreateBridge>(&library, b"windbg_dac_create\0")? };
        let destroy = unsafe { load_symbol::<DestroyBridge>(&library, b"windbg_dac_destroy\0")? };
        let enable_module_load_notifications = unsafe {
            load_symbol::<EnableModuleLoadNotifications>(
                &library,
                b"windbg_dac_enable_module_load_notifications\0",
            )?
        };
        let is_module_loaded =
            unsafe { load_symbol::<IsModuleLoaded>(&library, b"windbg_dac_is_module_loaded\0")? };
        let resolve_and_notify = unsafe {
            load_symbol::<ResolveAndNotify>(&library, b"windbg_dac_resolve_and_notify\0")?
        };
        let refresh_method_code = unsafe {
            load_symbol::<RefreshMethodCode>(&library, b"windbg_dac_refresh_method_code\0")?
        };
        let last_error = unsafe { load_symbol::<LastError>(&library, b"windbg_dac_last_error\0")? };

        let coreclr_path = to_wide(coreclr_path.as_os_str())?;
        let mut raw_bridge = std::ptr::null_mut();
        let mut native_runtime = NativeRuntimeInfo::default();
        let status = unsafe {
            create(
                session.client.as_raw(),
                coreclr_path.as_ptr(),
                u8::from(allow_target_writes),
                &mut raw_bridge,
                &mut native_runtime,
            )
        };
        if status != WINDBG_DAC_OK {
            bail!(
                "initializing the CoreCLR DAC bridge failed: {}",
                bridge_error(last_error)
            );
        }
        let bridge = NonNull::new(raw_bridge)
            .context("the CoreCLR DAC bridge reported success without returning a bridge handle")?;

        Ok(Self {
            _library: library,
            bridge,
            destroy,
            enable_module_load_notifications,
            is_module_loaded,
            resolve_and_notify,
            refresh_method_code,
            last_error,
            runtime_info: managed_runtime_info(&native_runtime)?,
        })
    }

    pub fn runtime_info(&self) -> &ManagedRuntimeInfo {
        &self.runtime_info
    }

    pub fn enable_module_load_notifications(&self) -> anyhow::Result<()> {
        let status = unsafe { (self.enable_module_load_notifications)(self.bridge.as_ptr()) };
        if status != WINDBG_DAC_OK {
            bail!(
                "requesting CLR managed-module load notifications failed: {}",
                bridge_error(self.last_error)
            );
        }
        Ok(())
    }

    pub fn is_module_loaded(&self, managed_module_path: &Path) -> anyhow::Result<bool> {
        let managed_module_path = to_wide(managed_module_path.as_os_str())?;
        let mut loaded = 0u8;
        let status = unsafe {
            (self.is_module_loaded)(
                self.bridge.as_ptr(),
                managed_module_path.as_ptr(),
                &mut loaded,
            )
        };
        if status != WINDBG_DAC_OK {
            bail!(
                "checking whether the managed module is available through the DAC failed: {}",
                bridge_error(self.last_error)
            );
        }
        Ok(loaded != 0)
    }

    pub fn resolve_and_notify(
        &mut self,
        managed_module_path: &Path,
        fully_qualified_method: &str,
    ) -> anyhow::Result<(ManagedMethodInfo, ManagedCodeAvailability)> {
        let managed_module_path = to_wide(managed_module_path.as_os_str())?;
        let method = to_wide(OsStr::new(fully_qualified_method))?;
        let mut native_method = NativeMethodInfo::default();
        let status = unsafe {
            (self.resolve_and_notify)(
                self.bridge.as_ptr(),
                managed_module_path.as_ptr(),
                method.as_ptr(),
                &mut native_method,
            )
        };
        self.handle_method_status(status, &native_method, "resolving the managed method")?;
        let availability = if native_method.code_available == 0 {
            ManagedCodeAvailability::PendingJit
        } else {
            ManagedCodeAvailability::Available
        };
        Ok((managed_method_info(&native_method)?, availability))
    }

    pub fn refresh_method_code(&self) -> anyhow::Result<ManagedMethodInfo> {
        let mut native_method = NativeMethodInfo::default();
        let status =
            unsafe { (self.refresh_method_code)(self.bridge.as_ptr(), &mut native_method) };
        self.handle_method_status(status, &native_method, "querying generated managed code")?;
        managed_method_info(&native_method)
    }

    fn handle_method_status(
        &self,
        status: u32,
        native_method: &NativeMethodInfo,
        operation: &str,
    ) -> anyhow::Result<()> {
        match status {
            WINDBG_DAC_OK => Ok(()),
            WINDBG_DAC_NOT_FOUND => bail!("{operation} failed: {}", bridge_error(self.last_error)),
            WINDBG_DAC_AMBIGUOUS => bail!(
                "{operation} failed because {} method definitions matched; exact signature selection is required",
                native_method.matching_method_count
            ),
            WINDBG_DAC_CODE_UNAVAILABLE => {
                bail!("{operation} failed: {}", bridge_error(self.last_error))
            }
            _ => bail!("{operation} failed: {}", bridge_error(self.last_error)),
        }
    }
}

impl Drop for CoreClrDacBridge {
    fn drop(&mut self) {
        unsafe {
            (self.destroy)(self.bridge.as_ptr());
        }
    }
}

fn bridge_dll_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = env::var_os(BRIDGE_DLL_ENV).map(PathBuf::from) {
        ensure!(
            path.is_file(),
            "{BRIDGE_DLL_ENV} must name the CoreCLR DAC bridge DLL: {}",
            path.display()
        );
        return Ok(path);
    }

    let executable_path = env::current_exe().context("locating the windbg-tool executable")?;
    let candidate = executable_path
        .parent()
        .context("the windbg-tool executable has no parent directory")?
        .join(BRIDGE_DLL_NAME);
    ensure!(
        candidate.is_file(),
        "the CoreCLR DAC bridge is unavailable at {}. Run `cargo xtask native-build` and stage {} beside windbg-tool.exe, or set {BRIDGE_DLL_ENV}.",
        candidate.display(),
        BRIDGE_DLL_NAME
    );
    Ok(candidate)
}

unsafe fn load_symbol<T: Copy>(library: &Library, symbol: &[u8]) -> anyhow::Result<T> {
    Ok(*unsafe { library.get::<T>(symbol) }
        .with_context(|| format!("loading bridge export {}", String::from_utf8_lossy(symbol)))?)
}

fn to_wide(value: impl AsRef<std::ffi::OsStr>) -> anyhow::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide = value.as_ref().encode_wide().collect::<Vec<_>>();
    ensure!(
        !wide.contains(&0),
        "the CoreCLR DAC bridge input must not contain an embedded NUL"
    );
    wide.push(0);
    Ok(wide)
}

fn bridge_error(last_error: LastError) -> String {
    let pointer = unsafe { last_error() };
    if pointer.is_null() {
        return "the native bridge did not provide an error message".to_string();
    }

    let mut length = 0usize;
    while length < MAX_WIDE_CHARS {
        if unsafe { *pointer.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
}

fn managed_runtime_info(native: &NativeRuntimeInfo) -> anyhow::Result<ManagedRuntimeInfo> {
    Ok(ManagedRuntimeInfo {
        coreclr_path: PathBuf::from(utf16_field(&native.coreclr_path, "CoreCLR path")?),
        dac_path: PathBuf::from(utf16_field(&native.dac_path, "DAC path")?),
        coreclr_file_version: (native.coreclr_version_ms, native.coreclr_version_ls),
        dac_file_version: (native.dac_version_ms, native.dac_version_ls),
    })
}

fn managed_method_info(native: &NativeMethodInfo) -> anyhow::Result<ManagedMethodInfo> {
    Ok(ManagedMethodInfo {
        token: native.method_token,
        matching_method_count: native.matching_method_count,
        resolved_method: utf16_field(&native.resolved_method, "managed method name")?,
        code_notification_flags: native.code_notification_flags,
        representative_entry_address: (native.code_available != 0)
            .then_some(native.representative_entry_address)
            .filter(|address| *address != 0),
    })
}

fn utf16_field(value: &[u16], name: &str) -> anyhow::Result<String> {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .context(format!(
            "{name} from the native bridge was not NUL terminated"
        ))?;
    String::from_utf16(&value[..length])
        .with_context(|| format!("{name} from the native bridge was invalid UTF-16"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nul_terminated_utf16() {
        let mut value = [0u16; 8];
        value[..4].copy_from_slice(&['t' as u16, 'e' as u16, 's' as u16, 't' as u16]);

        assert_eq!(utf16_field(&value, "test").unwrap(), "test");
    }

    #[test]
    fn rejects_unterminated_utf16() {
        assert!(utf16_field(&[1u16; 4], "test").is_err());
    }
}
