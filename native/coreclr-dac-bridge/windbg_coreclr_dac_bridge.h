#pragma once

#include <stdint.h>
#include <wchar.h>

#ifdef _WIN32
#define WINDBG_DAC_EXPORT __declspec(dllexport)
#else
#define WINDBG_DAC_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WindbgDacBridge WindbgDacBridge;

typedef enum WindbgDacStatus {
    WINDBG_DAC_OK = 0,
    WINDBG_DAC_ERROR = 1,
    WINDBG_DAC_INVALID_ARGUMENT = 2,
    WINDBG_DAC_NOT_FOUND = 3,
    WINDBG_DAC_AMBIGUOUS = 4,
    WINDBG_DAC_CODE_UNAVAILABLE = 5,
} WindbgDacStatus;

typedef struct WindbgDacRuntimeInfo {
    wchar_t coreclr_path[1024];
    wchar_t dac_path[1024];
    uint32_t coreclr_version_ms;
    uint32_t coreclr_version_ls;
    uint32_t dac_version_ms;
    uint32_t dac_version_ls;
} WindbgDacRuntimeInfo;

enum {
    WINDBG_DAC_MAX_METHOD_CANDIDATES = 8,
    WINDBG_DAC_MAX_SIGNATURE_HEX_CHARS = 1024,
};

typedef struct WindbgDacMethodCandidate {
    uint32_t method_token;
    uint8_t signature_truncated;
    uint8_t reserved[3];
    wchar_t signature_hex[WINDBG_DAC_MAX_SIGNATURE_HEX_CHARS];
} WindbgDacMethodCandidate;

typedef struct WindbgDacMethodInfo {
    uint32_t method_token;
    uint32_t matching_method_count;
    uint64_t representative_entry_address;
    uint32_t code_notification_flags;
    uint8_t code_available;
    uint8_t reserved[3];
    wchar_t resolved_method[1024];
    wchar_t resolved_signature_hex[WINDBG_DAC_MAX_SIGNATURE_HEX_CHARS];
    uint32_t reported_candidate_count;
    uint8_t candidates_truncated;
    uint8_t reserved2[3];
    WindbgDacMethodCandidate candidates[WINDBG_DAC_MAX_METHOD_CANDIDATES];
} WindbgDacMethodInfo;

// The debug_client parameter is an IDebugClient5 pointer retained by the caller for the bridge lifetime.
WINDBG_DAC_EXPORT WindbgDacStatus windbg_dac_create(
    void* debug_client,
    const wchar_t* coreclr_path,
    uint8_t allow_target_writes,
    WindbgDacBridge** bridge,
    WindbgDacRuntimeInfo* runtime_info);

WINDBG_DAC_EXPORT void windbg_dac_destroy(WindbgDacBridge* bridge);

WINDBG_DAC_EXPORT WindbgDacStatus windbg_dac_enable_module_load_notifications(
    WindbgDacBridge* bridge);

WINDBG_DAC_EXPORT WindbgDacStatus windbg_dac_disable_module_load_notifications(
    WindbgDacBridge* bridge);

WINDBG_DAC_EXPORT WindbgDacStatus windbg_dac_is_module_loaded(
    WindbgDacBridge* bridge,
    const wchar_t* managed_module_path,
    uint8_t* loaded);

WINDBG_DAC_EXPORT WindbgDacStatus windbg_dac_resolve_and_notify(
    WindbgDacBridge* bridge,
    const wchar_t* managed_module_path,
    const wchar_t* fully_qualified_method,
    const uint8_t* signature_blob,
    uint32_t signature_blob_length,
    WindbgDacMethodInfo* method_info);

// Resolves metadata and any already-generated native method instance without
// registering CLR notifications or invoking any target-write callback.
WINDBG_DAC_EXPORT WindbgDacStatus windbg_dac_resolve_read_only(
    WindbgDacBridge* bridge,
    const wchar_t* managed_module_path,
    const wchar_t* fully_qualified_method,
    const uint8_t* signature_blob,
    uint32_t signature_blob_length,
    WindbgDacMethodInfo* method_info);

WINDBG_DAC_EXPORT WindbgDacStatus windbg_dac_refresh_method_code(
    WindbgDacBridge* bridge,
    WindbgDacMethodInfo* method_info);

WINDBG_DAC_EXPORT const wchar_t* windbg_dac_last_error(void);

#ifdef __cplusplus
}
#endif
