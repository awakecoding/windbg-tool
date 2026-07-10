// This narrow ABI declaration is derived from the MIT-licensed CLR data contracts in
// dotnet/diagnostics (clrdata.idl and xclrdata.idl). Keep it isolated from Rust: these
// interfaces are version-sensitive runtime/DAC contracts rather than a stable Rust ABI.
#include "windbg_coreclr_dac_bridge.h"

#include <windows.h>
#include <dbgeng.h>

#include <algorithm>
#include <array>
#include <cwchar>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using CLRDATA_ADDRESS = ULONG64;
using CLRDATA_ENUM = ULONG64;
using HCORENUM = void*;
using mdToken = ULONG32;
using mdTypeDef = ULONG32;
using mdTypeRef = ULONG32;
using mdInterfaceImpl = ULONG32;
using mdFieldDef = ULONG32;
using mdMethodDef = ULONG32;
using mdParamDef = ULONG32;
using mdMemberRef = ULONG32;
using mdPermission = ULONG32;
using PCCOR_SIGNATURE = const BYTE*;

static const CLSID CLSID_CorMetaDataDispenser =
    {0xe5cb7a31, 0x7512, 0x11d2, {0x89, 0xce, 0x00, 0x80, 0xc7, 0x92, 0xe5, 0xd8}};
static const IID IID_IMetaDataDispenser =
    {0x809c652e, 0x7396, 0x11d2, {0x97, 0x71, 0x00, 0xa0, 0xc9, 0xb4, 0xd5, 0x0c}};
static const IID IID_IMetaDataImport =
    {0x7dac8207, 0xd3ae, 0x4c75, {0x9b, 0x67, 0x92, 0x80, 0x1a, 0x49, 0x7d, 0x44}};

// This prefix follows the stable, MIT-licensed CoreCLR metadata contract in cor.h.
// Only methods through GetMethodProps are declared because the bridge never mutates metadata.
struct IMetaDataDispenser : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE DefineScope(
        REFCLSID rclsid,
        DWORD create_flags,
        REFIID iid,
        IUnknown** scope) = 0;
    virtual HRESULT STDMETHODCALLTYPE OpenScope(
        LPCWSTR path,
        DWORD open_flags,
        REFIID iid,
        IUnknown** scope) = 0;
    virtual HRESULT STDMETHODCALLTYPE OpenScopeOnMemory(
        LPCVOID data,
        ULONG size,
        DWORD open_flags,
        REFIID iid,
        IUnknown** scope) = 0;
};

struct IMetaDataImport : IUnknown {
    virtual void STDMETHODCALLTYPE CloseEnum(HCORENUM enumeration) = 0;
    virtual HRESULT STDMETHODCALLTYPE CountEnum(HCORENUM enumeration, ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE ResetEnum(HCORENUM enumeration, ULONG position) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumTypeDefs(
        HCORENUM* enumeration,
        mdTypeDef types[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumInterfaceImpls(
        HCORENUM* enumeration,
        mdTypeDef type,
        mdInterfaceImpl implementations[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumTypeRefs(
        HCORENUM* enumeration,
        mdTypeRef references[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE FindTypeDefByName(
        LPCWSTR type_name,
        mdToken enclosing_type,
        mdTypeDef* type) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetScopeProps(
        LPWSTR name,
        ULONG name_capacity,
        ULONG* name_length,
        GUID* mvid) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetModuleFromScope(mdToken* module) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTypeDefProps(
        mdTypeDef type,
        LPWSTR name,
        ULONG name_capacity,
        ULONG* name_length,
        DWORD* attributes,
        mdToken* extends) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetInterfaceImplProps(
        mdInterfaceImpl implementation,
        mdTypeDef* type,
        mdToken* interface_type) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTypeRefProps(
        mdTypeRef reference,
        mdToken* resolution_scope,
        LPWSTR name,
        ULONG name_capacity,
        ULONG* name_length) = 0;
    virtual HRESULT STDMETHODCALLTYPE ResolveTypeRef(
        mdTypeRef reference,
        REFIID iid,
        IUnknown** scope,
        mdTypeDef* type) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMembers(
        HCORENUM* enumeration,
        mdTypeDef type,
        mdToken members[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMembersWithName(
        HCORENUM* enumeration,
        mdTypeDef type,
        LPCWSTR name,
        mdToken members[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMethods(
        HCORENUM* enumeration,
        mdTypeDef type,
        mdMethodDef methods[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMethodsWithName(
        HCORENUM* enumeration,
        mdTypeDef type,
        LPCWSTR name,
        mdMethodDef methods[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumFields(
        HCORENUM* enumeration,
        mdTypeDef type,
        mdFieldDef fields[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumFieldsWithName(
        HCORENUM* enumeration,
        mdTypeDef type,
        LPCWSTR name,
        mdFieldDef fields[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumParams(
        HCORENUM* enumeration,
        mdMethodDef method,
        mdParamDef parameters[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMemberRefs(
        HCORENUM* enumeration,
        mdToken parent,
        mdMemberRef references[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMethodImpls(
        HCORENUM* enumeration,
        mdTypeDef type,
        mdToken bodies[],
        mdToken declarations[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumPermissionSets(
        HCORENUM* enumeration,
        mdToken token,
        DWORD actions,
        mdPermission permissions[],
        ULONG maximum,
        ULONG* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE FindMember(
        mdTypeDef type,
        LPCWSTR name,
        PCCOR_SIGNATURE signature,
        ULONG signature_size,
        mdToken* member) = 0;
    virtual HRESULT STDMETHODCALLTYPE FindMethod(
        mdTypeDef type,
        LPCWSTR name,
        PCCOR_SIGNATURE signature,
        ULONG signature_size,
        mdMethodDef* method) = 0;
    virtual HRESULT STDMETHODCALLTYPE FindField(
        mdTypeDef type,
        LPCWSTR name,
        PCCOR_SIGNATURE signature,
        ULONG signature_size,
        mdFieldDef* field) = 0;
    virtual HRESULT STDMETHODCALLTYPE FindMemberRef(
        mdTypeRef type,
        LPCWSTR name,
        PCCOR_SIGNATURE signature,
        ULONG signature_size,
        mdMemberRef* reference) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetMethodProps(
        mdMethodDef method,
        mdTypeDef* type,
        LPWSTR name,
        ULONG name_capacity,
        ULONG* name_length,
        DWORD* attributes,
        PCCOR_SIGNATURE* signature,
        ULONG* signature_size,
        ULONG* code_rva,
        DWORD* implementation_flags) = 0;
};

struct CLRDATA_ADDRESS_RANGE {
    CLRDATA_ADDRESS start_address;
    CLRDATA_ADDRESS end_address;
};

struct IXCLRDataProcess;
struct IXCLRDataModule;
struct IXCLRDataMethodDefinition;
struct IXCLRDataTask;
struct IXCLRDataValue;
struct IXCLRDataAppDomain;
struct IXCLRDataAssembly;
struct IXCLRDataTypeDefinition;
struct IXCLRDataTypeInstance;
struct IXCLRDataMethodInstance;
struct IXCLRDataExceptionState;
struct IXCLRDataExceptionNotification;

static constexpr ULONG32 CLRDATA_METHNOTIFY_GENERATED = 0x00000001;
static constexpr ULONG32 CLRDATA_METHNOTIFY_DISCARDED = 0x00000002;
static constexpr ULONG32 CLRDATA_NOTIFY_ON_MODULE_LOAD = 0x00000001;

static const IID IID_ICLRDataTarget =
    {0x3e11ccee, 0xd08b, 0x43e5, {0xaf, 0x01, 0x32, 0x71, 0x7a, 0x64, 0xda, 0x03}};
static const IID IID_ICLRDataTarget2 =
    {0x6d05fae3, 0x189c, 0x4630, {0xa6, 0xdc, 0x1c, 0x25, 0x1e, 0x1c, 0x01, 0xab}};
static const IID IID_IXCLRDataProcess =
    {0x5c552ab6, 0xfc09, 0x4cb3, {0x8e, 0x36, 0x22, 0xfa, 0x03, 0xc7, 0x98, 0xb7}};

struct ICLRDataTarget : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetMachineType(ULONG32* machine_type) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetPointerSize(ULONG32* pointer_size) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetImageBase(LPCWSTR image_path, CLRDATA_ADDRESS* base_address) = 0;
    virtual HRESULT STDMETHODCALLTYPE ReadVirtual(
        CLRDATA_ADDRESS address,
        BYTE* buffer,
        ULONG32 bytes_requested,
        ULONG32* bytes_read) = 0;
    virtual HRESULT STDMETHODCALLTYPE WriteVirtual(
        CLRDATA_ADDRESS address,
        BYTE* buffer,
        ULONG32 bytes_requested,
        ULONG32* bytes_written) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTLSValue(ULONG32 thread_id, ULONG32 index, CLRDATA_ADDRESS* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetTLSValue(ULONG32 thread_id, ULONG32 index, CLRDATA_ADDRESS value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCurrentThreadID(ULONG32* thread_id) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetThreadContext(
        ULONG32 thread_id,
        ULONG32 context_flags,
        ULONG32 context_size,
        BYTE* context) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetThreadContext(
        ULONG32 thread_id,
        ULONG32 context_size,
        BYTE* context) = 0;
    virtual HRESULT STDMETHODCALLTYPE Request(
        ULONG32 request_code,
        ULONG32 input_size,
        BYTE* input,
        ULONG32 output_size,
        BYTE* output) = 0;
};

struct ICLRDataTarget2 : ICLRDataTarget {
    virtual HRESULT STDMETHODCALLTYPE AllocVirtual(
        CLRDATA_ADDRESS address,
        ULONG32 size,
        ULONG32 type_flags,
        ULONG32 protect_flags,
        CLRDATA_ADDRESS* allocation) = 0;
    virtual HRESULT STDMETHODCALLTYPE FreeVirtual(
        CLRDATA_ADDRESS address,
        ULONG32 size,
        ULONG32 type_flags) = 0;
};

// Only the prefix used by this bridge is declared. Method ordering is the ABI.
struct IXCLRDataProcess : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Flush() = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumTasks(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumTask(CLRDATA_ENUM* handle, IXCLRDataTask** task) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumTasks(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTaskByOSThreadID(ULONG32 thread_id, IXCLRDataTask** task) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTaskByUniqueID(ULONG64 task_id, IXCLRDataTask** task) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetFlags(ULONG32* flags) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsSameObject(IXCLRDataProcess* process) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetManagedObject(IXCLRDataValue** value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetDesiredExecutionState(ULONG32* state) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetDesiredExecutionState(ULONG32 state) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAddressType(CLRDATA_ADDRESS address, ULONG32* type) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetRuntimeNameByAddress(
        CLRDATA_ADDRESS address,
        ULONG32 flags,
        ULONG32 buffer_length,
        ULONG32* name_length,
        WCHAR* name,
        CLRDATA_ADDRESS* displacement) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumAppDomains(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumAppDomain(CLRDATA_ENUM* handle, IXCLRDataAppDomain** app_domain) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumAppDomains(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAppDomainByUniqueID(ULONG64 id, IXCLRDataAppDomain** app_domain) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumAssemblies(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumAssembly(CLRDATA_ENUM* handle, IXCLRDataAssembly** assembly) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumAssemblies(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumModules(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumModule(CLRDATA_ENUM* handle, IXCLRDataModule** module) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumModules(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetModuleByAddress(CLRDATA_ADDRESS address, IXCLRDataModule** module) = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved24() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved25() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved26() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved27() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved28() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved29() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved30() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved31() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved32() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved33() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved34() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved35() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved36() = 0;
    virtual HRESULT STDMETHODCALLTYPE Reserved37() = 0;
    virtual HRESULT STDMETHODCALLTYPE GetOtherNotificationFlags(ULONG32* flags) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetOtherNotificationFlags(ULONG32 flags) = 0;
};

struct IXCLRDataModule : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE StartEnumAssemblies(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumAssembly(CLRDATA_ENUM* handle, IXCLRDataAssembly** assembly) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumAssemblies(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumTypeDefinitions(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumTypeDefinition(CLRDATA_ENUM* handle, IXCLRDataTypeDefinition** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumTypeDefinitions(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumTypeInstances(IXCLRDataAppDomain* app_domain, CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumTypeInstance(CLRDATA_ENUM* handle, IXCLRDataTypeInstance** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumTypeInstances(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumTypeDefinitionsByName(
        LPCWSTR name,
        ULONG32 flags,
        CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumTypeDefinitionByName(
        CLRDATA_ENUM* handle,
        IXCLRDataTypeDefinition** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumTypeDefinitionsByName(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumTypeInstancesByName(
        LPCWSTR name,
        ULONG32 flags,
        IXCLRDataAppDomain* app_domain,
        CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumTypeInstanceByName(
        CLRDATA_ENUM* handle,
        IXCLRDataTypeInstance** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumTypeInstancesByName(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTypeDefinitionByToken(ULONG32 token, IXCLRDataTypeDefinition** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumMethodDefinitionsByName(
        LPCWSTR name,
        ULONG32 flags,
        CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMethodDefinitionByName(
        CLRDATA_ENUM* handle,
        IXCLRDataMethodDefinition** method) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumMethodDefinitionsByName(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumMethodInstancesByName(
        LPCWSTR name,
        ULONG32 flags,
        IXCLRDataAppDomain* app_domain,
        CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumMethodInstanceByName(
        CLRDATA_ENUM* handle,
        IXCLRDataMethodInstance** method) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumMethodInstancesByName(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetMethodDefinitionByToken(
        mdMethodDef token,
        IXCLRDataMethodDefinition** method) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumDataByName(
        LPCWSTR name,
        ULONG32 flags,
        IXCLRDataAppDomain* app_domain,
        IXCLRDataTask* task,
        CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumDataByName(CLRDATA_ENUM* handle, IXCLRDataValue** value) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumDataByName(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetName(ULONG32 buffer_length, ULONG32* name_length, WCHAR* name) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetFileName(
        ULONG32 buffer_length,
        ULONG32* name_length,
        WCHAR* name) = 0;
};

struct IXCLRDataMethodDefinition : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetTypeDefinition(IXCLRDataTypeDefinition** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumInstances(IXCLRDataAppDomain* app_domain, CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumInstance(CLRDATA_ENUM* handle, IXCLRDataMethodInstance** instance) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumInstances(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetName(
        ULONG32 flags,
        ULONG32 buffer_length,
        ULONG32* name_length,
        WCHAR* name) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTokenAndScope(mdMethodDef* token, IXCLRDataModule** module) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetFlags(ULONG32* flags) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsSameObject(IXCLRDataMethodDefinition* method) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetLatestEnCVersion(ULONG32* version) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumExtents(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumExtent(CLRDATA_ENUM* handle, void* extent) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumExtents(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCodeNotification(ULONG32* flags) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetCodeNotification(ULONG32 flags) = 0;
    virtual HRESULT STDMETHODCALLTYPE Request(
        ULONG32 request_code,
        ULONG32 input_size,
        BYTE* input,
        ULONG32 output_size,
        BYTE* output) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetRepresentativeEntryAddress(CLRDATA_ADDRESS* address) = 0;
};

struct IXCLRDataMethodInstance : IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetTypeInstance(IXCLRDataTypeInstance** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetDefinition(IXCLRDataMethodDefinition** method) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTokenAndScope(mdMethodDef* token, IXCLRDataModule** module) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetName(
        ULONG32 flags,
        ULONG32 buffer_length,
        ULONG32* name_length,
        WCHAR* name) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetFlags(ULONG32* flags) = 0;
    virtual HRESULT STDMETHODCALLTYPE IsSameObject(IXCLRDataMethodInstance* method) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetEnCVersion(ULONG32* version) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumTypeArguments(ULONG32* argument_count) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetTypeArgumentByIndex(
        ULONG32 index,
        IXCLRDataTypeInstance** type) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetILOffsetsByAddress(
        CLRDATA_ADDRESS address,
        ULONG32 offset_count,
        ULONG32* offsets_needed,
        ULONG32* offsets) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetAddressRangesByILOffset(
        ULONG32 il_offset,
        ULONG32 range_count,
        ULONG32* ranges_needed,
        CLRDATA_ADDRESS_RANGE* ranges) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetILAddressMap(
        ULONG32 map_count,
        ULONG32* maps_needed,
        void* maps) = 0;
    virtual HRESULT STDMETHODCALLTYPE StartEnumExtents(CLRDATA_ENUM* handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumExtent(
        CLRDATA_ENUM* handle,
        CLRDATA_ADDRESS_RANGE* extent) = 0;
    virtual HRESULT STDMETHODCALLTYPE EndEnumExtents(CLRDATA_ENUM handle) = 0;
    virtual HRESULT STDMETHODCALLTYPE Request(
        ULONG32 request_code,
        ULONG32 input_size,
        BYTE* input,
        ULONG32 output_size,
        BYTE* output) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetRepresentativeEntryAddress(CLRDATA_ADDRESS* address) = 0;
};

using CLRDataCreateInstanceFn =
    HRESULT(STDAPICALLTYPE*)(REFIID iid, ICLRDataTarget* target, void** interface_pointer);

template <typename T>
class ComReference {
public:
    ComReference() = default;
    explicit ComReference(T* pointer) : pointer_(pointer) {}
    ~ComReference() { reset(); }

    ComReference(const ComReference&) = delete;
    ComReference& operator=(const ComReference&) = delete;

    T* get() const { return pointer_; }
    T** put() {
        reset();
        return &pointer_;
    }

    T* detach() {
        T* pointer = pointer_;
        pointer_ = nullptr;
        return pointer;
    }

    void reset(T* pointer = nullptr) {
        if (pointer_ != nullptr) {
            pointer_->Release();
        }
        pointer_ = pointer;
    }

private:
    T* pointer_ = nullptr;
};

using MetaDataGetDispenserFn =
    HRESULT(STDAPICALLTYPE*)(REFCLSID dispenser_class, REFIID iid, LPVOID* interface_pointer);

class MetadataImport final {
public:
    ~MetadataImport() {
        importer_.reset();
        dispenser_.reset();
        if (mscoree_ != nullptr) {
            FreeLibrary(mscoree_);
        }
    }

    static HRESULT Open(const wchar_t* managed_module_path, std::unique_ptr<MetadataImport>* metadata) {
        if (managed_module_path == nullptr || metadata == nullptr) {
            return E_INVALIDARG;
        }
        *metadata = nullptr;

        auto result = std::make_unique<MetadataImport>();
        result->mscoree_ = LoadLibraryExW(
            L"mscoree.dll",
            nullptr,
            LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (result->mscoree_ == nullptr) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        const auto get_dispenser = reinterpret_cast<MetaDataGetDispenserFn>(
            GetProcAddress(result->mscoree_, "MetaDataGetDispenser"));
        if (get_dispenser == nullptr) {
            return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
        }

        HRESULT open_result = get_dispenser(
            CLSID_CorMetaDataDispenser,
            IID_IMetaDataDispenser,
            reinterpret_cast<void**>(result->dispenser_.put()));
        if (FAILED(open_result)) {
            return open_result;
        }
        open_result = result->dispenser_.get()->OpenScope(
            managed_module_path,
            0,
            IID_IMetaDataImport,
            reinterpret_cast<IUnknown**>(result->importer_.put()));
        if (FAILED(open_result)) {
            return open_result;
        }

        *metadata = std::move(result);
        return S_OK;
    }

    HRESULT GetMethodSignature(mdMethodDef method, std::vector<BYTE>* signature) const {
        if (signature == nullptr) {
            return E_POINTER;
        }
        signature->clear();
        PCCOR_SIGNATURE signature_data = nullptr;
        ULONG signature_length = 0;
        const HRESULT result = importer_.get()->GetMethodProps(
            method,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
            &signature_data,
            &signature_length,
            nullptr,
            nullptr);
        if (FAILED(result)) {
            return result;
        }
        if (signature_data == nullptr || signature_length == 0) {
            return E_UNEXPECTED;
        }
        signature->assign(signature_data, signature_data + signature_length);
        return S_OK;
    }

private:
    HMODULE mscoree_ = nullptr;
    ComReference<IMetaDataDispenser> dispenser_;
    ComReference<IMetaDataImport> importer_;
};

thread_local std::wstring g_last_error;

void set_error(const std::wstring& error) {
    g_last_error = error;
}

std::wstring format_hresult(const wchar_t* operation, HRESULT result) {
    wchar_t message[256]{};
    swprintf_s(message, L"%s failed with HRESULT 0x%08X.", operation, static_cast<unsigned int>(result));
    return message;
}

WindbgDacStatus fail(WindbgDacStatus status, const std::wstring& error) {
    set_error(error);
    return status;
}

bool read_file_version(const wchar_t* path, uint32_t* version_ms, uint32_t* version_ls) {
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(path, &ignored);
    if (size == 0) {
        return false;
    }

    std::vector<BYTE> buffer(size);
    if (!GetFileVersionInfoW(path, 0, size, buffer.data())) {
        return false;
    }

    VS_FIXEDFILEINFO* version = nullptr;
    UINT version_size = 0;
    if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<void**>(&version), &version_size) ||
        version == nullptr ||
        version_size < sizeof(*version) ||
        version->dwSignature != VS_FFI_SIGNATURE) {
        return false;
    }

    *version_ms = version->dwFileVersionMS;
    *version_ls = version->dwFileVersionLS;
    return true;
}

void copy_string(wchar_t* destination, size_t destination_count, const std::wstring& source) {
    wcsncpy_s(destination, destination_count, source.c_str(), _TRUNCATE);
}

void copy_signature_hex(
    wchar_t* destination,
    size_t destination_count,
    const std::vector<BYTE>& signature,
    uint8_t* truncated) {
    static constexpr wchar_t hexadecimal[] = L"0123456789ABCDEF";
    if (destination == nullptr || destination_count == 0 || truncated == nullptr) {
        return;
    }

    const size_t maximum_bytes = (destination_count - 1) / 2;
    const size_t copied_bytes = std::min(signature.size(), maximum_bytes);
    for (size_t index = 0; index < copied_bytes; ++index) {
        destination[index * 2] = hexadecimal[signature[index] >> 4];
        destination[index * 2 + 1] = hexadecimal[signature[index] & 0x0f];
    }
    destination[copied_bytes * 2] = L'\0';
    *truncated = static_cast<uint8_t>(copied_bytes != signature.size());
}

void record_method_candidate(
    WindbgDacMethodInfo* method_info,
    mdMethodDef method_token,
    const std::vector<BYTE>& signature) {
    if (method_info->reported_candidate_count >= WINDBG_DAC_MAX_METHOD_CANDIDATES) {
        method_info->candidates_truncated = 1;
        return;
    }

    auto* candidate = &method_info->candidates[method_info->reported_candidate_count++];
    candidate->method_token = method_token;
    copy_signature_hex(
        candidate->signature_hex,
        std::size(candidate->signature_hex),
        signature,
        &candidate->signature_truncated);
}

void record_resolved_signature(WindbgDacMethodInfo* method_info, const std::vector<BYTE>& signature) {
    uint8_t ignored = 0;
    copy_signature_hex(
        method_info->resolved_signature_hex,
        std::size(method_info->resolved_signature_hex),
        signature,
        &ignored);
}

std::wstring sibling_dac_path(const wchar_t* coreclr_path) {
    std::wstring path(coreclr_path);
    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return {};
    }
    path.resize(separator + 1);
    path += L"mscordaccore.dll";
    return path;
}

class DbgEngDataTarget final : public ICLRDataTarget2 {
public:
    DbgEngDataTarget(IDebugClient5* client, bool allow_target_writes)
        : client_(client), allow_target_writes_(allow_target_writes) {
        client_.get()->AddRef();
        const HRESULT data_spaces_result =
            client_.get()->QueryInterface(__uuidof(IDebugDataSpaces4), reinterpret_cast<void**>(data_spaces_.put()));
        const HRESULT symbols_result =
            client_.get()->QueryInterface(__uuidof(IDebugSymbols5), reinterpret_cast<void**>(symbols_.put()));
        const HRESULT system_objects_result =
            client_.get()->QueryInterface(__uuidof(IDebugSystemObjects4), reinterpret_cast<void**>(system_objects_.put()));
        const HRESULT advanced_result =
            client_.get()->QueryInterface(__uuidof(IDebugAdvanced3), reinterpret_cast<void**>(advanced_.put()));
        if (FAILED(data_spaces_result) || FAILED(symbols_result) || FAILED(system_objects_result) ||
            FAILED(advanced_result)) {
            wchar_t message[512]{};
            swprintf_s(
                message,
                L"DbgEng interface queries: data spaces=0x%08X, symbols=0x%08X, system objects=0x%08X, advanced=0x%08X.",
                static_cast<unsigned int>(data_spaces_result),
                static_cast<unsigned int>(symbols_result),
                static_cast<unsigned int>(system_objects_result),
                static_cast<unsigned int>(advanced_result));
            diagnostic_ = message;
        }
    }

    const std::wstring& diagnostic() const { return diagnostic_; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (iid == IID_IUnknown || iid == IID_ICLRDataTarget) {
            *object = static_cast<ICLRDataTarget*>(this);
            AddRef();
            return S_OK;
        }
        if (iid == IID_ICLRDataTarget2) {
            *object = static_cast<ICLRDataTarget2*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&references_));
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const LONG references = InterlockedDecrement(&references_);
        if (references == 0) {
            delete this;
        }
        return static_cast<ULONG>(references);
    }

    HRESULT STDMETHODCALLTYPE GetMachineType(ULONG32* machine_type) override {
        if (machine_type == nullptr) {
            diagnostic_ = L"ICLRDataTarget::GetMachineType received a null output pointer.";
            return E_POINTER;
        }
        *machine_type = IMAGE_FILE_MACHINE_AMD64;
        diagnostic_ = L"ICLRDataTarget::GetMachineType returned IMAGE_FILE_MACHINE_AMD64.";
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetPointerSize(ULONG32* pointer_size) override {
        if (pointer_size == nullptr) {
            diagnostic_ = L"ICLRDataTarget::GetPointerSize received a null output pointer.";
            return E_POINTER;
        }
        *pointer_size = sizeof(uint64_t);
        diagnostic_ = L"ICLRDataTarget::GetPointerSize returned 8.";
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GetImageBase(LPCWSTR image_path, CLRDATA_ADDRESS* base_address) override {
        if (image_path == nullptr || base_address == nullptr || symbols_.get() == nullptr) {
            diagnostic_ = L"ICLRDataTarget::GetImageBase received invalid arguments or has no IDebugSymbols5.";
            return E_INVALIDARG;
        }

        ULONG index = 0;
        ULONG64 base = 0;
        HRESULT result = symbols_.get()->GetModuleByModuleNameWide(image_path, 0, &index, &base);
        if (FAILED(result)) {
            const wchar_t* file_name = wcsrchr(image_path, L'\\');
            file_name = file_name == nullptr ? image_path : file_name + 1;
            result = symbols_.get()->GetModuleByModuleNameWide(file_name, 0, &index, &base);
            if (FAILED(result)) {
                std::wstring module_name(file_name);
                const size_t extension = module_name.find_last_of(L'.');
                if (extension != std::wstring::npos) {
                    module_name.resize(extension);
                    result = symbols_.get()->GetModuleByModuleNameWide(
                        module_name.c_str(),
                        0,
                        &index,
                        &base);
                }
            }
        }
        if (SUCCEEDED(result)) {
            *base_address = base;
        }
        wchar_t message[1200]{};
        swprintf_s(
            message,
            L"ICLRDataTarget::GetImageBase(%s) returned 0x%08X (base=0x%llX).",
            image_path,
            static_cast<unsigned int>(result),
            static_cast<unsigned long long>(base));
        diagnostic_ = message;
        return result;
    }

    HRESULT STDMETHODCALLTYPE ReadVirtual(
        CLRDATA_ADDRESS address,
        BYTE* buffer,
        ULONG32 bytes_requested,
        ULONG32* bytes_read) override {
        if (buffer == nullptr || bytes_read == nullptr || data_spaces_.get() == nullptr) {
            diagnostic_ = L"ICLRDataTarget::ReadVirtual received invalid arguments or has no IDebugDataSpaces4.";
            return E_POINTER;
        }
        ULONG read = 0;
        const HRESULT result = data_spaces_.get()->ReadVirtual(address, buffer, bytes_requested, &read);
        *bytes_read = read;
        wchar_t message[256]{};
        swprintf_s(
            message,
            L"ICLRDataTarget::ReadVirtual(0x%llX, %u) returned 0x%08X (%u bytes).",
            static_cast<unsigned long long>(address),
            bytes_requested,
            static_cast<unsigned int>(result),
            read);
        diagnostic_ = message;
        return read != 0 && FAILED(result) ? S_OK : result;
    }

    HRESULT STDMETHODCALLTYPE WriteVirtual(
        CLRDATA_ADDRESS address,
        BYTE* buffer,
        ULONG32 bytes_requested,
        ULONG32* bytes_written) override {
        if (buffer == nullptr || bytes_written == nullptr || data_spaces_.get() == nullptr) {
            diagnostic_ = L"ICLRDataTarget::WriteVirtual received invalid arguments or has no IDebugDataSpaces4.";
            return E_POINTER;
        }
        if (!allow_target_writes_) {
            diagnostic_ =
                L"ICLRDataTarget::WriteVirtual was rejected because runtime writes were not explicitly enabled.";
            return E_ACCESSDENIED;
        }

        ULONG written = 0;
        const HRESULT result =
            data_spaces_.get()->WriteVirtual(address, buffer, bytes_requested, &written);
        *bytes_written = written;
        wchar_t message[256]{};
        swprintf_s(
            message,
            L"ICLRDataTarget::WriteVirtual(0x%llX, %u) returned 0x%08X (%u bytes).",
            static_cast<unsigned long long>(address),
            bytes_requested,
            static_cast<unsigned int>(result),
            written);
        diagnostic_ = message;
        return written != 0 && FAILED(result) ? S_OK : result;
    }

    HRESULT STDMETHODCALLTYPE GetTLSValue(ULONG32, ULONG32, CLRDATA_ADDRESS*) override {
        diagnostic_ = L"ICLRDataTarget::GetTLSValue is not implemented.";
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE SetTLSValue(ULONG32, ULONG32, CLRDATA_ADDRESS) override {
        diagnostic_ = L"ICLRDataTarget::SetTLSValue was rejected because this bridge is read-only.";
        return E_ACCESSDENIED;
    }

    HRESULT STDMETHODCALLTYPE GetCurrentThreadID(ULONG32* thread_id) override {
        if (thread_id == nullptr || system_objects_.get() == nullptr) {
            diagnostic_ = L"ICLRDataTarget::GetCurrentThreadID received invalid arguments or has no IDebugSystemObjects4.";
            return E_POINTER;
        }
        ULONG native_thread_id = 0;
        const HRESULT result = system_objects_.get()->GetCurrentThreadSystemId(&native_thread_id);
        *thread_id = native_thread_id;
        wchar_t message[256]{};
        swprintf_s(
            message,
            L"ICLRDataTarget::GetCurrentThreadID returned 0x%08X (%u).",
            static_cast<unsigned int>(result),
            native_thread_id);
        diagnostic_ = message;
        return result;
    }

    HRESULT STDMETHODCALLTYPE GetThreadContext(
        ULONG32 thread_id,
        ULONG32 context_flags,
        ULONG32 context_size,
        BYTE* context) override {
        if (context == nullptr || advanced_.get() == nullptr) {
            diagnostic_ = L"ICLRDataTarget::GetThreadContext received invalid arguments or has no IDebugAdvanced3.";
            return E_POINTER;
        }

        ULONG32 current_thread = 0;
        HRESULT result = GetCurrentThreadID(&current_thread);
        if (FAILED(result)) {
            diagnostic_ = format_hresult(L"ICLRDataTarget::GetCurrentThreadID", result);
            return result;
        }
        if (thread_id != current_thread || context_size < sizeof(CONTEXT)) {
            diagnostic_ = L"ICLRDataTarget::GetThreadContext only supports the current x64 thread and a full CONTEXT.";
            return E_INVALIDARG;
        }

        auto* native_context = reinterpret_cast<CONTEXT*>(context);
        native_context->ContextFlags = context_flags;
        result = advanced_.get()->GetThreadContext(native_context, context_size);
        diagnostic_ = format_hresult(L"ICLRDataTarget::GetThreadContext", result);
        return result;
    }

    HRESULT STDMETHODCALLTYPE SetThreadContext(ULONG32, ULONG32, BYTE*) override {
        diagnostic_ = L"ICLRDataTarget::SetThreadContext was rejected because this bridge is read-only.";
        return E_ACCESSDENIED;
    }

    HRESULT STDMETHODCALLTYPE Request(ULONG32, ULONG32, BYTE*, ULONG32, BYTE*) override {
        diagnostic_ = L"ICLRDataTarget::Request is not implemented.";
        return E_NOTIMPL;
    }

    HRESULT STDMETHODCALLTYPE AllocVirtual(
        CLRDATA_ADDRESS address,
        ULONG32 size,
        ULONG32 type_flags,
        ULONG32 protect_flags,
        CLRDATA_ADDRESS* allocation) override {
        if (allocation == nullptr) {
            diagnostic_ = L"ICLRDataTarget2::AllocVirtual received a null allocation output pointer.";
            return E_POINTER;
        }
        if (!allow_target_writes_) {
            diagnostic_ =
                L"ICLRDataTarget2::AllocVirtual was rejected because runtime writes were not explicitly enabled.";
            return E_ACCESSDENIED;
        }

        HANDLE process_handle = nullptr;
        HRESULT result = current_process_handle(&process_handle);
        if (FAILED(result)) {
            return result;
        }
        void* const allocated =
            VirtualAllocEx(process_handle, reinterpret_cast<void*>(address), size, type_flags, protect_flags);
        if (allocated == nullptr) {
            const DWORD error = GetLastError();
            result = HRESULT_FROM_WIN32(error);
            wchar_t message[320]{};
            swprintf_s(
                message,
                L"ICLRDataTarget2::AllocVirtual(0x%llX, %u, 0x%X, 0x%X) failed with Win32 error %lu.",
                static_cast<unsigned long long>(address),
                size,
                type_flags,
                protect_flags,
                error);
            diagnostic_ = message;
            return result;
        }
        *allocation = reinterpret_cast<CLRDATA_ADDRESS>(allocated);
        wchar_t message[320]{};
        swprintf_s(
            message,
            L"ICLRDataTarget2::AllocVirtual(0x%llX, %u, 0x%X, 0x%X) allocated 0x%llX.",
            static_cast<unsigned long long>(address),
            size,
            type_flags,
            protect_flags,
            static_cast<unsigned long long>(*allocation));
        diagnostic_ = message;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE FreeVirtual(
        CLRDATA_ADDRESS address,
        ULONG32 size,
        ULONG32 type_flags) override {
        if (!allow_target_writes_) {
            diagnostic_ =
                L"ICLRDataTarget2::FreeVirtual was rejected because runtime writes were not explicitly enabled.";
            return E_ACCESSDENIED;
        }

        HANDLE process_handle = nullptr;
        HRESULT result = current_process_handle(&process_handle);
        if (FAILED(result)) {
            return result;
        }
        if (!VirtualFreeEx(process_handle, reinterpret_cast<void*>(address), size, type_flags)) {
            const DWORD error = GetLastError();
            result = HRESULT_FROM_WIN32(error);
            wchar_t message[256]{};
            swprintf_s(
                message,
                L"ICLRDataTarget2::FreeVirtual(0x%llX, %u, 0x%X) failed with Win32 error %lu.",
                static_cast<unsigned long long>(address),
                size,
                type_flags,
                error);
            diagnostic_ = message;
            return result;
        }
        wchar_t message[256]{};
        swprintf_s(
            message,
            L"ICLRDataTarget2::FreeVirtual(0x%llX, %u, 0x%X) succeeded.",
            static_cast<unsigned long long>(address),
            size,
            type_flags);
        diagnostic_ = message;
        return S_OK;
    }

private:
    HRESULT current_process_handle(HANDLE* process_handle) {
        if (process_handle == nullptr || system_objects_.get() == nullptr) {
            diagnostic_ =
                L"ICLRDataTarget2 requires an output process handle and IDebugSystemObjects4.";
            return E_POINTER;
        }
        ULONG64 raw_process_handle = 0;
        const HRESULT result = system_objects_.get()->GetCurrentProcessHandle(&raw_process_handle);
        if (FAILED(result)) {
            diagnostic_ = format_hresult(L"IDebugSystemObjects4::GetCurrentProcessHandle", result);
            return result;
        }
        *process_handle = reinterpret_cast<HANDLE>(raw_process_handle);
        return S_OK;
    }

    ~DbgEngDataTarget() = default;

    LONG references_ = 1;
    ComReference<IDebugClient5> client_;
    ComReference<IDebugDataSpaces4> data_spaces_;
    ComReference<IDebugSymbols5> symbols_;
    ComReference<IDebugSystemObjects4> system_objects_;
    ComReference<IDebugAdvanced3> advanced_;
    bool allow_target_writes_;
    std::wstring diagnostic_;
};

struct WindbgDacBridge {
    WindbgDacBridge(IDebugClient5* client, bool allow_target_writes)
        : target(new DbgEngDataTarget(client, allow_target_writes)) {}

    ~WindbgDacBridge() {
        method_instance.reset();
        method.reset();
        process.reset();
        target->Release();
        if (dac_module != nullptr) {
            FreeLibrary(dac_module);
        }
    }

    DbgEngDataTarget* target;
    ComReference<IXCLRDataProcess> process;
    ComReference<IXCLRDataMethodDefinition> method;
    ComReference<IXCLRDataMethodInstance> method_instance;
    HMODULE dac_module = nullptr;
    std::wstring dac_path;
    std::wstring managed_module_path;
    mdMethodDef method_token = 0;
    std::vector<BYTE> method_signature;
    uint32_t matching_method_count = 0;
    uint32_t reported_candidate_count = 0;
    uint8_t candidates_truncated = 0;
    std::array<WindbgDacMethodCandidate, WINDBG_DAC_MAX_METHOD_CANDIDATES> method_candidates{};
};

HRESULT find_method_instance(
    IXCLRDataMethodDefinition* method,
    ComReference<IXCLRDataMethodInstance>* instance) {
    instance->reset();
    CLRDATA_ENUM enumeration = 0;
    HRESULT result = method->StartEnumInstances(nullptr, &enumeration);
    if (result == S_FALSE || FAILED(result)) {
        return result;
    }

    ComReference<IXCLRDataMethodInstance> selected;
    result = method->EnumInstance(&enumeration, selected.put());
    const HRESULT end_result = method->EndEnumInstances(enumeration);
    if (FAILED(result) || result == S_FALSE) {
        return result;
    }
    if (FAILED(end_result)) {
        return end_result;
    }
    instance->reset(selected.detach());
    return S_OK;
}

HRESULT populate_method_info(
    IXCLRDataMethodDefinition* method,
    ComReference<IXCLRDataMethodInstance>* method_instance,
    WindbgDacMethodInfo* info) {
    std::array<wchar_t, 1024> name{};
    ULONG32 name_length = 0;
    if (SUCCEEDED(method->GetName(0, static_cast<ULONG32>(name.size()), &name_length, name.data()))) {
        copy_string(info->resolved_method, std::size(info->resolved_method), name.data());
    }

    ComReference<IXCLRDataModule> scope;
    method->GetTokenAndScope(&info->method_token, scope.put());
    info->code_notification_flags = CLRDATA_METHNOTIFY_GENERATED | CLRDATA_METHNOTIFY_DISCARDED;

    // Method definitions expose IL extents; only a method instance exposes JIT-native code.
    const HRESULT instance_result = find_method_instance(method, method_instance);
    if (instance_result == S_FALSE) {
        return S_OK;
    }
    if (FAILED(instance_result)) {
        return instance_result;
    }

    CLRDATA_ADDRESS entry_address = 0;
    const HRESULT entry_result =
        method_instance->get()->GetRepresentativeEntryAddress(&entry_address);
    if (entry_result == E_UNEXPECTED) {
        method_instance->reset();
        return S_OK;
    }
    if (FAILED(entry_result)) {
        return entry_result;
    }
    if (entry_address != 0) {
        info->representative_entry_address = entry_address;
        info->code_available = 1;
    }
    return S_OK;
}

bool module_paths_match(const std::wstring& expected, const std::wstring& actual) {
    if (_wcsicmp(expected.c_str(), actual.c_str()) == 0) {
        return true;
    }

    const wchar_t* expected_name = wcsrchr(expected.c_str(), L'\\');
    expected_name = expected_name == nullptr ? expected.c_str() : expected_name + 1;
    const wchar_t* actual_name = wcsrchr(actual.c_str(), L'\\');
    actual_name = actual_name == nullptr ? actual.c_str() : actual_name + 1;
    return _wcsicmp(expected_name, actual_name) == 0;
}

WindbgDacStatus find_module_by_path(
    IXCLRDataProcess* process,
    const wchar_t* managed_module_path,
    ComReference<IXCLRDataModule>* module) {
    const HRESULT flush_result = process->Flush();
    if (FAILED(flush_result)) {
        return fail(WINDBG_DAC_ERROR, format_hresult(L"Refreshing the DAC process state", flush_result));
    }

    CLRDATA_ENUM enumeration = 0;
    HRESULT result = process->StartEnumModules(&enumeration);
    if (FAILED(result) || result == S_FALSE) {
        return fail(WINDBG_DAC_NOT_FOUND, L"The DAC did not enumerate any managed modules.");
    }

    const std::wstring expected_path(managed_module_path);
    std::vector<std::wstring> observed_module_paths;
    while (true) {
        ComReference<IXCLRDataModule> candidate;
        result = process->EnumModule(&enumeration, candidate.put());
        if (result == S_FALSE) {
            break;
        }
        if (FAILED(result)) {
            process->EndEnumModules(enumeration);
            return fail(WINDBG_DAC_ERROR, format_hresult(L"Enumerating DAC modules", result));
        }

        std::array<wchar_t, 32768> file_name{};
        ULONG32 file_name_length = 0;
        result = candidate.get()->GetFileName(
            static_cast<ULONG32>(file_name.size()),
            &file_name_length,
            file_name.data());
        if (SUCCEEDED(result) && file_name[0] != L'\0' && observed_module_paths.size() < 16) {
            observed_module_paths.emplace_back(file_name.data());
        }
        if (SUCCEEDED(result) && module_paths_match(expected_path, file_name.data())) {
            process->EndEnumModules(enumeration);
            module->reset(candidate.detach());
            return WINDBG_DAC_OK;
        }
    }
    process->EndEnumModules(enumeration);
    std::wstring observed = L" No module file names were available.";
    if (!observed_module_paths.empty()) {
        observed = L" Observed modules: ";
        for (size_t index = 0; index < observed_module_paths.size(); ++index) {
            if (index != 0) {
                observed += L"; ";
            }
            observed += observed_module_paths[index];
        }
        observed += L".";
    }
    return fail(
        WINDBG_DAC_NOT_FOUND,
        L"The DbgEng-selected managed module is not present in the matching DAC module enumeration." +
            observed);
}

extern "C" WindbgDacStatus windbg_dac_create(
    void* debug_client,
    const wchar_t* coreclr_path,
    uint8_t allow_target_writes,
    WindbgDacBridge** bridge,
    WindbgDacRuntimeInfo* runtime_info) {
    g_last_error.clear();
    if (debug_client == nullptr || coreclr_path == nullptr || bridge == nullptr || runtime_info == nullptr) {
        return fail(WINDBG_DAC_INVALID_ARGUMENT, L"A DbgEng client, CoreCLR path, bridge output, and runtime output are required.");
    }
    *bridge = nullptr;
    memset(runtime_info, 0, sizeof(*runtime_info));

    if (sizeof(void*) != sizeof(uint64_t)) {
        return fail(WINDBG_DAC_ERROR, L"The CoreCLR DAC bridge supports only x64 debugger hosts.");
    }

    const std::wstring coreclr(coreclr_path);
    const std::wstring dac_path = sibling_dac_path(coreclr_path);
    if (dac_path.empty() || GetFileAttributesW(coreclr_path) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(dac_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return fail(WINDBG_DAC_NOT_FOUND, L"An exact CoreCLR sibling mscordaccore.dll was not found.");
    }

    if (!read_file_version(
            coreclr_path,
            &runtime_info->coreclr_version_ms,
            &runtime_info->coreclr_version_ls) ||
        !read_file_version(
            dac_path.c_str(),
            &runtime_info->dac_version_ms,
            &runtime_info->dac_version_ls)) {
        return fail(WINDBG_DAC_ERROR, L"The CoreCLR or DAC file version could not be read.");
    }

    copy_string(runtime_info->coreclr_path, std::size(runtime_info->coreclr_path), coreclr);
    copy_string(runtime_info->dac_path, std::size(runtime_info->dac_path), dac_path);

    if (runtime_info->coreclr_version_ms != runtime_info->dac_version_ms ||
        runtime_info->coreclr_version_ls != runtime_info->dac_version_ls) {
        return fail(WINDBG_DAC_ERROR, L"CoreCLR and mscordaccore.dll file versions do not match exactly.");
    }

    auto native_bridge = std::make_unique<WindbgDacBridge>(
        reinterpret_cast<IDebugClient5*>(debug_client),
        allow_target_writes != 0);
    const HMODULE dac_module = LoadLibraryExW(
        dac_path.c_str(),
        nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (dac_module == nullptr) {
        wchar_t message[256]{};
        swprintf_s(message, L"Loading the matching DAC failed with Win32 error %lu.", GetLastError());
        return fail(WINDBG_DAC_ERROR, message);
    }

    const auto create_instance = reinterpret_cast<CLRDataCreateInstanceFn>(
        GetProcAddress(dac_module, "CLRDataCreateInstance"));
    if (create_instance == nullptr) {
        FreeLibrary(dac_module);
        return fail(WINDBG_DAC_ERROR, L"The matching DAC does not export CLRDataCreateInstance.");
    }

    native_bridge->dac_module = dac_module;
    const HRESULT result = create_instance(
        IID_IXCLRDataProcess,
        native_bridge->target,
        reinterpret_cast<void**>(native_bridge->process.put()));
    if (FAILED(result)) {
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"CLRDataCreateInstance", result) + L" DAC callback diagnostics: " +
                native_bridge->target->diagnostic());
    }
    if (native_bridge->process.get() == nullptr) {
        return fail(
            WINDBG_DAC_ERROR,
            L"CLRDataCreateInstance reported success without returning IXCLRDataProcess.");
    }

    native_bridge->dac_path = dac_path;
    *bridge = native_bridge.release();
    return WINDBG_DAC_OK;
}

extern "C" void windbg_dac_destroy(WindbgDacBridge* bridge) {
    delete bridge;
}

extern "C" WindbgDacStatus windbg_dac_enable_module_load_notifications(WindbgDacBridge* bridge) {
    g_last_error.clear();
    if (bridge == nullptr) {
        return fail(WINDBG_DAC_INVALID_ARGUMENT, L"A bridge is required.");
    }

    const HRESULT result =
        bridge->process.get()->SetOtherNotificationFlags(CLRDATA_NOTIFY_ON_MODULE_LOAD);
    if (FAILED(result)) {
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"Requesting CLR managed-module load notifications", result) +
                L" DAC callback diagnostics: " + bridge->target->diagnostic());
    }
    return WINDBG_DAC_OK;
}

extern "C" WindbgDacStatus windbg_dac_disable_module_load_notifications(WindbgDacBridge* bridge) {
    g_last_error.clear();
    if (bridge == nullptr) {
        return fail(WINDBG_DAC_INVALID_ARGUMENT, L"A bridge is required.");
    }

    const HRESULT result = bridge->process.get()->SetOtherNotificationFlags(0);
    if (FAILED(result)) {
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"Disabling CLR managed-module load notifications", result) +
                L" DAC callback diagnostics: " + bridge->target->diagnostic());
    }
    return WINDBG_DAC_OK;
}

extern "C" WindbgDacStatus windbg_dac_is_module_loaded(
    WindbgDacBridge* bridge,
    const wchar_t* managed_module_path,
    uint8_t* loaded) {
    g_last_error.clear();
    if (bridge == nullptr || managed_module_path == nullptr || loaded == nullptr) {
        return fail(
            WINDBG_DAC_INVALID_ARGUMENT,
            L"A bridge, managed module path, and loaded output are required.");
    }

    *loaded = 0;
    ComReference<IXCLRDataModule> module;
    const WindbgDacStatus status =
        find_module_by_path(bridge->process.get(), managed_module_path, &module);
    if (status == WINDBG_DAC_NOT_FOUND) {
        g_last_error.clear();
        return WINDBG_DAC_OK;
    }
    if (status != WINDBG_DAC_OK) {
        return status;
    }

    *loaded = 1;
    return WINDBG_DAC_OK;
}

extern "C" WindbgDacStatus windbg_dac_resolve_and_notify(
    WindbgDacBridge* bridge,
    const wchar_t* managed_module_path,
    const wchar_t* fully_qualified_method,
    const uint8_t* signature_blob,
    uint32_t signature_blob_length,
    WindbgDacMethodInfo* method_info) {
    g_last_error.clear();
    if (bridge == nullptr || managed_module_path == nullptr || fully_qualified_method == nullptr ||
        method_info == nullptr) {
        return fail(
            WINDBG_DAC_INVALID_ARGUMENT,
            L"A bridge, managed module path, fully-qualified method name, and method output are required.");
    }
    memset(method_info, 0, sizeof(*method_info));
    if ((signature_blob == nullptr) != (signature_blob_length == 0)) {
        return fail(
            WINDBG_DAC_INVALID_ARGUMENT,
            L"An exact metadata signature must provide both a non-null byte buffer and a non-zero length.");
    }

    ComReference<IXCLRDataModule> module;
    const WindbgDacStatus module_status =
        find_module_by_path(bridge->process.get(), managed_module_path, &module);
    if (module_status != WINDBG_DAC_OK) {
        return module_status;
    }

    std::unique_ptr<MetadataImport> metadata;
    const HRESULT metadata_result = MetadataImport::Open(managed_module_path, &metadata);
    if (FAILED(metadata_result)) {
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"Opening the selected managed module metadata", metadata_result));
    }

    CLRDATA_ENUM enumeration = 0;
    HRESULT result =
        module.get()->StartEnumMethodDefinitionsByName(fully_qualified_method, 0, &enumeration);
    if (FAILED(result) || result == S_FALSE) {
        return fail(WINDBG_DAC_NOT_FOUND, L"The requested managed method was not found in the selected module.");
    }

    ComReference<IXCLRDataMethodDefinition> selected;
    uint32_t count = 0;
    uint32_t selected_count = 0;
    std::vector<BYTE> selected_signature;
    while (true) {
        ComReference<IXCLRDataMethodDefinition> candidate;
        result = module.get()->EnumMethodDefinitionByName(&enumeration, candidate.put());
        if (result == S_FALSE) {
            break;
        }
        if (FAILED(result)) {
            module.get()->EndEnumMethodDefinitionsByName(enumeration);
            return fail(WINDBG_DAC_ERROR, format_hresult(L"Enumerating managed method definitions", result));
        }

        ++count;
        mdMethodDef candidate_token = 0;
        ComReference<IXCLRDataModule> candidate_scope;
        result = candidate.get()->GetTokenAndScope(&candidate_token, candidate_scope.put());
        if (FAILED(result) || candidate_token == 0) {
            module.get()->EndEnumMethodDefinitionsByName(enumeration);
            return fail(
                WINDBG_DAC_ERROR,
                format_hresult(L"Obtaining a managed method definition token", result));
        }

        std::vector<BYTE> candidate_signature;
        result = metadata->GetMethodSignature(candidate_token, &candidate_signature);
        if (FAILED(result)) {
            module.get()->EndEnumMethodDefinitionsByName(enumeration);
            return fail(
                WINDBG_DAC_ERROR,
                format_hresult(L"Reading a managed MethodDef signature", result));
        }
        record_method_candidate(method_info, candidate_token, candidate_signature);

        const bool selected_by_name = signature_blob == nullptr;
        const bool selected_by_signature = signature_blob != nullptr &&
            candidate_signature.size() == signature_blob_length &&
            std::equal(candidate_signature.begin(), candidate_signature.end(), signature_blob);
        if (selected_by_name || selected_by_signature) {
            ++selected_count;
            if (selected_count == 1) {
                selected_signature = std::move(candidate_signature);
                selected.reset(candidate.detach());
            }
        }
    }
    module.get()->EndEnumMethodDefinitionsByName(enumeration);

    method_info->matching_method_count = count;
    if (count == 0) {
        return fail(WINDBG_DAC_NOT_FOUND, L"The requested managed method was not found in the selected module.");
    }
    if (signature_blob == nullptr && count != 1) {
        return fail(
            WINDBG_DAC_AMBIGUOUS,
            L"The requested managed method is ambiguous. Supply --signature with the exact ECMA-335 MethodDef signature bytes.");
    }
    if (signature_blob != nullptr && selected_count == 0) {
        return fail(
            WINDBG_DAC_NOT_FOUND,
            L"No managed method definition with the requested name has the supplied exact metadata signature.");
    }
    if (selected_count != 1) {
        return fail(
            WINDBG_DAC_AMBIGUOUS,
            L"More than one managed method definition matched the supplied exact metadata signature.");
    }

    bridge->method.reset(selected.detach());
    bridge->method_instance.reset();
    result = populate_method_info(
        bridge->method.get(),
        &bridge->method_instance,
        method_info);
    if (FAILED(result)) {
        bridge->method.reset();
        bridge->method_instance.reset();
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"Resolving a native code instance for the managed method", result));
    }
    method_info->matching_method_count = count;
    record_resolved_signature(method_info, selected_signature);
    bridge->managed_module_path = managed_module_path;
    bridge->method_token = method_info->method_token;
    bridge->method_signature = std::move(selected_signature);
    bridge->matching_method_count = method_info->matching_method_count;
    bridge->reported_candidate_count = method_info->reported_candidate_count;
    bridge->candidates_truncated = method_info->candidates_truncated;
    memcpy(
        bridge->method_candidates.data(),
        method_info->candidates,
        sizeof(method_info->candidates));
    result = bridge->method.get()->SetCodeNotification(method_info->code_notification_flags);
    if (FAILED(result)) {
        bridge->method.reset();
        bridge->method_signature.clear();
        bridge->matching_method_count = 0;
        bridge->reported_candidate_count = 0;
        bridge->candidates_truncated = 0;
        bridge->method_candidates.fill({});
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"Requesting CLR code-generation notification", result) +
                L" DAC callback diagnostics: " + bridge->target->diagnostic());
    }

    return WINDBG_DAC_OK;
}

extern "C" WindbgDacStatus windbg_dac_refresh_method_code(
    WindbgDacBridge* bridge,
    WindbgDacMethodInfo* method_info) {
    g_last_error.clear();
    if (bridge == nullptr || method_info == nullptr) {
        return fail(WINDBG_DAC_INVALID_ARGUMENT, L"A bridge and method output are required.");
    }
    if (bridge->method.get() == nullptr) {
        return fail(WINDBG_DAC_NOT_FOUND, L"No managed method has been resolved for this bridge.");
    }

    if (bridge->managed_module_path.empty() || bridge->method_token == 0) {
        return fail(
            WINDBG_DAC_ERROR,
            L"The resolved managed method does not retain a module path and metadata token.");
    }
    memset(method_info, 0, sizeof(*method_info));
    method_info->matching_method_count = bridge->matching_method_count;
    method_info->reported_candidate_count = bridge->reported_candidate_count;
    method_info->candidates_truncated = bridge->candidates_truncated;
    memcpy(
        method_info->candidates,
        bridge->method_candidates.data(),
        sizeof(method_info->candidates));
    record_resolved_signature(method_info, bridge->method_signature);
    ComReference<IXCLRDataModule> module;
    const WindbgDacStatus module_status =
        find_module_by_path(bridge->process.get(), bridge->managed_module_path.c_str(), &module);
    if (module_status != WINDBG_DAC_OK) {
        return module_status;
    }
    bridge->method_instance.reset();
    bridge->method.reset();
    const HRESULT definition_result =
        module.get()->GetMethodDefinitionByToken(bridge->method_token, bridge->method.put());
    if (FAILED(definition_result) || bridge->method.get() == nullptr) {
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"Reopening the managed method definition after CLR code generation", definition_result));
    }
    const HRESULT result = populate_method_info(
        bridge->method.get(),
        &bridge->method_instance,
        method_info);
    if (FAILED(result)) {
        return fail(
            WINDBG_DAC_ERROR,
            format_hresult(L"Refreshing the managed method native code instance", result));
    }
    if (method_info->code_available == 0) {
        return fail(WINDBG_DAC_CODE_UNAVAILABLE, L"The managed method does not have a representative native entry address yet.");
    }
    return WINDBG_DAC_OK;
}

extern "C" const wchar_t* windbg_dac_last_error(void) {
    return g_last_error.c_str();
}
