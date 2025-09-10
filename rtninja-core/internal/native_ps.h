// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_PS_H_
#define RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_PS_H_

#include "rtninja-core/internal/window_types.h"
#include "rtninja-core/internal/native_status.h"
#include "rtninja-core/internal/native_types.h"

namespace rtninja {
namespace nt {

// copied from: https://ntdoc.m417z.com/processinfoclass
enum PROCESS_INFORMATION_CLASS {
  ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
  ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
  ProcessIoCounters, // q: IO_COUNTERS
  ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
  ProcessTimes, // q: KERNEL_USER_TIMES
  ProcessBasePriority, // s: KPRIORITY
  ProcessRaisePriority, // s: ULONG
  ProcessDebugPort, // q: HANDLE
  ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
  ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
  ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
  ProcessLdtSize, // s: PROCESS_LDT_SIZE
  ProcessDefaultHardErrorMode, // qs: ULONG
  ProcessIoPortHandlers, // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
  ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS // (non-wow64)
  ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
  ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
  ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
  ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
  ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
  ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
  ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
  ProcessPriorityBoost, // qs: ULONG
  ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
  ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
  ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
  ProcessWow64Information, // q: ULONG_PTR
  ProcessImageFileName, // q: UNICODE_STRING
  ProcessLUIDDeviceMapsEnabled, // q: ULONG
  ProcessBreakOnTermination, // qs: ULONG
  ProcessDebugObjectHandle, // q: HANDLE // 30
  ProcessDebugFlags, // qs: ULONG
  ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
  ProcessIoPriority, // qs: IO_PRIORITY_HINT
  ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
  ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
  ProcessCookie, // q: ULONG
  ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
  ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
  ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
  ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
  ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
  ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
  ProcessImageFileNameWin32, // q: UNICODE_STRING
  ProcessImageFileMapping, // q: HANDLE (input)
  ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
  ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
  ProcessGroupInformation, // q: USHORT[]
  ProcessTokenVirtualizationEnabled, // s: ULONG
  ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
  ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
  ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
  ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
  ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
  ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
  ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
  ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
  ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
  ProcessHandleTable, // q: ULONG[] // since WINBLUE
  ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
  ProcessCommandLineInformation, // q: UNICODE_STRING // 60
  ProcessProtectionInformation, // q: PS_PROTECTION
  ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
  ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
  ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
  ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
  ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
  ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
  ProcessSubsystemProcess, // s: void // EPROCESS->SubsystemProcess
  ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
  ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
  ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
  ProcessIumChallengeResponse,
  ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
  ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
  ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
  ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
  ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
  ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
  ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
  ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
  ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
  ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
  ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
  ProcessCaptureTrustletLiveDump, // q: ULONG
  ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
  ProcessEnclaveInformation,
  ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
  ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
  ProcessImageSection, // q: HANDLE
  ProcessDebugAuthInformation, // s: CiTool.exe --device-id // PplDebugAuthorization // since RS4 // 90
  ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
  ProcessSequenceNumber, // q: ULONGLONG
  ProcessLoaderDetour, // since RS5
  ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
  ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
  ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
  ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
  ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
  ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
  ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
  ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
  ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
  ProcessCreateStateChange, // since WIN11
  ProcessApplyStateChange,
  ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
  ProcessAltPrefetchParam, // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
  ProcessAssignCpuPartitions, // HANDLE
  ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
  ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
  ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT // 110
  ProcessEffectivePagePriority, // q: ULONG
  ProcessSchedulerSharedData, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
  ProcessSlistRollbackInformation,
  ProcessNetworkIoCounters, // q: PROCESS_NETWORK_COUNTERS
  ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
  ProcessEnclaveAddressSpaceRestriction, // since 25H2
  ProcessAvailableCpus, // PROCESS_AVAILABLE_CPUS_INFORMATION
  MaxProcessInfoClass
};

template<class Ptr>
struct alignas(sizeof(Ptr)) PROCESS_BASIC_INFORMATION_T :
    public internal::AS_POINTER_T<PROCESS_BASIC_INFORMATION_T<ULONG32>> {
  Ptr ExitStatus;       // The exit status of the process. (GetExitCodeProcess)
  Ptr PebBaseAddress;   // A pointer to the process environment block (PEB) of the process.
  Ptr AffinityMask;
  Ptr BasePriority;     // The base priority of the process. (GetPriorityClass)
  Ptr UniqueProcessId;  // The unique identifier of the process. (GetProcessId)
  Ptr InheritedFromUniqueProcessId; // The unique identifier of the parent process.
};
using PROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION_T<ULONG_PTR>;
using PROCESS_BASIC_INFORMATION32 = PROCESS_BASIC_INFORMATION_T<ULONG32>;
using PROCESS_BASIC_INFORMATION64 = PROCESS_BASIC_INFORMATION_T<ULONG64>;

template <class Ptr>
struct alignas(sizeof(Ptr)) CLIENT_ID_T :
    public internal::AS_POINTER_T<CLIENT_ID_T<ULONG32>> {
  Ptr UniqueProcess;
  Ptr UniqueThread;
};
using CLIENT_ID = CLIENT_ID_T<ULONG_PTR>;
using CLIENT_ID32 = CLIENT_ID_T<ULONG32>;
using CLIENT_ID64 = CLIENT_ID_T<ULONG64>;

template <class Ptr>
struct alignas(sizeof(Ptr)) NT_TIB_T :
    public internal::AS_POINTER_T<NT_TIB_T<ULONG32>> {
  Ptr ExceptionList;
  Ptr StackBase;
  Ptr StackLimit;
  Ptr SubSystemTib;
  union {
    Ptr   FiberData;
    ULONG Version;
  };
  Ptr ArbitraryUserPointer;
  Ptr Self;
};
using NT_TIB = NT_TIB_T<ULONG_PTR>;
using NT_TIB32 = NT_TIB_T<ULONG32>;
using NT_TIB64 = NT_TIB_T<ULONG64>;


template <class Ptr>
struct alignas(sizeof(Ptr)) TEB_T :
    public internal::AS_POINTER_T<TEB_T<ULONG32>> {
  NT_TIB_T<Ptr> Tib;
  Ptr EnvironmentPointer;
  CLIENT_ID_T<Ptr> ClientId;
  Ptr ActiveRpcInfo;
  Ptr ThreadLocalStoragePointer;
  Ptr Peb;
  // appending...
};
using TEB = TEB_T<ULONG_PTR>;
using TEB32 = TEB_T<ULONG32>;
using TEB64 = TEB_T<ULONG64>;

template <class Ptr>
struct alignas(sizeof(Ptr)) LDR_DATA_TABLE_ENTRY_T :
    public internal::AS_POINTER_T<LDR_DATA_TABLE_ENTRY_T<ULONG32>> {
  LIST_ENTRY_T<Ptr> InLoadOrderLinks;
  LIST_ENTRY_T<Ptr> InMemoryOrderLinks;
  LIST_ENTRY_T<Ptr> InInitializationOrderLinks;
  Ptr   DllBase;
  Ptr   EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING_T<Ptr> FullDllName;
  UNICODE_STRING_T<Ptr> BaseDllName;
  DWORD Flags;
  WORD  LoadCount;
  WORD  TlsIndex;
  // appending...
};
using LDR_DATA_TABLE_ENTRY = LDR_DATA_TABLE_ENTRY_T<ULONG_PTR>;
using LDR_DATA_TABLE_ENTRY32 = LDR_DATA_TABLE_ENTRY_T<ULONG32>;
using LDR_DATA_TABLE_ENTRY64 = LDR_DATA_TABLE_ENTRY_T<ULONG64>;

template <class Ptr>
struct alignas(sizeof(Ptr)) PEB_LDR_DATA_T :
    public internal::AS_POINTER_T<PEB_LDR_DATA_T<ULONG32>> {
  ULONG Length;
  ULONG Initialized;
  Ptr   SsHandle;
  LIST_ENTRY_T<Ptr> InLoadOrderModuleList; // .Flink = LDR_DATA_TABLE_ENTRY
  LIST_ENTRY_T<Ptr> InMemoryOrderModuleList;
  LIST_ENTRY_T<Ptr> InInitializationOrderModuleList;
  Ptr   EntryInProgress;
  DWORD ShutdownInProgress;
  Ptr   ShutdownThreadId;
};
using PEB_LDR_DATA = PEB_LDR_DATA_T<ULONG_PTR>;
using PEB_LDR_DATA32 = PEB_LDR_DATA_T<ULONG32>;
using PEB_LDR_DATA64 = PEB_LDR_DATA_T<ULONG64>;

template <class Ptr>
struct alignas(sizeof(Ptr)) RTL_USE_PROCESS_PARAMETERS_T :
    public internal::AS_POINTER_T<RTL_USE_PROCESS_PARAMETERS_T<ULONG32>> {
  ULONG MaximumLength;
  ULONG Length;
  ULONG Flags;
  ULONG DebugFlags;
  Ptr   ConsoleHandle;
  ULONG ConsoleFlags;
  Ptr   StandardInput;
  Ptr   StandardOutput;
  Ptr   StandardError;
  UNICODE_STRING_T<Ptr> CurDirDosPath;
  Ptr   CurDirHandle;
  UNICODE_STRING_T<Ptr> DllPath;
  UNICODE_STRING_T<Ptr> ImagePathName;
  UNICODE_STRING_T<Ptr> CommandLine;
  Ptr   Environment;
  ULONG StartingX;
  ULONG StartingY;
  ULONG CountX;
  ULONG CountY;
  ULONG CountCharsX;
  ULONG CountCharsY;
  ULONG FillAttribute;
  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  UNICODE_STRING_T<Ptr> WindowTitle;
  UNICODE_STRING_T<Ptr> DesktopInfo;
  UNICODE_STRING_T<Ptr> ShellInfo;
  UNICODE_STRING_T<Ptr> RuntimeData;
  // appending...
};
using RTL_USE_PROCESS_PARAMETERS = RTL_USE_PROCESS_PARAMETERS_T<ULONG_PTR>;
using RTL_USE_PROCESS_PARAMETERS32 = RTL_USE_PROCESS_PARAMETERS_T<ULONG32>;
using RTL_USE_PROCESS_PARAMETERS64 = RTL_USE_PROCESS_PARAMETERS_T<ULONG64>;

template <class Ptr>
struct alignas(sizeof(Ptr)) PEB_T :
    public internal::AS_POINTER_T<PEB_T<ULONG32>> {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN BitField;
  Ptr     Mutant;
  Ptr     ImageBaseAddress;
  Ptr     LoaderData;      // PPEB_LDR_DATA
  Ptr     ProcessParamters;
  Ptr     SubSystemData;
  Ptr     ProcessHeap;
  Ptr     FastPebLock;
  Ptr     AtlThunkSListPtr;
  Ptr     IFEOKey;
  Ptr     CrossProcessFlags;
  Ptr     UserSharedInfoPtr;
  ULONG   SystemReserved;
  ULONG   AtlThunkSListPtr32;
  Ptr     ApiSetMap;
  Ptr     TlsExpansionCounter;
  Ptr     TlsBitmap;
  ULONG   TlsBitmapBits[2];
  Ptr     ReadOnlySharedMemoryBase;
  Ptr     HotpatchInformation;
  Ptr     ReadOnlyStaticServerData;
  Ptr     AnsiCodePageData;
  Ptr     OemCodePageData;
  Ptr     UnicodeCaseTableData;
  ULONG   NumberOfProcessors;
  ULONG   NtGlobalFlag;
  ULONG   CriticalSectionTimeout[2];
  Ptr     HeapSegmentReserve;
  Ptr     HeapSegmentCommit;
  Ptr     HeapDeCommitTotalFreeThreshold;
  Ptr     HeapDeCommitFreeBlockThreshold;
  ULONG   NumberOfHeaps;
  ULONG   MaximumNumberOfHeaps;
  Ptr     ProcessHeaps;
  Ptr     GdiSharedHandleTable;
  Ptr     ProcessStarterHelper;
  ULONG   GdiDCAttributeList;
  // appending... 
};
using PEB = PEB_T<ULONG_PTR>;
using PEB32 = PEB_T<ULONG32>;
using PEB64 = PEB_T<ULONG64>;

template <class Ptr>
struct alignas(sizeof(Ptr)) PS_ATTRIBUTE_T : 
    public internal::AS_POINTER_T<PS_ATTRIBUTE_T<ULONG32>> {
  Ptr Attribute;
  Ptr Size;
  Ptr Value;
  Ptr ReturnLength; // Ptr.
};
using PS_ATTRIBUTE = PS_ATTRIBUTE_T<ULONG_PTR>;
using PS_ATTRIBUTE32 = PS_ATTRIBUTE_T<ULONG32>;
using PS_ATTRIBUTE64 = PS_ATTRIBUTE_T<ULONG64>;

template <class Ptr>
struct PS_ATTRIBUTE_LIST_T {
  SIZE_T TotalLength;
  PS_ATTRIBUTE_T<Ptr> Attributes[1];
};
using PS_ATTRIBUTE_LIST = PS_ATTRIBUTE_LIST_T<ULONG_PTR>;
using PS_ATTRIBUTE_LIST32 = PS_ATTRIBUTE_LIST_T<ULONG32>;
using PS_ATTRIBUTE_LIST64 = PS_ATTRIBUTE_LIST_T<ULONG64>;

enum MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation, // q: MEMORY_BASIC_INFORMATION
  MemoryWorkingSetInformation, // q: MEMORY_WORKING_SET_INFORMATION
  MemoryMappedFilenameInformation, // q: UNICODE_STRING
  MemoryRegionInformation, // q: MEMORY_REGION_INFORMATION
  MemoryWorkingSetExInformation, // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
  MemorySharedCommitInformation, // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
  MemoryImageInformation, // q: MEMORY_IMAGE_INFORMATION
  MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
  MemoryPrivilegedBasicInformation, // MEMORY_BASIC_INFORMATION
  MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
  MemoryBasicInformationCapped, // 10
  MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
  MemoryBadInformation, // since WIN11
  MemoryBadInformationAllProcesses, // since 22H1
  MemoryImageExtensionInformation, // MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
  MaxMemoryInfoClass
};

using NtOpenProcessFunc = NTSTATUS (NTAPI*) (
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ OBJECT_ATTRIBUTES* ObjectAttributes,
    _In_opt_ CLIENT_ID* ClientId
    );

using NtQueryInformationProcessFunc = NTSTATUS(NTAPI*) (
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
    
using NtWow64QueryInformationProcess64Func = NTSTATUS(NTAPI*) (
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );
    
using NtQueryVirtualMemoryFunc = NTSTATUS(NTAPI*)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONG_PTR BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

using NtReadVirtualMemoryFunc = NTSTATUS(NTAPI*) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead
    );
    
using NtWow64ReadVirtualMemory64Func = NTSTATUS(NTAPI*) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONGLONG BaseAddress,
    _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
    _In_ ULONGLONG NumberOfBytesToRead,
    _Out_opt_ PULONGLONG NumberOfBytesRead
    );

using NtWriteVirtualMemoryFunc = NTSTATUS(NTAPI*) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );
    
using NtWow64WriteVirtualMemory64Func = NTSTATUS(NTAPI*) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONGLONG BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ ULONGLONG NumberOfBytesToWrite,
    _Out_opt_ PULONGLONG NumberOfBytesWritten
    );

using NtProtectVirtualMemoryFunc =  NTSTATUS(NTAPI*) (
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );

using NtAllocateVirtualMemoryFunc = NTSTATUS(NTAPI*)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );

using NtFreeVirtualMemoryFunc = NTSTATUS(NTAPI*)(
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
   );

using RtlCreateUserThreadFunc = NTSTATUS(NTAPI*)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ LPTHREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE ThreadHandle,
    _Out_opt_ CLIENT_ID* ClientId
    );

// implements 

// leaked handle(on win32)
HANDLE CurrentProcess();

HANDLE OpenProcess(
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOL InneriteHandle,
    _In_opt_ ULONG_PTR ProcessId
    );

BOOL QueryProcessInformation(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength = NULL
    );

BOOL QueryProcessInformation64(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength = NULL
    );

SIZE_T QueryProcessMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONG_PTR BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength
    );

SIZE_T QueryProcessMemory64(
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONGLONG BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength
    );

BOOL ReadProcessMemory64(
    _In_ HANDLE ProcessHandle,
    _In_opt_ ULONGLONG BaseAddress,
    _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead = NULL
    );

BOOL WriteProcessMemory64(
    _In_ HANDLE ProcessHandle,
    _In_ ULONGLONG BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten = NULL
    );

BOOL ProtectProcessMemory64(
    _In_ HANDLE ProcessHandle,
    _Inout_ ULONGLONG BaseAddress,
    _Inout_ SIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
    );

PVOID AllocateProcessMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );

BOOL FreeProcessMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG FreeType
    );

HANDLE CreateThread(
    _In_     HANDLE hProcess,
    _In_     SIZE_T dwStackSize,
    _In_     ULONG_PTR lpStartAddress,
    _In_opt_ ULONG_PTR lpParameter,
    _In_     DWORD dwCreationFlags,
    _In_opt_ LPDWORD lpThreadId
    );

HANDLE CreateThread64(
    _In_     HANDLE hProcess,
    _In_     SIZE_T dwStackSize,
    _In_     ULONGLONG lpStartAddress,
    _In_opt_ ULONGLONG lpParameter,
    _In_     DWORD dwCreationFlags,
    _In_opt_ LPDWORD lpThreadId
    );

}   // namespace nt
}   // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_PS_H_
