// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.
#include "rtninja-core/internal/native_ps.h"

#include "rtninja-core/internal/native_types.h"
#include "rtninja-core/internal/no_destructor.h"
#include "rtninja-core/internal/compiler_config.h"

namespace rtninja {
namespace nt {

namespace {

// GetNtOpenProcess
RTNINJA_NT_API(
    NtOpenProcess, 
    0x704F744E, 0x72506E65, 0x7365636F, 0x00000073)

// GetNtQueryInformationProcess
RTNINJA_NT_API(
    NtQueryInformationProcess, 
    0x7551744E, 0x49797265, 0x726F666E, 0x6974616D,
    0x72506E6F, 0x7365636F, 0x00000073)

    
// GetNtWow64QueryInformationProcess64
RTNINJA_NT_API(
    NtWow64QueryInformationProcess64, 
    0x6F57744E, 0x51343677, 0x79726575, 0x6F666E49,
    0x74616D72, 0x506E6F69, 0x65636F72, 0x34367373,
    0x00000000)

 // GetNtQueryVirtualMemory
RTNINJA_NT_API(
    NtQueryVirtualMemory, 
    0x7551744E, 0x56797265, 0x75747269, 0x654D6C61,
    0x79726F6D, 0x0000000)
       
// GetNtQueryVirtualMemory64
RTNINJA_NT_API64(
    NtQueryVirtualMemory, 
    0x7551744E, 0x56797265, 0x75747269, 0x654D6C61,
    0x79726F6D, 0x0000000)

// GetNtReadVirtualMemory
RTNINJA_NT_API(
    NtReadVirtualMemory, 
    0x6552744E, 0x69566461, 0x61757472, 0x6D654D6C,
    0x0079726F)
    
// GetNtWow64ReadVirtualMemory64
RTNINJA_NT_API(
    NtWow64ReadVirtualMemory64, 
    0x6F57744E, 0x52343677, 0x56646165, 0x75747269,
    0x654D6C61, 0x79726F6D, 0x00003436)
    
// GetNtWriteVirtualMemory
RTNINJA_NT_API(
    NtWriteVirtualMemory, 
    0x7257744E, 0x56657469, 0x75747269, 0x654D6C61,
    0x79726F6D, 0x00000000)
    
// GetNtWow64WriteVirtualMemory64
RTNINJA_NT_API(
    NtWow64WriteVirtualMemory64, 
    0x6F57744E, 0x57343677, 0x65746972, 0x74726956,
    0x4D6C6175, 0x726F6D65, 0x00343679)

// GetNtProtectVirtualMemory
RTNINJA_NT_API(
    NtProtectVirtualMemory, 
    0x7250744E, 0x6365746F, 0x72695674, 0x6C617574,
    0x6F6D654D, 0x00007972)
    
// GetNtProtectVirtualMemory64
RTNINJA_NT_API64(
    NtProtectVirtualMemory, 
    0x7250744E, 0x6365746F, 0x72695674, 0x6C617574,
    0x6F6D654D, 0x00007972)
    
// GetNtAllocateVirtualMemory
RTNINJA_NT_API(
    NtAllocateVirtualMemory, 
    0x6C41744E, 0x61636F6C, 0x69566574, 0x61757472, 
    0x6D654D6C, 0x0079726F)
    
// GetNtFreeVirtualMemory
RTNINJA_NT_API(
    NtFreeVirtualMemory, 
    0x7246744E, 0x69566565, 0x61757472, 0x6D654D6C,
    0x0079726F)
    
// GetRtlCreateUserThread
RTNINJA_NT_API(
    RtlCreateUserThread, 
    0x436C7452, 0x74616572, 0x65735565, 0x72685472,
    0x00646165)

// GetRtlCreateUserThread64
RTNINJA_NT_API64(
    RtlCreateUserThread, 
    0x436C7452, 0x74616572, 0x65735565, 0x72685472,
    0x00646165)


#define MAX_ADDRESS_32 (0x7FFFFFFF)
#define SAFE_SET(ptr, val) do{ if (ptr){*ptr = val;}} while(0)

}  // namespace 

HANDLE OpenProcess(ACCESS_MASK DesiredAccess,
                   BOOL InneriteHandle,
                   ULONG_PTR ProcessId) {
  ScopedNtStatus status;
  auto func = GetNtOpenProcess();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return nullptr;
  }

  OBJECT_ATTRIBUTES attr;
  attr.Length = sizeof(attr);
  attr.RootDirectory = 0;
  attr.ObjectName = 0;
  attr.Attributes = InneriteHandle ? kOBJInherit : 0;
  attr.SecurityDescriptor = 0;
  attr.SecurityQualityOfService = 0;

  CLIENT_ID client_id;
  client_id.UniqueProcess = ProcessId;
  client_id.UniqueThread = 0;

  HANDLE handle = nullptr;
  status = func(&handle, DesiredAccess, &attr, &client_id);
  return handle;
}

BOOL QueryProcessInformation(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength) {
  SAFE_SET(ReturnLength, 0);

  ScopedNtStatus status;
  auto func = GetNtQueryInformationProcess();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

  ULONG bytes_retn;
  status = func(ProcessHandle, ProcessInformationClass, 
                ProcessInformation, ProcessInformationLength,
                &bytes_retn);

  SAFE_SET(ReturnLength, bytes_retn);
  return NT_SUCCESS(status);
}

BOOL QueryProcessInformation64(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    ) {
#if defined(RTNINJA_ARCH_CPU_X86_64)
  return QueryProcessInformation(
      ProcessHandle, ProcessInformationClass, ProcessInformation,
      ProcessInformationLength, ReturnLength);
#elif defined(RTNINJA_ARCH_CPU_X86)
  SAFE_SET(ReturnLength, 0);
  ScopedNtStatus status;

  auto func = GetNtWow64QueryInformationProcess64();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

  ULONG bytes_retn;
  status = func(
      ProcessHandle, ProcessInformationClass, ProcessInformation,
      ProcessInformationLength, &bytes_retn);
  SAFE_SET(ReturnLength, bytes_retn);
  return NT_SUCCESS(status);
#endif
}

// 
SIZE_T QueryProcessMemory(HANDLE ProcessHandle,
                          ULONG_PTR BaseAddress,
                          MEMORY_INFORMATION_CLASS MemoryInformationClass,
                          PVOID MemoryInformation,
                          SIZE_T MemoryInformationLength) {
  ScopedNtStatus status;
  auto func = GetNtQueryVirtualMemory();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return 0;
  }

  SIZE_T bytes_retn = 0;
  status = func(ProcessHandle, BaseAddress,
                MemoryInformationClass, MemoryInformation,
                MemoryInformationLength, &bytes_retn);

  return bytes_retn;
}

// 
SIZE_T QueryProcessMemory64(HANDLE ProcessHandle,
                            ULONGLONG BaseAddress,
                            MEMORY_INFORMATION_CLASS MemoryInformationClass,
                            PVOID MemoryInformation,
                            SIZE_T MemoryInformationLength) {
#if defined(RTNINJA_ARCH_CPU_X86)
  ScopedNtStatus status;
  X64Call x64call = GetX64Call();
  ULONGLONG func64 = GetNtQueryVirtualMemory64();
  if (x64call == nullptr || func64 == 0ull) {
    status = kStatusNotImplemented;
    return 0;
  }

  ULONGLONG bytes_retn = 0;
  ULONGLONG process = (ProcessHandle == INVALID_HANDLE_VALUE ?
      MAXULONGLONG : HandleToUlong64(ProcessHandle));
  status = static_cast<NTSTATUS>(
      x64call(func64, 6,
          process, 
          BaseAddress,
          (ULONGLONG)(MemoryInformationClass),
          HandleToUlong64(MemoryInformation),
          (ULONGLONG)(MemoryInformationLength),
          HandleToUlong64(&bytes_retn)));
  return static_cast<SIZE_T>(bytes_retn);
#elif defined(RTNINJA_ARCH_CPU_X86_64)
  return QueryProcessMemory(
      ProcessHandle, BaseAddress, MemoryInformationClass,
      MemoryInformation, MemoryInformationLength);
#endif
}

// 
BOOL ReadProcessMemory64(HANDLE ProcessHandle,
                         ULONGLONG BaseAddress,
                         PVOID Buffer,
                         SIZE_T NumberOfBytesToRead,
                         PSIZE_T NumberOfBytesRead) {
  SAFE_SET(NumberOfBytesRead, 0);

  ScopedNtStatus status;
  auto func = GetNtReadVirtualMemory();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

#if defined(RTNINJA_ARCH_CPU_X86)
  // Accesss 32bit address.
  ULONGLONG end_address = BaseAddress + NumberOfBytesToRead;
  if (BaseAddress <= MAX_ADDRESS_32 && end_address <= MAX_ADDRESS_32) {
    SIZE_T bytes_read = 0;
    status = func(ProcessHandle, Ulong64ToHandle(BaseAddress),
                  Buffer, NumberOfBytesToRead, &bytes_read);
    SAFE_SET(NumberOfBytesRead, bytes_read);
    return NT_SUCCESS(status);
  }

  // Accesss 64bit address.
  auto fun64 = GetNtWow64ReadVirtualMemory64();
  if (fun64 == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

  bool want_close_handle = false;
  if (ProcessHandle == INVALID_HANDLE_VALUE) {
    ProcessHandle = OpenProcess(PROCESS_VM_READ, false, GetCurrentProcessId());
    want_close_handle = true;
  }

  ULONGLONG bytes_read = 0;
  status = fun64(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead,
                 &bytes_read);
  SAFE_SET(NumberOfBytesRead, static_cast<SIZE_T>(bytes_read));

  if (want_close_handle)
    ::CloseHandle(ProcessHandle);

  return NT_SUCCESS(status);

#elif defined(RTNINJA_ARCH_CPU_X86_64)
  SIZE_T bytes_read = 0;
  status = func(ProcessHandle, Ulong64ToHandle(BaseAddress),
                Buffer, NumberOfBytesToRead, &bytes_read);
  SAFE_SET(NumberOfBytesRead, bytes_read);
  return NT_SUCCESS(status);
#endif
}

// 
BOOL WriteProcessMemory64(HANDLE ProcessHandle,
                          ULONGLONG BaseAddress,
                          PVOID Buffer,
                          SIZE_T NumberOfBytesToWrite,
                          PSIZE_T NumberOfBytesWritten) {
  SAFE_SET(NumberOfBytesWritten, 0);

  ScopedNtStatus status;
  auto func = GetNtWriteVirtualMemory();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

#if defined(RTNINJA_ARCH_CPU_X86)
  // Accesss 32bit address.
  ULONGLONG end_address = BaseAddress + NumberOfBytesToWrite;
  if (BaseAddress <= MAX_ADDRESS_32 && end_address <= MAX_ADDRESS_32) {
    SIZE_T bytes_written = 0;
    status = func(ProcessHandle, Ulong64ToHandle(BaseAddress),
                  Buffer, NumberOfBytesToWrite, &bytes_written);
    SAFE_SET(NumberOfBytesWritten, bytes_written);
    return NT_SUCCESS(status);
  }

  // Accesss 64bit address.
  auto fun64 = GetNtWow64WriteVirtualMemory64();
  if (fun64 == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

  bool want_close_handle = false;
  if (ProcessHandle == INVALID_HANDLE_VALUE) {
    ProcessHandle = OpenProcess(PROCESS_VM_WRITE, false, GetCurrentProcessId());
    want_close_handle = true;
  }

  ULONGLONG bytes_written = 0;
  status = fun64(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, 
                 &bytes_written);
  SAFE_SET(NumberOfBytesWritten, static_cast<SIZE_T>(bytes_written));

  if (want_close_handle)
    ::CloseHandle(ProcessHandle);

  return NT_SUCCESS(status);

#elif defined(RTNINJA_ARCH_CPU_X86_64)
  SIZE_T bytes_written = 0;
  status = func(ProcessHandle, Ulong64ToHandle(BaseAddress),
                Buffer, NumberOfBytesToWrite, &bytes_written);
  SAFE_SET(NumberOfBytesWritten, bytes_written);
  return NT_SUCCESS(status);
#endif
}

// 
BOOL ProtectProcessMemory64(HANDLE ProcessHandle,
                            ULONGLONG BaseAddress,
                            SIZE_T RegionSize,
                            ULONG NewProtection,
                            PULONG OldProtection) {
  ScopedNtStatus status;
  auto func = GetNtProtectVirtualMemory();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

  ULONG old_protect = 0;

#if defined(RTNINJA_ARCH_CPU_X86)
  if (BaseAddress <= MAX_ADDRESS_32 ) {
    PVOID ptr = Ulong64ToHandle(BaseAddress);
    status = func(ProcessHandle, &ptr, &RegionSize, NewProtection, 
                  &old_protect);
    SAFE_SET(OldProtection, old_protect);
    return NT_SUCCESS(status);
  }

  auto x64call = GetX64Call();
  auto fun64 = GetNtProtectVirtualMemory64();
  if (!x64call || fun64 == 0ull) {
    status = kStatusNotImplemented;
    return FALSE;
  }

  ULONGLONG process = (ProcessHandle == INVALID_HANDLE_VALUE ?
      MAXULONGLONG : HandleToUlong64(ProcessHandle));
  status = static_cast<NTSTATUS>(
      x64call(fun64, 5, 
          process, 
          HandleToUlong64(&BaseAddress), 
          HandleToUlong64(&RegionSize),
          (ULONGLONG)(NewProtection), 
          HandleToUlong64(&old_protect)));
  SAFE_SET(OldProtection, old_protect);
  return NT_SUCCESS(status);

#elif defined(RTNINJA_ARCH_CPU_X86_64)
  PVOID ptr = Ulong64ToHandle(BaseAddress);
  status = func(ProcessHandle, &ptr, &RegionSize, NewProtection,
                &old_protect);
  SAFE_SET(OldProtection, old_protect);
  return NT_SUCCESS(status);
#endif
}


PVOID AllocateProcessMemory(HANDLE ProcessHandle,
                            PVOID BaseAddress,
                            SIZE_T RegionSize,
                            ULONG AllocationType,
                            ULONG PageProtection
                            ) {
  ScopedNtStatus status;
  auto func = GetNtAllocateVirtualMemory();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return nullptr;
  }

  status = func(ProcessHandle, &BaseAddress, 0, &RegionSize, 
                AllocationType, PageProtection);

  return NT_SUCCESS(status) ? BaseAddress : nullptr;
}

BOOL FreeProcessMemory(HANDLE ProcessHandle,
                       PVOID BaseAddress,
                       SIZE_T RegionSize,
                       ULONG FreeType) {
  ScopedNtStatus status;
  auto func = GetNtFreeVirtualMemory();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return FALSE;
  }

  status = func(ProcessHandle, &BaseAddress, &RegionSize, FreeType);
  return NT_SUCCESS(status);
}


HANDLE CurrentProcess() {
#if defined(RTNINJA_ARCH_CPU_X86)
  static const NoDestructor<HANDLE> self_handle([]() -> HANDLE {
    HANDLE handle = NULL;
    ::DuplicateHandle(INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, 
                      INVALID_HANDLE_VALUE, &handle, 
                      0, FALSE, DUPLICATE_SAME_ACCESS);
    return handle == NULL 
        ? OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId()) 
        : handle;
  }());
  return *self_handle;
#elif defined(RTNINJA_ARCH_CPU_X86_64)
  return INVALID_HANDLE_VALUE;
#endif
}

HANDLE CreateThread(HANDLE hProcess,
                    SIZE_T dwStackSize,
                    ULONG_PTR lpStartAddress,
                    ULONG_PTR lpParameter,
                    DWORD dwCreationFlags,
                    LPDWORD lpThreadId) {
  SAFE_SET(lpThreadId, 0);

  ScopedNtStatus status;
  
  auto func = GetRtlCreateUserThread();
  if (func == nullptr) {
    status = kStatusNotImplemented;
    return nullptr;
  }

  HANDLE thread_handle = nullptr;
  CLIENT_ID client_id;
  status = func(
      hProcess, 
      nullptr, 
      !!(dwCreationFlags & CREATE_SUSPENDED), 
      0, 
      dwStackSize, 
      dwStackSize,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress),
      reinterpret_cast<LPVOID>(lpParameter),
      &thread_handle,
      &client_id);
  if (NT_SUCCESS(status)) {
    SAFE_SET(lpThreadId, static_cast<DWORD>(client_id.UniqueThread));
    return thread_handle;
  }

  return nullptr;
}

HANDLE CreateThread64(HANDLE hProcess,
                      SIZE_T dwStackSize,
                      ULONGLONG lpStartAddress,
                      ULONGLONG lpParameter,
                      DWORD dwCreationFlags,
                      LPDWORD lpThreadId) {
#if defined(RTNINJA_ARCH_CPU_X86)
  SAFE_SET(lpThreadId, 0);

  ScopedNtStatus status;

  auto func64 = GetRtlCreateUserThread64();
  auto x64call = GetX64Call();
  if (func64 == 0ull || x64call == nullptr) {
    status = kStatusNotImplemented;
    return nullptr;
  }

  ULONGLONG thread_handle = 0ull;
  CLIENT_ID64 client_id;

  status = static_cast<NTSTATUS>(x64call(
      func64, 
      10,
      HandleToUlong64(hProcess), // ProcessHandle
      0ull,                      // ThreadSecurityDescriptor
      static_cast<ULONG64>(!!(dwCreationFlags & CREATE_SUSPENDED)),
      0ull,
      static_cast<ULONG64>(dwStackSize),
      static_cast<ULONG64>(dwStackSize),
      lpStartAddress,
      lpParameter,
      HandleToUlong64(&thread_handle),
      HandleToHandle64(&client_id)));
  if (NT_SUCCESS(status)) {
    SAFE_SET(lpThreadId, static_cast<DWORD>(client_id.UniqueThread));
    return Ulong64ToHandle(thread_handle);
  }

  return nullptr;
#elif defined(RTNINJA_ARCH_CPU_X86_64)
  return CreateThread(
      hProcess, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags,
      lpThreadId);
#endif
}

}  // namespace nt
}  // namespace rtninja