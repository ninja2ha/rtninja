// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include "rtninja-core/process.h"

#include <iostream>

#include "rtninja-core/internal/pe_image.h"
#include "rtninja-core/internal/compiler_config.h"
#include "rtninja-core/scoped_mem.h"
#include "rtninja-core/scoped_handle.h"

namespace rtninja {

namespace {

constexpr size_t kProcedureNameMaxLen = 64;

struct alignas(sizeof(void*)) ShellParam {
  PVOID ShellAddr;  // ecx + 0] (x86), ecx + 0](x64)
  SIZE_T ShellAddrSize; // ecx + 4] (x86, ecx + 8](x64)

  nt::LdrLoadDllFunc LdrLoadDll;
  nt::LdrGetProcedureAddressFunc GetProc;
  nt::NtSetEventFunc NtSetEvent;
  nt::NtCloseFunc NtClose;

  // Dulipcate handle
  HANDLE SignEvent;

  // Injectlib & Calling
  nt::UNICODE_STRING InjectDll;
  nt::ANSI_STRING Procedure;

  WCHAR InjectDllBuf[MAX_PATH];
  CHAR ProcedureBuf[kProcedureNameMaxLen];
  WCHAR ConfigFile[MAX_PATH];
};

DWORD CALLBACK ThreadProcImpl(__in ShellParam* p) {
  // LoadCustomLibrary
  PVOID module = nullptr;
  p->InjectDll.Buffer = reinterpret_cast<ULONG_PTR>(p->InjectDllBuf);
  p->LdrLoadDll(NULL, 0, &p->InjectDll, &module);

  // may be blocked.
  if (module != nullptr) {
    using RtNinjaMain = VOID(*)(const wchar_t*);
    RtNinjaMain func = nullptr;
    p->Procedure.Buffer = reinterpret_cast<ULONG_PTR>(p->ProcedureBuf);
    p->GetProc(module, &p->Procedure, 0, (PVOID*)&func);
    if (func != nullptr) {
      func(p->ConfigFile);
    }
  }

  p->NtSetEvent(p->SignEvent);
  p->NtClose(p->SignEvent);
  return 0;
}

static const ULONG32 ThreadProcShell32[] = {
  0x51EC8B55, 0x08758B56, 0x00FC45C7, 0x8D000000, 0x46892C46, 0xFC458D20,
  0x1C468D50, 0x08468B50, 0x006A006A, 0x4D8BD0FF, 0x74C985FC, 0x34868D33,
  0xC7000002, 0x00000845, 0x46890000, 0x08458D28, 0x8D006A50, 0x8B502446,
  0xFF510C46, 0x084D8BD0, 0x0C74C985, 0x0274868D, 0xFF500000, 0x04C483D1,
  0x8B1876FF, 0xD0FF1046, 0x8B1876FF, 0xD0FF1446, 0x8B5EC033, 0x04C25DE5
};

static const ULONG64 ThreadProcShell64[] = {
  0x8D4820EC83485340, 0x00302444C7485841, 0x8948D98B48000000, 0xD23338418D4C4041, 
  0xFF30244C8D4CC933, 0x4830244C8B481053, 0x60838D483674C985, 0x382444C748000002, 
  0x48538D4800000000, 0x244C8D4C50438948, 0x481853FFC0334538, 0x74C085483824448B, 
  0x000002A08B8D4809, 0x53FF304B8B48D0FF, 0x2853FF304B8B4820, 0xC35B20C48348C033
};

////////////////////////////////////////////////////////////////////////////////

template <class Ptr>
struct alignas(sizeof(Ptr)) ShellParamT 
    : nt::internal::AS_POINTER_T<ShellParamT<ULONG32>> {
  // same with ShellParam, don not change order of members.
  Ptr ShellAddr;  // ecx + 0] (x86), ecx + 0](x64)
  Ptr ShellAddrSize; // ecx + 4] (x86, ecx + 8](x64)

  Ptr LdrLoadDll;
  Ptr GetProc;
  Ptr NtSetEvent;
  Ptr NtClose;

  // Dulipcate handle
  Ptr SignEvent;

  // Injectlib & Calling
  nt::UNICODE_STRING_T<Ptr> InjectDll;
  nt::ANSI_STRING_T<Ptr> Procedure;

  WCHAR InjectDllBuf[MAX_PATH];
  CHAR ProcedureBuf[kProcedureNameMaxLen];
  WCHAR ConfigFile[MAX_PATH];
};

template<class Ptr>
Process::InjectError InjectLibraryT(const Process* process,
                                    const ShellParamT<Ptr>* param,
                                    const void* shell_func,
                                    size_t shell_func_size) {
  std::unique_ptr<BYTE[]> codes(new BYTE[4096]);

  BYTE* next_ptr = codes.get();

  // Writes shellcode param;
  constexpr size_t func_offset = ((sizeof(*param) + 0x10) & 0xFFFFFFF0);
  memcpy(next_ptr, param, sizeof(*param));
  next_ptr += func_offset;

  // Wrirtes shellcode fun;
  memcpy(next_ptr, shell_func, shell_func_size);
  next_ptr += shell_func_size;

  SIZE_T code_size = next_ptr - codes.get();
  if (!process->WriteMem64(param->ShellAddr, codes.get(), code_size))
    return Process::kInjectWriteShell;

  // Regardless of the architecture of the target process. 
  // x86-process alwasy allocate 32bit address.
  ULONG_PTR thread_param = static_cast<ULONG_PTR>(param->ShellAddr);
  ULONG_PTR thread_proc = thread_param + func_offset;
  
  ScopedHandle thread(process->architecture() == Process::kArchX64
      ? nt::CreateThread64(process->handle(), 0, 
                           static_cast<ULONG64>(thread_proc),
                           static_cast<ULONG64>(thread_param), 0, nullptr)
      : nt::CreateThread(process->handle(), 0, thread_proc, thread_param, 0,
                         nullptr));
  if (thread.get() == nullptr)
    return Process::kInjectCreateThread;

  ::WaitForSingleObject(thread.get(), INFINITE);
  return Process::kInjectOk;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

Process::InjectError Process::InjectLibraryByThreading(
    HANDLE sign_event,
    const WStringPiece& dll32,
    const WStringPiece& dll64,
    const StringPiece& proc,
    const WStringPiece& proc_param) const {
  if (!IsValid())
    return kInjectInvalidProcess;
    
  // ShellParam.DllNameBuffer
  if (dll32.size() >= MAX_PATH || dll64.size() >= MAX_PATH ) 
    return kInjectDllPath;

  // ShellParam.ProcBuffer
  if (proc.size() >= kProcedureNameMaxLen) 
    return kInjectProcName;

  // ShellParam.Config
  if (proc_param.size() >= MAX_PATH) 
    return kInjectProcParam;

  DWORD ntdll[] = {
      0x0074004E, 0x006C0044, 0x002E006C, 0x006C0064, 0x0000006C};
  ModuleEntry me;
  if (!GetModuleInfo2(
          WStringPiece(reinterpret_cast<wchar_t*>(ntdll)), false, &me)) {
    return kInjectQueryModule;
  }
  
  DWORD ldr_load_dll[] = { 
      0x4C72644C, 0x4464616F, 0x00006C6C};
  DWORD get_proc[] = {
      0x4772644C, 0x72507465, 0x6465636F, 0x41657275, 0x65726464, 0x00007373};
  DWORD set_event[] = {
      0x6553744E, 0x65764574, 0x0000746E, 0x00000000};
  DWORD nt_close[] = {
      0x6C43744E, 0x0065736F, 0x00000000 };

  ProcEntry proc_entry[] = {
    { reinterpret_cast<const char*>(ldr_load_dll), 0 }, // 0
    { reinterpret_cast<const char*>(get_proc), 0 },     // 1
    { reinterpret_cast<const char*>(set_event), 0 },    // 2
    { reinterpret_cast<const char*>(nt_close), 0 },     // 3
  };

  // TODO: Gets procedures bypass iat(IMPORT ADDRESS TABLE) hooking.
  if (!GetModuleProcs(me.base, proc_entry, ARRAYSIZE(proc_entry)))
    return kInjectQueryModuleProc;

  // Clones sync_event to injected process to set event.
  HANDLE targt_sign_event = nullptr;
  if (sign_event) {
    ::DuplicateHandle(
        INVALID_HANDLE_VALUE, sign_event, process_, &targt_sign_event,
        DUPLICATE_SAME_ACCESS, FALSE, 0);
  }

  constexpr size_t allocate_size = 0x1000;
  ScopedMemAlloc allocate_mem(handle(), allocate_size, PAGE_EXECUTE_READWRITE);
  if (allocate_mem.get() == nullptr)
    return kInjectAllocShell;
    
  ShellParamT<ULONG64> shell_param;

  WORD buffer_size = 0;
  if (architecture() == kArchX86) {
    ShellParamT<ULONG32>* shell_param32 = shell_param.AsPtr32();
    ZeroMemory(shell_param32, sizeof(*shell_param32));

    shell_param32->LdrLoadDll = HandleToUlong32(proc_entry[0].address);
    shell_param32->GetProc = HandleToUlong32(proc_entry[1].address);
    shell_param32->NtSetEvent = HandleToUlong32(proc_entry[2].address);
    shell_param32->NtClose = HandleToUlong32(proc_entry[3].address);
    shell_param32->SignEvent = HandleToUlong32(targt_sign_event);

    shell_param32->ShellAddr = HandleToUlong32(allocate_mem.get());
    shell_param32->ShellAddrSize = allocate_size;

    // Fills injected dll file path.
    wcsncpy_s(shell_param32->InjectDllBuf, dll32.data(), dll32.size());
    buffer_size = static_cast<WORD>(dll32.size() * sizeof(wchar_t));
    shell_param32->InjectDll.Length = buffer_size;
    shell_param32->InjectDll.MaximumLength = buffer_size + sizeof(wchar_t);

    // Fills main entry
    strncpy_s(shell_param32->ProcedureBuf, proc.data(), proc.size());
    buffer_size = static_cast<WORD>(proc.size() * sizeof(char));
    shell_param32->Procedure.Length = buffer_size;
    shell_param32->Procedure.MaximumLength = buffer_size + sizeof(char);

    // Fills config
    wcsncpy_s(shell_param32->ConfigFile, proc_param.data(), proc_param.size());

    return InjectLibraryT(
        this, shell_param32, ThreadProcShell32, sizeof(ThreadProcShell32));
  } 
  
  else if(architecture() == kArchX64) { 
    ZeroMemory(&shell_param, sizeof(shell_param));
    shell_param.LdrLoadDll = proc_entry[0].address;
    shell_param.GetProc = proc_entry[1].address;
    shell_param.NtSetEvent = proc_entry[2].address;
    shell_param.NtClose = proc_entry[3].address;
    shell_param.SignEvent = HandleToUlong64(targt_sign_event);

    shell_param.ShellAddr = HandleToUlong64(allocate_mem.get());
    shell_param.ShellAddrSize = allocate_size;

    // Fills injected dll file path.
    wcsncpy_s(shell_param.InjectDllBuf, dll64.data(), dll64.size());
    buffer_size = static_cast<WORD>(dll64.size() * sizeof(wchar_t));
    shell_param.InjectDll.Length = buffer_size;
    shell_param.InjectDll.MaximumLength = buffer_size + sizeof(wchar_t);

    // Fills main entry
    strncpy_s(shell_param.ProcedureBuf, proc.data(), proc.size());
    buffer_size = static_cast<WORD>(proc.size() * sizeof(char));
    shell_param.Procedure.Length = buffer_size;
    shell_param.Procedure.MaximumLength = buffer_size + sizeof(char);

    // Fills config
    wcsncpy_s(shell_param.ConfigFile, proc_param.data(), proc_param.size());
    
    return InjectLibraryT<ULONG64>(
        this, &shell_param, ThreadProcShell64, sizeof(ThreadProcShell64));
  }

  return kInjectInvalidProcess;
}

}  // namespace rtninja