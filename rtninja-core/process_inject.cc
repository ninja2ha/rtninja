// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include "rtninja-core/process.h"

#include <iostream>

#include "rtninja-core/internal/native_types.h"
#include "rtninja-core/internal/native_ps.h"
#include "rtninja-core/scoped_handle.h"
#include "rtninja-core/scoped_mem.h"

namespace rtninja {

namespace {

constexpr size_t kProcedureNameMaxLen = 64;

struct alignas(sizeof(void*)) ShellParam {
  PCWSTR DllPath; // LdrLoadDll first param
  PVOID ShellAddr;  // ecx + 4] (x86), ecx + 8](x64)
  SIZE_T ShellAddrSize; // ecx + 8] (x86, ecx + 10](x64)

  nt::LdrLoadDllFunc LdrLoadDll;
  nt::LdrGetProcedureAddressFunc GetProc;
  nt::NtProtectVirtualMemoryFunc ProtectMem;
  nt::NtWriteVirtualMemoryFunc WriteMem;
  nt::NtSetEventFunc NtSetEvent;
  nt::NtCloseFunc NtClose;

  // Dulipcate handle
  HANDLE SignEvent;

  // Restore
  BYTE OrignalCode[32];

  // Injectlib & Calling
  nt::UNICODE_STRING InjectDll;
  nt::ANSI_STRING Procedure;

  WCHAR InjectDllBuf[MAX_PATH];
  CHAR ProcedureBuf[kProcedureNameMaxLen];
  WCHAR ConfigFile[MAX_PATH];
};

NTSTATUS NTAPI LdrLoadDllImpl(__in ShellParam* p,
                              __in_opt PULONG DllCharacteristics,
                              __in nt::UNICODE_STRING* DllName,
                              __out PVOID *DllHandle) {
  NTSTATUS s = 0;
  // restore code..
  SIZE_T hook_size = sizeof(p->OrignalCode);
  PVOID hook_address = p->LdrLoadDll;

  PVOID protect_addr = hook_address;
  SIZE_T protect_size = hook_size;
  ULONG old_protect = 0;

  p->ProtectMem(
      INVALID_HANDLE_VALUE, &protect_addr, &protect_size, PAGE_EXECUTE_READWRITE,
      &old_protect);
  s = p->WriteMem(
      INVALID_HANDLE_VALUE, hook_address, p->OrignalCode, hook_size, 
      &hook_size);
  p->ProtectMem(
      INVALID_HANDLE_VALUE, &protect_addr, &protect_size, old_protect,
      &old_protect);

  if (NT_SUCCESS(s))  {
    // LoadOrigalDll
    s = p->LdrLoadDll(p->DllPath, DllCharacteristics, DllName, DllHandle);

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
  }

  if (!NT_SUCCESS(s)) {
    // Restores hook failed, make a crash.
    __debugbreak();
  }

  p->NtSetEvent(p->SignEvent);
  p->NtClose(p->SignEvent);

  return s;
}

// shellcode of LdrLoadDllImpl
static const ULONG32 LdrLoadDllShell32[] = { 
  0x83EC8B55, 0x57560CEC, 0x8D087D8B, 0x6A500845, 0xF8458D40, 0x20FC45C7, 
  0x8B000000, 0x8D500C77, 0x7589F445, 0x478B50F4, 0xC7FF6A14, 0x0020F845, 
  0x45C70000, 0x00000008, 0x8DD0FF00, 0xFF50FC45, 0x478DFC75, 0x478B5028, 
  0xFF6A5618, 0xF08BD0FF, 0x5008458D, 0x8D0875FF, 0x8D50F845, 0x8B50F445, 
  0xFF6A1447, 0xF685D0FF, 0x75FF6E78, 0x0C478B14, 0xFF1075FF, 0x37FF0C75, 
  0xF08BD0FF, 0x001445C7, 0x8D000000, 0x47895847, 0x14458D4C, 0x48478D50,
  0x0C478B50, 0x006A006A, 0x4D8BD0FF, 0x74C98514, 0x60878D33, 0xC7000002, 
  0x00001045, 0x47890000, 0x10458D54, 0x8D006A50, 0x8B505047, 0xFF511047, 
  0x104D8BD0, 0x0C74C985, 0x02A0878D, 0xFF500000, 0x04C483D1, 0x0179F685, 
  0x2477FFCC, 0xFF1C478B, 0x2477FFD0, 0xFF20478B, 0xC68B5FD0, 0x5DE58B5E, 
  0xCC0010C2
};

// shellcode of LdrLoadDllImpl
static const ULONG64 LdrLoadDllShell64[] {
  0x49105B8949DC8B4C, 0x4856415756186B89, 0x4918598B4860EC83, 0xC749F98B4808438D, 
  0x8B4900000020B843, 0xE88B49C85B8949F1, 0x00000020C043C749, 0x000843C741F28B4C, 
  0x000040B941000000, 0x438D4DA843894900, 0x538D49FFC98348C0, 0x244C8B4C2857FFC8, 
  0x8D4C3024448D4830, 0x4820244489485047, 0x57FFFFC98348D38B, 0x000080248C8B4430, 
  0xD88B3824448D4C00, 0x848D484024548D48, 0xC983480000008024, 0x57FF2024448948FF, 
  0x0F8B487F78DB8528, 0x8B49C58B4CCE8B4C, 0x70478D4C1857FFD6, 0x000000482444C748, 
  0x48244C8D4CD88B00, 0x3300000090878D48, 0xFF78478948C933D2, 0x4848244C8B481857, 
  0x98878D483C74C985, 0x502444C748000002, 0x80978D4800000000, 0x0088878948000000, 
  0x4550244C8D4C0000, 0x448B482057FFC033, 0x480974C085485024, 0xD0FF000002D88F8D, 
  0x4F8B48CC0179DB85, 0x484F8B483857FF48, 0x60245C8D4C4057FF, 0x8B49285B8B49C38B, 
  0x5F5E41E38B49306B, 0xCCCCCCCCCCCCC35E
};

////////////////////////////////////////////////////////////////////////////////

template <class Ptr>
struct alignas(sizeof(Ptr)) ShellParamT 
    : nt::internal::AS_POINTER_T<ShellParamT<ULONG32>> {
  // same with ShellParam, don not change order of members.
  Ptr DllPath; // LdrLoadDll first param
  Ptr ShellAddr;  // ecx + 4] (x86), ecx + 8](x64)
  Ptr ShellAddrSize; // ecx + 8] (x86, ecx + 10](x64)

  Ptr LdrLoadDll;
  Ptr GetProc;
  Ptr ProtectMem;
  Ptr WriteMem;
  Ptr NtSetEvent;
  Ptr NtClose;

  // Dulipcate handle
  Ptr SignEvent;

  // Restore
  BYTE OrignalCode[32];

  // Injectlib & Calling
  nt::UNICODE_STRING_T<Ptr> InjectDll;
  nt::ANSI_STRING_T<Ptr> Procedure;

  WCHAR InjectDllBuf[MAX_PATH];
  CHAR ProcedureBuf[kProcedureNameMaxLen];
  WCHAR ConfigFile[MAX_PATH];
};

Process::InjectError InjectLibrary32(const Process* process,
                                     const ShellParamT<ULONG32>* param) {
  constexpr size_t hook_size = sizeof(param->OrignalCode);
  if (!process->ReadMem64(param->LdrLoadDll,
                          const_cast<BYTE*>(param->OrignalCode), hook_size)) {
    return Process::kInjectReadHook;
  }

  std::unique_ptr<BYTE[]> codes(new BYTE[4096]);

  BYTE* next_ptr = codes.get();

  // Writes shellcode param;
  constexpr size_t func_offset = ((sizeof(*param) + 0x10) & 0xFFFFFFF0);
  memcpy(next_ptr, param, sizeof(*param));
  next_ptr += func_offset;

  // Makes top shell code :
  // - ;thunk_code_up
  // - nop
  // - nop
  // - mov eax, shell_param
  // - push [esp + 4]
  // - pop [eax]
  // - mov [esp + 4], eax
  // - nop
  // - nop
  // - ;LdrLoadDllImpl Shellcode
  // - ...
  // - ;thunk_code_down
  // - jmp kernel32.VirtualFreeEx??(not implement currently)
  ULONG32 thunk_code_up[] = {
      0xB8909090, 0x0000000, 0x042474FF, 0x4489008F, 0x90900424};
  thunk_code_up[1] = param->ShellAddr;
  memcpy(next_ptr, thunk_code_up, sizeof(thunk_code_up));
  next_ptr += sizeof(thunk_code_up);

  memcpy(next_ptr, LdrLoadDllShell32, sizeof(LdrLoadDllShell32));
  next_ptr += sizeof(LdrLoadDllShell32);

  SIZE_T code_size = next_ptr - codes.get();
  if (!process->WriteMem64(param->ShellAddr, codes.get(), code_size))
    return Process::kInjectWriteShell;

  ScopedMemAccess64 access(process->handle(), param->LdrLoadDll, 12);

  thunk_code_up[1] = param->ShellAddr + func_offset;
  thunk_code_up[2] = 0x9090E0FF;
  if (!process->WriteMem64(param->LdrLoadDll, thunk_code_up, 12))
    return Process::kInjectWriteHook;

  return Process::kInjectOk;
}

Process::InjectError InjectLibrary64(const Process* process,
                                     const ShellParamT<ULONG64>* param) {
  constexpr size_t hook_size = sizeof(param->OrignalCode);
  if (!process->ReadMem64(param->LdrLoadDll,
                          const_cast<BYTE*>(param->OrignalCode), hook_size)) {
    return Process::kInjectReadHook;
  }

  std::unique_ptr<BYTE[]> codes(new BYTE[4096]);

  BYTE* next_ptr = codes.get();

  // Writes param;
  constexpr size_t func_offset = ((sizeof(*param) + 0x10) & 0xFFFFFFF0);
  memcpy(next_ptr, param, sizeof(*param));
  next_ptr += func_offset;

  // Makes top shell code :
  // - ;thunk_code_up
  // - mov rax, shell_param
  // - mov [rax], rcx
  // - mov rcx, rax
  // - ;LdrLoadDllImpl Shellcode
  // - ...
  // - ;thunk_code_down
  // - jmp kernel32.VirtualFreeEx?? (not implement currently)
  ULONG32 thunk_code_up[] = {
      0xB8489090, 0x55667788, 0x11223344, 0x48088948, 0x9090C88B};

  *(ULONG64*)(thunk_code_up + 1) = param->ShellAddr;
  memcpy(next_ptr, thunk_code_up, sizeof(thunk_code_up));
  next_ptr += sizeof(thunk_code_up);

  memcpy(next_ptr, LdrLoadDllShell64, sizeof(LdrLoadDllShell64));
  next_ptr += sizeof(LdrLoadDllShell64);

  // Writes shellcode
  SIZE_T code_size = next_ptr - codes.get();
  if (!process->WriteMem64(param->ShellAddr, codes.get(), code_size))
    return Process::kInjectWriteShell;

  // Writes hook code
  ScopedMemAccess64 access(process->handle(), param->LdrLoadDll, 16);

  *(ULONG64*)(thunk_code_up + 1) = param->ShellAddr + func_offset;
  thunk_code_up[3] = 0x9090E0FF;
  if (!process->WriteMem64(param->LdrLoadDll, thunk_code_up, 16))
    return Process::kInjectWriteHook;

  return Process::kInjectOk;
}

}  // namesapce

////////////////////////////////////////////////////////////////////////////////

rtninja::Process::InjectError Process::InjectLibraryByHookingLdrLoadDll(
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
  DWORD protect_mem[] = { 
    0x7250744E, 0x6365746F, 0x72695674, 0x6C617574,0x6F6D654D, 0x00007972};
  DWORD write_mem[] = {
    0x7257744E, 0x56657469, 0x75747269, 0x654D6C61, 0x79726F6D, 0x00000000};
  DWORD set_event[] = {
    0x6553744E, 0x65764574, 0x0000746E, 0x00000000};
  DWORD free_mem[] = {
    0x7246744E, 0x69566565, 0x61757472, 0x6D654D6C, 0x0079726F};
  DWORD nt_close[] = {
    0x6C43744E, 0x0065736F, 0x00000000 };

  ProcEntry proc_entry[] = {
    { reinterpret_cast<const char*>(ldr_load_dll), 0 }, // 0
    { reinterpret_cast<const char*>(get_proc), 0 },     // 1
    { reinterpret_cast<const char*>(write_mem), 0 },    // 2
    { reinterpret_cast<const char*>(set_event), 0 },    // 3
    { reinterpret_cast<const char*>(nt_close), 0 },     // 4
    { reinterpret_cast<const char*>(free_mem), 0 },     // 5
    { reinterpret_cast<const char*>(protect_mem), 0 },  // 6
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
    shell_param32->WriteMem = HandleToUlong32(proc_entry[2].address);
    shell_param32->NtSetEvent = HandleToUlong32(proc_entry[3].address);
    shell_param32->NtClose = HandleToUlong32(proc_entry[4].address);
    shell_param32->ProtectMem = HandleToUlong32(proc_entry[6].address);
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

    InjectError code = InjectLibrary32(this, shell_param32);
    if (code == kInjectOk) {
      // Shellcode may be not run. so let the shellcode release it.
      allocate_mem.release();
    }
    return code;
  } 
  
  else if(architecture() == kArchX64) { 
    ZeroMemory(&shell_param, sizeof(shell_param));
    shell_param.LdrLoadDll = proc_entry[0].address;
    shell_param.GetProc = proc_entry[1].address;
    shell_param.WriteMem = proc_entry[2].address;
    shell_param.NtSetEvent = proc_entry[3].address;
    shell_param.NtClose = proc_entry[4].address;
    shell_param.ProtectMem = proc_entry[6].address;
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

    InjectError code = InjectLibrary64(this, &shell_param);
    if (code == kInjectOk) {
      // Shellcode may be not run. so let the shellcode release it.
      allocate_mem.release();
    }
    return code;
  }

  return kInjectInvalidProcess;
}

}  // namespace rtninja