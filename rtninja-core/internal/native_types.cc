// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.
#include "rtninja-core/internal/native_types.h"

#include <memory>

#include "rtninja-core/internal/native_ps.h"
#include "rtninja-core/internal/no_destructor.h"
#include "rtninja-core/internal/pe_image.h"
#include "rtninja-core/internal/compiler_config.h"

namespace rtninja {
namespace nt {

namespace {

const BYTE g_X64CallShell[] = {
  0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x10, 0x8D, 0x55, 0x14, 0x83, 0xEC, 0x40, 0x53, 
  0x56, 0x57, 0x85, 0xC9, 0x7E, 0x15, 0x8B, 0x45, 0x14, 0x8D, 0x55, 0x1C, 0x49, 
  0x89, 0x45, 0xF0, 0x8B, 0x45, 0x18, 0x89, 0x4D, 0x10, 0x89, 0x45, 0xF4, 0xEB, 
  0x08, 0x0F, 0x57, 0xC0, 0x66, 0x0F, 0x13, 0x45, 0xF0, 0x85, 0xC9, 0x7E, 0x15, 
  0x49, 0x83, 0xC2, 0x08, 0x89, 0x4D, 0x10, 0x8B, 0x42, 0xF8, 0x89, 0x45, 0xE8, 
  0x8B, 0x42, 0xFC, 0x89, 0x45, 0xEC, 0xEB, 0x08, 0x0F, 0x57, 0xC0, 0x66, 0x0F, 
  0x13, 0x45, 0xE8, 0x85, 0xC9, 0x7E, 0x15, 0x49, 0x83, 0xC2, 0x08, 0x89, 0x4D, 
  0x10, 0x8B, 0x42, 0xF8, 0x89, 0x45, 0xE0, 0x8B, 0x42, 0xFC, 0x89, 0x45, 0xE4, 
  0xEB, 0x08, 0x0F, 0x57, 0xC0, 0x66, 0x0F, 0x13, 0x45, 0xE0, 0x85, 0xC9, 0x7E, 
  0x15, 0x49, 0x83, 0xC2, 0x08, 0x89, 0x4D, 0x10, 0x8B, 0x42, 0xF8, 0x89, 0x45, 
  0xD8, 0x8B, 0x42, 0xFC, 0x89, 0x45, 0xDC, 0xEB, 0x08, 0x0F, 0x57, 0xC0, 0x66, 
  0x0F, 0x13, 0x45, 0xD8, 0x8B, 0xC1, 0x89, 0x55, 0xC0, 0x99, 0x0F, 0x57, 0xC0, 
  0x66, 0x0F, 0x13, 0x45, 0xC8, 0xC7, 0x45, 0xC4, 0x00, 0x00, 0x00, 0x00, 0x89, 
  0x45, 0xD0, 0x89, 0x55, 0xD4, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xC7, 
  0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x8C, 0x65, 0xF8, 0xB8, 0x2B, 0x00,
  0x00, 0x00, 0x66, 0x8E, 0xE0, 0x89, 0x65, 0xFC, 0x83, 0xE4, 0xF0, 0x6A, 0x33, 
  0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB, 0x48, 0x8B, 0x4D, 
  0xF0, 0x48, 0x8B, 0x55, 0xE8, 0xFF, 0x75, 0xE0, 0x49, 0x58, 0xFF, 0x75, 0xD8, 
  0x49, 0x59, 0x48, 0x8B, 0x45, 0xD0, 0xA8, 0x01, 0x75, 0x03, 0x83, 0xEC, 0x08, 
  0x57, 0x48, 0x8B, 0x7D, 0xC0, 0x48, 0x85, 0xC0, 0x74, 0x16, 0x48, 0x8D, 0x7C, 
  0xC7, 0xF8, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0xFF, 0x37, 0x48, 0x83, 0xEF, 0x08, 
  0x48, 0x83, 0xE8, 0x01, 0xEB, 0xEF, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0x55, 0x08, 
  0x48, 0x8B, 0x4D, 0xD0, 0x48, 0x8D, 0x64, 0xCC, 0x20, 0x5F, 0x48, 0x89, 0x45, 
  0xC8, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 
  0x00, 0x83, 0x04, 0x24, 0x0D, 0xCB, 0x66, 0x8C, 0xD8, 0x66, 0x8E, 0xD0, 0x8B, 
  0x65, 0xFC, 0x66, 0x8B, 0x45, 0xF8, 0x66, 0x8E, 0xE0, 0x8B, 0x45, 0xC8, 0x8B, 
  0x55, 0xCC, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3
};

ULONGLONG GetModuleFromPeb64(HANDLE process, PEB64* peb) {
  if (process == NULL)
    return 0;

  PEB_LDR_DATA64 loaded_data;
  if (!ReadProcessMemory64(
          process, peb->LoaderData, &loaded_data, sizeof(loaded_data))) {
    return 0;
  }

  LDR_DATA_TABLE_ENTRY64 module;
  if (!ReadProcessMemory64(process, 
                           loaded_data.InLoadOrderModuleList.Flink, 
                           &module, sizeof(module))) {
    return 0;
  }

  if (!ReadProcessMemory64(
          process, module.InLoadOrderLinks.Flink, &module, sizeof(module))) {
    return 0;
  }

  return module.DllBase;
}

BOOL EnumerateModuleProcedures64(
    HANDLE process,
    ULONGLONG module,
    BOOL(*callback)(const char*, ULONGLONG, void*),
    void* cookie) {
  if (process == NULL)
    return TRUE;

  IMAGE_DOS_HEADER dos_header;
  ULONGLONG ptr = module;
  SIZE_T size = sizeof(dos_header);
  if (!ReadProcessMemory64(process, ptr, &dos_header, size))
    return TRUE;

  IMAGE_NT_HEADERS64 nt_headers;
  ptr = dos_header.e_lfanew + module;
  size = sizeof(IMAGE_NT_HEADERS64);
  if (!ReadProcessMemory64(process, ptr, &nt_headers, size))
    return TRUE;

  IMAGE_EXPORT_DIRECTORY export_dir;
  ptr = nt_headers.OptionalHeader
      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + module;
  size = sizeof(export_dir);
  if (!ReadProcessMemory64(process, ptr, &export_dir, size))
    return TRUE;

  DWORD number_of_names = export_dir.NumberOfNames;
  std::unique_ptr<DWORD[]> names(new DWORD[number_of_names]);
  std::unique_ptr<WORD[]> name_oridinals(new WORD[number_of_names]);
  std::unique_ptr<DWORD[]> funcs(new DWORD[export_dir.NumberOfFunctions]);

  ptr = module + export_dir.AddressOfNames;
  size = number_of_names * sizeof(DWORD);
  if (!ReadProcessMemory64(process, ptr, names.get(), size))
    return TRUE;

  ptr = module + export_dir.AddressOfNameOrdinals;
  size = number_of_names * sizeof(WORD);
  if (!ReadProcessMemory64(process, ptr, name_oridinals.get(), size))
    return TRUE;

  ptr = module + export_dir.AddressOfFunctions;
  size = export_dir.NumberOfFunctions * sizeof(DWORD);
  if (!ReadProcessMemory64(process, ptr, funcs.get(), size))
    return TRUE;

  CHAR func_name[128];
  ULONG64 func_addr;
  for (DWORD i = 0; i < number_of_names; i++) {
    ptr = module + names[i];
    if (!ReadProcessMemory64(process, ptr, func_name, sizeof(func_name) - 1))
      return TRUE;

    func_name[sizeof(func_name) - 1] = '\0';
    func_addr = module + funcs[name_oridinals[i]];
    if (callback && !callback(func_name, func_addr, cookie))
      return FALSE;
  }

  return TRUE;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

BOOL IsHostAmd64() {
#if defined(RTNINJA_ARCH_CPU_X86)
  static const NoDestructor<BOOL> wow64([]() -> BOOL {
    BOOL is_wow64;
    ::IsWow64Process(INVALID_HANDLE_VALUE, &is_wow64);
    return is_wow64;
  }());
  return *wow64;
#elif defined(RTNINJA_ARCH_CPU_X86_64)
  return TRUE;
#endif
}

HMODULE GetModule() {
  static const NoDestructor<HMODULE> module([]() -> HMODULE {
    TEB* teb = reinterpret_cast<TEB*>(NtCurrentTeb());
    PEB* peb = reinterpret_cast<PEB*>(teb->Peb);

    PEB_LDR_DATA* loaded_data = 
        reinterpret_cast<PEB_LDR_DATA*>(peb->LoaderData);
    if (loaded_data == nullptr)
      return nullptr;

    LDR_DATA_TABLE_ENTRY* module = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
        loaded_data->InLoadOrderModuleList.Flink);
    if (module == nullptr)
      return nullptr;

    module = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
        module->InLoadOrderLinks.Flink);
    return reinterpret_cast<HMODULE>(module->DllBase);
  }());
  return *module;
}

ULONGLONG GetModule64() {
#if defined(RTNINJA_ARCH_CPU_X86)
  static const NoDestructor<ULONGLONG> module([]() -> ULONGLONG {
    if (!IsHostAmd64())
      return 0ull;

    TEB* teb = reinterpret_cast<TEB*>(NtCurrentTeb());
    // https://stackoverflow.com/questions/34736009/get-32bit-peb-of-another-process-from-a-x64-process
    PEB64* peb64 = reinterpret_cast<PEB64*>(teb->Peb - 0x1000);

    return GetModuleFromPeb64(CurrentProcess(), peb64);
  }());
  return *module;
#elif defined(RTNINJA_ARCH_CPU_X86_64) 
  return reinterpret_cast<ULONGLONG>(GetModule());
#endif // RTNINJA_ARCH_CPU_X86
}

FARPROC GetProcedure(CONST CHAR* name) {
  PEImage pe_image(GetModule());
  return pe_image.GetProcAddress(name, nullptr);
}

ULONGLONG GetProcedure64(CONST CHAR* name) {
#if defined(RTNINJA_ARCH_CPU_X86)
  ULONGLONG ntdll = GetModule64();
  if (ntdll == 0ull)
    return 0ull;

  struct Cookie {
    const CHAR* name;
    ULONGLONG address;
  } cookie{name, 0ull};

  EnumerateModuleProcedures64(CurrentProcess(), ntdll, 
      [] (const char* name, ULONGLONG func, void* ud) -> BOOL {
    Cookie* cookie = reinterpret_cast<Cookie*>(ud);
    if (_stricmp(name, cookie->name))
      return TRUE;
    cookie->address = func;
    return FALSE;
  }, &cookie);

  return cookie.address;

#elif defined(RTNINJA_ARCH_CPU_X86_64) 
  return reinterpret_cast<ULONGLONG>(GetProcedure(name));
#endif
}

#if defined(RTNINJA_ARCH_CPU_X86)
X64Call GetX64Call() {
  if (!IsHostAmd64())
    return NULL;

  static const NoDestructor<X64Call> x64call([]() -> X64Call {
    X64Call call;
    call = reinterpret_cast<X64Call>(
        VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (call)
      memcpy(call, g_X64CallShell, sizeof(g_X64CallShell));
    return call;
  }());
  return *x64call;
}
#endif

}  // namespace nt
}  // namespace rtninja
