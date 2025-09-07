// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include "rtninja-core/process.h"

#include <string>
#include <memory>
#include <iostream>
#include <functional>

#include "rtninja-core/internal/native_status.h"
#include "rtninja-core/internal/native_types.h"
#include "rtninja-core/internal/native_ps.h"

namespace rtninja {

namespace {

// --
template <typename Ptr>
bool EnumPEBLdrData(HANDLE process, 
                    nt::PEB_T<Ptr>* peb,
                    std::function<
                        bool(nt::LDR_DATA_TABLE_ENTRY_T<Ptr>*)> callback) {
  Ptr list_entry_ptr = 
      peb->LoaderData + 
      FIELD_OFFSET(nt::PEB_LDR_DATA_T<Ptr>, InLoadOrderModuleList);

  nt::LIST_ENTRY_T<Ptr> list_entry;
  if (!nt::ReadProcessMemory64(process, list_entry_ptr, &list_entry,
                               sizeof(list_entry))) {
    return true;
  }

  Ptr read_ptr = list_entry.Flink;
  nt::LDR_DATA_TABLE_ENTRY_T<Ptr> dll_entry;

  for (;;) {

  if (read_ptr == 0)
    return true;

  if (!nt::ReadProcessMemory64(
          process, read_ptr, &dll_entry, sizeof(dll_entry)) ||
      dll_entry.DllBase == 0) {
    return true;
  }

  if (callback && !callback(&dll_entry))
    return false;

  // read next.
  read_ptr = dll_entry.InLoadOrderLinks.Flink;

  }

  return true;
}

// --
template<class Ptr, class MBI, class Query>
bool EnumModulesByMemoryRegion(const Process* process,
                               bool(*callback)(Process::ModuleEntry*, void*),
                               void* cookie) {
  static constexpr size_t CacheSize = MAX_PATH * 2;
  struct MapFileValue : nt::UNICODE_STRING_T<Ptr> {
    wchar_t Cache[CacheSize];
  };
  std::unique_ptr<MapFileValue> map_file(new MapFileValue);

  Ptr next_base(0);
  MBI mbi;
  while (Query()(process->handle(), next_base, nt::MemoryBasicInformation, 
                 &mbi, sizeof(mbi)) 
             == sizeof(mbi)) {
    next_base += mbi.RegionSize;
    if (mbi.AllocationBase == Ptr(0) || mbi.AllocationBase != mbi.BaseAddress)
      continue;

    // not a valid module.
    WORD machine;
    if (process->EnumerateModuleProcs(mbi.BaseAddress, nullptr, &machine))
      continue;

    map_file->Length = 0;
    map_file->MaximumLength = CacheSize;
    map_file->Buffer = (Ptr)((ULONG_PTR)(map_file->Cache));

    // Queries mapping file name.
    Query()(process->handle(), mbi.BaseAddress, 
            nt::MemoryMappedFilenameInformation,
            map_file.get(), sizeof(MapFileValue));
    if (map_file->Length == 0)
      continue;

    size_t cchr = map_file->Length / sizeof(wchar_t);

    Process::ModuleEntry entry;
    entry.base = mbi.BaseAddress;
    entry.arch_x64 = (machine != IMAGE_FILE_MACHINE_I386);
    entry.full_path.set(map_file->Cache, cchr);
    if (callback && !callback(&entry, cookie))
      return false;
  }

  return true;
}

// --
template <class Ptr>
bool ReadProcessUnicodeString(HANDLE process,
                              const nt::UNICODE_STRING_T<Ptr>* ptr,
                              std::wstring* out) {
  if (out)
    out->clear();

  SIZE_T chr_size = ptr->Length / sizeof(wchar_t);
  if (chr_size == 0 || ptr->MaximumLength == 0)
    return true;

  std::wstring ustr;
  ustr.reserve(chr_size + 1);
  ustr.resize(chr_size);
  if (!nt::ReadProcessMemory64(process, ptr->Buffer, &ustr[0], ptr->Length))
    return false;

  if (out)
    out->swap(ustr);
  return true;
}

// --
template <class Headers>
bool EnumerateModuleProcedures(
    HANDLE process,
    ULONG64 module,
    const Headers* headers,
    std::function<bool(const char*, ULONG64)> callback) {
  IMAGE_EXPORT_DIRECTORY export_dir;
  ULONG64 ptr = headers->OptionalHeader
      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + module;
  SIZE_T size = sizeof(export_dir);
  if (!nt::ReadProcessMemory64(process, ptr, &export_dir, size))
    return true;

  DWORD number_of_names = export_dir.NumberOfNames;
  std::unique_ptr<DWORD[]> names(new DWORD[number_of_names]);
  std::unique_ptr<WORD[]> name_oridinals(new WORD[number_of_names]);
  std::unique_ptr<DWORD[]> funcs(new DWORD[export_dir.NumberOfFunctions]);

  ptr = module + export_dir.AddressOfNames;
  size = number_of_names * sizeof(DWORD);
  if (!nt::ReadProcessMemory64(process, ptr, names.get(), size))
    return true;

  ptr = module + export_dir.AddressOfNameOrdinals;
  size = number_of_names * sizeof(WORD);
  if (!nt::ReadProcessMemory64(process, ptr, name_oridinals.get(), size))
    return true;

  ptr = module + export_dir.AddressOfFunctions;
  size = export_dir.NumberOfFunctions * sizeof(DWORD);
  if (!nt::ReadProcessMemory64(process, ptr, funcs.get(), size))
    return true;

  CHAR func_name[128];
  ULONG64 func_addr;
  for (DWORD i = 0; i < number_of_names; i++) {
    ptr = module + names[i];
    if (!nt::ReadProcessMemory64(
            process, ptr, func_name, sizeof(func_name) - 1))
      return true;

    func_name[sizeof(func_name) - 1] = '\0';
    func_addr = module + funcs[name_oridinals[i]];
    if (callback && !callback(func_name, func_addr))
      return false;
  }

  return true;
}

// --
bool EndsWith(WStringPiece input, WStringPiece comp, bool case_insentive) {
  if (comp.length() > input.length())
    return false;

  size_t start_pos = input.length() - comp.length();
  size_t comp_size = comp.length();
  return case_insentive ?
      !wcsncmp(input.data() + start_pos, comp.data(), comp_size) :
      !_wcsnicmp(input.data() + start_pos, comp.data(), comp_size);
}


}  // namespace 

////////////////////////////////////////////////////////////////////////////////

// --
bool Process::EnumerateModules(bool(*callback)(ModuleEntry*, void*),
                               void* cookie) const {
  ULONG32 peb_address32 = 0;
  ULONG64 peb_address64 = 0ull;
  if (!GetPEB(&peb_address32, &peb_address64))
    return true;

  int count64 = 0;
  bool continue_enum = true;

  nt::PEB64 peb64;
  if (peb_address64 != 0ull &&
      nt::ReadProcessMemory64(process_, peb_address64, &peb64, sizeof(peb64))) {
    continue_enum = EnumPEBLdrData<ULONG64>(process_, &peb64,
        [this, &count64, callback, cookie] (nt::LDR_DATA_TABLE_ENTRY64* entry) {
          std::wstring full_path;
          ReadProcessUnicodeString(process_, &entry->FullDllName, &full_path);

          ModuleEntry info;
          info.base = entry->DllBase;
          info.arch_x64 = count64++ ? true : (architecture() != kArchX86);
          info.full_path = full_path;
          return callback(&info, cookie);
        });
  }

  if (!continue_enum)
    return false;


  int count32 = 0;
  if (peb_address32 != 0ul &&
      nt::ReadProcessMemory64(
          process_, peb_address32, &peb64, sizeof(nt::PEB32))) {
    continue_enum = EnumPEBLdrData<ULONG32>(process_, peb64.AsPtr32(),
        [this, &count64, &count32, callback, cookie] 
              (nt::LDR_DATA_TABLE_ENTRY32* entry) {
          // skip main module...
          if (!count32++ && count64)
            return true;

          std::wstring full_path;
          ReadProcessUnicodeString(process_, &entry->FullDllName, &full_path);

          ModuleEntry info;
          info.base = entry->DllBase;
          info.arch_x64 = false;
          info.full_path = full_path;
          return callback(&info, cookie);
        });
  }

  return continue_enum;
}

// --
bool Process::GetModuleInfo(WStringPiece module_file,
                            bool search_x64_first,
                            ModuleEntry* info) const {
  ZeroMemory(info, sizeof(*info));

  struct Cookie {
    WStringPiece module_file; // once copy!!
    Architecture proc_arch;
    bool search_x64_first;
    ModuleEntry* info;
  } cookie{ module_file, architecture(), search_x64_first, info };

  EnumerateModules([](ModuleEntry* entry, void* cookie) { 
    Cookie* ck = reinterpret_cast<Cookie*>(cookie);
    if (!EndsWith(entry->full_path, ck->module_file, false))
      return true;

    // want seach x64 module first
    if (ck->proc_arch == kArchX86 && ck->search_x64_first && !entry->arch_x64) {
      *(ck->info) = *entry;
      ck->info->full_path_data = entry->full_path.as_string();
      ck->info->full_path = ck->info->full_path_data;
      return true;
    }

    *(ck->info) = *entry;
    ck->info->full_path_data = entry->full_path.as_string();
    ck->info->full_path = ck->info->full_path_data;
    return false;
  }, &cookie);
  return info->base != 0ull;
}

// --
bool Process::EnumerateModules2(bool(*callback)(ModuleEntry*, void*),
                                void* cookie) const {
  struct Query32 {
    SIZE_T operator()(HANDLE a, ULONG b, nt::MEMORY_INFORMATION_CLASS c, 
                      PVOID d, SIZE_T e) {
      return nt::QueryProcessMemory(a, b, c, d, e);
    }
  };
  
  struct Query64 {
    SIZE_T operator()(HANDLE a, ULONGLONG b, nt::MEMORY_INFORMATION_CLASS c, 
                      PVOID d, SIZE_T e) {
      return nt::QueryProcessMemory64(a, b, c, d, e);
    }
  };

  // query 64 module
  if (nt::IsHostAmd64()) {
    return EnumModulesByMemoryRegion<
        ULONGLONG, MEMORY_BASIC_INFORMATION64, Query64>(
          this, callback, cookie);
  } else {
    return EnumModulesByMemoryRegion<
        ULONG, MEMORY_BASIC_INFORMATION32, Query32>(
          this, callback, cookie);
  }
  return true;
}

// --
bool Process::GetModuleInfo2(WStringPiece module_file,
                             bool search_x64_first,
                             ModuleEntry* info) const {
  ZeroMemory(info, sizeof(*info));

  struct Cookie {
    WStringPiece module_file; // once copy!!
    Architecture proc_arch;
    bool search_x64_first;
    ModuleEntry* info;
  } cookie{ module_file, architecture(), search_x64_first, info };

  EnumerateModules2([](ModuleEntry* entry, void* cookie) { 
    Cookie* ck = reinterpret_cast<Cookie*>(cookie);
    if (!EndsWith(entry->full_path, ck->module_file, false))
      return true;

    // wanna gets x64 module at first? 
    // to save x86 module entry and searching next.
    if (ck->proc_arch == kArchX86 && ck->search_x64_first && !entry->arch_x64) {
      *(ck->info) = *entry;
      ck->info->full_path_data = entry->full_path.as_string();
      ck->info->full_path = ck->info->full_path_data;
      return true;
    }

    *(ck->info) = *entry;
    ck->info->full_path_data = entry->full_path.as_string();
    ck->info->full_path = ck->info->full_path_data;
    return false;
  }, &cookie);
  return info->base != 0ull;
}

// --
bool Process::EnumerateModuleProcs(ULONG64 module,
                                   bool(*callback)(const char*,ULONG64,void*),
                                   void* cookie) const {
  IMAGE_DOS_HEADER dos_header;
  if (!nt::ReadProcessMemory64(
          process_, module, &dos_header, sizeof(dos_header))) 
    return true;

  IMAGE_NT_HEADERS64 nt_headers;
  ULONG64 ptr = module + dos_header.e_lfanew;
  SIZE_T size = sizeof(nt_headers);
  if (!nt::ReadProcessMemory64(process_, ptr, &nt_headers, size))
    return true;

  WORD machine = nt_headers.FileHeader.Machine;
  if (machine == IMAGE_FILE_MACHINE_I386) {
    PIMAGE_NT_HEADERS32 nt_headers32 = 
        reinterpret_cast<PIMAGE_NT_HEADERS32>(&nt_headers);
    if (!callback) { 
      if (cookie)
        *(WORD*)cookie = machine;
      return false;
    }

    return EnumerateModuleProcedures(process_, module, nt_headers32, 
      [callback, cookie](const char* name, ULONG64 ptr) {
        // ptr may be hooked from IAT.
        if (!callback(name, ptr & 0xFFFFFFFF, cookie))
          return false;
        return true;
      });
  }
  else if (machine == IMAGE_FILE_MACHINE_AMD64) {
    if (!callback) {
      if (cookie)
        *(WORD*)cookie = machine;
      return false;
    }

    return EnumerateModuleProcedures(process_, module, &nt_headers,
      [callback, cookie](const char* name, ULONG64 ptr) {
        if (!callback(name, ptr, cookie))
          return false;
        return true;
      });
  }

  return true;
}

// --
bool Process::GetModuleProcs(
    ULONG64 module, ProcEntry* proc_entry, ULONG count)  const {
  struct Cookie {
    ProcEntry* proc_entry;
    ULONG count;
    ULONG found_count;
  } cookie { proc_entry, count, 0};
  return !EnumerateModuleProcs(
      module, [](const char* name,  ULONG64 func, void* cookie) {
    Cookie* p = reinterpret_cast<Cookie*>(cookie);
    for (ULONG i = 0; i < p->count; i++) {
      if (!_stricmp(p->proc_entry[i].name, name)) {
        p->proc_entry[i].address = func;
        p->found_count++;
        return p->found_count != p->count;
      }
    }
    return true;
  }, &cookie);
}

}  // namespace rtninja