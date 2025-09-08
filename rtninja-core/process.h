// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_PROCESS_H_
#define RTNINJA_RTNINJA_CORE_PROCESS_H_

#include <windows.h>

#include <memory>
#include <string>

#include "rtninja-core/string_piece.h"
#include "rtninja-core/error_util.h"
#include "rtninja-core/internal/native_types.h"
#include "rtninja-core/internal/compiler_config.h"

namespace rtninja {

class Process {
 public:
  explicit Process(HANDLE process_handle, bool closing_process = true);
  ~Process();

  enum Architecture {
    kArchUnknow,
    kArchX86,
    kArchX64
  };

  // Returns process architecture or Architecture::kArchUnknow on error.
  Architecture architecture() const { return process_arch_; }

  // Returns currently process handle.
  HANDLE handle() const {return process_; }

  // Returns true on valid. otherwise false.
  bool IsValid() const { return process_arch_ != kArchUnknow; }

  // -- Mem op -----------------------------------------------------------------

  // Returns number of peb. wow64 process has two diffent peb address. 
  // REQUIRED ACCESS: 
  // - PROCESS_QUERY_INFORMATION
  int GetPEB(ULONG32* peb32, ULONG64* peb64) const;

  // Reads process memory. 
  // Returns bytes of readed memory, which value is 0 on error.
  // NOTE: Calling GetLastError to get more deatils.
  // REQUIRED ACCESS: 
  // - PROCESS_VM_READ
  SIZE_T ReadMem64(ULONGLONG address, PVOID buffer, SIZE_T read_size) const;

  // Writes process memory. 
  // Returns bytes of wrote memory, which value is 0 on error.
  // NOTE: Calling GetLastError to get more deatils.
  // REQUIRED ACCESS: 
  // - PROCESS_VM_WRITE
  SIZE_T WriteMem64(ULONGLONG address, PVOID buffer, SIZE_T write_size) const;

  // -- Ldr start --------------------------------------------------------------

  class ModuleEntry {
   public:
    ULONG64 base;                // base of image.
    WStringPiece full_path;      // full path of image.
    bool arch_x64;               // checks if image is x64-architecture.

   private:
    friend class Process;
    std::wstring full_path_data; // an stroage for full_path. reserved for 
                                 // 'GetModuleInfo' | 'GetModuleInfo2'.
  };

  // Enumerates modules by reading peb ldr data.
  // Returns false on user aborted.
  // NOTE: Calling GetLastError to get more details.
  // WARN: Invoking this method after CreateProcess will get a empty result. 
  //       using EnumerateModules2 to instead of.
  // REQUIRED ACCESS: 
  // - PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  bool EnumerateModules(bool(* callback)(ModuleEntry*, void*),
                        void* cookie) const;

  // Returns true on success and false on error.
  // Setting |search_x64_first| as true, if you want to get x64 module entries 
  // from a wow64-process.
  // NOTE: Calling GetLastError() to get more detail...
  // WARN: Invoking this method after CreateProcess will get a empty result. 
  //       using GetModuleInfo2 to instead of.
  // REQUIRED ACCESS: 
  // - PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  bool GetModuleInfo(WStringPiece module_file,
                     bool search_x64_first,
                     ModuleEntry* info) const;

  // Enumerates modules by querying virtual memoryt information. 
  // Returns false on user aborted.
  // NOTE: Calling ::GetLastError() to get more details.
  // REQUIRED ACCESS: 
  // - PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  bool EnumerateModules2(bool(* callback)(ModuleEntry*, void*),
                         void* cookie) const;

  // NOTE: To see document of |GetModuleInfo|.
  bool GetModuleInfo2(WStringPiece module_file,
                      bool search_x64_first,
                      ModuleEntry* info) const;

  // Returns false on user aborted or means the |module| is valid if
  // |callback| is passed a nullptr and NtHeaders.FileHeader.Machine will be
  // wrote into |cookie|.
  // NOTE: Calling ::GetLastError() to get more details.
  // REQUIRED ACCESS: 
  // - PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  bool EnumerateModuleProcs(ULONG64 module,
                            bool(* callback)(const char*, ULONG64, void*),
                            void* cookie) const;

  struct ProcEntry {
    const char* name; // input
    ULONG64 address;  // out
  };
  // Returns true on found all of procedures.
  // NOTE: Calling ::GetLastError() to get more details.
  // REQUIRED ACCESS: 
  // - PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  bool GetModuleProcs(ULONG64 module, ProcEntry* proc_info, ULONG proc_count) 
      const;

  // -- injector  --------------------------------------------------------------

  enum InjectError {
    kInjectOk = 0,        // injects successed.
    kInjectInvalidProcess,// the target process is invalid.
    kInjectDllPath,       // the length of dllpath is too long. required < 260.
    kInjectProcName,      // the length of proc is too long. required < 64
    kInjectProcParam,    // the length of procparam is too long. required < 260
    kInjectQueryModule,   // failed to invoke GetModuleInfo | GetModuleInfo2
                          // calling ::GetLastError() to get more details.
    kInjectQueryModuleProc, // failed to invoke EnumerateModuleProcs
                            // calling ::GetLastError() to get more details.
    kInjectAllocShell,    // failed to allocate shell memory. 
                          // calling ::GetLastError() to get more details.
    kInjectWriteShell,    // failed to write shell memory
                          // calling ::GetLastError() to get more details.
    kInjectReadHook,      // failed to read hook code to target process.
                          // calling ::GetLastError() to get more details.
    kInjectWriteHook,     // failed to write hook code to target process.
                          // calling ::GetLastError() to get more details.
  };
  // Returns InjectError code.
  // NOTE:
  // |sync_event|: this is a event handle to sign after 'RtNinjaMain' invoked.
  // |proc|: this is the name of exports function which was wrote as 
  //        'void RtNinjaMain(const wchar_* proc_param) {} '
  // REQUIRED ACCESS: 
  // - PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION
  InjectError InjectLibraryAfterCreateProcess(
      HANDLE sync_event,
      const WStringPiece& dll32,
      const WStringPiece& dll64,
      const StringPiece& proc = StringPiece(),
      const WStringPiece& proc_param = WStringPiece()) const;

 private:
  // -- Mem op(private) --------------------------------------------------------

  // Reads 'Buffer' of UnicodeString from target process.
  // Return true on success and values are wrote into |out|.
  // Retrun false on error or invoking ::GetLastError() to get more details.
  bool ReadUnicodeString32(const nt::UNICODE_STRING32* ustr, std::wstring* out)
      const;
  bool ReadUnicodeString64(const nt::UNICODE_STRING64* ustr, std::wstring* out)
      const;

  // Initializes architecture of process.
  void InitializeProcessArch();

  HANDLE process_;
  bool closing_process_;
  Architecture process_arch_ = kArchUnknow;
};

}  // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_PROCESS_H_
