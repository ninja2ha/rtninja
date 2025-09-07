// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include "rtninja-core/process.h"

#include "rtninja-core/internal/native_types.h"
#include "rtninja-core/internal/native_ps.h"
#include "rtninja-core/internal/compiler_config.h"

namespace rtninja {

Process::Process(HANDLE process_handle, bool closing_process)
    : process_(process_handle),
      closing_process_(closing_process) {
  InitializeProcessArch();
}

Process::~Process() {
  if (closing_process_) {
    ::CloseHandle(process_);
    process_ = nullptr;
  }
}

void Process::InitializeProcessArch() {
  BOOL is_wow64;
  if (!IsWow64Process(process_, &is_wow64))
    return ;  // error

#if defined(RTNINJA_ARCH_CPU_X86)
  if (is_wow64) {
    process_arch_ = kArchX86;
    return ;
  }

  // Gets wow64 status of self-process is very fast and safe.
  // It`s just read from the contexnt of thread.
  BOOL os_is64bit = FALSE;
  IsWow64Process(GetCurrentProcess(), &os_is64bit);
  process_arch_ = os_is64bit ? kArchX64 : kArchX86;

#elif defined(RTNINJA_ARCH_CPU_X86_64)
  process_arch_ = is_wow64 ? kArchX86 : kArchX64;
#endif
}

SIZE_T Process::ReadMem64(ULONGLONG address, PVOID buffer, SIZE_T read_size) 
    const {
  nt::ReadProcessMemory64(process_, address, buffer, read_size, &read_size);
  return read_size;
}

SIZE_T Process::WriteMem64(ULONGLONG address, PVOID buffer, SIZE_T write_size) 
    const {
  nt::WriteProcessMemory64(process_, address, buffer, write_size, &write_size);
  return write_size;
}

int Process::GetPEB(ULONG32* peb32, ULONG64* peb64) const {
#if defined(RTNINJA_ARCH_CPU_X86)
  int count = 0;

  nt::PROCESS_BASIC_INFORMATION64 buffer;
  SIZE_T buffer_size = sizeof(nt::PROCESS_BASIC_INFORMATION32);
  if (architecture() == kArchX86 &&
      nt::QueryProcessInformation(
          process_, nt::ProcessBasicInformation, &buffer, buffer_size)) {
    *peb32 = buffer.AsPtr32()->PebBaseAddress;
    count++;
  }

  buffer_size = sizeof(nt::PROCESS_BASIC_INFORMATION64);
  if (nt::QueryProcessInformation64(
          process_, nt::ProcessBasicInformation, &buffer, buffer_size)) {
    *peb64 = buffer.PebBaseAddress;
    count++;
  }

  return count;
#elif defined(RTNINJA_ARCH_CPU_X86_64)
  int count  = 0;

  nt::PROCESS_BASIC_INFORMATION64 buffer;
  if (nt::QueryProcessInformation64(
          process_, nt::ProcessBasicInformation, &buffer, sizeof(buffer))) {
    *peb64 = buffer.PebBaseAddress;
    count++;
  }

  // https://stackoverflow.com/questions/34736009/get-32bit-peb-of-another-process-from-a-x64-process
  if (process_arch_ == kArchX86 && count) {
    *peb32 = (ULONG32)(*peb64 + 0x1000);
    count++;
  }

  return count;
#endif
}

}  // namespace ninja_core