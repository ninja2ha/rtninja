// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include <stdio.h>

#include <string>
#include <iostream>

#include "rtninja-core/internal/window_types.h"
#include "rtninja-core/process.h"
#include "rtninja-core/error_util.h"

namespace {

std::wstring GetExeRunDir() {
  wchar_t dir[MAX_PATH] = {0};
  if (!GetModuleFileNameW(NULL, dir, MAX_PATH))
    return std::wstring();

  wchar_t* zero_pos = wcsrchr(dir, '\\');
  if (zero_pos != nullptr)
    zero_pos[1] = L'\0';
  return std::wstring(dir);
}

std::wstring MakeCommandline(const std::wstring& exe, 
                             const std::wstring& param = std::wstring()) {
  std::wstring out;
  out = L"\"";
  out += exe;
  out += L"\"";
  if (!param.empty()) {
    out += L" ";
    out += param;
  }
  return out;
}

int testCreateProcessAndInjectDll(const std::wstring& exe,
                                  const std::wstring& dll32,
                                  const std::wstring& dll64) {
  auto command_line_str = ::MakeCommandline(exe, L"-nothing");
  auto command_line = &command_line_str[0];

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  ZeroMemory(&pi, sizeof(pi));
  si.cb = sizeof(si);

  ::CreateProcessW(NULL, command_line, NULL, NULL, FALSE, 
                   CREATE_SUSPENDED, NULL, NULL, &si, &pi);
  if (pi.hProcess == nullptr) {
    std::wcout << "[WARN]: CreateProcess failed."
               << "cmd=" << command_line_str;
    return 0;
  }

  ResumeThread(pi.hThread);

  Sleep(1000);

  HANDLE sync_event = ::CreateEvent(NULL, TRUE, FALSE, NULL);

  rtninja::Process proc(pi.hProcess);
  auto code = proc.InjectLibraryByThreading(
      sync_event, dll32, dll64, "RtNinjaMain");
  if (rtninja::Process::kInjectOk != code) { 
    DWORD sys_err = ::GetLastError();
    std::wcout << "[WARN]: Injects failed."
               << "injectcode=" << code << ", "
               << "os=" << rtninja::FormatSysErrorToMessage(sys_err) << std::endl;
    
  }

  if (rtninja::Process::kInjectOk == code) {
    DWORD wait_code = ::WaitForSingleObject(sync_event, 5000);
    if (wait_code != WAIT_OBJECT_0) {
      std::wcout << "[WARN]: Waits for sync event failed."
                   << "error=" << wait_code;
    }
  }

  ::CloseHandle(pi.hThread);
  ::CloseHandle(sync_event);

  return 0;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

static const char* g_Tests[] = {
  "-inject32",
  "-inject64"
};

int command_main(const char* command) {
  std::wstring rundir = GetExeRunDir();
  std::wstring run_exe32 = rundir + L"rtninja-test-exe32.exe";
  std::wstring run_exe64 = rundir + L"rtninja-test-exe64.exe";
  std::wstring dll32 = rundir + L"rtninja-test-dll32.dll";
  std::wstring dll64 = rundir + L"rtninja-test-dll64.dll";

  if (!_stricmp(command, "-inject32"))
    return testCreateProcessAndInjectDll(run_exe32, dll32, dll64);

  if (!_stricmp(command, "-inject64"))
    return testCreateProcessAndInjectDll(run_exe64, dll32, dll64);

  return -1;
}

int main(int argc, const char* argv[]) {
  const char* command = nullptr;
  if (argc > 1)
    command = argv[1];

  if (command == nullptr) {
    std::cout << "Input index of cases:" << std::endl;
    for (size_t i = 0; i < ARRAYSIZE(g_Tests); i++) {
      std::cout << "  " << (i + 1) << ". " << g_Tests[i] << std::endl;
    }
    int index;
    std::cin >> index;

    if (index > 0 && index <= ARRAYSIZE(g_Tests)) {
      int r = command_main(g_Tests[index - 1]);
      system("pause");
      return r;
    }
    return -1;
  }

  MessageBox(NULL, NULL, NULL, MB_OK);
  return 0;
}