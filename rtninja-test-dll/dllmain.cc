// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include <windows.h>

EXTERN_C 
VOID __declspec(dllexport) RtNinjaMain(const WCHAR* config) {
  OutputDebugStringA("'RtNinjaMain' invoked.");
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason_for_call, LPVOID) {
  if (reason_for_call == DLL_PROCESS_ATTACH) {
    OutputDebugStringA("dll loaded.");
  }
  return TRUE;
}