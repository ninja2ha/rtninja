// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include "rtninja-core/error_util.h"

#include <windows.h>

namespace rtninja {

std::wstring SystemErrorCode2Hex(unsigned long error_code) {
  static_assert(sizeof(error_code) == 4, 
                "Invalid type of SystemErrorCode!");
  wchar_t str[] = L"0x00000000";
  for (int i = 7; i >= 0; i--) {
    unsigned long chr = error_code & 0xf;
    str[i + 2] 
		    = static_cast<char>(chr >= 10 ? (chr - 10) + L'A' : (chr + L'0'));
    error_code >>= 4;
  }
  return str;
}

// Formats dos error code to a message. 
std::wstring FormatSysErrorToMessage(unsigned long error_code) {
  constexpr DWORD kErrorMessageBufferSize = 256;
  wchar_t msgbuf[kErrorMessageBufferSize];
  DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  DWORD len = ::FormatMessageW(flags, nullptr, error_code, 0, msgbuf,
                               kErrorMessageBufferSize, nullptr);
  DWORD format_err = GetLastError();
  if (len) {
    // Messages returned by system end with line breaks. so remove it.
    while (--len) {
      if (msgbuf[len] == '\r' || msgbuf[len] == '\n') {
        msgbuf[len] = '\0';
        continue;
      }
      break;
    }
    std::wstring wide = msgbuf;
    wide += SystemErrorCode2Hex(error_code);
    return wide;
  }

  std::wstring wide;
  wide = L"Error (";
  wide += SystemErrorCode2Hex(format_err);
  wide += L") while retrieving error. (";
  wide += SystemErrorCode2Hex(error_code);
  wide += L")";
  return wide;
}

}  // namespace rtninja