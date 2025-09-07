// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#include "rtninja-core/internal/native_status.h"

#include "rtninja-core/internal/native_types.h"
#include "rtninja-core/internal/no_destructor.h"

namespace rtninja {
namespace nt { 

namespace {

RTNINJA_NT_API(
    RtlNtStatusToDosError,
    0x4E6C7452, 0x61745374, 0x54737574, 0x736F446F,
    0x6F727245, 0x00000072)

}  // namespace

ScopedNtStatus::~ScopedNtStatus() {
  SetLastErrorFromNtStatus(s_);
}

void SetLastErrorFromNtStatus(NTSTATUS s) {
  auto func = GetRtlNtStatusToDosError();
  if (func) {
    ::SetLastError(NT_SUCCESS(s) ? 0 : func(s));
  }
}

}  // namespace nt
}  // namespace rtninja