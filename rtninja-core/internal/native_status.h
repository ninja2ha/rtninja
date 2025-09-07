// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_STATUS_H_
#define RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_STATUS_H_

#include "rtninja-core/internal/window_types.h"

using NTSTATUS = long;
#define NT_SUCCESS(status) ((((long)(status)) >= 0) ? TRUE : FALSE)

namespace rtninja {
namespace nt {

enum StatusCode {
  kStatusUnsuccessful = 0xC0000001l,
  kStatusNotImplemented = 0xC0000002l,
};

// helpers
class ScopedNtStatus {
 public: 
  ScopedNtStatus() : s_(0) {}
  explicit ScopedNtStatus(NTSTATUS s) : s_(s) {}
  ~ScopedNtStatus();

  // operators.
  inline void operator=(NTSTATUS s) { s_ = s; }
  inline operator long() { return s_; }
  inline bool operator==(NTSTATUS s) { return s_ == s; }

 private:
  NTSTATUS s_;
};

void SetLastErrorFromNtStatus(NTSTATUS s);

}  // namespace nt
}  // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_STATUS_H_