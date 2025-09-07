// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_SCOPED_MEM_H_
#define RTNINJA_RTNINJA_CORE_SCOPED_MEM_H_

#include "rtninja-core/internal/native_types.h"
#include "rtninja-core/internal/native_ps.h"

namespace rtninja {

////////////////////////////////////////////////////////////////////////////////

class ScopedMemAlloc {
 public:
  ScopedMemAlloc(HANDLE process, SIZE_T size, ULONG protect) 
      : process_(process),
        base_(nt::AllocateProcessMemory(process, nullptr, 
                                        size, MEM_COMMIT, protect)) {
  }
  ~ScopedMemAlloc() {
    if (base_) { 
      nt::FreeProcessMemory(process_, base_, 0, MEM_RELEASE);
    }
  }

  PVOID get() const { return base_; }
  void release() { process_ = nullptr; base_ = nullptr; }

 private:
  HANDLE process_;
  PVOID base_;
};

////////////////////////////////////////////////////////////////////////////////

class ScopedMemAccess64 {
 public:
  ScopedMemAccess64(
      HANDLE process, ULONGLONG address, SIZE_T size) 
          : process_(process), address_(address), size_(size), protect_(0) {
    nt::ProtectProcessMemory64(
        process, address, size, PAGE_EXECUTE_READWRITE, &protect_);
  }

  ~ScopedMemAccess64() {
    if (protect_ != 0) {
      nt::ProtectProcessMemory64(
          process_, address_, size_, protect_, &protect_);
    }
  }

  void release() {
    protect_ = 0;
  }

 private:
  HANDLE process_;
  ULONGLONG address_;
  SIZE_T size_;
  ULONG protect_ ;
};

}  // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_SCOPED_MEM_H_