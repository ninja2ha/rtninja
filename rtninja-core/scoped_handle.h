// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_SCOPED_HANDLE_H_
#define RTNINJA_RTNINJA_CORE_SCOPED_HANDLE_H_

#include <windows.h>

#include <memory>

namespace rtninja {

namespace internal {
struct HandleDeleter {
  void operator()(void* handle) {
    ::CloseHandle(handle);
  }
};
}  // namespace internal
using ScopedHandle = std::unique_ptr<void, internal::HandleDeleter>;

}  // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_SCOPED_HANDLE_H_