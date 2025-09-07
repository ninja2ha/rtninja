// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_INTERNAL_WINDOW_TYPES_H_
#define RTNINJA_RTNINJA_CORE_INTERNAL_WINDOW_TYPES_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

// already defined.
#if defined(min)
#undef min
#endif

#if defined(max)
#undef max
#endif

#define HandleToUlong32(handle) ((ULONG32)((ULONG_PTR)(handle)))
#define HandleToUlong64(handle) ((ULONG64)((ULONG_PTR)(handle)))
#define Ulong64ToHandle(value) ((LPVOID)((ULONG_PTR)(value)))

#endif  // RTNINJA_RTNINJA_CORE_INTERNAL_WINDOW_TYPES_H_