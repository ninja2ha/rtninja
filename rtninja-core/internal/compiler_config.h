// Copyright (c) 2025 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_INTERNAL_COMPILER_CONFIG_H_
#define RTNINJA_RTNINJA_CORE_INTERNAL_COMPILER_CONFIG_H_

#if defined(_M_X64) || defined(__x86_64__)
#define RTNINJA_ARCH_CPU_X86_64 1
#define RTNINJA_ARCH_CPU_64_BITS 1
#elif defined(_M_IX86) || defined(__i386__)
#define RTNINJA_ARCH_CPU_X86 1 1
#define RTNINJA_ARCH_CPU_32_BITS 1
#endif

#endif  // RTNINJA_RTNINJA_CORE_INTERNAL_COMPILER_CONFIG_H_