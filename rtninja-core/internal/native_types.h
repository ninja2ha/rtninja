// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_TYPES_H_
#define RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_TYPES_H_

#include "rtninja-core/internal/window_types.h"
#include "rtninja-core/internal/native_status.h"
#include "rtninja-core/internal/compiler_config.h"

namespace rtninja {
namespace nt {

namespace internal {

template <typename T>
struct AS_POINTER_T {
  T* AsPtr32() {
    return reinterpret_cast<T*>(this);
  }
};

}  // namespace internal

template <class Ptr>
struct alignas(sizeof(Ptr)) LIST_ENTRY_T :
    public internal::AS_POINTER_T<LIST_ENTRY_T<ULONG32>> {
  Ptr Flink;
  Ptr Blink;
};
using LIST_ENTRY = LIST_ENTRY_T<ULONG_PTR>;
using LIST_ENTRY32 = LIST_ENTRY_T<ULONG32>;
using LIST_ENTRY64 = LIST_ENTRY_T<ULONG64>;

template <class Ptr> 
struct alignas(sizeof(Ptr)) UNICODE_STRING_T :
    public internal::AS_POINTER_T<UNICODE_STRING_T<ULONG32>> {
  WORD Length;
  WORD MaximumLength;
  Ptr Buffer;
};
using UNICODE_STRING = UNICODE_STRING_T<ULONG_PTR>;
using UNICODE_STRING32 = UNICODE_STRING_T<ULONG32>;
using UNICODE_STRING64 = UNICODE_STRING_T<ULONG64>;

template <class Ptr>
using ANSI_STRING_T = UNICODE_STRING_T<Ptr>;
using ANSI_STRING = UNICODE_STRING_T<ULONG_PTR>;
using ANSI_STRING32 = UNICODE_STRING_T<ULONG32>;
using ANSI_STRING64 = UNICODE_STRING_T<ULONG64>;

template <class Ptr> 
struct alignas(sizeof(Ptr)) OBJECT_ATTRIBUTES_T :
    public internal::AS_POINTER_T<OBJECT_ATTRIBUTES_T<ULONG32>> {
  ULONG Length;
  Ptr RootDirectory;
  Ptr ObjectName; // PUNICODE_STRING
  ULONG Attributes;
  Ptr SecurityDescriptor; // PSECURITY_DESCRIPTOR;
  Ptr SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
};
using OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES_T<ULONG_PTR>;
using OBJECT_ATTRIBUTES32 = OBJECT_ATTRIBUTES_T<ULONG32>;
using OBJECT_ATTRIBUTES64 = OBJECT_ATTRIBUTES_T<ULONG64>;

enum ObjectAttributeFlag {
  kOBJInherit = 2l,
  kOBJPermanet = 16l,
  kOBJExclusive = 32l,
  kOBJCaseInsensitive = 64l,
  kOBJOpenIf = 128l,
  kOBJOpenLink = 256l,
  kOBJValidAttributes = 498l
};

////////////////////////////////////////////////////////////////////////////////
// ntdll api

using NtCloseFunc = NTSTATUS(NTAPI*)(
    _In_ _Post_ptr_invalid_ HANDLE Handle
    );

using NtClearEventFunc = NTSTATUS(NTAPI*)(
    _In_ _Post_ptr_invalid_ HANDLE EventHandle
    );
    
using NtSetEventFunc = NTSTATUS(NTAPI*)(
    _In_ _Post_ptr_invalid_ HANDLE EventHandle
    );

using LdrLoadDllFunc = NTSTATUS (NTAPI*)(
    __in_opt PCWSTR DllPath,
    __in_opt PULONG DllCharacteristics,
    __in CONST UNICODE_STRING* DllName,
    __out PVOID *DllHandle
    );

using LdrGetProcedureAddressFunc = NTSTATUS (NTAPI*)(
    __in PVOID DllHandle,
    __in_opt CONST ANSI_STRING* ProcedureName,
    __in_opt ULONG ProcedureNumber,
    __out PVOID *ProcedureAddress
    );

using RtlNtStatusToDosErrorFunc = DWORD(NTAPI*)(
    __in NTSTATUS Status
    );

////////////////////////////////////////////////////////////////////////////////
// helpers api

BOOL IsHostAmd64();

HMODULE GetModule();
ULONGLONG GetModule64();

FARPROC GetProcedure(CONST CHAR* name);
ULONGLONG GetProcedure64(CONST CHAR* name);

// template converter.
template<class T>
inline T GetProcedureT(CONST CHAR* name) { return (T)GetProcedure(name); }

#if defined(RTNINJA_ARCH_CPU_X86)
using X64Call = ULONGLONG(*)(ULONGLONG func, ULONG param_count, ...);
// leaked...
X64Call GetX64Call();
#endif  // RTNINJA_ARCH_CPU_X86

}   // namespace nt
}   // namespace rtninja

#define RTNINJA_NT_API(api, ...)                                     \
rtninja::nt::api##Func Get##api() {                                  \
  static const rtninja::NoDestructor<rtninja::nt::api##Func> fun([]{ \
    DWORD ints_name[] = {__VA_ARGS__};                               \
    return rtninja::nt::GetProcedureT<rtninja::nt::api##Func>(       \
        reinterpret_cast<const CHAR*>(ints_name));                   \
  }());                                                              \
  return *fun;                                                       \
}

#define RTNINJA_NT_API64(api, ...)                                   \
ULONGLONG Get##api##64() {                                           \
  static const rtninja::NoDestructor<ULONGLONG> fun([]{              \
    DWORD ints_name[] = {__VA_ARGS__};                               \
    return rtninja::nt::GetProcedure64(                              \
        reinterpret_cast<const char*>(ints_name));                   \
  }());                                                              \
  return *fun;                                                       \
}


#endif  // RTNINJA_RTNINJA_CORE_INTERNAL_NATIVE_TYPES_H_
