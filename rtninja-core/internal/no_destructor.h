// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.
// From: https://github.com/chromium/chromium/blob/81.0.4044.156/base/no_destructor.h

#ifndef RTNINJA_RTNINJA_CORE_INTERNAL_NO_DESTRUCTOR_H_
#define RTNINJA_RTNINJA_CORE_INTERNAL_NO_DESTRUCTOR_H_

#include <new>
#include <utility>

namespace rtninja {

// A wrapper that makes it easy to create an object of type T with static
// storage duration that:
// - is only constructed on first access
// - never invokes the destructor
// in order to satisfy the styleguide ban on global constructors and
// destructors.
//
// Runtime constant example:
// const std::string& GetLineSeparator() {
//  // Forwards to std::string(size_t, char, const Allocator&) constructor.
//   static const cr::NoDestructor<std::string> s(5, '-');
//   return *s;
// }
//
// More complex initialization with a lambda:
// const std::string& GetSessionNonce() {
//   static const cr::NoDestructor<std::string> nonce([] {
//     std::string s(16);
//     crypto::RandString(s.data(), s.size());
//     return s;
//   }());
//   return *nonce;
// }
//
// NoDestructor<T> stores the object inline, so it also avoids a pointer
// indirection and a malloc. Also note that since C++11 static local variable
// initialization is thread-safe and so is this pattern. Code should prefer to
// use NoDestructor<T> over:
// - A function scoped static T* or T& that is dynamically initialized.
// - A global cr::LazyInstance<T>.
//
// Note that since the destructor is never run, this *will* leak memory if used
// as a stack or member variable. Furthermore, a NoDestructor<T> should never
// have global scope as that may require a static initializer.
template <typename T>
class NoDestructor {
 public:
  // Not constexpr; just write static constexpr T x = ...; if the value should
  // be a constexpr.
  template <typename... Args>
  explicit NoDestructor(Args&&... args) {
    new (storage_) T(std::forward<Args>(args)...);
  }

  // Allows copy and move construction of the contained type, to allow
  // construction from an initializer list, e.g. for std::vector.
  explicit NoDestructor(const T& x) { new (storage_) T(x); }
  explicit NoDestructor(T&& x) { new (storage_) T(std::move(x)); }

  NoDestructor(const NoDestructor&) = delete;
  NoDestructor& operator=(const NoDestructor&) = delete;
  ~NoDestructor() = default;

  const T& operator*() const { return *get(); }
  T& operator*() { return *get(); }

  const T* operator->() const { return get(); }
  T* operator->() { return get(); }

  const T* get() const { return reinterpret_cast<const T*>(storage_); }
  T* get() { return reinterpret_cast<T*>(storage_); }

 private:
  alignas(T) char storage_[sizeof(T)];
};

}  // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_INTERNAL_NO_DESTRUCTOR_H_