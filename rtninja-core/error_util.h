// Copyright (c) 2010 Ninja2ha. All rights reserved.
// Use of this source code is governed by a LPGL3.0-style license that can be
// found in the LICENSE file.

#ifndef RTNINJA_RTNINJA_CORE_ERROR_UTIL_H_
#define RTNINJA_RTNINJA_CORE_ERROR_UTIL_H_

#include <string>

namespace rtninja {

// Formats dos error code to a message. 
std::wstring FormatSysErrorToMessage(unsigned long error); 

}  // namespace rtninja

#endif  // RTNINJA_RTNINJA_CORE_SCOPED_MEM_H_