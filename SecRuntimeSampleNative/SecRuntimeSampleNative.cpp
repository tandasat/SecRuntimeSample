// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares implements the Thing class
//
#include "pch.h"
#include "SecRuntimeSampleNative.h"
#include "Process.h"

using namespace SecRuntimeSampleNative;

namespace stdexp = std::experimental;

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

const Win32Api g_Win32Api;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Does clever stuff sincerely
Platform::String ^ Thing::DoesStuff() {
  //if (::IsDebuggerPresent()) {
  //  __debugbreak();
  //}

  const auto text = Process::EnumProcesses();
  return ref new Platform::String(text.c_str());
}

// Debug prints
HRESULT LogPrint(const char *FunctionName, const char *Format, ...) {
  va_list args;
  va_start(args, Format);
  char logMessage[300];
  auto status = ::vsnprintf_s(logMessage, _TRUNCATE, Format, args);
  va_end(args);
  if (status == -1) {
    return status;
  }

  wchar_t message[400];
  status = ::swprintf_s(message, RTL_NUMBER_OF(message), L"%-20S\t%S\n",
                       FunctionName, logMessage);
  if (!SUCCEEDED(status)) {
    return status;
  }
  ::OutputDebugString(message);
  return status;
}