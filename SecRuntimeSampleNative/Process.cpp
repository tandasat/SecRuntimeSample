// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module implements Process functions
//
#include "pch.h"

namespace stdexp = std::experimental;

namespace Process {
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

struct ProcessInfo {
  DWORD_PTR ProcessId;
  DWORD_PTR InheritedFromUniqueProcessId;
  FILETIME CreationTime;
  std::wstring UserName;
  std::wstring Integrity;
  std::wstring ImagePath;
  std::vector<std::wstring> PriviregeNames;
  std::vector<const ProcessInfo *> Children;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

std::wstring GetProcessOwner(HANDLE ProcessHandle);

DWORD_PTR GetInheritedFromUniqueProcessId(HANDLE ProcessHandle);

std::wstring GetIntegrityLevel(HANDLE ProcessHandle);

std::vector<std::wstring> GetPrivilegeNames(HANDLE ProcessHandle);

ProcessInfo MakeProcessInfo(DWORD ProcessId, HANDLE ProcessHandle);

void Tree(const ProcessInfo &Process, const std::wstring &Padding);

void DumpInTree(const std::vector<ProcessInfo> &Processes);

std::wstring DumpInList(const std::vector<ProcessInfo> &Processes);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Returns process owner's name
std::wstring GetProcessOwner(HANDLE ProcessHandle) {
  HANDLE processTokenHandle = nullptr;
  if (S_OK !=
          g_Win32Api.OpenProcessTokenForQuery(ProcessHandle,
                                              &processTokenHandle) &&
      !processTokenHandle) {
    return {};
  }
  const auto scopedCloseHandle = stdexp::make_scope_exit(
      [processTokenHandle]() { ::CloseHandle(processTokenHandle); });

  // Get token information
  DWORD requiredSize = 0;
  g_Win32Api.GetTokenInformation(processTokenHandle, TokenUser, nullptr, 0,
                                 &requiredSize);
  if (!requiredSize) {
    return {};
  }

  std::vector<char> buffer(requiredSize);
  auto userToken = reinterpret_cast<PTOKEN_USER>(buffer.data());
  if (!g_Win32Api.GetTokenInformation(processTokenHandle, TokenUser, userToken,
                                      requiredSize, &requiredSize)) {
    return {};
  }

  // Look up user and domain names
  TCHAR userName[MAX_PATH] = {};
  DWORD userNameLength = _countof(userName);
  TCHAR domainName[MAX_PATH] = {};
  DWORD domainNameLength = _countof(domainName);
  SID_NAME_USE sidType = {};
  if (!g_Win32Api.LookupAccountSid(nullptr, userToken->User.Sid, userName,
                                   &userNameLength, domainName,
                                   &domainNameLength, &sidType)) {
    return {};
  }

  // Make it pretty
  std::wstring ownerName = TEXT("\\\\");
  ownerName += domainName;
  ownerName += TEXT("\\");
  ownerName += userName;
  return ownerName;
}

// Returns a process ID of the process associated with ProcessHandle.
DWORD_PTR GetInheritedFromUniqueProcessId(HANDLE ProcessHandle) {
  PROCESS_BASIC_INFORMATION pbi = {};
  ULONG size = 0;
  auto status = g_Win32Api.NtQueryInformationProcess(
      ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &size);
  if (status != 0) {
    return 0;
  }
  return pbi.InheritedFromUniqueProcessId;
}

// Returns a string representation of an integrity level of the process
// associated with ProcessHandle.
std::wstring GetIntegrityLevel(HANDLE ProcessHandle) {
  HANDLE processTokenHandle = nullptr;
  if (S_OK !=
          g_Win32Api.OpenProcessTokenForQuery(ProcessHandle,
                                              &processTokenHandle) &&
      !processTokenHandle) {
    return {};
  }
  const auto scopedCloseHandle = stdexp::make_scope_exit(
      [processTokenHandle]() { ::CloseHandle(processTokenHandle); });

  // Get token information
  DWORD requiredSize = 0;
  g_Win32Api.GetTokenInformation(processTokenHandle, TokenIntegrityLevel,
                                 nullptr, 0, &requiredSize);
  if (!requiredSize) {
    return {};
  }

  std::vector<char> buffer(requiredSize);
  auto uerToken = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());

  if (!g_Win32Api.GetTokenInformation(processTokenHandle, TokenIntegrityLevel,
                                      uerToken, requiredSize, &requiredSize)) {
    return {};
  }

  // Lookup its name
  TCHAR userName[MAX_PATH] = {};
  DWORD userNameLength = _countof(userName);
  TCHAR domainName[MAX_PATH] = {};
  DWORD domainNameLength = _countof(domainName);
  SID_NAME_USE sidType = {};
  if (!g_Win32Api.LookupAccountSid(nullptr, uerToken->Label.Sid, userName,
                                   &userNameLength, domainName,
                                   &domainNameLength, &sidType)) {
    return {};
  }

  // Delete some not interesting strings.
  std::wstring name = userName;
  std::wstring junk = L" Mandatory Level";
  return name.replace(name.find(junk), junk.length(), L"");
}

// Returns a list of privilege names assigned to a process associated with
// ProcessHandle.
std::vector<std::wstring> GetPrivilegeNames(HANDLE ProcessHandle) {
  HANDLE tokenHandle = nullptr;
  if (S_OK !=
          g_Win32Api.OpenProcessTokenForQuery(ProcessHandle, &tokenHandle) &&
      !tokenHandle) {
    return {};
  }
  const auto scopedCloseHandle =
      stdexp::make_scope_exit([tokenHandle]() { ::CloseHandle(tokenHandle); });

  // Get token information
  DWORD requiredSize = 0;
  g_Win32Api.GetTokenInformation(tokenHandle, TokenPrivileges, nullptr, 0,
                                 &requiredSize);
  if (!requiredSize) {
    return {};
  }

  std::vector<BYTE> buffer(requiredSize);
  if (!g_Win32Api.GetTokenInformation(tokenHandle, TokenPrivileges,
                                      buffer.data(), requiredSize,
                                      &requiredSize)) {
    return {};
  }
  auto tokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());

  // Iterate all privileges and retrieve their name
  std::vector<std::wstring> privilegeNames;
  privilegeNames.reserve(tokenPrivileges->PrivilegeCount);

  for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) {
    requiredSize = 0;
    g_Win32Api.LookupPrivilegeName(
        nullptr, &tokenPrivileges->Privileges[i].Luid, nullptr, &requiredSize);
    if (!requiredSize) {
      return {};  // Threat it as a complete failure
    }
    std::vector<wchar_t> privilegeName(requiredSize + 1);
    if (!g_Win32Api.LookupPrivilegeName(nullptr,
                                        &tokenPrivileges->Privileges[i].Luid,
                                        privilegeName.data(), &requiredSize)) {
      return {};  // Threat it as a complete failure
    }

    std::wstring state = L"Disabled";
    switch (tokenPrivileges->Privileges[i].Attributes) {
      case SE_PRIVILEGE_ENABLED:
        state = L"Enabled";
        break;

      case SE_PRIVILEGE_ENABLED_BY_DEFAULT:
        state = L"Enabled Default";
        break;

      case SE_PRIVILEGE_REMOVED:
        state = L"Removed";
        break;

      case SE_PRIVILEGE_USED_FOR_ACCESS:
        state = L"Used for access";
        break;
    }
    privilegeNames.push_back(std::wstring(privilegeName.data()) + L"\t(" +
                             state + L")");
  }
  return privilegeNames;
}

ProcessInfo MakeProcessInfo(DWORD ProcessId, HANDLE ProcessHandle) {
  wchar_t fullPath[MAX_PATH] = {};
  DWORD size = _countof(fullPath);
  if (!g_Win32Api.QueryFullProcessImageName(ProcessHandle, 0, fullPath,
                                            &size)) {
    g_Win32Api.GetProcessImageFileName(ProcessHandle, fullPath,
                                       _countof(fullPath));
  }

  const auto ppid = GetInheritedFromUniqueProcessId(ProcessHandle);
  const auto username = GetProcessOwner(ProcessHandle);
  const auto integrity = GetIntegrityLevel(ProcessHandle);
  FILETIME createTime = {};
  FILETIME unused = {};
  FILETIME localTime = {};
  if (g_Win32Api.GetProcessTimes(ProcessHandle, &createTime, &unused, &unused,
                                 &unused)) {
    g_Win32Api.FileTimeToLocalFileTime(&createTime, &localTime);
  }

  return {
      ProcessId,
      ppid,
      localTime,
      username,
      integrity,
      fullPath,
      GetPrivilegeNames(ProcessHandle),
  };
}

void Tree(const ProcessInfo &Process, const std::wstring &Padding) {
  SYSTEMTIME st = {};
  FileTimeToSystemTime(&Process.CreationTime, &st);

  std::vector<wchar_t> time(1000);
  ::GetTimeFormatEx(nullptr, TIME_FORCE24HOURFORMAT | TIME_NOTIMEMARKER, &st,
                    L"hh:mm:ss", time.data(), time.size());

  char head[100];
  ::sprintf_s(head, "%S> %u", Padding.c_str(), Process.ProcessId);

  LOG_DEBUG("%-15s  - %S %S", head, time.data(), Process.ImagePath.c_str());
  for (auto process : Process.Children) {
    Tree(*process, Padding + L"  ");
  }
}

void DumpInTree(const std::vector<ProcessInfo> &Processes) {
  std::vector<DWORD_PTR> deadParentPIDs;
  for (const auto &current : Processes) {
    const auto parent = std::find_if(
        std::begin(Processes), std::end(Processes),
        [&current](const ProcessInfo &process) {
          return process.ProcessId == current.InheritedFromUniqueProcessId;
        });
    if (parent == Processes.end()) {
      deadParentPIDs.push_back(current.InheritedFromUniqueProcessId);
    }
  };

  std::sort(std::begin(deadParentPIDs), std::end(deadParentPIDs));
  deadParentPIDs.erase(
      std::unique(std::begin(deadParentPIDs), std::end(deadParentPIDs)),
      std::end(deadParentPIDs));

  auto copiedProcesses = Processes;
  for (auto ProcessId : deadParentPIDs) {
    copiedProcesses.push_back({
        ProcessId,
    });
  }

  ProcessInfo root;
  for (const auto &current : copiedProcesses) {
    const auto parent = std::find_if(
        std::begin(copiedProcesses), std::end(copiedProcesses),
        [&current](const ProcessInfo &process) {
          return process.ProcessId == current.InheritedFromUniqueProcessId &&
                 g_Win32Api.CompareFileTime(&process.CreationTime,
                                            &current.CreationTime) == -1;
        });
    if (parent == copiedProcesses.end()) {
      root.Children.push_back(&current);
    } else {
      parent->Children.push_back(&current);
    }
  }

  for (auto process : root.Children) {
    Tree(*process, L"");
  }
}

std::wstring DumpInList(const std::vector<ProcessInfo> &Processes) {
  std::wstring text;
  for (auto &&process : Processes) {
    SYSTEMTIME stime = {};
    ::FileTimeToSystemTime(&process.CreationTime, &stime);

    auto size =
        ::GetDateFormatEx(nullptr, 0, &stime, nullptr, nullptr, 0, nullptr);
    if (!size) {
      continue;
    }
    std::vector<wchar_t> date(size);
    if (!::GetDateFormatEx(nullptr, 0, &stime, nullptr, date.data(),
                           date.size(), nullptr)) {
      continue;
    }

    size =
        ::GetTimeFormatEx(nullptr, TIME_FORCE24HOURFORMAT | TIME_NOTIMEMARKER,
                          &stime, nullptr, nullptr, 0);
    if (!size) {
      continue;
    }
    std::vector<wchar_t> time(size);
    if (!::GetTimeFormatEx(nullptr, TIME_FORCE24HOURFORMAT | TIME_NOTIMEMARKER,
                           &stime, nullptr, time.data(), time.size())) {
      continue;
    }

    LOG_DEBUG("%5lu  %5lu  %-10S  %12S  %-32S  %-10S  %S", process.ProcessId,
              process.InheritedFromUniqueProcessId, date.data(), time.data(),
              process.UserName.c_str(), process.Integrity.c_str(),
              process.ImagePath.c_str());

    wchar_t entry[400];
    ::swprintf_s(entry, L"%5lu  %5lu  %-10s  %12s  %-32s  %-10s  \t%s\n",
                 process.ProcessId, process.InheritedFromUniqueProcessId,
                 date.data(), time.data(), process.UserName.c_str(),
                 process.Integrity.c_str(), process.ImagePath.c_str());
    text += entry;
  }
  return text;
}

std::wstring EnumProcesses() {
  std::vector<ProcessInfo> processes;

  // Brute force to find processes
  for (auto pid = 4; pid < 10000; pid += 4) {
    // Try to open the PID
    HANDLE processHandle = nullptr;
    const auto status =
        g_Win32Api.OpenProcessForQuery(nullptr, pid, &processHandle);
    if (status != S_OK || !processHandle) {
      if (status != E_ACCESSDENIED && status != E_INVALIDARG) {
        LOG_DEBUG("%5lu %08x", pid, status);
      }
      continue;
    }
    const auto scopedCloseHandle = stdexp::make_scope_exit(
        [processHandle]() { ::CloseHandle(processHandle); });

    // Build process information and store it
    processes.push_back(MakeProcessInfo(pid, processHandle));
  }

  // Sort the process list based on processes' created times
  std::sort(std::begin(processes), std::end(processes),
            [](const ProcessInfo &Lhs, const ProcessInfo &Rhs) {
              if (Lhs.CreationTime.dwHighDateTime ==
                  Rhs.CreationTime.dwHighDateTime) {
                return Lhs.CreationTime.dwLowDateTime <
                       Rhs.CreationTime.dwLowDateTime;
              }
              {
                return Lhs.CreationTime.dwHighDateTime <
                       Rhs.CreationTime.dwHighDateTime;
              }
            });

  DumpInTree(processes);
  return DumpInList(processes);
}

}  // namespace Process
