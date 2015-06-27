// Copyright (c) 2015, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

//
// This module declares interfaces to functions written in assembler.
//
#pragma once

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

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//




#pragma once
#include <windows.h>

extern "C" {

typedef struct tagPROCESSENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD th32ModuleID;
  DWORD cntThreads;
  DWORD th32ParentProcessID;
  LONG pcPriClassBase;
  DWORD dwFlags;
  TCHAR szExeFile[MAX_PATH];
} PROCESSENTRY32, *PPROCESSENTRY32, *LPPROCESSENTRY32;

#ifndef MAX_MODULE_NAME32
#define MAX_MODULE_NAME32 255
#endif
typedef struct tagMODULEENTRY32 {
  DWORD dwSize;
  DWORD th32ModuleID;
  DWORD th32ProcessID;
  DWORD GlblcntUsage;
  DWORD ProccntUsage;
  BYTE *modBaseAddr;
  DWORD modBaseSize;
  HMODULE hModule;
  TCHAR szModule[MAX_MODULE_NAME32 + 1];
  TCHAR szExePath[MAX_PATH];
} MODULEENTRY32, *PMODULEENTRY32, *LPMODULEENTRY32;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// RTL_ to avoid collisions in the global namespace.
// I don't believe there are possible/likely constant RootDirectory
// or SecurityDescriptor values other than NULL, so they are hardcoded.
// As well, the string will generally be const, so we cast that away.
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)                                \
  {                                                                         \
    sizeof(OBJECT_ATTRIBUTES), NULL, RTL_CONST_CAST(PUNICODE_STRING)(n), a, \
        NULL, NULL                                                          \
  }

// This synonym is more appropriate for initializing what isn't actually const.
#define RTL_INIT_OBJECT_ATTRIBUTES(n, a) RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)

typedef struct {
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

BOOL WINAPI AllocConsole(void);

HANDLE WINAPI CreateFile(_In_ LPCTSTR lpFileName, _In_ DWORD dwDesiredAccess,
                         _In_ DWORD dwShareMode,
                         _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                         _In_ DWORD dwCreationDisposition,
                         _In_ DWORD dwFlagsAndAttributes,
                         _In_opt_ HANDLE hTemplateFile);

HANDLE WINAPI CreateToolhelp32Snapshot(_In_ DWORD dwFlags,
                                       _In_ DWORD th32ProcessID);

BOOL WINAPI CryptBinaryToString(_In_ const BYTE *pbBinary, _In_ DWORD cbBinary,
                                _In_ DWORD dwFlags, _Out_opt_ LPTSTR pszString,
                                _Inout_ DWORD *pcchString);

LONG WINAPI CompareFileTime(_In_ const FILETIME *lpFileTime1,
                            _In_ const FILETIME *lpFileTime2);

BOOL WINAPI CopyFile(_In_ LPCTSTR lpExistingFileName,
                     _In_ LPCTSTR lpNewFileName, _In_ BOOL bFailIfExists);

BOOL WINAPI DeviceIoControl(_In_ HANDLE hDevice, _In_ DWORD dwIoControlCode,
                            _In_opt_ LPVOID lpInBuffer,
                            _In_ DWORD nInBufferSize,
                            _Out_opt_ LPVOID lpOutBuffer,
                            _In_ DWORD nOutBufferSize,
                            _Out_opt_ LPDWORD lpBytesReturned,
                            _Inout_opt_ LPOVERLAPPED lpOverlapped);

BOOL WINAPI EnumDeviceDrivers(_Out_ LPVOID *lpImageBase, _In_ DWORD cb,
                              _Out_ LPDWORD lpcbNeeded);

DWORD WINAPI GetCurrentDirectory(_In_ DWORD nBufferLength,
                                 _Out_ LPTSTR lpBuffer);

DWORD WINAPI GetDeviceDriverFileName(_In_ LPVOID ImageBase,
                                     _Out_ LPTSTR lpFilename, _In_ DWORD nSize);

BOOL WINAPI GetFileSizeEx(_In_ HANDLE hFile, _Out_ PLARGE_INTEGER lpFileSize);

HMODULE WINAPI GetModuleHandle(_In_opt_ LPCTSTR lpModuleName);

DWORD WINAPI GetProcessImageFileName(_In_ HANDLE hProcess,
                                     _Out_ LPTSTR lpImageFileName,
                                     _In_ DWORD nSize);

BOOL WINAPI GetProcessTimes(_In_ HANDLE hProcess,
                            _Out_ LPFILETIME lpCreationTime,
                            _Out_ LPFILETIME lpExitTime,
                            _Out_ LPFILETIME lpKernelTime,
                            _Out_ LPFILETIME lpUserTime);

BOOL WINAPI GetTokenInformation(
    _In_ HANDLE TokenHandle, _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
    _Out_opt_ LPVOID TokenInformation, _In_ DWORD TokenInformationLength,
    _Out_ PDWORD ReturnLength);

BOOL WINAPI FileTimeToLocalFileTime(_In_ const FILETIME *lpFileTime,
                                    _Out_ LPFILETIME lpLocalFileTime);

HMODULE WINAPI LoadLibrary(_In_ LPCTSTR lpFileName);

BOOL WINAPI LookupAccountSid(_In_opt_ LPCTSTR lpSystemName, _In_ PSID lpSid,
                             _Out_opt_ LPTSTR lpName, _Inout_ LPDWORD cchName,
                             _Out_opt_ LPTSTR lpReferencedDomainName,
                             _Inout_ LPDWORD cchReferencedDomainName,
                             _Out_ PSID_NAME_USE peUse);

BOOL WINAPI LookupPrivilegeName(_In_opt_ LPCTSTR lpSystemName,
                                _In_ PLUID lpLuid, _Out_opt_ LPTSTR lpName,
                                _Inout_ LPDWORD cchName);

BOOL WINAPI Module32First(_In_ HANDLE hSnapshot, _Inout_ LPMODULEENTRY32 lpme);

BOOL WINAPI Module32Next(_In_ HANDLE hSnapshot, _Out_ LPMODULEENTRY32 lpme);

NTSTATUS NTAPI NtGetNextProcess(_In_ HANDLE ProcessHandle,
                                _In_ ACCESS_MASK DesiredAccess,
                                _In_opt_ ULONG HandleAttributes,
                                _In_opt_ ULONG Flags,
                                _Out_ PHANDLE NewProcessHandle);

NTSTATUS WINAPI NtOpenProcess(_Out_ PHANDLE ProcessHandle,
                              _In_ ACCESS_MASK DesiredAccess,
                              _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                              _In_opt_ PCLIENT_ID ClientId);

enum PROCESSINFOCLASS {
  ProcessBasicInformation = 0,
};

typedef struct _tagPROCESS_BASIC_INFORMATION {
  PVOID ExitStatus;
  PVOID PebBaseAddress;
  PVOID AffinityMask;
  PVOID BasePriority;
  DWORD_PTR UniqueProcessId;
  DWORD_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

NTSTATUS WINAPI NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

HANDLE WINAPI OpenProcess(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle,
                          _In_ DWORD dwProcessId);

BOOL WINAPI OpenProcessToken(_In_ HANDLE ProcessHandle,
                             _In_ DWORD DesiredAccess,
                             _Out_ PHANDLE TokenHandle);

PTSTR PathFindFileName(_In_ PTSTR pPath);

BOOL WINAPI Process32First(_In_ HANDLE hSnapshot,
                           _Inout_ LPPROCESSENTRY32 lppe);

BOOL WINAPI Process32Next(_In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe);

BOOL WINAPI QueryFullProcessImageName(_In_ HANDLE hProcess, _In_ DWORD dwFlags,
                                      _Out_ LPTSTR lpExeName,
                                      _Inout_ PDWORD lpdwSize);

// Undocumented

HRESULT WINAPI OpenProcessForQuery(void *Unknown, DWORD ProcessId,
                                   HANDLE *ProcessHandle);
HRESULT WINAPI OpenProcessTokenForQuery(HANDLE ProcessHandle,
                                        HANDLE *TokenHandle);

HRESULT WINAPI SetDeveloperUnlockState(BOOLEAN Data);
HRESULT WINAPI QueryKernelPrivilegeCache(wchar_t *lpInBuffer,
                                         LPVOID lpOutBuffer);
}

#define WIN32API_STRINGIFY(x) #x
#define WIN32API_TOSTRING(x) WIN32API_STRINGIFY(x)

// Neutral
#define WIN32API_INIT_PROC_N(Module, Name) \
  Name(reinterpret_cast<decltype(&::Name)>(::GetProcAddress(Module, #Name)))

// Wide
#define WIN32API_INIT_PROC_W(Module, Name)  \
  Name(reinterpret_cast<decltype(&::Name)>( \
      ::GetProcAddress((Module), WIN32API_TOSTRING(Name##W))))

// ASCII
#define WIN32API_INIT_PROC_A(Module, Name)  \
  Name(reinterpret_cast<decltype(&::Name)>( \
      ::GetProcAddress((Module), WIN32API_TOSTRING(Name##A))))

// Define variable
#define WIN32API_DEFINE_PROC(Name) const decltype(&::Name) Name

class Win32Api {
 public:
  Win32Api()
      : m_Kernelbase(GetKernelBase()),
        WIN32API_INIT_PROC_W(m_Kernelbase, GetModuleHandle),
        WIN32API_INIT_PROC_W(m_Kernelbase, GetCurrentDirectory),
        WIN32API_INIT_PROC_A(m_Kernelbase, CreateFile),
        WIN32API_INIT_PROC_N(m_Kernelbase, GetFileSizeEx),
        WIN32API_INIT_PROC_N(m_Kernelbase, GetTokenInformation),
        WIN32API_INIT_PROC_N(m_Kernelbase, OpenProcess),
        WIN32API_INIT_PROC_W(m_Kernelbase, QueryFullProcessImageName),
        WIN32API_INIT_PROC_W(m_Kernelbase, GetProcessImageFileName),
        WIN32API_INIT_PROC_N(m_Kernelbase, GetProcessTimes),
        WIN32API_INIT_PROC_N(m_Kernelbase, FileTimeToLocalFileTime),
        WIN32API_INIT_PROC_N(m_Kernelbase, AllocConsole),
        WIN32API_INIT_PROC_N(m_Kernelbase, EnumDeviceDrivers),
        WIN32API_INIT_PROC_W(m_Kernelbase, GetDeviceDriverFileName),
        WIN32API_INIT_PROC_N(m_Kernelbase, CompareFileTime),
        m_Kernel32(GetModuleHandle(L"Kernel32legacy.dll")),
        WIN32API_INIT_PROC_W(m_Kernel32, CopyFile),
        WIN32API_INIT_PROC_W(m_Kernel32, LoadLibrary),
        WIN32API_INIT_PROC_N(m_Kernel32, CreateToolhelp32Snapshot),
        WIN32API_INIT_PROC_W(m_Kernel32, Module32First),
        WIN32API_INIT_PROC_W(m_Kernel32, Module32Next),
        m_Crypt32(LoadLibrary(L"Crypt32.dll")),
        WIN32API_INIT_PROC_A(m_Crypt32, CryptBinaryToString),
        m_Ntdll(GetModuleHandle(L"Ntdll.dll")),
        WIN32API_INIT_PROC_N(m_Ntdll, NtQueryInformationProcess),
        WIN32API_INIT_PROC_N(m_Ntdll, NtGetNextProcess),
        m_SecRuntime(GetModuleHandle(L"SecRuntime.dll")),
        WIN32API_INIT_PROC_N(m_SecRuntime, OpenProcessForQuery),
        WIN32API_INIT_PROC_N(m_SecRuntime, OpenProcessTokenForQuery),
        WIN32API_INIT_PROC_N(m_SecRuntime, SetDeveloperUnlockState),
        WIN32API_INIT_PROC_N(m_SecRuntime, QueryKernelPrivilegeCache),
        m_Advapi32(GetModuleHandle(L"Advapi32legacy.dll")),
        WIN32API_INIT_PROC_W(m_Advapi32, LookupAccountSid),
        WIN32API_INIT_PROC_W(m_Advapi32, LookupPrivilegeName) {}

  Win32Api &operator=(const Win32Api &) = delete;

 private:
  static HMODULE GetKernelBase() {
    return GetBaseAddress(&::DisableThreadLibraryCalls);
  }

  static HMODULE GetBaseAddress(const void *Address) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!::VirtualQuery(Address, &mbi, sizeof(mbi))) {
      return nullptr;
    }
    const auto mz = *reinterpret_cast<WORD *>(mbi.AllocationBase);
    if (mz != IMAGE_DOS_SIGNATURE) {
      return nullptr;
    }
    return reinterpret_cast<HMODULE>(mbi.AllocationBase);
  }

 public:
  const HMODULE m_Kernelbase;
  WIN32API_DEFINE_PROC(GetModuleHandle);
  WIN32API_DEFINE_PROC(GetCurrentDirectory);
  WIN32API_DEFINE_PROC(CreateFile);
  WIN32API_DEFINE_PROC(GetFileSizeEx);
  WIN32API_DEFINE_PROC(GetTokenInformation);
  WIN32API_DEFINE_PROC(OpenProcess);
  WIN32API_DEFINE_PROC(QueryFullProcessImageName);
  WIN32API_DEFINE_PROC(GetProcessImageFileName);
  WIN32API_DEFINE_PROC(GetProcessTimes);
  WIN32API_DEFINE_PROC(FileTimeToLocalFileTime);
  WIN32API_DEFINE_PROC(AllocConsole);
  WIN32API_DEFINE_PROC(EnumDeviceDrivers);
  WIN32API_DEFINE_PROC(GetDeviceDriverFileName);
  WIN32API_DEFINE_PROC(CompareFileTime);
  const HMODULE m_Kernel32;
  WIN32API_DEFINE_PROC(CopyFile);
  WIN32API_DEFINE_PROC(LoadLibrary);
  WIN32API_DEFINE_PROC(CreateToolhelp32Snapshot);
  WIN32API_DEFINE_PROC(Module32First);
  WIN32API_DEFINE_PROC(Module32Next);
  const HMODULE m_Crypt32;
  WIN32API_DEFINE_PROC(CryptBinaryToString);
  const HMODULE m_Ntdll;
  WIN32API_DEFINE_PROC(NtQueryInformationProcess);
  WIN32API_DEFINE_PROC(NtGetNextProcess);
  const HMODULE m_SecRuntime;
  WIN32API_DEFINE_PROC(OpenProcessForQuery);
  WIN32API_DEFINE_PROC(OpenProcessTokenForQuery);
  WIN32API_DEFINE_PROC(SetDeveloperUnlockState);
  WIN32API_DEFINE_PROC(QueryKernelPrivilegeCache);
  const HMODULE m_Advapi32;
  WIN32API_DEFINE_PROC(LookupAccountSid);
  WIN32API_DEFINE_PROC(LookupPrivilegeName);
};

#undef WIN32API_STRINGIFY
#undef WIN32API_TOSTRING
#undef WIN32API_INIT_PROC_N
#undef WIN32API_INIT_PROC_W
#undef WIN32API_INIT_PROC_A
#undef WIN32API_DEFINE_PROC
