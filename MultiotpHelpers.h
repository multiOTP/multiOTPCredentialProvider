/**
 * BASE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Helper functions for copying parameters and packaging the buffer
 * for GetSerialization.
 *
 * Extra code provided "as is" for the multiOTP open source project
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.6.1.5
 * @date      2019-10-23
 * @since     2013
 * @copyright (c) 2016-2019 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT 
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2019-10-23 5.6.1.5 SysCo/al FIX: Prefix password parameter was buggy (better handling of parameters in debug mode)
 *                               FIX: swprintf_s problem with special chars (thanks to anekix)
 *   2019-01-25 5.4.1.6 SysCo/al FIX: Username with space are now supported
 *                               ENH: Added integrated Visual C++ 2017 Redistributable installation
 *   2018-09-14 5.4.0.1 SysCo/al FIX: Better domain name and hostname detection
 *                               FIX: The cache lifetime check process was buggy since 5.3.0.3
 *                               ENH: multiOTP Credential Provider files and objects have been reorganized
 *   2018-08-26 5.3.0.3 SysCo/al FIX: Users without 2FA token are now supported
 *   2018-08-21 5.3.0.0 SysCo/yj FIX: Save flat domain name in the registry. While offline, use this value instead of asking the DC
 *                      SysCo/al ENH: The multiOTP timeout (how long the Credential Provider wait a response from
 *                                    the multiOTP process) is now 60 seconds by default (instead of 10)
 *   2018-03-11 5.2.0.0 SysCo/al New implementation from scratch
 *
 *********************************************************************/
 
#pragma once

#pragma warning(push)
#pragma warning(disable: 28251)
#include <credentialprovider.h>
#include <ntsecapi.h>
#pragma warning(pop)

#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>

#include <windows.h>
#include <strsafe.h>

#pragma warning(push)
#pragma warning(disable: 4995)
#include <shlwapi.h>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable: 28301)
#include <wincred.h>
#pragma warning(pop)

// Begin extra code (debug tools)
#define MULTIOTP_SUCCESS ((HRESULT)0)
#define MULTIOTP_UNKNOWN_ERROR ((HRESULT)99)
#define MULTIOTP_CHECK "multiOTP Credential Provider mode" // Special string to check that multiOTP is correctly running

#if _DEBUG
	#define DEVELOP_MODE TRUE
	#define SKIP_OTP_CHECK FALSE // Available in development only, ignore the OTP code check
	#define LOGFILE_NAME "C:\\multiotp-credential-provider.log"
#else
	#define DEVELOP_MODE FALSE
	#define SKIP_OTP_CHECK FALSE
	#define LOGFILE_NAME ""
#endif

#define MAX_TIME_SIZE 250

#define ZERO(NAME) \
	ZeroMemory(NAME, sizeof(NAME))

#define INIT_ZERO_WCHAR(NAME, SIZE) \
	wchar_t NAME[SIZE]; \
	ZERO(NAME)

#define INIT_ZERO_CHAR(NAME, SIZE) \
	char NAME[SIZE]; \
	ZERO(NAME) 

void PrintLn(const wchar_t *message, const wchar_t *message2, const wchar_t *message3, const wchar_t *message4);
void PrintLn(const wchar_t *message, const wchar_t *message2, const wchar_t *message3);
void PrintLn(const wchar_t *message, const wchar_t *message2);
void PrintLn(const wchar_t *message);
void PrintLn(const char* message);
void PrintLn(const char* message, int line);
void PrintLn(const wchar_t *message, int line);
void PrintLn(int line);
void GetCurrentTimeAndDate(char(&time)[MAX_TIME_SIZE]);
void WriteLogFile(const wchar_t* szString);
void WriteLogFile(const char* szString);
// End extra code (debug tools)


// Begin extra code (Remote Session)
#pragma comment(lib, "user32.lib")
#define TERMINAL_SERVER_KEY L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
#define GLASS_SESSION_ID    L"GlassSessionId"
BOOL IsRemoteSession(void);
// End extra code (Remote Session)


//makes a copy of a field descriptor using CoTaskMemAlloc
HRESULT FieldDescriptorCoAllocCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR &rcpfd,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd
    );

//makes a copy of a field descriptor on the normal heap
HRESULT FieldDescriptorCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR &rcpfd,
    _Out_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *pcpfd
    );

//creates a UNICODE_STRING from a NULL-terminated string
HRESULT UnicodeStringInitWithString(
    _In_ PWSTR pwz,
    _Out_ UNICODE_STRING *pus
    );

//initializes a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the provided credentials
HRESULT KerbInteractiveUnlockLogonInit(
    _In_ PWSTR pwzDomain,
    _In_ PWSTR pwzUsername,
    _In_ PWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Out_ KERB_INTERACTIVE_UNLOCK_LOGON *pkiul
    );

//packages the credentials into the buffer that the system expects
HRESULT KerbInteractiveUnlockLogonPack(
    _In_ const KERB_INTERACTIVE_UNLOCK_LOGON &rkiulIn,
    _Outptr_result_bytebuffer_(*pcb) BYTE **prgb,
    _Out_ DWORD *pcb
    );

//get the authentication package that will be used for our logon attempt
HRESULT RetrieveNegotiateAuthPackage(
    _Out_ ULONG *pulAuthPackage
    );

//encrypt a password (if necessary) and copy it; if not, just copy it
HRESULT ProtectIfNecessaryAndCopyPassword(
    _In_ PCWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_result_nullonfailure_ PWSTR *ppwzProtectedPassword
    );

HRESULT KerbInteractiveUnlockLogonRepackNative(
    _In_reads_bytes_(cbWow) BYTE *rgbWow,
    _In_ DWORD cbWow,
    _Outptr_result_bytebuffer_(*pcbNative) BYTE **prgbNative,
    _Out_ DWORD *pcbNative
    );

void KerbInteractiveUnlockLogonUnpackInPlace(
    _Inout_updates_bytes_(cb) KERB_INTERACTIVE_UNLOCK_LOGON *pkiul,
    DWORD cb
    );

HRESULT DomainUsernameStringAlloc(
    _In_ PCWSTR pwszDomain,
    _In_ PCWSTR pwszUsername,
    _Outptr_result_nullonfailure_ PWSTR *ppwszDomainUsername
    );

// Begin extra code (UPN conversion)
HRESULT UpnUsernameDomainStringAlloc(
    _In_ PCWSTR pwszUsername,
	_In_ PCWSTR pwszDomain,
	_Outptr_result_nullonfailure_ PWSTR *ppwszUsernameDomain
	);
// End extra code (UPN conversion)

HRESULT SplitDomainAndUsername(
    _In_ PCWSTR pszQualifiedUserName,
	_Outptr_result_nullonfailure_ PWSTR *ppszDomain,
	_Outptr_result_nullonfailure_ PWSTR *ppszUsername
	);

// Begin extra code (detect remote session)
BOOL IsRemoteSession(void);
// End extra code (detect remote session)

// Begin extra code (multiOTP handling)
HRESULT multiotp_request(_In_ PCWSTR username,
	_In_ PCWSTR PREV_OTP,
	_In_ PCWSTR OTP,
	_In_ PCWSTR PREFIX_PASS
	);
// End extra code (UPN conversion)

// Begin extra code (ErrorInfo)
void ErrorInfo(LPTSTR lpszFunction);
// End extra code (ErrorInfo)
