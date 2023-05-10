/**
 * multiOTP Credential Provider
 *
 * Extra code provided "as is" for the multiOTP open source project
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.9.6.1
 * @date      2023-05-10
 * @since     2013
 * @copyright (c) 2016-2023 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright (c) 2012 Dominik Pretzsch
 * @copyright (c) Microsoft Corporation. All rights reserved.
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *   2022-05-20 5.9.0.2 SysCo/yj ENH: Once SMS or EMAIL link is clicked, the link is hidden and a message is displayed to let the user know that the token was sent
 *   2022-05-20 5.9.0.2 SysCo/yj FIX: When active directory server is available UPN username is stored in the registry UPNcache
 *   2020-08-31 5.8.0.0 SysCo/al ENH: Retarget to the last SDK 10.0.19041.1
 *   2019-12-20 5.6.2.0 SysCo/al ENH: Files reorganization.
 *                               ENH: "Change password on login" support
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

#ifndef _MULTIOTP_HELPERS_H
#define _MULTIOTP_HELPERS_H

#pragma once

#define MULTIOTP_SUCCESS ((HRESULT)0)
#define MULTIOTP_IS_WITHOUT2FA ((HRESULT)8)
#define MULTIOTP_UNKNOWN_ERROR ((HRESULT)99)
#define MULTIOTP_CHECK "multiOTP Credential Provider mode" // Special string to check that multiOTP is correctly running
#define MULTIOTP_DEBUG_LOGFILE_NAME "C:\\multiotp-credential-provider-debug.log"
#define MULTIOTP_RELEASE_LOGFILE_NAME "C:\\multiotp-credential-provider-release.log"
#define DEBUG_BOX(message) DebugBox(__FUNCTION__, __LINE__, message)

#if _DEBUG
#define DEBUG_MODE TRUE
#define DISPLAY_DEBUG_BOX TRUE
#define DEVELOP_MODE TRUE // For compatibiliy
#define SKIP_OTP_CHECK FALSE // Available in development only, ignore the OTP code check
#define LOGFILE_NAME MULTIOTP_DEBUG_LOGFILE_NAME
#else
#define DEBUG_MODE FALSE
#define DISPLAY_DEBUG_BOX FALSE
#define DEVELOP_MODE FALSE // For compatibiliy TODO change this block
#define SKIP_OTP_CHECK FALSE
#define LOGFILE_NAME MULTIOTP_RELEASE_LOGFILE_NAME
#endif

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
#include <string>
#include "SecureString.h"
 // Begin extra code (debug tools)

#define MAX_TIME_SIZE 250

#define MAX_ULONG  ((ULONG)(-1))

#define NOT_EMPTY(NAME) \
	(NAME != NULL && NAME[0] != NULL)

#define EMPTY(NAME) \
	(NAME == NULL || NAME[0] == NULL)

#define ZERO(NAME) \
	ZeroMemory(NAME, sizeof(NAME))

#define INIT_ZERO_WCHAR(NAME, SIZE) \
	wchar_t NAME[SIZE]; \
	ZERO(NAME)

#define INIT_ZERO_CHAR(NAME, SIZE) \
	char NAME[SIZE]; \
	ZERO(NAME) 

void DebugBox(const char* title, int line, const wchar_t* message);
void DebugBox(const char* title, int line, const char* message);
void PrintLn(const wchar_t* message, const wchar_t* message2, const wchar_t* message3, const wchar_t* message4, const wchar_t* message5);
void PrintLn(const wchar_t* message, const wchar_t* message2, const wchar_t* message3, const wchar_t* message4);
void PrintLn(const wchar_t* message, const wchar_t* message2, const wchar_t* message3);
void PrintLn(const wchar_t* message, const wchar_t* message2);
void PrintLn(const wchar_t* message);
void PrintLn(const char* message);
void PrintLn(const char* message, int line);
void PrintLn(const wchar_t* message, int line);
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
HRESULT MultiOTPFieldDescriptorCoAllocCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
);

//makes a copy of a field descriptor on the normal heap
HRESULT MultiOTPFieldDescriptorCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    _Out_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
);

//creates a UNICODE_STRING from a NULL-terminated string
HRESULT MultiOTPUnicodeStringInitWithString(
    _In_ PWSTR pwz,
    _Out_ UNICODE_STRING* pus
);

//initializes a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the provided credentials
HRESULT MultiOTPKerbInteractiveUnlockLogonInit(
    _In_ PWSTR pwzDomain,
    _In_ PWSTR pwzUsername,
    _In_ PWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Out_ KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
);

//packages the credentials into the buffer that the system expects
HRESULT MultiOTPKerbInteractiveUnlockLogonPack(
    _In_ const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    _Outptr_result_bytebuffer_(*pcb) BYTE** prgb,
    _Out_ DWORD* pcb
);

//packages the credentials into the buffer that the system expects
HRESULT MultiOTPKerbChangePasswordPack(
    __in const KERB_CHANGEPASSWORD_REQUEST& rkcrIn,
    __deref_out_bcount(*pcb) BYTE** prgb,
    __out DWORD* pcb
);

//get the authentication package that will be used for our logon attempt
HRESULT MultiOTPRetrieveNegotiateAuthPackage(
    _Out_ ULONG* pulAuthPackage
);

//encrypt a password (if necessary) and copy it; if not, just copy it
HRESULT MultiOTPProtectIfNecessaryAndCopyPassword(
    _In_ PCWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_result_nullonfailure_ PWSTR* ppwzProtectedPassword
);

HRESULT MultiOTPKerbInteractiveUnlockLogonRepackNative(
    _In_reads_bytes_(cbWow) BYTE* rgbWow,
    _In_ DWORD cbWow,
    _Outptr_result_bytebuffer_(*pcbNative) BYTE** prgbNative,
    _Out_ DWORD* pcbNative
);

void MultiOTPKerbInteractiveUnlockLogonUnpackInPlace(
    _Inout_updates_bytes_(cb) KERB_INTERACTIVE_UNLOCK_LOGON* pkiul,
    DWORD cb
);

HRESULT MultiOTPDomainUsernameStringAlloc(
    _In_ PCWSTR pwszDomain,
    _In_ PCWSTR pwszUsername,
    _Outptr_result_nullonfailure_ PWSTR* ppwszDomainUsername
);

// Begin extra code (UPN conversion)
HRESULT UpnUsernameDomainStringAlloc(
    _In_ PCWSTR pwszUsername,
    _In_ PCWSTR pwszDomain,
    _Outptr_result_nullonfailure_ PWSTR* ppwszUsernameDomain
);
// End extra code (UPN conversion)

HRESULT SplitDomainAndUsername(
    _In_ PCWSTR pszQualifiedUserName,
    _Outptr_result_nullonfailure_ PWSTR* ppszDomain,
    _Outptr_result_nullonfailure_ PWSTR* ppszUsername
);

// Begin extra code (detect remote session)
BOOL IsRemoteSession(void);
// End extra code (detect remote session)

// Begin extra code (multiOTP handling)
HRESULT multiotp_request(_In_ std::wstring username,
    _In_ SecureWString PREV_OTP,
    _In_ SecureWString OTP
);
// End extra code (UPN conversion)

// Begin extra code (ErrorInfo)
void ErrorInfo(LPTSTR lpszFunction);
// End extra code (ErrorInfo)

void SeparateUserAndDomainName(
    __in wchar_t* domain_slash_username,
    __out wchar_t* username,
    __in int sizeUsername,
    __out_opt wchar_t* domain,
    __in_opt int sizeDomain
);

void WideCharToChar(
    __in PWSTR data,
    __in int buffSize,
    __out char* pc
);

void CharToWideChar(
    __in char* data,
    __in int buffSize,
    __out PWSTR pc
);

std::wstring getCleanUsername(
    const std::wstring username,
    const std::wstring domain
);

HRESULT hideCPField(__in ICredentialProviderCredential* self, __in ICredentialProviderCredentialEvents* pCPCE, __in DWORD fieldId);
HRESULT displayCPField(__in ICredentialProviderCredential* self, __in ICredentialProviderCredentialEvents* pCPCE, __in DWORD fieldId);

int minutesSinceEpoch();

HRESULT multiotp_request_command(_In_ std::wstring command, _In_ std::wstring params);

void replaceAll(std::wstring& str, const std::wstring& from, const std::wstring& to);
#endif