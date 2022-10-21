/**
 * multiOTP Credential Provider
 *
 * Extra code provided "as is" for the multiOTP open source project
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.9.3.1
 * @date      2022-10-21
 * @since     2013
 * @copyright (c) 2016-2022 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright (c) 2012 Dominik Pretzsch
 * @copyright (c) Microsoft Corporation. All rights reserved.
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2022-05-20 5.9.0.2 SysCo/yj ENH: Once SMS or EMAIL link is clicked, the link is hidden and a message is displayed to let the user know that the token was sent.
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

#include "MultiotpHelpers.h"
#include <intsafe.h>

#include <sstream>
#include <atlstr.h>

 // To extract IP address of the client
#include <Wtsapi32.h>

#include "MultiotpRegistry.h"
#include "SecureString.h"
#include "Logger.h"

// To use the TranslateNameW function
#include "Security.h"
// DsGetDcNameW
#include "DsGetDC.h"

// Begin extra code (debug tools)

void DebugBox(const char* title, int line, const wchar_t* message) {
    if (DISPLAY_DEBUG_BOX) {
        char fulltitle[1024];
        wchar_t wfulltitle[1024];
        wchar_t wfullmessage[2048];
        size_t outSize;
        sprintf_s(fulltitle, sizeof(fulltitle), "#%d: %s", line, title);
        mbstowcs_s(&outSize, wfulltitle, fulltitle, strlen(fulltitle) + 1);

        wcscpy_s(wfullmessage, 2048, wfulltitle);
        wcscat_s(wfullmessage, 2048, L"\n\n");
        wcscat_s(wfullmessage, 2048, message);

        MessageBox(NULL, wfullmessage, wfulltitle, MB_OK | MB_SYSTEMMODAL);
    }
}

void DebugBox(const char* title, int line, const char* message) {
    wchar_t wmessage[1024];
    size_t outSize;
    mbstowcs_s(&outSize, wmessage, message, strlen(message) + 1);
    DebugBox(title, line, wmessage);
}

void PrintLn(const wchar_t* message, const wchar_t* message2, const wchar_t* message3, const wchar_t* message4, const wchar_t* message5)
{
    INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
    GetCurrentTimeAndDate(date_time);
    WriteLogFile(date_time);

    WriteLogFile(message);
    WriteLogFile(message2);
    WriteLogFile(message3);
    WriteLogFile(message4);
    WriteLogFile(message5);
    WriteLogFile("\n");
}
void PrintLn(const wchar_t* message, const wchar_t* message2, const wchar_t* message3, const wchar_t* message4)
{
    INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
    GetCurrentTimeAndDate(date_time);
    WriteLogFile(date_time);

    WriteLogFile(message);
    WriteLogFile(message2);
    WriteLogFile(message3);
    WriteLogFile(message4);
    WriteLogFile("\n");
}
void PrintLn(const wchar_t* message, const wchar_t* message2, const wchar_t* message3)
{
    PrintLn(message, message2, message3, L"");
}
void PrintLn(const wchar_t* message, const wchar_t* message2)
{
    PrintLn(message, message2, L"");
}
void PrintLn(const wchar_t* message) {
    PrintLn(message, L"");
}

void PrintLn(const char* message)
{
    INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
    GetCurrentTimeAndDate(date_time);
    WriteLogFile(date_time);

    WriteLogFile(message);
    WriteLogFile("\n");
}

void PrintLn(const char* message, int line)
{
    INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
    GetCurrentTimeAndDate(date_time);
    WriteLogFile(date_time);

    char oneline1[1024];
    sprintf_s(oneline1, sizeof(oneline1), message, line);

    WriteLogFile(oneline1);
    WriteLogFile("\n");
}

void PrintLn(const wchar_t* message, int line)
{
    INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
    GetCurrentTimeAndDate(date_time);
    WriteLogFile(date_time);

    // MessageBox(NULL, (LPCWSTR)message, NULL, MB_ICONWARNING);

    wchar_t onelinew[1024];
    swprintf_s(onelinew, sizeof(onelinew) / sizeof(wchar_t), message, line);

    //	OutputDebugStringW(message);
    WriteLogFile(onelinew);
    WriteLogFile("\n");
}

void PrintLn(int line)
{
    INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
    GetCurrentTimeAndDate(date_time);
    WriteLogFile(date_time);

    char onelinedt[1024];
    sprintf_s(onelinedt, sizeof(onelinedt), "%d", line);

    WriteLogFile(onelinedt);
    WriteLogFile("\n");
}

void WriteLogFile(const char* szString)
{
    if (DEBUG_MODE) {
        FILE* pFile;
        if (fopen_s(&pFile, LOGFILE_NAME, "a") == 0)
        {
            fprintf(pFile, "%s", szString);
            fclose(pFile);
        }
    }
}

void WriteLogFile(const wchar_t* szString)
{
    if (DEBUG_MODE) {
        FILE* pFile;
        if (fopen_s(&pFile, LOGFILE_NAME, "a") == 0)
        {
            fwprintf(pFile, L"%s", szString);
            fclose(pFile);
        }
    }
}

void GetCurrentTimeAndDate(char(&time)[MAX_TIME_SIZE])
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    sprintf_s(time, ARRAYSIZE(time), "%04d%02d%02d %02d%02d%02d%04d: ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}
// End extra code (debug tools)

//
// Copies the field descriptor pointed to by rcpfd into a buffer allocated
// using CoTaskMemAlloc. Returns that buffer in ppcpfd.
//
HRESULT MultiOTPFieldDescriptorCoAllocCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
)
{
    HRESULT hr;
    *ppcpfd = nullptr;
    DWORD cbStruct = sizeof(**ppcpfd);

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);
    if (pcpfd)
    {
        pcpfd->dwFieldID = rcpfd.dwFieldID;
        pcpfd->cpft = rcpfd.cpft;
        pcpfd->guidFieldType = rcpfd.guidFieldType;

        if (rcpfd.pszLabel)
        {
            hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
        }
        else
        {
            pcpfd->pszLabel = nullptr;
            hr = S_OK;
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    if (SUCCEEDED(hr))
    {
        *ppcpfd = pcpfd;
    }
    else
    {
        CoTaskMemFree(pcpfd);
    }

    return hr;
}

//
// Coppies rcpfd into the buffer pointed to by pcpfd. The caller is responsible for
// allocating pcpfd. This function uses CoTaskMemAlloc to allocate memory for
// pcpfd->pszLabel.
//
HRESULT MultiOTPFieldDescriptorCoAllocCopy(
    _In_ const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    _Out_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
)
{
    HRESULT hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

    cpfd.dwFieldID = rcpfd.dwFieldID;
    cpfd.cpft = rcpfd.cpft;
    cpfd.guidFieldType = rcpfd.guidFieldType;

    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
    }
    else
    {
        cpfd.pszLabel = nullptr;
        hr = S_OK;
    }

    if (SUCCEEDED(hr))
    {
        *pcpfd = cpfd;
    }

    return hr;
}

//
// This function copies the length of pwz and the pointer pwz into the UNICODE_STRING structure
// This function is intended for serializing a credential in GetSerialization only.
// Note that this function just makes a copy of the string pointer. It DOES NOT ALLOCATE storage!
// Be very, very sure that this is what you want, because it probably isn't outside of the
// exact GetSerialization call where the sample uses it.
//
HRESULT MultiOTPUnicodeStringInitWithString(
    _In_ PWSTR pwz,
    _Out_ UNICODE_STRING* pus
)
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenString = wcslen(pwz);
        USHORT usCharCount;
        hr = SizeTToUShort(lenString, &usCharCount);
        if (SUCCEEDED(hr))
        {
            USHORT usSize;
            hr = SizeTToUShort(sizeof(wchar_t), &usSize);
            if (SUCCEEDED(hr))
            {
                hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
                if (SUCCEEDED(hr))
                {
                    pus->MaximumLength = pus->Length;
                    pus->Buffer = pwz;
                    hr = S_OK;
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

//
// The following function is intended to be used ONLY with the Kerb*Pack functions.  It does
// no bounds-checking because its callers have precise requirements and are written to respect
// its limitations.
// You can read more about the UNICODE_STRING type at:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/unicode_string.asp
//
static void _UnicodeStringPackedUnicodeStringCopy(
    __in const UNICODE_STRING& rus,
    __in PWSTR pwzBuffer,
    __out UNICODE_STRING* pus
)
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

//
// Initialize the members of a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the
// passed-in strings.  This is useful if you will later use KerbInteractiveUnlockLogonPack
// to serialize the structure.
//
// The password is stored in encrypted form for CPUS_LOGON and CPUS_UNLOCK_WORKSTATION
// because the system can accept encrypted credentials.  It is not encrypted in CPUS_CREDUI
// because we cannot know whether our caller can accept encrypted credentials.
//
HRESULT MultiOTPKerbInteractiveUnlockLogonInit(
    _In_ PWSTR pwzDomain,
    _In_ PWSTR pwzUsername,
    _In_ PWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Out_ KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
)
{
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;

    // Note: this method uses custom logic to pack a KERB_INTERACTIVE_UNLOCK_LOGON with a
    // serialized credential.  We could replace the calls to UnicodeStringInitWithString
    // and KerbInteractiveUnlockLogonPack with a single cal to CredPackAuthenticationBuffer,
    // but that API has a drawback: it returns a KERB_INTERACTIVE_UNLOCK_LOGON whose
    // MessageType is always KerbInteractiveLogon.
    //
    // If we only handled CPUS_LOGON, this drawback would not be a problem.  For
    // CPUS_UNLOCK_WORKSTATION, we could cast the output buffer of CredPackAuthenticationBuffer
    // to KERB_INTERACTIVE_UNLOCK_LOGON and modify the MessageType to KerbWorkstationUnlockLogon,
    // but such a cast would be unsupported -- the output format of CredPackAuthenticationBuffer
    // is not officially documented.

    // Initialize the UNICODE_STRINGS to share our username and password strings.
    HRESULT hr = MultiOTPUnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);
    if (SUCCEEDED(hr))
    {
        hr = MultiOTPUnicodeStringInitWithString(pwzUsername, &pkil->UserName);
        if (SUCCEEDED(hr))
        {
            hr = MultiOTPUnicodeStringInitWithString(pwzPassword, &pkil->Password);
            if (SUCCEEDED(hr))
            {
                // Set a MessageType based on the usage scenario.
                switch (cpus)
                {
                case CPUS_UNLOCK_WORKSTATION:
                    pkil->MessageType = KerbWorkstationUnlockLogon;
                    hr = S_OK;
                    break;

                case CPUS_LOGON:
                    pkil->MessageType = KerbInteractiveLogon;
                    hr = S_OK;
                    break;

                case CPUS_CREDUI:
                    pkil->MessageType = (KERB_LOGON_SUBMIT_TYPE)0; // MessageType does not apply to CredUI
                    hr = S_OK;
                    break;

                default:
                    hr = E_FAIL;
                    break;
                }

                if (SUCCEEDED(hr))
                {
                    // KERB_INTERACTIVE_UNLOCK_LOGON is just a series of structures.  A
                    // flat copy will properly initialize the output parameter.
                    CopyMemory(pkiul, &kiul, sizeof(*pkiul));
                }
            }
        }
    }

    return hr;
}

//
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.  In these, the PWSTR members of each
// UNICODE_STRING are not actually pointers but byte offsets into the overall buffer represented
// by the packed KERB_INTERACTIVE_UNLOCK_LOGON.  For example:
//
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> Length is in bytes, not characters
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName begins immediately
//                                                                              after the KERB_... struct in the buffer
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS are NOT null-terminated
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
//
// THere's more information on this at:
// http://msdn.microsoft.com/msdnmag/issues/05/06/SecurityBriefs/#void
//

HRESULT MultiOTPKerbInteractiveUnlockLogonPack(
    _In_ const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    _Outptr_result_bytebuffer_(*pcb) BYTE** prgb,
    _Out_ DWORD* pcb
)
{
    HRESULT hr;

    const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
        pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Password.Length;

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);
    if (pkiulOut)
    {
        ZeroMemory(&pkiulOut->LogonId, sizeof(pkiulOut->LogonId));

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the KERB_INTERACTIVE_UNLOCK_LOGON
        //
        KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;

        //
        // copy each string,
        // fix up appropriate buffer pointer to be offset,
        // advance buffer pointer over copied characters in extra space
        //
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Password, (PWSTR)pbBuffer, &pkilOut->Password);
        pkilOut->Password.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

        *prgb = (BYTE*)pkiulOut;
        *pcb = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

HRESULT MultiOTPKerbChangePasswordPack(
    const KERB_CHANGEPASSWORD_REQUEST& rkcrIn,
    BYTE** prgb,
    DWORD* pcb
)
{
    HRESULT hr;

    DWORD cb = sizeof(rkcrIn) +
        rkcrIn.DomainName.Length +
        rkcrIn.AccountName.Length +
        rkcrIn.OldPassword.Length +
        rkcrIn.NewPassword.Length;

    KERB_CHANGEPASSWORD_REQUEST* pkcr = (KERB_CHANGEPASSWORD_REQUEST*)CoTaskMemAlloc(cb);

    if (pkcr)
    {
        pkcr->MessageType = rkcrIn.MessageType;

        BYTE* pbBuffer = (BYTE*)pkcr + sizeof(KERB_CHANGEPASSWORD_REQUEST);

        _UnicodeStringPackedUnicodeStringCopy(rkcrIn.DomainName, (PWSTR)pbBuffer, &pkcr->DomainName);
        pkcr->DomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkcr);
        pbBuffer += pkcr->DomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(rkcrIn.AccountName, (PWSTR)pbBuffer, &pkcr->AccountName);
        pkcr->AccountName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkcr);
        pbBuffer += pkcr->AccountName.Length;

        _UnicodeStringPackedUnicodeStringCopy(rkcrIn.OldPassword, (PWSTR)pbBuffer, &pkcr->OldPassword);
        pkcr->OldPassword.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkcr);
        pbBuffer += pkcr->OldPassword.Length;

        _UnicodeStringPackedUnicodeStringCopy(rkcrIn.NewPassword, (PWSTR)pbBuffer, &pkcr->NewPassword);
        pkcr->NewPassword.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkcr);

        *prgb = (BYTE*)pkcr;
        *pcb = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}

//
// This function packs the string pszSourceString in pszDestinationString
// for use with LSA functions including LsaLookupAuthenticationPackage.
//
static HRESULT _LsaInitString(
    __out PSTRING pszDestinationString,
    __in PCSTR pszSourceString
)
{
    size_t cchLength = strlen(pszSourceString);
    USHORT usLength;
    HRESULT hr = SizeTToUShort(cchLength, &usLength);
    if (SUCCEEDED(hr))
    {
        pszDestinationString->Buffer = (PCHAR)pszSourceString;
        pszDestinationString->Length = usLength;
        pszDestinationString->MaximumLength = pszDestinationString->Length + 1;
        hr = S_OK;
    }
    return hr;
}

//
// Retrieves the 'negotiate' AuthPackage from the LSA. In this case, Kerberos
// For more information on auth packages see this msdn page:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/msv1_0_lm20_logon.asp
//
HRESULT MultiOTPRetrieveNegotiateAuthPackage(_Out_ ULONG* pulAuthPackage)
{
    HRESULT hr;
    HANDLE hLsa;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszKerberosName;
        _LsaInitString(&lsaszKerberosName, NEGOSSP_NAME_A);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberosName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr = HRESULT_FROM_NT(status);
    }

    return hr;
}

//
// Return a copy of pwzToProtect encrypted with the CredProtect API.
//
// pwzToProtect must not be NULL or the empty string.
//
static HRESULT _ProtectAndCopyString(
    _In_ PCWSTR pwzToProtect,
    _Outptr_result_nullonfailure_ PWSTR* ppwzProtected
)
{
    *ppwzProtected = nullptr;

    // pwzToProtect is const, but CredProtect takes a non-const string.
    // So, make a copy that we know isn't const.
    PWSTR pwzToProtectCopy;
    HRESULT hr = SHStrDupW(pwzToProtect, &pwzToProtectCopy);
    if (SUCCEEDED(hr))
    {
        // The first call to CredProtect determines the length of the encrypted string.
        // Because we pass a NULL output buffer, we expect the call to fail.
        //
        // Note that the third parameter to CredProtect, the number of characters of pwzToProtectCopy
        // to encrypt, must include the NULL terminator!
        DWORD cchProtected = 0;
        if (!CredProtectW(FALSE, pwzToProtectCopy, (DWORD)wcslen(pwzToProtectCopy) + 1, nullptr, &cchProtected, nullptr))
        {
            DWORD dwErr = GetLastError();

            if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
            {
                // Allocate a buffer long enough for the encrypted string.
                PWSTR pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(wchar_t));
                if (pwzProtected)
                {
                    // The second call to CredProtect actually encrypts the string.
                    if (CredProtectW(FALSE, pwzToProtectCopy, (DWORD)wcslen(pwzToProtectCopy) + 1, pwzProtected, &cchProtected, nullptr))
                    {
                        *ppwzProtected = pwzProtected;
                        hr = S_OK;
                    }
                    else
                    {
                        CoTaskMemFree(pwzProtected);

                        dwErr = GetLastError();
                        hr = HRESULT_FROM_WIN32(dwErr);
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }
            else
            {
                hr = HRESULT_FROM_WIN32(dwErr);
            }
        }
        else
        {
            hr = E_UNEXPECTED;
        }

        CoTaskMemFree(pwzToProtectCopy);
    }

    return hr;
}

//
// If pwzPassword should be encrypted, return a copy encrypted with CredProtect.
//
// If not, just return a copy.
//
HRESULT MultiOTPProtectIfNecessaryAndCopyPassword(
    _In_ PCWSTR pwzPassword,
    _In_ CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _Outptr_result_nullonfailure_ PWSTR* ppwzProtectedPassword
)
{
    *ppwzProtectedPassword = nullptr;

    HRESULT hr;

    // ProtectAndCopyString is intended for non-empty strings only.  Empty passwords
    // do not need to be encrypted.
    if (pwzPassword && *pwzPassword)
    {
        // pwzPassword is const, but CredIsProtected takes a non-const string.
        // So, ake a copy that we know isn't const.
        PWSTR pwzPasswordCopy;
        hr = SHStrDupW(pwzPassword, &pwzPasswordCopy);
        if (SUCCEEDED(hr))
        {
            bool bCredAlreadyEncrypted = false;
            CRED_PROTECTION_TYPE protectionType;

            // If the password is already encrypted, we should not encrypt it again.
            // An encrypted password may be received through SetSerialization in the
            // CPUS_LOGON scenario during a Terminal Services connection, for instance.
            if (CredIsProtectedW(pwzPasswordCopy, &protectionType))
            {
                if (CredUnprotected != protectionType)
                {
                    bCredAlreadyEncrypted = true;
                }
            }

            // Passwords should not be encrypted in the CPUS_CREDUI scenario.  We
            // cannot know if our caller expects or can handle an encryped password.
            if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted)
            {
                hr = SHStrDupW(pwzPasswordCopy, ppwzProtectedPassword);
            }
            else
            {
                hr = _ProtectAndCopyString(pwzPasswordCopy, ppwzProtectedPassword);
            }

            CoTaskMemFree(pwzPasswordCopy);
        }
    }
    else
    {
        hr = SHStrDupW(L"", ppwzProtectedPassword);
    }

    return hr;
}

//
// Unpack a KERB_INTERACTIVE_UNLOCK_LOGON *in place*.  That is, reset the Buffers from being offsets to
// being real pointers.  This means, of course, that passing the resultant struct across any sort of
// memory space boundary is not going to work -- repack it if necessary!
//
void MultiOTPKerbInteractiveUnlockLogonUnpackInPlace(
    _Inout_updates_bytes_(cb) KERB_INTERACTIVE_UNLOCK_LOGON* pkiul,
    DWORD cb
)
{

    PrintLn("KerbInteractiveUnlockLogonUnpackInPlace method");

    if (sizeof(*pkiul) <= cb)
    {
        KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;

        // Sanity check: if the range described by each (Buffer + MaximumSize) falls within the total bytecount,
        // we can be pretty confident that the Buffers are actually offsets and that this is a packed credential.
        if (((ULONG_PTR)pkil->LogonDomainName.Buffer + pkil->LogonDomainName.MaximumLength <= cb) &&
            ((ULONG_PTR)pkil->UserName.Buffer + pkil->UserName.MaximumLength <= cb) &&
            ((ULONG_PTR)pkil->Password.Buffer + pkil->Password.MaximumLength <= cb))
        {
            pkil->LogonDomainName.Buffer = pkil->LogonDomainName.Buffer
                ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->LogonDomainName.Buffer)
                : nullptr;

            pkil->UserName.Buffer = pkil->UserName.Buffer
                ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->UserName.Buffer)
                : nullptr;

            pkil->Password.Buffer = pkil->Password.Buffer
                ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->Password.Buffer)
                : nullptr;

            PrintLn("pkil->LogonDomainName.Buffer");
            PrintLn(pkil->LogonDomainName.Buffer);
            PrintLn("pkil->UserName.Buffer");
            PrintLn(pkil->UserName.Buffer);
            PrintLn("pkil->Password.Buffer");
            PrintLn(pkil->Password.Buffer);
        }
    }
}

//
// Use the CredPackAuthenticationBuffer and CredUnpackAuthenticationBuffer to convert a 32 bit WOW
// cred blob into a 64 bit native blob by unpacking it and immediately repacking it.
//
HRESULT MultiOTPKerbInteractiveUnlockLogonRepackNative(
    _In_reads_bytes_(cbWow) BYTE* rgbWow,
    _In_ DWORD cbWow,
    _Outptr_result_bytebuffer_(*pcbNative) BYTE** prgbNative,
    _Out_ DWORD* pcbNative
)
{
    HRESULT hr = E_OUTOFMEMORY;
    PWSTR pszDomainUsername = nullptr;
    DWORD cchDomainUsername = 0;
    PWSTR pszPassword = nullptr;
    DWORD cchPassword = 0;

    *prgbNative = nullptr;
    *pcbNative = 0;

    // Unpack the 32 bit KERB structure
    CredUnPackAuthenticationBufferW(CRED_PACK_WOW_BUFFER, rgbWow, cbWow, pszDomainUsername, &cchDomainUsername, nullptr, nullptr, pszPassword, &cchPassword);
    if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
    {
        pszDomainUsername = (PWSTR)LocalAlloc(0, cchDomainUsername * sizeof(wchar_t));
        if (pszDomainUsername)
        {
            pszPassword = (PWSTR)LocalAlloc(0, cchPassword * sizeof(wchar_t));
            if (pszPassword)
            {
                if (CredUnPackAuthenticationBufferW(CRED_PACK_WOW_BUFFER, rgbWow, cbWow, pszDomainUsername, &cchDomainUsername, nullptr, nullptr, pszPassword, &cchPassword))
                {
                    hr = S_OK;
                }
                else
                {
                    hr = GetLastError();
                }
            }
        }
    }

    // Repack native
    if (SUCCEEDED(hr))
    {
        hr = E_OUTOFMEMORY;
        CredPackAuthenticationBufferW(0, pszDomainUsername, pszPassword, *prgbNative, pcbNative);
        if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
        {
            *prgbNative = (BYTE*)LocalAlloc(LMEM_ZEROINIT, *pcbNative);
            if (*prgbNative)
            {
                if (CredPackAuthenticationBufferW(0, pszDomainUsername, pszPassword, *prgbNative, pcbNative))
                {
                    hr = S_OK;
                }
                else
                {
                    LocalFree(*prgbNative);
                }
            }
        }
    }

    LocalFree(pszDomainUsername);
    if (pszPassword)
    {
        SecureZeroMemory(pszPassword, cchPassword * sizeof(wchar_t));
        LocalFree(pszPassword);
    }
    return hr;
}

// Concatonates pwszDomain and pwszUsername and places the result in *ppwszDomainUsername.
HRESULT MultiOTPDomainUsernameStringAlloc(
    _In_ PCWSTR pwszDomain,
    _In_ PCWSTR pwszUsername,
    _Outptr_result_nullonfailure_ PWSTR* ppwszDomainUsername
)
{
    HRESULT hr;
    *ppwszDomainUsername = nullptr;
    size_t cchDomain = wcslen(pwszDomain);
    size_t cchUsername = wcslen(pwszUsername);
    // Length of domain, 1 character for '\', length of Username, plus null terminator.
    size_t cbLen = sizeof(wchar_t) * (cchDomain + 1 + cchUsername + 1);
    PWSTR pwszDest = (PWSTR)HeapAlloc(GetProcessHeap(), 0, cbLen);
    if (pwszDest)
    {
        hr = StringCbPrintfW(pwszDest, cbLen, L"%s\\%s", pwszDomain, pwszUsername);
        if (SUCCEEDED(hr))
        {
            *ppwszDomainUsername = pwszDest;
        }
        else
        {
            HeapFree(GetProcessHeap(), 0, pwszDest);
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

// Begin extra code (UPN conversion)
// Concatenates UPN (with @) pwszUsername and pwszDomain and places the result in *ppwszUsernameDomain.
HRESULT UpnUsernameDomainStringAlloc(
    _In_ PCWSTR pwszUsername,
    _In_ PCWSTR pwszDomain,
    _Outptr_result_nullonfailure_ PWSTR* ppwszUsernameDomain
)
{
    HRESULT hr;
    *ppwszUsernameDomain = nullptr;
    size_t cchUsername = wcslen(pwszUsername);
    size_t cchDomain = wcslen(pwszDomain);
    // Length of Username, 1 character for '@', length of domain, plus null terminator.
    size_t cbLen = sizeof(wchar_t) * (cchUsername + 1 + cchDomain + 1);
    PWSTR pwszDest = (PWSTR)HeapAlloc(GetProcessHeap(), 0, cbLen);
    if (pwszDest)
    {
        hr = StringCbPrintfW(pwszDest, cbLen, L"%s@%s", pwszUsername, pwszDomain);
        if (SUCCEEDED(hr))
        {
            *ppwszUsernameDomain = pwszDest;
        }
        else
        {
            HeapFree(GetProcessHeap(), 0, pwszDest);
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}
// End extra code (UPN conversion)

HRESULT SplitDomainAndUsername(_In_ PCWSTR pszQualifiedUserName, _Outptr_result_nullonfailure_ PWSTR* ppszDomain, _Outptr_result_nullonfailure_ PWSTR* ppszUsername)
{
    HRESULT hr = E_UNEXPECTED;
    *ppszDomain = nullptr;
    *ppszUsername = nullptr;
    PWSTR pszDomain;
    PWSTR pszUsername;
    const wchar_t* pchWhack = wcschr(pszQualifiedUserName, L'\\');
    const wchar_t* pchEnd = pszQualifiedUserName + wcslen(pszQualifiedUserName) - 1;
    
    // Begin extra code (UPN support)
    const wchar_t* pchWhatSign = wcschr(pszQualifiedUserName, L'@');
    // End extra code (UPN support)

    if (pchWhack != nullptr && pchWhatSign != nullptr) // for example login with RDP like abc@domain.ch => domain.ch\abcd@domain.ch
    {
        const wchar_t* pchUsernameBegin = pchWhack+1;
        const wchar_t* pchUsernameEnd = pchWhatSign - 1;
        const wchar_t* pchDomainBegin = pszQualifiedUserName;
        const wchar_t* pchDomainEnd = pchWhack-1;

        size_t lenDomain = pchDomainEnd - pchDomainBegin + 1; // number of actual chars, NOT INCLUDING null terminated string
        pszDomain = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenDomain + 1)));
        if (pszDomain != nullptr)
        {
            hr = StringCchCopyN(pszDomain, lenDomain + 1, pchDomainBegin, lenDomain);
            if (SUCCEEDED(hr))
            {
                size_t lenUsername = pchUsernameEnd - pchUsernameBegin + 1; // number of actual chars, NOT INCLUDING null terminated string
                pszUsername = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenUsername + 1)));
                if (pszUsername != nullptr)
                {
                    hr = StringCchCopyN(pszUsername, lenUsername + 1, pchUsernameBegin, lenUsername);
                    if (SUCCEEDED(hr))
                    {
                        *ppszDomain = pszDomain;
                        *ppszUsername = pszUsername;
                    }
                    else
                    {
                        CoTaskMemFree(pszUsername);
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }

            if (FAILED(hr))
            {
                CoTaskMemFree(pszDomain);
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else if (pchWhack != nullptr)
    {
        const wchar_t* pchDomainBegin = pszQualifiedUserName;
        const wchar_t* pchDomainEnd = pchWhack - 1;
        const wchar_t* pchUsernameBegin = pchWhack + 1;
        const wchar_t* pchUsernameEnd = pchEnd;

        size_t lenDomain = pchDomainEnd - pchDomainBegin + 1; // number of actual chars, NOT INCLUDING null terminated string
        pszDomain = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenDomain + 1)));
        if (pszDomain != nullptr)
        {
            hr = StringCchCopyN(pszDomain, lenDomain + 1, pchDomainBegin, lenDomain);
            if (SUCCEEDED(hr))
            {
                size_t lenUsername = pchUsernameEnd - pchUsernameBegin + 1; // number of actual chars, NOT INCLUDING null terminated string
                pszUsername = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenUsername + 1)));
                if (pszUsername != nullptr)
                {
                    hr = StringCchCopyN(pszUsername, lenUsername + 1, pchUsernameBegin, lenUsername);
                    if (SUCCEEDED(hr))
                    {
                        *ppszDomain = pszDomain;
                        *ppszUsername = pszUsername;
                    }
                    else
                    {
                        CoTaskMemFree(pszUsername);
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }

            if (FAILED(hr))
            {
                CoTaskMemFree(pszDomain);
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    // Begin extra code (UPN support)
    // The user and domain names are only splitted, nothing better
    else if (pchWhatSign != nullptr)
    {
        const wchar_t* pchUsernameBegin = pszQualifiedUserName;
        const wchar_t* pchUsernameEnd = pchWhatSign - 1;
        const wchar_t* pchDomainBegin = pchWhatSign + 1;
        const wchar_t* pchDomainEnd = pchEnd;

        size_t lenDomain = pchDomainEnd - pchDomainBegin + 1; // number of actual chars, NOT INCLUDING null terminated string
        pszDomain = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenDomain + 1)));
        if (pszDomain != nullptr)
        {
            hr = StringCchCopyN(pszDomain, lenDomain + 1, pchDomainBegin, lenDomain);
            if (SUCCEEDED(hr))
            {
                size_t lenUsername = pchUsernameEnd - pchUsernameBegin + 1; // number of actual chars, NOT INCLUDING null terminated string
                pszUsername = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(wchar_t) * (lenUsername + 1)));
                if (pszUsername != nullptr)
                {
                    hr = StringCchCopyN(pszUsername, lenUsername + 1, pchUsernameBegin, lenUsername);
                    if (SUCCEEDED(hr))
                    {
                        *ppszDomain = pszDomain;
                        *ppszUsername = pszUsername;
                    }
                    else
                    {
                        CoTaskMemFree(pszUsername);
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }

            if (FAILED(hr))
            {
                CoTaskMemFree(pszDomain);
            }
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    // End extra code (UPN support)
    return hr;
}


// Begin extra code (Remote Session)
BOOL IsRemoteSession(void)
{

    LPTSTR ppBuffer = NULL;
    DWORD  pBytesReturned = 0;
    PWTS_CLIENT_ADDRESS pWTSCA = NULL;

    BOOL fIsRemoteSession = FALSE;

    if (GetSystemMetrics(SM_REMOTESESSION))
    {
        fIsRemoteSession = TRUE;
    }
    else {
        HKEY hRegKey = NULL;
        LONG lResult;

        lResult = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            TERMINAL_SERVER_KEY,
            0, // ulOptions
            KEY_READ,
            &hRegKey
        );

        if (lResult == ERROR_SUCCESS)
        {
            DWORD dwGlassSessionId;
            DWORD cbGlassSessionId = sizeof(dwGlassSessionId);
            DWORD dwType;

            lResult = RegQueryValueEx(
                hRegKey,
                GLASS_SESSION_ID,
                NULL, // lpReserved
                &dwType,
                (BYTE*)&dwGlassSessionId,
                &cbGlassSessionId
            );

            if (lResult == ERROR_SUCCESS)
            {
                DWORD dwCurrentSessionId;

                if (ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSessionId))
                {
                    fIsRemoteSession = (dwCurrentSessionId != dwGlassSessionId);
                }
            }
        }

        if (hRegKey)
        {
            RegCloseKey(hRegKey);
        }
    }

    if (fIsRemoteSession) {
        if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSClientAddress, &ppBuffer, &pBytesReturned)) {
            pWTSCA = (PWTS_CLIENT_ADDRESS)ppBuffer;

            // Address family can be only:
            // AF_UNSPEC  = 0 (unspecified)
            // AF_INET    = 2 (internetwork: UDP, TCP, etc.)
            // AF_IPX     = AF_NS = 6 (IPX protocols: IPX, SPX, etc.)
            // AF_NETBIOS = 17 (NetBios-style addresses)

            CString familyStr; familyStr.Empty();

            switch (pWTSCA->AddressFamily)
            {
            case 0:
                familyStr = "AF_UNSPEC";
                break;
            case 2:
                familyStr = "AF_INET";
                break;
            case 6:
                familyStr = "AF_IPX";
                break;
            case 17:
                familyStr = "AF_NETBIOS";
                break;
            }

            // The client local IP address is located in bytes 2, 3, 4, and 5.
            // The other bytes are not used.
            // If AddressFamily returns AF_UNSPEC, the first byte in Address
            // is initialized to zero.

            char IPaddress[50];
            sprintf_s(IPaddress, "%u.%u.%u.%u", pWTSCA->Address[2], pWTSCA->Address[3], pWTSCA->Address[4], pWTSCA->Address[5]);
            if (DEVELOP_MODE) PrintLn(IPaddress);
        }
        WTSFreeMemory(ppBuffer);
    }
    return fIsRemoteSession;
}
// End extra code (Remote Session)


// Begin extra code (multiOTP handling)
HRESULT multiotp_request(_In_ std::wstring username,
    _In_ SecureWString PREV_OTP,
    _In_ SecureWString OTP
)
{
    HRESULT hr = E_NOTIMPL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL bSuccess = FALSE;
    // Create a pipe for the redirection of the STDOUT 
    // of a child process. 
    HANDLE g_hChildStd_OUT_Rd = NULL;
    HANDLE g_hChildStd_OUT_Wr = NULL;
    SECURITY_ATTRIBUTES saAttr;

    DWORD exitCode;
    wchar_t cmd[2048];
    wchar_t options[2048];
    size_t len;
    PWSTR path;

    
    len = username.length();
    if (PREV_OTP.length() > 0) {
        len += PREV_OTP.length();
        len += 1;//space char
    }
    len += 1;//space char
    len += OTP.length();

    if (DEVELOP_MODE) PrintLn("cmd len: %d", int(len));

    //cmd = (PWSTR)CoTaskMemAlloc(sizeof(wchar_t) * (len + 1));//+1 null pointer

    // Credential provider mode
    wcscpy_s(cmd, 2048, L"-cp");
    wcscat_s(cmd, 2048, L" ");

    if (DEVELOP_MODE) {
        wcscat_s(cmd, 2048, L"-debug");
        wcscat_s(cmd, 2048, L" ");
    }

    if (PREV_OTP.length() > 0) {
        wcscat_s(cmd, 2048, L"-resync");
        wcscat_s(cmd, 2048, L" ");
    }

    wcscat_s(cmd, 2048, L"\"");
    wcscat_s(cmd, 2048, username.c_str());
    wcscat_s(cmd, 2048, L"\"");
    wcscat_s(cmd, 2048, L" ");

    if (PREV_OTP.length() > 0) {
        wcscat_s(cmd, 2048, L"\"");
        wcscat_s(cmd, 2048, PREV_OTP.c_str());
        wcscat_s(cmd, 2048, L"\"");
        wcscat_s(cmd, 2048, L" ");
    }

    wcscat_s(cmd, 2048, L"\"");
    wcscat_s(cmd, 2048, OTP.c_str());
    wcscat_s(cmd, 2048, L"\"");

    len = wcslen(cmd);
    if (DEVELOP_MODE) PrintLn("command len:%d", int(len));
    if (DEVELOP_MODE) PrintLn(cmd);
    //return hr;

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    bSuccess = CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0);
    if (bSuccess) {
        bSuccess = SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);
    }

    SecureZeroMemory(&si, sizeof(si));
    SecureZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

    si.hStdError = g_hChildStd_OUT_Wr;
    si.hStdOutput = g_hChildStd_OUT_Wr;
    si.dwFlags |= STARTF_USESTDHANDLES;

    hr = MULTIOTP_UNKNOWN_ERROR;
    

    if (readRegistryValueString(CONF_PATH, &path, L"c:\\multiotp\\") > 1) {
        DWORD timeout = 60;

        timeout = readRegistryValueInteger(CONF_TIMEOUT, timeout);

        DWORD server_timeout = 5;
        DWORD server_cache_level = 1;
        PWSTR shared_secret;
        PWSTR servers;
        std::wstring shared_secret_escaped;

        server_timeout = readRegistryValueInteger(CONF_SERVER_TIMEOUT, server_timeout);
        wchar_t server_timeout_string[1024];
        _ultow_s(server_timeout, server_timeout_string, 10);
        wcscpy_s(options, 2048, L"-server-timeout=");
        wcscat_s(options, 2048, server_timeout_string);
        wcscat_s(options, 2048, L" ");

        server_cache_level = readRegistryValueInteger(CONF_CACHE_ENABLED, server_cache_level);
        wchar_t server_cache_level_string[1024];
        _ultow_s(server_cache_level, server_cache_level_string, 10);
        wcscat_s(options, 2048, L"-server-cache-level=");
        wcscat_s(options, 2048, server_cache_level_string);
        wcscat_s(options, 2048, L" ");

        if (readRegistryValueString(CONF_SERVERS, &servers, L"") > 1) {
            wcscat_s(options, 2048, L"-server-url=");
            wcscat_s(options, 2048, servers);
            wcscat_s(options, 2048, L" ");
        }

        if (readRegistryValueString(CONF_SHARED_SECRET, &shared_secret, L"ClientServerSecret") > 1) {
            wcscat_s(options, 2048, L"\"");
            wcscat_s(options, 2048, L"-server-secret=");
            shared_secret_escaped = shared_secret;
            replaceAll(shared_secret_escaped, L"\"", L"\\\"");
            wcscat_s(options, 2048, shared_secret_escaped.c_str());
            wcscat_s(options, 2048, L"\"");
            wcscat_s(options, 2048, L" ");
        }

        wcscat_s(options, 2048, cmd);

        wchar_t appname[2048];

        wcscpy_s(appname, 2048, L"\"");
        wcscat_s(appname, 2048, path);
        size_t npath = wcslen(appname);
        if (appname[npath - 1] != '\\' && appname[npath - 1] != '/') {
            appname[npath] = '\\';
            appname[npath + 1] = '\0';
        }
        wcscat_s(appname, 2048, L"multiotp.exe");
        wcscat_s(appname, 2048, L"\"");
        wcscat_s(appname, 2048, L" ");
        wcscat_s(appname, 2048, options);

        if (DEVELOP_MODE) PrintLn(L"Calling ", appname);
        if (DEVELOP_MODE) PrintLn(L"with options ", options);
        // As argc 0 is the full filename itself, we use the lpCommandLine only 
        if (::CreateProcessW(NULL, appname, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, path, &si, &pi)) {

            DWORD result = WaitForSingleObject(pi.hProcess, (timeout * 1000));

            if (DEVELOP_MODE) PrintLn("WaitForSingleObject result: %d", result);

            if (result == WAIT_OBJECT_0) {
                GetExitCodeProcess(pi.hProcess, &exitCode);

                if (DEVELOP_MODE) PrintLn("multiotp.exe Exit Code: %d", exitCode);

                // hr = exitCode;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                // Read the data written to the pipe
                DWORD bytesInPipe = 0;
                bSuccess = TRUE;
                while (bSuccess && (bytesInPipe == 0)) {
                    bSuccess = PeekNamedPipe(g_hChildStd_OUT_Rd, NULL, 0, NULL, &bytesInPipe, NULL);
                }
                if (bytesInPipe != 0) {
                    DWORD dwRead;
                    CHAR* pipeContents = new CHAR[bytesInPipe];
                    bSuccess = ReadFile(g_hChildStd_OUT_Rd, pipeContents, bytesInPipe, &dwRead, NULL);
                    if (!(!bSuccess || dwRead == 0)) {
                        std::stringstream stream(pipeContents);
                        std::string str;
                        while (getline(stream, str))
                        {
                            if (DEVELOP_MODE) PrintLn(CStringW(str.c_str()));
                            if (str.find(MULTIOTP_CHECK) != std::string::npos) {
                                if (DEVELOP_MODE) PrintLn("Executable string info detected!");
                                hr = exitCode;
                            }
                        }
                    }
                }
            }
        }
        CoTaskMemFree(path);
    }
    return hr;
}
// End extra code (UPN conversion)


// Begin extra code (ErrorInfo)
void ErrorInfo(LPTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"),
        lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    // ExitProcess(dw);
}
// End extra code (ErrorInfo)

void SeparateUserAndDomainName(
    __in wchar_t* fq_username,
    __out wchar_t* username,
    __in int sizeUsername,
    __out_opt wchar_t* domain,
    __in_opt int sizeDomain
)
{
    int pos;
    for (pos = 0; fq_username[pos] != L'\\' && fq_username[pos] != L'@' && fq_username[pos] != NULL; pos++);

    if (fq_username[pos] != NULL)
    {
        if (fq_username[pos] == L'\\')
        {
            int i;
            for (i = 0; i < pos && i < sizeDomain; i++)
                domain[i] = fq_username[i];
            domain[i] = L'\0';

            for (i = 0; fq_username[pos + i + 1] != NULL && i < sizeUsername; i++)
                username[i] = fq_username[pos + i + 1];
            username[i] = L'\0';
        }
        else
        {
            int i;
            for (i = 0; i < pos && i < sizeUsername; i++)
                username[i] = fq_username[i];
            username[i] = L'\0';

            for (i = 0; fq_username[pos + i + 1] != NULL && i < sizeDomain; i++)
                domain[i] = fq_username[pos + i + 1];
            domain[i] = L'\0';
        }
    }
    else
    {
        int i;
        for (i = 0; i < pos && i < sizeUsername; i++)
            username[i] = fq_username[i];
        username[i] = L'\0';
    }
}

void WideCharToChar(
    __in PWSTR data,
    __in int buffSize,
    __out char* pc
)
{
    WideCharToMultiByte(
        CP_ACP,
        0,
        data,
        -1,
        pc,
        buffSize,
        NULL,
        NULL);
}

void CharToWideChar(
    __in char* data,
    __in int buffSize,
    __out PWSTR pc
)
{
    MultiByteToWideChar(
        CP_ACP,
        0,
        data,
        -1,
        pc,
        buffSize);
}

std::wstring getCleanUsername(const std::wstring username, const std::wstring domain)
{
    HRESULT hr = E_UNEXPECTED;

    wchar_t fullname[1024];
    wchar_t uname[1024];
    wchar_t legacyname[1024];
    wchar_t upn_name[1024];
    wchar_t otp_name[1024];

    PWSTR pszDefaultPrefix = L"";
    PWSTR pszDomain = L"";
    DWORD dwDefaultPrefixSize = 0;
    DWORD dwDomainSize = 0;

    PWSTR strNetBiosDomainName = L"";

    BOOLEAN rc;

    dwDefaultPrefixSize = readRegistryValueString(CONF_DEFAULT_PREFIX, &pszDefaultPrefix, L"");
    dwDomainSize = readRegistryValueString(CONF_DOMAIN_NAME, &pszDomain, L"");

    const wchar_t* pchWhack = wcschr(username.c_str(), L'\\'); // retourne un pointeur vers la premi?re occurence du backslahs Recherche s'il y a un backslahs
    const wchar_t* pchWatSign = wcschr(username.c_str(), L'@'); // retourne un pointeur vers la premi?re occurence du @ Recherche s'il y a un @

    // S'il y a un domain prefix stock? dans la registry et le nom d'utilisateur ne contient pas de \\ ni de @ (Pour forcer le login en local ou dans un domaine particulier)
    if ((dwDefaultPrefixSize > 1) && (pchWatSign == nullptr) && (pchWhack == nullptr)) {
        wcscpy_s(fullname, 1024, pszDefaultPrefix); // Mettre le prefix dans la variable fullname
        wcscat_s(fullname, 1024, L"\\"); // Ajouter un backslash
        wcscat_s(fullname, 1024, username.c_str()); // Ajouter le nom d'utilisateur
        pchWhack = wcschr(fullname, L'\\'); // Chercher s'il y a un backslash
    }
    else {
        wcscpy_s(fullname, 1024, username.c_str()); // Mettre le prefix dans la variable fullname
    }

    // Est-ce que le domain est renseign? dans la base de registre tcpip de Windows (l'ordinateur est en domain)?
    if (dwDomainSize > 1) {
        DOMAIN_CONTROLLER_INFO* pDCI;
        if (DsGetDcNameW(NULL, pszDomain, NULL, NULL, DS_IS_DNS_NAME | DS_RETURN_FLAT_NAME, &pDCI) == ERROR_SUCCESS) { // Est-ce possible de r?cup?rer le domaine ?
            strNetBiosDomainName = pDCI->DomainName;
            // Write flat domain name in the internal multiOTP Credential registry cache
            writeRegistryValueString(CONF_FLAT_DOMAIN, strNetBiosDomainName);
        }
        else {
            // Read flat domain name from the internal multiOTP Credential registry cache
            readRegistryValueString(CONF_FLAT_DOMAIN, &strNetBiosDomainName, L"");
        }
    }
    else {
        // DO Nothing
    }

    if ((dwDomainSize > 1) && (pchWatSign == nullptr) && (pchWhack == nullptr)) {
        wcscpy_s(fullname, 1024, strNetBiosDomainName);
        wcscat_s(fullname, 1024, L"\\");
        wcscat_s(fullname, 1024, username.c_str());
        pchWhack = wcschr(fullname, L'\\');
    }
    else {
        // Do nothing
    }

    writeKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"", L"currentOfflineUser", L"");

    if (pchWatSign != nullptr) {
        ULONG size = 1024;
        wchar_t buffer[1024];
        wcscpy_s(fullname, 1024, username.c_str());
        wcscpy_s(upn_name, 1024, fullname);

        pchWhack = wcschr(fullname, L'\\');

        rc = TranslateNameW(fullname, NameUserPrincipal, NameSamCompatible, buffer, &size); // NameDnsDomain should also work instead of NameSamCompatible (Engineering\JSmith)
        if (rc) {
            // Store in the registry the Legacy returned by the AD server
            writeKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"LEGACYcache", fullname, buffer);
            if (readRegistryValueInteger(CONF_UPN_FORMAT, 0)) { // If we are in UPN mode we try to contact the AD server to check what is the UPN name
                ULONG sizeTemp = 1024;
                wchar_t bufferTemp[1024];
                rc = TranslateNameW(buffer, NameSamCompatible, NameUserPrincipal, bufferTemp, &sizeTemp); // NameDnsDomain should also work instead of NameSamCompatible
                if (rc) {
                    wcscpy_s(upn_name, 1024, bufferTemp);
                    // Store in the registry the UPN returned by the AD server
                    writeKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"UPNcache", fullname, upn_name);
                } else {
                    // Do nothing
                }
            } else {
                wcscpy_s(legacyname, 1024, buffer);
                pchWhack = wcschr(legacyname, L'\\');
            }
        } else if(readRegistryValueInteger(CONF_UPN_FORMAT, 0))  { // If we are in UPN mode then search for the value in cache
            // Search in registry UPNcache if there is a matching entry
            PWSTR tempStr = L"";
            if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"UPNcache", fullname, &tempStr, L"") > 1) {
                wcscpy_s(upn_name, 1024, tempStr);
            }

            if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"LEGACYcache", fullname, &tempStr, L"") > 1) {
                wcscpy_s(legacyname, 1024, tempStr);
                pchWhack = wcschr(legacyname, L'\\');
                writeKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"", L"currentOfflineUser", legacyname);
            }
        } else {
            PWSTR tempStr = L"";
            if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"LEGACYcache", fullname, &tempStr, L"") >1) {
                wcscpy_s(legacyname, 1024, tempStr);
                pchWhack = wcschr(legacyname, L'\\');
                writeKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"", L"currentOfflineUser", legacyname);
            }
        }
    } else {
        ULONG size = 1024;
        wchar_t buffer[1024];
        rc = TranslateNameW(fullname, NameSamCompatible, NameUserPrincipal, buffer, &size); // NameDnsDomain should also work instead of NameSamCompatible
        if (rc) {
            wcscpy_s(upn_name, 1024, buffer);
            // Store in the registry the UPN returned by the AD server
            if (readRegistryValueInteger(CONF_UPN_FORMAT, 0)) {
                writeKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"UPNcache", fullname, upn_name);
            }
            else {
                // Do Nothing
            }
        }
        else {
            // Search in registry UPNcache if there is a matching entry
            if (readRegistryValueInteger(CONF_UPN_FORMAT, 0)) {
                PWSTR temp = L"";
                if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"UPNcache", fullname, &temp, L"") > 1) {
                    // The domain controller is not available but there is a entry in the UPN cache then create upn_name with this cache
                    wcscpy_s(upn_name, 1024, temp);
                } else {
                    wcscpy_s(upn_name, 1024, username.c_str());
                    wcscat_s(upn_name, 1024, L"@");
                    wcscat_s(upn_name, 1024, pszDomain);
                }
                wcscpy_s(fullname, 1024, username.c_str());
            } else {
                // The domain controller is not available then create upn_name with the registry
                wcscpy_s(uname, 1024, username.c_str());
                wcscat_s(uname, 1024, L"@");
                wcscat_s(uname, 1024, pszDomain);
            }
        }
    }

    if (pchWhack != nullptr) {
        const wchar_t* pchUsernameBegin = pchWhack + 1;
        hr = wcscpy_s(uname, 1024, pchUsernameBegin);
    }
    else {
        hr = wcscpy_s(uname, 1024, fullname);
    }

    if (readRegistryValueInteger(CONF_UPN_FORMAT, 0)) {
        return upn_name;
    }
    else {
        return uname;
    }
}

HRESULT hideCPField(__in ICredentialProviderCredential* self, __in ICredentialProviderCredentialEvents* pCPCE, __in DWORD fieldId)
{

    HRESULT hr = S_OK;

    if (!pCPCE || !self)
    {
        return E_INVALIDARG;
    }

    hr = pCPCE->SetFieldState(self, fieldId, CREDENTIAL_PROVIDER_FIELD_STATE::CPFS_HIDDEN);

    if (SUCCEEDED(hr))
    {
        hr = pCPCE->SetFieldInteractiveState(self, fieldId, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE::CPFIS_DISABLED);
    }

    return hr;
}

HRESULT displayCPField(__in ICredentialProviderCredential* self, __in ICredentialProviderCredentialEvents* pCPCE, __in DWORD fieldId)
{

    HRESULT hr = S_OK;

    if (!pCPCE || !self)
    {
        return E_INVALIDARG;
    }

    hr = pCPCE->SetFieldState(self, fieldId, CREDENTIAL_PROVIDER_FIELD_STATE::CPFS_DISPLAY_IN_SELECTED_TILE);

    if (SUCCEEDED(hr))
    {
        hr = pCPCE->SetFieldInteractiveState(self, fieldId, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE::CPFIS_DISABLED);
    }

    return hr;
}

int minutesSinceEpoch() {
    std::time_t seconds = std::time(nullptr);
    return seconds/60;
}

HRESULT multiotp_request_command(_In_ std::wstring command, _In_ std::wstring params)
{
    HRESULT hr = E_NOTIMPL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL bSuccess = FALSE;
    // Create a pipe for the redirection of the STDOUT 
    // of a child process. 
    HANDLE g_hChildStd_OUT_Rd = NULL;
    HANDLE g_hChildStd_OUT_Wr = NULL;
    SECURITY_ATTRIBUTES saAttr;

    DWORD exitCode;
    wchar_t cmd[2048];
    wchar_t options[2048];
    size_t len;
    PWSTR path;
    
    // Set the params
    wcscpy_s(cmd, 2048, params.c_str());
    wcscat_s(cmd, 2048, L" ");

    // Credential provider mode
    wcscat_s(cmd, 2048, L"-cp");
    wcscat_s(cmd, 2048, L" ");

    if (DEVELOP_MODE) {
        wcscat_s(cmd, 2048, L"-debug");
        wcscat_s(cmd, 2048, L" ");
    }
    len = wcslen(cmd);

    if (DEVELOP_MODE) PrintLn("command len:%d", int(len));
    if (DEVELOP_MODE) PrintLn(cmd);
    
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    bSuccess = CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0);
    if (bSuccess) {
        bSuccess = SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);
    }

    SecureZeroMemory(&si, sizeof(si));
    SecureZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);

    si.hStdError = g_hChildStd_OUT_Wr;
    si.hStdOutput = g_hChildStd_OUT_Wr;
    si.dwFlags |= STARTF_USESTDHANDLES;

    hr = MULTIOTP_UNKNOWN_ERROR;


    if (readRegistryValueString(CONF_PATH, &path, L"c:\\multiotp\\") > 1) {
        DWORD timeout = 60;

        timeout = readRegistryValueInteger(CONF_TIMEOUT, timeout);

        DWORD server_timeout = 5;
        DWORD server_cache_level = 1;
        PWSTR shared_secret;
        PWSTR servers;
        std::wstring shared_secret_escaped;

        server_timeout = readRegistryValueInteger(CONF_SERVER_TIMEOUT, server_timeout);
        wchar_t server_timeout_string[1024];
        _ultow_s(server_timeout, server_timeout_string, 10);
        wcscpy_s(options, 2048, L"-server-timeout=");
        wcscat_s(options, 2048, server_timeout_string);
        wcscat_s(options, 2048, L" ");

        server_cache_level = readRegistryValueInteger(CONF_CACHE_ENABLED, server_cache_level);
        wchar_t server_cache_level_string[1024];
        _ultow_s(server_cache_level, server_cache_level_string, 10);
        wcscat_s(options, 2048, L"-server-cache-level=");
        wcscat_s(options, 2048, server_cache_level_string);
        wcscat_s(options, 2048, L" ");

        if (readRegistryValueString(CONF_SERVERS, &servers, L"") > 1) {
            wcscat_s(options, 2048, L"-server-url=");
            wcscat_s(options, 2048, servers);
            wcscat_s(options, 2048, L" ");
        }

        if (readRegistryValueString(CONF_SHARED_SECRET, &shared_secret, L"ClientServerSecret") > 1) {
            wcscat_s(options, 2048, L"\"");
            wcscat_s(options, 2048, L"-server-secret=");            
            shared_secret_escaped = shared_secret;
            replaceAll(shared_secret_escaped, L"\"", L"\\\"");
            wcscat_s(options, 2048, shared_secret_escaped.c_str());
            wcscat_s(options, 2048, L"\"");
            wcscat_s(options, 2048, L" ");
        }

        wcscat_s(options, 2048, cmd);

        wchar_t appname[2048];

        wcscpy_s(appname, 2048, L"\"");
        wcscat_s(appname, 2048, path);
        size_t npath = wcslen(appname);
        if (appname[npath - 1] != '\\' && appname[npath - 1] != '/') {
            appname[npath] = '\\';
            appname[npath + 1] = '\0';
        }
        wcscat_s(appname, 2048, L"multiotp.exe");
        wcscat_s(appname, 2048, L"\"");
        wcscat_s(appname, 2048, L" ");
        wcscat_s(appname, 2048, command.c_str());
        wcscat_s(appname, 2048, L" ");
        wcscat_s(appname, 2048, options);

        if (DEVELOP_MODE) PrintLn(L"Calling ", appname);
        if (DEVELOP_MODE) PrintLn(L"with options ", options);
        // As argc 0 is the full filename itself, we use the lpCommandLine only 
        if (::CreateProcessW(NULL, appname, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, path, &si, &pi)) {

            DWORD result = WaitForSingleObject(pi.hProcess, (timeout * 1000));

            if (DEVELOP_MODE) PrintLn("WaitForSingleObject result: %d", result);

            if (result == WAIT_OBJECT_0) {
                GetExitCodeProcess(pi.hProcess, &exitCode);

                if (DEVELOP_MODE) PrintLn("multiotp.exe Exit Code: %d", exitCode);

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                // Read the data written to the pipe
                DWORD bytesInPipe = 0;
                bSuccess = TRUE;
                while (bSuccess && (bytesInPipe == 0)) {
                    bSuccess = PeekNamedPipe(g_hChildStd_OUT_Rd, NULL, 0, NULL, &bytesInPipe, NULL);
                }
                if (bytesInPipe != 0) {
                    DWORD dwRead;
                    CHAR* pipeContents = new CHAR[bytesInPipe];
                    bSuccess = ReadFile(g_hChildStd_OUT_Rd, pipeContents, bytesInPipe, &dwRead, NULL);
                    if (!(!bSuccess || dwRead == 0)) {
                        std::stringstream stream(pipeContents);
                        std::string str;
                        while (getline(stream, str))
                        {
                            if (DEVELOP_MODE) PrintLn(CStringW(str.c_str()));
                            if (str.find(MULTIOTP_CHECK) != std::string::npos) {
                                if (DEVELOP_MODE) PrintLn("Executable string info detected!");
                                hr = exitCode;
                            }
                        }
                    }
                }
            }
        }
        CoTaskMemFree(path);
    }
    return hr;
}

void replaceAll(std::wstring& str, const std::wstring& from, const std::wstring& to) {
    if (from.empty())
        return;
    size_t start_pos = 0;
    PrintLn(L"Looking for ", from.c_str());
    PrintLn(L" IN ", str.c_str());
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        PrintLn(L"We found a ",from.c_str());
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}