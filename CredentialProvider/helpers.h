/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2017 NetKnights GmbH
**
** Author		Dominik Pretzsch
**				Nils Behlen
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#pragma once
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>
#include <windows.h>
#include <strsafe.h>
#include <string>
#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)

//makes a copy of a field descriptor using CoTaskMemAlloc
HRESULT FieldDescriptorCoAllocCopy(
	__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
	__deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
);

//makes a copy of a field descriptor on the normal heap
HRESULT FieldDescriptorCopy(
	__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
	__deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
);

//creates a UNICODE_STRING from a NULL-terminated string
HRESULT UnicodeStringInitWithString(
	__in PWSTR pwz,
	__out UNICODE_STRING* pus
);

//initializes a KERB_INTERACTIVE_UNLOCK_LOGON with weak references to the provided credentials
HRESULT KerbInteractiveUnlockLogonInit(
	__in PWSTR pwzDomain,
	__in PWSTR pwzUsername,
	__in PWSTR pwzPassword,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__out KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
);

//packages the credentials into the buffer that the system expects
HRESULT KerbInteractiveUnlockLogonPack(
	__in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
	__deref_out_bcount(*pcb) BYTE** prgb,
	__out DWORD* pcb
);

//packages the credentials into the buffer that the system expects
HRESULT KerbChangePasswordPack(
	__in const KERB_CHANGEPASSWORD_REQUEST& rkcrIn,
	__deref_out_bcount(*pcb) BYTE** prgb,
	__out DWORD* pcb
);

//get the authentication package that will be used for our logon attempt
HRESULT RetrieveNegotiateAuthPackage(
	__out ULONG* pulAuthPackage
);

//encrypt a password (if necessary) and copy it; if not, just copy it
HRESULT ProtectIfNecessaryAndCopyPassword(
	__in PCWSTR pwzPassword,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__deref_out PWSTR* ppwzProtectedPassword
);

HRESULT KerbInteractiveUnlockLogonRepackNative(
	__in_bcount(cbWow) BYTE* rgbWow,
	__in DWORD cbWow,
	__deref_out_bcount(*pcbNative) BYTE** prgbNative,
	__out DWORD* pcbNative
);

void KerbInteractiveUnlockLogonUnpackInPlace(
	__inout_bcount(cb) KERB_INTERACTIVE_UNLOCK_LOGON* pkiul,
	__in DWORD cb
);

HRESULT DomainUsernameStringAlloc(
	__in PCWSTR pwszDomain,
	__in PCWSTR pwszUsername,
	__deref_out PWSTR* ppwszDomainUsername
);
