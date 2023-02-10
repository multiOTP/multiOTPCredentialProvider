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

#ifndef _CPROVIDER_H
#define _CPROVIDER_H

#include <windows.h>
#include <strsafe.h>
#include <Wtsapi32.h>						
#include <Lm.h>
#include <credentialprovider.h>

#include <helpers.h>

#include "CCredential.h"

#define MAX_CREDENTIALS 3
#define MAX_DWORD   0xffffffff        // maximum DWORD

enum SERIALIZATION_AVAILABLE_FOR
{
	SAF_USERNAME,
	SAF_PASSWORD,
	SAF_DOMAIN
};

class CProvider : public ICredentialProvider, public ICredentialProviderSetUserArray
{
public:
	// IUnknown
	IFACEMETHODIMP_(ULONG) AddRef()
	{
		return ++_cRef;
	}

	IFACEMETHODIMP_(ULONG) Release()
	{
		LONG cRef = --_cRef;
		if (!cRef)
		{
			delete this;
		}
		return cRef;
	}

	#pragma warning( disable : 4838 )
	IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
	{
		static const QITAB qit[] =
		{
			QITABENT(CProvider, ICredentialProvider), // IID_ICredentialProvider
			QITABENT(CProvider, ICredentialProviderSetUserArray), // IID_ICredentialProviderSetUserArray
			{ 0 },
		};
		return QISearch(this, qit, riid, ppv);
	}

public:
	IFACEMETHODIMP SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, __in DWORD dwFlags) override;
	IFACEMETHODIMP SetSerialization(__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;

	IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, __in UINT_PTR upAdviseContext) override;
	IFACEMETHODIMP UnAdvise() override;

	IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount) override;
	IFACEMETHODIMP GetFieldDescriptorAt(__in DWORD dwIndex, __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;

	IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount, __out_range(<, *pdwCount) DWORD* pdwDefault,
		__out BOOL* pbAutoLogonWithDefault) override;

	IFACEMETHODIMP GetCredentialAt(__in DWORD dwIndex, __deref_out ICredentialProviderCredential** ppcpc) override;

	IFACEMETHODIMP SetUserArray(_In_ ICredentialProviderUserArray* users);

	friend HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);
	
protected:
	CProvider();
	__override ~CProvider();

private:
	void _CleanupSetSerialization();

	void _GetSerializedCredentials(PWSTR *username, PWSTR *password, PWSTR *domain);
	
	bool _SerializationAvailable(SERIALIZATION_AVAILABLE_FOR checkFor);

private:
	LONG									_cRef;

	KERB_INTERACTIVE_UNLOCK_LOGON*          _pkiulSetSerialization;
	DWORD                                   _dwSetSerializationCred; //index into rgpCredentials for the SetSerializationCred

	std::unique_ptr<CCredential>			_credential;

	std::shared_ptr<MultiOTPConfiguration>			_config;

	ICredentialProviderUserArray *_pCredProviderUserArray;

};

#endif
