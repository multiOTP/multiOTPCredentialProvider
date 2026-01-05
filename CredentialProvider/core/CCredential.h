/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2017 NetKnights GmbH
**				2020-2026 SysCo systemes de communication sa
**
** Author		Dominik Pretzsch
**				Nils Behlen
**				Yann Jeanrenaud, Andre Liechti
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

#include "Dll.h"
#include "Utilities.h"
#include "MultiOTPConfiguration.h"
#include "PrivacyIDEA.h"
#include <scenario.h>
#include <unknwn.h>
#include <helpers.h>
#include <string>
#include <map>
#include "MultiOTP.h"
#include "mq.h" // multiOTP/yj
#include "sddl.h" // multiOTP/yj

#define NOT_EMPTY(NAME) \
	(NAME != NULL && NAME[0] != NULL)

#define ZERO(NAME) \
	SecureZeroMemory(NAME, sizeof(NAME))

class CCredential : public IConnectableCredentialProviderCredential
{
public:
	// IUnknown
	IFACEMETHODIMP_(ULONG) AddRef() noexcept
	{
		return ++_cRef;
	}

	IFACEMETHODIMP_(ULONG) Release() noexcept
	{
		LONG cRef = --_cRef;
		if (!cRef)
		{
			// The Credential is owned by the Provider object
		}
		return cRef;
	}

#pragma warning( disable : 4838 )
	IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
	{
		static const QITAB qit[] =
		{
			QITABENT(CCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
			QITABENT(CCredential, IConnectableCredentialProviderCredential), // IID_IConnectableCredentialProviderCredential
			{ 0 },
		};

		return QISearch(this, qit, riid, ppv);
	}
public:
	// ICredentialProviderCredential
	IFACEMETHODIMP Advise(__in ICredentialProviderCredentialEvents* pcpce);
	IFACEMETHODIMP UnAdvise();

	IFACEMETHODIMP SetSelected(__out BOOL* pbAutoLogon);
	IFACEMETHODIMP SetDeselected();

	IFACEMETHODIMP GetFieldState(__in DWORD dwFieldID,
		__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
		__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

	IFACEMETHODIMP GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz);
	IFACEMETHODIMP GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp);
	IFACEMETHODIMP GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked, __deref_out PWSTR* ppwszLabel);
	IFACEMETHODIMP GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems, __out_range(< , *pcItems) DWORD* pdwSelectedItem);
	IFACEMETHODIMP GetComboBoxValueAt(__in DWORD dwFieldID, __in DWORD dwItem, __deref_out PWSTR* ppwszItem);
	IFACEMETHODIMP GetSubmitButtonValue(__in DWORD dwFieldID, __out DWORD* pdwAdjacentTo);

	IFACEMETHODIMP SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz);
	IFACEMETHODIMP SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked);
	IFACEMETHODIMP SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem);
	IFACEMETHODIMP CommandLinkClicked(__in DWORD dwFieldID);

	IFACEMETHODIMP GetSerialization(__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
		__deref_out_opt PWSTR* ppwszOptionalStatusText,
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
	IFACEMETHODIMP ReportResult(__in NTSTATUS ntsStatus,
		__in NTSTATUS ntsSubstatus,
		__deref_out_opt PWSTR* ppwszOptionalStatusText,
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);


public:
	// IConnectableCredentialProviderCredential 
	IFACEMETHODIMP Connect(__in IQueryContinueWithStatus* pqcws);
	IFACEMETHODIMP Disconnect();

	CCredential(std::shared_ptr<MultiOTPConfiguration> c);
	virtual ~CCredential();

public:
	HRESULT Initialize(//__in CProvider* pProvider,
		__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
		__in const FIELD_STATE_PAIR* rgfsp,
		__in_opt PWSTR user_name,
		__in_opt PWSTR domain_name,
		__in_opt PWSTR password);

private:

	void ShowErrorMessage(const std::wstring& message, const HRESULT& code);

	void PushAuthenticationCallback(bool success);

	LONG									_cRef;

	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR	_rgCredProvFieldDescriptors[FID_NUM_FIELDS];	// An array holding the type and 
																							// name of each field in the tile.

	FIELD_STATE_PAIR						_rgFieldStatePairs[FID_NUM_FIELDS];          // An array holding the state of 
																						 // each field in the tile.

	wchar_t* _rgFieldStrings[FID_NUM_FIELDS];			 // An array holding the string 
																						 // value of each field. This is 
																						 // different from the name of 
																						 // the field held in 
																						 // _rgCredProvFieldDescriptors.
	ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;

	DWORD                                   _dwComboIndex;                               // Tracks the current index 
																						 // of our combobox.

	MultiOTP								_privacyIDEA;

	std::shared_ptr<MultiOTPConfiguration>			_config;

	Utilities								_util;

	HRESULT									_piStatus = E_FAIL;
	void storeLastConnectedUserIfNeeded();
	std::wstring cleanUsername(std::wstring message);
	HRESULT getSid(LPCWSTR wszAccName, PSID* ppSid);
	HRESULT storeSidAndTimeStamp(PSID ppsid);
	bool CCredential::hasloggedInRecently(LPTSTR userId);
	LPTSTR getSidFromUsername(std::wstring username);
};
