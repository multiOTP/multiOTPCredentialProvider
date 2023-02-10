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

#include "CProvider.h"
#include "version.h"
#include "Logger.h"
#include "MultiOTPConfiguration.h"
#include "scenario.h"
#include "RegistryReader.h"
#include "Shared.h"
#include <credentialprovider.h>
#include <tchar.h>

using namespace std;

CProvider::CProvider() :
	_cRef(1),
	_pkiulSetSerialization(nullptr),
	_dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT),
	_pCredProviderUserArray(nullptr)
{
	DllAddRef();

	_config = std::make_shared<MultiOTPConfiguration>();
	Logger::Get().releaseLog = _config->releaseLog;
}

CProvider::~CProvider()
{
	if (_credential != NULL)
	{
		_credential->Release();
	}

	if (_pCredProviderUserArray != nullptr)
	{
		_pCredProviderUserArray->Release();
		_pCredProviderUserArray = nullptr;
	}
	
	DllRelease();
}

void CProvider::_CleanupSetSerialization()
{
	DebugPrint(__FUNCTION__);


	if (_pkiulSetSerialization)
	{
		KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
		SecureZeroMemory(_pkiulSetSerialization,
			sizeof(*_pkiulSetSerialization) +
			pkil->LogonDomainName.MaximumLength +
			pkil->UserName.MaximumLength +
			pkil->Password.MaximumLength);
		HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
	}
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.  
//
// This sample only handles the logon and unlock scenarios as those are the most common.
HRESULT CProvider::SetUsageScenario(
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in DWORD dwFlags
)
{
#ifdef _DEBUG
	DebugPrint(string(__FUNCTION__) + ": " + Shared::CPUStoString(cpus));
	_config->printConfiguration();
#endif
	HRESULT hr = E_INVALIDARG;

	_config->provider.credPackFlags = dwFlags;
	_config->provider.cpu = cpus;

	// Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
	// that we're not designed for that scenario.

	switch (cpus)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
		hr = S_OK;
		break;
	case CPUS_CHANGE_PASSWORD:
	case CPUS_PLAP:
	case CPUS_INVALID:
		hr = E_NOTIMPL;
		break;
	default:
		return E_INVALIDARG;
	}

	if (hr == S_OK)
	{
		if (!Shared::IsRequiredForScenario(cpus, PROVIDER))
		{
			DebugPrint("CP is not enumerated because of the configuration for this scenario.");
			hr = E_NOTIMPL;
		}
	}

	DebugPrint("SetScenario result:");
	DebugPrint(hr);

	return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt. It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a credential.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to 
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// Since this sample doesn't support CPUS_CREDUI, we have not implemented the credui specific
// pieces of this function.  For information on that, please see the credUI sample.
HRESULT CProvider::SetSerialization(
	__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
)
{
	DebugPrint(__FUNCTION__);
	HRESULT result = E_NOTIMPL;
	ULONG authPackage = NULL;
	result = RetrieveNegotiateAuthPackage(&authPackage);

	if (!SUCCEEDED(result))
	{
		DebugPrint("Failed to retrieve authPackage");
		return result;
	}

	if (_config->provider.cpu == CPUS_CREDUI)
	{
		DebugPrint("CPUS_CREDUI");

		if (((_config->provider.credPackFlags & CREDUIWIN_IN_CRED_ONLY) || (_config->provider.credPackFlags & CREDUIWIN_AUTHPACKAGE_ONLY))
			&& authPackage != pcpcs->ulAuthenticationPackage)
		{
			DebugPrint("authPackage invalid");
			return E_INVALIDARG;
		}

		if (_config->provider.credPackFlags & CREDUIWIN_AUTHPACKAGE_ONLY)
		{
			DebugPrint("CPUS_CREDUI but not CREDUIWIN_AUTHPACKAGE_ONLY");
			result = S_FALSE;
		}
	}

	if (authPackage == pcpcs->ulAuthenticationPackage && pcpcs->cbSerialization > 0 && pcpcs->rgbSerialization)
	{
		KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*)pcpcs->rgbSerialization;
		if (pkil->Logon.MessageType == KerbInteractiveLogon)
		{
			if (pkil->Logon.UserName.Length && pkil->Logon.UserName.Buffer)
			{
				BYTE* nativeSerialization = nullptr;
				DWORD nativeSerializationSize = 0;
				DebugPrint("Serialization found from remote");

				if (_config->provider.credPackFlags == CPUS_CREDUI && (_config->provider.credPackFlags & CREDUIWIN_PACK_32_WOW))
				{
					if (!SUCCEEDED(KerbInteractiveUnlockLogonRepackNative(pcpcs->rgbSerialization, pcpcs->cbSerialization,
						&nativeSerialization, &nativeSerializationSize)))
					{
						return result;
					}
				}
				else
				{
					nativeSerialization = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pcpcs->cbSerialization);
					nativeSerializationSize = pcpcs->cbSerialization;

					if (!nativeSerialization)
					{
						return E_OUTOFMEMORY;
					}

					CopyMemory(nativeSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
				}

				KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*)nativeSerialization, nativeSerializationSize);

				if (_pkiulSetSerialization)
				{
					LocalFree(_pkiulSetSerialization);
				}

				_pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)nativeSerialization;

				result = S_OK;
			}
		}
	}
	DebugPrint(result);

	return result;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated
HRESULT CProvider::Advise(
	__in ICredentialProviderEvents* pcpe,
	__in UINT_PTR upAdviseContext
)
{
	DebugPrint(__FUNCTION__);

	if (_config->provider.pCredentialProviderEvents != nullptr)
	{
		_config->provider.pCredentialProviderEvents->Release();
	}

	_config->provider.pCredentialProviderEvents = pcpe;
	_config->provider.pCredentialProviderEvents->AddRef();

	_config->provider.upAdviseContext = upAdviseContext;

	return S_OK;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CProvider::UnAdvise()
{
	DebugPrint(__FUNCTION__);

	if (_config->provider.pCredentialProviderEvents != nullptr)
	{
		_config->provider.pCredentialProviderEvents->Release();
	}

	_config->provider.pCredentialProviderEvents = nullptr;
	_config->provider.upAdviseContext = NULL;

	return S_OK;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired 
// using the field descriptors.
HRESULT CProvider::GetFieldDescriptorCount(
	__out DWORD* pdwCount
)
{
	DebugPrint(__FUNCTION__);

	*pdwCount = FID_NUM_FIELDS;

	return S_OK;
}

// Gets the field descriptor for a particular field
HRESULT CProvider::GetFieldDescriptorAt(
	__in DWORD dwIndex,
	__deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
)
{
	//DebugPrintLn(__FUNCTION__);
	HRESULT hr = E_FAIL;
	if (!_config->provider.cpu)
	{
		return E_FAIL;
	}

	// Verify dwIndex is a valid field.
	if ((dwIndex < FID_NUM_FIELDS) && ppcpfd)
	{
		// Adjust the FieldDescriptor to copy depending on language and config
		wstring label = L"";
		switch (dwIndex)
		{
		case FID_USERNAME:
			label = Utilities::GetTranslatedText(TEXT_USERNAME);
			break;
		case FID_LDAP_PASS:
			label = Utilities::GetTranslatedText(TEXT_PASSWORD);
			break;
		case FID_NEW_PASS_1:
			label = Utilities::GetTranslatedText(TEXT_NEW_PASSWORD);
			break;
		case FID_NEW_PASS_2:
			label = Utilities::GetTranslatedText(TEXT_CONFIRM_PASSWORD);
			break;
		case FID_OTP:
			label = _config->otpFieldText;
			if (label.empty())
				label = Utilities::GetTranslatedText(TEXT_OTP);
			break;
		default: break;
		}

		if (!label.empty())
		{
			s_rgScenarioCredProvFieldDescriptors[dwIndex].pszLabel = const_cast<LPWSTR>(label.c_str());
		}

		hr = FieldDescriptorCoAllocCopy(s_rgScenarioCredProvFieldDescriptors[dwIndex],
			ppcpfd);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
//
// The default tile is the tile which will be shown in the zoomed view by default. If 
// more than one provider specifies a default tile the behavior is the last used cred
// prov gets to specify the default tile to be displayed
//
// If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call GetSerialization
// on the credential you've specified as the default and will submit that credential
// for authentication without showing any further UI.
HRESULT CProvider::GetCredentialCount(
	__out DWORD* pdwCount,
	__out_range(< , *pdwCount) DWORD* pdwDefault,
	__out BOOL* pbAutoLogonWithDefault
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	*pdwCount = 1; //_dwNumCreds;
	*pdwDefault = 0; // this means we want to be the default
	*pbAutoLogonWithDefault = FALSE;
	if (_config->noDefault)
	{
		*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
	}

	// if serialized creds are available, try using them to logon
	if (_SerializationAvailable(SAF_USERNAME) && _SerializationAvailable(SAF_PASSWORD))
	{
		*pdwDefault = 0;
		_config->isRemoteSession = Shared::IsCurrentSessionRemote();
		if (_config->isRemoteSession && !_config->twoStepHideOTP)
		{
			*pbAutoLogonWithDefault = FALSE;
		}
		else
		{
			*pbAutoLogonWithDefault = TRUE;
		}
	}

	DebugPrint(hr);
	return hr;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CProvider::GetCredentialAt(
	__in DWORD dwIndex,
	__deref_out ICredentialProviderCredential** ppcpc
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_FAIL;
	const CREDENTIAL_PROVIDER_USAGE_SCENARIO usage_scenario = _config->provider.cpu;


	if (!_credential)
	{
		DebugPrint("Checking for serialized credentials");

		PWSTR serializedUser, serializedPass, serializedDomain;
		_GetSerializedCredentials(&serializedUser, &serializedPass, &serializedDomain);

		DebugPrint("Checking for missing credentials");

		if (usage_scenario == CPUS_UNLOCK_WORKSTATION && serializedUser == nullptr)
		{
			if (serializedUser == nullptr)
			{
				DebugPrint("Looking-up missing user name from session");

				DWORD dwLen = 0;

				if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
					WTS_CURRENT_SESSION,
					WTSUserName,
					&serializedUser,
					&dwLen))
				{
					serializedUser = nullptr;
				}
			}

			if (serializedDomain == nullptr)
			{
				DebugPrint("Looking-up missing domain name from session");

				DWORD dwLen = 0;

				if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
					WTS_CURRENT_SESSION,
					WTSDomainName,
					&serializedDomain,
					&dwLen))
				{
					serializedDomain = nullptr;
				}
			}
		}
		else if (usage_scenario == CPUS_LOGON || usage_scenario == CPUS_CREDUI)
		{
			if (serializedDomain == nullptr)
			{
				DebugPrint("Looking-up missing domain name from computer");

				NETSETUP_JOIN_STATUS join_status;

				if (!NetGetJoinInformation(
					nullptr,
					&serializedDomain,
					&join_status) == NERR_Success || join_status == NetSetupUnjoined || join_status == NetSetupUnknownStatus)
				{
					serializedDomain = nullptr;
				}
				DebugPrint("Found domain:");
				DebugPrint(serializedDomain);
			}
		}

		DebugPrint("Initializing CCredential");

		_credential = std::make_unique<CCredential>(_config);

		hr = _credential->Initialize(
			s_rgScenarioCredProvFieldDescriptors,
			Utilities::GetFieldStatePairFor(usage_scenario, _config->twoStepHideOTP),
			serializedUser, serializedDomain, serializedPass);
	}
	else
	{
		hr = S_OK;
	}

	DebugPrint("Checking for successful initialization");

	if (FAILED(hr))
	{
		DebugPrint("Initialization failed");
		return hr;
	}

	DebugPrint("Checking for successful instantiation");

	if (!_credential)
	{
		DebugPrint("Instantiation failed");
		return E_OUTOFMEMORY;
	}

	DebugPrint("Returning interface to credential");

	if ((dwIndex == 0) && ppcpc)
	{
		if (usage_scenario == CPUS_CREDUI)
		{
			DebugPrint("CredUI: returning an IID_ICredentialProviderCredential");
			hr = _credential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
		}
		else
		{
			DebugPrint("Non-CredUI: returning an IID_IConnectableCredentialProviderCredential");
			hr = _credential->QueryInterface(IID_IConnectableCredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
			//hr = _pccCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void **>(ppcpc));
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrint(hr);

	return hr;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	//DebugPrint(__FUNCTION__);
	HRESULT hr;

	CProvider* pProvider = new CProvider();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}
	//DebugPrint("CSample_CreateInstance Result:");
	//DebugPrint(hr);

	return hr;
}

void CProvider::_GetSerializedCredentials(PWSTR* username, PWSTR* password, PWSTR* domain)
{
	DebugPrint(__FUNCTION__);

	if (username)
	{
		if (_SerializationAvailable(SAF_USERNAME))
		{
			*username = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.UserName.Length + sizeof(wchar_t));
			CopyMemory(*username, _pkiulSetSerialization->Logon.UserName.Buffer, _pkiulSetSerialization->Logon.UserName.Length);
		}
		else
		{
			*username = NULL;
		}
	}

	if (password)
	{
		if (_SerializationAvailable(SAF_PASSWORD))
		{
			*password = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.Password.Length + sizeof(wchar_t));
			CopyMemory(*password, _pkiulSetSerialization->Logon.Password.Buffer, _pkiulSetSerialization->Logon.Password.Length);
		}
		else
		{
			*password = NULL;
		}
	}

	if (domain)
	{
		if (_SerializationAvailable(SAF_DOMAIN))
		{
			*domain = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.LogonDomainName.Length + sizeof(wchar_t));
			CopyMemory(*domain, _pkiulSetSerialization->Logon.LogonDomainName.Buffer, _pkiulSetSerialization->Logon.LogonDomainName.Length);
		}
		else
		{
			*domain = NULL;
		}
	}
}

bool CProvider::_SerializationAvailable(SERIALIZATION_AVAILABLE_FOR checkFor)
{
	DebugPrint(__FUNCTION__);

	bool result = false;

	if (!_pkiulSetSerialization)
	{
		DebugPrint("No serialized creds set");
	}
	else
	{
		switch (checkFor)
		{
		case SAF_USERNAME:
			result = _pkiulSetSerialization->Logon.UserName.Length && _pkiulSetSerialization->Logon.UserName.Buffer;
			break;
		case SAF_PASSWORD:
			result = _pkiulSetSerialization->Logon.Password.Length && _pkiulSetSerialization->Logon.Password.Buffer;
			break;
		case SAF_DOMAIN:
			result = _pkiulSetSerialization->Logon.LogonDomainName.Length && _pkiulSetSerialization->Logon.LogonDomainName.Buffer;
			break;
		}
	}

	return result;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT CProvider::SetUserArray(_In_ ICredentialProviderUserArray* users)
{
	if (_pCredProviderUserArray)
	{
		_pCredProviderUserArray->Release();
	}
	_pCredProviderUserArray = users;
	_pCredProviderUserArray->AddRef();

	DWORD dwUserCount;
	_pCredProviderUserArray->GetCount(&dwUserCount);
	_config->numberOfLockedUser = dwUserCount;
	
	_config->lockedUsers = _pCredProviderUserArray;

	return S_OK;
}
