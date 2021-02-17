/**
 * BASE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * MultiotpProvider implements ICredentialProvider, which is the main
 * interface that logonUI uses to decide which tiles to display.
 * In this sample, we will display one tile that uses each of the nine
 * available UI controls.
 *
 * Extra code provided "as is" for the multiOTP open source project
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.8.1.0
 * @date      2021-02-12
 * @since     2013
 * @copyright (c) 2016-2021 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2020-08-31 5.8.0.0 SysCo/al ENH: Retarget to the last SDK 10.0.19041.1
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

#include <initguid.h>
#include "MultiotpProvider.h"
#include "MultiotpCredential.h"
#include "guid.h"

// Handling registry
#include "MultiotpRegistry.h"

// MultiotpHelpers
#include "MultiotpHelpers.h"

MultiotpProvider::MultiotpProvider():
    _cRef(1),
	// _pCredential(nullptr),
	// _pkiulSetSerialization(NULL),  // Experimental
	// _dwCredUIFlags(0),  // Experimental
    _pCredProviderUserArray(nullptr)
{
    DllAddRef();
	if (DEVELOP_MODE) PrintLn("========== MultiotpProvider created ==========");
}

MultiotpProvider::~MultiotpProvider()
{
	/*
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
	*/
    _ReleaseEnumeratedCredentials();
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
	if (DEVELOP_MODE) PrintLn("========== MultiotpProvider destroyed ==========");
    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT MultiotpProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

if (DEVELOP_MODE) PrintLn("MultiotpProvider::Provider Scenario: %d", cpus);
    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::SetUsageScenario CPUS_LOGON");
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_UNLOCK_WORKSTATION:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::SetUsageScenario CPUS_UNLOCK_WORKSTATION");
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::SetUsageScenario CPUS_CHANGE_PASSWORD");

        hr = E_NOTIMPL;
        break;

    case CPUS_CREDUI:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::SetUsageScenario CPUS_CREDUI");
        hr = E_NOTIMPL;
        break;

    default:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::SetUsageScenario CPUS_xxx default");
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT MultiotpProvider::SetSerialization(
    // _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
	__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::SetSerialization"); // that's the place to filter incoming SID from credentials supplied by NLA

	HRESULT hr = E_INVALIDARG;
	
	// EXPERIMENTAL

	/*
	if ((CLSID_Multiotp == pcpcs->clsidCredentialProvider) || (CPUS_CREDUI == _cpus))
	{
		// Get the current AuthenticationPackageID that we are supporting
		ULONG ulNegotiateAuthPackage;
		hr = RetrieveNegotiateAuthPackage(&ulNegotiateAuthPackage);

		if (SUCCEEDED(hr))
		{
			if (CPUS_CREDUI == _cpus)
			{
				if (CREDUIWIN_IN_CRED_ONLY & _dwCredUIFlags)
				{
					// If we are being told to enumerate only the incoming credential, we must not return
					// success unless we can enumerate it.  We'll set hr to failure here and let it be
					// overridden if the enumeration logic below succeeds.
					hr = E_INVALIDARG;
				}
				else if (_dwCredUIFlags & CREDUIWIN_AUTHPACKAGE_ONLY)
				{
					if (ulNegotiateAuthPackage == pcpcs->ulAuthenticationPackage)
					{
						// In the credui case, SetSerialization should only ever return S_OK if it is able to serialize the input cred.
						// Unfortunately, SetSerialization had to be overloaded to indicate whether or not it will be able to GetSerialization 
						// for the specific Auth Package that is being requested for CREDUIWIN_AUTHPACKAGE_ONLY to work, so when that flag is 
						// set, it should return S_FALSE unless it is ALSO able to serialize the input cred, then it can return S_OK.
						// So in this case, we can set it to be S_FALSE because we support the authpackage, and then if we
						// can serialize the input cred, it will get overwritten with S_OK.
						hr = S_FALSE;
					}
					else
					{
						//we don't support this auth package, so we want to let logonUI know that by failing
						hr = E_INVALIDARG;
					}
				}
			}

			if ((ulNegotiateAuthPackage == pcpcs->ulAuthenticationPackage) &&
				(0 < pcpcs->cbSerialization && pcpcs->rgbSerialization))
			{
				KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*)pcpcs->rgbSerialization;
				if (KerbInteractiveLogon == pkil->Logon.MessageType)
				{
					// If there isn't a username, we can't serialize or create a tile for this credential.
					if (0 < pkil->Logon.UserName.Length && pkil->Logon.UserName.Buffer)
					{
						if ((CPUS_CREDUI == _cpus) && (CREDUIWIN_PACK_32_WOW & _dwCredUIFlags))
						{
							BYTE* rgbNativeSerialization;
							DWORD cbNativeSerialization;
							if (SUCCEEDED(KerbInteractiveUnlockLogonRepackNative(pcpcs->rgbSerialization, pcpcs->cbSerialization, &rgbNativeSerialization, &cbNativeSerialization)))
							{
								KerbInteractiveUnlockLogonUnpackInPlace((PKERB_INTERACTIVE_UNLOCK_LOGON)rgbNativeSerialization, cbNativeSerialization);

								_pkiulSetSerialization = (PKERB_INTERACTIVE_UNLOCK_LOGON)rgbNativeSerialization;
								hr = S_OK;
							}
						}
						else
						{
							BYTE* rgbSerialization;
							rgbSerialization = (BYTE*)HeapAlloc(GetProcessHeap(), 0, pcpcs->cbSerialization);
							HRESULT hrCreateCred = rgbSerialization ? S_OK : E_OUTOFMEMORY;

							if (SUCCEEDED(hrCreateCred))
							{
								CopyMemory(rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
								KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization, pcpcs->cbSerialization);

								if (_pkiulSetSerialization)
								{
									HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
								}
								_pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization;
								if (SUCCEEDED(hrCreateCred))
								{
									// we allow success to override the S_FALSE for the CREDUIWIN_AUTHPACKAGE_ONLY, but
									// failure to create the cred shouldn't override that we can still handle
									// the auth package
									hr = hrCreateCred;
								}
							}
						}
					}
				}
			}
		}
	}*/
	return hr;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
HRESULT MultiotpProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::Advise");
    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT MultiotpProvider::UnAdvise()
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::UnAdvise");
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT MultiotpProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT MultiotpProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
HRESULT MultiotpProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::GetCredentialCount");

    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }
	DWORD dwUserCount = 1;
	HRESULT hr;

	if (_pCredProviderUserArray != nullptr) {
		hr = _pCredProviderUserArray->GetCount(&dwUserCount);
		if (hr == 0) {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::UserArrayCount:(%d)", dwUserCount);
		}
		else {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::UserArray.GetCount Error");
			dwUserCount = 1;
		}
	}
	else {
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::Unassigned UserArray");
		dwUserCount = 1;
	}

	if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1)) {
		dwUserCount += 1;//display additional empty tile
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::Count +1 (empty tile)");
	}

	if (DEVELOP_MODE) PrintLn("MultiotpProvider::User count:(%d)", dwUserCount);

	if (IsRemoteSession()) {
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::GetCredentialCount: RDP connection");

		*pdwCount = dwUserCount;//1
		
		//get RDP port from registry
		int RDPPort = 3389;//default RDPPort
//		HRESULT hr;

		RDPPort = readRegistryValueInteger(CONF_RDP_PORT, RDPPort);
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::RDP connection on port: %d", RDPPort);
	}

	else {
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::Local connection");
		//logfile << "Local connection\n";

		if (readRegistryValueInteger(CONF_RDP_ONLY, 0)) {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::Only RDP is OTP protected!!!");
			*pdwCount = 0;//no filtering no OTP tile
		}
		else {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::RDP and Local OTP protection");
			*pdwCount = dwUserCount;//show OTP tile
		}

		if (DEVELOP_MODE) {
			PrintLn("MultiotpProvider::OTP tile always visible");
			*pdwCount = dwUserCount;//development - don't force but allow OTP in all scenarios
		}
	}

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT MultiotpProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::GetCredentialAt: %d", (int)dwIndex); 
	HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

	if (DEVELOP_MODE) PrintLn("MultiotpProvider::Credential.size(%d)", (int)_pCredential.size()); 
	
	/*
	if ((dwIndex == 0) && ppcpc)
	{
	hr = _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
	}
	*/
	if ((dwIndex < _pCredential.size()) && ppcpc)
	{
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::QueryInterface");
		hr = _pCredential[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
	}
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT MultiotpProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::SetUserArray");
	// if (_pCredProviderUserArray)
	if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}

void MultiotpProvider::_CreateEnumeratedCredentials()
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::_CreateEnumeratedCredentials: %d", _cpus);
	switch (_cpus)
    {
    case CPUS_LOGON:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::_CreateEnumeratedCredentials CPUS_LOGON");
        _EnumerateCredentials();
        break;

    case CPUS_UNLOCK_WORKSTATION:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::_CreateEnumeratedCredentials CPUS_UNLOCK_WORKSTATION");
        _EnumerateCredentials();
        break;

    default:
        break;
    }
}

void MultiotpProvider::_ReleaseEnumeratedCredentials()
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::_ReleaseEnumeratedCredentials");
	/*
	if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
	*/
	for (DWORD i = 0; i < _pCredential.size(); i++) {
		if (_pCredential[i] != nullptr)
		{
			_pCredential[i]->Release();
			_pCredential[i] = nullptr;
		}
	}
	_pCredential.clear();
}

HRESULT MultiotpProvider::_EnumerateCredentials()
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::_EnumerateCredential");
	HRESULT hr = E_UNEXPECTED;

	/*
    if (_pCredProviderUserArray != nullptr)
    {
        DWORD dwUserCount;
        _pCredProviderUserArray->GetCount(&dwUserCount);
        if (dwUserCount > 0)
        {
            ICredentialProviderUser *pCredUser;
            hr = _pCredProviderUserArray->GetAt(0, &pCredUser);
            if (SUCCEEDED(hr))
            {
                _pCredential = new(std::nothrow) MultiotpCredential();
                if (_pCredential != nullptr)
                {
                    hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
                    if (FAILED(hr))
                    {
                        _pCredential->Release();
                        _pCredential = nullptr;
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
                pCredUser->Release();
            }
        }
    }
	*/

	DWORD dwUserCount = 0;

	if (_pCredProviderUserArray != nullptr)
	{
		_pCredProviderUserArray->GetCount(&dwUserCount);
		if (dwUserCount > 0)
		{
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::ProviderUserArrayGetCount: %d", dwUserCount);
			//_pCredential = new MultiotpCredential*[dwUserCount];
			for (DWORD i = 0; i < dwUserCount; i++) {
				ICredentialProviderUser *pCredUser;
				hr = _pCredProviderUserArray->GetAt(i, &pCredUser);
				if (SUCCEEDED(hr))
				{
					//_pCredential[i] = new(std::nothrow) MultiotpCredential();
					_pCredential.push_back(new(std::nothrow) MultiotpCredential());
					if (_pCredential[i] != nullptr)
					{
						if (DEVELOP_MODE) PrintLn("MultiotpProvider::new Credential()");
						hr = _pCredential[i]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
						if (FAILED(hr))
						{
							_pCredential[i]->Release();
							_pCredential[i] = nullptr;
							if (DEVELOP_MODE) PrintLn("MultiotpProvider::User tile initialization failed");
						}
						else {
							// if (DEVELOP_MODE) PrintLn("MultiotpProvider::UserSID: %s", _pCredential[i]->_pszUserSid);
						}
					}
					else
					{
						hr = E_OUTOFMEMORY;
					}
					pCredUser->Release();
				}
			}
		}
		else {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::Empty User List");
			//create empty user tile later
			/*
			_pCredential.push_back(new(std::nothrow) CSampleCredential());
			if (_pCredential[_pCredential.size()-1] != nullptr) {
				hr = _pCredential[_pCredential.size()-1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
			}
			*/
		}
	}
	else {
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::Unassigned User List");
		//it is probably Credential Provider V1 System...
		//create empty user tile later
		/*
		_pCredential.push_back(new(std::nothrow) CSampleCredential());
		if (_pCredential[_pCredential.size() - 1] != nullptr) {
			hr = _pCredential[_pCredential.size() - 1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
		}
		*/
	}
	// if you are in a domain or have no users on the list you have to show "Other user tile"
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::IsOS(OS_DOMAINMEMBER): %d", IsOS(OS_DOMAINMEMBER));
	if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1)) {
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::Adding empty user tile");
		_pCredential.push_back(new(std::nothrow) MultiotpCredential());
		if (_pCredential[_pCredential.size() - 1] != nullptr) {
			hr = _pCredential[_pCredential.size() - 1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
		}
		else {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::Error adding user: %d", (int)_pCredential.size());
		}
	}

	return hr;
}

// Boilerplate code to create our provider.
HRESULT Multiotp_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::Provider_CreateInstance");
	HRESULT hr;
    MultiotpProvider *pProvider = new(std::nothrow) MultiotpProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}


// Boilerplate code to create our provider. ADDED BY TBW FOR FILTER
HRESULT CLMSFilter_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::Filter_CreateInstance");
	HRESULT hr;
	CLMSFilter* pProvider = new CLMSFilter();
	//MultiotpProvider* pProvider = new MultiotpProvider();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

HRESULT CLMSFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID* rgclsidProviders, BOOL* rgbAllow, DWORD cProviders)
{
	LPOLESTR clsid;//PWSTR
	int isRDP;
	int onlyRDP = 0;//Local and RDP

	if (DEVELOP_MODE) PrintLn("========== MultiotpProvider::Applying CLMSFilter::Filter ==========");

	isRDP = IsRemoteSession();
	if (!isRDP) {
		if (readRegistryValueInteger(CONF_RDP_ONLY, onlyRDP)) {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter: Only RDP is OTP protected!!!");
			//isRDP = FALSE;
			return S_OK;
		}
		else {
			if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter: RDP and Local OTP protection");
			isRDP = TRUE;
		}
	} else if (DEVELOP_MODE) {
		PrintLn("MultiotpProvider::CLMSFilter::Filter: RDP connection");
	}

	switch (cpus)
	{
	case CPUS_LOGON:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter CPUS_LOGON");
	case CPUS_UNLOCK_WORKSTATION:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter CPUS_UNLOCK_WORKSTATION");
		for (DWORD i = 0; i < cProviders; i++)
		{
			if (i < dwFlags) {}

			if (IsEqualGUID(rgclsidProviders[i], CLSID_Multiotp)) {
				rgbAllow[i] = isRDP;// TRUE;
			}
			else {
				rgbAllow[i] = !isRDP;// FALSE;
			}
			if (DEVELOP_MODE) {
				StringFromCLSID(rgclsidProviders[i], &clsid);
				if (rgbAllow[i] == FALSE) {
					PrintLn(L"\t-", clsid);
				}
				else {
					PrintLn(L"\t+", clsid);
				}
				CoTaskMemFree(clsid);
			}
		}
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter End of CPUS_UNLOCK_WORKSTATION");
		return S_OK;
	case CPUS_CREDUI: //issue #1
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter CPUS_CREDUI");
	case CPUS_CHANGE_PASSWORD:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter CPUS_CHANGE_PASSWORD");
		return E_NOTIMPL;
	default:
		if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter::Filter default");
		return E_INVALIDARG;
	}

}

CLMSFilter::CLMSFilter() :
	_cRef(1)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter.Create");
	DllAddRef();
}

CLMSFilter::~CLMSFilter()
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::CLMSFilter.Destroy");
	DllRelease();
}


HRESULT CLMSFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut)
{
	if (DEVELOP_MODE) PrintLn("MultiotpProvider::UpdateRemoteCredential");

  // Based on https://social.msdn.microsoft.com/Forums/en-US/6e1ac74e-a2d0-427a-88d7-65935b08484e/getting-nla-credentials-in-a-credential-provider?forum=visualstudiogeneral

  if (!pcpcsIn) // no point continuing has there are no credentials
    return E_NOTIMPL;

  pcpcsOut->ulAuthenticationPackage = pcpcsIn->ulAuthenticationPackage;
  pcpcsOut->cbSerialization = pcpcsIn->cbSerialization;
  pcpcsOut->rgbSerialization = pcpcsIn->rgbSerialization;
  pcpcsOut->clsidCredentialProvider = CLSID_Multiotp;
  
  if (pcpcsOut->cbSerialization > 0 && (pcpcsOut->rgbSerialization = (BYTE*)CoTaskMemAlloc(pcpcsIn->cbSerialization)) != NULL) {
    CopyMemory(pcpcsOut->rgbSerialization, pcpcsIn->rgbSerialization, pcpcsIn-> cbSerialization);
    return S_OK;
  } else {
    return E_NOTIMPL;
  }
}