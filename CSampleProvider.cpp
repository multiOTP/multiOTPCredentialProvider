//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we will display one tile that uses each of the nine
// available UI controls.
#include "IPtools.h"

#include <initguid.h>
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"
#include "registry.h"

CSampleProvider::CSampleProvider():
    _cRef(1),
    _pCredProviderUserArray(nullptr)
{
    DllAddRef();
	if (DEVELOP_MODE) PrintLn("CSampleProvider created=======================");
}

CSampleProvider::~CSampleProvider()
{
    /*if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }*/
	_ReleaseEnumeratedCredentials();
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
	if (DEVELOP_MODE) PrintLn("=====================CSampleProvider destroyed");
    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CSampleProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

	//logfile << "Scenario:";
	if (DEVELOP_MODE) PrintLn("Provider Scenario: %d", cpus);
	//logfile << cpus;
	//PrintLn(L"Scenario:");
	//logfile << "\n";

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
	case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;

        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
		/*
        if(newPassword.Compare(confirmPassword) == 0)
        {
            KERB_CHANGEPASSWORD_REQUEST kcpr;
            ZeroMemory(&kcpr, sizeof(kcpr));                    

            hr = UnicodeStringInitWithString(m_domain, &kcpr.DomainName);

            if (SUCCEEDED(hr))
            {
                hr = UnicodeStringInitWithString(m_username, &kcpr.AccountName);

                if (SUCCEEDED(hr))
                {
                    hr = UnicodeStringInitWithString(_rgFieldStrings[SFI_PASSWORD], &kcpr.OldPassword);
                    hr = UnicodeStringInitWithString(_rgFieldStrings[SFI_NEWPASSWORD], &kcpr.NewPassword);

                    if (SUCCEEDED(hr))
                    {
                        kcpr.MessageType = KerbChangePasswordMessage;
                        kcpr.Impersonating = FALSE;
                        hr = KerbChangePasswordPack( kcpr, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

                        if (SUCCEEDED(hr))
                        {
                            ULONG ulAuthPackage;
                            hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                            if (SUCCEEDED(hr))
                            {
                                pcpcs->ulAuthenticationPackage = ulAuthPackage;
                                pcpcs->clsidCredentialProvider = CLSID_CSampleProvider;

                                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                            }
                        }
                    }
                }
            }
        }
		*/

		hr = E_NOTIMPL;
		break;

    case CPUS_CREDUI:
    //case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
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
HRESULT CSampleProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
	if (DEVELOP_MODE) PrintLn("Provider::SetSerialization");//that's the place to filter incoming SID from credentials supplied by NLA
	HRESULT hr = E_INVALIDARG;/*
	if ((CLSID_CSample == pcpcs->clsidCredentialProvider) || (CPUS_CREDUI == _cpus))
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
HRESULT CSampleProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
	if (DEVELOP_MODE) PrintLn("Provider::Advise");
    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CSampleProvider::UnAdvise()
{
	if (DEVELOP_MODE) PrintLn("Provider::UnAdvise");
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT CSampleProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CSampleProvider::GetFieldDescriptorAt(
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
HRESULT CSampleProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
	if (DEVELOP_MODE) PrintLn(L"GetCredentialCount");

	*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }
	DWORD dwUserCount;
	HRESULT hr;

	if (_pCredProviderUserArray != nullptr) {
		hr = _pCredProviderUserArray->GetCount(&dwUserCount);
		if (hr == 0) {
			if (DEVELOP_MODE) PrintLn(L"UserArrayCount:(%d)", dwUserCount);
		}
		else {
			if (DEVELOP_MODE) PrintLn(L"UserArray.GetCount Error");
			dwUserCount = 1;
		}
	}
	else {
		if (DEVELOP_MODE) PrintLn(L"Unassigned UserArray");
		dwUserCount = 1;
	}

	if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1)) {
		dwUserCount += 1;//display additional empty tile
		if (DEVELOP_MODE) PrintLn(L"Count +1 (empty tile)");
	}

	if (DEVELOP_MODE) PrintLn(L"User count:(%d)", dwUserCount);

	if (GetSystemMetrics(SM_REMOTESESSION)) {
		//PrintLn("RDP connection");

		*pdwCount = dwUserCount;//1
		
		//get RDP port from registry
		int RDPPort = 3389;//default RDPPort
		PWSTR ipAddr;
//		HRESULT hr;

		RDPPort = readRegistryValueInteger(CONF_RDP_PORT, RDPPort);
		if (DEVELOP_MODE) PrintLn("RDP connection on port: %d", RDPPort);

		hr = GetRDPClientAddress(RDPPort, &ipAddr);
		if (hr == 0) {
			if (DEVELOP_MODE) PrintLn(L"Remote Addr: ", ipAddr);
			//PrintLn(ipAddr);
			CoTaskMemFree(ipAddr);
		}
	}
	else {
		if (DEVELOP_MODE) PrintLn("Local connection");
		//logfile << "Local connection\n";

		if (readRegistryValueInteger(CONF_RDP_ONLY, 0)) {
			if (DEVELOP_MODE) PrintLn("Only RDP is OTP protected!!!");
			*pdwCount = 0;//no filtering no OTP tile
		}
		else {
			if (DEVELOP_MODE) PrintLn("RDP and Local OTP protection");
			*pdwCount = dwUserCount;//show OTP tile
		}

		if (DEVELOP_MODE) {
			PrintLn("OTP tile always visible");
			*pdwCount = dwUserCount;//development - don't force but allow OTP in all scenarios
		}
	}

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CSampleProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
	if (DEVELOP_MODE) PrintLn("GetCredentialAt: %d", (int)dwIndex);
	HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

	if (DEVELOP_MODE) PrintLn("Credential.size(%d)", _pCredential.size());

    if ((dwIndex < _pCredential.size()) && ppcpc)
    {
		if (DEVELOP_MODE) PrintLn("QueryInterface");
		hr = _pCredential[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
	//logfile << "SetUserArray\n";
	if (DEVELOP_MODE) PrintLn("SetUserArray");
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}

void CSampleProvider::_CreateEnumeratedCredentials()
{
	if (DEVELOP_MODE) PrintLn("_CreateEnumeratedCredentials: %d", _cpus);
	//logfile << "_CreateEnumeratedCredentials: ";
	//logfile << _cpus;
	//logfile << "\n";
    switch (_cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        {
            _EnumerateCredentials();
            break;
        }
    default:
        break;
    }
}

void CSampleProvider::_ReleaseEnumeratedCredentials()
{
	if (DEVELOP_MODE) PrintLn("_ReleaseEnumeratedCredentials");
	for (int i = 0; i < _pCredential.size(); i++) {
		if (_pCredential[i] != nullptr)
		{
			_pCredential[i]->Release();
			_pCredential[i] = nullptr;
		}
	}
	_pCredential.clear();
}

HRESULT CSampleProvider::_EnumerateCredentials()
{
	if (DEVELOP_MODE) PrintLn("_EnumerateCredential");
	HRESULT hr = E_UNEXPECTED;
	DWORD dwUserCount = 0;

	//logfile << "_EnumerateCredential\n";
    if (_pCredProviderUserArray != nullptr)
    {
        //DWORD dwUserCount = 0;
        _pCredProviderUserArray->GetCount(&dwUserCount);
        if (dwUserCount > 0)
        {
			if (DEVELOP_MODE) PrintLn(L"ProviderUserArrayGetCount: %d", dwUserCount);
			//_pCredential = new CSampleCredential*[dwUserCount];
			for (DWORD i = 0; i < dwUserCount; i++) {
				ICredentialProviderUser *pCredUser;
				hr = _pCredProviderUserArray->GetAt(i, &pCredUser);
				if (SUCCEEDED(hr))
				{
					//_pCredential[i] = new(std::nothrow) CSampleCredential();
					_pCredential.push_back(new(std::nothrow) CSampleCredential());
					if (_pCredential[i] != nullptr)
					{
						//logfile << "new CSampleCredential()\n";
						if (DEVELOP_MODE) PrintLn("new Credential()");
						hr = _pCredential[i]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
						if (FAILED(hr))
						{
							_pCredential[i]->Release();
							_pCredential[i] = nullptr;
							if (DEVELOP_MODE) PrintLn(L"User tile initialization failed");
						}
						else {
							//PrintLn("initialized()");
							//logfile << "initialized()\n";
							//fwprintf(logfile, L"%s", _pCredential[i]->_pszUserSid);
							//logfile << _pCredential[i]->_pszUserSid[15];
							//PrintLn(_pCredential[i]->_pszUserSid);
							if (DEVELOP_MODE) PrintLn(L"UserSID: ", _pCredential[i]->_pszUserSid);
							//logfile << " - User Added\n";
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
			if (DEVELOP_MODE) PrintLn("Empty User List");
			//create empty user tile later
			/*_pCredential.push_back(new(std::nothrow) CSampleCredential());
			if (_pCredential[_pCredential.size()-1] != nullptr) {
				hr = _pCredential[_pCredential.size()-1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
			}*/
		}
	}
	else {
		if (DEVELOP_MODE) PrintLn("Unassigned User List");
		//it is probably Credential Provider V1 System...
		//create empty user tile later
		/*_pCredential.push_back(new(std::nothrow) CSampleCredential());
		if (_pCredential[_pCredential.size() - 1] != nullptr) {
			hr = _pCredential[_pCredential.size() - 1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
		}*/
	}
	//if you are in a domain or have no users on the list you have to show "Other user tile"
	if (DEVELOP_MODE) PrintLn(L"IsOS(OS_DOMAINMEMBER): %d", IsOS(OS_DOMAINMEMBER));
	if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1)) {
		if (DEVELOP_MODE) PrintLn(L"Adding empty user tile");
		_pCredential.push_back(new(std::nothrow) CSampleCredential());
		if (_pCredential[_pCredential.size() - 1] != nullptr) {
			hr = _pCredential[_pCredential.size() - 1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);
		}
		else {
			if (DEVELOP_MODE) PrintLn(L"Error adding user: %d", _pCredential.size());
		}
	}
    return hr;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
	if (DEVELOP_MODE) PrintLn("Provider_CreateInstance");
    HRESULT hr;
    CSampleProvider *pProvider = new(std::nothrow) CSampleProvider();
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
	if (DEVELOP_MODE) PrintLn("Filter_CreateInstance");
	HRESULT hr;
	CLMSFilter* pProvider = new CLMSFilter();
	//CSampleProvider* pProvider = new CSampleProvider();

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

	//clsid = (PWSTR)CoTaskMemAlloc(sizeof(wchar_t) * (260 + 1));

	/*PrintLn("================TEST======================");
	PWSTR path;
	if (readRegistryValueString(CONF_PATH, &path)) {
		PrintLn(path);
		CoTaskMemFree(path);
	}
	PrintLn("================END=======================");*/

	//return S_OK;
	if (DEVELOP_MODE) PrintLn("=============Applying Filter==============");
	isRDP = GetSystemMetrics(SM_REMOTESESSION);
	if (!isRDP) {
		if (readRegistryValueInteger(CONF_RDP_ONLY, onlyRDP)) {
			if (DEVELOP_MODE) PrintLn("Only RDP is OTP protected!!!");
			//isRDP = FALSE;
			return S_OK;
		}
		else {
			if (DEVELOP_MODE) PrintLn("RDP and Local OTP protection");
			isRDP = TRUE;
		}
	}
	switch (cpus)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
		if (DEVELOP_MODE) PrintLn("<Filter>");
		for (DWORD i = 0; i < cProviders; i++)
		{
			if (i < dwFlags) {}

			if (IsEqualGUID(rgclsidProviders[i], CLSID_CSample)) {
				rgbAllow[i] = isRDP;// TRUE;
			} else {
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
		if (DEVELOP_MODE) PrintLn("</Filter>");
		return S_OK;
	case CPUS_CREDUI: //issue #1
	case CPUS_CHANGE_PASSWORD:
		return E_NOTIMPL;
	default:
		return E_INVALIDARG;
	}
	
}

CLMSFilter::CLMSFilter() :
	_cRef(1)
{
	if (DEVELOP_MODE) PrintLn(L"CLMSFilter.Create");
	DllAddRef();
}

CLMSFilter::~CLMSFilter()
{
	if (DEVELOP_MODE) PrintLn(L"CLMSFilter.Destroy");
	DllRelease();
}

HRESULT CLMSFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut)
{
	if (DEVELOP_MODE) PrintLn("UpdateRemoteCredential");
	return E_NOTIMPL;
}