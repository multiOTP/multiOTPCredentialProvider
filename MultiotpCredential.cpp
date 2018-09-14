/**
* BASE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
* Copyright (c) Microsoft Corporation. All rights reserved.
*
* Extra code provided "as is" for the multiOTP open source project
*
* @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
* @version   5.4.0.1
* @date      2018-09-14
* @since     2013
* @copyright (c) 2016-2018 SysCo systemes de communication sa
* @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
* @copyright (c) 2013-2015 Last Squirrel IT
* @copyright Apache License, Version 2.0
*
*
* Change Log
*
*   2018-03-11 5.2.0.0 SysCo/al New implementation from scratch
*
*********************************************************************/

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "MultiotpCredential.h"
#include "guid.h"

#include "MultiotpHelpers.h"
#include "resource.h"

#include "MultiotpRegistry.h"

// To use the TranslateNameW function
#include "Security.h"
// DsGetDcNameW
#include "DsGetDC.h"

MultiotpCredential::MultiotpCredential():
    _cRef(1),
    _pCredProvCredentialEventsV1(nullptr),
	_pCredProvCredentialEventsV2(nullptr),
	_pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
	_fUserNameVisible(false),
    _dwComboIndex(0)
{
	if (DEVELOP_MODE) PrintLn("========== MultiotpCredential::MultiotpCredential ==========");
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

MultiotpCredential::~MultiotpCredential()
{
	if (DEVELOP_MODE) PrintLn("========== Destroying MultiotpCredential ==========");

	if (_rgFieldStrings[SFI_PASSWORD])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
		SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
	}

	// Begin extra code
	if (_rgFieldStrings[SFI_PREV_OTP])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PREV_OTP]);
		SecureZeroMemory(_rgFieldStrings[SFI_PREV_OTP], lenPassword * sizeof(*_rgFieldStrings[SFI_PREV_OTP]));
	}
	if (_rgFieldStrings[SFI_OTP])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_OTP]);
		SecureZeroMemory(_rgFieldStrings[SFI_OTP], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP]));
	}
	// End extra code

	for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
	if (DEVELOP_MODE) PrintLn("========== MultiotpCredential Destroyed ==========");
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT MultiotpCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
	if (DEVELOP_MODE) PrintLn("========== MultiotpCredential Initialize ==========");
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;

    // pcpUser->GetProviderID(&guidProvider);
    // _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

	LPOLESTR clsid;

	PWSTR pszDomain, pszHostname, pszLoginTitle;
	wchar_t szDomainInfo[1024], szLoginTitle[1024];

	if (readRegistryValueString(CONF_DOMAIN_NAME, &pszDomain, L"") > 1) {
		StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L"Domain: %s", pszDomain);
	}
	else if (readRegistryValueString(CONF_HOST_NAME, &pszHostname, L"") > 1) {
		StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L"Computer: %s", pszHostname);
	}
	else {
		StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L" ");
	}

	if (readRegistryValueString(CONF_LOGIN_TITLE, &pszLoginTitle, L"") > 1) {
		StringCchPrintf(szLoginTitle, ARRAYSIZE(szLoginTitle), pszLoginTitle);
	}
	else {
		StringCchPrintf(szLoginTitle, ARRAYSIZE(szLoginTitle), L"multiOTP Login");
	}

	if (pcpUser != nullptr) {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::pcpUser provided");
		pcpUser->GetProviderID(&guidProvider);
		StringFromCLSID(guidProvider, &clsid);
		if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::Provider\t", clsid);
		CoTaskMemFree(clsid);
		_fIsLocalUser = (guidProvider == Identity_LocalUserProvider);
	}
	else {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::no pcpUser!!!");

		_fIsLocalUser = true;//CP V1 or Domain
	}

	if (DEVELOP_MODE) PrintLn("MultiotpCredential::_fIsLocalUser=%d", _fIsLocalUser);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

	// Go further in any case
	hr = S_OK;

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"multiOTP Credential", &_rgFieldStrings[SFI_LABEL]);
    }
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_LOGIN_NAME]);
	}
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(szLoginTitle, &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_NEWPASSWORD]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PREV_OTP]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Receive an OTP by SMS", &_rgFieldStrings[SFI_REQUIRE_SMS]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(szDomainInfo, &_rgFieldStrings[SFI_DOMAIN_INFO]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Synchronize multiOTP", &_rgFieldStrings[SFI_SYNCHRONIZE_LINK]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Enter OTP", &_rgFieldStrings[SFI_FAILURE_TEXT]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Back", &_rgFieldStrings[SFI_NEXT_LOGIN_ATTEMPT]);
	}

	hr = S_OK;

	if (SUCCEEDED(hr))
    {
      //hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
      if (pcpUser != nullptr) {
        if (DEVELOP_MODE) PrintLn("MultiotpCredential::Known user");
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);//get username from the LogonUI user object
        if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::Qualified User Name: ", _pszQualifiedUserName);
        if (_fIsLocalUser) {
          PWSTR pszUserName;
          pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
          if (pszUserName != nullptr) {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::User name: ", szString);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LARGE_TEXT]);
            CoTaskMemFree(pszUserName);
            // hr = pcpUser->GetSid(&_pszUserSid);
          } else {
            hr = SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_LARGE_TEXT]);
          }
        } else {
          if (DEVELOP_MODE) PrintLn("MultiotpCredential::Domain user, skip SFI_LARGE_TEXT");
          // domain
          // hr = SHStrDupW(_pszQualifiedUserName, &_rgFieldStrings[SFI_LARGE_TEXT]);//Microsoft\login@domain.com
        }
      } else {
        if (DEVELOP_MODE) PrintLn("MultiotpCredential::Unknown user -> display LoginName");
        hr = SHStrDupW(L"", &_pszQualifiedUserName);
        _fUserNameVisible = true;
        _rgFieldStatePairs[SFI_LOGIN_NAME].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;//unhide login name
        // switch focus to login
        _rgFieldStatePairs[SFI_LOGIN_NAME].cpfis = CPFIS_FOCUSED;
        _rgFieldStatePairs[SFI_PASSWORD].cpfis = CPFIS_NONE;
        // Don't panic!!!
      }
    }

    // Display or not the "Receive an OTP by SMS" link
    if (readRegistryValueInteger(CONF_DISPLAY_SMS_LINK, 0)) {
      _rgFieldStatePairs[SFI_REQUIRE_SMS].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    } else {
      _rgFieldStatePairs[SFI_REQUIRE_SMS].cpfs = CPFS_HIDDEN;
    }
    
	/*
	if (SUCCEEDED(hr))
    {
        PWSTR pszUserName;
        pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
        if (pszUserName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
            CoTaskMemFree(pszUserName);
        }
        else
        {
            hr =  SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszDisplayName;
        pcpUser->GetStringValue(PKEY_Identity_DisplayName, &pszDisplayName);
        if (pszDisplayName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Display Name: %s", pszDisplayName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
            CoTaskMemFree(pszDisplayName);
        }
        else
        {
            hr = SHStrDupW(L"Display Name is NULL", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszLogonStatus;
        pcpUser->GetStringValue(PKEY_Identity_LogonStatusString, &pszLogonStatus);
        if (pszLogonStatus != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Logon Status: %s", pszLogonStatus);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            CoTaskMemFree(pszLogonStatus);
        }
        else
        {
            hr = SHStrDupW(L"Logon Status is NULL", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
    }
	*/
    // if (SUCCEEDED(hr))
    if (pcpUser != nullptr)
    {
		hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT MultiotpCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    // if (_pCredProvCredentialEvents != nullptr)
    // {
    //     _pCredProvCredentialEvents->Release();
    // }
    // return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));

	HRESULT hr;
	if (DEVELOP_MODE) PrintLn("MultiotpCredential:Advised");
	if (_pCredProvCredentialEventsV1 != nullptr)
	{
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::Releasing old _pCredProvCredentialEventsV1");
		_pCredProvCredentialEventsV1->Release();
	}
	if (_pCredProvCredentialEventsV2 != nullptr)
	{
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::Releasing old _pCredProvCredentialEventsV2");
		_pCredProvCredentialEventsV2->Release();
	}

	//V2 has beginupdate so we try to use it by default
	hr = pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEventsV2));
	if (!_pCredProvCredentialEventsV2) {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::_pCredProvCredentialEventsV2 Events not available");
		hr = pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEventsV1));
		if (!_pCredProvCredentialEventsV1) {
			_pCredProvCredentialEventsV1->AddRef();
		}
	}
	else {
		_pCredProvCredentialEventsV2->AddRef();
	}

	if (_pCredProvCredentialEventsV2) {
		_pCredProvCredentialEvents = _pCredProvCredentialEventsV2;
	}
	else if (_pCredProvCredentialEventsV1) {
		_pCredProvCredentialEvents = _pCredProvCredentialEventsV1;
	}

	if (_pCredProvCredentialEvents) {
	}

	return hr;
}

// LogonUI calls this to tell us to release the callback.
HRESULT MultiotpCredential::UnAdvise()
{
	if (DEVELOP_MODE) PrintLn("MultiotpCredential::UnAdvise");
	if (_pCredProvCredentialEventsV2)
	{
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::UnAdvise EventsV2");
		_pCredProvCredentialEventsV2->Release();
		_pCredProvCredentialEventsV2 = nullptr;
	}
	if (_pCredProvCredentialEventsV1)
	{
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::UnAdvise EventsV1");
		_pCredProvCredentialEventsV1->Release();
		_pCredProvCredentialEventsV1 = nullptr;
	}
	return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT MultiotpCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT MultiotpCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

	// Begin extra code
	if (_rgFieldStrings[SFI_PREV_OTP])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PREV_OTP]);
		SecureZeroMemory(_rgFieldStrings[SFI_PREV_OTP], lenPassword * sizeof(*_rgFieldStrings[SFI_PREV_OTP]));

		CoTaskMemFree(_rgFieldStrings[SFI_PREV_OTP]);
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PREV_OTP]);
		if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PREV_OTP, _rgFieldStrings[SFI_PREV_OTP]);
		}
	}

	if (_rgFieldStrings[SFI_OTP])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_OTP]);
		SecureZeroMemory(_rgFieldStrings[SFI_OTP], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP]));

		CoTaskMemFree(_rgFieldStrings[SFI_OTP]);
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP]);
		if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP, _rgFieldStrings[SFI_OTP]);
		}
	}
	// End extra code

	return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT MultiotpCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

	if (DEVELOP_MODE) PrintLn("MultiotpCredential::GetFieldState: %d", dwFieldID);

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT MultiotpCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

	if (DEVELOP_MODE) PrintLn("MultiotpCredential::GetStringValue: %d", dwFieldID);

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT MultiotpCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;
    PWSTR path;
    BOOLEAN alternate_bmp = FALSE;
    
    if ((SFI_TILEIMAGE == dwFieldID))
    {
		HBITMAP hbmp = nullptr;
        if (readRegistryValueString(CONF_PATH, &path, L"c:\\multiotp\\") > 1) {
            wchar_t bitmap_path[1024];
            wcscpy_s(bitmap_path, 1024, path);
            size_t npath = wcslen(bitmap_path);
            if (bitmap_path[npath - 1] != '\\' && bitmap_path[npath - 1] != '/') {
                bitmap_path[npath] = '\\';
                bitmap_path[npath+1] = '\0';
            }
            wcscat_s(bitmap_path, 1024, L"multiotp.bmp");
            if (PathFileExists(bitmap_path)) {
				hbmp = (HBITMAP)LoadImage(HINST_THISDLL, bitmap_path, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
				if (hbmp != nullptr) {
					alternate_bmp = true;
				}
            }
        }

        // From File:
        // HBITMAP hbmp = (HBITMAP)LoadImage(hInstance, "myimage.bmp", IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
        
        if (!alternate_bmp) {
			hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        }
        
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT MultiotpCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

	if (SFI_SUBMIT_BUTTON == dwFieldID)
	{
		// pdwAdjacentTo is a pointer to the fieldID you want the submit button to
		// appear next to.
    	*pdwAdjacentTo = SFI_OTP; // SFI_PASSWORD;
		hr = S_OK;
	}
	else
	{
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT MultiotpCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

	if (DEVELOP_MODE) PrintLn("MultiotpCredential::SetStringValue, fieldID: %d", dwFieldID);

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        // Begin extra code
		//validate numbers only for OTP Fields !!!!

		/*
		 * 2017-11-03 SysCo/yj/al - Remove Digit OTP only check (for mOTP or alphanumerical prefix password)

		if ((dwFieldID == SFI_OTP) || (dwFieldID == SFI_PREV_OTP)){
			int len;
			
			if (DEVELOP_MODE) PrintLn("MultiotpCredential::New OTP input:", pwz);

			len = wcslen(pwz);
			for (int i = 0; i < len; i++) {
				if (!isdigit(pwz[i])) {
					if (DEVELOP_MODE) PrintLn("MultiotpCredential::Invalid OTP field value, fieldID: %d", dwFieldID);
					//this line will stop the Credential Provider on WinServ 2008 R2...
					_pCredProvCredentialEvents->SetFieldString(this, dwFieldID, _rgFieldStrings[dwFieldID]);
					hr = E_INVALIDARG;
					return hr;
				}
			}

		}

		*/


      if (_pCredProvCredentialEvents) {

        HRESULT hr_sfi = S_OK;

        PWSTR pszDomain;
        PWSTR pszUsername;
        PWSTR pszHostname;
        PWSTR pszQualifiedUserName;

        wchar_t szDomainInfo[1024];

        DWORD dwHostnameSize = 0;

        hr_sfi = SHStrDupW(L"", &pszUsername);
        hr_sfi = SHStrDupW(_rgFieldStrings[SFI_LOGIN_NAME], &pszQualifiedUserName);

        const wchar_t *pchWhack = wcschr(pszQualifiedUserName, L'\\');
        const wchar_t *pchWatSign = wcschr(pszQualifiedUserName, L'@');

        if (pchWatSign != nullptr) {
          StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L" ");
        } else if (pchWhack != nullptr) {
          hr_sfi = SplitDomainAndUsername(pszQualifiedUserName, &pszDomain, &pszUsername);
          if (SUCCEEDED(hr_sfi)) {
            StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L"Domain: %s", pszDomain);
            if (wcscmp(pszDomain, L".") == 0) {
              dwHostnameSize = readRegistryValueString(CONF_HOST_NAME, &pszHostname, L"");
              StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L"Computer: %s", pszHostname);
            }
          }
        }
        else {
          if (readRegistryValueString(CONF_DOMAIN_NAME, &pszDomain, L"") > 1) {
            StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L"Domain: %s", pszDomain);
          }
          else if (readRegistryValueString(CONF_HOST_NAME, &pszHostname, L"") > 1) {
            StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L"Computer: %s", pszHostname);
          }
          else {
            StringCchPrintf(szDomainInfo, ARRAYSIZE(szDomainInfo), L" ");
          }
        }

        SHStrDupW(szDomainInfo, &_rgFieldStrings[SFI_DOMAIN_INFO]);
        _pCredProvCredentialEvents->SetFieldString(this, SFI_DOMAIN_INFO, _rgFieldStrings[SFI_DOMAIN_INFO]);
      }
      // End extra code

      PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
      CoTaskMemFree(*ppwszStored);
      hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT MultiotpCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr;
    *ppwszLabel = nullptr;

	/*
    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }
	*/

	hr = dwFieldID;

	*pbChecked = _fChecked;
	hr = E_INVALIDARG;

	return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT MultiotpCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT MultiotpCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;

    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT MultiotpCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;

    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT MultiotpCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT MultiotpCredential::CommandLinkClicked(DWORD dwFieldID)
{
	HRESULT hr = S_OK;

	PWSTR pszLoginTitle;
	wchar_t szLoginTitle[1024];

	if (readRegistryValueString(CONF_LOGIN_TITLE, &pszLoginTitle, L"") > 1) {
		StringCchPrintf(szLoginTitle, ARRAYSIZE(szLoginTitle), pszLoginTitle);
	}
	else {
		StringCchPrintf(szLoginTitle, ARRAYSIZE(szLoginTitle), L"multiOTP Login");
	}

	if (DEVELOP_MODE) PrintLn("MultiotpCredential::CommandLinkClicked: %d", dwFieldID);

	if (!_pCredProvCredentialEvents) {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::No Events to dispatch command");
	}

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        // HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
		/*
        case SFI_LAUNCHWINDOW_LINK:
            if (_pCredProvCredentialEvents)
            {
              if (DEVELOP_MODE) PrintLn("MultiotpCredential::Altering fields");
//                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
              _fShowControls = FALSE;//validate OTP
              if (_pCredProvCredentialEventsV2) {
                _pCredProvCredentialEventsV2->BeginFieldUpdates();
              }
              _pCredProvCredentialEvents->SetFieldState(this, SFI_LARGE_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
              if (_fUserNameVisible) {
                //show edit box
                _pCredProvCredentialEvents->SetFieldState(this, SFI_LOGIN_NAME, CPFS_DISPLAY_IN_SELECTED_TILE);
              }
              else {
                _pCredProvCredentialEvents->SetFieldState(this, SFI_LOGIN_NAME, CPFS_HIDDEN);
              }
              _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
              _pCredProvCredentialEvents->SetFieldState(this, SFI_PREV_OTP, CPFS_HIDDEN);
              _pCredProvCredentialEvents->SetFieldState(this, SFI_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
              _pCredProvCredentialEvents->SetFieldState(this, SFI_DOMAIN_INFO, CPFS_DISPLAY_IN_SELECTED_TILE);
              _pCredProvCredentialEvents->SetFieldState(this, SFI_SYNCHRONIZE_LINK, CPFS_HIDDEN); // CPFS_DISPLAY_IN_SELECTED_TILE
              _pCredProvCredentialEvents->SetFieldString(this, SFI_SYNCHRONIZE_LINK, L"Synchronize multiOTP");
              _pCredProvCredentialEvents->SetFieldState(this, SFI_FAILURE_TEXT, CPFS_HIDDEN);
              _pCredProvCredentialEvents->SetFieldState(this, SFI_NEXT_LOGIN_ATTEMPT, CPFS_HIDDEN);
              if (_pCredProvCredentialEventsV2) {
                _pCredProvCredentialEventsV2->EndFieldUpdates();
              }
            }

            // Pop a messagebox indicating the click.
            //::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
            break;
		*/
		case SFI_NEXT_LOGIN_ATTEMPT:
			if (_pCredProvCredentialEvents)
			{
				if (DEVELOP_MODE) PrintLn("MultiotpCredential::Altering fields");
				// _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
				_fShowControls = FALSE;//validate OTP
				if (_pCredProvCredentialEventsV2) {
					_pCredProvCredentialEventsV2->BeginFieldUpdates();
				}
				_pCredProvCredentialEvents->SetFieldState(this, SFI_LARGE_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
				if (_fUserNameVisible) {
					//show edit box
					_pCredProvCredentialEvents->SetFieldState(this, SFI_LOGIN_NAME, CPFS_DISPLAY_IN_SELECTED_TILE);
				}
				else {
					_pCredProvCredentialEvents->SetFieldState(this, SFI_LOGIN_NAME, CPFS_HIDDEN);
				}
				_pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
				_pCredProvCredentialEvents->SetFieldState(this, SFI_PREV_OTP, CPFS_HIDDEN);
				_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP, CPFS_DISPLAY_IN_SELECTED_TILE);
				_pCredProvCredentialEvents->SetFieldState(this, SFI_DOMAIN_INFO, CPFS_DISPLAY_IN_SELECTED_TILE);
				_pCredProvCredentialEvents->SetFieldState(this, SFI_SYNCHRONIZE_LINK, CPFS_HIDDEN); // CPFS_DISPLAY_IN_SELECTED_TILE
				_pCredProvCredentialEvents->SetFieldString(this, SFI_SYNCHRONIZE_LINK, L"Synchronize multiOTP");
				_pCredProvCredentialEvents->SetFieldState(this, SFI_FAILURE_TEXT, CPFS_HIDDEN);
				_pCredProvCredentialEvents->SetFieldState(this, SFI_NEXT_LOGIN_ATTEMPT, CPFS_HIDDEN);
				if (_pCredProvCredentialEventsV2) {
					_pCredProvCredentialEventsV2->EndFieldUpdates();
				}
			}

			// Pop a messagebox indicating the click.
			//::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
			break;
		case SFI_SYNCHRONIZE_LINK:
          if (_pCredProvCredentialEvents)
          {
            if (DEVELOP_MODE) PrintLn("MultiotpCredential::Altering fields");
            if (_pCredProvCredentialEventsV2) {
              _pCredProvCredentialEventsV2->BeginFieldUpdates();
            }
            cpfsShow = _fShowControls ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PREV_OTP, cpfsShow);
            _pCredProvCredentialEvents->SetFieldString(this, SFI_SYNCHRONIZE_LINK, _fShowControls ? L"Synchronize multiOTP" : L"multiOTP Login");
            _pCredProvCredentialEvents->SetFieldString(this, SFI_LARGE_TEXT, _fShowControls ? szLoginTitle : L"Synchronize multiOTP");
            _fShowControls = !_fShowControls;
            cpfsShow = _fShowControls ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, cpfsShow);
            if (_pCredProvCredentialEventsV2) {
              _pCredProvCredentialEventsV2->EndFieldUpdates();
            }
            //_fShowControls == TRUE => synchronize OTP
          }
          break;

        case SFI_REQUIRE_SMS:
          if (_pCredProvCredentialEvents) {

            HRESULT hr_sfi = S_OK;

            PWSTR pszDomain;
            PWSTR pszUsername;
            PWSTR pszNetBiosDomainName = L"";

            ULONG size = 1024;
            wchar_t buffer[1024];

            wchar_t fullname[1024];
            wchar_t uname[1024];
            wchar_t upn_name[1024];
            wchar_t otp_name[1024];

            DWORD dwDomainSize = 0;
            
            BOOLEAN rc;

            hr_sfi = SHStrDupW(L"", &pszUsername);

            dwDomainSize = readRegistryValueString(CONF_DOMAIN_NAME, &pszDomain, L"");
            if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::Detected domain: ", pszDomain);
            if (DEVELOP_MODE) PrintLn("MultiotpCredential::Detected domain size: %d", dwDomainSize);

            if (_fUserNameVisible) {
              //username is entered by the user
              CoTaskMemFree(_pszQualifiedUserName);
              hr_sfi = SHStrDupW(_rgFieldStrings[SFI_LOGIN_NAME], &_pszQualifiedUserName);
            }

            if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::_pszQualifiedUserName: ", _pszQualifiedUserName);
  
            if (DEVELOP_MODE) PrintLn("MultiotpCredential::OTP Username determination");
            const wchar_t *pchWhack = wcschr(_pszQualifiedUserName, L'\\');
            const wchar_t *pchWatSign = wcschr(_pszQualifiedUserName, L'@');

			if (dwDomainSize > 1) {
				DOMAIN_CONTROLLER_INFO* pDCI;
				if (DsGetDcNameW(NULL, pszDomain, NULL, NULL, DS_IS_DNS_NAME | DS_RETURN_FLAT_NAME, &pDCI) == ERROR_SUCCESS) {
					pszNetBiosDomainName = pDCI->DomainName;

					if (DEVELOP_MODE) PrintLn(L"Before writing registry with value: ", pszNetBiosDomainName);
					// Write flat domain name in the internal multiOTP Credential registry cache
					writeRegistryValueString(CONF_FLAT_DOMAIN, pszNetBiosDomainName);

					// NetApiBufferFree(pDCI);
				}
				else {
					// Read flat domain name from the internal multiOTP Credential registry cache
					readRegistryValueString(CONF_FLAT_DOMAIN, &pszNetBiosDomainName, L"");
					if (DEVELOP_MODE) PrintLn(L"Flat domain named retrieved in the registry : ", pszNetBiosDomainName);
				}
			}

            if ((dwDomainSize > 1) && (pchWatSign == nullptr) && (pchWhack == nullptr)) {
              if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::Take the default domain ", pszDomain, L" - ", pszNetBiosDomainName);
              wcscpy_s(fullname, 1024, pszNetBiosDomainName);
              wcscat_s(fullname, 1024, L"\\");
              wcscat_s(fullname, 1024, _pszQualifiedUserName);
              CoTaskMemFree(_pszQualifiedUserName);
              hr = SHStrDupW(fullname, &_pszQualifiedUserName);
              pchWhack = wcschr(fullname, L'\\');
              if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::The full user has been defined like this: ", fullname);
            }

            if (pchWatSign != nullptr) {
              wcscpy_s(upn_name, 1024, _pszQualifiedUserName);
              rc = TranslateNameW(_pszQualifiedUserName, NameUserPrincipal, NameSamCompatible, buffer, &size);
              if (rc) {
                if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::User translated from ", _pszQualifiedUserName, L" to ", buffer);
                CoTaskMemFree(_pszQualifiedUserName);
                hr = SHStrDupW(buffer, &_pszQualifiedUserName);
                pchWhack = wcschr(buffer, L'\\');
              }
            } else {
              rc = TranslateNameW(_pszQualifiedUserName, NameSamCompatible, NameUserPrincipal, buffer, &size);
              if (rc) {
                if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::User translated to UPN, from ", _pszQualifiedUserName, L" to ", buffer);
                wcscpy_s(upn_name, 1024, buffer);
              }
            }
            
            if (pchWhack != nullptr) {
              const wchar_t *pchUsernameBegin = pchWhack + 1;
              hr = wcscpy_s(uname, 1024, pchUsernameBegin);
            } else {
              hr = wcscpy_s(uname, 1024, _pszQualifiedUserName);
              // 2017-11-05 SysCo/al Add UPN support
              if (pchWatSign == nullptr) {
                //append localhost as a domain for windows logon
                wcscpy_s(fullname, 1024, L".\\");
                wcscat_s(fullname, 1024, _pszQualifiedUserName);
                CoTaskMemFree(_pszQualifiedUserName);
                hr = SHStrDupW(fullname, &_pszQualifiedUserName);
              }

              if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::_pszQualifiedUserName with domain: ", _pszQualifiedUserName);
            }
            
            if (readRegistryValueInteger(CONF_UPN_FORMAT, 0)) {
              wcscpy_s(otp_name, 1024, upn_name);
            } else {
              wcscpy_s(otp_name, 1024, uname);
            }
            
            hr = multiotp_request(otp_name, L"", L"sms", L"");
          }
          break;

        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT MultiotpCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
	if (DEVELOP_MODE) PrintLn("MultiotpCredential::GetSerialization");
	HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    wchar_t fullname[1024];
    wchar_t uname[1024];
    wchar_t upn_name[1024];
    wchar_t otp_name[1024];

    PWSTR domain = L"";
    DWORD domainSize = 0;

	PWSTR strNetBiosDomainName = L"";

	BOOLEAN rc;

	domainSize = readRegistryValueString(CONF_DOMAIN_NAME, &domain, L"");
	if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::Detected domain: ", domain);
	if (DEVELOP_MODE) PrintLn("MultiotpCredential::Detected domain size: %d", domainSize);

	if (_fUserNameVisible) {
		//username is entered by the user
		CoTaskMemFree(_pszQualifiedUserName);
		hr = SHStrDupW(_rgFieldStrings[SFI_LOGIN_NAME], &_pszQualifiedUserName);
	}

	if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::_pszQualifiedUserName: ", _pszQualifiedUserName);

	if (DEVELOP_MODE) PrintLn("MultiotpCredential::OTP Username determination");
	const wchar_t *pchWhack = wcschr(_pszQualifiedUserName, L'\\');
	const wchar_t *pchWatSign = wcschr(_pszQualifiedUserName, L'@');

	if (domainSize > 1) {
		DOMAIN_CONTROLLER_INFO* pDCI;
		if (DsGetDcNameW(NULL, domain, NULL, NULL, DS_IS_DNS_NAME | DS_RETURN_FLAT_NAME, &pDCI) == ERROR_SUCCESS) {
			strNetBiosDomainName = pDCI->DomainName;
			if (DEVELOP_MODE) PrintLn(L"Before writing registry with value: ", strNetBiosDomainName);
			// Write flat domain name in the internal multiOTP Credential registry cache
		    writeRegistryValueString(CONF_FLAT_DOMAIN, strNetBiosDomainName);

			// NetApiBufferFree(pDCI);
		}
		else {
			// Read flat domain name from the internal multiOTP Credential registry cache
			readRegistryValueString(CONF_FLAT_DOMAIN, &strNetBiosDomainName, L"");
			if (DEVELOP_MODE) PrintLn(L"Flat domain named retrieved in the registry : ", strNetBiosDomainName);
		}
	}

	if ((domainSize > 1) && (pchWatSign == nullptr) && (pchWhack == nullptr)) {
		if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::Take the default domain ", domain, L" - ", strNetBiosDomainName);
		wcscpy_s(fullname, 1024, strNetBiosDomainName);
		wcscat_s(fullname, 1024, L"\\");
		wcscat_s(fullname, 1024, _pszQualifiedUserName);
		hr = SHStrDupW(fullname, &_pszQualifiedUserName);
		pchWhack = wcschr(fullname, L'\\');
		if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::The full user has been defined like this: ", fullname);
	}

  if (pchWatSign != nullptr) {
    ULONG size = 1024;
    wchar_t buffer[1024];
    wcscpy_s(upn_name, 1024, _pszQualifiedUserName);
    rc = TranslateNameW(_pszQualifiedUserName, NameUserPrincipal, NameSamCompatible, buffer, &size); // NameDnsDomain should also work instead of NameSamCompatible
    if (rc) {
      if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::User translated from ", _pszQualifiedUserName, L" to ", buffer);
      CoTaskMemFree(_pszQualifiedUserName);
      hr = SHStrDupW(buffer, &_pszQualifiedUserName);
      pchWhack = wcschr(buffer, L'\\');
    }
  } else {
    ULONG size = 1024;
    wchar_t buffer[1024];
    rc = TranslateNameW(_pszQualifiedUserName, NameSamCompatible, NameUserPrincipal, buffer, &size); // NameDnsDomain should also work instead of NameSamCompatible
    if (rc) {
      if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::User translated to UPN, from ", _pszQualifiedUserName, L" to ", buffer);
      wcscpy_s(upn_name, 1024, buffer);
    }
  }

	if (pchWhack != nullptr) {
		const wchar_t *pchUsernameBegin = pchWhack + 1;
		hr = wcscpy_s(uname, 1024, pchUsernameBegin);
		//if the user entered: domain\username
		if (wcslen(_rgFieldStrings[SFI_LOGIN_NAME]) > 0) {
			_fIsLocalUser = true;//false
		}
	} else {
		hr = wcscpy_s(uname, 1024, _pszQualifiedUserName);

        // 2017-11-05 SysCo/al Add UPN support
        if (pchWatSign == nullptr) {
          //append localhost as a domain for windows logon
          wcscpy_s(fullname, 1024, L".\\");
          wcscat_s(fullname, 1024, _pszQualifiedUserName);

          CoTaskMemFree(_pszQualifiedUserName);
          hr = SHStrDupW(fullname, &_pszQualifiedUserName);
        }

        if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::_pszQualifiedUserName with domain: ", _pszQualifiedUserName);

        //if the user entered: username
        if (wcslen(_rgFieldStrings[SFI_LOGIN_NAME]) > 0) {
            _fIsLocalUser = true;
        }
	}

		if (readRegistryValueInteger(CONF_UPN_FORMAT, 0)) {
      wcscpy_s(otp_name, 1024, upn_name);
    } else {
      wcscpy_s(otp_name, 1024, uname);
    }

  
	if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::_pszQualifiedUserName before the check is the following: ", _pszQualifiedUserName);

	if ( ( ( _fShowControls) && (wcslen(_rgFieldStrings[SFI_PREV_OTP]) > 0) && (wcslen(_rgFieldStrings[SFI_OTP]) > 0) ) ||   //resync OTP
		 ( (!_fShowControls) && (wcslen(_rgFieldStrings[SFI_PASSWORD]) > 0) && (wcslen(_rgFieldStrings[SFI_OTP]) > 0) ) ||   //validate OTP
		 ( (!_fShowControls) && (wcslen(_rgFieldStrings[SFI_PASSWORD]) > 0) ) // validate connexion with password but without OTP !
		){
		if (SUCCEEDED(hr)) {
			if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::OTP User:", otp_name);
			//SHStrDupW(_rgFieldStrings[SFI_PREV_OTP], &otp1);
			#pragma warning(push)
			#pragma warning(disable : 4127)
			if (SKIP_OTP_CHECK && DEVELOP_MODE) {
				PrintLn(L"MultiotpCredential::Dll compiled with SKIP_OTP_CHECK !!!!!!!!", hr);
				hr = MULTIOTP_SUCCESS;
			} else {
				hr = MULTIOTP_UNKNOWN_ERROR;
				if (readRegistryValueInteger(CONF_PREFIX_PASSWORD, 0)) {
					hr = multiotp_request(otp_name, _rgFieldStrings[SFI_PREV_OTP], _rgFieldStrings[SFI_OTP], _rgFieldStrings[SFI_PASSWORD]);
				}
				else {
					hr = multiotp_request(otp_name, _rgFieldStrings[SFI_PREV_OTP], _rgFieldStrings[SFI_OTP], L"");
				}
			}
			#pragma warning(pop)

			if ((hr == MULTIOTP_SUCCESS) && (wcslen(_rgFieldStrings[SFI_PREV_OTP]) == 0)) {
				if (DEVELOP_MODE) PrintLn("MultiotpCredential::multiOTP Success, value ", hr);//OTP ok
			}
			else {
				SHStrDupW(L"Incorrect multiOTP OTP code", &_rgFieldStrings[SFI_FAILURE_TEXT]);
				for (DWORD i = 0; i < ARRAYSIZE(s_rgmultiOTPResponse); i++) {
					if (s_rgmultiOTPResponse[i].ErrorNum - hr == 0) {
						SHStrDupW(s_rgmultiOTPResponse[i].MessageText, &_rgFieldStrings[SFI_FAILURE_TEXT]);
						break;
					}
				}
				//PrintLn("MultiotpCredential::result_code: %d", hr);
				if (DEVELOP_MODE) PrintLn("MultiotpCredential::failure text");
				if (DEVELOP_MODE) PrintLn(_rgFieldStrings[SFI_FAILURE_TEXT]);
				//test
				if (_pCredProvCredentialEvents) {
					if (DEVELOP_MODE) PrintLn("MultiotpCredential::Display Back link");
					if (_pCredProvCredentialEventsV2) {
						_pCredProvCredentialEventsV2->BeginFieldUpdates();
					}
					_pCredProvCredentialEvents->SetFieldState(this, SFI_LARGE_TEXT, CPFS_HIDDEN);

					//_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
					_pCredProvCredentialEvents->SetFieldState(this, SFI_LOGIN_NAME, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldString(this, SFI_PREV_OTP, L"");
					_pCredProvCredentialEvents->SetFieldState(this, SFI_PREV_OTP, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP, L"");
					_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP, CPFS_HIDDEN);
                    _pCredProvCredentialEvents->SetFieldState(this, SFI_DOMAIN_INFO, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldState(this, SFI_SYNCHRONIZE_LINK, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldState(this, SFI_NEXT_LOGIN_ATTEMPT, CPFS_DISPLAY_IN_SELECTED_TILE);
					//hr = SHStrDupW(L"Incorrect multiOTP OTP code", &_rgFieldStrings[SFI_FAILURE_TEXT]);
					//if (SUCCEEDED(hr))
					//{
						_pCredProvCredentialEvents->SetFieldString(this, SFI_FAILURE_TEXT, _rgFieldStrings[SFI_FAILURE_TEXT]);
					//}
					_pCredProvCredentialEvents->SetFieldState(this, SFI_FAILURE_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
					if (_pCredProvCredentialEventsV2) {
						_pCredProvCredentialEventsV2->EndFieldUpdates();
					}
				}
				*ppwszOptionalStatusText = _rgFieldStrings[SFI_FAILURE_TEXT];
				if (_pCredProvCredentialEventsV2) {
					*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;
				}
				else {
					*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
				}

				return ENDPOINT_AUTH_CONTINUE;
			}
		}
		
	} else {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::Missing multiOTP OTP code or PASSWORD");
		if (_pCredProvCredentialEvents) {
			if (_pCredProvCredentialEventsV2) {
				_pCredProvCredentialEventsV2->BeginFieldUpdates();
			}
			_pCredProvCredentialEvents->SetFieldState(this, SFI_LARGE_TEXT, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(this, SFI_LOGIN_NAME, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(this, SFI_PREV_OTP, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_DOMAIN_INFO, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(this, SFI_SYNCHRONIZE_LINK, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(this, SFI_NEXT_LOGIN_ATTEMPT, CPFS_DISPLAY_IN_SELECTED_TILE);
			hr = SHStrDupW(L"Missing multiOTP OTP code or PASSWORD", &_rgFieldStrings[SFI_FAILURE_TEXT]);
			if (SUCCEEDED(hr))
			{
				_pCredProvCredentialEvents->SetFieldString(this, SFI_FAILURE_TEXT, _rgFieldStrings[SFI_FAILURE_TEXT]);
			}
			_pCredProvCredentialEvents->SetFieldState(this, SFI_FAILURE_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
			if (_pCredProvCredentialEventsV2) {
				_pCredProvCredentialEventsV2->EndFieldUpdates();
			}
		}

		*ppwszOptionalStatusText = L"Missing multiOTP OTP code or PASSWORD";
		if (_pCredProvCredentialEventsV2) {
			*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;
		}
		else {
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		}

		return ENDPOINT_AUTH_CONTINUE;
	}

	// For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
	if (DEVELOP_MODE) PrintLn("MultiotpCredential::Continue with Windows Login");
	if (_fIsLocalUser)
    {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::GetSerialization Local user");
		PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain;
            PWSTR pszUsername;
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
				if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::SplitDomainAndUsername = ", pszDomain, L": ", pszUsername);
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {
                    // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                    // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                    // as necessary.
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                    if (SUCCEEDED(hr))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_Multiotp;
                            // At this point the credential has created the serialized credential used for logon
                            // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                            // that we have all the information we need and it should attempt to submit the
                            // serialized credential.
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                }
                CoTaskMemFree(pszDomain);
                CoTaskMemFree(pszUsername);
			}
			else {
				if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::SplitDomainAndUsername failed for user: ", _pszQualifiedUserName);
			}
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
		if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::Domain user: ", _pszQualifiedUserName);
        DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

        // First get the size of the authentication buffer to allocate
        if (!CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), nullptr, &pcpcs->cbSerialization) &&
            (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
        {
            pcpcs->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(pcpcs->cbSerialization));
            if (pcpcs->rgbSerialization != nullptr)
            {
                hr = S_OK;

                // Retrieve the authentication buffer
                if (CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_Multiotp;

                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    if (SUCCEEDED(hr))
                    {
						if (DEVELOP_MODE) PrintLn("MultiotpCredential::Logon failed with error: %d", hr);
                        hr = E_FAIL;
                    }
                }

                if (FAILED(hr))
                {
                    CoTaskMemFree(pcpcs->rgbSerialization);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT MultiotpCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
	if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::ReportResult ntsStatus (%d)", ntsStatus);
	if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::ReportResult ntsSubstatus (%d)", ntsSubstatus);

	*ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PREV_OTP, L"");
			_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP, L"");
		}
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT MultiotpCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
	if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::GetUserSid for ", _pszQualifiedUserName);
	*ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
		if (DEVELOP_MODE) PrintLn(L"MultiotpCredential::GetUserSid \t", _pszUserSid);
	}
	else {
		hr = S_FALSE;
	}
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
// https://msdn.microsoft.com/en-us/library/windows/desktop/hh706885(v=vs.85).aspx
HRESULT MultiotpCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
	// if (DEVELOP_MODE) PrintLn("MultiotpCredential::GetFieldOptions: %d", dwFieldID);

	*pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
	else if (dwFieldID == SFI_PREV_OTP)
	{
//		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL | CPCFO_NUMBERS_ONLY;
		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
	}
	else if (dwFieldID == SFI_OTP)
	{
//		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL | CPCFO_NUMBERS_ONLY;
		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
	}
	else if (dwFieldID == SFI_TILEIMAGE)
	{
		*pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
	}

    return S_OK;
}
