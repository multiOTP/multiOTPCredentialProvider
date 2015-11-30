//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"

#include "helpers.h"
#include "resource.h"

#include "registry.h"



CSampleCredential::CSampleCredential():
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

HRESULT CSampleCredential::call_multiotp(_In_ PCWSTR username, _In_ PCWSTR PREV_PIN, _In_ PCWSTR PIN)
{
	if (DEVELOPING) PrintLn("call_multiotp");
	HRESULT hr = E_NOTIMPL;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD exitCode;
	wchar_t cmd[1024];
	size_t len;
	PWSTR path;

	len = wcslen(username);
	if (wcslen(PREV_PIN) > 0) {
		len += wcslen(PREV_PIN);
		len += 1;//space char
	}
	len += 1;//space char
	len += wcslen(PIN);

	if (DEVELOPING) PrintLn("cmd len: %d", len);

	//cmd = (PWSTR)CoTaskMemAlloc(sizeof(wchar_t) * (len + 1));//+1 null pointer

	if (DEVELOPING) {
		wcscpy_s(cmd, 1024, L"multiotp.exe -debug ");
		//cmd = L"multiotp.exe -debug ";
	}
	else {
		wcscpy_s(cmd, 1024, L"multiotp.exe ");
		//cmd = L"multiotp.exe ";
	}

	if (wcslen(PREV_PIN) > 0) {
		wcscpy_s(cmd, 1024, L"-resync ");
	}

	//cmd = StrDup(cmd);
	wcscat_s(cmd, 1024, username);
	wcscat_s(cmd, 1024, L" ");
	//cmd = StrCat(cmd, username);
	//cmd = StrCat(cmd, L" ");

	if (wcslen(PREV_PIN) > 0) {
		wcscat_s(cmd, 1024, PREV_PIN);
		wcscat_s(cmd, 1024, L" ");
		//cmd = StrCat(cmd, PREV_PIN);
		//cmd = StrCat(cmd, L" ");
	}
	wcscat_s(cmd, 1024, PIN);
	//cmd = StrCat(cmd, PIN);

	len = wcslen(cmd);
	if (DEVELOPING) PrintLn("command len:%d", len);
	PrintLn(cmd);
	//return hr;

	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);

	if (readRegistryValueString(CONF_PATH, &path, L"c:\\multiotp\\windows\\")) {
		DWORD timeout = 60;

		timeout = readRegistryValueInteger(CONF_TIMEOUT, timeout);

		wchar_t appname[1024];

		wcscpy_s(appname, 1024, path);
		wcscat_s(appname, 1024, L"multiotp.exe");

		if (DEVELOPING) PrintLn(L"Calling ", appname);
		if (::CreateProcessW(appname, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, path, &si, &pi)) {

			DWORD result = WaitForSingleObject(pi.hProcess, (timeout * 1000));

			/*
			Return values:
			WAIT_ABANDONED
			WAIT_OBJECT_0
			WAIT_TIMEOUT
			WAIT_FAILED
			*/
			/*
			switch (result)
			{
			case WAIT_ABANDONED:
				//hr = ENDPOINT_ERROR_WAIT_ABANDONED;
				break;
			case WAIT_OBJECT_0:
				//hr = ENDPOINT_SUCCESS_WAIT_OBJECT_0;
				break;
			case WAIT_TIMEOUT:
				//hr = ENDPOINT_ERROR_WAIT_TIMEOUT;
				break;
			case WAIT_FAILED:
				//hr = ENDPOINT_ERROR_WAIT_FAILED;
				break;
			default:
				//hr = E_FAIL;
				break;
			}
			*/

			if (DEVELOPING) PrintLn("WaitForSingleObject result: %d", result);
			//DebugPrintLn(result);

			if (result == WAIT_OBJECT_0) {
				GetExitCodeProcess(pi.hProcess, &exitCode);

				PrintLn("multiOTP.exe Exit Code: %d", exitCode);
				//DebugPrintLn(exitCode);

				hr = exitCode;
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
			}
		}
		CoTaskMemFree(path);
	}
	return hr;
}

CSampleCredential::~CSampleCredential()
{
	if (_rgFieldStrings[SFI_PASSWORD])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
		SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
	}
	if (_rgFieldStrings[SFI_PREV_PIN])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PREV_PIN]);
		SecureZeroMemory(_rgFieldStrings[SFI_PREV_PIN], lenPassword * sizeof(*_rgFieldStrings[SFI_PREV_PIN]));
	}
	if (_rgFieldStrings[SFI_PIN])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PIN]);
		SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPassword * sizeof(*_rgFieldStrings[SFI_PIN]));
	}
	for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
	if (DEVELOPING) PrintLn("Initialize");
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"MultiOTP Credential", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"MultiOTP Login", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PREV_PIN]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Synchronize MultiOTP", &_rgFieldStrings[SFI_SYNCHRONIZE_LINK]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Back", &_rgFieldStrings[SFI_NEXT_LOGIN_ATTEMPT]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Enter PIN", &_rgFieldStrings[SFI_FAILURE_TEXT]);
	}
	if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
		if (_fIsLocalUser) {
			//local
			//hr = SHStrDupW(_pszQualifiedUserName, &_rgFieldStrings[SFI_LARGE_TEXT]);//computername\login
			PWSTR pszUserName;
			pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
			if (pszUserName != nullptr)
			{
				wchar_t szString[256];
				StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
				hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LARGE_TEXT]);
				CoTaskMemFree(pszUserName);
			}
			else
			{
				hr = SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_LARGE_TEXT]);
			}

		}
		else {
			//domain
			//hr = SHStrDupW(_pszQualifiedUserName, &_rgFieldStrings[SFI_LARGE_TEXT]);//Microsoft\login@domain.com
			//OTP on the microsoft.com uses account: Microsoft:login@domain.com -> so we have to change \ to :

		}
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
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
	if (DEVELOPING) PrintLn("Advised");
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
	if (DEVELOPING) PrintLn("Unadvised");
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
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

	if (_rgFieldStrings[SFI_PREV_PIN])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PREV_PIN]);
		SecureZeroMemory(_rgFieldStrings[SFI_PREV_PIN], lenPassword * sizeof(*_rgFieldStrings[SFI_PREV_PIN]));

		CoTaskMemFree(_rgFieldStrings[SFI_PREV_PIN]);
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PREV_PIN]);
		if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PREV_PIN, _rgFieldStrings[SFI_PREV_PIN]);
		}
	}

	if (_rgFieldStrings[SFI_PIN])
	{
		size_t lenPassword = wcslen(_rgFieldStrings[SFI_PIN]);
		SecureZeroMemory(_rgFieldStrings[SFI_PIN], lenPassword * sizeof(*_rgFieldStrings[SFI_PIN]));

		CoTaskMemFree(_rgFieldStrings[SFI_PIN]);
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
		if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, _rgFieldStrings[SFI_PIN]);
		}
	}

	return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

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
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

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
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
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
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

	if (SFI_SUBMIT_BUTTON == dwFieldID)
	{
		// pdwAdjacentTo is a pointer to the fieldID you want the submit button to
		// appear next to.
    	*pdwAdjacentTo = SFI_PIN;
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
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
	//WriteLogFile(pwz);2.20.201.2015...
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
		//validate numbers only for PIN Fields !!!!
		
		if ((dwFieldID == SFI_PIN) || (dwFieldID == SFI_PREV_PIN)){
			int len;
			
			if (DEVELOPING) PrintLn(L"Field altered, fieldID:", dwFieldID);
			if (DEVELOPING) PrintLn(L"New input:", pwz);

			len = wcslen(pwz);
			for (int i = 0; i < len; i++) {
				if (!isdigit(pwz[i])) {
					if (DEVELOPING) PrintLn(L"Invalid field value, fieldID:", dwFieldID);
					_pCredProvCredentialEvents->SetFieldString(this, dwFieldID, _rgFieldStrings[dwFieldID]);
					hr = E_INVALIDARG;
					return hr;
				}
			}

		}
		
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
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
	*ppwszLabel = nullptr;
	return E_INVALIDARG;/*
    HRESULT hr;
    *ppwszLabel = nullptr;

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

    return hr;*/
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
	return E_INVALIDARG;/*
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

    return hr;*/
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
	return E_INVALIDARG;/*
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

    return hr;*/
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
	return E_INVALIDARG;/*
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

    return hr;*/
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
	return E_INVALIDARG;/*
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

    return hr;*/
}


// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        //HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
        case SFI_NEXT_LOGIN_ATTEMPT:
            if (_pCredProvCredentialEvents)
            {
//                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
				_fShowControls = FALSE;//validate pin
				_pCredProvCredentialEvents->BeginFieldUpdates();
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LARGE_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PREV_PIN, CPFS_HIDDEN);
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PIN, CPFS_DISPLAY_IN_SELECTED_TILE);
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_SYNCHRONIZE_LINK, CPFS_DISPLAY_IN_SELECTED_TILE);
				_pCredProvCredentialEvents->SetFieldString(nullptr, SFI_SYNCHRONIZE_LINK, L"Synchronize MultiOTP");
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_NEXT_LOGIN_ATTEMPT, CPFS_HIDDEN);
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FAILURE_TEXT, CPFS_HIDDEN);
				_pCredProvCredentialEvents->EndFieldUpdates();
			}

            // Pop a messagebox indicating the click.
            //::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
            break;
        case SFI_SYNCHRONIZE_LINK:
			if (_pCredProvCredentialEvents)
			{
				_pCredProvCredentialEvents->BeginFieldUpdates();
				cpfsShow = _fShowControls ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PREV_PIN, cpfsShow);
				_pCredProvCredentialEvents->SetFieldString(nullptr, SFI_SYNCHRONIZE_LINK, _fShowControls ? L"Synchronize MultiOTP" : L"MultiOTP Login");
				_pCredProvCredentialEvents->SetFieldString(nullptr, SFI_LARGE_TEXT, _fShowControls ? L"MultiOTP Login" : L"Synchronize MultiOTP");
				_fShowControls = !_fShowControls;
				cpfsShow = _fShowControls ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
				_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD, cpfsShow);
				_pCredProvCredentialEvents->EndFieldUpdates();
				//_fShowControls == TRUE => synchronize pin
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
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
	if (DEVELOPING) PrintLn("GetSerialization");
	HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

	wchar_t uname[1024];

	//PWSTR pin1;
	//PWSTR pin2;
	//SHStrDupW(_rgFieldStrings[SFI_PREV_PIN], &pin1);
	//SHStrDupW(_rgFieldStrings[SFI_PIN], &pin2);
	//free pin1, pin2
	//CoTaskMemFree(pin1);
	//CoTaskMemFree(pin2);

	if ( ( ( _fShowControls) && (wcslen(_rgFieldStrings[SFI_PREV_PIN]) > 0) && (wcslen(_rgFieldStrings[SFI_PIN]) > 0) ) ||   //resync pin
		 ( (!_fShowControls) && (wcslen(_rgFieldStrings[SFI_PASSWORD]) > 0) && (wcslen(_rgFieldStrings[SFI_PIN]) > 0) )      //validate pin
		){
		const wchar_t *pchWhack = wcschr(_pszQualifiedUserName, L'\\') + 1;
		hr = wcscpy_s(uname, 1024, pchWhack);
		if (SUCCEEDED(hr)) {
			if (DEVELOPING) PrintLn(uname);
			//SHStrDupW(_rgFieldStrings[SFI_PREV_PIN], &pin1);
			hr = call_multiotp(uname, _rgFieldStrings[SFI_PREV_PIN], _rgFieldStrings[SFI_PIN]);
			//PrintLn("end");
			if ((hr == 0) && (wcslen(_rgFieldStrings[SFI_PREV_PIN]) == 0)) {
				if (DEVELOPING) PrintLn("MultiOTP Success!");//pin ok
			}
			else {
				SHStrDupW(L"Incorrect MultiOTP PIN", &_rgFieldStrings[SFI_FAILURE_TEXT]);
				for (DWORD i = 0; i < ARRAYSIZE(s_rgMultiOTPResponse); i++) {
					if (s_rgMultiOTPResponse[i].ErrorNum - hr == 0) {
						SHStrDupW(s_rgMultiOTPResponse[i].MessageText, &_rgFieldStrings[SFI_FAILURE_TEXT]);
						break;
					}
				}
				//PrintLn("result_code: %d", hr);
				PrintLn(_rgFieldStrings[SFI_FAILURE_TEXT]);
				//test
				if (_pCredProvCredentialEvents) {
					_pCredProvCredentialEvents->BeginFieldUpdates();
					_pCredProvCredentialEvents->SetFieldState(this, SFI_LARGE_TEXT, CPFS_HIDDEN);

					//_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
					_pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldString(this, SFI_PREV_PIN, L"");
					_pCredProvCredentialEvents->SetFieldState(this, SFI_PREV_PIN, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, L"");
					_pCredProvCredentialEvents->SetFieldState(this, SFI_PIN, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldState(this, SFI_SYNCHRONIZE_LINK, CPFS_HIDDEN);
					_pCredProvCredentialEvents->SetFieldState(this, SFI_NEXT_LOGIN_ATTEMPT, CPFS_DISPLAY_IN_SELECTED_TILE);
					//hr = SHStrDupW(L"Incorrect MultiOTP PIN", &_rgFieldStrings[SFI_FAILURE_TEXT]);
					//if (SUCCEEDED(hr))
					//{
						_pCredProvCredentialEvents->SetFieldString(this, SFI_FAILURE_TEXT, _rgFieldStrings[SFI_FAILURE_TEXT]);
					//}
					_pCredProvCredentialEvents->SetFieldState(this, SFI_FAILURE_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
					_pCredProvCredentialEvents->EndFieldUpdates();
				}
				*ppwszOptionalStatusText = _rgFieldStrings[SFI_FAILURE_TEXT];
				*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;
				//free pin1, pin2
				//CoTaskMemFree(pin1);
				//CoTaskMemFree(pin2);
				return ENDPOINT_AUTH_CONTINUE;
			}
		}
		
	}
	else {
		if (DEVELOPING) PrintLn("Missing MultiOTP PIN or PASSWORD");
		if (_pCredProvCredentialEvents) {
			_pCredProvCredentialEvents->BeginFieldUpdates();
			_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LARGE_TEXT, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PREV_PIN, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PIN, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_SYNCHRONIZE_LINK, CPFS_HIDDEN);
			_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_NEXT_LOGIN_ATTEMPT, CPFS_DISPLAY_IN_SELECTED_TILE);
			hr = SHStrDupW(L"Missing MultiOTP PIN or PASSWORD", &_rgFieldStrings[SFI_FAILURE_TEXT]);
			if (SUCCEEDED(hr))
			{
				_pCredProvCredentialEvents->SetFieldString(this, SFI_FAILURE_TEXT, _rgFieldStrings[SFI_FAILURE_TEXT]);
			}
			_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FAILURE_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
			_pCredProvCredentialEvents->EndFieldUpdates();
		}

		*ppwszOptionalStatusText = L"Missing MultiOTP PIN or PASSWORD";
		*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;
		//free pin1, pin2
		//CoTaskMemFree(pin1);
		//CoTaskMemFree(pin2);
		return ENDPOINT_AUTH_CONTINUE;
	}
	//free pin1, pin2
	//CoTaskMemFree(pin1);
	//CoTaskMemFree(pin2);

    // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
    if (_fIsLocalUser)
    {
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain;
            PWSTR pszUsername;
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
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
                            pcpcs->clsidCredentialProvider = CLSID_CSample;
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
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
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
                        pcpcs->clsidCredentialProvider = CLSID_CSample;

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
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
	if (DEVELOPING) PrintLn("ReportResult");
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
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PREV_PIN, L"");
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PIN, L"");
		}
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
	if (DEVELOPING) PrintLn("GetUserSid");
	*ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
	//PrintLn("GetFieldOptions");

	*pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
	else if (dwFieldID == SFI_PREV_PIN)
	{
//		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL | CPCFO_NUMBERS_ONLY;
		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
	}
	else if (dwFieldID == SFI_PIN)
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
