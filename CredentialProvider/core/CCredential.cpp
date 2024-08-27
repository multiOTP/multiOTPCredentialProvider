/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2017 NetKnights GmbH
**				2020-2024 SysCo systemes de communication sa
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
* 
* Change Log
*   2023-01-27 5.9.2.2 SysCo/yj ENH: unlock timeout, activate numlock
*   2022-08-10 5.9.2.1 SysCo/yj ENH: unlock timeout, iswithout2fa, display last authenticated user
*   2022-05-26 5.9.0.3 SysCo/al-yj ENH: UPN cache, Legacy cache
    2022-05-20 5.9.0.2 SysCo/yj ENH: Once SMS or EMAIL link is clicked, the link is hidden and a message is displayed to let the user know that the token was sent.
    2021-11-18 5.8.3.2 SysCo/YJ ENH: Take into account login with user@domain in the excluded account
**
** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include "CCredential.h"
#include "MultiOTPConfiguration.h"
#include "Logger.h"
#include "json.hpp"
#include <resource.h>
#include <string>
#include <thread>
#include <future>
#include <sstream>
#include "MultiotpHelpers.h" // multiOTP/yj
#include "MultiotpRegistry.h" // multiOTP/yj
#include "DsGetDC.h" // multiOTP/yj
#include "Lm.h" // multiOTP/yj
#include "mq.h" // multiOTP/yj
#include "sddl.h" // multiOTP/yj
#include "credentialprovider.h" // multiOTP/yj
#include "wtsapi32.h" // multiOTP/yj pour utiliser WTSEnumerateSessions

using namespace std;

CCredential::CCredential(std::shared_ptr<MultiOTPConfiguration> c) :
	_config(c), _util(_config), _privacyIDEA(c->piconfig)
{
	_cRef = 1;
	_pCredProvCredentialEvents = nullptr;

	DllAddRef();

	_dwComboIndex = 0;

	ZERO(_rgCredProvFieldDescriptors);
	ZERO(_rgFieldStatePairs);
	ZERO(_rgFieldStrings);
}

CCredential::~CCredential()
{
	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, NULL, CLEAR_FIELDS_ALL_DESTROY);
	DllRelease();
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT CCredential::Initialize(
	__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	__in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name,
	__in_opt PWSTR password
)
{
	wstring wstrUsername, wstrDomainname;
	SecureWString wstrPassword;

	if (NOT_EMPTY(user_name))
	{
		wstrUsername = wstring(user_name);
	}
	if (NOT_EMPTY(domain_name))
	{
		wstrDomainname = wstring(domain_name);
	}
	if (NOT_EMPTY(password))
	{
		wstrPassword = SecureWString(password);
	}
#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	DebugPrint(L"Username from provider: " + (wstrUsername.empty() ? L"empty" : wstrUsername));
	DebugPrint(L"Domain from provider: " + (wstrDomainname.empty() ? L"empty" : wstrDomainname));
	if (_config->piconfig.logPasswords)
	{
		DebugPrint(L"Password from provider: " + (wstrPassword.empty() ? L"empty" : wstrPassword));
	}
#endif
	HRESULT hr = S_OK;

	if (!wstrUsername.empty())
	{
		DebugPrint("Copying user to credential");
		_config->credential.username = wstrUsername;
	}

	if (!wstrDomainname.empty())
	{
		DebugPrint("Copying domain to credential");
		_config->credential.domain = wstrDomainname;
	}

	if (!wstrPassword.empty())
	{
		DebugPrint("Copying password to credential");
		_config->credential.password = wstrPassword;
		SecureZeroMemory(password, sizeof(password));
	}

	for (DWORD i = 0; SUCCEEDED(hr) && i < FID_NUM_FIELDS; i++)
	{
		//DebugPrintLn("Copy field #:");
		//DebugPrintLn(i + 1);
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);

		if (FAILED(hr))
		{
			break;
		}

		_util.InitializeField(_rgFieldStrings, i);
	}

	DebugPrint("Init result:");
	if (SUCCEEDED(hr))
	{
		DebugPrint("OK");
	}
	else
	{
		DebugPrint("FAIL");
	}

	return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CCredential::Advise(
	__in ICredentialProviderCredentialEvents* pcpce
)
{
	//DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents != nullptr)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();

	return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CCredential::UnAdvise()
{
	//DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = nullptr;
	return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
	DebugPrint(__FUNCTION__);
	*pbAutoLogon = false;
	HRESULT hr = S_OK;

	if (_config->doAutoLogon)
	{
		*pbAutoLogon = TRUE;
		_config->doAutoLogon = false;
	}

	if (_config->credential.passwordMustChange
		&& _config->provider.cpu == CPUS_UNLOCK_WORKSTATION
		&& _config->winVerMajor != 10)
	{
		// We cant handle a password change while the maschine is locked, so we guide the user to sign out and in again like windows does
		DebugPrint("Password must change in CPUS_UNLOCK_WORKSTATION");
		_pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT, L"Go back until you are asked to sign in.");
		_pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT, L"To change your password sign out and in again.");
		_pCredProvCredentialEvents->SetFieldState(this, FID_LDAP_PASS, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, FID_OTP, CPFS_HIDDEN);
	}

	if (_config->credential.passwordMustChange)
	{
		_util.SetScenario(this, _pCredProvCredentialEvents, SCENARIO::CHANGE_PASSWORD);
		if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
		{
			_config->bypassPrivacyIDEA = true;
		}
	}

	if (_config->credential.passwordChanged)
	{
		*pbAutoLogon = TRUE;
	}
	// Manage link display if it's in one step mode
	if (_config->provider.cpu == CPUS_LOGON && !_config->credential.passwordMustChange)
	{
		if (!_config->twoStepHideOTP)
		{
			if (readRegistryValueInteger(CONF_DISPLAY_EMAIL_LINK, 0)) {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_EMAIL, CPFS_DISPLAY_IN_SELECTED_TILE);
			}
			else {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_EMAIL, CPFS_HIDDEN);
			}
			if (readRegistryValueInteger(CONF_DISPLAY_SMS_LINK, 0)) {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_SMS, CPFS_DISPLAY_IN_SELECTED_TILE);
			}
			else {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_SMS, CPFS_HIDDEN);
			}
		}
	}

	if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION && !_config->credential.passwordMustChange) {
		if (!_config->twoStepHideOTP)
		{
			if (readRegistryValueInteger(CONF_DISPLAY_EMAIL_LINK, 0)) {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_EMAIL, CPFS_DISPLAY_IN_SELECTED_TILE);
			}
			else {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_EMAIL, CPFS_HIDDEN);
			}
			if (readRegistryValueInteger(CONF_DISPLAY_SMS_LINK, 0)) {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_SMS, CPFS_DISPLAY_IN_SELECTED_TILE);
			}
			else {
				_pCredProvCredentialEvents->SetFieldState(this, FID_REQUIRE_SMS, CPFS_HIDDEN);
			}
		}
	}



	return hr;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CCredential::SetDeselected()
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);

	_util.ResetScenario(this, _pCredProvCredentialEvents);

	// Reset password changing in case another user wants to log in
	_config->credential.passwordChanged = false;
	_config->credential.passwordMustChange = false;

	return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CCredential::GetFieldState(
	__in DWORD dwFieldID,
	__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Validate paramters.
	if (dwFieldID < FID_NUM_FIELDS && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CCredential::GetStringValue(
	__in DWORD dwFieldID,
	__deref_out PWSTR* ppwsz
)
{
	//DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	// Check to make sure dwFieldID is a legitimate index.
	if (dwFieldID < FID_NUM_FIELDS && ppwsz)
	{
		// Make a copy of the string and return that. The caller
		// is responsible for freeing it.
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Gets the image to show in the user tile.
HRESULT CCredential::GetBitmapValue(
	__in DWORD dwFieldID,
	__out HBITMAP* phbmp
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_INVALIDARG;
	if ((FID_LOGO == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = nullptr;
		LPCSTR lpszBitmapPath = PrivacyIDEA::ws2s(_config->bitmapPath).c_str();
		DebugPrint(lpszBitmapPath);
		if (NOT_EMPTY(lpszBitmapPath))
		{
			DWORD const dwAttrib = GetFileAttributesA(lpszBitmapPath);

			DebugPrint(dwAttrib);
			if (dwAttrib != INVALID_FILE_ATTRIBUTES
				&& !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
			{
				hbmp = (HBITMAP)LoadImageA(nullptr, lpszBitmapPath, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);

				if (hbmp == nullptr)
				{
					DebugPrint(GetLastError());
				}
			}
		}
		if (hbmp == nullptr)
		{
			// multiOTP/yj
			PWSTR path;
			// If multiotp.bmp exists, use this file
			if (readRegistryValueString(CONF_PATH, &path, L"c:\\multiotp\\") > 1) {
				wchar_t bitmap_path[1024];
				wcscpy_s(bitmap_path, 1024, path);
				size_t npath = wcslen(bitmap_path);
				if (bitmap_path[npath - 1] != '\\' && bitmap_path[npath - 1] != '/') {
					bitmap_path[npath] = '\\';
					bitmap_path[npath + 1] = '\0';
				}
				wcscat_s(bitmap_path, 1024, L"multiotp.bmp");
				if (PathFileExists(bitmap_path)) {
					hbmp = (HBITMAP)LoadImage(HINST_THISDLL, bitmap_path, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
				}
				else {
					hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
				}
			}
			else {
				hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
			}
			// multiOTP/yj
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

	DebugPrint(hr);

	return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CCredential::GetSubmitButtonValue(
	__in DWORD dwFieldID,
	__out DWORD* pdwAdjacentTo
)
{
	DebugPrint(__FUNCTION__);
	//DebugPrint("Submit Button ID:" + to_string(dwFieldID));
	if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		// This is only called once when the credential is created.
		// When switching to the second step, the button is set via CredentialEvents
		*pdwAdjacentTo = _config->twoStepHideOTP ? FID_LDAP_PASS : FID_OTP;
		return S_OK;
	}
	return E_INVALIDARG;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT CCredential::SetStringValue(
	__in DWORD dwFieldID,
	__in PCWSTR pwz
)
{
	HRESULT hr;

	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
			CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	//DebugPrintLn(hr);

	return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the 
// currently selected item (pdwSelectedItem).
HRESULT CCredential::GetComboBoxValueCount(
	__in DWORD dwFieldID,
	__out DWORD* pcItems,
	__out_range(< , *pcItems) DWORD* pdwSelectedItem
)
{
	DebugPrint(__FUNCTION__);

	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		// UNUSED
		*pcItems = 0;
		*pdwSelectedItem = 0;
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CCredential::GetComboBoxValueAt(
	__in DWORD dwFieldID,
	__in DWORD dwItem,
	__deref_out PWSTR* ppwszItem)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszItem);

	return E_INVALIDARG;
}

// Called when the user changes the selected item in the combobox.
HRESULT CCredential::SetComboBoxSelectedValue(
	__in DWORD dwFieldID,
	__in DWORD dwSelectedItem
)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwSelectedItem);
	// Validate parameters.
	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		return S_OK;
	}
	else
	{
		return E_INVALIDARG;
	}
}

HRESULT CCredential::GetCheckboxValue(
	__in DWORD dwFieldID,
	__out BOOL* pbChecked,
	__deref_out PWSTR* ppwszLabel
)
{
	// Called to check the initial state of the checkbox
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszLabel);
	*pbChecked = FALSE;
	//SHStrDupW(L"Use offline token.", ppwszLabel); // TODO custom text?

	return S_OK;
}

HRESULT CCredential::SetCheckboxValue(
	__in DWORD dwFieldID,
	__in BOOL bChecked
)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);
	DebugPrint(__FUNCTION__);
	return S_OK;
}

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	DebugPrint(__FUNCTION__);
	switch (dwFieldID)
	{
	   case FID_REQUIRE_SMS:
		   if(_pCredProvCredentialEvents) {
				_config->provider.pCredProvCredential = this;
				_config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
				_config->provider.field_strings = _rgFieldStrings;
				_util.ReadFieldValues();
				
			   // Cacher le bouton
			   hideCPField(_config->provider.pCredProvCredential, _config->provider.pCredProvCredentialEvents, FID_REQUIRE_SMS);
			   displayCPField(_config->provider.pCredProvCredential, _config->provider.pCredProvCredentialEvents, FID_CODE_SENT_SMS);
			   return multiotp_request(getCleanUsername(_config->credential.username, _config->credential.domain), L"", L"sms");
		   }
		   break;
	   case FID_REQUIRE_EMAIL:
		   if (_pCredProvCredentialEvents) {
			   _config->provider.pCredProvCredential = this;
			   _config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
			   _config->provider.field_strings = _rgFieldStrings;
			   _util.ReadFieldValues();

			   hideCPField(_config->provider.pCredProvCredential, _config->provider.pCredProvCredentialEvents, FID_REQUIRE_EMAIL);
			   displayCPField(_config->provider.pCredProvCredential, _config->provider.pCredProvCredentialEvents, FID_CODE_SENT_EMAIL);
			   return multiotp_request(getCleanUsername(_config->credential.username, _config->credential.domain), L"", L"email");
		   }
		   break;
	   case FID_CODE_SENT_SMS:
		   break;
	   case FID_CODE_SENT_EMAIL:
		   break;
	   case FID_LASTUSER_LOGGED:
		   if (_pCredProvCredentialEvents) {
			   PWSTR tempStr = L"";
			   if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"", L"lastUserAuthenticated", &tempStr, L"") > 1)
			   {
				   _pCredProvCredentialEvents->SetFieldString(this, FID_USERNAME, tempStr);
				   // Hide button
				   _pCredProvCredentialEvents->SetFieldState(this, FID_LASTUSER_LOGGED, CREDENTIAL_PROVIDER_FIELD_STATE::CPFS_HIDDEN);
				   // Put focus in password field
				   _pCredProvCredentialEvents->SetFieldInteractiveState(this, FID_LDAP_PASS, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE::CPFIS_FOCUSED);
			   }
		   }
		   break;
	   default:
		   return E_INVALIDARG;
	}
	return S_OK;
}

//------ end of methods for controls we don't have in our tile ----//

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
HRESULT CCredential::GetSerialization(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);
	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

	HRESULT hr = E_FAIL, retVal = S_OK;

	/*
	CPGSR_NO_CREDENTIAL_NOT_FINISHED
	No credential was serialized because more information is needed.

	CPGSR_NO_CREDENTIAL_FINISHED
	This serialization response means that the Credential Provider has not serialized a credential but
	it has completed its work. This response has multiple meanings.
	It can mean that no credential was serialized and the user should not try again.
	This response can also mean no credential was submitted but the credential?s work is complete.
	For instance, in the Change Password scenario, this response implies success.

	CPGSR_RETURN_CREDENTIAL_FINISHED
	A credential was serialized. This response implies a serialization structure was passed back.

	CPGSR_RETURN_NO_CREDENTIAL_FINISHED
	The credential provider has not serialized a credential, but has completed its work.
	The difference between this value and CPGSR_NO_CREDENTIAL_FINISHED is that this flag
	will force the logon UI to return, which will unadvise all the credential providers.
	*/

	_config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
	_config->provider.pCredProvCredential = this;

	_config->provider.pcpcs = pcpcs;
	_config->provider.pcpgsr = pcpgsr;

	_config->provider.status_icon = pcpsiOptionalStatusIcon;
	_config->provider.status_text = ppwszOptionalStatusText;

	_config->provider.field_strings = _rgFieldStrings;

	// Do password change
	if (_config->credential.passwordMustChange)
	{
		// Compare new passwords
		if (_config->credential.newPassword1 == _config->credential.newPassword2)
		{
			_util.KerberosChangePassword(pcpgsr, pcpcs, _config->credential.username, _config->credential.password,
				_config->credential.newPassword1, _config->credential.domain);
		}
		else
		{
			// not finished
			ShowErrorMessage(L"New passwords don't match!", 0);
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			_config->clearFields = false;
		}
	}
	else if (_config->credential.passwordChanged)
	{
		// Logon with the new password
		hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
			_config->credential.username, _config->credential.newPassword1, _config->credential.domain);
		_config->credential.passwordChanged = false;
	}
	else
	{
		if (_config->userCanceled)
		{
			*_config->provider.status_icon = CPSI_ERROR;
			*_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
			SHStrDupW(L"Logon cancelled", _config->provider.status_text);
			return S_FALSE;
		}
		// Check if we are pre 2nd step or failure
		if (_piStatus != PI_AUTH_SUCCESS && _config->pushAuthenticationSuccessful == false)
		{
			if (_config->isSecondStep == false && _config->twoStepHideOTP)
			{
				// Prepare for the second step (input only OTP)
				_config->isSecondStep = true;
				_config->clearFields = false;
				_util.SetScenario(_config->provider.pCredProvCredential,
					_config->provider.pCredProvCredentialEvents,
					SCENARIO::SECOND_STEP);
				*_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
			else
			{
				// Failed authentication or error section
				// Create a message depending on the error
				int errorCode = 0;
				wstring errorMessage;
				bool isGerman = GetUserDefaultUILanguage() == 1031;
				if (_piStatus == PI_AUTH_FAILURE)
				{
					errorMessage = _config->defaultOTPFailureText;
				}
				// In this case the error is contained in a valid response from PI
				else if (_piStatus == PI_AUTH_ERROR)
				{
					errorMessage = _privacyIDEA.getLastErrorMessage();
					errorCode = _privacyIDEA.getLastError();
				}
				else if (_piStatus == PI_WRONG_OFFLINE_SERVER_UNAVAILABLE)
				{
					errorMessage = isGerman ? L"Server nicht erreichbar oder falsches offline OTP!" :
						L"Server unreachable or wrong offline OTP!";
				}
				else if (_piStatus == PI_ENDPOINT_SERVER_UNAVAILABLE)
				{
					errorMessage = isGerman ? L"Server nicht erreichbar!" : L"Server unreachable!";
				}
				else if (_piStatus == PI_ENDPOINT_SETUP_ERROR)
				{
					errorMessage = isGerman ? L"Fehler beim Verbindungsaufbau!" : L"Error while setting up the connection!";
				}
				ShowErrorMessage(errorMessage, errorCode);
				_util.ResetScenario(this, _pCredProvCredentialEvents);
				*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
			}
		}
		else if (_piStatus == PI_AUTH_SUCCESS || _config->pushAuthenticationSuccessful)
		{
			// Reset the authentication
			_piStatus = PI_STATUS_NOT_SET;
			_config->pushAuthenticationSuccessful = false;
			_privacyIDEA.stopPoll();

			// Pack credentials for logon
			if (_config->provider.cpu == CPUS_CREDUI)
			{
				hr = _util.CredPackAuthentication(pcpgsr, pcpcs, _config->provider.cpu,
					_config->credential.username, _config->credential.password, _config->credential.domain);
			}
			else
			{
				hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
					_config->credential.username, _config->credential.password, _config->credential.domain);
			}
			if (SUCCEEDED(hr))
			{
				/* if (_config->credential.passwordChanged)
					_config->credential.passwordChanged = false; */
			}
			else
			{
				retVal = S_FALSE;
			}
		}
		else
		{
			ShowErrorMessage(L"Unexpected error", 0);

			// Jump to the first login window
			_util.ResetScenario(this, _pCredProvCredentialEvents);
			retVal = S_FALSE;
		}
	}

	if (_config->clearFields)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	}
	else
	{
		_config->clearFields = true; // it's a one-timer...
	}

#ifdef _DEBUG
	if (pcpgsr)
	{
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_NO_CREDENTIAL_NOT_FINISHED) { DebugPrint("CPGSR_NO_CREDENTIAL_NOT_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_CREDENTIAL_FINISHED"); }
		if (*pcpgsr == CPGSR_RETURN_NO_CREDENTIAL_FINISHED) { DebugPrint("CPGSR_RETURN_NO_CREDENTIAL_FINISHED"); }
	}
	else { DebugPrint("pcpgsr is a nullpointer!"); }
	DebugPrint("CCredential::GetSerialization - END");
#endif //_DEBUG
	return retVal;
}

// if code == 0, the code won't be displayed
void CCredential::ShowErrorMessage(const std::wstring& message, const HRESULT& code)
{
	*_config->provider.status_icon = CPSI_ERROR;
	wstring errorMessage = message;
	if (code != 0) errorMessage += L" (" + to_wstring(code) + L")";
	SHStrDupW(errorMessage.c_str(), _config->provider.status_text);
}

// If push is successful, reset the credential to do autologin
void CCredential::PushAuthenticationCallback(bool success)
{
	DebugPrint(__FUNCTION__);
	if (success)
	{
		_config->pushAuthenticationSuccessful = true;
		_config->doAutoLogon = true;
		// When autologon is triggered, connect is called instantly, therefore bypass privacyIDEA on next run
		_config->bypassPrivacyIDEA = true;
		_config->provider.pCredentialProviderEvents->CredentialsChanged(_config->provider.upAdviseContext);
	}
}

// Connect is called first after the submit button is pressed.
HRESULT CCredential::Connect(__in IQueryContinueWithStatus* pqcws)
{

	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(pqcws);

	_config->provider.pCredProvCredential = this;
	_config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
	_config->provider.field_strings = _rgFieldStrings;
	_util.ReadFieldValues();

	// Check if the user is the excluded account
	if (!_config->excludedAccount.empty())
	{
		wstring toCompare;
		if (!_config->credential.domain.empty()) {
			toCompare.append(_config->credential.domain).append(L"\\");
		}
		toCompare.append(_config->credential.username);

		// If the excluded account starts with ".\" then replace ".\" by "computername\" JEYA 04.07.2022
		if (_config->excludedAccount.find_first_of(L".\\") == 0) {
			WCHAR wsz[MAX_SIZE_DOMAIN];
			DWORD cch = ARRAYSIZE(wsz);
			if (GetComputerName(wsz, &cch)) {
				_config->excludedAccount = wstring(wsz, cch) + L"\\" + _config->excludedAccount.substr(2, _config->excludedAccount.length() - 2);
			}
		}

		if (toCompare.find_first_of(L".\\") == 0) {
			WCHAR wsz[MAX_SIZE_DOMAIN];
			DWORD cch = ARRAYSIZE(wsz);
			if (GetComputerName(wsz, &cch)) {
				toCompare = wstring(wsz, cch) + L"\\" + toCompare.substr(2, toCompare.length() - 2);
			}
		}

		if (PrivacyIDEA::toUpperCase(toCompare) == PrivacyIDEA::toUpperCase(_config->excludedAccount)) {
			DebugPrint("Login data matches excluded account, skipping 2FA...");
			// Simulate 2FA success so the logic in GetSerialization can stay the same
			_piStatus = PI_AUTH_SUCCESS;
			storeLastConnectedUserIfNeeded();
			return S_OK;
		}

		// the buffer is allocated by the system
		LPWSTR	lpNameBuffer;

		NET_API_STATUS nas;
		NETSETUP_JOIN_STATUS BufferType;

		// get info
		nas = NetGetJoinInformation(NULL, &lpNameBuffer, &BufferType);

		if (nas != NERR_Success)
		{
			// op failed :(
			PrintLn(L"Failed");
		}
		else {
			switch (BufferType) // Source : https://forums.codeguru.com/showthread.php?401584-Which-API-can-retrieve-workgroup-name
			{
				case NetSetupDomainName:
					// Verify with the non UPN domain name
					if (!_config->credential.domain.empty()) {
						PWSTR strNetBiosDomainName = L"";
						PWSTR pszDomain;
						PWSTR pszUsername;
						PWSTR pszQualifiedUserName = const_cast<wchar_t*>(toCompare.c_str());
						DOMAIN_CONTROLLER_INFO* pDCI;
						HRESULT hr_sfi = S_OK;
						hr_sfi = SplitDomainAndUsername(pszQualifiedUserName, &pszDomain, &pszUsername); // contoso\admin@contoso.com => [contoso,admin];  admin@contoso.com => [contoso.com,admin]
						if (SUCCEEDED(hr_sfi)) {
							if (DsGetDcNameW(NULL, pszDomain, NULL, NULL, DS_IS_DNS_NAME | DS_RETURN_FLAT_NAME, &pDCI) == ERROR_SUCCESS) {
								strNetBiosDomainName = pDCI->DomainName;
								toCompare = strNetBiosDomainName;
								toCompare = toCompare.append(L"\\").append(pszUsername);
								if (PrivacyIDEA::toUpperCase(toCompare) == PrivacyIDEA::toUpperCase(_config->excludedAccount)) {
									DebugPrint("Login data matches excluded account, skipping 2FA...");
									// Simulate 2FA success so the logic in GetSerialization can stay the same
									_piStatus = PI_AUTH_SUCCESS;
									// clean up
									NetApiBufferFree(lpNameBuffer);
									storeLastConnectedUserIfNeeded();
									return S_OK;
								}
							}
							else {
								// In case SplitDomainAndUsername returns netbios domain name
								toCompare = pszDomain;
								toCompare = toCompare.append(L"\\").append(pszUsername);
								if (PrivacyIDEA::toUpperCase(toCompare) == PrivacyIDEA::toUpperCase(_config->excludedAccount)) {
									DebugPrint("Login data matches excluded account, skipping 2FA...");
									// Simulate 2FA success so the logic in GetSerialization can stay the same
									_piStatus = PI_AUTH_SUCCESS;
									// clean up
									NetApiBufferFree(lpNameBuffer);
									storeLastConnectedUserIfNeeded();
									return S_OK;
								}
							}
						}
					}
					break;

				default:
					TCHAR  infoBuf[32767];
					DWORD  bufCharCount = 32767;
					GetComputerName(infoBuf, &bufCharCount);
					toCompare = infoBuf;												
					toCompare = toCompare.append(L"\\").append(_config->credential.username);
					if (PrivacyIDEA::toUpperCase(toCompare) == PrivacyIDEA::toUpperCase(_config->excludedAccount)) {
						DebugPrint("Login data matches excluded account, skipping 2FA...");
						// Simulate 2FA success so the logic in GetSerialization can stay the same
						_piStatus = PI_AUTH_SUCCESS;
						// clean up
						NetApiBufferFree(lpNameBuffer);
						storeLastConnectedUserIfNeeded();
						return S_OK;
					}
					break;
			}
		}

		// clean up
		NetApiBufferFree(lpNameBuffer);
		
	}
	if (_config->bypassPrivacyIDEA)
	{
		DebugPrint("Bypassing privacyIDEA...");
		_config->bypassPrivacyIDEA = false;

		return S_OK;
	}

	// Is multiOTP unlock timeout activated ?
	if (_config->multiOTPTimeoutUnlock > 0) {
		DebugPrint("multiOTP timeout Unlock is configured on : "+ std::to_string(_config->multiOTPTimeoutUnlock) + " minutes");

		// Let's search for the SID of the user that tries to log in
		wchar_t username[1024];
		std::wstring temp = cleanUsername(_config->provider.field_strings[FID_USERNAME]);
		wcscpy_s(username, 1024, temp.c_str());
		HRESULT hr = MQ_OK;
		PSID authLoginUserSid = NULL;
		hr = CCredential::getSid(username, &authLoginUserSid);
		if (FAILED(hr))
		{
			// Write in the log that it has failed
			DebugPrint(L"GetSid has failed with username: ");
			DebugPrint(username);
			DebugPrint(hr);
			DebugPrint("****");
		}
		else {
			// Convert SID to string
			LPTSTR authLoginUserSidAsString = NULL;
			ConvertSidToStringSid(authLoginUserSid, &authLoginUserSidAsString);
			DebugPrint(L"The SID of the user trying to connect is: " + (std::wstring)authLoginUserSidAsString);

			// Check the registry. Has this user logged in recently ?
			if (hasloggedInRecently(authLoginUserSidAsString))
			{
				DebugPrint("The user has logged in recently");
				WTS_SESSION_INFOW* pSessionInfo = NULL;
				DWORD count;
				// Look for the user in the current computer sessions
				if (0 != WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &count))
				{
					DebugPrint("Number of active sessions:" + std::to_string(count));

					// For each session
					for (int index = 0; index < count; index++) {
						DebugPrint("Session number:   " + std::to_string(index));
						DebugPrint("        id:       " + std::to_string(pSessionInfo[index].SessionId));
						DebugPrint("        state:    " + std::to_string(pSessionInfo[index].State));

						LPWSTR name;
						DWORD nameSize;
						WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, pSessionInfo[index].SessionId, _WTS_INFO_CLASS::WTSUserName, &name, &nameSize);
						DebugPrint(L"        username: " + (wstring)name);

						PSID pSessionUserSid = NULL;
						hr = CCredential::getSid(name, &pSessionUserSid);
						if (FAILED(hr)) {
							DebugPrint("FAILED to find the SID");
						}
						else {
							LPTSTR sessionSidAsString = NULL;
							ConvertSidToStringSid(pSessionUserSid, &sessionSidAsString);

							DebugPrint(L"        sid:      " + (wstring)sessionSidAsString);
							
							// Is the session linked to the user trying to connect ?
							if (pSessionInfo[index].State == WTS_CONNECTSTATE_CLASS::WTSActive && wcscmp(authLoginUserSidAsString,sessionSidAsString)==0) {
								DebugPrint("Found a session for the user trying to connect");
								_piStatus = PI_AUTH_SUCCESS; // Ne pas stocker l'heure de login sinon cela prolongerait le timeout
								return S_OK;
							}
						}
					}
					DebugPrint("No session found");
				}
			}
			else {
				DebugPrint("The user has NOT logged in recently");
			}
		}
	}

	
	// The user is without2fa no need to go further
	if (_config->multiOTPWithout2FA && _privacyIDEA.isWithout2FA(_config->credential.username, _config->credential.domain))
	{
		_piStatus = PI_AUTH_SUCCESS;
		storeLastConnectedUserIfNeeded(); 
		return S_OK;
	}
	HRESULT error_code;

	if (_config->twoStepHideOTP && !_config->isSecondStep)
	{
		if (!_config->twoStepSendEmptyPassword && !_config->twoStepSendPassword)
		{
			// Delay for a short moment, otherwise logonui freezes (???)
			this_thread::sleep_for(chrono::milliseconds(200));
		
			// Then skip to next step

			// Activate the numlock			
			if (_config->numlockOn && GetKeyState(VK_NUMLOCK) == 0 ) {
				keybd_event(VK_NUMLOCK, 0x45, KEYEVENTF_EXTENDEDKEY | 0, 0);
				keybd_event(VK_NUMLOCK, 0x45, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
			}
		}
		else
		{
			// Send either empty pass or the windows password in first step
			SecureWString toSend = L"sms";
			if (!_config->twoStepSendEmptyPassword && _config->twoStepSendPassword)
				toSend = _config->credential.password;
			_piStatus = _privacyIDEA.validateCheck(_config->credential.username, _config->credential.domain, toSend, "", error_code);
			if (_piStatus == PI_TRIGGERED_CHALLENGE)
			{
				Challenge c = _privacyIDEA.getCurrentChallenge();
				_config->challenge = c;
				if (!c.transaction_id.empty())
				{
					// Always show the OTP field, if push was triggered, start polling in background
					if (c.tta == TTA::BOTH || c.tta == TTA::PUSH)
					{
						// When polling finishes, pushAuthenticationCallback is invoked with the finialization success value
						_privacyIDEA.asyncPollTransaction(PrivacyIDEA::ws2s(_config->credential.username), c.transaction_id,
							std::bind(&CCredential::PushAuthenticationCallback, this, std::placeholders::_1));
					}
				}
				else
				{
					DebugPrint("Found incomplete challenge: " + c.toString());
				}
			}
			else
			{
				// Only classic OTP available, nothing else to do in the first step
			}
		}
	}
	//////////////////// SECOND STEP ////////////////////////
	else if (_config->twoStepHideOTP && _config->isSecondStep)
	{
		// Send with optional transaction_id from first step
		_piStatus = _privacyIDEA.validateCheck(
			_config->credential.username,
			_config->credential.domain,
			SecureWString(_config->credential.otp.c_str()),
			"", error_code);
		PWSTR tempStr = L"";
		if (_piStatus == PI_AUTH_SUCCESS)
		{
			storeLastConnectedUserIfNeeded();
		}
		else {
			_config->defaultOTPFailureText = getErrorMessage(error_code);
		}
		if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"", L"currentOfflineUser", &tempStr, L"") > 1) {
			PWSTR pszDomain;
			PWSTR pszUsername;
			SplitDomainAndUsername(tempStr, &pszDomain, &pszUsername); // contoso\admin@contoso.com => [contoso,admin];  admin@contoso.com => [contoso.com,admin]
			_config->credential.username = pszUsername;
			_config->credential.domain = pszDomain;
		}
	}
	//////// NORMAL SETUP WITH 3 FIELDS -> SEND OTP ////////
	else
	{
		// A voir si on vient ici
		_piStatus = _privacyIDEA.validateCheck(
			_config->credential.username,
			_config->credential.domain,
			SecureWString(_config->credential.otp.c_str()),
			"", error_code);
		PWSTR tempStr = L"";
		if (_piStatus == PI_AUTH_SUCCESS) {
			if (readKeyValueInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"", L"currentOfflineUser", &tempStr, L"") > 1) {
				_config->credential.username = tempStr;
			}
			storeLastConnectedUserIfNeeded();
		}
		else {
			_config->defaultOTPFailureText = getErrorMessage(error_code);
		}
	}
	DebugPrint("Connect - END");
	return S_OK; // always S_OK
}

HRESULT CCredential::Disconnect()
{
	return E_NOTIMPL;
}

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CCredential::ReportResult(
	__in NTSTATUS ntsStatus,
	__in NTSTATUS ntsSubstatus,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	// only print interesting statuses
	if (ntsStatus != 0)
	{
		std::stringstream ss;
		ss << std::hex << ntsStatus;
		DebugPrint("ntsStatus: " + ss.str());
	}
	if (ntsSubstatus != 0)
	{
		std::stringstream ss;
		ss << std::hex << ntsSubstatus;
		DebugPrint("ntsSubstatus: " + ss.str());
	}
#endif

	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	if (_config->credential.passwordMustChange && ntsStatus == 0 && ntsSubstatus == 0)
	{
		// Password change was successful, set this so SetSelected knows to autologon
		_config->credential.passwordMustChange = false;
		_config->credential.passwordChanged = true;
		_util.ResetScenario(this, _pCredProvCredentialEvents);
		return S_OK;
	}

	bool const pwMustChange = (ntsStatus == STATUS_PASSWORD_MUST_CHANGE) || (ntsSubstatus == STATUS_PASSWORD_EXPIRED);
	if (pwMustChange /* && !_config->credential.passwordMustChange*/)
	{
		_config->credential.passwordMustChange = true;
		DebugPrint("Status: Password must change");
		return S_OK;
	}

	// check if the password update was NOT successfull
	// these two are for new passwords not conform to password policies
	bool pwNotUpdated = (ntsStatus == STATUS_PASSWORD_RESTRICTION) || (ntsSubstatus == STATUS_ILL_FORMED_PASSWORD);
	if (pwNotUpdated)
	{
		DebugPrint("Status: Password update failed: Not conform to policies");
	}
	// this catches the wrong old password 
	pwNotUpdated = pwNotUpdated || ((ntsStatus == STATUS_LOGON_FAILURE) && (ntsSubstatus == STATUS_INTERNAL_ERROR));

	if (pwNotUpdated)
	{
		// it wasn't updated so we start over again
		_config->credential.passwordMustChange = true;
		_config->credential.passwordChanged = false;
	}
	/*
	if (ntsStatus == STATUS_LOGON_FAILURE && !pwNotUpdated)
	{
		_util.ResetScenario(this, _pCredProvCredentialEvents);
	}
	*/
	_util.ResetScenario(this, _pCredProvCredentialEvents);
	return S_OK;
}

void CCredential::storeLastConnectedUserIfNeeded() {
	PSID pTrustedUserSid = NULL;
	HRESULT hr = MQ_OK;

	if (_config->multiOTPDisplayLastUser || _config->multiOTPTimeoutUnlock > 0) {
		wchar_t username[1024];

		// R?cup?rer le SID
		std::wstring temp = cleanUsername(_config->provider.field_strings[FID_USERNAME]);
		wcscpy_s(username, 1024, temp.c_str());
		hr = CCredential::getSid(username, &pTrustedUserSid);
		if (FAILED(hr))
		{
			// Write in the log that it has failed
			DebugPrint(L"GetSid has failed with username: ");
			DebugPrint(username);
			DebugPrint(hr);
			DebugPrint("****");
		}

		// Store the SID and timestamp in order to check for locked users
		CCredential::storeSidAndTimeStamp(pTrustedUserSid);

		// A conserver pour proposer le dernier login
		wcscpy_s(username, 1024, _config->provider.field_strings[FID_USERNAME]);
		// Store the username
        writeRegistryValueString(LAST_USER_AUTHENTICATED, username);
		// Store the timestamp
		if (_config->multiOTPTimeoutUnlock > 0) {			
			const int timestamp = minutesSinceEpoch();
			writeRegistryValueInteger(LAST_USER_TIMESTAMP, timestamp);
		}
	} else {
		// Remove the registry value if the settings is disabled
		writeRegistryValueString(LAST_USER_AUTHENTICATED, L"");
	}
}

std::wstring CCredential::cleanUsername(std::wstring username)
{
	std::wstring clean = username;

	// Enlever ce qu'il y a avant le
	if (clean.find('\\') != string::npos) {
		clean = clean.substr(clean.find('\\') + 1);
	}

	if (clean.find('@') != string::npos) {
		clean = clean.substr(0, clean.find('@'));
	}
	return clean;
}

/**
Source : https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms707085(v=vs.85)?redirectedfrom=MSDN#Anchor_1
**/
HRESULT CCredential::getSid(LPCWSTR wszAccName, PSID* ppSid)
{
	// Validate the input parameters.  
	if (wszAccName == NULL || ppSid == NULL)
	{
		return MQ_ERROR_INVALID_PARAMETER;
	}

	// Create buffers that may be large enough.  
	// If a buffer is too small, the count parameter will be set to the size needed.  
	const DWORD INITIAL_SIZE = 32;
	DWORD cbSid = 0;
	DWORD dwSidBufferSize = INITIAL_SIZE;
	DWORD cchDomainName = 0;
	DWORD dwDomainBufferSize = INITIAL_SIZE;
	WCHAR* wszDomainName = NULL;
	SID_NAME_USE eSidType;
	DWORD dwErrorCode = 0;
	HRESULT hr = MQ_OK;

	// Create buffers for the SID and the domain name.  
	*ppSid = (PSID) new BYTE[dwSidBufferSize];
	if (*ppSid == NULL)
	{
		return MQ_ERROR_INSUFFICIENT_RESOURCES;
	}
	memset(*ppSid, 0, dwSidBufferSize);
	wszDomainName = new WCHAR[dwDomainBufferSize];
	if (wszDomainName == NULL)
	{
		return MQ_ERROR_INSUFFICIENT_RESOURCES;
	}
	memset(wszDomainName, 0, dwDomainBufferSize * sizeof(WCHAR));

	// Obtain the SID for the account name passed.  
	for (; ; ) // boucle infinie
	{

		// Set the count variables to the buffer sizes and retrieve the SID.  
		cbSid = dwSidBufferSize;
		cchDomainName = dwDomainBufferSize;
		if (LookupAccountNameW(
			NULL,            // Computer name. NULL for the local computer  
			wszAccName,
			*ppSid,          // Pointer to the SID buffer. Use NULL to get the size needed,  
			&cbSid,          // Size of the SID buffer needed.  
			wszDomainName,   // wszDomainName,  
			&cchDomainName,
			&eSidType
		))
		{
			if (IsValidSid(*ppSid) == FALSE)
			{
				DebugPrint(L"The SID for %s is invalid.\n", wszAccName);
				dwErrorCode = MQ_ERROR;
			}
			break;
		}
		dwErrorCode = GetLastError();

		// Check if one of the buffers was too small.  
		if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER)
		{
			if (cbSid > dwSidBufferSize)
			{

				// Reallocate memory for the SID buffer.  
				DebugPrint(L"The SID buffer was too small. It will be reallocated.\n");
				FreeSid(*ppSid);
				*ppSid = (PSID) new BYTE[cbSid];
				if (*ppSid == NULL)
				{
					return MQ_ERROR_INSUFFICIENT_RESOURCES;
				}
				memset(*ppSid, 0, cbSid);
				dwSidBufferSize = cbSid;
			}
			if (cchDomainName > dwDomainBufferSize)
			{

				// Reallocate memory for the domain name buffer.  
				DebugPrint(L"The domain name buffer was too small. It will be reallocated.");
				delete[] wszDomainName;
				wszDomainName = new WCHAR[cchDomainName];
				if (wszDomainName == NULL)
				{
					return MQ_ERROR_INSUFFICIENT_RESOURCES;
				}
				memset(wszDomainName, 0, cchDomainName * sizeof(WCHAR));
				dwDomainBufferSize = cchDomainName;
			}
		}
		else
		{
			hr = HRESULT_FROM_WIN32(dwErrorCode);
			break;
		}
	}

	delete[] wszDomainName;
	return hr;
}


HRESULT CCredential::storeSidAndTimeStamp(PSID ppsid) {
	LPTSTR StringSid = NULL;
	ConvertSidToStringSid(ppsid, &StringSid);
	const int timestamp = minutesSinceEpoch();
	writeKeyValueIntegerInMultiOTPRegistry(HKEY_CLASSES_ROOT, L"history", StringSid, timestamp);
	return S_OK;
}


/*
* Check if the SID exists in the history table AND check if the timeStamp is correct
*/
bool CCredential::hasloggedInRecently(LPTSTR userId) {
	DWORD lastLoggedInTime = 0;

	// Is multiOTP configured for unlockTimeout ?
	if (_config->multiOTPTimeoutUnlock > 0) {
		// Search if the key exists
		lastLoggedInTime = readKeyValueInMultiOTPRegistryInteger(HKEY_CLASSES_ROOT, L"history", userId, 0);

		DebugPrint(L"LAST LOGGED IN TIME FOR USER: "+ (std::wstring)userId );		
		DebugPrint(lastLoggedInTime);

		const int timestamp = minutesSinceEpoch();

		return (timestamp- lastLoggedInTime) < _config->multiOTPTimeoutUnlock;
	}
	return false;
}