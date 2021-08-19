#include "Utilities.h"
#include "helpers.h"
#include "SecureString.h"
#include "scenario.h"
#include "guid.h"
#include <Shlwapi.h>
#include "MultiotpRegistry.h"

using namespace std;

Utilities::Utilities(std::shared_ptr<Configuration> c) noexcept
{
	_config = c;
}

const std::wstring Utilities::texts[10][2] = {
		{L"Username", L"Benutzername"},
		{L"Password", L"Kennwort"},
		{L"Old Password", L"Altes Kennwort"},
		{L"New Password", L"Neues Kennwort"},
		{L"Confirm password", L"Kennwort bestätigen"},
		{L"Sign in to: ", L"Anmelden an: "},
		{L"One-Time Password", L"Einmalpassword"},
		{L"Wrong One-Time Password!", L"Falsches Einmalpasswort!"},
		{L"Wrong password", L"Das Kennwort ist falsch. Wiederholen Sie den Vorgang."},
		{L"Please enter your second factor!", L"Bitte geben Sie ihren zweiten Faktor ein!"}
};

std::wstring Utilities::GetTranslatedText(int id)
{
	const int inGerman = GetUserDefaultUILanguage() == 1031; // 1031 is german
	return texts[id][inGerman];
}

HRESULT Utilities::KerberosLogon(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in SecureWString password,
	__in std::wstring domain)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr;

	WCHAR wsz[MAX_SIZE_DOMAIN]; // actually MAX_COMPUTERNAME_LENGTH + 1 would be enough
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = false;

	if (domain.empty())
	{
		bGetCompName = GetComputerNameW(wsz, &cch);
	}
	if (bGetCompName)
	{
		domain = wstring(wsz, cch);
	}

#ifdef _DEBUG
	DebugPrint("Packing Credential:");
	DebugPrint(username);
	DebugPrint(password.empty() ? L"empty password" :
		(_config->piconfig.logPasswords ? password : L"hidden but has value"));
	DebugPrint(domain);
#endif

	if (!domain.empty() || bGetCompName)
	{
		PWSTR pwzProtectedPassword;

		hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus, &pwzProtectedPassword);

		if (SUCCEEDED(hr))
		{
			KERB_INTERACTIVE_UNLOCK_LOGON kiul;
			LPWSTR lpwszDomain = new wchar_t[domain.size() + 1];
			wcscpy_s(lpwszDomain, (domain.size() + 1), domain.c_str());

			LPWSTR lpwszUsername = new wchar_t[username.size() + 1];
			wcscpy_s(lpwszUsername, (username.size() + 1), username.c_str());

			// Initialize kiul with weak references to our credential.
			hr = KerbInteractiveUnlockLogonInit(lpwszDomain, lpwszUsername, pwzProtectedPassword, cpus, &kiul);

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
						//DebugPrintLn("Packing of KERB_INTERACTIVE_UNLOCK_LOGON successful");
						// At self point the credential has created the serialized credential used for logon
						// By setting self to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
						// that we have all the information we need and it should attempt to submit the 
						// serialized credential.
						*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
					}
				}
			}

			delete[] lpwszDomain;
			delete[] lpwszUsername;

			CoTaskMemFree(pwzProtectedPassword);
		}
	}
	else
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
	}

	return hr;
}

HRESULT Utilities::KerberosChangePassword(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__in std::wstring username,
	__in SecureWString password_old,
	__in SecureWString password_new,
	__in std::wstring domain)
{
	DebugPrint(__FUNCTION__);
	KERB_CHANGEPASSWORD_REQUEST kcpr;
	ZeroMemory(&kcpr, sizeof(kcpr));

	HRESULT hr;

	WCHAR wsz[64];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = true;

	if (!domain.empty())
	{
		wcscpy_s(wsz, ARRAYSIZE(wsz), domain.c_str());
	}
	else
	{
		bGetCompName = GetComputerNameW(wsz, &cch);
	}

	DebugPrint(L"User: " + username);
	DebugPrint(L"Domain: " + wstring(wsz));
	DebugPrint(L"Pw old: " + _config->piconfig.logPasswords ? password_old :
		(password_old.empty() ? L"no value" : L"hidden but has value"));
	DebugPrint(L"Pw new: " + _config->piconfig.logPasswords ? password_new :
		(password_new.empty() ? L"no value" : L"hidden but has value"));

	if (!domain.empty() || bGetCompName)
	{
		hr = UnicodeStringInitWithString(wsz, &kcpr.DomainName);
		if (SUCCEEDED(hr))
		{
			PWSTR lpwszUsername = new wchar_t[(username.size() + 1)];
			wcscpy_s(lpwszUsername, (username.size() + 1), username.c_str());

			hr = UnicodeStringInitWithString(lpwszUsername, &kcpr.AccountName);
			if (SUCCEEDED(hr))
			{
				// These buffers cant be zeroed since they are passed to LSA
				PWSTR lpwszPasswordOld = new wchar_t[(password_old.size() + 1)];
				wcscpy_s(lpwszPasswordOld, (password_old.size() + 1), password_old.c_str());

				PWSTR lpwszPasswordNew = new wchar_t[(password_new.size() + 1)];
				wcscpy_s(lpwszPasswordNew, (password_new.size() + 1), password_new.c_str());
				// vvvv they just copy the pointer vvvv
				hr = UnicodeStringInitWithString(lpwszPasswordOld, &kcpr.OldPassword);
				hr = UnicodeStringInitWithString(lpwszPasswordNew, &kcpr.NewPassword);

				if (SUCCEEDED(hr))
				{
					kcpr.MessageType = KerbChangePasswordMessage;
					kcpr.Impersonating = FALSE;
					hr = KerbChangePasswordPack(kcpr, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
					if (SUCCEEDED(hr))
					{
						ULONG ulAuthPackage;
						hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
						if (SUCCEEDED(hr))
						{
							pcpcs->ulAuthenticationPackage = ulAuthPackage;
							pcpcs->clsidCredentialProvider = CLSID_CSample;
							*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
						}
					}
				}
			}
		}
	}
	else
	{
		DWORD dwErr = GetLastError();
		hr = HRESULT_FROM_WIN32(dwErr);
	}

	return hr;
}

HRESULT Utilities::CredPackAuthentication(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in SecureWString password,
	__in std::wstring domain)
{

#ifdef _DEBUG
	DebugPrint(__FUNCTION__);
	DebugPrint(username);
	if (_config->piconfig.logPasswords) 
	{
		DebugPrint(password.c_str());
	}
	DebugPrint(domain);
#endif

	const DWORD credPackFlags = _config->provider.credPackFlags;
	PWSTR pwzProtectedPassword;
	HRESULT hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus, &pwzProtectedPassword);

	WCHAR wsz[MAX_SIZE_DOMAIN];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = false;

	if (domain.empty())
	{
		bGetCompName = GetComputerNameW(wsz, &cch);
	}
	if (bGetCompName)
	{
		domain = wsz;
	}

	if (SUCCEEDED(hr))
	{
		PWSTR domainUsername = NULL;
		hr = DomainUsernameStringAlloc(domain.c_str(), username.c_str(), &domainUsername);
		DebugPrint(domainUsername);
		if (SUCCEEDED(hr))
		{
			DWORD size = 0;
			BYTE* rawbits = NULL;

			LPWSTR lpwszPassword = new wchar_t[(password.size() + 1)];
			wcscpy_s(lpwszPassword, (password.size() + 1), password.c_str());

			if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
				domainUsername, lpwszPassword, rawbits, &size))
			{
				// We received the necessary size, let's allocate some rawbits
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					rawbits = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);

					if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
						domainUsername, lpwszPassword, rawbits, &size))
					{
						HeapFree(GetProcessHeap(), 0, rawbits);
						HeapFree(GetProcessHeap(), 0, domainUsername);

						hr = HRESULT_FROM_WIN32(GetLastError());
					}
					else
					{
						pcpcs->rgbSerialization = rawbits;
						pcpcs->cbSerialization = size;
					}
				}
				else
				{
					HeapFree(GetProcessHeap(), 0, domainUsername);
					hr = HRESULT_FROM_WIN32(GetLastError());
				}
			}

			if (SUCCEEDED(hr))
			{
				ULONG ulAuthPackage;
				hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

				if (SUCCEEDED(hr))
				{
					pcpcs->ulAuthenticationPackage = ulAuthPackage;
					pcpcs->clsidCredentialProvider = CLSID_CSample;

					// At this point the credential has created the serialized credential used for logon
					// By setting self to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
					// that we have all the information we need and it should attempt to submit the 
					// serialized credential.
					*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
				}
			}

			SecureZeroMemory(lpwszPassword, sizeof(lpwszPassword));
		}

		CoTaskMemFree(pwzProtectedPassword);
	}

	return hr;
}

HRESULT Utilities::SetScenario(
	__in ICredentialProviderCredential* pCredential,
	__in ICredentialProviderCredentialEvents* pCPCE,
	__in SCENARIO scenario)
{
	//DebugPrint(__FUNCTION__);
	HRESULT hr = S_OK;

	switch (scenario)
	{
	case SCENARIO::LOGON_BASE:
		DebugPrint("SetScenario: LOGON_BASE");
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioDisplayAllFields);
		break;
	case SCENARIO::UNLOCK_BASE:
		DebugPrint("SetScenario: UNLOCK_BASE");
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioUnlockPasswordOTP);
		break;
	case SCENARIO::SECOND_STEP:
		DebugPrint("SetScenario: SECOND_STEP");
		// Set the submit button next to the OTP field for the second step
		_config->provider.pCredProvCredentialEvents->SetFieldSubmitButton(_config->provider.pCredProvCredential,
			FID_SUBMIT_BUTTON, FID_OTP);
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioSecondStepOTP);
		break;
	case SCENARIO::CHANGE_PASSWORD:
		DebugPrint("SetScenario: CHANGE_PASSWORD");
		// Set the submit button next to the repeat pw field
		_config->provider.pCredProvCredentialEvents->SetFieldSubmitButton(_config->provider.pCredProvCredential,
			FID_SUBMIT_BUTTON, FID_NEW_PASS_2);
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioPasswordChange);
		break;
	case SCENARIO::UNLOCK_TWO_STEP:
		DebugPrint("SetScenario: UNLOCK_TWO_STEP");
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioUnlockFirstStepPassword);
		break;
	case SCENARIO::LOGON_TWO_STEP:
		DebugPrint("SetScenario: LOGON_TWO_STEP");
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioLogonFirstStepUserLDAP);
		break;
	case SCENARIO::NO_CHANGE:
		DebugPrint("SetScenario: NO_CHANGE");
	default:
		break;
	}


	if (_config->credential.passwordMustChange)
	{
		// Show username in large text, prefill old password
		pCPCE->SetFieldString(pCredential, FID_LARGE_TEXT, _config->credential.username.c_str());
		pCPCE->SetFieldString(pCredential, FID_LDAP_PASS, _config->credential.password.c_str());
	}
	else
	{
		const int hideFullName = _config->hideFullName;
		const int hideDomain = _config->hideDomainName;

		// Fill the textfields with text depending on configuration
		// Large text for username@domain, username or nothing
		// Small text for transaction message or default OTP message

		// Large text
		wstring text = _config->credential.username + L"@" + _config->credential.domain;
		if (hideDomain)
		{
			text = _config->credential.username;
		}
		if (hideFullName)
		{
			text = L"";
		}
		//DebugPrint(L"Setting large text: " + text);
		if (text.empty() || _config->credential.username.empty())
		{
			//pCPCE->SetFieldState(pCredential, FID_LARGE_TEXT, CPFS_HIDDEN);
			pCPCE->SetFieldString(pCredential, FID_LARGE_TEXT, _config->loginText.c_str());
			DebugPrint(L"Setting large text: " + _config->loginText);
		}
		else
		{
			pCPCE->SetFieldString(pCredential, FID_LARGE_TEXT, text.c_str());
			DebugPrint(L"Setting large text: " + text);
		}

		// Small text, use if 1step or in 2nd step of 2step
		if (!_config->twoStepHideOTP || (_config->twoStepHideOTP && _config->isSecondStep))
		{
			if (!_config->challenge.message.empty())
			{
				//DebugPrint(L"Setting message of challenge to small text: " + _config->challenge.message);
				pCPCE->SetFieldString(pCredential, FID_SMALL_TEXT, _config->challenge.message.c_str());
				pCPCE->SetFieldState(pCredential, FID_SMALL_TEXT, CPFS_DISPLAY_IN_BOTH);
			}
			else
			{
				pCPCE->SetFieldString(pCredential, FID_SMALL_TEXT, _config->defaultOTPHintText.c_str());
			}
		}
		else
		{
			pCPCE->SetFieldState(pCredential, FID_SMALL_TEXT, CPFS_HIDDEN);
		}
	}

	// Domain in FID_SUBTEXT, optional
	if (_config->showDomainHint)
	{
		wstring domaintext = GetTranslatedText(TEXT_DOMAIN_HINT) + _config->credential.domain;
		pCPCE->SetFieldString(pCredential, FID_SUBTEXT, domaintext.c_str());
	}
	else
	{
		pCPCE->SetFieldState(pCredential, FID_SUBTEXT, CPFS_HIDDEN);
	}

	// Display or not the "Receive an OTP by SMS" link
	if (readRegistryValueInteger(CONF_DISPLAY_SMS_LINK, 0)) {
		pCPCE->SetFieldState(pCredential, FID_REQUIRE_SMS, CPFS_DISPLAY_IN_SELECTED_TILE);
	}
	else {
		pCPCE->SetFieldState(pCredential, FID_REQUIRE_SMS, CPFS_HIDDEN);
	}

	return hr;
}

HRESULT Utilities::Clear(
	wchar_t* (&field_strings)[FID_NUM_FIELDS],
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[FID_NUM_FIELDS],
	ICredentialProviderCredential* pcpc,
	ICredentialProviderCredentialEvents* pcpce,
	char clear)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	for (unsigned int i = 0; i < FID_NUM_FIELDS && SUCCEEDED(hr); i++)
	{
		char do_something = 0;

		if ((pcpfd[i].cpft == CPFT_PASSWORD_TEXT && clear >= CLEAR_FIELDS_CRYPT) || (pcpfd[i].cpft == CPFT_EDIT_TEXT && clear >= CLEAR_FIELDS_EDIT_AND_CRYPT))
		{
			if (field_strings[i])
			{
				// CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
				const size_t len = lstrlen(field_strings[i]);
				SecureZeroMemory(field_strings[i], len * sizeof(*field_strings[i]));

				do_something = 1;
			}
		}

		if (do_something || clear >= CLEAR_FIELDS_ALL)
		{
			CoTaskMemFree(field_strings[i]);
			hr = SHStrDupW(L"", &field_strings[i]);

			if (pcpce)
			{
				pcpce->SetFieldString(pcpc, i, field_strings[i]);
			}
			if (clear == CLEAR_FIELDS_ALL_DESTROY)
			{
				CoTaskMemFree(pcpfd[i].pszLabel);
			}
		}
	}

	return hr;
}

HRESULT Utilities::SetFieldStatePairBatch(
	__in ICredentialProviderCredential* self,
	__in ICredentialProviderCredentialEvents* pCPCE,
	__in const FIELD_STATE_PAIR* pFSP)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	if (!pCPCE || !self)
	{
		return E_INVALIDARG;
	}

	for (unsigned int i = 0; i < FID_NUM_FIELDS && SUCCEEDED(hr); i++)
	{
		hr = pCPCE->SetFieldState(self, i, pFSP[i].cpfs);

		if (SUCCEEDED(hr))
		{
			hr = pCPCE->SetFieldInteractiveState(self, i, pFSP[i].cpfis);
		}
	}

	return hr;
}

// can be removed, SetScenario does the same
HRESULT Utilities::InitializeField(
	LPWSTR* rgFieldStrings,
	DWORD field_index)
{
	HRESULT hr = E_INVALIDARG;
	const int hide_fullname = _config->hideFullName;
	const int hide_domainname = _config->hideDomainName;

	wstring loginText = _config->loginText;
	wstring user_name = _config->credential.username;
	wstring domain_name = _config->credential.domain;

	switch (field_index)
	{
	case FID_NEW_PASS_1:
	case FID_NEW_PASS_2:
	case FID_LDAP_PASS:
	case FID_OTP:
	case FID_SUBMIT_BUTTON:
		hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		break;
	case FID_SUBTEXT:
	{
		wstring text = L"";
		if (_config->showDomainHint)
		{
			text = GetTranslatedText(TEXT_DOMAIN_HINT) + _config->credential.domain;;
		}
		hr = SHStrDupW(text.c_str(), &rgFieldStrings[field_index]);

		break;
	}
	case FID_USERNAME:
	{
		hr = SHStrDupW((user_name.empty() ? L"" : user_name.c_str()), &rgFieldStrings[field_index]);

		DebugPrint(L"Setting username: " + wstring(rgFieldStrings[field_index]));
		break;
	}
	case FID_LARGE_TEXT:
	{
		// This is the USERNAME field which is displayed in the list of users to the right
		if (!loginText.empty())
		{
			hr = SHStrDupW(loginText.c_str(), &rgFieldStrings[field_index]);
		}
		else
		{
			hr = SHStrDupW(L"privacyIDEA Login", &rgFieldStrings[field_index]);
		}
		DebugPrint(L"Setting large text: " + wstring(rgFieldStrings[field_index]));
		break;
	}
	case FID_SMALL_TEXT:
	{
		// In CPUS_UNLOCK_WORKSTATION the username is already provided, therefore the field is disabled
		// and the name is displayed in this field instead (or hidden)
		if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION && !user_name.empty()
			&& !hide_fullname && !hide_domainname)
		{
			if (!domain_name.empty())
			{
				wstring fullName = user_name + L"@" + domain_name;

				hr = SHStrDupW(fullName.c_str(), &rgFieldStrings[field_index]);
			}
			else if (!user_name.empty())
			{
				hr = SHStrDupW(user_name.c_str(), &rgFieldStrings[field_index]);
			}
			else
			{
				hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
			}
		}
		else if (!user_name.empty() && hide_domainname && !hide_fullname)
		{
			hr = SHStrDupW(user_name.c_str(), &rgFieldStrings[field_index]);
		}
		else if (hide_fullname)
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		}
		else
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		}
		DebugPrint(L"Setting small text: " + wstring(rgFieldStrings[field_index]));
		break;
	}
	case FID_LOGO:
		hr = S_OK;
		break;
	case FID_REQUIRE_SMS:
		hr = SHStrDupW(L"Receive an OTP by SMS", &rgFieldStrings[field_index]);
		break;
	default:
		hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		break;
	}
	//DebugPrintLn(rgFieldStrings[field_index]);
	return hr;
}

HRESULT Utilities::ReadFieldValues()
{
	DebugPrint(__FUNCTION__);
	//HRESULT ret = S_OK;
	switch (_config->provider.cpu)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
	{
		if (!_config->credential.passwordMustChange)
		{
			ReadUserField();
			ReadPasswordField();
			ReadOTPField();
		}
		else
		{
			ReadPasswordChangeFields();
		}
		break;
	}

	}
	return S_OK;
}

HRESULT Utilities::ReadPasswordChangeFields()
{
	_config->credential.password = _config->provider.field_strings[FID_LDAP_PASS];
	DebugPrint(L"Old pw: " + _config->credential.password);
	_config->credential.newPassword1 = _config->provider.field_strings[FID_NEW_PASS_1];
	DebugPrint(L"new pw1: " + _config->credential.newPassword1);
	_config->credential.newPassword2 = _config->provider.field_strings[FID_NEW_PASS_2];
	DebugPrint(L"New pw2: " + _config->credential.newPassword2);
	return S_OK;
}

HRESULT Utilities::ReadUserField()
{
	if (_config->provider.cpu != CPUS_UNLOCK_WORKSTATION)
	{
		wstring input(_config->provider.field_strings[FID_USERNAME]);
		DebugPrint(L"Loading user/domain from GUI, raw: '" + input + L"'");
		wstring user_name, domain_name;

		auto const pos = input.find_first_of(L"\\", 0);
		if (pos == std::string::npos)
		{
			// only user input, copy string
			user_name = wstring(input);
		}
		else
		{
			// Actually split DOMAIN\USER
			user_name = wstring(input.substr(pos + 1, input.size()));
			domain_name = wstring(input.substr(0, pos));
		}

		if (!user_name.empty())
		{
			wstring newUsername(user_name);
			DebugPrint(L"Changing user from '" + _config->credential.username + L"' to '" + newUsername + L"'");
			_config->credential.username = newUsername;
		}
		else
		{
			DebugPrint(L"Username is empty, keeping old value: '" + _config->credential.username + L"'");
		}

		if (!domain_name.empty())
		{
			wstring newDomain(domain_name);
			DebugPrint(L"Changing domain from '" + _config->credential.domain + L"' to '" + newDomain + L"'");
			_config->credential.domain = newDomain;
		}
		else
		{
			DebugPrint(L"Domain is empty, keeping old value: '" + _config->credential.domain + L"'");
		}
	}

	return S_OK;
}

HRESULT Utilities::ReadPasswordField()
{
	SecureWString newPassword(_config->provider.field_strings[FID_LDAP_PASS]);

	if (newPassword.empty())
	{
		DebugPrint("New password empty, keeping old value");
	}
	else
	{
		_config->credential.password = newPassword;
		DebugPrint(L"Loading password from GUI, value:");
		if (_config->piconfig.logPasswords)
		{
			DebugPrint(newPassword.c_str());
		}
		else
		{
			if (newPassword.empty())
			{
				DebugPrint("[Hidden] empty value");
			}
			else
			{
				DebugPrint("[Hidden] has value");
			}
		}

	}
	return S_OK;
}

HRESULT Utilities::ReadOTPField()
{
	wstring newOTP(_config->provider.field_strings[FID_OTP]);
	DebugPrint(L"Loading OTP from GUI, from '" + _config->credential.otp + L"' to '" + newOTP + L"'");
	_config->credential.otp = newOTP;

	return S_OK;
}

const FIELD_STATE_PAIR* Utilities::GetFieldStatePairFor(
	CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	bool twoStepHideOTP)
{
	if (cpus == CPUS_UNLOCK_WORKSTATION)
	{
		return twoStepHideOTP ? s_rgScenarioUnlockFirstStepPassword : s_rgScenarioUnlockPasswordOTP;
	}
	else
	{
		return twoStepHideOTP ? s_rgScenarioLogonFirstStepUserLDAP : s_rgScenarioDisplayAllFields;
	}
}

HRESULT Utilities::ResetScenario(
	ICredentialProviderCredential* pSelf,
	ICredentialProviderCredentialEvents* pCredProvCredentialEvents)
{
	DebugPrint(__FUNCTION__);
	// 2 step progress is reset aswell, therefore put the submit button next to the password field again
	_config->isSecondStep = false;
	_config->provider.pCredProvCredentialEvents->SetFieldSubmitButton(
		_config->provider.pCredProvCredential, FID_SUBMIT_BUTTON, FID_LDAP_PASS);

	if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
	{
		if (_config->twoStepHideOTP)
		{
			SetScenario(pSelf, pCredProvCredentialEvents,
				SCENARIO::UNLOCK_TWO_STEP);
		}
		else
		{
			SetScenario(pSelf, pCredProvCredentialEvents,
				SCENARIO::UNLOCK_BASE);
		}
	}
	else if (_config->provider.cpu == CPUS_LOGON)
	{
		if (_config->twoStepHideOTP)
		{
			SetScenario(pSelf, pCredProvCredentialEvents, SCENARIO::LOGON_TWO_STEP);
		}
		else
		{
			SetScenario(pSelf, pCredProvCredentialEvents, SCENARIO::LOGON_BASE);
		}
	}

	return S_OK;
}
