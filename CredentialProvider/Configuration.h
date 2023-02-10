/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
** Author: Nils Behlen
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
** * * * * * * * * * * * * * * * * * * */

#pragma once
#include "PIConf.h"
#include "Challenge.h"
#include "SecureString.h"
#include <string>
#include <credentialprovider.h>

class Configuration
{
public:

	static const std::wstring registryPath;// = L"SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP\\";
	static const std::wstring registryRealmPath;// = registryPath + L"realm-mapping";

	Configuration();

	void printConfiguration();

	PICONFIG piconfig;

	std::wstring loginText = L"";
	std::wstring otpFieldText = L"";
	std::wstring bitmapPath = L"";

	bool twoStepHideOTP = false;
	bool twoStepSendPassword = false;
	bool twoStepSendEmptyPassword = false;
	bool isSecondStep = false;

	bool hideFullName = false;
	bool hideDomainName = false;

	bool showDomainHint = false;

	bool releaseLog = false;

	bool noDefault = false;

	int hide_otp_sleep_s = 0;

	int winVerMajor = 0;
	int winVerMinor = 0;
	int winBuildNr = 0;

	bool pushAuthenticationSuccessful = false;

	bool isRemoteSession = false;

	bool doAutoLogon = false;

	bool userCanceled = false;

	Challenge challenge;
	std::wstring defaultOTPFailureText = L"";
	std::wstring defaultOTPHintText = L"";

	std::wstring excludedAccount = L"";

	bool clearFields = true;
	bool bypassPrivacyIDEA = false;

	int numberOfLockedUser = 0;
	ICredentialProviderUserArray* lockedUsers = nullptr;


	struct PROVIDER
	{
		ICredentialProviderEvents* pCredentialProviderEvents = nullptr;
		UINT_PTR upAdviseContext = 0;

		CREDENTIAL_PROVIDER_USAGE_SCENARIO cpu = CPUS_INVALID;
		DWORD credPackFlags = 0;

		// Possibly read-write
		CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr = nullptr;
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs = nullptr;
		PWSTR* status_text = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON* status_icon = nullptr;
		ICredentialProviderCredentialEvents* pCredProvCredentialEvents = nullptr;

		// Read-only
		ICredentialProviderCredential* pCredProvCredential = nullptr;
		wchar_t** field_strings = nullptr;
	} provider;

	struct CREDENTIAL
	{
		std::wstring username = L"";
		std::wstring domain = L"";
		SecureWString password = L"";
		std::wstring otp = L"";

		bool passwordMustChange = false;
		bool passwordChanged = false;

		// ChangePassword
		SecureWString newPassword1 = L"";
		SecureWString newPassword2 = L"";
	} credential;
};
