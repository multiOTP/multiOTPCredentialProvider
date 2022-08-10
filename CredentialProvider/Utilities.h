#pragma once
#include "MultiOTPConfiguration.h"
#include "Logger.h"
#include <scenario.h>
#include <memory>
#include <Windows.h>
#include <wincred.h>

#define CLEAR_FIELDS_CRYPT 0
#define CLEAR_FIELDS_EDIT_AND_CRYPT 1
#define CLEAR_FIELDS_ALL 2
#define CLEAR_FIELDS_ALL_DESTROY 3

#define MAX_SIZE_DOMAIN 64
#define MAX_SIZE_USERNAME 512

enum class SCENARIO
{
	NO_CHANGE = 0,
	LOGON_BASE = 1,
	UNLOCK_BASE = 2,
	SECOND_STEP = 3,
	LOGON_TWO_STEP = 4,
	UNLOCK_TWO_STEP = 5,
	CHANGE_PASSWORD = 6,
};

class Utilities
{
public:
	Utilities(std::shared_ptr<MultiOTPConfiguration> c) noexcept;

	// Returns the text for the id in english or german, depending on GetUserDefaultUILanguage
	static std::wstring GetTranslatedText(int id);

	HRESULT KerberosLogon(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in SecureWString password,
		__in std::wstring domain
	);

	HRESULT KerberosChangePassword(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
		__in std::wstring username,
		__in SecureWString password_old,
		__in SecureWString password_new,
		__in std::wstring domain
	);

	HRESULT CredPackAuthentication(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in SecureWString password,
		__in std::wstring domain
	);

	// Set all fields state depending on the scenario, then fill the fields depending on scenario and configuration
	HRESULT SetScenario(
		__in ICredentialProviderCredential* pCredential,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in SCENARIO scenario
	);

	HRESULT Clear(
		wchar_t* (&field_strings)[FID_NUM_FIELDS],
		CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[FID_NUM_FIELDS],
		ICredentialProviderCredential* pcpc,
		ICredentialProviderCredentialEvents* pcpce,
		char clear
	);

	HRESULT SetFieldStatePairBatch(
		__in ICredentialProviderCredential* self,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in const FIELD_STATE_PAIR* pFSP
	);

	HRESULT InitializeField(
		LPWSTR* rgFieldStrings,
		DWORD field_index
	);
	
	HRESULT ReadFieldValues();

	static const FIELD_STATE_PAIR* GetFieldStatePairFor(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, bool twoStepHideOTP);

	HRESULT ResetScenario(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents);

private:
	std::shared_ptr<MultiOTPConfiguration> _config;

	HRESULT ReadUserField();

	HRESULT ReadPasswordField();

	HRESULT ReadOTPField();

	HRESULT ReadPasswordChangeFields();

#define TEXT_USERNAME 0
#define TEXT_PASSWORD 1
#define TEXT_OLD_PASSWORD 2
#define TEXT_NEW_PASSWORD 3
#define TEXT_CONFIRM_PASSWORD 4
#define TEXT_DOMAIN_HINT 5
#define TEXT_OTP 6
#define TEXT_WRONG_OTP 7
#define TEXT_WRONG_PASSWORD 8
#define TEXT_DEFAULT_OTP_HINT 9

	const static std::wstring texts[10][2];
};

