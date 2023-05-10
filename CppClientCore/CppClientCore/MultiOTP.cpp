/**
 * multiOTP Credential Provider, extends privacyIdea
 *
 * @author    Yann Jeanrenaud, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.9.6.1
 * @date      2023-05-10
 * @since     2021
 * @copyright (c) 2016-2023 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2021-03-24 1.0.0.0 SysCo/yj New implementation from scratch
 *
 *********************************************************************/
#include "MultiotpHelpers.h"
#include "MultiOTP.h"
#include "OfflineHandler.h"
#include "Logger.h"
#include "Endpoint.h"
#include "PIConf.h"
#include "Codes.h"
#include "SecureString.h"
#include <Windows.h>
#include <string>
#include <map>
#include <functional>
#include <atomic>
#include "MultiotpRegistry.h"

using namespace std;

MultiOTP::MultiOTP(PICONFIG conf):PrivacyIDEA(conf)
{
}

HRESULT MultiOTP::validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id)
{
	HRESULT hr = E_UNEXPECTED;

	hr = multiotp_request(getCleanUsername(username, domain), L"", otp);

	// Gérer le prev OTP

	if ((hr == MULTIOTP_SUCCESS)) {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::multiOTP Success, value ", hr);//OTP ok
		return PI_AUTH_SUCCESS;
	}
	else {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::multiOTP Error, value ", hr);//OTP ok
		return PI_AUTH_FAILURE;
	}
}

bool MultiOTP::isWithout2FA(const std::wstring& username, const std::wstring& domain)
{
	HRESULT hr = E_UNEXPECTED;
	hr = multiotp_request_command(L"-iswithout2fa", L"\""+getCleanUsername(username, domain)+ L"\"");
	if ((hr == MULTIOTP_IS_WITHOUT2FA)) {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::multiOTP user is without2FA", hr);
		return true;
	}
	else {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::multiOTP user is not without2fa ", hr);
	}
	return false;
}
