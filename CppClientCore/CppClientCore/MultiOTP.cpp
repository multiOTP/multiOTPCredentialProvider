/**
 * multiOTP Credential Provider, extends privacyIdea
 *
 * @author    Yann Jeanrenaud, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.10.0.1
 * @date      2025-10-28
 * @since     2021
 * @copyright (c) 2016-2025 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *	 2025-10-22 5.9.9.4 SysCo/yj ENH: Tranforming isWithout2FA in userTokenType in order to manage push token.
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

HRESULT MultiOTP::validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id, HRESULT& error_code, const std::wstring& usersid)
{
	HRESULT hr = E_UNEXPECTED;

	hr = multiotp_request(getCleanUsername(username, domain), L"", otp, usersid);
    error_code = hr;
	// Gérer le prev OTP
	if ((hr == MULTIOTP_SUCCESS)) {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::multiOTP Success, value  %d", hr);//OTP ok
		return PI_AUTH_SUCCESS;
	}
	else {
		if (DEVELOP_MODE) PrintLn("MultiotpCredential::multiOTP Error, value  %d", hr);//OTP ok
		return PI_AUTH_FAILURE;
	}
}

/**
Return user token type :
	6: push token
	7: with token
	8: without2FA
	21: User doesn't exists
	38: User disabled
	81: Cache too old
	99: error
*/
HRESULT MultiOTP::userTokenType(const std::wstring& username, const std::wstring& domain, const std::wstring& usersid)
{
	HRESULT hr = E_UNEXPECTED;
	hr = multiotp_request_command(L"-iswithout2fa", L"\""+getCleanUsername(username, domain)+ L"\"", usersid);
	if (DEVELOP_MODE) {
		if (hr == MULTIOTP_IS_WITHOUT2FA) {
			PrintLn("MultiotpCredential::multiOTP user is without2FA", hr);
		}
		else if (hr == MULTIOTP_IS_PUSH_TOKEN) {
			PrintLn("MultiotpCredential::multiOTP user is push token", hr);
		}
		else {
			PrintLn("MultiotpCredential::multiOTP user is not without2fa, nor push token ", hr);
		}
	}

	return hr;
}
