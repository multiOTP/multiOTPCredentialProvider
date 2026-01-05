/**
 * multiOTP Credential Provider, extends privacyIdea
 *
 * @author    Yann Jeanrenaud, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.10.1.2
 * @date      2026-01-05
 * @since     2021
 * @copyright (c) 2016-2026 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *	 2025-10-22 5.9.9.4 SysCo/yj  ENH: Tranforming isWithout2FA in userTokenType in order to manage push token.
 *   2021-03-24 1.0.0.0 SysCo/yj New implementation from scratch
 *
 *********************************************************************/
#pragma once
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
#include "PrivacyIDEA.h"

class MultiOTP : public PrivacyIDEA {
	
public:
	MultiOTP(PICONFIG conf);

	// Tries to verify with offline otp first. If there is none,
	// sends the parameters to privacyIDEA and checks the response for
	// 1. Offline otp data, 2. Triggered challenges, 3. Authentication success
	// <returns> PI_AUTH_SUCCESS, PI_TRIGGERED_CHALLENGE, PI_AUTH_FAILURE, PI_AUTH_ERROR, PI_ENDPOINT_SETUP_ERROR, PI_WRONG_OFFLINE_SERVER_UNAVAILABLE </returns>
	HRESULT validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id, HRESULT& error_code, const std::wstring& usersid);
	HRESULT MultiOTP::userTokenType(const std::wstring& username, const std::wstring& domain, const std::wstring& usersid);

private:

};