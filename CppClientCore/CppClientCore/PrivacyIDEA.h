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

#define PI_ENDPOINT_VALIDATE_CHECK					"/validate/check"
#define PI_ENDPOINT_POLL_TX							"/validate/polltransaction"
#define PI_ENDPOINT_OFFLINE_REFILL					"/validate/offlinerefill"

class PrivacyIDEA
{
public:
	PrivacyIDEA(PICONFIG conf) :
		_realmMap(conf.realmMap),
		_defaultRealm(conf.defaultRealm),
		_logPasswords(conf.logPasswords),
		_endpoint(conf),
		_offlineHandler(conf.offlineFilePath, conf.offlineTryWindow),
		_lastError(0)
	{};

	PrivacyIDEA& operator=(const PrivacyIDEA& privacyIDEA) = delete;

	// Tries to verify with offline otp first. If there is none,
	// sends the parameters to privacyIDEA and checks the response for
	// 1. Offline otp data, 2. Triggered challenges, 3. Authentication success
	// <returns> PI_AUTH_SUCCESS, PI_TRIGGERED_CHALLENGE, PI_AUTH_FAILURE, PI_AUTH_ERROR, PI_ENDPOINT_SETUP_ERROR, PI_WRONG_OFFLINE_SERVER_UNAVAILABLE </returns>
	HRESULT validateCheck(const std::wstring& username, const std::wstring& domain, const SecureWString& otp, const std::string& transaction_id = std::string());

	bool stopPoll();

	// Poll for the given transaction asynchronously. When polling returns success, the transaction is finalized
	// according to https://privacyidea.readthedocs.io/en/latest/configuration/authentication_modes.html#outofband-mode
	// After that, the callback function is called with the result
	void asyncPollTransaction(std::string username, std::string transaction_id, std::function<void(bool)> callback);

	// Poll for a transaction once. Can be used if the plugin wants to control the looping
	// <returns> PI_TRANSACTION_SUCCESS or PI_TRANSACTION_FAILURE </returns>
	HRESULT pollTransaction(std::string transaction_id);

	bool isOfflineDataAvailable(const std::wstring& username);

	Challenge getCurrentChallenge();

	static std::wstring s2ws(const std::string& s);

	static std::string ws2s(const std::wstring& ws);

	static SecureString sws2ss(const SecureWString& sws);

	static SecureWString ss2sws(const SecureString& ss);

	static std::wstring toUpperCase(std::wstring s);

	static std::string longToHexString(long in);

	int getLastError();

	std::wstring getLastErrorMessage();

private:
	HRESULT appendRealm(std::wstring domain, SecureString& data);

	void pollThread(const std::string& transaction_id, const std::string& username, std::function<void(bool)> callback);

	HRESULT tryOfflineRefill(std::string username, SecureString lastOTP);

	std::map<std::wstring, std::wstring> _realmMap;

	std::wstring _defaultRealm = L"";

	Endpoint _endpoint;
	OfflineHandler _offlineHandler;

	Challenge _currentChallenge;

	bool _logPasswords = false;

	std::atomic<bool> _runPoll = false;

	int _lastError = 0;
	std::string _lastErrorMessage;
};

