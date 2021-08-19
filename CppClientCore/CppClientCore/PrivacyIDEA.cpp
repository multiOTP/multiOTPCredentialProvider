#include "PrivacyIDEA.h"
#include "Challenge.h"
#include <codecvt>
#include <thread>
#include <sstream>

using namespace std;

// Check if there is a mapping for the given domain or - if not - a default realm is set
HRESULT PrivacyIDEA::appendRealm(std::wstring domain, SecureString& data)
{
	wstring realm = L"";
	try
	{
		realm = _realmMap.at(toUpperCase(domain));
	}
	catch (const std::out_of_range& e)
	{
		UNREFERENCED_PARAMETER(e);
		// no mapping - if default domain exists use that
		if (!_defaultRealm.empty())
		{
			realm = _defaultRealm;
		}
	}

	if (!realm.empty())
	{
		data += "&" + _endpoint.encodePair("realm", ws2s(realm));
	}

	return S_OK;
}

void PrivacyIDEA::pollThread(
	const std::string& transaction_id,
	const std::string& username,
	std::function<void(bool)> callback)
{
	DebugPrint("Starting poll thread...");
	HRESULT res = E_FAIL;
	bool success = false;
	SecureString data = _endpoint.encodePair("transaction_id", transaction_id);
	while (_runPoll.load())
	{
		string response = _endpoint.connect(PI_ENDPOINT_POLL_TX, data, RequestMethod::GET);
		res = _endpoint.parseForTransactionSuccess(response);
		if (res == PI_TRANSACTION_SUCCESS)
		{
			success = true;
			_runPoll.store(false);
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(500));
	}
	DebugPrint("Polling stopped");
	if (success)
	{
		try
		{
			DebugPrint("Finalizing transaction...");
			HRESULT result = _endpoint.finalizePolling(username, transaction_id);
			callback((result == PI_AUTH_SUCCESS));
		}
		catch (const std::out_of_range& e)
		{
			UNREFERENCED_PARAMETER(e);
			DebugPrint("Could not get transaction id to finialize");
			callback(false);
		}
	}
}

HRESULT PrivacyIDEA::tryOfflineRefill(std::string username, SecureString lastOTP)
{
	SecureString data = _endpoint.encodePair("pass", lastOTP);
	string refilltoken, serial;
	HRESULT hr = _offlineHandler.getRefillTokenAndSerial(username, refilltoken, serial);
	if (hr != S_OK)
	{
		DebugPrint("Failed to get parameters for offline refill!");
		return E_FAIL;
	}

	data += "&" + _endpoint.encodePair("refilltoken", refilltoken)
		+ "&" + _endpoint.encodePair("serial", serial);
	string response = _endpoint.connect(PI_ENDPOINT_OFFLINE_REFILL, data, RequestMethod::POST);

	if (response.empty())
	{
		DebugPrint("Offline refill response was empty");
		return E_FAIL;
	}

	HRESULT res = _offlineHandler.parseRefillResponse(response, username);

	return res;
}

HRESULT PrivacyIDEA::validateCheck(const std::wstring& username, const std::wstring& domain,
	const SecureWString& otp, const std::string& transaction_id)
{
	DebugPrint(__FUNCTION__);
	HRESULT piStatus = E_FAIL;
	HRESULT ret = PI_AUTH_FAILURE;
	HRESULT offlineStatus = E_FAIL;

	string strUsername = ws2s(username);

	// Check if offline otp available
	if (_offlineHandler.isDataVailable(strUsername) == S_OK)
	{
		DebugPrint("Offline data available");
		offlineStatus = _offlineHandler.verifyOfflineOTP(otp, strUsername);
		if (offlineStatus == S_OK)
		{
			// try refill then return
			DebugPrint("Offline authentication successful");
			offlineStatus = tryOfflineRefill(strUsername, sws2ss(otp));
			if (offlineStatus != S_OK)
			{
				ReleaseDebugPrint("Offline refill failed: " + longToHexString(offlineStatus));
			}
			return PI_AUTH_SUCCESS;	// Still return SUCCESS because offline authentication was successful
		}
		else
		{
			// Continue with other steps
			offlineStatus = PI_OFFLINE_WRONG_OTP;
			ReleaseDebugPrint("Offline data was available, but authenticiation failed");
		}
	}
	else if (offlineStatus == PI_OFFLINE_DATA_NO_OTPS_LEFT)
	{
		DebugPrint("No offline OTPs left for the user.");
	}

	// Connect to the privacyIDEA Server
	SecureString data = _endpoint.encodePair("user", ws2s(username)) + "&" + _endpoint.encodePair("pass", otp);

	if (!transaction_id.empty())
	{
		data += "&" + _endpoint.encodePair("transaction_id", transaction_id);
	}

	appendRealm(domain, data);

	string response = _endpoint.connect(PI_ENDPOINT_VALIDATE_CHECK, data, RequestMethod::POST);

	// If the response is empty, there was an error in the endpoint
	if (response.empty())
	{
		HRESULT epCode = _endpoint.getLastErrorCode();
		DebugPrint("Response was empty. Endpoint error: " + longToHexString(epCode));
		// If offline was available, give the hint that the entered OTP might be wrong
		if (offlineStatus == PI_OFFLINE_WRONG_OTP && epCode == PI_ENDPOINT_SERVER_UNAVAILABLE)
		{
			return PI_WRONG_OFFLINE_SERVER_UNAVAILABLE;
		}

		// otherwise return PI_ENDPOINT_SERVER_UNAVAILABLE or PI_ENDPOINT_SETUP_ERROR
		return epCode;
	}

	// Check if the response contains an error, message and code will be set
	if (_endpoint.parseForError(response, _lastErrorMessage, _lastError) == PI_JSON_ERROR_CONTAINED)
	{
		return PI_AUTH_ERROR;
	}

	// Check for initial offline OTP data
	piStatus = _offlineHandler.parseForOfflineData(response);
	if (piStatus == S_OK) // Data was found
	{
		// Continue
	}
	else if (piStatus == PI_OFFLINE_NO_OFFLINE_DATA)
	{
		// Continue
	}
	else
	{
		// ERROR
	}
	// Check for triggered challenge response transactions
	Challenge c;
	piStatus = _endpoint.parseTriggerRequest(response, c);
	if (piStatus == PI_TRIGGERED_CHALLENGE)
	{
		// Check the challenge data 
		if (c.serial.empty() || c.transaction_id.empty() || c.tta == TTA::NOT_SET)
		{
			DebugPrint("Incomplete challenge data: " + c.toString());
			ret = PI_AUTH_FAILURE;
		}
		else
		{
			_currentChallenge = c;
			ret = PI_TRIGGERED_CHALLENGE;
		}
	} // else if (res == PI_NO_CHALLENGE) {}

	// Check for normal success
	piStatus = _endpoint.parseAuthenticationRequest(response);
	if (piStatus == PI_AUTH_SUCCESS)
	{
		ret = PI_AUTH_SUCCESS;
	}
	else
	{
		// If a challenge was triggered, parsing for authentication fails, so check here if a challenge was triggered
		if (ret != PI_TRIGGERED_CHALLENGE)
		{
			if (piStatus == PI_JSON_ERROR_CONTAINED)
			{
				ret = PI_AUTH_ERROR;
			}
			else if (piStatus == PI_AUTH_FAILURE)
			{
				ret = PI_AUTH_FAILURE;
			}
		}
	}

	return ret;
}

bool PrivacyIDEA::stopPoll()
{
	DebugPrint("Stopping poll thread...");
	_runPoll.store(false);
	return true;
}

void PrivacyIDEA::asyncPollTransaction(std::string username, std::string transaction_id, std::function<void(bool)> callback)
{
	_runPoll.store(true);
	std::thread t(&PrivacyIDEA::pollThread, this, transaction_id, username, callback);
	t.detach();
}

HRESULT PrivacyIDEA::pollTransaction(std::string transaction_id)
{
	return _endpoint.pollForTransaction(_endpoint.encodePair("transaction_id", transaction_id));
}

bool PrivacyIDEA::isOfflineDataAvailable(const std::wstring& username)
{
	return _offlineHandler.isDataVailable(ws2s(username)) == S_OK;
}

Challenge PrivacyIDEA::getCurrentChallenge()
{
	return _currentChallenge;
}

std::wstring PrivacyIDEA::s2ws(const std::string& s)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(s);
}

std::string PrivacyIDEA::ws2s(const std::wstring& ws)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(ws);
}

SecureString PrivacyIDEA::sws2ss(const SecureWString& sws)
{
	size_t outSize = 0;
	size_t size = sws.size() + 1;
	char* outBuf = new char[size];

	wcstombs_s(&outSize, outBuf, size, sws.c_str(), (size - 1));

	SecureString ret;
	if (outSize > 0)
	{
		ret = SecureString(outBuf);
	}
	else
	{
		ret = SecureString();
	}
	SecureZeroMemory(outBuf, size);
	delete[] outBuf;

	return ret;
}

SecureWString PrivacyIDEA::ss2sws(const SecureString& ss)
{
	size_t outSize = 0;
	size_t size = ss.size() + 1;
	wchar_t* outBuf = new wchar_t[size];

	mbstowcs_s(&outSize, outBuf, size, ss.c_str(), (size - 1));

	SecureWString ret;
	if (outSize > 0)
	{
		ret = SecureWString(outBuf);
	}
	else
	{
		ret = SecureWString();
	}
	SecureZeroMemory(outBuf, size);
	delete[] outBuf;

	return ret;
}

std::wstring PrivacyIDEA::toUpperCase(std::wstring s)
{
	std::transform(s.begin(), s.end(), s.begin(), ::toupper);
	return s;
}

std::string PrivacyIDEA::longToHexString(long in)
{
	std::stringstream ss;
	ss << "0x" << std::hex << in;
	return std::string(ss.str());
}

int PrivacyIDEA::getLastError()
{
	return _lastError;
}

std::wstring PrivacyIDEA::getLastErrorMessage()
{
	return s2ws(_lastErrorMessage);
}
