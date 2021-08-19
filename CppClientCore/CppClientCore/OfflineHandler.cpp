/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2019 NetKnights GmbH
** Author:		Nils Behlen
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

#include "OfflineHandler.h"
#include "Codes.h"
#include "Endpoint.h" // tryParseJSON
#include <iostream>
#include <fstream>
#include <atlenc.h>

#pragma comment (lib, "bcrypt.lib")

using namespace std;
using json = nlohmann::json;

std::wstring getErrorText(DWORD err)
{
	LPWSTR msgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&msgBuf,
		0, NULL);
	return (msgBuf == nullptr) ? wstring() : wstring(msgBuf);
}

OfflineHandler::OfflineHandler(const wstring& filePath, int tryWindow)
{
	// Load the offline file on startup
	_filePath = filePath.empty() ? _filePath : filePath;
	_tryWindow = tryWindow == 0 ? _tryWindow : tryWindow;
	const HRESULT res = loadFromFile();
	if (res != S_OK)
	{
		DebugPrint(L"Unable to load offline file: " + to_wstring(res) + L": " + getErrorText(res));
	}
	else
	{
		DebugPrint("Offline data loaded successfully!");
	}
}

OfflineHandler::~OfflineHandler()
{
	if (!dataSets.empty())
	{
		const HRESULT res = saveToFile();
		if (res != S_OK)
		{
			DebugPrint(L"Unable to save offline file: " + to_wstring(res) + L": " + getErrorText(res));
		}
		else
		{
			DebugPrint("Offline data saved successfully!");
		}
	}
}

HRESULT OfflineHandler::verifyOfflineOTP(const SecureWString& otp, const string& username)
{
	HRESULT success = E_FAIL;

	for (auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			const int lowestKey = item.getLowestKey();
			int matchingKey = lowestKey;

			for (int i = lowestKey; i < (lowestKey + _tryWindow); i++)
			{
				try
				{
					string storedValue = item.offlineOTPs.at(to_string(i));
					if (pbkdf2_sha512_verify(otp, storedValue))
					{
						matchingKey = i;
						success = S_OK;
						break;
					}
				}
				catch (const std::out_of_range& e)
				{
					UNREFERENCED_PARAMETER(e);
					// TODO handle missing offline otps -> ignore
				}
			}

			if (success == S_OK)
			{
				if (matchingKey >= lowestKey) // Also include if the matching is the first
				{
					cout << "difference: " << (matchingKey - lowestKey) << endl;
					for (int i = lowestKey; i <= matchingKey; i++)
					{
						item.offlineOTPs.erase(to_string(i));
					}
				}
			}
		}
	}

	return success;
}

HRESULT OfflineHandler::getRefillTokenAndSerial(const std::string& username, std::string& refilltoken, std::string& serial)
{
	if (dataSets.empty()) return PI_OFFLINE_NO_OFFLINE_DATA;

	for (const auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			string iserial(item.serial);
			string irefilltoken(item.refilltoken);
			if (iserial.empty() || irefilltoken.empty()) return PI_OFFLINE_NO_OFFLINE_DATA;
			refilltoken = irefilltoken;
			serial = iserial;
			return S_OK;
		}
	}

	return PI_OFFLINE_DATA_USER_NOT_FOUND;
}

// Check an authentication reponse from privacyIDEA if it contains the inital data for offline
HRESULT OfflineHandler::parseForOfflineData(const std::string& in)
{
	DebugPrint(__FUNCTION__);
	auto j = Endpoint::tryParseJSON(in);
	if (j == nullptr) return PI_JSON_PARSE_ERROR;

	auto jAuth_items = j["auth_items"];
	if (jAuth_items == nullptr) return PI_OFFLINE_NO_OFFLINE_DATA;

	// Get the serial to add to the data
	auto jSerial = j["detail"]["serial"];
	if (!jSerial.is_string()) return PI_JSON_FORMAT_ERROR;
	string serial = jSerial.get<std::string>();

	auto jOffline = jAuth_items["offline"];

	if (!jOffline.is_array()) return PI_JSON_FORMAT_ERROR;
	if (jOffline.size() < 1) return PI_OFFLINE_NO_OFFLINE_DATA;

	for (const auto& item : jOffline)
	{
		// Build the object
		OfflineData toAdd(item.dump());
		toAdd.serial = serial;

		// Check if the user already has data first, then add
		bool done = false;
		for (auto& existing : dataSets)
		{
			if (existing.user == toAdd.user || existing.username == toAdd.username)
			{
				//DebugPrint("found exsisting user data.");
				existing.refilltoken = toAdd.refilltoken;

				for (const auto& newOTP : toAdd.offlineOTPs)
				{
					existing.offlineOTPs.try_emplace(newOTP.first, newOTP.second);
				}
				done = true;
			}
		}

		if (!done)
		{
			dataSets.push_back(toAdd);
			//DebugPrint("did not find exsisting user data, adding new");
		}
	}
	return S_OK;
}

HRESULT OfflineHandler::parseRefillResponse(const std::string& in, const std::string& username)
{
	DebugPrint(__FUNCTION__);
	auto jIn = Endpoint::tryParseJSON(in);
	if (jIn == nullptr) return PI_JSON_PARSE_ERROR;
	// Set the new refill token
	json offline;
	try
	{
		offline = jIn["auth_items"]["offline"].at(0);
	}
	catch (const std::exception& e)
	{
		DebugPrint(e.what());
		return PI_JSON_FORMAT_ERROR;
	}

	if (offline == nullptr) return PI_JSON_FORMAT_ERROR;

	for (auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			// still adding the values we got
			if (offline["refilltoken"].is_string())
			{
				item.refilltoken = offline["refilltoken"].get<std::string>();
			}
			else
			{
				item.refilltoken = "";
			}

			auto jResponse = offline["response"];
			for (const auto& jItem : jResponse.items())
			{
				string key = jItem.key();
				string value = jItem.value();
				item.offlineOTPs.try_emplace(key, value);
			}
			return S_OK;
		}
	}

	return E_FAIL;
}

HRESULT OfflineHandler::isDataVailable(const std::string& username)
{
	// Check is usable data available for the given username
	for (auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			return (item.offlineOTPs.empty() ? PI_OFFLINE_DATA_NO_OTPS_LEFT : S_OK);
		}
	}

	return PI_OFFLINE_DATA_USER_NOT_FOUND;
}

HRESULT OfflineHandler::saveToFile()
{
	ofstream o;
	o.open(_filePath, ios_base::out); // Destroy contents | create new

	if (!o.is_open()) return GetLastError();

	json::array_t jArr;

	for (auto& item : dataSets)
	{
		jArr.push_back(item.toJSON());
	}

	json j;
	j["offline"] = jArr;

	o << j.dump(4);
	o.close();
	return S_OK;
}

HRESULT OfflineHandler::loadFromFile()
{
	// Check for the file, load if exists
	string fileContent = "";
	string line;
	ifstream ifs(_filePath);

	if (!ifs.good()) return GetLastError();

	if (ifs.is_open())
	{
		while (getline(ifs, line))
		{
			fileContent += line;
		}
		ifs.close();
	}

	if (fileContent.empty()) return PI_OFFLINE_FILE_EMPTY;

	try
	{
		auto j = json::parse(fileContent);

		auto jOffline = j["offline"];

		if (jOffline.is_array())
		{
			for (auto const& item : jOffline)
			{
				OfflineData d(item.dump());
				dataSets.push_back(d);
			}
		}
	}
	catch (const json::parse_error& e)
	{
		DebugPrint(e.what());
		return PI_JSON_PARSE_ERROR;
	}

	return S_OK;
}

// Returns the outer right value of the passlib format and cuts it off the input string including the $
std::string OfflineHandler::getNextValue(std::string& in)
{
	string tmp = in.substr(in.find_last_of('$') + 1);
	in = in.substr(0, in.find_last_of('$'));
	return tmp;
}

char* OfflineHandler::UnicodeToCodePage(int codePage, const wchar_t* src)
{
	if (!src) return 0;
	int srcLen = (int)wcslen(src);
	if (!srcLen)
	{
		char* x = new char[1];
		x[0] = '\0';
		return x;
	}

	int requiredSize = WideCharToMultiByte(codePage,
		0,
		src, srcLen, 0, 0, 0, 0);

	if (!requiredSize)
	{
		return 0;
	}

	char* x = new char[(LONGLONG)requiredSize + 1];
	x[requiredSize] = 0;

	int retval = WideCharToMultiByte(codePage,
		0,
		src, srcLen, x, requiredSize, 0, 0);
	if (!retval)
	{
		delete[] x;
		return nullptr;
	}

	return x;
}

bool OfflineHandler::pbkdf2_sha512_verify(SecureWString password, std::string storedValue)
{
	bool isValid = false;
	// Format of stored values (passlib):
	// $algorithm$iteratons$salt$checksum
	string storedOTP = getNextValue(storedValue);
	// $algorithm$iteratons$salt
	string salt = getNextValue(storedValue);
	// $algorithm$iteratons
	int iterations = 10000;
	try
	{
		iterations = stoi(getNextValue(storedValue));
	}
	catch (const invalid_argument& e)
	{
		DebugPrint(e.what());
	}
	// $algorithm
	string algorithm = getNextValue(storedValue);

	// Salt is in adapted abase64 encoding of passlib where [./+] is substituted
	base64toabase64(salt);

	int bufLen = Base64DecodeGetRequiredLength((int)(salt.size() + 1));
	BYTE* bufSalt = (BYTE*)CoTaskMemAlloc(bufLen);
	if (bufSalt == nullptr)
	{
		return false;
	}
	Base64Decode(salt.c_str(), (int)(salt.size() + 1), bufSalt, &bufLen);

	// The password is encoded into UTF-8 from Unicode
	char* prepPassword = UnicodeToCodePage(65001, password.c_str());
	const int prepPasswordSize = (int)strnlen_s(prepPassword, INT_MAX);

	BYTE* prepPasswordBytes = reinterpret_cast<unsigned char*>(prepPassword);

	// Get the size of the output from the stored value, which is also in abase64 encoding
	base64toabase64(storedOTP);

	int bufLenStored = Base64DecodeGetRequiredLength((int)(storedOTP.size() + 1));
	BYTE* bufStored = (BYTE*)CoTaskMemAlloc(bufLenStored);
	if (bufStored == nullptr)
	{
		return false;
	}
	Base64Decode(storedOTP.c_str(), (int)(storedOTP.size() + 1), bufStored, &bufLenStored);

	// Do PBKDF2
	const ULONGLONG cIterations = iterations;
	ULONG cbDerivedKey = (ULONG)bufLenStored;
	PUCHAR pbDerivedKey = (unsigned char*)CoTaskMemAlloc(sizeof(unsigned char) * cbDerivedKey);
	if (pbDerivedKey == nullptr)
	{
		DebugPrint("Could not allocate memory for derived key.");
		return false;
	}

	const ULONG dwFlags = 0; // RESERVED, MUST BE ZERO
	BCRYPT_ALG_HANDLE hPrf = BCRYPT_HMAC_SHA512_ALG_HANDLE;

	const NTSTATUS status = BCryptDeriveKeyPBKDF2(hPrf, prepPasswordBytes, prepPasswordSize, bufSalt, bufLen,
		cIterations, pbDerivedKey, cbDerivedKey, dwFlags);

	CoTaskMemFree(bufSalt);

	if (status == 0) // STATUS_SUCCESS
	{
		// Compare the bytes
		if (cbDerivedKey == (ULONG)bufLenStored)
		{
			while (cbDerivedKey--)
			{
				if (pbDerivedKey[cbDerivedKey] != bufStored[cbDerivedKey])
				{
					goto Exit;
				}
			}
			isValid = true;
		}
	}
	else
	{
		DebugPrint("PBKDF2 Error: " + to_string(status));
		isValid = false;
	}

Exit:
	SecureZeroMemory(prepPassword, sizeof(prepPassword));
	SecureZeroMemory(prepPasswordBytes, sizeof(prepPasswordBytes));
	CoTaskMemFree(pbDerivedKey);
	CoTaskMemFree(bufStored);

	return isValid;
}

// Replaces '.' with '+' in the input string.
void OfflineHandler::base64toabase64(std::string& in)
{
	std::replace(in.begin(), in.end(), '.', '+');
}
