#pragma once
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

#include "OfflineData.h"
#include "SecureString.h"
#include <string>
#include <map>
#include <Windows.h>
#include <vector>

class OfflineHandler
{
public:
	OfflineHandler(const std::wstring& filePath, int tryWindow = 10);

	~OfflineHandler();

	HRESULT verifyOfflineOTP(const SecureWString& otp, const std::string& username);

	HRESULT getRefillTokenAndSerial(const std::string& username, std::string& refilltoken, std::string& serial);

	HRESULT parseForOfflineData(const std::string& in);

	HRESULT parseRefillResponse(const std::string& in, const std::string& username);

	HRESULT isDataVailable(const std::string& username);

private:
	std::vector<OfflineData> dataSets = std::vector<OfflineData>();

	std::wstring _filePath = L"C:\\offlineFile.json";

	int _tryWindow = 10;

	bool pbkdf2_sha512_verify(SecureWString password, std::string storedValue);

	void base64toabase64(std::string& in);

	std::string getNextValue(std::string& in);

	char* UnicodeToCodePage(int codePage, const wchar_t* src);

	HRESULT saveToFile();

	HRESULT loadFromFile();
};

