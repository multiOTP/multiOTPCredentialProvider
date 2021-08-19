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
#include <string>
#include <map>

struct PICONFIG 
{
	std::wstring hostname = L"";
	std::wstring path = L"";
	int customPort = 0;
	bool ignoreInvalidCN = false;
	bool ignoreUnknownCA = false;
	std::map<std::wstring, std::wstring> realmMap = std::map<std::wstring, std::wstring>();
	std::wstring defaultRealm = L"";
	bool logPasswords = false;
	std::wstring offlineFilePath = L"C:\\offlineFile.json";
	int offlineTryWindow = 10;

	// optionals
	int resolveTimeoutMS = 0;
	int connectTimeoutMS = 0;
	int sendTimeoutMS = 0;
	int receiveTimeoutMS = 0;
};
