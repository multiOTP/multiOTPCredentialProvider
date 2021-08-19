/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 Nils Behlen
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
#include "SecureString.h"
#include <string>

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#define ReleaseDebugPrint(message)	Logger::Get().log(message, __FILENAME__, __LINE__, true)
#define DebugPrint(message)			Logger::Get().log(message, __FILENAME__, __LINE__, false)

// Singleton logger class that writes to a file on C: and to OutputDebugString
class Logger
{
public:
	std::string logfilePathDebug = "C:\\PICredentialProviderDebugLog.txt";
	std::string logfilePathProduction = "C:\\PICredentialProviderLog.txt";

	Logger(Logger const&) = delete;
	void operator=(Logger const&) = delete;

	static Logger& Get() {
		static Logger instance;
		return instance;
	}

	void log(const char* message, const char* file, int line, bool logInProduction);

	void log(const wchar_t* message, const char* file, int line, bool logInProduction);

	void log(const int message, const char* file, int line, bool logInProduction);

	void log(const std::string& message, const char* file, int line, bool logInProduction);

	void log(const std::wstring& message, const char* file, int line, bool logInProduction);

	void log(const SecureString& message, const char* file, int line, bool logInProduction);

	void log(const SecureWString& message, const char* file, int line, bool logInProduction);

	bool releaseLog = false;

private:
	Logger() = default;

	void logS(const std::string& message, const char* file, int line, bool logInProduction);

	void logW(const std::wstring& message, const char* file, int line, bool logInProduction);
};
