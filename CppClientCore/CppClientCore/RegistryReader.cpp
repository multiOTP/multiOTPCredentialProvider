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
#include "RegistryReader.h"
#include "PrivacyIDEA.h"
#include <Windows.h>
#include <tchar.h>

using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 1024

RegistryReader::RegistryReader(const std::wstring& pathToKey)
{
	wpath = pathToKey;
}

bool RegistryReader::getAll(const std::wstring& path, std::map<std::wstring, std::wstring>& map)
{
	// Open handle to realm-mapping key
	HKEY hKey = nullptr;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		path.c_str(),
		0,
		KEY_READ,
		&hKey) != ERROR_SUCCESS)
	{
		return false;
	}

	WCHAR    achClass[MAX_PATH] = TEXT(""); // buffer for class name 
	DWORD    cchClassName = MAX_PATH;		// size of class string 
	DWORD    cSubKeys = 0;					// number of subkeys 
	DWORD    cbMaxSubKey;					// longest subkey size 
	DWORD    cchMaxClass;					// longest class string 
	DWORD    cValues;						// number of values for key 
	DWORD    cchMaxValue;					// longest value name 
	DWORD    cbMaxValueData;				// longest value data 
	DWORD    cbSecurityDescriptor;			// size of security descriptor 
	FILETIME ftLastWriteTime;				// last write time 

	DWORD i, retCode;

	WCHAR achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	if (cValues)
	{
		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValueW(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);
			if (retCode == ERROR_SUCCESS)
			{
				wstring value = PrivacyIDEA::toUpperCase(achValue);
				// Get the data for the value
				const DWORD SIZE = 1024;
				TCHAR szData[SIZE] = _T("");
				DWORD dwValue = SIZE;
				DWORD dwType = 0;
				DWORD dwRet = 0;

				dwRet = RegQueryValueEx(
					hKey,
					value.c_str(),
					NULL,
					&dwType,
					(LPBYTE)&szData,
					&dwValue);
				if (dwRet == ERROR_SUCCESS)
				{
					if (dwType == REG_SZ)
					{
						wstring data(szData);
						map.try_emplace(value, data);
					}
				}
			}
		}
	}
	RegCloseKey(hKey);
	return true;
}

std::wstring RegistryReader::getRegistry(std::wstring name)
{
	DWORD dwRet = NULL;
	HKEY hKey = nullptr;
	dwRet = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		wpath.c_str(),
		NULL,
		KEY_QUERY_VALUE,
		&hKey);
	if (dwRet != ERROR_SUCCESS)
	{
		return L"";
	}

	const DWORD SIZE = 1024;
	TCHAR szValue[SIZE] = _T("");
	DWORD dwValue = SIZE;
	DWORD dwType = 0;
	dwRet = RegQueryValueEx(
		hKey,
		name.c_str(),
		NULL,
		&dwType,
		(LPBYTE)&szValue,
		&dwValue);
	if (dwRet != ERROR_SUCCESS)
	{
		return L"";
	}

	if (dwType != REG_SZ)
	{
		return L"";
	}
	RegCloseKey(hKey);
	hKey = NULL;
	return wstring(szValue);
}

bool RegistryReader::getBoolRegistry(std::wstring name)
{
	// Non existing keys evaluate to false.
	return getRegistry(name) == L"1";
}

int RegistryReader::getIntRegistry(std::wstring name)
{
	return _wtoi(getRegistry(name).c_str()); // Invalid parameter returns 0
}
