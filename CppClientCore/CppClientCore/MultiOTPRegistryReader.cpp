/**
 * multiOTP Credential Provider, extends privacyIdea RegistryReader
 *
 * @author    Yann Jeanrenaud, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.8.3.0
 * @date      2021-09-14
 * @since     2021
 * @copyright (c) 2016-2021 SysCo systemes de communication sa
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
#include "MultiOTPRegistryReader.h"

#include <Windows.h>
#include <tchar.h>
#include "MultiOTP.h"

using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 1024

MultiOTPRegistryReader::MultiOTPRegistryReader(const std::wstring& pathToKey) : RegistryReader(pathToKey)
{

}

std::wstring MultiOTPRegistryReader::getRegistry(std::wstring name, HKEY container)
{
	DWORD dwRet = NULL;
	HKEY hKey = nullptr;
	dwRet = RegOpenKeyEx(
		container,
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

bool MultiOTPRegistryReader::getBoolRegistry(std::wstring name, HKEY container)
{
	return getRegistry(name, container) == L"1";
}

int MultiOTPRegistryReader::getIntRegistry(std::wstring name, HKEY container)
{
	return _wtoi(getRegistry(name, container).c_str()); // Invalid parameter returns 0
}

bool MultiOTPRegistryReader::getAll(const std::wstring& path, std::map<std::wstring, std::wstring>& map, HKEY container)
{
	// Open handle to realm-mapping key
	HKEY hKey = nullptr;

	if (RegOpenKeyEx(container,
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
				wstring value = MultiOTP::toUpperCase(achValue);
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
