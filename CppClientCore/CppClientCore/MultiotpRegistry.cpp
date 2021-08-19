/**
 * multiOTP Credential Provider
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.8.2.9
 * @date      2021-08-19
 * @since     2013
 * @copyright (c) 2016-2021 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2020-08-31 5.8.0.0 SysCo/al ENH: Retarget to the last SDK 10.0.19041.1
 *   2019-10-23 5.6.1.5 SysCo/al FIX: Prefix password parameter was buggy (better handling of parameters in debug mode)
 *                               FIX: swprintf_s problem with special chars (thanks to anekix)
 *   2019-01-25 5.4.1.6 SysCo/al FIX: Username with space are now supported
 *                               ENH: Added integrated Visual C++ 2017 Redistributable installation
 *   2018-09-14 5.4.0.1 SysCo/al FIX: Better domain name and hostname detection
 *                               FIX: The cache lifetime check process was buggy since 5.3.0.3
 *                               ENH: multiOTP Credential Provider files and objects have been reorganized
 *   2018-08-26 5.3.0.3 SysCo/al FIX: Users without 2FA token are now supported
 *   2018-08-21 5.3.0.0 SysCo/yj FIX: Save flat domain name in the registry. While offline, use this value instead of asking the DC
 *                      SysCo/al ENH: The multiOTP timeout (how long the Credential Provider wait a response from
 *                                    the multiOTP process) is now 60 seconds by default (instead of 10)
 *   2018-03-11 5.2.0.0 SysCo/al New implementation from scratch
 *
 *********************************************************************/

#include "MultiotpRegistry.h"
#include "guid.h"
#include "MultiotpHelpers.h"

VOID writeRegistryValueString(_In_ CONF_VALUE conf_value, _In_ PWSTR writeValue) {
	HKEY regKey;
	HKEY rootKeyValue = s_CONF_VALUES[conf_value].ROOT_KEY;
	PWSTR confKeyName = s_CONF_VALUES[conf_value].KEY_NAME;
	PWSTR confValueName = s_CONF_VALUES[conf_value].VALUE_NAME;
	//	size_t len;
	wchar_t confKeyNameCLSID[1024];
	HRESULT hr;
	PWSTR clsid;
	hr = StringFromCLSID(CLSID_Multiotp, &clsid);
	if (hr == S_OK) {
		if (DEVELOP_MODE) PrintLn(L"hr is OK");
		wcscpy_s(confKeyNameCLSID, 1024, confKeyName);
		if (confKeyName == (PWSTR)MULTIOTP_SETTINGS) {
			wcscat_s(confKeyNameCLSID, 1024, clsid);
		}
		CoTaskMemFree(clsid); //not needed
		if (DEVELOP_MODE) PrintLn(L"Writing REGISTRY Key: ", confKeyNameCLSID, L"\\", confValueName);

		LONG result = ::RegOpenKeyEx(rootKeyValue, confKeyNameCLSID, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &regKey);
		if (result == ERROR_SUCCESS) {
			result = ::RegSetValueEx(
				regKey,
				confValueName,
				0,
				REG_SZ,
				(const BYTE*)writeValue,
				sizeof(wchar_t) * (1 + (DWORD)wcslen(writeValue)));
		}
	}
	else {
		if (DEVELOP_MODE) PrintLn(L"hr is KO");
	}
}


DWORD readRegistryValueString(_In_ CONF_VALUE conf_value, _Outptr_result_nullonfailure_ PWSTR* data, _In_ PWSTR defaultValue) {
	HKEY rootKeyValue = s_CONF_VALUES[conf_value].ROOT_KEY;
	PWSTR confKeyName = s_CONF_VALUES[conf_value].KEY_NAME;
	PWSTR confValueName = s_CONF_VALUES[conf_value].VALUE_NAME;
	DWORD dwSize = 0;
	//	size_t len;
	wchar_t confKeyNameCLSID[1024];
	HRESULT hr;
	PWSTR clsid;

	*data = nullptr;

	hr = StringFromCLSID(CLSID_Multiotp, &clsid);

	if (hr == S_OK) {
		wcscpy_s(confKeyNameCLSID, 1024, confKeyName);
		if (confKeyName == (PWSTR)MULTIOTP_SETTINGS) {
			wcscat_s(confKeyNameCLSID, 1024, clsid);
		}

		CoTaskMemFree(clsid);//not needed

		if (DEVELOP_MODE) PrintLn(L"Reading REGISTRY Key: ", confKeyNameCLSID, L"\\", confValueName);

		DWORD keyType = 0;
		DWORD dataSize = 0;
		const DWORD flags = RRF_RT_REG_SZ; // Only read strings (REG_SZ)
		LONG result = ::RegGetValue(
			rootKeyValue,
			confKeyNameCLSID,
			confValueName,
			flags,
			&keyType,
			nullptr,    // pvData == nullptr --> Request buffer size for string
			&dataSize);
		if ((result == ERROR_SUCCESS) && (keyType == REG_SZ)) {
			//reserve read return
			*data = (PWSTR)CoTaskMemAlloc(dataSize);
			result = ::RegGetValue(
				rootKeyValue,
				confKeyNameCLSID,
				confValueName,
				flags,
				nullptr,
				*data, // Write string in this destination buffer
				&dataSize);
			if (result == ERROR_SUCCESS) {
				dwSize = dataSize / sizeof(WCHAR);
				if (DEVELOP_MODE) PrintLn("Len %d", dataSize);
				return dwSize;
			}
			else {
				CoTaskMemFree(*data);
				*data = nullptr;
				dwSize = 0;
			}
		}
		else {
			/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx */
			if (DEVELOP_MODE) PrintLn("ReadRegistryValue: System Error Code ( %d )", result);
		}
	}

	dwSize = DWORD(wcslen(defaultValue));
	*data = (PWSTR)CoTaskMemAlloc(sizeof(wchar_t) * (dwSize + 1));
	wcscpy_s(*data, 1024, defaultValue);
	return dwSize;
}

DWORD readRegistryValueInteger(_In_ CONF_VALUE conf_value, _In_ DWORD defaultValue) {
	DWORD DWdata;
	DWORD dataSize;

	HKEY rootKeyValue = s_CONF_VALUES[conf_value].ROOT_KEY;
	PWSTR confKeyName = s_CONF_VALUES[conf_value].KEY_NAME;
	PWSTR confValueName = s_CONF_VALUES[conf_value].VALUE_NAME;

	wchar_t confKeyNameCLSID[1024];
	HRESULT hr;
	PWSTR clsid;

	hr = StringFromCLSID(CLSID_Multiotp, &clsid);

	if (hr == S_OK) {
		wcscpy_s(confKeyNameCLSID, 1024, confKeyName);
		if (confKeyName == (PWSTR)MULTIOTP_SETTINGS) {
			wcscat_s(confKeyNameCLSID, 1024, clsid);
		}

		CoTaskMemFree(clsid); //not needed

		if (DEVELOP_MODE) PrintLn(L"Reading REGISTRY Key:", confKeyNameCLSID, L"\\", confValueName);

		dataSize = sizeof(DWORD);

		LONG result = ::RegGetValue(
			rootKeyValue,
			confKeyNameCLSID,
			confValueName,
			RRF_RT_REG_DWORD,
			NULL,
			&DWdata,
			&dataSize);

		if (result == ERROR_SUCCESS) {
			return DWdata;
		}
		else if (result == ERROR_MORE_DATA) {
			if (DEVELOP_MODE) PrintLn("Result = %d", DWdata);
			if (DEVELOP_MODE) PrintLn("More data ( %d )", dataSize);
			return 1;
		}
		else {
			if (DEVELOP_MODE) PrintLn("ReadRegistryValue: System Error Code ( %d )", result);
			if (DEVELOP_MODE) PrintLn("default value: %d", defaultValue);
			return defaultValue;
		}
	}
	else {
		if (DEVELOP_MODE) PrintLn("default value: %d", defaultValue);
		return defaultValue;
	}
}
