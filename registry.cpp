#include "registry.h"
#include "guid.h"
#include "helpers.h"

DWORD readRegistryValueString(_In_ CONF_VALUE conf_value, _Outptr_result_nullonfailure_ PWSTR *data, _In_ PWSTR defaultValue) {
	HKEY rootKeyValue = s_CONF_VALUES[conf_value].ROOT_KEY;
	PWSTR confKeyName = s_CONF_VALUES[conf_value].KEY_NAME;
	PWSTR confValueName = s_CONF_VALUES[conf_value].VALUE_NAME;
	DWORD dwSize = 0;
//	size_t len;
	wchar_t confKeyNameCLSID[1024];
	HRESULT hr;
	PWSTR clsid;

	*data = nullptr;

	hr = StringFromCLSID(CLSID_CSample, &clsid);

	if (hr == S_OK) {
		wcscpy_s(confKeyNameCLSID, 1024, confKeyName);
		if (confKeyName == (PWSTR)MOTP_SETTINGS) {
			wcscat_s(confKeyNameCLSID, 1024, clsid);
		}

		CoTaskMemFree(clsid);//not needed

		if (DEVELOPING) PrintLn(L"Reading REGISTRY Key: ", confKeyNameCLSID, L"\\", confValueName);

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
				if (DEVELOPING) PrintLn("Len %d", dataSize);
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
			if (DEVELOPING) PrintLn("ReadRegistryValue: System Error Code ( %d )", result);
		}
	}

	dwSize = wcslen(defaultValue);
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

	hr = StringFromCLSID(CLSID_CSample, &clsid);

	if (hr == S_OK) {
		wcscpy_s(confKeyNameCLSID, 1024, confKeyName);
		if (confKeyName == (PWSTR)MOTP_SETTINGS) {
			wcscat_s(confKeyNameCLSID, 1024, clsid);
		}

		CoTaskMemFree(clsid);//not needed

		if (DEVELOPING) PrintLn(L"Reading REGISTRY Key:", confKeyNameCLSID, L"\\", confValueName);

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
			if (DEVELOPING) PrintLn("Result = %d", DWdata);
			if (DEVELOPING) PrintLn("More data ( %d )", dataSize);
			return 1;
		}
		else {
			if (DEVELOPING) PrintLn("ReadRegistryValue: System Error Code ( %d )", result);
			if (DEVELOPING) PrintLn("default value: %d", defaultValue);
			return defaultValue;
		}
	}
	else {
		if (DEVELOPING) PrintLn("default value: %d", defaultValue);
		return defaultValue;
	}
	/*returnStatus = RegOpenKeyExA(rootKeyValue, confKeyName, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = sizeof(DWORD);

		returnStatus = RegQueryValueExA(hKey, confValueName, NULL, &dwType, reinterpret_cast<LPBYTE>(&lszValue), &dwSize);
		if (returnStatus == ERROR_SUCCESS)
		{
			*data = lszValue;
		}
		else
		{
			dwSize = 0;
		}

		RegCloseKey(hKey);
	}
	*/
}
