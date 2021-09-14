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
#pragma once
#include "RegistryReader.h"
#include <Windows.h>

class MultiOTPRegistryReader : public RegistryReader {

public:
	MultiOTPRegistryReader(const std::wstring& pathToKey);
	std::wstring getRegistry(std::wstring name, HKEY container = HKEY_CLASSES_ROOT);
	bool getBoolRegistry(std::wstring name, HKEY container = HKEY_CLASSES_ROOT);
	int getIntRegistry(std::wstring name, HKEY container = HKEY_CLASSES_ROOT);
	bool getAll(const std::wstring& path, std::map<std::wstring, std::wstring>& map, HKEY container = HKEY_CLASSES_ROOT);
private:

};