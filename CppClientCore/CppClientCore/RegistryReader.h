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

class RegistryReader
{
public:
	RegistryReader(const std::wstring& pathToKey);

	std::wstring wpath;

	// puts all keys and values from the current path into a map, the keys will be converted to uppercase
	bool getAll(const std::wstring& path, std::map<std::wstring, std::wstring>& map);

	std::wstring getRegistry(std::wstring name);

	bool getBoolRegistry(std::wstring name);

	int getIntRegistry(std::wstring name);
};

