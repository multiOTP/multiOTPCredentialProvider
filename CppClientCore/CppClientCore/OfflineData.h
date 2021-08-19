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
#pragma once

#include "Logger.h"
#include "../nlohmann/json.hpp"

#include <string>
#include <map>

#define JSON_DUMP_INDENTATION 4

class OfflineData
{
public:
	OfflineData(std::string json_string);

	nlohmann::json toJSON();

	int getLowestKey();

	size_t getOfflineOTPsLeft() noexcept;

	std::string user = "";
	std::string username = "";
	std::string serial = "";
	std::string refilltoken = "";
	std::map<std::string, std::string> offlineOTPs;
	int rounds = 10000;
	int count = 0;
};
