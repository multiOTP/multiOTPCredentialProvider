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
#include <vector>

// Token Type Available
enum class TTA
{
	NOT_SET,
	OTP,
	PUSH,
	BOTH
};

class Challenge
{
public:
	std::string toString();

	std::wstring message = L"";

	std::string transaction_id = "";

	std::string serial = "";

	TTA tta = TTA::NOT_SET;

private:
	std::string ttaToString(TTA tta);
};
