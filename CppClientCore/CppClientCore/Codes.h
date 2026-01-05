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

// 7880900-0X PRIVACYIDEA CODES
#define PI_TRANSACTION_SUCCESS						((HRESULT)0x78809004)
#define PI_TRANSACTION_FAILURE						((HRESULT)0x78809005)
#define PI_OFFLINE_OTP_SUCCESS						((HRESULT)0x78809006)
#define PI_OFFLINE_OTP_FAILURE						((HRESULT)0x78809007)
#define PI_NO_CHALLENGES							((HRESULT)0x78809009)

#define PI_ERROR_EMPTY_RESPONSE						((HRESULT)0x7880900E)
#define PI_STATUS_NOT_SET							((HRESULT)0x7880900F)

// 888090-1X VALIDATE CHECK RETURN CODES
#define PI_AUTH_SUCCESS								((HRESULT)0x88809010)
#define PI_AUTH_FAILURE								((HRESULT)0x88809011)

// This means there was an error specified in the response from Privacyidea
// The error can be retrieved by calling getLastError and getLastErrorMessage
#define PI_AUTH_ERROR								((HRESULT)0x88809012)
#define PI_TRIGGERED_CHALLENGE						((HRESULT)0x88809013)

// This means either the server is really unavailable while the user thought it would be available 
// OR
// The user meant to authenticate offline (and expects the server to be unavailable) but the entered OTP didn't match the offlineData
// NOTE this implies there was offlineData available for the user
#define PI_WRONG_OFFLINE_SERVER_UNAVAILABLE			((HRESULT)0x88809014)
#define PI_ENDPOINT_SETUP_ERROR						((HRESULT)0x88809015)


// 888090-2X OFFLINE CODES
#define PI_OFFLINE_DATA_NO_OTPS_LEFT				((HRESULT)0x88809020)
#define PI_OFFLINE_DATA_USER_NOT_FOUND				((HRESULT)0x88809021)
#define PI_OFFLINE_NO_OFFLINE_DATA					((HRESULT)0x88809022) 
#define PI_OFFLINE_FILE_DOES_NOT_EXIST				((HRESULT)0x88809023)
#define PI_OFFLINE_FILE_EMPTY						((HRESULT)0x88809024)
#define PI_OFFLINE_WRONG_OTP						((HRESULT)0x88809025)

// 888090-3X JSON ERRORS
#define PI_JSON_FORMAT_ERROR						((HRESULT)0x88809030)
#define PI_JSON_PARSE_ERROR							((HRESULT)0x88809031)
#define PI_JSON_ERROR_CONTAINED						((HRESULT)0x88809032)

// 888090-4X ENDPOINT ERRORS
// Use only those for now, since there is no need for the code to differentiate the error further
// The "real" cause is logged right after the error occurs in the endpoint
#define PI_ENDPOINT_SERVER_UNAVAILABLE				((HRESULT)0x88809041)

#define MULTIOTP_USERLOCKED							((HRESULT)0x88809042)
#define MULTIOTP_USERDELAYED						((HRESULT)0x88809043)
