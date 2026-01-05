/**
 * multiOTP Credential Provider
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.10.1.2
 * @date      2026-01-05
 * @since     2013
 * @copyright (c) 2016-2026 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 * Please check the README.md for the full change log
 *
 *********************************************************************/

#pragma once

#include "windows.h"
#include <winreg.h>
#include <stdio.h>

#define MULTIOTP_SETTINGS           L"CLSID\\"
#define MULTIOTP_PATH               L"multiOTPPath"
#define MULTIOTP_TIMEOUT            L"multiOTPTimeout"
#define MULTIOTP_RDPONLY            L"multiOTPRDPOnly"
#define MULTIOTP_PREFIX_PASSWORD    L"multiOTPPrefixPass"  // No more used
#define MULTIOTP_DISPLAY_SMS_LINK   L"multiOTPDisplaySmsLink"
#define MULTIOTP_DISPLAY_EMAIL_LINK L"multiOTPDisplayEmailLink"
#define MULTIOTP_UPN_FORMAT         L"multiOTPUPNFormat"
#define MULTIOTP_LOGIN_TITLE        L"multiOTPLoginTitle"
#define MULTIOTP_CACHE_ENABLED      L"multiOTPCacheEnabled"
#define MULTIOTP_SERVERS            L"multiOTPServers"
#define MULTIOTP_SERVER_TIMEOUT     L"multiOTPServerTimeout"
#define MULTIOTP_SHARED_SECRET      L"multiOTPSharedSecret"
#define MULTIOTP_FLAT_DOMAIN        L"multiOTPFlatDomain"
#define MULTIOTP_DEFAULT_PREFIX     L"multiOTPDefaultPrefix"
#define MULTIOTP_DISPLAY_LASTUSER   L"multiOTPDisplayLastUser"
#define MULTIOTP_LAST_USER_AUTHENTICATED   L"lastUserAuthenticated"
#define MULTIOTP_LAST_USER_TIMESTAMP   L"lastUserTimestamp"
#define MULTIOTP_NUMLOCK_ON   L"numlockOn"
#define MULTIOTP_OTP_FAIL_TEXT   L"otp_fail_text"


#define RDP_SETTINGS                L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
#define RDP_PORT                    L"PortNumber"

#define TCPIP_SETTINGS              L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define TCPIP_DOMAIN                L"Domain"
#define TCPIP_HOSTNAME              L"Hostname"

struct REGISTRY_KEY
{
	HKEY ROOT_KEY;
	PWSTR KEY_NAME;
	PWSTR VALUE_NAME;
};

enum CONF_VALUE
{
	CONF_PATH = 0,
	CONF_TIMEOUT = 1,
	CONF_RDP_ONLY = 2,
	CONF_PREFIX_PASSWORD = 3,  // No more used
	CONF_DISPLAY_SMS_LINK = 4,
	CONF_UPN_FORMAT = 5,
	CONF_LOGIN_TITLE = 6,
	CONF_CACHE_ENABLED = 7,
	CONF_SERVERS = 8,
	CONF_SERVER_TIMEOUT = 9,
	CONF_SHARED_SECRET = 10,
	CONF_FLAT_DOMAIN = 11,
	CONF_DEFAULT_PREFIX = 12,
	CONF_RDP_PORT = 13,
	CONF_DOMAIN_NAME = 14,
	CONF_HOST_NAME = 15,
	CONF_DISPLAY_EMAIL_LINK = 16,
	CONF_DISPLAY_LAST_USER= 17,
	LAST_USER_AUTHENTICATED = 18,
	LAST_USER_TIMESTAMP = 19,
	CONF_NUMLOCK_ON = 20,
	CONF_NUM_VALUES = 21,
	CONF_ERROR_MESSAGE = 22
};

static const REGISTRY_KEY s_CONF_VALUES[] =
{
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_PATH }, // 0
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_TIMEOUT }, // 1
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_RDPONLY }, // 2
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_PREFIX_PASSWORD }, // 3 No more used
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_DISPLAY_SMS_LINK }, // 4
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_UPN_FORMAT }, // 5
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_LOGIN_TITLE }, // 6
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_CACHE_ENABLED }, // 7
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_SERVERS }, // 8
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_SERVER_TIMEOUT }, // 9
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_SHARED_SECRET }, // 10
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_FLAT_DOMAIN }, // 11
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_DEFAULT_PREFIX }, // 12
	{ HKEY_LOCAL_MACHINE, RDP_SETTINGS, RDP_PORT }, // 13
	{ HKEY_LOCAL_MACHINE, TCPIP_SETTINGS, TCPIP_DOMAIN }, // 14
	{ HKEY_LOCAL_MACHINE, TCPIP_SETTINGS, TCPIP_HOSTNAME }, // 15
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_DISPLAY_EMAIL_LINK}, // 16
    { HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_DISPLAY_LASTUSER}, // 17
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_LAST_USER_AUTHENTICATED}, // 18
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_LAST_USER_TIMESTAMP}, // 19
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_NUMLOCK_ON}, // 20
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_NUMLOCK_ON}, // 21 no more used
	{ HKEY_CLASSES_ROOT, MULTIOTP_SETTINGS, MULTIOTP_OTP_FAIL_TEXT}, // 22
};
VOID writeKeyValueInMultiOTPRegistry(_In_ HKEY rootKeyValue, _In_ PWSTR keyName, _In_ PWSTR valueName, _In_ PWSTR writeValue);
VOID writeRegistryValueString(_In_ CONF_VALUE conf_value, _In_ PWSTR writeValue);
DWORD readRegistryValueString(_In_ CONF_VALUE conf_value, _Outptr_result_nullonfailure_ PWSTR* data, _In_ PWSTR defaultValue);
DWORD readRegistryValueInteger(_In_ CONF_VALUE conf_value, _In_ DWORD defaultValue);
DWORD readKeyValueInMultiOTPRegistry(_In_ HKEY rootKeyValue, _In_ PWSTR keyName, _In_ PWSTR valueName, _Outptr_result_nullonfailure_ PWSTR* data, _In_ PWSTR defaultValue);
VOID writeRegistryValueInteger(_In_ CONF_VALUE conf_value, _In_ DWORD writeValue);
VOID writeKeyValueIntegerInMultiOTPRegistry(_In_ HKEY rootKeyValue, _In_ PWSTR keyName, _In_ PWSTR valueName, _In_ DWORD writeValue);
DWORD readKeyValueInMultiOTPRegistryInteger(_In_ HKEY rootKeyValue, _In_ PWSTR keyName, _In_ PWSTR valueName, _In_ DWORD defaultValue);