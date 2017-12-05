#pragma once

#include "windows.h"
#include <winreg.h>
#include <stdio.h>

#define MOTP_SETTINGS    L"CLSID\\"
#define MOTP_PATH        L"multiOTPPath"
#define MOTP_TIMEOUT     L"multiOTPTimeout"
#define MOTP_RDPONLY     L"multiOTPRDPOnly"
#define MOTP_PREFIX_PASS L"multiOTPPrefixPass"

#define RDP_SETTINGS     L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
#define RDP_PORT         L"PortNumber"

#define TCPIP_SETTINGS   L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define TCPIP_DOMAIN     L"Domain"
#define TCPIP_HOSTNAME   L"Hostname"

struct REGISTRY_KEY
{
	HKEY ROOT_KEY;
	PWSTR KEY_NAME;
	PWSTR VALUE_NAME;
};

enum CONF_VALUE
{
	CONF_PATH				  = 0,
	CONF_TIMEOUT 			  = 1,
	CONF_RDP_ONLY             = 2,
	CONF_PREFIX_PASSWORD      = 3,
	CONF_RDP_PORT             = 4,
	CONF_DOMAIN_NAME          = 5,
	CONF_HOST_NAME            = 6,
	CONF_NUM_VALUES			  = 7,
};

static const REGISTRY_KEY s_CONF_VALUES[] =
{
	{ HKEY_CLASSES_ROOT, MOTP_SETTINGS, MOTP_PATH},
	{ HKEY_CLASSES_ROOT, MOTP_SETTINGS, MOTP_TIMEOUT },
    { HKEY_CLASSES_ROOT, MOTP_SETTINGS, MOTP_RDPONLY },
	{ HKEY_CLASSES_ROOT, MOTP_SETTINGS, MOTP_PREFIX_PASS },

	{ HKEY_LOCAL_MACHINE, RDP_SETTINGS, RDP_PORT },

	{ HKEY_LOCAL_MACHINE, TCPIP_SETTINGS, TCPIP_DOMAIN },
	{ HKEY_LOCAL_MACHINE, TCPIP_SETTINGS, TCPIP_HOSTNAME },
};

DWORD readRegistryValueString( _In_ CONF_VALUE conf_value, _Outptr_result_nullonfailure_ PWSTR *data, _In_ PWSTR defaultValue);
DWORD readRegistryValueInteger(_In_ CONF_VALUE conf_value, _In_ DWORD defaultValue );
