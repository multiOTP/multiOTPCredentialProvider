/**
 * BASE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * MultiotpCredential is our implementation of ICredentialProviderCredential.
 * ICredentialProviderCredential is what LogonUI uses to let a credential
 * provider specify what a user tile looks like and then tell it what the
 * user has entered into the tile.  ICredentialProviderCredential is also
 * responsible for packaging up the users credentials into a buffer that
 * LogonUI then sends on to LSA.
 *
 * Extra code provided "as is" for the multiOTP open source project
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.6.1.5
 * @date      2019-10-23
 * @since     2013
 * @copyright (c) 2016-2019 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
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

#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <propkey.h>
#include "common.h"
#include "dll.h"
#include "resource.h"

#define ENDPOINT_AUTH_CONTINUE	((HRESULT)0x88809002) 

class MultiotpCredential : public ICredentialProviderCredential2, ICredentialProviderCredentialWithFieldOptions
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
		#pragma warning( push )
		#pragma warning( disable : 4838)
		static const QITAB qit[] =
        {
            QITABENT(MultiotpCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
            QITABENT(MultiotpCredential, ICredentialProviderCredential2), // IID_ICredentialProviderCredential2
            QITABENT(MultiotpCredential, ICredentialProviderCredentialWithFieldOptions), //IID_ICredentialProviderCredentialWithFieldOptions
            // {0},
		    { static_cast<int>(0) },
        };
		#pragma warning( pop ) 
		return QISearch(this, qit, riid, ppv);
    }
  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(_In_ ICredentialProviderCredentialEvents *pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(_Out_ BOOL *pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                 _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                    _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                NTSTATUS ntsSubstatus,
                                _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);


    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid);

    // ICredentialProviderCredentialWithFieldOptions
    IFACEMETHODIMP GetFieldOptions(DWORD dwFieldID,
                                   _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo);

  public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                       _In_ FIELD_STATE_PAIR const *rgfsp,
                       _In_ ICredentialProviderUser *pcpUser);
    MultiotpCredential();

	// Add _pszUserSid to public
	PWSTR                                   _pszUserSid;

  private:
    virtual ~MultiotpCredential();
    long                                    _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;                                          // The usage scenario for which we were enumerated.
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];    // An array holding the type and name of each field in the tile.
    FIELD_STATE_PAIR                        _rgFieldStatePairs[SFI_NUM_FIELDS];             // An array holding the state of each field in the tile.
    PWSTR                                   _rgFieldStrings[SFI_NUM_FIELDS];                // An array holding the string value of each field. This is different from the name of the field held in _rgCredProvFieldDescriptors.
    // PWSTR                                   _pszUserSid;
    PWSTR                                   _pszQualifiedUserName;                          // The user name that's used to pack the authentication buffer

    // ICredentialProviderCredentialEvents2*    _pCredProvCredentialEvents;                    // Used to update fields.
                                                                                               // CredentialEvents2 for Begin and EndFieldUpdates.

	ICredentialProviderCredentialEvents2*   _pCredProvCredentialEventsV2;                   // CredentialEvents2 for Begin and EndFieldUpdates.
	ICredentialProviderCredentialEvents*    _pCredProvCredentialEventsV1;                   // Old CredentialEvents
	ICredentialProviderCredentialEvents*    _pCredProvCredentialEvents;                     // Used to update fields.
	BOOL                                    _fChecked;                                      // Tracks the state of our checkbox.
    DWORD                                   _dwComboIndex;                                  // Tracks the current index of our combobox.
    bool                                    _fShowControls;                                 // Tracks the state of our show/hide controls link.
    bool                                    _fIsLocalUser;                                  // If the cred prov is assosiating with a local user tile

	bool									_fUserNameVisible;								// User can enter username
};
