/**
 * BASE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Standard dll required functions and class factory implementation.
 *
 * Extra code provided "as is" for the multiOTP open source project
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.4.0.1
 * @date      2018-09-14
 * @since     2013
 * @copyright (c) 2016-2018 SysCo systemes de communication sa
 * @copyright (c) 2015-2016 ArcadeJust ("RDP only" enhancement)
 * @copyright (c) 2013-2015 Last Squirrel IT 
 * @copyright Apache License, Version 2.0
 *
 *
 * Change Log
 *
 *   2018-03-11 5.2.0.0 SysCo/al New implementation from scratch
 *
 *********************************************************************/

#include <windows.h>
#include <unknwn.h>
#include "Dll.h"
#include "MultiotpHelpers.h"

static long g_cRef = 0;   // global dll reference count
HINSTANCE g_hinst = NULL; // global dll hinstance

extern HRESULT Multiotp_CreateInstance(__in REFIID riid, __deref_out void** ppv);
extern HRESULT CLMSFilter_CreateInstance(__in REFIID riid, __deref_out void** ppv);
EXTERN_C GUID CLSID_Multiotp;

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1)
    {
    }

    // IUnknown
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv)
    {
		#pragma warning( push )
		#pragma warning( disable : 4838)
		static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
		#pragma warning( pop )
		return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            // hr = Multiotp_CreateInstance(riid, ppv);
			// Begin Extra Code to handle the filter
			if (IID_ICredentialProvider == riid) {
				if (DEVELOP_MODE) PrintLn("Dll:Invoke IID_ICredentialProvider");
				hr = Multiotp_CreateInstance(riid, ppv);
			}
			else if (IID_ICredentialProviderFilter == riid) {
				if (DEVELOP_MODE) PrintLn("Dll:Invoke IID_ICredentialProviderFilter");
				hr = CLMSFilter_CreateInstance(riid, ppv);
			}
			else {
				*ppv = NULL;
				hr = CLASS_E_NOAGGREGATION;
				if (DEVELOP_MODE) PrintLn("Dll:Invoke unknown object");
			}
			// End Extra Code
        }
        else
        {
            *ppv = NULL;
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    IFACEMETHODIMP LockServer(__in BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

private:
    ~CClassFactory()
    {
    }
    long _cRef;
};

HRESULT CClassFactory_CreateInstance(__in REFCLSID rclsid, __in REFIID riid, __deref_out void **ppv)
{
    *ppv = NULL;

    HRESULT hr;

    if (CLSID_Multiotp == rclsid)
    {
        CClassFactory* pcf = new CClassFactory();
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

void DllAddRef()
{
	if (DEVELOP_MODE) PrintLn("Dll:DllAddRef");
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
	if (DEVELOP_MODE) PrintLn("Dll:DllRelease");
    InterlockedDecrement(&g_cRef);
}

STDAPI DllCanUnloadNow()
{
	if (DEVELOP_MODE) PrintLn("Dll:DllCanUnloadNow?");
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

STDAPI_(BOOL) DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void *)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    g_hinst = hinstDll;
    return TRUE;
}

