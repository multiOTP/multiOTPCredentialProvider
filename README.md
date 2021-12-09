multiOTPCredentialProvider
==========================
multiOTP Credential Provider for multiOTP is a free and open source implementation of a V2 Credential Provider for the multiOTP strong two-factor authentication solution (Apache License, Version 2.0)

(c) 2016-2021 SysCo systemes de communication sa (enhancements since 2016 and simple installer with configuration options)  
(c) 2017-2021 NetKnights GmbH
(c) 2015-2016 ArcadeJust ("RDP only" enhancement)  
(c) 2013-2015 Last Squirrel IT  

Current build: 5.8.4.0 (2021-11-18)

The binary download page is available here : https://download.multiotp.net/credential-provider/ (download link are at the bottom of the page)

Please note that the multiOTPCredentialProvider-files-only-A.B.C.D.zip zipped file contains only the DLL in x64 format.

[![Donate via PayPal](https://img.shields.io/badge/donate-paypal-87ceeb.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&currency_code=USD&business=paypal@sysco.ch&item_name=Donation%20for%20multiOTP%20project)
*Please consider supporting this project by making a donation via [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&currency_code=USD&business=paypal@sysco.ch&item_name=Donation%20for%20multiOTP%20project)*

Visit http://forum.multiotp.net/ for additional support.


multiOTP Credential Provider for multiOTP supporting Windows 7/8/8.1/10/2012(R2)/2016/2019
- support MSI deployement with MST transform file
- supports both local and domain users
- forced OTP check for RDP
- forced or disabled check of OTP for local logons
- client executable of multiOTP is automatically installed and configured
- DLL and EXE files are digitally signed
- the first strong two factor authentication solution that have cache support in order to work also offline!


PREREQUISITES
=============
- last x86 AND x64 MSVC++ redistribuable installed (Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017 and 2019)
  https://aka.ms/vs/16/release/vc_redist.x86.exe and https://aka.ms/vs/16/release/vc_redist.x64.exe
- installed multiOTP server(s)
- configured multiOTP user (multiOTP username = [domain user name] or [windows local account name] or [microsoft account name])


MANUAL INSTALLATION
===================
Launch the installer (in the installer directory) and configure the various parameters during the setup. You must have administrator access to successfully install the multiOTP Credential Provider.


MSI DEPLOYMENT
==============
Be sure that last x86 AND x64 MSVC++ redistribuable are installed.
If it's not the case, you can deploy them automatically using the four MSI provided in the vc_redist_MSI.zip file

Using Orca, you can create Transform files in order to set the settings of the credential provider.
The following properties can be set :
    MULTIOTP_TIMEOUT        Number of seconds to wait for the multiOTP server response. Default value 5.
    MULTIOTP_CACHE          0|1 1 to enable local cache.
    MULTIOTP_CPUSCREDUI     run as admin mode (0 or 1 or 2 + e or d for example 1e)
    MULTIOTP_TIMEOUTCP      Number of seconds to wait for the credentail provider to respond. Default value 60.
    MULTIOTP_TWO_STEP_HIDE_OTP 0|1 1 to force the credential to request an OTP password in a second step.
    MULTIOTP_TWO_STEP_SEND_PASSWORD 0|1 1 to enable the credential to request an OTP password by SMS.    
    MULTIOTP_CPUSLOGON      logon mode (0 or 1 or 2 + e or d for example 1e)
    MULTIOTP_CPUSUNLOCK     unlock mode (0 or 1 or 2 + e or d for example 1e)
    MULTIOTP_DISPLAYSMSLINK 0|1 1 to enable the sms link on the OTP authentication page.
    MULTIOTP_LOGINTEXT      text displayed underneath the credential logo.
    MULTIOTP_BITMAP_PATH    The complete path and filename of the bmp image. Size must be 128x128 pixels.
    MULTIOTP_URL            FQDN of the multiOTP server for example https://192.168.1.188
    MULTIOTP_SECRET         Secret shared with the smultiOTP server.
    MULTIOTP_OTP_TEXT       Text displayed in the OTP field.
    MULTIOTP_OTP_HINT_TEXT  Text displayed when prompted to enter the OTP in the second step.
    MULTIOTP_OTP_FAIL_TEXT  Text displayed when OTP code is not valid.
    MULTIOTP_EXCLUDED_ACCOUNT Specify an account that should be excluded from 2FA. For example contoso\backdoor

Copy the MSI and MST files to a share which is accessible in Read-Execute for every computers

Create a GPO that applies to the selected computers, adding the following settings:
  Computer Settings > Administrative Templates > System > Logon
    Always wait for the network at computer startup and logon - Enabled

Create a second GPO that applies to the selected computers, adding the following settings:
  Computer Configuration > Policies > Administrative Templates > System > Group Policy
    Enable the Specify startup policy processing wait time. Set Amount of time to wait (in seconds): = 120

If x86 AND x64 MSVC++ redistributable are not already installed on those computers,
create a GPO to deploy the 4 x86 AND x64 MSVC++ redistribuable files.

Finaly, create a GPO that applies to the selected computers to deploy the MSI with its MST file

To force to apply the GPO on the selected computers:
gpupdate /force /boot on each computer, using administrator privilege


LOCAL ONLY STRONG AUTHENTICATION INSTALLATION
=============================================
1) Install the multiOTP Credential Provider, which contains also multiOTP inside.
2) Using the wizard, answer to the different questions
3) To disable the Credential Provider, uninstall it from Windows,
   or execute multiOTPCredentialProvider-unregister.reg


CENTRALIZED STRONG AUTHENTICATION INSTALLATION (with cache support)
===================================================================
1) First, install a multiOTP server (commercial or open source edition).
   (https://www.multiOTP.com or https://www.multiOTP.net)
2) On each client, install the multiOTP Credential Provider.
3) Using the wizard, type the URL of the multiOTP server(s).
4) To disable the Credential Provider, uninstall it from Windows,
   or execute multiOTPCredentialProvider-unregister.reg


UNINSTALLATION
==============
- Uninstall the multiOTP Credential Provider using the regular uninstallation procedure, or launch the file multiOTPCredentialProvider-unregister.reg (you must have administrator access).


TECHNICAL DETAILS
=================
- the credential provider DLL (multiOTPCredentialProvider.dll) is installed in the system folder \Windows\System32
- the credential provider options are stored in the following registry key
  (registry entries have priority over multiotp.ini file entries): HKEY_CLASSES_ROOT\CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}
- the previous registry keys (up to 5.8.1.x) are converted to the new values
- the available registry keys are
   cpus_logon                    Logon authentication type [0|1|2|3][e|d]
                                 0: relevant for remote (RDP) and local operation
                                 1: relevant for remote operation
                                 2: relevant for local operation
                                 3: relevent for remote and local operation - but multiOTP Credential Provider is completely disabled.
                                 “e”: Only the multiOTP Credential Provider is available. All other credential providers are not available.
                                 “d”: In addition all other credential providers are available.
                                 Example: cpus_logon = 0e: Only the multiOTP Credential Provider is available for Logon via remote and locally.                                 
                                 
   cpus_unlock                   Unlock authentication type [0|1|2|3][e|d]
   cpus_credui                   Authentication in Windows authentication type [0|1|2|3][e|d]
   excluded_account              Specify an account that should be excluded from 2FA. The format is required to be domainusername or computernameusername.
   login_text                    Specify the text that is displayed underneath the Credential Provider logo and on the right side where available credentials arelisted.
   multiOTPCacheEnabled          [1|0], used directly by multiOTP
   multiOTPDefaultPrefix         [Default computer/domain, default is '']. multiOTP use automatically the domain name as default, or computer
                                 name if the computer is not in a domain. You can set here a manual default computer/domain, like for example '.'
   multiOTPDisplaySmsLink        [0|1]
   multiOTPServers               [multiOTP server(s) to contact, default is 'https://192.168.1.88'], used directly by multiOTP
   multiOTPServerTimeout         [timeout in seconds before switching to the next server, default is 5], used directly by multiOTP
   multiOTPSharedSecret          [secret to connect this client to the server, default is 'ClientServerSecret'], used directly by multiOTP
   multiOTPTimeout               [timeout in seconds, default is 60]
   two_step_hide_otp             [0|1] Set to 1 if the Credential Provider should ask for the user’s OTP in a second step. In the first step the
                                 user will only be asked for the password.
   two_step_send_password        [0|1] Set to 1 if the Credential Provider should send the user’s password to the multiOTP server
   two_step_send_empty_password  [0|1] Set to 1 if the Credential Provider should send an empty password to the multiOTP server
   otp_text                      Speficy the text that is displayed in the OTP input field. Usually this is “One-Time Password”, but you can change it
                                 to any other value you like.
   otp_hint_text                 Speficy the text that is displayed when prompted to enter the OTP in the second step.
   otp_fail_text                 Specify a custom text that is shown when the OTP verification failed.
   v1_bitmap_path                The complete path and filename of a bitmap image. This is a customized login image. The image must be a version 3
                                 Windows BMP file with a resolution of 128x128 pixels.


THANKS TO
=========
- NetKnights GmbH
- ArcadeJust ("RDP only" enhancement)
- LastSquirrelIT (initial implementation)
- All contributors with bugs annoucements and improvements requests


Report if you have any problems or questions regarding this app.


CHANGE LOG OF RELEASED VERSIONS
===============================
```
2021-09-14 5.8.4.0 FIX: multiOTPServerTimeout in now saved in a DWORD
                   FIX: Upgrade from a previous MSI installation without uninstall and reinstall
2021-09-14 5.8.3.0 ENH: Allow again a tile image in the same folder of the DLL
                   ENH: Remote server is optional again
2021-08-19 5.8.2.9 ENH: MSI deployment supported
                   ENH: password expiration is now managed
                   ENH: password must not be typed twice anymore
2021-03-14 5.8.1.1 FIX: In some cases, the HOTP/TOTP was not well computed (in the multiOTP.exe companion)
2020-09-26 5.8.0.3 FIX: vcruntime140.dll has been removed from PHP subfolder
2020-08-31 5.8.0.0 ENH: Integration of last multiOTP.exe
                   FIX: Registry entries are read protected against regular users
2019-11-26 5.6.1.6 ENH: Silent install supported (WARNING! No test will be done, be sure the regitry parameters are correct !)
2019-10-23 5.6.1.5 FIX: Better handling of parameters in debug mode
                   FIX: swprintf_s problem with special chars (thanks to anekix)
                   ENH: Optional manual default computer/domain setup
                   ENH: PHP 7.3 used in the one single file
2019-01-25 5.4.1.6 FIX: Username with space are now supported
                   ENH: Added integrated Visual C++ 2017 Redistributable installation
2018-09-14 5.4.0.1 FIX: Better domain name and hostname detection
                   FIX: The cache lifetime check process was buggy since 5.3.0.3
                   ENH: multiOTP Credential Provider files and objects have been reorganized
2018-08-26 5.3.0.3 FIX: Users without 2FA token are now supported
2018-08-21 5.3.0.0 FIX: Save flat domain name in the registry. While offline, use this value instead of asking the DC
                   ENH: Enigma Virtual Box updated to version 9.00 (to create the special all-in-one-file)
                   ENH: PHP 7.2.8 used in the one single file
                   ENH: The multiOTP timeout (how long the Credential Provider wait a response
                        from the multiOTP process) is now 60 seconds by default (instead of 10)
2018-03-11 5.2.0.0 ENH: New implementation from scratch
2018-03-05 5.1.0.8 ENH: Enigma Virtual Box updated to version 8.10 (to create the special all-in-one-file)
2018-02-27 5.1.0.7 FIX: [Receive an OTP by SMS] link is now fixed for Windows 10
2018-02-26 5.1.0.6 ENH: Credential Provider registry entries are now always used when calling multiOTP.exe
2018-02-21 5.1.0.5 FIX: To avoid virus false positive alert, multiOTP.exe is NO more packaged in one single file
                        using Enigma, a php folder is now included in the multiOTP folder
                   FIX: multiOTPOptions registry entry is now useless is ignored
2018-02-21 5.1.0.4 ENH: Credential Provider registry entries are used if available
2018-02-19 5.1.0.3 ENH: Setup wizard has one more page for better layout
                   ENH: Options stored in the multiOTPOptions registry are read and have more priorities than config file
                   ENH: Login title can be customized using the multiOTPLoginTitle registry
                   ENH: Tile image can be customized by saving a 128x128 bmp in the file [multiOTPPath]\multiotp.bmp
                   ENH: The default installation folder is now [ProgramFiles]\multiOTP
2017-12-11 5.0.6.2 ENH: [Receive an OTP by SMS] link can be displayed or not (option during installation)
                   ENH: UPN username format can be sent to the multiOTP server (by default, legacy username)
                   ENH: Better documentation
2017-12-04 5.0.6.1 FIX: [Synchronize OTP] link removed (useless, synchronization is done automatically by typing OTP1 + [space] + OTP2)
                   ENH: Default domain name support
                   ENH: User can request an SMS code using a command link
2017-11-10 5.0.6.0 ENH: Specific Credential Provider mode in the CLI version
2017-11-05 5.0.5.9 ENH: Full support for login@domain.name UPN notation (AD/LDAP should be synchronized using the userPrincipalName instead of sAMAccountName identifier)
2017-11-04 5.0.5.6 FIX: Removed digit OTP only check for the OTP field
                   ENH: Friendly name of the second factor field renamed from PIN to OTP
2017-06-02 5.0.4.6 FIX: Fixed default folder detection for the multiotp.exe file
2016-11-04 5.0.2.6 ENG: First public release with an installer, based on hard work done by Last Squirrel IT and ArcadeJust
```
