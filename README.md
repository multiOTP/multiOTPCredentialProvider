multiOTPCredentialProvider
==========================
multiOTP Credential Provider for multiOTP is a free and open source implementation of a V2 Credential Provider for the multiOTP strong two-factor authentication solution (Apache License, Version 2.0)

(c) 2016-2018 SysCo systemes de communication sa (enhancements since 2016 and simple installer with configuration options)  
(c) 2015-2016 ArcadeJust ("RDP only" enhancement)  
(c) 2013-2015 Last Squirrel IT  

Current build: 5.4.0.1 (2018-09-14)

Binary download: https://download.multiotp.net/credential-provider/

Please note that the multiOTPCredentialProvider-files-only-A.B.C.D.zip zipped file contains only the DLL in both x64 and i386 format, and a special all-in-one-file multiotp.exe executable created using Enigma Virtual Box (https://enigmaprotector.com/en/downloads.html).

[![Donate via PayPal](https://img.shields.io/badge/donate-paypal-87ceeb.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&currency_code=USD&business=paypal@sysco.ch&item_name=Donation%20for%20multiOTP%20project)
*Please consider supporting this project by making a donation via [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&currency_code=USD&business=paypal@sysco.ch&item_name=Donation%20for%20multiOTP%20project)*

Visit http://forum.multiotp.net/ for additional support.


multiOTP Credential Provider for multiOTP supporting Windows 7/8/8.1/10/2012(R2)/2016.
- supports both local and domain users
- forced OTP check for RDP
- forced or disabled check of OTP for local logons
- client executable of multiOTP is automatically installed and configured
- multiOTP Credential Provider is only activated if the authentication test is passed successfully
- DLL and EXE files are digitally signed
- the first strong two factor authentication solution that have cache support in order to work also offline!

![multiOTPCredentialProvider setup1](https://raw.githubusercontent.com/multiOTP/multiOTPCredentialProvider/master/screenshots/multiOTPCredentialProvider-setup1.png)

![multiOTPCredentialProvider setup2](https://raw.githubusercontent.com/multiOTP/multiOTPCredentialProvider/master/screenshots/multiOTPCredentialProvider-setup2.png)

![multiOTPCredentialProvider test](https://raw.githubusercontent.com/multiOTP/multiOTPCredentialProvider/master/screenshots/multiOTPCredentialProvider-test.png)

![multiOTPCredentialProvider login](https://raw.githubusercontent.com/multiOTP/multiOTPCredentialProvider/master/screenshots/multiOTPCredentialProvider-login.png)


PREREQUISITES
=============
- installed multiOTP server(s)
- configured multiOTP user (multiOTP username = [domain user name] or [windows local account name] or [microsoft account name])


INSTALLATION
============
- Launch the installer (in the installer directory) and configure the various parameters during the detup. You must have administrator access to successfully install the multiOTP Credential Provider.


LOCAL ONLY STRONG AUTHENTICATION INSTALLATION
=============================================
1) Install the multiOTP Credential Provider, which contains also multiOTP inside.
2) During the installation, specify the folder on the client where the
   multiotp.exe file and folders must be installed and configured.
3) In the wizard, leave the URL of the multiOTP server(s) empty.
4) You can also choose to require a strong authentication only for RDP.
5) When you are on the test page, open a command prompt in the folder where
   multiOTP is now installed and create a new local user. Example:
   1) *multiotp -fastcreatenopin my_user*
   2) *multiotp -qrcode my_user my_qrcode.png)*
6) If the test is successful, the Credential Provider is installed.
7) To disable the Credential Provider, uninstall it from Windows,
   or execute multiOTPCredentialProvider-unregister.reg


CENTRALIZED STRONG AUTHENTICATION INSTALLATION (with cache support)
===================================================================
1) First, install a multiOTP server (commercial or open source edition).
   (https://www.multiotp.com or https://www.multiotp.net)
2) On each client, install the multiOTP Credential Provider.
3) During the installation, specify the folder on the client where the
   multiotp.exe file and folders must be installed and configured.
4) In the wizard, type the URL of the multiOTP server(s).
5) You can also choose to require a strong authentication only for RDP.
6) On the test page, test your account to be sure that everything works.
7) If the test is successful, the Credential Provider is installed.
8) To disable the Credential Provider, uninstall it from Windows,
   or execute multiOTPCredentialProvider-unregister.reg


UNATTENDED INSTALLATION
=======================
An MSI file will be available soon to mass deploy the multiOTP Credential Provider.


UNINSTALLATION
==============
- Uninstall the multiOTP Credential Provider using the regular uninstallation procedure, or launch the file multiOTPCredentialProvider-unregister.reg (you must have administrator access).


TECHNICAL DETAILS
=================
- the credential provider DLL (multiOTPCredentialProvider.dll) is installed in the system folder \Windows\System32
- the credential provider options are stored in the following registry key (registry entries have priority over multiotp.ini file entries): HKEY_CLASSES_ROOT\CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}
  - multiOTPCacheEnabled : [1|0], used directly by multiOTP
  - multiOTPDisplaySmsLink : [0|1]
  - multiOTPLoginTitle : [Login title, default is '', which displays 'multiOTP Login']
  - multiOTPPath : [X:\Path\to\multiotp\folder]
  - multiOTPPrefixPass : [0|1]
  - multiOTPRDPOnly : [0|1]
  - multiOTPServers : [multiOTP server(s) to contact, default is 'https://192.168.1.88'], used directly by multiOTP
  - multiOTPServerTimeout : [timeout in seconds before switching to the next server, default is 5], used directly by multiOTP
  - multiOTPSharedSecret : [secret to connect this client to the server, default is 'ClientServerSecret'], used directly by multiOTP
  - multiOTPTimeout : [timeout in seconds, default is 60]
  - multiOTPUPNFormat : [0|1]
- if the tile file [multiOTPPath]\multiotp.bmp exists, it will replace the default 128x128 tile image


THANKS TO
=========
- ArcadeJust ("RDP only" enhancement)
- LastSquirrelIT (initial implementation)


Report if you have any problems or questions regarding this app.


CHANGE LOG OF RELEASED VERSIONS
===============================
```
2019-09-14 5.4.0.1 SysCo/al FIX: Better domain name and hostname detection
                            FIX: The cache lifetime check process was buggy since 5.3.0.3
                            ENH: multiOTP Credential Provider has been reviewed
2018-08-26 5.3.0.3 SysCo/al FIX: Users without 2FA token are now supported
2018-08-21 5.3.0.0 SysCo/yj FIX: Save flat domain name in the registry. While offline, use this value instead of asking the DC
                   SysCo/al ENH: Enigma Virtual Box updated to version 9.00 (to create the special all-in-one-file)
                            ENH: PHP 7.2.8 used in the one single file
                            ENH: The multiOTP timeout (how long the Credential Provider wait a response from
                                 the multiOTP process) is now 60 seconds by default (instead of 10)
2018-03-05 5.1.0.8 SysCo/al ENH: Enigma Virtual Box updated to version 8.10 (to create the special all-in-one-file)
2018-02-27 5.1.0.7 SysCo/al FIX: [Receive an OTP by SMS] link is now fixed for Windows 10
2018-02-26 5.1.0.6 SysCo/al ENH: Credential Provider registry entries are now always used when calling multiOTP.exe
2018-02-21 5.1.0.5 SysCo/al FIX: To avoid virus false positive alert, multiOTP.exe is NO more packaged in one single file
                                 using Enigma, a php folder is now included in the multiOTP folder
                            FIX: multiOTPOptions registry entry is now useless is ignored
2018-02-21 5.1.0.4 SysCo/al ENH: Credential Provider registry entries are used if available
2018-02-19 5.1.0.3 SysCo/al ENH: Setup wizard has one more page for better layout
                            ENH: Options stored in the multiOTPOptions registry are read and have more priorities than config file
                            ENH: Login title can be customized using the multiOTPLoginTitle registry
                            ENH: Tile image can be customized by saving a 128x128 bmp in the file [multiOTPPath]\multiotp.bmp
                            ENH: The default installation folder is now [ProgramFiles]\multiOTP
2017-12-11 5.0.6.2 SysCo/al ENH: [Receive an OTP by SMS] link can be displayed or not (option during installation)
                            ENH: UPN username format can be sent to the multiOTP server (by default, legacy username)
                            ENH: Better documentation
2017-12-04 5.0.6.1 SysCo/al FIX: [Synchronize OTP] link removed (useless, synchronization is done automatically by typing OTP1 + [space] + OTP2)
                            ENH: Default domain name support
                            ENH: User can request an SMS code using a command link
2017-11-10 5.0.6.0 SysCo/al ENH: Specific Credential Provider mode in the CLI version
2017-11-05 5.0.5.9 SysCo/al ENH: Full support for login@domain.name UPN notation (AD/LDAP should be synchronized using the userPrincipalName instead of sAMAccountName identifier)
2017-11-04 5.0.5.6 SysCo/al FIX: Removed digit OTP only check for the OTP field
                            ENH: Friendly name of the second factor field renamed from PIN to OTP
2017-06-02 5.0.4.6 SysCo/al FIX: Fixed default folder detection for the multiotp.exe file
2016-11-04 5.0.2.6 SysCo/al ENG: First public release with an installer, based on hard work done by Last Squirrel IT and ArcadeJust
```
