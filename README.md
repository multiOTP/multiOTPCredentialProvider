multiOTPCredentialProvider
==========================
multiOTP Credential Provider for multiOTP is a free implementation of a Credential Provider for the multiOTP strong two-factor authentication solution  

(c) 2016-2017 SysCo systemes de communication sa (installer and enhancements) 
(c) 2015-2016 ArcadeJust ("RDP only" enhancement) 
(c) 2013-2015 Last Squirrel IT 

Current build: 5.0.5.9 (2017-11-05)

Apache License, Version 2.0

Binary download: https://download.multiotp.net/credential-provider/

[![Donate via PayPal](https://img.shields.io/badge/donate-paypal-87ceeb.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&currency_code=USD&business=paypal@sysco.ch&item_name=Donation%20for%20multiOTP%20project)
*Please consider supporting this project by making a donation via [PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&currency_code=USD&business=paypal@sysco.ch&item_name=Donation%20for%20multiOTP%20project)*

multiOTP Credential Provider for multiOTP supporting Windows 7/8/8.1/10/2012(R2). Also supports domain users and Microsoft Account OTP (you can read about it here http://windows.microsoft.com/en-us/windows/identity-verification-apps-faq and here https://github.com/LastSquirrelIT/MultiOneTimePassword-CredentialProvider/wiki/multiOTP)
- Forced OTP check for RDP
- Forced, optional or disabled check of OTP for local logons
- client executable of multiOTP is automatically installed and configured
- multiOTP Credential Provider is only activated if the authentication test is passed successfully
- DLL and EXE files are digitally signed
- the first strong two factor authenticaton solution that have cache support in order to work also offline!

![multiOTPCredentialProvider setup](https://raw.githubusercontent.com/multiOTP/multiOTPCredentialProvider/master/screenshots/multiOTPCredentialProvider-setup.png)

![multiOTPCredentialProvider test](https://raw.githubusercontent.com/multiOTP/multiOTPCredentialProvider/master/screenshots/multiOTPCredentialProvider-test.png)

Prerequisitions:
- installed multiOTP server(s)
- configured multiOTP user (multiOTP username = windows local account name or domain user name or microsoft account name)

Installation:
- Launch the installer (in the installer directory) and set the various parameters. You must have administrator access.

Thanks to:
- ArcadeJust ("RDP only" enhancement)
- LastSquirrelIT (first version)

Report if you have any problems or questions regarding this app.


CHANGE LOG OF RELEASED VERSIONS
===============================
```
2017-11-05 5.0.5.9 SysCo/al Full support for login@domain.name UPN notation (AD/LDAP should be synchronized using the userPrincipalName instead of sAMAccountName identifier)
2017-11-04 5.0.5.6 SysCo/al Removed digit OTP only check for the OTP field
                            Friendly name of the second factor field renamed from PIN to OTP
2017-06-02 5.0.4.6 SysCo/al Fixed default folder detection for the multiotp.exe file
2016-11-04 5.0.2.6 SysCo/al First public release with an installer, based on hard work done by Last Squirrel IT and ArcadeJust
```
