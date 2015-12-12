# MultiotpCPV2RDP
Credential Provider V2 (user oriented) for MultiOTP supporting Windows 8, Windows 8.1, Windows 10 and Windows Server 2012 R2.
- Forced OTP check for RDP. 
- Forced, optional or dissabled check of OTP for local logons

Prerequisitions:
- installed multiotp
- configured multiotp user (multiotp username = windows account name)

Instalation:

1. Copy MultiOTPCredentialProviderV2.dll to Windows\system32\ (check the ntfs rights for system user)
2. Edit MultiOTPPath setting in file register.reg
3. Run register.reg or manually add keys to the registry (check if the keys were successfully created)

You have just finished the default installation process and now you can go and see if the RDP logon displays MultiOTP PIN window (try to connect to your machine from another device). If you can login using your new credential provider and wanted CPV2 to only ask for the OTP when you are connecting from RDP you are done. If you would like OTP to force PIN every time user logons you can change it in the registry.reg key: MultiOTPRDPOnly. Setting it to "0" forcess OTP for local logon attempts the same as for RDP. If you would like OTP to be optional/alternative method for local logon you will have to use MultiOTPCredentialProviderV2_devel.dll (just rename it and replace the default one). Now setting MultiOTPRDPOnly=1 will also switch the local OTP to optional mode. The devel dll also has a lot more logging informations stored in C:\multiotplog.txt if you think something is not working please post your log file and I will try to help you (if you do not have C:\ drive try to map it).
