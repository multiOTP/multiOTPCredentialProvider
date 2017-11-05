param (
    [Parameter(Mandatory=$true)] [string] $multiOTPPath,
    [Parameter(Mandatory=$true)] [bool] $multiOTPRDPOnly,
    [Parameter(Mandatory=$true)] [int] $multiOTPTimeout
)

$SelfDir = Split-Path $MyInvocation.InvocationName
& "$SelfDir\uninstall.ps1"

$clsid='{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}'

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | out-null

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid" -Value 'multiOTPCredentialProvider' | out-null
New-Item -Path "HKCR:\CLSID\$clsid" -Value 'multiOTPCredentialProvider'  | out-null
New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'string' -Name 'multiOTPPath' -Value $multiOTPPath | out-null
if ($multiOTPRDPOnly) {
    New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'multiOTPRDPOnly' -Value 1 | out-null
} else {
    New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'multiOTPRDPOnly' -Value 0 | out-null
}
New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'multiOTPTimeout' -Value $multiOTPTimeout | out-null

New-Item -Path "HKCR:\CLSID\$clsid\InprocServer32" -Value "${SelfDir}\multiOTPCredentialProvider.dll" | out-null
New-ItemProperty -Path "HKCR:\CLSID\$clsid\InprocServer32" -PropertyType 'string' -Name 'ThreadingModel' -Value 'Apartment' | out-null

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\$clsid" -Value 'multiOTPCredentialProvider' | out-null
