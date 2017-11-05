$clsid='{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}'

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | out-null

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid" -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\CLSID\$clsid" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\$clsid" -ErrorAction SilentlyContinue
