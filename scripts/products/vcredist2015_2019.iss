; Patched for offline installation and for 2015-2019
; requires Windows 10, Windows 7 Service Pack 1, Windows 8, Windows 8.1, Windows Server 2003 Service Pack 2, Windows Server 2008 R2 SP1, Windows Server 2008 Service Pack 2, Windows Server 2012, Windows Vista Service Pack 2, Windows XP Service Pack 3
; https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads

[CustomMessages]
vcredist2015_2019_title=Visual C++ 2015-2019 Redistributable (x86)
vcredist2015_2019_title_x64=Visual C++ 2015-2019 Redistributable (x64)
vcredist2015_2019_title_arm64=Visual C++ 2015-2019 Redistributable (ARM64)

vcredist2015_2019_size=13.7 MB
vcredist2015_2019_size_x64=14.4 MB
vcredist2015_2019_size_arm64=6.67 MB

vcredist2015_2019_exe=vc_redist.x86.exe
vcredist2015_2019_exe_x64=vc_redist.x64.exe

[Files]
;includes vc_redist.x64.exe and vc_redist.x86.exe in setup executable so that we don't need to download it
Source: "redis\vc_redist.x64.exe"; Flags: dontcopy; Check: Is64BitInstallMode
Source: "redis\vc_redist.x86.exe"; Flags: dontcopy; Check: not Is64BitInstallMode

[Code]
const

    vcredist2015_2019_url = 'https://aka.ms/vs/16/release/vc_redist.x86.exe';
    vcredist2015_2019_url_x64 = 'https://aka.ms/vs/16/release/vc_redist.x64.exe';
    vcredist2015_2019_url_arm64 = 'https://aka.ms/vs/16/release/VC_redist.arm';

    vcredist2015_2019_upgradecode = '{65E5BD06-6392-3027-8C26-853107D3CF1A}';
    vcredist2015_2019_upgradecode_x64 = '{36F68A90-239C-34DF-B58C-64B30153CE35}';
    vcredist2015_2019_upgradecode_arm64 = '{????}';

procedure vcredist2015_2019(minVersion: string);
begin
    if (Is64BitInstallMode) then begin
        ExtractTemporaryFile('vc_redist.x64.exe');
    end;
    
    // Always extract x86, as it is still used by a lot of tools
    ExtractTemporaryFile('vc_redist.x86.exe');

	if (not IsIA64()) then begin
        if (Is64BitInstallMode) then begin
            if (not msiproductupgrade(vcredist2015_2019_upgradecode_x64, minVersion)) then
                AddProduct(CustomMessage('vcredist2015_2019_exe_x64'),
                    '/passive /norestart',
                    CustomMessage('vcredist2015_2019_title_x64'),
                    CustomMessage('vcredist2015_2019_size_x64'),
                    vcredist2015_2019_url_x64,
                    false, false, false);
        end;
		if (not msiproductupgrade(vcredist2015_2019_upgradecode, minVersion)) then
			AddProduct(CustomMessage('vcredist2015_2019_exe'),
				'/passive /norestart',
				CustomMessage('vcredist2015_2019_title'),
				CustomMessage('vcredist2015_2019_size'),
				vcredist2015_2019_url,
				false, false, false);
	end;
    
end;

[Setup]
