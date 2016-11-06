; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define MyAppName "multiOTP Credential Provider"
#define MyAppVersion "5.0.2.6"
#define MyAppPublisher "SysCo systemes de communication sa"
#define MyAppURL "http://www.multiotp.com/"
#define MyAppCopyright "Copyright (c) 2010-2016 SysCo / ArcadeJust / LastSquirrelIT (Apache License)"

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
VersionInfoVersion={#MyAppVersion}
VersionInfoCopyright={#MyAppCopyright}
VersionInfoProductName={#MyAppName}
DefaultDirName={sd}\multiOTP
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\multiotp.exe
DisableProgramGroupPage=yes
OutputDir=D:\Data\projects\multiotp\multiOTPCredentialProvider\installer
OutputBaseFilename=multiOTPCredentialProvider
SetupIconFile=D:\Data\projects\multiotp\ico\multiOTP.ico
Compression=lzma
SolidCompression=yes
; "ArchitecturesInstallIn64BitMode=x64" requests that the install be
; done in "64-bit mode" on x64, meaning it should use the native
; 64-bit Program Files directory and the 64-bit view of the registry.
; On all other architectures it will install in "32-bit mode".
ArchitecturesInstallIn64BitMode=x64
; Note: We don't set ProcessorsAllowed because we want this
; installation to run on all architectures (including Itanium,
; since it's capable of running 32-bit code too).

; Signing options
;SignTool=standard
;SignedUninstaller=yes

[Languages]
;Name: "english"; MessagesFile: "compiler:Default.isl"
;Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Files]
; NOTE: Don't use "Flags: ignoreversion" on any shared system files
Source: "stable\multiotp.exe"; DestDir: "{app}"; Flags: ignoreversion; AfterInstall: AfterInstallProcedure;
Source: "stable\x64\multiOTPCredentialProvider.dll"; DestDir: "{sys}"; Flags: ignoreversion; Check: Is64BitInstallMode;
Source: "stable\i386\multiOTPCredentialProvider.dll"; DestDir: "{sys}"; Flags: ignoreversion; Check: not Is64BitInstallMode;

[Icons]
Name: "{group}\{cm:ProgramOnTheWeb,{#MyAppName}}"; Filename: "{#MyAppURL}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Registry]
; Imported Registry File: "D:\Data\projects\multiotp\multiOTPCredentialProvider\register.reg"
Root: "HKLM"; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}"; ValueType: string; ValueData: "multiOTPCredentialProvider"; Flags: uninsdeletekey
Root: "HKLM"; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}"; ValueType: string; ValueData: "multiOTPCredentialProvider"; Flags: uninsdeletekey
Root: "HKCR"; Subkey: "CLSID\{{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}\InprocServer32"; ValueType: string; ValueData: "multiOTPCredentialProvider.dll"; Flags: uninsdeletekey
Root: "HKCR"; Subkey: "CLSID\{{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}\InprocServer32"; ValueType: string; ValueName: "ThreadingModel"; ValueData: "Apartment"; Flags: uninsdeletekey
Root: "HKCR"; Subkey: "CLSID\{{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}"; ValueType: string; ValueData: "multiOTPCredentialProvider"; Flags: uninsdeletekey
Root: "HKCR"; Subkey: "CLSID\{{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}"; ValueType: string; ValueName: "multiOTPPath"; ValueData: "{app}\"; Flags: uninsdeletekey


[CustomMessages]
ProgramOnTheWeb=%1 on the Web
UninstallProgram=Uninstall %1
multiOTPserversLabel=URL of your multiOTP server(s), separated by semi-colons
multiOTPServersSample=Example: https://192.168.1.88 ; https://192.168.1.89:44443
multiOTPconfiguration=multiOTP configuration
multiOTPconfigurationDescription=Type the needed multiOTP server information, then click Next.
multiOTPServerTimeoutLabel=Timeout (in seconds) before switching to the next server
multiOTPSharedSecretLabel=Secret shared with your multiOTP server(s)

;french.ProgramOnTheWeb=%1 sur Internet
;french.UninstallProgram=Désinstaller %1
;french.multiOTPserversLabel=URL de votre/vos serveur(s) multiOTP, séparés par un point-virgule


[Code]
var
  testPage: TWizardPage;
  testDone: Boolean;
  testSuccess: Boolean;
  testButton: TNewButton;
  testButtonResult: TNewStaticText;
  credentialProviderState: TNewStaticText;
  credentialProviderInstalled: Boolean;
  multiOTPversion: TNewStaticText;

  testUsernameEdit: TEdit;
  testPasswordEdit: TEdit;
  testOtpdEdit: TEdit;

  multiOTPServers: String;
  multiOTPServerTimeout: Cardinal;
  multiOTPSharedSecret: String;
  multiOTPCacheEnabled: Cardinal;
  multiOTPRDPOnly: Cardinal;
  multiOTPTimeout: Cardinal;

  multiOTPServersEdit: TEdit;
  multiOTPServerTimeoutEdit: TEdit;
  multiOTPSharedSecretEdit: TEdit;
  multiOTPCacheEnabledCheckBox: TCheckBox;
  multiOTPRDPOnlyCheckBox: TCheckBox;
  multiOTPTimeoutEdit: TEdit;

procedure AfterInstallProcedure;
var
  ResultCode: Integer;
  TmpFileName: string;
  ExecStdout: AnsiString;
begin
  multiOTPServers := multiOTPServersEdit.Text;
  RegWriteStringValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPServers', multiOTPServers);

  multiOTPServerTimeout := StrToIntDef(multiOTPServerTimeoutEdit.Text, multiOTPServerTimeout);
  RegWriteDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPServerTimeout', multiOTPServerTimeout);

  multiOTPSharedSecret := multiOTPSharedSecretEdit.Text;
  RegWriteStringValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPSharedSecret', multiOTPSharedSecret);

  if (cbChecked = multiOTPCacheEnabledCheckBox.State) then begin
    multiOTPCacheEnabled := 1;
  end else begin
    multiOTPCacheEnabled := 0;
  end;
  RegWriteDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPCacheEnabled', multiOTPCacheEnabled);

  if (cbChecked = multiOTPRDPOnlyCheckBox.State) then begin
    multiOTPRDPOnly := 1;
  end else begin
    multiOTPRDPOnly := 0;
  end;
  RegWriteDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPRDPOnly', multiOTPRDPOnly);

  multiOTPTimeout := StrToIntDef(multiOTPTimeoutEdit.Text, multiOTPTimeout);
  RegWriteDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPTimeout', multiOTPTimeout);

  // multiOTP configuration
  if Not Exec(ExpandConstant('{app}\multiotp.exe'), '-config server-secret='+multiOTPSharedSecret+' server-cache-level='+IntToStr(multiOTPCacheEnabled)+' server-timeout='+IntToStr(multiOTPServerTimeout)+' server-url='+multiOTPServers+'', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
    MsgBox('Error during multiOTP configuration', mbCriticalError, MB_OK);
    // MsgBox(SysErrorMessage(ResultCode), mbInformation, MB_OK);
    ResultCode := 99;
  end;

  TmpFileName := ExpandConstant('{tmp}') + '\multiotp_version.txt';
  Exec('cmd.exe', '/C '+ExpandConstant('{app}\multiotp.exe')+' -version > "' + TmpFileName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if (LoadStringFromFile(TmpFileName, ExecStdout)) then begin
    multiOTPversion.Caption := ExecStdout;
  end;
  DeleteFile(TmpFileName);
end;

procedure CreateSetupPage;
var
  Page: TWizardPage;
  multiOTPServersLabel: TNewStaticText;
  multiOTPServersSample: TNewStaticText;
  multiOTPServerTimeoutLabel: TNewStaticText;
  multiOTPSharedSecretLabel: TNewStaticText;
  multiOTPSharedSecretSample: TNewStaticText;
  multiOTPSharedSecretSample2: TNewStaticText;
  multiOTPTimeoutLabel: TNewStaticText;

  pageTop: Integer;
  pageLeft: Integer;

begin
  pageTop := 0;
  pageLeft := 0;

  // Create the page
  Page := CreateCustomPage(wpSelectTasks,
    ExpandConstant('{cm:multiOTPconfiguration}'),
    ExpandConstant('{cm:multiOTPconfigurationDescription}'));


  multiOTPServersLabel := TNewStaticText.Create(Page);
  with multiOTPServersLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsBold];
    Caption := ExpandConstant('{cm:multiOTPServersLabel}');
    Parent := Page.Surface;
  end;
  pageTop := pageTop + multiOTPServersLabel.Height + ScaleY(2);

  multiOTPServersSample := TNewStaticText.Create(Page);
  with multiOTPServersSample do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsItalic];
    Caption := ExpandConstant('{cm:multiOTPServersSample}');
    Parent := Page.Surface;
  end;
  pageTop := pageTop + multiOTPServersSample.Height + ScaleY(2);

  multiOTPServersEdit := TEdit.Create(Page);
  with multiOTPServersEdit do
  begin
    Parent := Page.Surface;
    Left := pageLeft;
    Top := pageTop;
    Width := Page.SurfaceWidth - Left;
    Text := multiOTPServers;
  end;
  pageTop := pageTop + multiOTPServersEdit.Height + ScaleY(4);

  multiOTPServerTimeoutLabel := TNewStaticText.Create(Page);
  with multiOTPServerTimeoutLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Caption := ExpandConstant('{cm:multiOTPServerTimeoutLabel} : ');
    Parent := Page.Surface;
  end;

  multiOTPServerTimeoutEdit := TEdit.Create(Page);
  with multiOTPServerTimeoutEdit do
  begin
    Parent := Page.Surface;
    Left := pageLeft + multiOTPServerTimeoutLabel.Width;
    Top := pageTop - ScaleY(2);
    Width := 2 * multiOTPServerTimeoutLabel.Height;
    Text := IntToStr(multiOTPServerTimeout);
  end;
  pageTop := pageTop + multiOTPServerTimeoutLabel.Height + ScaleY(8);

  multiOTPSharedSecretLabel := TNewStaticText.Create(Page);
  with multiOTPSharedSecretLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsBold];
    Caption := ExpandConstant('{cm:multiOTPSharedSecretLabel}');
    Parent := Page.Surface;
  end;
  pageTop := pageTop + multiOTPSharedSecretLabel.Height + ScaleY(2);

  multiOTPSharedSecretSample := TNewStaticText.Create(Page);
  with multiOTPSharedSecretSample do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsItalic];
    Caption := 'On your multiOTP server, Menu Configuration/Devices, Edit/Add a device';
    Parent := Page.Surface;
  end;
  pageTop := pageTop + multiOTPSharedSecretSample.Height;
  multiOTPSharedSecretSample2 := TNewStaticText.Create(Page);
  with multiOTPSharedSecretSample2 do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsItalic];
    Caption := 'that match the IP and subnet mask of this current Windows machine';
    Parent := Page.Surface;
  end;
  pageTop := pageTop + multiOTPSharedSecretSample2.Height + ScaleY(2);

  multiOTPSharedSecretEdit := TEdit.Create(Page);
  with multiOTPSharedSecretEdit do
  begin
    Parent := Page.Surface;
    Left := pageLeft;
    Top := pageTop;
    Width := 20 * ScaleX(multiOTPSharedSecretLabel.Font.Size);
    Text := multiOTPSharedSecret;
  end;
  pageTop := pageTop + multiOTPSharedSecretEdit.Height + ScaleY(8);

  multiOTPCacheEnabledCheckBox := TCheckBox.Create(Page);
  with multiOTPCacheEnabledCheckBox do begin
    Top := pageTop;
    Left := pageLeft;
    Width := Page.SurfaceWidth;
    Caption := 'Enable cache support on this machine if authorized by the server(s)';
    if (1 = multiOTPCacheEnabled) then begin
      State := cbChecked;
    end else begin
      State := cbUnchecked;
    end;
    Parent := Page.Surface;
  end;
  pageTop := pageTop + multiOTPCacheEnabledCheckBox.Height + ScaleY(8);

  multiOTPRDPOnlyCheckBox := TCheckBox.Create(Page);
  with multiOTPRDPOnlyCheckBox do begin
    Top := pageTop;
    Left := pageLeft;
    Width := Page.SurfaceWidth;
    Caption := 'Only RDP connection must be protected with strong authentication';
    if (1 = multiOTPRDPOnly) then begin
      State := cbChecked;
    end else begin
      State := cbUnchecked;
    end;
    Parent := Page.Surface;
  end;
  pageTop := pageTop + multiOTPRDPOnlyCheckBox.Height + ScaleY(8);

  multiOTPTimeoutLabel := TNewStaticText.Create(Page);
  with multiOTPTimeoutLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Caption := 'Timeout (in seconds) for the Credential Provider : ';
    Parent := Page.Surface;
  end;

  multiOTPTimeoutEdit := TEdit.Create(Page);
  with multiOTPTimeoutEdit do
  begin
    Parent := Page.Surface;
    Left := pageLeft + multiOTPTimeoutLabel.Width;
    Top := pageTop - ScaleY(2);
    Width := 2 * multiOTPTimeoutLabel.Height;
    Text := IntToStr(multiOTPTimeout);
  end;
  pageTop := pageTop + multiOTPTimeoutLabel.Height + ScaleY(8);


  // Add items (False means it's not a password edit)
  //WizardPage.Add('URL of your multiOTP server(s), separated with a ; if more than one : ', False);
  //WizardPage.Add('Timeout before switching to the next server : ', False);
  //WizardPage.Add('Secret shared with your server(s) (Configuration / Devices / Secret) : ', False);

  // Set initial values (optional)
  //WizardPage.Values[0] := ExpandConstant('https://192.168.1.88');
  //WizardPage.Values[1] := ExpandConstant('5');
  //WizardPage.Values[2] := ExpandConstant('MySharedSecret');

  // Read values into variables
  //multiOTPServers := WizardPage.Values[0];
  //multiOTPServerTimeout := WizardPage.Values[1];
  //multiOTPSecret := WizardPage.Values[1];

end;


procedure TestButtonClick(Sender: TObject);
var
  ResultCode: Integer;

begin
  testButtonResult.Caption := 'please wait...';
  credentialProviderState.Caption := 'please wait...';

  testDone := true;
  testSuccess := false;

  if ('' = testUsernameEdit.Text) Or ('' = testOtpdEdit.Text) Then Begin
      testButtonResult.Caption := 'Username or password is missing';
  end else if Not Exec(ExpandConstant('{app}\multiotp.exe'), testUsernameEdit.Text+' '+testOtpdEdit.Text, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
    MsgBox('System error during multiOTP test ('+IntToStr(ResultCode)+')', mbCriticalError, MB_OK);
    ResultCode := 99;
  end else begin
    if (0 = ResultCode) then begin
      testSuccess := true;
      testButtonResult.Caption := 'username and OTP validated by the multiOTP server';
    end else if (21 = ResultCode) then begin
      testButtonResult.Caption := 'User doesn''t exist';
    end else if (24 = ResultCode) then begin
      testButtonResult.Caption := 'User locked (too many tries)';
    end else if (25 = ResultCode) then begin
      testButtonResult.Caption := 'User delayed (too many tries)';
    end else if (26 = ResultCode) then begin
      testButtonResult.Caption := 'This token has already been used';
    end else if (28 = ResultCode) then begin
      testButtonResult.Caption := 'Unable to write the changes for the user';
    end else if (30 = ResultCode) then begin
      testButtonResult.Caption := 'Username or password is missing';
    end else if (98 = ResultCode) then begin
      testButtonResult.Caption := 'Wrong token length, check if a prefix is required';
    end else begin
      testButtonResult.Caption := 'Check exit code '+IntToStr(ResultCode)+', in multiOTP documentation';
    end;
  end;

  testOtpdEdit.Text := '';

  WizardForm.NextButton.Enabled := testDone

  if (testSuccess) then begin
    // testButton.Enabled := false;
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','', 'multiOTPCredentialProvider');
    RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','', 'multiOTPCredentialProvider');
    credentialProviderState.Caption := 'installed and activated';
  end else begin
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}');
    RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}');
    credentialProviderState.Caption := 'NOT activated';
  end;
end;


procedure CreateTestPage;
var
  testUsernameLabel: TNewStaticText;
  testPasswordLabel: TNewStaticText;
  testOtpLabel: TNewStaticText;
  testButtonResultLabel: TNewStaticText;
  credentialProviderStateLabel: TNewStaticText;
  multiOTPversionLabel: TNewStaticText;

  pageTop: Integer;
  pageLeft: Integer;

begin
  pageTop := 0;
  pageLeft := 0;

  // Create the page
  testPage := CreateCustomPage(wpInstalling,
    'multiOTP configuration test',
    'Check if multiOTP is working correctly.');

  testUsernameLabel := TNewStaticText.Create(testPage);
  with testUsernameLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsBold];
    Caption := 'Windows username : ';
    Parent := testPage.Surface;
  end;
  // pageTop := pageTop + testUsernameLabel.Height + ScaleY(2);

  testUsernameEdit := TEdit.Create(testPage);
  with testUsernameEdit do
  begin
    Parent := testPage.Surface;
    Left := pageLeft + testUsernameLabel.Width;
    Top := pageTop - ScaleY(2);
    Width := ScaleX(200); // testPage.SurfaceWidth - testUsernameLabel.Width;
    Text := '';
  end;
  pageTop := pageTop + testUsernameLabel.Height + ScaleY(8);

  testPasswordLabel := TNewStaticText.Create(testPage);
  with testPasswordLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsBold];
    Caption := 'Windows password : ';
    Parent := testPage.Surface;
  end;
  // pageTop := pageTop + testPasswordLabel.Height + ScaleY(2);

  testPasswordEdit := TEdit.Create(testPage);
  with testPasswordEdit do
  begin
    PasswordChar := '*';
    Parent := testPage.Surface;
    Left := pageLeft + testPasswordLabel.Width;
    Top := pageTop - ScaleY(2);
    Width := ScaleX(200); // testPage.SurfaceWidth - testPasswordLabel.Width;
    Text := '';
  end;
  pageTop := pageTop + testPasswordLabel.Height + ScaleY(8);

  testOtpLabel := TNewStaticText.Create(testPage);
  with testOtpLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Font.Style := [fsBold];
    Caption := 'OTP for this user : ';
    Parent := testPage.Surface;
  end;
  // pageTop := pageTop + testOtpLabel.Height + ScaleY(2);

  testOtpdEdit := TEdit.Create(testPage);
  with testOtpdEdit do
  begin
    PasswordChar := '*';
    Parent := testPage.Surface;
    Left := pageLeft + testOtpLabel.Width;
    Top := pageTop - ScaleY(2);
    Width := ScaleX(200); // testPage.SurfaceWidth - testOtpLabel.Width;
    Text := '';
  end;
  pageTop := pageTop + testOtpLabel.Height + ScaleY(16);

  testButton := TNewButton.Create(testPage);
  with testButton do begin
    Top := pageTop;
    Left := pageLeft;
    Caption := 'Test the multiOTP authentication to activate the Credential Provider';
    Width := testPage.SurfaceWidth - Left;
    Parent := testPage.Surface;
    OnClick := @TestButtonClick;
  end;
  pageTop := pageTop + testButton.Height + ScaleY(16);

  testButtonResultLabel := TNewStaticText.Create(testPage);
  with testButtonResultLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Caption := 'multiOTP test result : ';
    Parent := testPage.Surface;
  end;
  // pageTop := pageTop + testPasswordLabel.Height + ScaleY(2);

  testButtonResult := TNewStaticText.Create(testPage);
  with testButtonResult do
  begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft + testButtonResultLabel.Width;
    Font.Style := [fsBold];
    Caption := '...';
    Parent := testPage.Surface;
  end;
  pageTop := pageTop + testButtonResultLabel.Height + ScaleY(2);

  credentialProviderStateLabel := TNewStaticText.Create(testPage);
  with credentialProviderStateLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Caption := 'Credential Provider state : ';
    Parent := testPage.Surface;
  end;

  credentialProviderState := TNewStaticText.Create(testPage);
  with credentialProviderState do
  begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft + credentialProviderStateLabel.Width;
    Font.Style := [fsBold];
    Caption := '...';
    Parent := testPage.Surface;
  end;
  pageTop := pageTop + credentialProviderStateLabel.Height + ScaleY(24);

  pageTop := testPage.SurfaceHeight - credentialProviderStateLabel.Height;
  multiOTPversionLabel := TNewStaticText.Create(testPage);
  with multiOTPversionLabel do begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft;
    Caption := 'multiOTP library version : ';
    Font.Style := [fsItalic];
    Parent := testPage.Surface;
  end;

  multiOTPversion := TNewStaticText.Create(testPage);
  with multiOTPversion do
  begin
    AutoSize := True;
    WordWrap := False;
    Top := pageTop;
    Left := pageLeft + multiOTPversionLabel.Width;
    Font.Style := [fsItalic,fsBold];
    Parent := testPage.Surface;
  end;

end;


procedure InitializeWizard;
var
  stringValue: String;
begin
  // Default values
  multiOTPServers := 'https://192.168.1.88';
  multiOTPServerTimeout := 5;
  multiOTPSharedSecret := 'ClientServerSecret';
  multiOTPCacheEnabled := 1;
  multiOTPRDPOnly := 1;
  multiOTPTimeout := 10;

  // Read registry values if they exists
  RegQueryStringValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPServers', multiOTPServers);
  RegQueryDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPServerTimeout', multiOTPServerTimeout);
  RegQueryStringValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPSharedSecret', multiOTPSharedSecret);
  RegQueryDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPCacheEnabled', multiOTPCacheEnabled);
  RegQueryDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPRDPOnly', multiOTPRDPOnly);
  RegQueryDWordValue(HKEY_CLASSES_ROOT, 'CLSID\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','multiOTPTimeout', multiOTPTimeout);

  // credentialProviderInstalled := RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}','', stringValue);
  credentialProviderInstalled := false;

  // Create two custom pages
  CreateSetupPage;
  CreateTestPage;

  // Test variables initialization
  testDone := false;
  testSuccess := false;
end;


procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = TestPage.ID then
    begin
      if (credentialProviderInstalled) then begin
        credentialProviderState.Caption := 'installed and activated';
      end else begin
        credentialProviderState.Caption := 'NOT activated';
        RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}');
        RegDeleteKeyIncludingSubkeys(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{FCEFDFAB-B0A1-4C4D-8B2B-4FF4E0A3D978}');
      end;
      WizardForm.NextButton.Enabled := testDone;
    end;
end;
