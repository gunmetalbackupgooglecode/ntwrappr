; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{6033E76D-15C5-482B-8042-4C05D1C9E542}
AppName=NT Wrapper
AppVerName=NT Wrapper 0.2
AppPublisher=Great
AppPublisherURL=http://code.google.com/p/ntwrappr
AppSupportURL=http://code.google.com/p/ntwrappr
AppUpdatesURL=http://code.google.com/p/ntwrappr
CreateAppDir=no
OutputBaseFilename=setup
Compression=lzma
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "D:\Progs\ntsystem\bin\native.exe"; DestDir: "{win}\System32"; Flags: ignoreversion
Source: "D:\Progs\ntsystem\bin\ntwrappr.dll"; DestDir: "{win}\System32"; Flags: ignoreversion
Source: "D:\Progs\ntsystem\bin\ntshell.exe"; DestDir: "{win}\System32"; Flags: ignoreversion
Source: "D:\Progs\ntsystem\bin\psxtest.exe"; DestDir: "{win}\System32"; Flags: ignoreversion
Source: "D:\Progs\ntsystem\bin\psxss.dll"; DestDir: "{win}\System32"; Flags: ignoreversion
Source: "D:\Progs\ntsystem\bin\ntconss.exe"; DestDir: "{win}\System32"; Flags: ignoreversion
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager"; ValueName: "BootExecute"; ValueType: "multisz"; ValueData: "{olddata}ntconss *"

