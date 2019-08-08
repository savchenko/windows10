Cheat-sheet for a single-user Windows 10 installation.  
As you might have noticed, things are a little ad-hoc.

If you are looking for something reproducible and more of a \*nix flavour, check-out the [Playbook](https://github.com/stoptracking/playbook).
# Before install
1. Recognize that you are dealing with the closed-source operating system that has useful features and hostile elements simultaneously:

> Automatic learning enables the collection and storage of text and ink written by the user in order to help adapt handwriting recognition to the vocabulary and handwriting style of the user. 
> 
> Text that is collected includes all outgoing messages in Windows Mail, and MAPI enabled email clients, as well as URLs from the Internet Explorer browser history. The information that is stored includes word frequency and new words not already known to the handwriting recognition engines (for example, proper names and acronyms).
>
> Deleting email content or the browser history does not delete the stored personalization data. Ink entered through Input Panel is collected and stored. 

2. Un-plug ethernet if present, disable WiFi.
3. Enable UEFI-native boot, "Secure boot", DEP, VTx/VT-d. 

# After
1. If necessary, install GPU drivers using offline installer.
2. Turn on "controlled folder access" and "core isolation".
3. Enable "Windows Sandbox" and "Windows Defender App Guard" in "Windows features".
4. Use [DG readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337).  
   1. Temporarily change execution policy for PowerShell scripts:  
   `Set-ExecutionPolicy -ExecutionPolicy AllSigned`  
   1. Check current status:  
   `.\DG_Readiness_tool_v3.4.ps1 -Ready`  
   1. Enable:  
   `.\DG_Readiness_tool_v3.4.ps1 -Enable`  
   1. Looks like this?  
   ![](https://i.imgur.com/QsaDuOV.png)
   1. Good. Don't forget to switch exec.policy back:  
   `Set-ExecutionPolicy -ExecutionPolicy Restricted`  
5. Use O&O AppBuster and ShutUP instead of messing-up with multitude of GPOs manually.
6. Run these from `cmd` instead of PowerShell:    

Cortana: 
```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
```
3D paint:  
```powershell
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )
```
Error reporting:
```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
```
Disable LLMNR (alternatively, can be done via GPO)
```powershell
reg add  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient”
reg add  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient” /v ” EnableMulticast” /t REG_DWORD /d “0” /f
```
Don't enforce updates:
```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```
Don't call home on every boot to check the license:
```powershell
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
```
Disable sync:
```powershell
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
```
Disable Windows tips:
```powershell
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
```
Limit PTR requests:
```powershell
reg add  "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip" /v DisableReverseAddressRegistrations /t REG_DWORD /d 1 /f
```
7. Configure minimal Windows Firewall (drop all incoming, allow core networking and other services to taste).  
Don't forget that `svchost` will need an access to use WinUpdate.
9. Edit BitLocker-related GPOs:
   1. Enable "enhanced pin" - allows to use extended character set
   1. Enable PCR banks to taste.
10. Use `manage-bde` to set-up BitLocker and add/remove recovery agents.  
_Tip of the day:_ Add file protectors instead of the pre-generated numerical sequences.
11. Plug back ethernet, update system and "Windows Store" apps.
8. `choco install miniwall` and configure per-application network access.
9. `choco install pgp4win`
   1. Import pubkey, insert smart-card.
   3. Open `kleopatra`, Tools &rarr; Manage Smartcards, ensure yours is present.
   4. Do not close Kleopatra.
   5. Issue `gpg.exe --card-status` to refresh the SCDaemon.
   6. Press F5 in Kleopatra, assuming pubkey corresponds to private key stored on the card, relevant line will become highlighted with in bold.
   7. Change trust level of your own certificate to ultimate.
10. Adjust content of system CA as necessary:
![noliability](https://user-images.githubusercontent.com/300146/61441050-f8b60880-a983-11e9-9188-9af5941b4147.png)
11. Explorer tweaks to remove unnecessary cruft:
```reg
[-HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing]
[-HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}]
[-HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo]
[-HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing]
[-HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing]
[-HKEY_CLASSES_ROOT\Directory\shellex\CopyHookHandlers\Sharing]
[-HKEY_CLASSES_ROOT\Directory\shellex\PropertySheetHandlers\Sharing]
[-HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing]
[-HKEY_CLASSES_ROOT\Drive\shellex\PropertySheetHandlers\Sharing]
[-HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Library Location]
[-HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen]
[-HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing]
[-HKEY_CLASSES_ROOT\Microsoft.Website\ShellEx\ContextMenuHandlers\PintoStartScreen]
[-HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo]
[-HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing]
[-HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen]
[-HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location]
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked]
"{1d27f844-3a1f-4410-85ac-14651078412d}"=""
"{7AD84985-87B4-4a16-BE58-8B72A5B390F7}"="Play to Menu"
```
15. Install necessary drivers.
16. Enable "Early Launch Antimalware" GPO:
![2019-07-26 12_19_27-Boot-Start Driver Initialization Policy](https://user-images.githubusercontent.com/300146/61922498-d46bb480-af9f-11e9-9039-be001136de1c.png)
17. Check your current PS execution policy:
```powershell
> Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser      Restricted
 LocalMachine      Restricted
 ```
18. Create profile:
```powershell
New-Item -path $profile -type file -force
```
19. Add handy alias for Yubikey OTP, this goes into `Microsoft.PowerShell_profile.ps1`
```powershell
function yocmd {
    $token = cmd /c "$env:Programfiles\Yubico\YubiKey Manager\ykman.exe" oath code $args
    $token_value = $token.split(" ")
    Set-Clipboard -Value $token_value[2]
}
Set-Alias -Name yo -Value yocmd
```
20. Enable DNSSEC in DNS client.
Local GPO &rarr; Windows Settings &rarr; Name Resolution Policy.
![2019-08-08 21_17_36-Window](https://user-images.githubusercontent.com/300146/62701837-63f37780-ba24-11e9-9d0b-c1062d7f4ad1.png)

# TODO

1. Limit talkativeness of the `svchost.exe `
