Please note, this is a mere cheat-sheet for a single-user Windows 10 installation.  
Nothing is automated and it is unknown if it ever will be, treat accordingly.

If you are looking for something reproducible and more of a \*nix flavour, check-out the [Playbook](https://github.com/stoptracking/playbook).
# Before install
1. Pray your gods.
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
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
```
3D paint:  
```
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )
```
Error reporting:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
```
Don't enforce updates:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```
Don't call home on every boot to check the license:
```
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
```
Disable sync:
```
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
```
Disable Windows tips:
```
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
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
   7. Change trust level on your own certificate to ultimate.
