[Summary](#summary)
- [Summary](#summary)
- [Rationale](#rationale)
- [Intro](#intro)
- [Before installation](#before-installation)
- [Yo](#yo)
- [Update Windows](#update-windows)

# Summary
Cheat-sheet for a single-user Windows 10 installation. As you might notice, things are a little ad-hoc.  
Level 3 baseline plus/minus some additional customizations: less network noise, focus on single-user workstation, etc.

![seccon-framework](https://user-images.githubusercontent.com/300146/63164652-3469ee00-c068-11e9-8a0a-96347d5254b0.png)

Tools used:
* MS Docs & Technet
* Wireshark and MS Network Monitor
* [GPO and Policy Analyzer](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/)
* [Intel CSME](https://downloadcenter.intel.com/download/28632/Intel-CSME-Detection-Tool)

If you are looking for something reproducible and more of a \*nix flavour, check-out the [Playbook](https://github.com/stoptracking/playbook).

# Rationale
One might rightfully ask, - "Why author decided to bother with MS product while there are much more comfortable \*nix-based operating systems?". At present, main considerations for touching the proprietary OS are:
* Ability to use well-tested FDE that it tied to TPM _and_ user-supplied secret. While it is possible to implement via `keyscript` in `/etc/crypttab`, such ~bodging~ hacking is not exactly default modus operandi of LUKS.
* Type-1 hypervisor. See below for the details on HVCI.
* Application firewall with the [WFP layer](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) that allows bulding additional rules on top of the same engine.
* Handy commercial software that is not available under Linux or \*BSD.
* Good hardware support.

# Intro
1. Recognize that you are dealing with the closed-source operating system that has useful features and hostile elements simultaneously. To give you an idea on how chilly MS world is different from a warm \*nix shell, this is enabled by default:

> Automatic learning enables the collection and storage of text and ink written by the user in order to help adapt handwriting recognition to the vocabulary and handwriting style of the user. 
> 
> Text that is collected includes all outgoing messages in Windows Mail, and MAPI enabled email clients, as well as URLs from the Internet Explorer browser history. The information that is stored includes word frequency and new words not already known to the handwriting recognition engines (for example, proper names and acronyms).
>
> Deleting email content or the browser history does not delete the stored personalization data. Ink entered through Input Panel is collected and stored. 

2. Be aware that you will be enabling [Hypervisor-protected code integrity (HVCI)](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity) which imposes _significant_ performance penalty on all Intel CPUs released before "7th generation" and [AMD before Ryzen 2](https://github.com/MicrosoftDocs/windows-itpro-docs/issues/3997). To quote Mark Russinovich and Alex Ionescu:

> "The Secure Kernel relies on the Mode-Based Execution Control (MBEC) feature, if present in hardware, which enhances the SLAT with a user/kernel executable bit, or the hypervisor’s software emulation of this feature, called Restricted User Mode (RUM)." 

![HVCI](https://user-images.githubusercontent.com/300146/64527010-019fd680-d344-11e9-9cbe-08fe004c1baf.png)

3. In addition to the above, you are likely to experience performance hit from countermeasures against [2019 side-channel attacks](https://www.intel.com/content/www/us/en/architecture-and-technology/engineering-new-protections-into-hardware.html). Down the track, you can obtain CPU stepping by running `wmic cpu get caption` in PowerShell and, if using Intel, comparing against [this list](https://www.intel.com/content/www/us/en/architecture-and-technology/engineering-new-protections-into-hardware.html).

# Before installation
3. Un-plug ethernet if present, disable WiFi.
3. Install latest BIOS from a vendor or flash Coreboot with the latest CPU microcode.
4. Strip Intel ME using [metool](https://github.com/corna/me_cleaner) or be ready to assess/update/patch/ using CSME, link above.
4. Enable UEFI-native boot, "Secure boot", DEP, VTx/VT-d (or AMD-V).
5. In case you are using Intel&trade; CPU, consider disabling HyperThreading&reg;.
   1. On certain SMB platforms IntelTXT&reg; is enabled and not exposed in BIOS which may prevent from disabling HT.
   2. This, however, sometimes can be circumvented by using vendor's mass-provisioning tool. For example, HP:
   ```powershell
   .\BiosConfigUtility64.exe /setvalue:"Trusted Execution Technology (TXT)","Disable" /cpwdfile:"pwd.bin" /verbose
   ```
   ```xml
	<BIOSCONFIG Version="" Computername="WIN" Date="2019/08/31" Time="21:23:19" UTC="10">
		<SUCCESS msg="Successfully read password from file" />
		<SETTING changeStatus="skip" name="Trusted Execution Technology (TXT)" returnCode="18">
			<OLDVALUE><![CDATA[Enable]]></OLDVALUE>
			<VALUE><![CDATA[Disable]]></VALUE>
		</SETTING>
		<SUCCESS msg="No errors occurred" />
		<Information msg="BCU return value" real="0" translated="0" />
	</BIOSCONFIG>
    ```
    3. Finally, disable HT:
    ```powershell
    .\BiosConfigUtility64.exe /setvalue:"Intel (R) HT Technology","Disable" /cpwdfile:"pwd.bin" /l /verbose
    ```
# During installation
1. Keep machine disconnected from the Internet
2. Opt-out from personal data collection when asked

# After installation
1. If necessary, install GPU drivers using _verified_ offline installer, use DCH package if possible.
2. From `./Tools/dgreadiness_v3.6`, launch [DG readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337).  
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

3. Check if Hyper-V scheduler needs an adjustment to mitigate CVE-2018-3646. 
   1. Read [Windows guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-au/help/4457951/windows-guidance-to-protect-against-speculative-execution-side-channel)
   2. Determine current scheduler:
   ```powershell
   Get-WinEvent -FilterHashTable @{ProviderName="Microsoft-Windows-Hyper-V-Hypervisor"; ID=2} | select -Last 1
   ```
   4. If the command above has returned "root" aka 0x4, execute `bcdedit /set hypervisorschedulertype core` from elevated shell and reboot.
   5. Configure each VM to take advantage of `core` by setting their hardware thread count per core to two:
   ```powershell
   Set-VMProcessor -VMName <VMName> -HwThreadCountPerCore 2
   ```

## Setting-up the machine
1. Review its code and once satisfied, run the  `./Scripts/cmd.bat`.
2. Import initial firewall policy from `./Settings/WDF`
3. Edit BitLocker-related GPOs:
   1. Enable "enhanced pin" - allows to use extended character set
   2. Enable PCR banks to taste.
4.  Use `manage-bde` to set-up BitLocker and add/remove recovery agents.  
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
Windows Registry Editor Version 5.00
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
  CurrentUser    RemoteSigned
 LocalMachine      Restricted
 ```
18. Create profile:
```powershell
New-Item -path $profile -type file -force
```
19. Add handy alias for Yubikey OTP, this goes into `Microsoft.PowerShell_profile.ps1`
```powershell
# Yo
function yocmd {
    $token = cmd /c "$env:Programfiles\Yubico\YubiKey Manager\ykman.exe" oath code $args
    $token_value = $token.split(" ")
    Set-Clipboard -Value $token_value[2]
}
Set-Alias -Name yo -Value yocmd
```
20. Let's limit service host's unstoppable desire to talk with the outside world.  
   - Create rule named "block_service_host" that either prevents `%SystemRoot%\System32\svchost.exe` from any connections or just denies 80/443 ports access. Latter is assuming you know why it needs to access other ports.
   - Add to your profile:  
   ```powershell
# Update Windows
function updatecmd {
    $enabled = Get-NetFirewallRule -DisplayName block_service_host | Select-Object -Property Action
    if ($enabled -like "*Block*") {
        Set-NetFirewallRule -DisplayName block_service_host -Action Allow
    }
    else {
    }
    Get-WindowsUpdate -Verbose -Install -AcceptAll
    # Start-Sleep -s 5
    Read-host “Press Enter to continue...”
    Set-NetFirewallRule -DisplayName block_service_host -Action Block
}

function sudo_updatecmd {
    Start-Process -FilePath powershell.exe -ArgumentList {updatecmd} -verb RunAs
}

Set-Alias -Name update -Value sudo_updatecmd
```
   - Now, when you'd like to update Windows, just run `update` from the PS.
     This would request for an elevated session, temporarily allow svchost to communicate, download and install necessary packages and finally turn the blocker rule back on.
21. Let's add [attack surface reduction rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/attack-surface-reduction-exploit-guard#attack-surface-reduction-rules).
```powershell
$asrs = @("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block executable content from email client and webmail
           "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Block all Office applications from creating child processes
           "3B576869-A4EC-4529-8536-B80A7769E899", # Block Office applications from creating executable content
           "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", # Block Office applications from injecting code into other processes
           "D3E037E1-3EB8-44C8-A917-57927947596D", # Block JavaScript or VBScript from launching downloaded executable content
           "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Block execution of potentially obfuscated scripts
           "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", # Block Win32 API calls from Office macro
           "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
           "c1db55ab-c21a-4637-bb3f-a12568109d35", # Use advanced protection against ransomware
           "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
           "d1e49aac-8f56-4280-b9ba-993a6d77406c", # Block process creations originating from PSExec and WMI commands
           "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", # Block untrusted and unsigned processes that run from USB
           "26190899-1602-49e8-8b27-eb1d0a1ce869", # Block Office communication application from creating child processes
           "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", # Block Adobe Reader from creating child processes
           "e6db77e5-3df2-4cf1-b95a-636979351e5b") # Block persistence through WMI event subscription 
foreach ($rule in $asrs) {
	Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Enabled
}
```
22. Check that rules are applied correctly:
```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
```
23. Check antimalware:
```powershell
Get-MpComputerStatus | Select-Object -Property "*enabled*"

AMServiceEnabled          : True
AntispywareEnabled        : True
AntivirusEnabled          : True
BehaviorMonitorEnabled    : True
IoavProtectionEnabled     : True
NISEnabled                : True
OnAccessProtectionEnabled : True
RealTimeProtectionEnabled : True
```
If anything from the above is disabled &mdash; investigate why and fix.

24. Enable controlled folder access:
```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled
```

25. Enable and configure [exploit mitigation options](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/customize-exploit-protection)
```powershell
Get-ProcessMitigation -System
```

26. Enable Local Security Authority (LSA) hardening:
```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
```

27. Import GPO rules and restart:
```powershell
LGPO.exe /v /g '.\{8559EB48-4AB7-436F-91E2-A45222356495}\'
```

28. Use `tools/mdstools` to assess the damage caused by [speculative execution attacks](https://mdsattacks.com/).  

29. Also, from `tools/SpeControl`:  
```powershell
Import-Module -name .\SpeculationControl.psm1
Get-SpeculationControlSettings -Verbose
```

30. To enable [CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639) mitigations, as per [MS](https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in) article,
```powershell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 8 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
```
Reboot and verify:
```powershell
Get-SpeculationControlSettings -Quiet | grep KVAS\w*SupportEnabled
KVAShadowWindowsSupportEnabled      : True
```

31. Verify Device Guard&trade; operational status:
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```


After Windows is activated, run the following to prevent it from calling home on every boot to check the license:
```powershell
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
```


# Git

1. Install git:
```powershell
choco install --force git --params "/NoGuiHereIntegration /NoShellHereIntegration"
```
2. Configure to sign commits by default:
```powershell
git config --global gpg.program "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
git config --global user.signingkey $LONG_KEY_ID
git config --global commit.gpgsign true
```

# GPG

1. Export pubkey from a (sub)key that is allowed to authenticate: `gpg.exe --export-ssh-key ID`
2. Enable Putty support: `echo "enable-putty-support" >> C:\Users\asv\AppData\Roaming\gnupg\test.conf`
3. Restart daemon: `gpg-connect-agent KILLAGENT /bye; gpg-agent.exe -v --enable-putty-support`.
4. Try to login, authenticate card as usual. Should see something like this:
![2019-08-09 21_46_11-192 168 2 202 - PuTTY](https://user-images.githubusercontent.com/300146/62778531-c49bb680-baef-11e9-8147-c34ec73c12e6.png)


# TODO

1. Selectively limit talkativeness of the `svchost.exe` (see https://github.com/henrypp/simplewall/issues/516)
2. Figure out why DNS client is spamming public with unsolicited PTR requests:  
    Try `(dns.flags.response == 0 and dns.qry.name contains "arpa")` in Wireshark.
    
    ![svchost_dns](https://user-images.githubusercontent.com/300146/62759132-a1f1a980-babf-11e9-9c3f-97819f7df1b6.png)
    
    This is currently mitigated by blocking outgoing on `svchost.exe` with the script in paragraph №21 above. Considering that it does not prevent DNS client from normal operations, I am still very much curious about WTF is going on.

3. Consider https://github.com/Microsoft/AaronLocker (_requires "Enterprise"?.._)

4. Mention separation of apps that have network access from "protected folders".

    
# Notes

Microsoft Network Monitor allows filtering on per-process basis:
```powershell
Conversation.ProcessName == "shady.exe"
```

Cleanup "MS Defender App Guard":
```cmd
wdagtool.exe cleanup
wdagtool.exe cleanup RESET_PERSISTENCE_LAYER
```

There is an in-built alternative to `shasum`:
```powershell
CertUtil -hashfile $FILE SHA1
```

Remove annoying "Git GUI here" and "Git Shell here" shortcuts added by TortoiseGit:
```reg
Windows Registry Editor Version 5.00
[-HKEY_CLASSES_ROOT\Directory\shell\git_gui]
[-HKEY_CLASSES_ROOT\Directory\shell\git_shell]
[-HKEY_CLASSES_ROOT\LibraryFolder\background\shell\git_gui]
[-HKEY_CLASSES_ROOT\LibraryFolder\background\shell\git_shell]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\background\shell\git_gui]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\background\shell\git_shell]
```

## Adobe Reader DC lockdown

```reg
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown]
"bUpdater"=dword:00000000
"bSuppressSignOut"=dword:00000001
"bToggleAdobeDocumentServices"=dword:00000001
"bToggleFillSign"=dword:00000001
"bToggleSendACopy"=dword:00000000
"bToggleAdobeSign"=dword:00000001
"bToggleManageSign"=dword:00000001
"bToggleSendAndTrack"=dword:00000001
"bTogglePrefsSync"=dword:00000001
"bToggleNotifications"=dword:00000001
"bToggleDocumentCloud"=dword:00000001
"bToggleWebConnectors"=dword:00000001
"bToggleAdobeReview"=dword:00000001
"bAcroSuppressOpenInReader"=dword:00000001
"bToggleShareFeedback"=dword:00000000
"bToggleToDoList"=dword:00000001
"bToggleFTE"=dword:00000001
"bToggleToDoTiles"=dword:00000001
"bToggleDCAppCenter"=dword:00000001
"bMixRecentFilesFeatureLockDown"=dword:00000001
"bShowEbookMenu"=dword:00000000
"bCommercialPDF"=dword:00000001
"bRegisterProduct"=dword:00000001
"bShowAdsAllow"=dword:00000001
"bEnableFlash"=dword:00000000
"bFindMoreWorkflowsOnline"=dword:00000000
"bFindMoreCustomizationsOnline"=dword:00000000
"bShowRhpToolSearch"=dword:00000000
"bEnableAcrobatPromptForDocOpen"=dword:00000000
"bAcroSuppressUpsell"=dword:00000001
"bPurchaseAcro"=dword:00000000
"bReaderRetentionExperiment"=dword:00000000
```

## Per-application process mitigation settings
Save all settings:
```powershell
Get-ProcessMitigation -RegistryConfigFilePath settings.xml
```
Apply all settings from a previously saved XML:
```powershell
Set-ProcessMitigation -PolicyFilePath .\settings.xml
```

### KeePassXC
```xml
<AppConfig Executable="KeePassXC.exe">
  <DEP Enable="true" EmulateAtlThunks="false" />
  <ASLR ForceRelocateImages="true" RequireInfo="false" BottomUp="true" HighEntropy="true" />
  <StrictHandle Enable="true" />
  <ExtensionPoints DisableExtensionPoints="true" />
  <ControlFlowGuard Enable="true" SuppressExports="false" />
  <SignedBinaries EnforceModuleDependencySigning="true" />
  <Fonts DisableNonSystemFonts="true" AuditOnly="false" Audit="false" />
  <ImageLoad BlockRemoteImageLoads="true" AuditRemoteImageLoads="false" BlockLowLabelImageLoads="true" AuditLowLabelImageLoads="false" />
  <Payload EnableExportAddressFilter="true" AuditEnableExportAddressFilter="false" EnableExportAddressFilterPlus="true" AuditEnableExportAddressFilterPlus="false" EnableImportAddressFilter="true" AuditEnableImportAddressFilter="false" EnableRopStackPivot="true" AuditEnableRopStackPivot="false" EnableRopCallerCheck="true" AuditEnableRopCallerCheck="false" EnableRopSimExec="true" AuditEnableRopSimExec="false" />
  <SEHOP Enable="true" TelemetryOnly="false" />
  <Heap TerminateOnError="true" />
  <ChildProcess DisallowChildProcessCreation="true" Audit="false" />
</AppConfig>
```

### Firefox
```xml
<AppConfig Executable="firefox.exe">
  <DEP Enable="true" EmulateAtlThunks="false" />
  <ASLR ForceRelocateImages="true" RequireInfo="false" BottomUp="true" HighEntropy="true" />
  <StrictHandle Enable="true" />
  <ExtensionPoints DisableExtensionPoints="true" />
  <ControlFlowGuard Enable="true" SuppressExports="false" />
  <SignedBinaries EnforceModuleDependencySigning="true" />
  <ImageLoad BlockRemoteImageLoads="true" AuditRemoteImageLoads="false" BlockLowLabelImageLoads="true" AuditLowLabelImageLoads="false" />
  <Payload EnableImportAddressFilter="true" AuditEnableImportAddressFilter="false" EnableRopStackPivot="true" AuditEnableRopStackPivot="false" EnableRopCallerCheck="true" AuditEnableRopCallerCheck="false" EnableRopSimExec="true" AuditEnableRopSimExec="false" />
  <SEHOP Enable="true" TelemetryOnly="false" />
  <Heap TerminateOnError="true" />
</AppConfig>
```

### Notepad++
```xml
<AppConfig Executable="notepad++.exe">
  <DEP Enable="true" EmulateAtlThunks="false" />
  <ASLR ForceRelocateImages="true" RequireInfo="false" BottomUp="true" HighEntropy="true" />
  <StrictHandle Enable="true" />
  <ExtensionPoints DisableExtensionPoints="true" />
  <DynamicCode BlockDynamicCode="true" AllowThreadsToOptOut="false" Audit="false" />
  <ControlFlowGuard Enable="true" SuppressExports="false" />
  <SignedBinaries EnforceModuleDependencySigning="true" />
  <Fonts DisableNonSystemFonts="true" AuditOnly="false" Audit="false" />
  <ImageLoad BlockRemoteImageLoads="true" AuditRemoteImageLoads="false" BlockLowLabelImageLoads="true" AuditLowLabelImageLoads="false" />
  <Payload EnableExportAddressFilter="true" AuditEnableExportAddressFilter="false" EnableExportAddressFilterPlus="true" AuditEnableExportAddressFilterPlus="false" EnableImportAddressFilter="true" AuditEnableImportAddressFilter="false" EnableRopStackPivot="true" AuditEnableRopStackPivot="false" EnableRopCallerCheck="true" AuditEnableRopCallerCheck="false" EnableRopSimExec="true" AuditEnableRopSimExec="false" />
  <SEHOP Enable="true" TelemetryOnly="false" />
  <Heap TerminateOnError="true" />
  <ChildProcess DisallowChildProcessCreation="true" Audit="false" />
</AppConfig>

```

### mIRC
```xml
<AppConfig Executable="mirc.exe">
  <DEP Enable="true" EmulateAtlThunks="false" />
  <ASLR ForceRelocateImages="true" RequireInfo="false" BottomUp="true" HighEntropy="true" />
  <StrictHandle Enable="true" />
  <ExtensionPoints DisableExtensionPoints="true" />
  <DynamicCode BlockDynamicCode="true" AllowThreadsToOptOut="false" Audit="false" />
  <ControlFlowGuard Enable="true" SuppressExports="false" />
  <SignedBinaries MicrosoftSignedOnly="true" AllowStoreSignedBinaries="false" Audit="false" AuditStoreSigned="false" EnforceModuleDependencySigning="true" />
  <Fonts DisableNonSystemFonts="true" AuditOnly="false" Audit="false" />
  <ImageLoad BlockRemoteImageLoads="true" AuditRemoteImageLoads="false" BlockLowLabelImageLoads="true" AuditLowLabelImageLoads="false" />
  <Payload EnableExportAddressFilter="true" AuditEnableExportAddressFilter="false" EnableExportAddressFilterPlus="true" AuditEnableExportAddressFilterPlus="false" EnableImportAddressFilter="true" AuditEnableImportAddressFilter="false" EnableRopStackPivot="true" AuditEnableRopStackPivot="false" EnableRopCallerCheck="true" AuditEnableRopCallerCheck="false" EnableRopSimExec="true" AuditEnableRopSimExec="false" />
  <SEHOP Enable="true" TelemetryOnly="false" />
  <Heap TerminateOnError="true" />
  <ChildProcess DisallowChildProcessCreation="true" Audit="false" />
</AppConfig>
```
	  
