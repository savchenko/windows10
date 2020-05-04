
# Summary
This is a cheat-sheet for a single-user installation of Windows 10 build 1909.
Level 3 baseline plus/minus some additional customizations: less network noise, focus on single-user workstation, etc.

![seccon-framework](https://user-images.githubusercontent.com/300146/63164652-3469ee00-c068-11e9-8a0a-96347d5254b0.png)

Tools used:
* [MS Docs](https://docs.microsoft.com/en-us/windows/windows-10/)
* [MS Security Compliance Toolkit](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)
* [GP Search](https://gpsearch.azurewebsites.net/)
* [GPO and Policy Analyzer](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* [Connection endpoints documentation](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* [Endpoint management](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* [Wireshark](https://wireshark.org) and [MS Network Monitor](https://www.microsoft.com/en-au/download/details.aspx?id=4865)
* [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/)
* [Intel CSME](https://downloadcenter.intel.com/download/28632/Intel-CSME-Detection-Tool)

If you are looking for something more reproducible and of a \*nix flavour, check-out the [Playbook](https://github.com/stoptracking/playbook).

# Foreword
This guide suggests to follow rather strict approach and accepts no closed-source utilities that promise to "fix Windows privacy".

Author has rather dim view on such tools and whenever possible proposes to rely on empirical evidence and collected data rather than a promise. When possible, instruments provided by Microsoft are used instead of 3rd-party applications.

Great care should be taken when using commercial operating system with "post-sale monetisation" as a part of its business model. Make no mistake as to what is a product and [where profits are coming from](https://www.microsoft.com/investor/reports/ar19/index.html).

Number of settings are applied via direct registry injection instead of a GPO import. I can only quote Microsoft, here:

> To turn off Messaging cloud sync:
>    There is no Group Policy corresponding to this registry key.

and here:

> Note: There is no Group Policy to turn off the Malicious Software Reporting Tool diagnostic data.

# Rationale
One might rightfully ask, &mdash; _"Why to bother with MS product while there are better \*nix-based operating systems?"_<br />
At present, main considerations are:
* Ability to use [well-tested FDE](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-countermeasures) that it tied to TPM _and_ user-supplied secret. While it is possible to implement something similar via `keyscript` in `/etc/crypttab`, such ~bodging~ hacking is not a default modus operandi of LUKS.

	And while there is `clevis`, _"TPM in conjunction with user password"_ and additional backup keys with automatic roll-over after kernel upgrades are not supported by any major Linux distribution as in Q1 2020.
* Commercial-grade Type-1 hypervisor.
* Application firewall with the [WFP layer](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) that allows building additional rules on top of the same engine. Usable GUIs to manage WFP and CLI for the Windows Firewall itself.
* Handy software that is not available under Linux or \*BSD.
* Good hardware support.

# First steps
1. Recognize that you are dealing with the closed-source, SaaS-like operating system that has a combination of useful features and hostile elements simultaneously. To give an idea on how the "Microsoft world" is different, this is enabled by default: 

> Automatic learning enables the collection and storage of text and ink written by the user in order to help adapt handwriting recognition to the vocabulary and handwriting style of the user.  
> 
> Text that is collected includes all outgoing messages in Windows Mail, and MAPI enabled email clients, as well as URLs from the Internet Explorer browser history. The information that is stored includes word frequency and new words not already known to the handwriting recognition engines (for example, proper names and acronyms).
>
> Deleting email content or the browser history does not delete the stored personalization data. Ink entered through Input Panel is collected and stored.

2. Be aware that you will be enabling [Hypervisor-protected code integrity (HVCI)](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity) which imposes _significant_ performance penalty on all Intel CPUs released before "7th generation" and AMD processors prior to ["Ryzen 2"](https://github.com/MicrosoftDocs/windows-itpro-docs/issues/3997). To quote Mark Russinovich and Alex Ionescu:

> "The Secure Kernel relies on the Mode-Based Execution Control (MBEC) feature, if present in hardware, which enhances the SLAT with a user/kernel executable bit, or the hypervisor’s software emulation of this feature, called Restricted User Mode (RUM)." 

After we are done, your environment will look like this:
![HVCI](https://user-images.githubusercontent.com/300146/64527010-019fd680-d344-11e9-9cbe-08fe004c1baf.png)
...plus some more VMs on the side.

3. Remember about performance hit from countermeasures against [2019 side-channel attacks](https://www.intel.com/content/www/us/en/architecture-and-technology/engineering-new-protections-into-hardware.html). Down the track, you can obtain CPU stepping by running `wmic cpu get caption` in PowerShell and, if using Intel, compare against [this list](https://www.intel.com/content/www/us/en/architecture-and-technology/engineering-new-protections-into-hardware.html). This is when hardware upgrade might be a wise choice.

# Before installation
1. Un-plug ethernet if present, disable WiFi.
1. Install latest BIOS/FWs from a vendor.
1. Consider stripping Intel ME using [metool](https://github.com/corna/me_cleaner) or be ready to assess/update/patch using CSME, link above.
1. Enable UEFI-native boot, "Secure boot", DEP, VTx/VT-d (or AMD-V).
1. In case you are using Intel&trade;, depending on the CPU generation you might consider disabling HyperThreading&reg;.  
   1. On certain SMB platforms IntelTXT&reg; is enabled and not exposed in BIOS which may prevent from disabling HT.
   1. Sometimes this can be circumvented by using vendor's mass-provisioning tool. For example, HP:
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
    3. Afterwards, you should be able to disable HT:
	```powershell
	.\BiosConfigUtility64.exe /setvalue:"Intel (R) HT Technology","Disable" /cpwdfile:"pwd.bin" /l /verbose
	```
# During installation
1. Keep machine disconnected from the Internet
2. Opt-out from all personal data collection when asked. This means answering "no" to every single question.

# After installation
1. Copy this repository to the target machine via local means
1. Copy `LGPO.exe` from `./Tools` to `C:\Windows\system32\`.  
Alternatively, you can copy it elsewhere and add the location to `$PATH`.

## Enable HVCI and Credential Guard
1. From `./Tools/dgreadiness_v3.6`, launch [DG readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337).  
   1. Temporarily change execution policy for PowerShell scripts:  
   `Set-ExecutionPolicy -ExecutionPolicy AllSigned`  
   1. Check current status:  
   `.\DG_Readiness_tool_v3.6.ps1 -Ready`  
   1. Enable:  
   `.\DG_Readiness_tool_v3.6.ps1 -Enable`  
   1. Looks like this?  
   ![](https://i.imgur.com/QsaDuOV.png)
   1. Good. Don't forget to switch the policy back:  
   `Set-ExecutionPolicy -ExecutionPolicy Restricted`

1. Reboot

## Apply baseline policies

### Security
1. Navigate to `./Tools/baseline_security/Scripts` and:

	```powershell
	Set-ExecutionPolicy -ExecutionPolicy Unrestricted
	.\Baseline-LocalInstall.ps1 -Win10NonDomainJoined
	```
1. Reboot

### Traffic restriction
1. Navigate to `./Tools/baseline_traffic` and:

	```powershell
	cp ..\LGPO\LGPO.exe .\Tools\
	.\RestrictedTraffic_ClientEnt_Install.cmd
	```
	1. Accept the terms.
1. Open "Group Policy editor", navigate to `Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options`
1. Change "User Account Control: Behavior of the elevation prompt for standard users" to "Prompt for credentials on the secure desktop"
1. Reboot

### Stoptracking GPOs
Navigate to `./Tools/Scripts`.
1. In elevated `cmd.exe`, execute:
	- `windows.bat`
	- `edge.bat`
1. In elevated PowerShell:
	- `apps.ps1`

## Check Hyper-V settings
2. While this should be not necessary on builds after 1809, check if Hyper-V scheduler needs an adjustment to mitigate CVE-2018-3646. 
   1. Read [Windows guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-au/help/4457951/windows-guidance-to-protect-against-speculative-execution-side-channel)
   2. Determine current scheduler:
   ```powershell
   Get-WinEvent -FilterHashTable @{ProviderName="Microsoft-Windows-Hyper-V-Hypervisor"; ID=2} | select -Last 1
   ```
   4. If the command above has returned 0x4, execute from elevated shell and reboot: `bcdedit /set hypervisorschedulertype core`.
   5. Later, you will need to configure each VM so it takes advantage of the Core scheduler **by setting its hardware thread-count-per-core to two**:
   ```powershell
   Set-VMProcessor -VMName <VMName> -HwThreadCountPerCore 2
   ```

3. After reboot, verify current state:
   ```powershell
   Get-CimInstance -Namespace ROOT\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | fl SecurityServicesRunning, SecurityServicesConfigured, VirtualizationBasedSecurityStatus
   ```
   If curious (as you should be), compare against [documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity). In general, output should look like this:
   ```powershell
    AvailableSecurityProperties                  : {1, 2, 3, 4, 5, 7}
    CodeIntegrityPolicyEnforcementStatus         : 0
    InstanceIdentifier                           : 4ff40742-2649-41b8-bdd1-e80fad1cce80
    RequiredSecurityProperties                   : {0}	#
    SecurityServicesConfigured                   : {0}	# Depends on the hardware support
    SecurityServicesRunning                      : {0}	#
    UsermodeCodeIntegrityPolicyEnforcementStatus : 0
    Version                                      : 1.0
    VirtualizationBasedSecurityStatus            : 0
    PSComputerName                               : COMPUTERNAME
   ```

## First 3 steps

2. Import initial firewall policy from `./Settings/WDF`
3. Import Group Policy from `./Settings/GPO`
5. After the Windows is activated, execute from elevated `cmd.exe`:
```bat
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /t REG_DWORD /v NoGenTicket /d 1 /f
```

Allowed traffic list for Windows Restricted Traffic Limited Functionality Baseline
Table 16
Allowed traffic endpoints
activation-v2.sls.microsoft.com/*
crl.microsoft.com/pki/crl/*
ocsp.digicert.com/*
www.microsoft.com/pkiops/*

## Full Disk Encryption for NT systems: Bitlocker
4. Open policy editor and search the following: _"Configure TPM platform validation for native UEFI firmware configurations"_.
5.  Enable PCR banks according to your hardware, here is the [comprehensive list with explanations](https://docs.microsoft.com/en-us/windows/win32/secprov/getkeyprotectorplatformvalidationprofile-win32-encryptablevolume).  
Good start on a relatively modern device with TPM 2.0 would be `0,1,.......`
7.  Use `manage-bde` to set-up BitLocker and add/remove recovery agents.
    1. Double-check that Bitlocker is disabled for the system drive:
      ```powershell
      .\manage-bde.exe -protectors -get C:
      ```
    2. If result is negative, add TPM and PIN:
      ```powershell
      .\manage-bde.exe -protectors -add -tp C:
      ```
    3. Until the above is confirmed working, add temporary recovery key:
      ```powershell
      .\manage-bde.exe -protectors -add -rp C:
      ```
      Write-down the numerical password, you will need it if machine refuses to boot with the chosen set of PCR banks.

    4. If computer has started successfully and `Manage-BDE -protectors -get C:` returns data set at step #1...

    5. Add file protectors instead of the pre-generated numerical sequence:
      ```powershell
      .\manage-bde.exe -protectors -delete -t RecoveryPassword C:
      .\manage-bde.exe -protectors -add -rk X:\WHERE_TO_STORE_KEY C:
      ```
      *N.B.* Don't forget to securely wipe device "X" after the key is transferred to a proper location. 

8. If necessary, install GPU drivers using _verified_ offline installer, use DCH package if possible.

11. `choco install pgp4win`
1. Import pubkey, insert smart-card.
    1) Open `kleopatra`, Tools &rarr; Manage Smartcards, ensure yours is present.
    2) Do not close Kleopatra.
    3) Issue `gpg.exe --card-status` to refresh the SCDaemon.
    4) Press F5 in Kleopatra, assuming pubkey corresponds to private key stored on the card, relevant line will become highlighted with in bold.
    5) Change trust level of your own certificate to ultimate.
2.  Adjust content of system CA as necessary:
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
if (!(Test-Path -Path $PROFILE.CurrentUserAllHosts)) {
  New-Item -ItemType File -Path $PROFILE.CurrentUserAllHosts -Force
}
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

#TODO: Expand on OTP: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exploit-protection#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion

https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction

https://github.com/AndyFul

https://demo.wd.microsoft.com/?ocid=cx-wddocs-testground

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

Set keyboard layout:
```powershell
Set-WinUserLanguageList -LanguageList en-US
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

Moved to the WIKI.

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
	  
