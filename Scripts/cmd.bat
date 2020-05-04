::
:: https://github.com/stoptracking/windows10
::

@echo off
SETLOCAL EnableDelayedExpansion

echo This should be run with Administrator privileges, otherwise errors will occur.
set /p rtg="Press any key if you are ready, close this window if not."
cls

echo [101;93m Limite Cortana [0m
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f

echo [101;93m Disable error reporting [0m
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

echo [101;93m Disable LLMNR [0m
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v " EnableMulticast" /t REG_DWORD /d "0" /f

echo [101;93m Adjust Windows Update settings... [0m
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v DetectionFrequencyEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v DetectionFrequency /t REG_DWORD /d 1 /f

echo [101;93m Disable Windows tips [0m
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f

echo [101;93m Disable "Windows Spotlight" [0m
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f

echo [101;93m Disable consumer features [0m
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

echo [101;93m Do not show feedback notifications [0m
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

echo [101;93m Disable suggested apps [0m
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f

echo [101;93m Disable settings synchronization [0m
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f

echo [101;93m Disable user override of the settings synchronization [0m
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f

echo [101;93m Disable device metadata retrieval [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f

echo [101;93m Disable "Find my device" [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice\AllowFindMyDevice" /t REG_DWORD /d 0 /f

echo [101;93m Disable font streaming  [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders" /t REG_DWORD /d 0 /f

echo [101;93m Disabling web-search... [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /d 0 /f

echo [101;93m Limit Cortana application via Windows Firewall... [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /t REG_SZ /v "v2.25|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\searchUI.exe|Name=Block outbound Cortana|" /f

echo [101;93m Disable Windows preview builds [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /t REG_DWORD /v AllowBuildPreview /d 0 /f

echo [101;93m Turn off "live tiles" [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /t REG_DWORD /v NoCloudApplicationNotification /d 1 /f

echo [101;93m Disable Windows mail application [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Mail" /v ManualLaunchAllowed /t REG_DWORD /d 0 /f

echo [101;93m Disable Microsoft Account [0m
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wlidsvc" /t REG_DWORD /v Start /d 4 /f

echo [101;93m Disable NCSI [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v NoActiveProbe /t REG_DWORD /d 1 /f

echo [101;93m Disable OneDrive [0m
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OneDrive" /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f



set /p done=""
