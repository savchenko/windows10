::
:: https://github.com/stoptracking/windows10
::

@echo off
SETLOCAL EnableDelayedExpansion

echo.
echo This should be run with Administrator privileges, otherwise errors will occur.
set /p rtg="Press any key if you are ready, close this window if not."
cls

echo Limit Cortana and Online/Bing search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAAD /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
REM Where is the documentation for "CortanaConsent"?..
REM reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f

echo Limit Cortana application via Windows Firewall...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /t REG_SZ /v "v2.25|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\searchUI.exe|Name=Block outbound Cortana|" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f

echo Disable indexing of encrypted files
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f

echo Disable error reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

echo Disable Microsoft experimentation
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v value /t REG_DWORD /d 0 /f

echo Do not allow WifiSense hotspots
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f

echo Disable LLMNR and Smart-Name-Resoltion
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f

:: Windows updates

echo Enable Windows Update
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DoNotConnectToWindowsUpdateInternetLocations /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUStatusServer /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v UseWUServer /f

echo Keep auto-updates enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f

echo Notify before download or installation
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f

echo Do not reboot automatically if someone is logged into the system
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f

echo Do not wake-up the machine to install an update
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUPowerManagement /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrenLtVersion\Schedule\Maintenance" /v WakeUp /t REG_DWORD /d 0 /f

echo Treat minor updates like other updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f

echo Check for new updates every hour
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v DetectionFrequencyEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v DetectionFrequency /t REG_DWORD /d 1 /f

echo Disable "featured software" in Windows update
reg add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /T REG_DWORD /V EnableFeaturedSoftware /D 0 /F

echo Defer feature-updates by 360 days 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /t REG_DWORD /v DeferFeatureUpdates /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /t REG_DWORD /v DeferFeatureUpdatesPeriodInDays /d 360 /f

echo Ensure security updates are installed on day zero
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /t REG_DWORD /v DeferQualityUpdates /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /t REG_DWORD /v DeferQualityUpdatesPeriodInDays /d 0 /f

::

echo Disable Windows tips
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f

echo Prevent sharing of handwriting and speech
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v AllowLinguisticDataCollection /t REG_DWORD /d 0 /f

echo Do not leak information about AppV usage via Windows Customer Experience
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /T REG_DWORD /V "CEIPEnable" /D 0 /F
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /T REG_DWORD /V "CEIPEnable" /D 0 /F

echo Disable "Windows Spotlight"
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKEY_Local_Machine\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization"/v LockScreenImage /d "%SystemRoot%\web\screen\img105.jpg" /f
reg add "HKEY_Local_Machine\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v LockScreenOverlaysDisabled /t REG_DWORD /d 1 /f

echo Disable consumer features
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKEY_Current_User\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f

echo Do not show feedback notifications and disable "Feedback & diagnostics"
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "AllowTelemetry" /D 0 /F

echo Disable suggested apps
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f

echo Disable password reveal
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Speech" /t REG_DWORD /v DisablePasswordReveal /d 1 /f

echo Disable settings synchronization
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f

echo Disable user override of the settings synchronization
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f

echo Disable device metadata retrieval
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f

echo Disable "Find my device"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t REG_DWORD /d 0 /f

echo Disable font streaming 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableFontProviders /t REG_DWORD /d 0 /f

echo Disable web-search...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /d 0 /f

echo Disable biometrics
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics" /v Enabled /d 0 /f

echo Disable camera from AppX
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Camera" /v AllowCamera /d 0 /f

echo Disable Windows preview builds
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /t REG_DWORD /v AllowBuildPreview /d 0 /f

echo Turn off "live tiles"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /t REG_DWORD /v NoCloudApplicationNotification /d 1 /f

echo Disable help ratings
reg add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v NoExplicitFeedback /t REG_DWORD /d 1 /f

echo Disable Windows mail application
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Mail" /v ManualLaunchAllowed /t REG_DWORD /d 0 /f

echo Disable Microsoft Account and do not nag about it[0m
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wlidsvc" /t REG_DWORD /v Start /d 4 /f
reg add "HKCU\Software\Microsoft\Windows Security Health\State" /t REG_DWORD /v AccountProtection_MicrosoftAccount_Disconnected /d 1 /f

echo Disable NCSI
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v NoActiveProbe /t REG_DWORD /d 1 /f

echo Disable OneDrive
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OneDrive" /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f

echo Do not download maps data
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v AutoDownloadAndUpdateMapData /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v AllowUntriggeredNetworkTrafficOnSettingsPage /t REG_DWORD /d 0 /f

echo Turn off advertising ID
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /t REG_DWORD /v Enabled /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /t REG_DWORD /v DisabledByGroupPolicy /d 1 /f

echo Do not retrieve device metadata from the Internet
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /V "PreventDeviceMetadataFromNetwork" /T REG_DWORD /D 1 /F

echo Do not track application launches
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /t REG_DWORD /v Start_TrackProgs /d 0 /f

echo Do not share user's language list
reg add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /t REG_DWORD /v HttpAcceptLanguageOptOut /d 1 /f

echo Do not share app status with random devices
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /t REG_DWORD /v EnableCdp /d 0 /f

echo Do not share location and sensors data
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v DisableSensors /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessLocation /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /t REG_DWORD /v DisableLocation /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /t REG_DWORD /v DisableLocationScripting /d 1 /f

echo Disable Maps updates
reg add "HKEY_LOCAL_MACHINE\System\Maps" /t REG_DWORD /v AutoUpdateEnabled /d 0 /f

echo Do not share across devices
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /t REG_DWORD /v CdpSessionUserAuthzPolicy /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /t REG_DWORD /v RomeSdkChannelUserAuthzPolicy /d 0 /f

echo Disable clipboard history
reg add "HKCU\Software\Microsoft\Clipboard" /t REG_DWORD /v EnableClipboardHistory /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v AllowClipboardHistory /d 0 /f

echo Adjust AppX privacy settings
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v AllowMessageSync /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessAccountInfo /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessCalendar /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessCallHistory /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessCamera /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessContacts /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessEmail /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessMessaging /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessMicrophone /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessMotion /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessPhone /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessRadios /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessTasks /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsAccessTrustedDevices /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsActivateWithVoice /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsActivateWithVoiceAboveLock /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsGetDiagnosticInfo /d 2 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /t REG_DWORD /v LetAppsSyncWithDevices /d 2 /f

echo CapabilityAccessManager
echo.

echo Camera
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /T REG_SZ /V "Value" /D Deny /F

echo Microphone
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /T REG_SZ /V "Value" /D Deny /F

echo Account Info
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /T REG_SZ /V "Value" /D Deny /F

echo Contacts
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /T REG_SZ /V "Value" /D Deny /F

echo Calendar
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /T REG_SZ /V "Value" /D Deny /F

echo Call history
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /T REG_SZ /V "Value" /D Deny /F

echo Email
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /T REG_SZ /V "Value" /D Deny /F

echo Tasks
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /T REG_SZ /V "Value" /D Deny /F

echo TXT/MMS
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /T REG_SZ /V "Value" /D Deny /F

echo Other Devices
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /T REG_SZ /V "Value" /D Deny /F

echo Cellular Data
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /T REG_SZ /V "Value" /D Deny /F

echo Allow apps to run in background global setting
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /T REG_DWORD /V "GlobalUserDisabled" /D 1 /F
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "BackgroundAppGlobalToggle" /D 0 /F

echo My Documents
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /T REG_SZ /V "Value" /D Deny /F

echo My Pictures
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /T REG_SZ /V "Value" /D Deny /F

echo My Videos
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /T REG_SZ /V "Value" /D Deny /F

echo File System
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /T REG_SZ /V "Value" /D Deny /F

echo Location
reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /T REG_SZ /V "Value" /D Deny /F

echo.

echo Do not send my voice data (!) to Microsoft
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /t REG_DWORD /v HasAccepted /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Speech" /t REG_DWORD /v AllowSpeechModelUpdate /d 0 /f

echo Do not share writing and typing (!) information with Microsoft
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /t REG_DWORD /v RestrictImplicitTextCollection /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /t REG_DWORD /v RestrictImplicitInkCollection /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /t REG_DWORD /v HarvestContacts /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /t REG_DWORD /v "Enabled" /d 0 /f

echo Disable activity feed
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /t REG_DWORD /v EnableActivityFeed /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /t REG_DWORD /v PublishUserActivities /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /t REG_DWORD /v UploadUserActivities /d 0 /f

echo Disable Windows Sync
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" /t REG_DWORD /v DisableSettingSync /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" /t REG_DWORD /v DisableSettingSyncUserOverride /d 1 /f

echo Turn off messaging cloud sync
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Messaging" /t REG_DWORD /v CloudServiceSyncEnabled /d 0 /f

echo Disable Teredo
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" /t REG_SZ /v "Disabled" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" /v Teredo_State /d "Disabled" /f

echo Disable Wifi Sense
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v WiFISenseAllowed /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f

echo Delete WPAD key for the current user
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /f

echo Disable SpyNet and do not send samples to Microsoft
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" /t REG_DWORD /v SpyNetReporting /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet"  /t REG_DWORD /v SubmitSamplesConsent /d 2 /f

echo Disable MSRT
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MRT"  /t REG_DWORD /v DontReportInfectionInformation /d 1 /f

echo Disable Microsoft Store
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /t REG_DWORD /v DisableStoreApps /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore " /t REG_DWORD /v AutoDownload /d 2 /f

echo Do not use SmartScreen for AppX
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f

echo Disable "Apps for websites"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v EnableAppUriHandlers /d 0 /f

echo Disable "delivery optimisation"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization " /t REG_DWORD /v DODownloadMode /d 100 /f

echo Disable MS Store
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f

echo Disable AppX's from the Store
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f

echo Disable "Push to install"
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f

echo Disable "Content delivery manager"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f

echo Disable Autoplay
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /T REG_DWORD /V "DisableAutoplay" /D 1 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /T REG_DWORD /V "DisableAutoplay" /D 1 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /T REG_DWORD /V "NoAutoplayfornonVolume" /D 1 /F
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /T REG_DWORD /V NoDriveTypeAutoRun /D 255 /F

echo Disable Explorer web-wizards
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /T REG_DWORD /V NoWebServices /D 1 /F

echo Disable Fast Startup feature
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /T REG_DWORD /V HiberbootEnabled /D 0 /F

echo Disable online tips
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t REG_DWORD /d 0 /f

echo Do not download printer drivers over HTTP
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" /T REG_DWORD /V DisableWebPnPDownload /D 1 /F

echo Force-scan attachments with antivirus
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ScanWithAntiVirus" /T REG_DWORD /V ScanWithAntiVirus /D 3 /F

echo Restrict AppCompat (Application compatibility)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v VDMDisallowed /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableEngine /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableWizard /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v SbEnable /t REG_DWORD /d 0 /f

echo Disable Game DVR
reg add "HKCU\System\GameConfigStore" /T REG_DWORD /V "GameDVR_Enabled" /D 0 /F
reg add "HKCU\Software\Microsoft\GameBar" /T REG_DWORD /V "AutoGameModeEnabled" /D 0 /F
reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /T REG_DWORD /V "AllowGameDVR" /D 0 /F

echo Disable Ink Workspace
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f

echo Prevent automatic Edge-to-Chromium upgrade
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EdgeUpdate" /v DoNotUpdateToEdgeWithChromium /t REG_DWORD /d 1 /f

echo Do not attempt to search in Windows Store for an unknown file extension
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f

echo Remove "3D paint"...
for /f "tokens=1* delims=" %%I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%%I" /f )
for /f "tokens=1* delims=" %%I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%%I" /f )
echo ...done

:: TODO: Test if this can be executed from SHIFT+F10
echo Disable first logon animation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f


:: Disable services

echo Disable error reporting service
sc config WerSvc start=disabled

echo Disable Telemetry service
sc config DiagTrack start=disabled

echo Disable Wireless Application Protocol (WAP) service
sc config dmwappushservice start=disabled

echo Disable OneSync service
sc config OneSyncSvc start=disabled

echo Disable text messaging service
sc config MessagingService start=disabled

echo Disable MS account identity service
sc config wlidsvc start=disabled

echo Disable Windows Insider service
sc config wisvc start=disabled

echo Disable "Retail Demo" service
sc config RetailDemo start=disabled

echo Disable events collector service
sc config diagnosticshub.standardcollector.service start=disabled

echo Disable XBox services
sc config XblAuthManager start=disabled
sc config XblGameSave start=disabled
sc config XboxNetApiSvc start=disabled

echo Disable ActiveX Installer 
sc config AxInstSV start=disabled

echo Disable AllJoyn router
sc config AJRouter start=disabled

echo Disable bluetooth service
sc config bthserv start=disabled

echo Disable "connected devices platform" services
sc config CDPUserSvc start=disabled
sc config CDPSvc start=disabled

echo Disable Game DVR service
sc config BcastDVRUserService start=disabled

echo Disable bluetooth service
sc config BluetoothUserService start=disabled

echo Disable Miracast and DLNA service
sc config DevicePickerUserSvc start=disabled

echo Disable ConnectUX service (WiFi/bluetooth displays)
sc config DevicesFlowUserSvc start=disabled

echo Disable text messaging service
sc config MessagingService start=disabled

echo Disable Client-licensing service (MS Store)
sc config ClipSVC start=disabled

echo Disable maps broker service
sc config MapsBroker start=disabled

echo Disable Function Discovery Resource Publication service
sc config FDResPub start=disabled

echo Disable geolocation service
sc config lfsvc start=disabled

echo Disable 6to4 service
sc config iphlpsvc start=disabled

echo Disable LLTDM service
sc config lltdsvc start=disabled

echo Disable MS Account services
sc config wlidsvc start=disabled
sc config NgcSvc start=disabled

echo Disable Network Connection Broker (AppX connectivity) service
sc config NcbService start=disabled

echo Disable RPC Locator service
sc config RpcLocator start=disabled

echo Disable Program Compatibility Assistant service
sc config PcaSvc start=disabled

echo Disable sensor services
sc config SensorService start=disabled
sc config SensorDataService start=disabled
sc config SensrSvc start=disabled

echo Disable autoplay service
sc config ShellHWDetection start=disabled

echo Disable SSDP service
sc config SSDPSRV start=disabled

echo Disable sync host service
sc config OneSyncSvc start=disabled

echo Disable NetBIOS service
sc config lmhosts start=disabled

echo Disable touch keyboard and handwriting service
sc config TabletInputService start=disabled

echo Disable UPnP service
sc config upnphost start=disabled

echo Disable Wallet (AppX) service
sc config WalletService start=disabled

echo Disable Windows Insider service
sc config wisvc start=disabled

echo Disable Windows Store license service
sc config LicenseManager start=disabled

echo Disable mobile hotspot service
sc config icssvc start=disabled


:: Networking


echo Disable ipv6
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
netsh int ipv6 set state disabled
netsh int isatap set state disabled

echo Disable Teredo
netsh int teredo set state disabled

echo Disable 6to4 tunneling
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled

:: Do not do this, will break "File History", etc
:: echo Disable administrative shares
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f

echo Disable memory dump on crash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0x7 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0x7 /f

echo Disable Network Connectivity Assistant
reg add "HKLM\System\CurrentControlSet\Services\NcaSvc" /v "Start" /t REG_DWORD /d "4" /f

echo Disable NetBios
reg add "HKLM\System\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip" /v "NetbiosOptions" /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\NetBIOS" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

echo Disable LLTD and SNMP
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v AllowRspndrOndomain /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v AllowRspndrOnPublicNet /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v AllowLLTDIOOndomain /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v AllowLLTDIOOnPublicNet /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v EnableRspndr /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v EnableLLTDIO /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\rspndr" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\lltdio" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\MsLldp" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\SNMP" /v "Start" /t REG_DWORD /d "4" /f

echo Disable ip source routing
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f

echo Disable Do not resolve unqualified DNS queries
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v UseDomainNameDevolution /t REG_DWORD /d 0 /f

echo Disable ICMP redirect
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f

echo Force-enable Windows Firewall and apply initial settings
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v EnableFirewall /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v DisableUnicastResponsesToMulticastBroadcast /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DisableUnicastResponsesToMulticastBroadcast /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v EnableFirewall /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DisableUnicastResponsesToMulticastBroadcast /t REG_DWORD /d 1 /f


:: Disable tasks
:: TODO: Test each one again

echo Disable tasks that might leak information to Microsoft and Friends
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*"

:: Enable

echo Enable Local Security Authority (LSA) hardening
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f

echo Always display file extension in Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f

echo Warn user on folder merge conflict
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideMergeConflicts /t REG_DWORD /d 0 /f

echo Show NTFS-encrypted or compressed files in a different colour
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowEncryptCompressedColor /t REG_DWORD /d 1 /f

echo Enforce saving zone information for downloaded files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f

echo Adjust trust logic for file attachments
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v UseTrustedHandlers /t REG_DWORD /d 3 /f

echo Scan attachments with antivirus
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f

echo Enable verbose boot and shutdown
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v VerboseStatus /t REG_DWORD /d 1 /f

echo Set DEP policy to OptOut
bcdedit /set {current} nx OptOut

echo Enable long paths
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f


echo All done! Press any key to exit...
echo.
set /p done=""
cls
