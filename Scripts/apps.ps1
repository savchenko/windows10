#Requires -RunAsAdministrator
#Requires -Version 5

#
# https://github.com/stoptracking/windows10
#

Write-Host "Disable PowerShell v2"
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

Write-Host "Disable Windows Media Player"
Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer

Write-Host "Disable Internet Explorer"
Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer*" } | Disable-WindowsOptionalFeature -Online

Write-Host "Disable 'Remote Assistance'"
Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online

Write-Host "Disable Hello Face"
Get-WindowsCapability -Online | Where-Object { $_.Name -like "Hello.Face*" } | Remove-WindowsCapability -Online

Write-Host "All done! Please proceed with the new user creation and delete this one afterwards."
