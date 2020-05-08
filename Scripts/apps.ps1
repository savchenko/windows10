#
# https://github.com/stoptracking/windows10
#

Write-Host "Remove pre-installed applications..."
Get-AppXProvisionedPackage –online | where-object {$_.PackageName –notlike "*store*"} | Remove-AppxProvisionedPackage -online  -erroraction silentlycontinue

Write-Host "Remove installed applications for all users..."
Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage -erroraction silentlycontinue

Write-Host "Remove installed applications for the current user..."
Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage -erroraction silentlycontinue

Write-Host "All done! Please proceed with the new user creation and delete this one afterwards."