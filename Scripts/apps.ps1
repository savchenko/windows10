#
# https://github.com/stoptracking/windows10
#

echo "Remove pre-installed applications..."
Get-AppXProvisionedPackage –online | where-object {$_.PackageName –notlike "*store*"} | Remove-AppxProvisionedPackage -online  -erroraction silentlycontinue

echo "Remove installed applications for all users..."
Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage -erroraction silentlycontinue

echo "Remove installed applications for the current ..."
Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage -erroraction silentlycontinue