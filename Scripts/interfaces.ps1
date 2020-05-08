#
# https://github.com/stoptracking/windows10
#

Write-Host "Disabling NetBios for all interfaces"

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

Write-Host "All done!"