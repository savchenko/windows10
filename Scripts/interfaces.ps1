#
# https://github.com/stoptracking/windows10
#

Write-Host "Disable NetBios for all interfaces"
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

Write-Host "Disable ipv6 for all interfaces"
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

Write-Host "Disable LLDP for all interfaces"
Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp

Write-Host "All done!"