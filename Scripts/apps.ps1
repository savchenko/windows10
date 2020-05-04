#
# https://github.com/stoptracking/windows10
#

echo "Removing pre-installed applications..."


echo "Bing"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingNews"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage

echo "Weather"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingWeather"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage

echo "Money"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingFinance"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage

echo "Sports"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.BingSports"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage

echo "Twitter"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "*.Twitter"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage *.Twitter | Remove-AppxPackage

echo "XBox"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage

echo "Sway"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.Office.Sway"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.Office.Sway | Remove-AppxPackage

echo "OneNote"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.Office.OneNote"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage

echo "Get office upsell"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.MicrosoftOfficeHub"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage

echo "Get Skype upsell"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.SkypeApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage

echo "Sticky notes"
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like "Microsoft.MicrosoftStickyNotes"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage