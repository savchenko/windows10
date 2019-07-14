# Before install
1. Pray your gods
2. Un-plug ethernet if present, disable WiFi
3. Enable UEFI-native boot, "Secure boot", DEP, VTx/VT-d, 

# After
1. If necessary, install GPU drivers using offline installer
2. Turn on "controlled folder access" and "core isolation". Either manually or via GPo.
3. Enable "Windows Sandbox" and "Windows Defender App Guard" in "Windows features"
4. `Get-AppxPackage -AllUsers | where-object {$_.name –notlike "*store*"} | Remove-AppxPackage`
5. Download [DG readiness tool](https://www.microsoft.com/en-us/download/details.aspx?id=53337)
    5.1 Temporarily change execution policy for PowerShell scripts:
        `Set-ExecutionPolicy -ExecutionPolicy AllSigned`
    5.2 Check current status
        `.\DG_Readiness_tool_v3.5.ps1 -Ready`
    5.3 Enable:
        `.\DG_Readiness_tool_v3.5.ps1 -Enable`
    5.4 Reboot, check again. Happy with the result? Don't forget to switch exec.policy back:
        `Set-ExecutionPolicy -ExecutionPolicy Restricted`
