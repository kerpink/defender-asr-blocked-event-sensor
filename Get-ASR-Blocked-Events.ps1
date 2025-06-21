<#
.SYNOPSIS
Custom sensor script to report Microsoft Defender ASR activity in a standardized format.

.DESCRIPTION
This script retrieves the most recent Microsoft Defender for Endpoint Attack Surface Reduction (ASR) event 
from the Defender Operational Event Log. It extracts the ASR rule GUID, maps it to a human-readable rule name, 
and outputs key event details in a pipe-delimited format. The output can be consumed by Tanium, 
Microsoft Intune, or other endpoint monitoring platforms to extend ASR visibility.

.OUTPUTS
Pipe-delimited string: ComputerName|Rule ID|Rule Name|Short Description|Timestamp (ISO 8601)

.EXAMPLE
.\Get-ASR-Event.ps1

COMPONENT
Microsoft Defender for Endpoint, Microsoft Intune, Tanium

.AUTHOR
Kerpink Williams

.VERSION
1.0.0

#>

# Mapping of Rule GUIDs to Rule Names
$ruleMap = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from lsass.exe"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files unless trusted"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JS/VBS from launching executables"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office apps from creating executables"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office apps from injecting code"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office comms apps from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations from PSExec/WMI"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting in Safe Mode"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block unsigned processes from USB"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied/impersonated system tools"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Advanced protection against ransomware"
}

$computerName = $env:COMPUTERNAME

# Get the first ASR event
$event = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' |
 Where-Object { $_.Id -eq 1121 -or $_.Id -eq 1122 } |
 Select-Object -First 1

if ($event) {
    $message = $event.Message
    $time = $event.TimeCreated.ToString("o")

    if ($message -match "ID:\s*([A-Fa-f0-9\-]{36})") {
        $ruleId = $matches[1].ToLower()
        $ruleName = $ruleMap[$ruleId]
        if (-not $ruleName) { $ruleName = "Unknown Rule" }
    } else {
        $ruleId = "Unknown"
        $ruleName = "Unknown Rule"
    }

    $shortMessage = ($message -split "`n")[0].Trim()
 Write-Output "$computerName|$ruleId|$ruleName|$shortMessage|$time"
}
