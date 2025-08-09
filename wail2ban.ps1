<#
.SYNOPSIS
    wail2ban is a PowerShell script that monitors Windows Event Logs for failed login attempts and bans the offending IP addresses.

.DESCRIPTION
    wail2ban is an attempt to recreate the functionality of fail2ban for Windows. It monitors the Windows Event Logs for specific event IDs that indicate a failed login attempt. When a certain number of failed attempts from the same IP address are detected within a specified time window, the script will create a new inbound firewall rule to block that IP address.

    The script can be configured to monitor different event logs and event IDs, and the ban duration is configurable. The script also supports a whitelist of IP addresses that should never be banned.

.PARAMETER ListBans
    Lists all the currently banned IP addresses.

.PARAMETER UnbanIP
    Removes the specified IP address from the ban list.

.PARAMETER ClearAllBans
    Removes all the IP addresses that have been banned by this script.

.EXAMPLE
    .\wail2ban.ps1
    Starts the script in monitoring mode.

.EXAMPLE
    .\wail2ban.ps1 -ListBans
    Lists all the currently banned IP addresses.

.EXAMPLE
    .\wail2ban.ps1 -UnbanIP "1.2.3.4"
    Removes the IP address "1.2.3.4" from the ban list.

.EXAMPLE
    .\wail2ban.ps1 -ClearAllBans
    Removes all the IP addresses that have been banned by this script.

.EXAMPLE
    .\wail2ban.ps1 -CheckWindow 300
    Sets the check window to 300 seconds (5 minutes).

.EXAMPLE
    .\wail2ban.ps1 -CheckCount 10
    Sets the check count to 10 (ban after 10 failures).

.EXAMPLE
    .\wail2ban.ps1 -LoopDuration 10
    Sets the loop duration to 10 seconds (check for new events every 10 seconds).

.EXAMPLE
    .\wail2ban.ps1 -MaxBanDuration 86400
    Sets maximum ban duration to 1 day (86400 seconds)

.NOTES
    Author: glasnt
    License: BSD 3-Clause License
#>
[CmdletBinding()]
param (
    [switch]$ListBans,
    [string]$UnbanIP,
    [switch]$ClearAllBans,
    [switch]$Silent,
    [switch]$html,
    [switch]$install,
    [int]$ReportDays = 7,
    [int]$CheckWindow = 120,
    [int]$CheckCount = 5,
    [int]$LoopDuration = 5,
    [int]$MaxBanDuration = 7776000,
    [string]$EventsToTrack = "Security 4625",
    [string]$WhiteList = "" 
)


# Prerequisite Checks
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Please run it as an administrator."
    exit 1
}


if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires PowerShell version 5.1 or higher."
    exit 1
}

$policy = Get-ExecutionPolicy
if ($policy -eq 'Restricted') {
    Write-Error "The PowerShell execution policy is set to 'Restricted'. Please set it to 'RemoteSigned' or 'Unrestricted' to run this script."
    exit 1
}

################################################################################
#                        _ _ ____  _                 
#         __      ____ _(_) |___ \| |__   __ _ _ __  
#         \ \ /\ / / _` | | | __) | '_ \ / _` | '_ \ 
#          \ V  V / (_| | | |/ __/| |_) | (_| | | | |
#           \_/\_/ \__,_|_|_|_____|_.__/ \__,_|_| |_|
#   
################################################################################


$DebugPreference = if ($Silent) { "SilentlyContinue" } else { "Continue" }


################################################################################
#  Configurable Variables
################################################################################

$BannedIPsStateFile = $PSScriptRoot + "\bannedIPs.json"
$RecordEventLog = "Application"     # Where we store our own event messages
$FirewallRulePrefix = "wail2ban block:" # What we name our Rules

################################################################################
#  End of Configurable Variables
################################################################################

New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')

$BannedIPs = @{}
$TrackedIPs = @{}

# Define whitelist IPs
$Whitelist = $WhiteList -split '\s+' | Where-Object { $_ -ne "" }

# Create a DataTable to store event logs and IDs
$CheckEventsTable = New-Object System.Data.DataTable
$CheckEventsTable.Columns.Add("EventLog") | Out-Null
$CheckEventsTable.Columns.Add("EventID") | Out-Null

# Split events string into components and validate pair structure
$eventComponents = $EventsToTrack -split '\s+'
if ($eventComponents.Count % 2 -ne 0) {
    Write-Error "Invalid EventsToTrack format - must contain event pairs in 'LogName EventID' format"
    exit 1
}

# Process each log/eventID pair
for ($i = 0; $i -lt $eventComponents.Count; $i += 2) {
    $logName = $eventComponents[$i]
    $eventID = $eventComponents[$i + 1]
    
    if ($logName -in @("Security", "Application", "System")) {
        $CheckEventsTable.Rows.Add($logName, $eventID) | Out-Null
    } else {
        Write-Error "Invalid event log type: $logName. Allowed values are Security, Application, System."
    }
}

# We also want to whitelist this machine's NICs.
$SelfList = @() 
$SelfList += (Get-NetIPAddress -AddressFamily IPv4).IPAddress

################################################################################
# Functions
################################################################################

function _LogEventMessage ($text, $task) {
    $e = New-Object System.Diagnostics.EventLog($RecordEventLog)
    $e.Source = "wail2ban"
    switch ($task) {
        "BAN" { $logeventID = 1000 }
        "UNBAN" { $logeventID = 2000 }
    }
    $e.WriteEntry($text, [System.Diagnostics.EventLogEntryType]::Information, $logeventID)
}

# Log type functions
function _Error       ($action, $ip, $reason) { _WriteLog "E" $action $ip $reason }
function _Warning     ($action, $ip, $reason) { _WriteLog "W" $action $ip $reason }
function _Debug       ($action, $ip, $reason) { _WriteLog "D" $action $ip $reason }

# Log things to the console
function _WriteLog ($type, $action, $ip, $reason) {
    $timestamp = (Get-Date -format u).replace("Z", "")
    $output = "[$timestamp] ${action}: $ip - $reason"
    switch ($type) {
        "D" { Write-Debug $output }
        "W" { Write-Warning "WARNING: $output" }
        "E" { Write-Error "ERROR: $output" }
    }
}
	 
# Get the current list of wail2ban bans
function _GetJailList {
    return Get-NetFirewallRule -DisplayName "$($FirewallRulePrefix)*" | Select-Object @{Name = 'name'; Expression = { $_.DisplayName } }, @{Name = 'description'; Expression = { $_.Description } }
}

# Confirm if rule exists.
function _RuleExists ($IP) {
    $ruleName = "$FirewallRulePrefix $IP"
    return [bool](Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
}

# Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
function _Netmask($MaskLength) {
    $IPAddress = [UInt32]([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
    $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
            $Remainder = $IPAddress % [Math]::Pow(256, $i)
            ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
            $IPAddress = $Remainder
        } )

    Return [String]::Join('.', $DottedIP)
}
  
# Check if IP is whitelisted
function _Whitelisted($IP) {
    $Whitelisted = $null
    foreach ($wl in $Whitelist) {
        if ($IP -eq $wl) { $Whitelisted = "Uniquely listed."; break }
        if ($wl.Contains("/")) {
            try {
                $Mask = _Netmask($wl.Split("/")[1])
                $subnet = $wl.Split("/")[0]
                if ((([net.ipaddress]$IP).Address -Band ([net.ipaddress]$Mask).Address ) -eq `
                    (([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address )) {
                    $Whitelisted = "Contained in subnet $wl"; break;
                }
            } catch {
                _Warning "WHITELIST" $wl "Invalid CIDR format in whitelist, skipping."
            }
        }
    }
    return $Whitelisted
} 

# Read in the saved file of settings. Only called on script start.
function _LoadBannedIPsState {
    if (Test-Path $BannedIPsStateFile) {
        try {
            $content = Get-Content $BannedIPsStateFile -Raw -ErrorAction Stop
            if (-not ([string]::IsNullOrWhiteSpace($content))) {
                $loadedIPs = $content | ConvertFrom-Json -ErrorAction Stop
                if ($loadedIPs) {
                     # $BannedIPs is a hashtable, ConvertFrom-Json returns PSCustomObject. We must convert it.
                     foreach($prop in $loadedIPs.psobject.Properties) {
                         $BannedIPs[$prop.Name] = $prop.Value
                     }
                }
                _Debug "STATE" "wail2ban" "$($BannedIPs.Count) ban counts loaded from $BannedIPsStateFile"
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            _Error "STATE LOAD FAILED" "wail2ban" "Could not load or parse $BannedIPsStateFile. Error: `"$errorMessage`""
        }
    }
    else { 
        _Debug "STATE" "wail2ban" "No state file found at $BannedIPsStateFile"
    }
}

# Save the current ban counts to the state file
function _SaveBannedIPsState {
    try {
        $BannedIPs | ConvertTo-Json -Depth 5 | Out-File $BannedIPsStateFile -Encoding utf8 -ErrorAction Stop
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "STATE SAVE FAILED" "wail2ban" "Could not save state to $BannedIPsStateFile. Error: `"$errorMessage`""
    }
}

# Get the ban time for an IP, in seconds
function _GetBanDuration ($IP) {
    if ($BannedIPs.ContainsKey($IP)) {
        [int]$count = $BannedIPs.Get_Item($IP)
    }
    else {
        $count = 0
        $BannedIPs.Add($IP, $count)
    }
    $count += 1
    $BannedIPs.Set_Item($IP, $count)
    $BanDuration = [math]::min([math]::pow(5, $count) * 60, $MaxBanDuration)
    _Debug "IP $IP has the new count of $count, being $BanDuration seconds"
    _SaveBannedIPsState
    return $BanDuration
}

# Ban the IP (with checking)
function _JailLockup ($IP, $ExpireDate) {
    $result = _Whitelisted($IP)
    if ($result) { _Warning "WHITELISTED" $IP "Attempted to ban whitelisted IP" }
    elseif ($SelfList -contains $IP) { _Warning "WHITELISTED" $IP "Attempted to ban self IP" }
    else {
        if (_RuleExists $IP) {
            _Warning "ALREADY BANNED" $IP "Attempted to ban already banned IP"
        }
        else {
            if (!$ExpireDate) {
                $BanDuration = _GetBanDuration($IP)
                $ExpireDate = (Get-Date).AddSeconds($BanDuration)
            }

            _FirewallAdd $IP $ExpireDate

            $jsonLog = @{
                "IP" = $IP;
                "BanCount" = $BannedIPs.Get_Item($IP);
                "BanDurationSeconds" = $BanDuration;
                "ExpireDate" = $ExpireDate
            } | ConvertTo-Json -Compress
            _LogEventMessage $jsonLog BAN

        }
    }
}

# Unban the IP (with checking)
function _JailRelease ($IP) {
    if (-not (_RuleExists $IP)) {
        _Debug "NOT BANNED" $IP "Attempted to unban IP that is not banned"
    }
    else {
        _FirewallRemove  $IP
    }
}

# Add the Firewall Rule
function _FirewallAdd ($IP, $ExpireDate) {
    $Expire = (Get-Date $ExpireDate -format u).replace("Z", "")
    $ruleName = "$FirewallRulePrefix $IP"
    $description = "Expire: $Expire"

    try {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol Any -Action Block -RemoteAddress $IP -Description $description -ErrorAction Stop | Out-Null
        _Debug "BAN" $IP "Firewall rule added, expiring on $ExpireDate"
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "BAN FAILED" $IP "Could not add firewall rule. Error: `"$errorMessage`""
    }
}

# Remove the Filewall Rule
function _FirewallRemove ($IP) {
    $ruleName = "$FirewallRulePrefix $IP"
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop | Out-Null
        _Debug "UNBAN" $IP "Firewall ban removed"
        _LogEventMessage "UNBAN: $IP - Firewall ban removed" UNBAN
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "UNBAN FAILED" $IP "Could not remove firewall rule. Error: `"$errorMessage`""
    }
}

# Remove any expired bans
function _UnbanOldRecords {
    $jail = _GetJailList
    if ($jail) {
        foreach ($inmate in $jail) {
            $IP = $inmate.Name.substring($FirewallRulePrefix.length + 1)
            $ReleaseDate = $inmate.Description.substring("Expire: ".Length)
			
            if ($([int]([datetime]$ReleaseDate - (Get-Date)).TotalSeconds) -lt 0) {
                _Debug "EXPIRED BAN" $IP "Ban expired at $(Get-Date $ReleaseDate -format G)"
                _JailRelease $IP
            }
        }
    }
}

# Tracks failed login attempts from a given IP.
function _TrackIP($IP) {
    if ($TrackedIPs.ContainsKey($IP)) {
        $TrackedIPs[$IP].Count += 1
        $TrackedIPs[$IP].Timestamps.Add((Get-Date))
    }
    else {
        $TrackedIPs[$IP] = @{
            Count = 1
            Timestamps = [System.Collections.Generic.List[datetime]]::new()
        }
        $TrackedIPs[$IP].Timestamps.Add((Get-Date))
    }

    # Remove old timestamps
    $TrackedIPs[$IP].Timestamps.RemoveAll({
        $_ -is [datetime] -and $_.AddSeconds($CheckWindow) -lt (Get-Date)
    }) | Out-Null
    $TrackedIPs[$IP].Count = $TrackedIPs[$IP].Timestamps.Count

    if ($TrackedIPs[$IP].Count -ge $CheckCount) {
        _JailLockup $IP
        $TrackedIPs.Remove($IP)
    }
}

function _InstallScheduledTask {
    $taskName = "wail2ban"
    $action = New-ScheduledTaskAction -Execute (Get-Process -Id $PID).Path -Argument "-ExecutionPolicy Bypass -File $($PSScriptRoot)\wail2ban.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
    Write-Host "Scheduled task 'wail2ban' installed successfully."
}

# Handle script argupments
function _HandleCli {
    if ($install) {
        _InstallScheduledTask
        exit
    }

    if ($html) {  # Add this condition
        _GetHTMLReport
        exit
    }

    if ($ListBans) {
        $inmates = _GetJailList
        if ($inmates) {
            "wail2ban currently banned listings: `n"
            foreach ($a in $inmates) {
                $IP = $a.name.substring($FirewallRulePrefix.length + 1)
                $Expire = $a.description.substring("Expire: ".length)
                "" + $IP.PadLeft(14) + " expires at $Expire"
            }
            "`nThis is a listing of the current Windows Firewall with Advanced Security rules, starting with `"" + $FirewallRulePrefix + " *`""
        }
        else { "There are no currrently banned IPs" }
        exit
    }

    if ($UnbanIP) {
        _Debug "UNBAN" $UnbanIP "Unban IP invoked from command line"
        _JailRelease $UnbanIP
        if ($BannedIPs.ContainsKey($UnbanIP)) {
            $BannedIPs.Remove($UnbanIP) | Out-Null
            _SaveBannedIPsState
            _Debug "UNBAN" $UnbanIP "Removed from persistent ban list."
        }
        exit
    }

    if ($ClearAllBans) {
        _Debug "JAILBREAK" "wail2ban" "Jailbreak initiated by console. Removing ALL IPs currently banned"
        $EnrichmentCentre = _GetJailList
        if ($EnrichmentCentre) {
            foreach ($subject in $EnrichmentCentre) {
                $IP = $subject.name.substring($FirewallRulePrefix.length + 1)
                _FirewallRemove $IP
            }
            $BannedIPs.Clear()
            _SaveBannedIPsState
        }
        else { "No current firewall listings to remove." }
        exit
    }
}

function _GetHTMLReport {
    $startTime = (Get-Date).AddDays(-$ReportDays)
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'wail2ban'
        ID           = 1000
        StartTime    = $startTime
    } -ErrorAction SilentlyContinue

    $jsonLog = @()
    foreach ($e in $events) {
        try {
            $logObject = $e.Message | ConvertFrom-Json
            $logObject | Add-Member -NotePropertyName TimeCreated -NotePropertyValue $e.TimeCreated
            $jsonLog += $logObject
        } catch {
            Write-Warning "Failed to parse message for event $($e.Id)"
        }
    }

    $ipStats = $jsonLog | Group-Object -Property ip | 
               Select-Object @{Name='IP'; Expression={$_.Name}}, 
                             @{Name='Count'; Expression={$_.Count}},
                             @{Name='TotalBanDuration'; Expression={
                                 if ($_.Count -gt 1) {
                                     $firstBan = $_.Group[-1].TimeCreated
                                     $lastBan = $_.Group[0].TimeCreated
                                     $duration = $lastBan - $firstBan
                                     "{0}d {1}h {2}m" -f $duration.Days, $duration.Hours, $duration.Minutes
                                 } else {
                                     "N/A"
                                 }
                             }} |
               Sort-Object Count -Descending

    $totalEvents = $jsonLog.Count
    $uniqueIPs = $ipStats.Count

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>WAIL2Ban Report</title>
    <style>
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>WAIL2Ban Report (Last $ReportDays Days)</h1>
    
    <h2>IP Statistics</h2>
    <table>
        <tr><th>IP Address</th><th>Count</th><th>Total Ban Duration</th><th>Details</th></tr>
        $(if ($ipStats) {
            ($ipStats | ForEach-Object {
                "<tr><td>$($_.IP)</td><td>$($_.Count)</td><td>$($_.TotalBanDuration)</td>" +
                "<td><a href='https://www.abuseipdb.com/check/$($_.IP)' target='_blank'>View Details</a></td></tr>"
            }) -join "`n"
        } else {
            "<tr><td colspan='4'>No events found</td></tr>"
        })
    </table>
    
    <h2>Total Statistics</h2>
    <table>
        <tr><th>Total Events</th><td>$totalEvents</td></tr>
        <tr><th>Unique IPs</th><td>$uniqueIPs</td></tr>
    </table>
</body>
</html>
"@

    $reportPath = Join-Path $PSScriptRoot "report.html"
    $html | Out-File $reportPath -Force
}

function Main {
    _LoadBannedIPsState
    _HandleCli

    _Debug "START" "wail2ban" "wail2ban invoked"

    _Debug "CONFIG" "wail2ban" "Checking for a heap of events: "
    $CheckEventsTable | ForEach-Object { _Debug  "CONFIG" "wail2ban" " - $($_.EventLog) log event code $($_.EventID)" }
    _Debug "CONFIG" "wail2ban" "The Whitelist: $Whitelist"
    _Debug "CONFIG" "wail2ban" "The Self-list: $Selflist"

    while ($true) {
        $eventFilter = @{
            LogName = @($CheckEventsTable.EventLog | Get-Unique)
            ID = @($CheckEventsTable.EventID | Get-Unique)
            StartTime = (Get-Date).AddSeconds(-$LoopDuration)
        }

        $events = Get-WinEvent -FilterHashtable $eventFilter -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($e in $events) {
                $message = $e.Message
                Select-String $RegexIP -input $message -AllMatches | ForEach-Object { 
                    foreach ($a in $_.matches) {
                        $IP = $a.Value
                        if ($SelfList -notcontains $IP -and -not (_Whitelisted $IP)) {
                            if (-not (_RuleExists $IP)) {
                                _TrackIP $IP
                            }
                        }
                    }
                }
            }
        }

        _UnbanOldRecords
        Start-Sleep -Seconds $LoopDuration
    }
}


Main

