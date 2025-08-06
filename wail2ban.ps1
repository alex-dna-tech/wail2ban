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

.NOTES
    Author: glasnt
    License: BSD 3-Clause License
#>
param (
    [switch]$ListBans,
    [string]$UnbanIP,
    [switch]$ClearAllBans,
    [switch]$html  # Add this new parameter
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

$DebugPreference = "Continue"          # Show debug output, keep running
# $DebugPreference = "SilentlyContinue"  # Suppress debug output
# $DebugPreference = "Inquire"           # Ask what to do on debug output
# $DebugPreference = "Stop"              # Stop execution on debug output


################################################################################
#  Configurable Variables
################################################################################

$CHECK_WINDOW = 120  # We check the most recent X seconds of log.        Default: 120
$CHECK_COUNT = 5    # Ban after this many failures in search period.     Default: 5
$LOOP_DURATION = 5 # How often we check for new events, in seconds. Default: 5
$MAX_BANDURATION = 7776000 # 3 Months in seconds

$BannedIPsStateFile = $PSScriptRoot + "\bannedIPs.json"
$RecordEventLog = "Application"     # Where we store our own event messages
$FirewallRulePrefix = "wail2ban block:" # What we name our Rules

################################################################################
#  End of Configurable Variables
################################################################################

New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')

$BannedIPs = @{}
$TrackedIPs = @{}

# Define event logs and IDs
$EventsToTrack = @{
    "Security" = @{
        "4625" = "RDP Logins"
        #"18456" = "MSSQL Logins"  # Uncomment to include MSSQL logins
    }
    "Application" = @{
        #"EventID" = "Event Description"  # Add more event IDs and descriptions as needed
    }
    "System" = @{
        #"EventID" = "Event Description"  # Add more event IDs and descriptions as needed
    }
}

# Define whitelist IPs
$WhitelistIPs = @(
    # "192.168.1.0/24", 
    # "1.2.3.4" 
)

# Create a DataTable to store event logs and IDs
$CheckEventsTable = New-Object System.Data.DataTable
$CheckEventsTable.Columns.Add("EventLog") | Out-Null
$CheckEventsTable.Columns.Add("EventID") | Out-Null
$CheckEventsTable.Columns.Add("EventDescription") | Out-Null

# Populate the DataTable with event logs and IDs
foreach ($EventType in $EventsToTrack.Keys) {
    $eventSource = $EventsToTrack[$EventType]
    foreach ($EventID in $eventSource.Keys) {
        $row = $CheckEventsTable.NewRow()
        $row.EventLog = $EventType
        $row.EventID = $EventID
        $row.EventDescription = $eventSource[$EventID]
        $CheckEventsTable.Rows.Add($row)
    }
}

# We also want to whitelist this machine's NICs.
$SelfList = @() 
$SelfList += (Get-NetIPAddress -AddressFamily IPv4).IPAddress

################################################################################
# Functions
################################################################################

function _LogEventMessage ($text, $task, $result) {
    $event = new-object System.Diagnostics.EventLog($RecordEventLog)
    $event.Source = "wail2ban"
    switch ($task) {
        "ADD" { $logeventID = 1000 }
        "REMOVE" { $logeventID = 2000 }
        "LOG" { $logeventID = 3000 }
    }
    switch ($result) {
        "FAIL" { $eventtype = [System.Diagnostics.EventLogEntryType]::Error; $logeventID += 1 }
        default { $eventtype = [System.Diagnostics.EventLogEntryType]::Information }
    }
    $event.WriteEntry($text, $eventType, $logeventID)
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
    foreach ($white in $Whitelist) {
        if ($IP -eq $white) { $Whitelisted = "Uniquely listed."; break }
        if ($white.Contains("/")) {
            try {
                $Mask = _Netmask($white.Split("/")[1])
                $subnet = $white.Split("/")[0]
                if ((([net.ipaddress]$IP).Address -Band ([net.ipaddress]$Mask).Address ) -eq `
                    (([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address )) {
                    $Whitelisted = "Contained in subnet $white"; break;
                }
            } catch {
                _Warning "WHITELIST" $white "Invalid CIDR format in whitelist, skipping."
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
        [int]$Setting = $BannedIPs.Get_Item($IP)
    }
    else {
        $Setting = 0
        $BannedIPs.Add($IP, $Setting)
    }
    $Setting += 1
    $BannedIPs.Set_Item($IP, $Setting)
    $BanDuration = [math]::min([math]::pow(5, $Setting) * 60, $MAX_BANDURATION)
    _Debug "IP $IP has the new setting of $setting, being $BanDuration seconds"
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
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol Any -Action Block -RemoteAddress $IP -Description $description -ErrorAction Stop
        _Debug "BAN" $IP "Firewall rule added, expiring on $ExpireDate"
        _LogEventMessage "BAN: $IP - Firewall rule added, expiring on $ExpireDate" ADD OK
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "BAN FAILED" $IP "Could not add firewall rule. Error: `"$errorMessage`""
        _LogEventMessage "BAN FAILED: $IP - Could not add firewall rule. Error: `"$errorMessage`"" LOG FAIL
    }
}

# Remove the Filewall Rule
function _FirewallRemove ($IP) {
    $ruleName = "$FirewallRulePrefix $IP"
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
        _Debug "UNBAN" $IP "Firewall ban removed"
        _LogEventMessage "UNBAN: $IP - Firewall ban removed" REMOVE OK
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "UNBAN FAILED" $IP "Could not remove firewall rule. Error: `"$errorMessage`""
        _LogEventMessage "UNBAN FAILED: $IP - Could not remove firewall rule. Error: `"$errorMessage`"" LOG FAIL
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
        $_ -is [datetime] -and $_.AddSeconds($CHECK_WINDOW) -lt (Get-Date)
    }) | Out-Null
    $TrackedIPs[$IP].Count = $TrackedIPs[$IP].Timestamps.Count

    if ($TrackedIPs[$IP].Count -ge $CHECK_COUNT) {
        _JailLockup $IP
        $TrackedIPs.Remove($IP)
    }
}

# Handle script argupments
function _HandleCli {
    if ($html) {  # Add this condition
        html-report
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

function html-report {
    $reportPath = Join-Path $PSScriptRoot "report.html"
    "" | Out-File $reportPath -Force
    
    function _Html ($a) { $a | Out-File $reportPath -Append }

    # Email-compatible simple HTML
    _Html "<!DOCTYPE html>"
    _Html "<html><head><title>wail2ban Report</title></head><body style='font-family: Arial, sans-serif;'>"
    _Html "<h1>wail2ban Ban Statistics</h1>"

    # Get ban events from Application log
    $banEvents = Get-WinEvent -LogName Application -ProviderName wail2ban | 
        Where-Object {$_.Id -in (1000, 2000)} | 
        Sort-Object TimeCreated

    $ipStats = @{}
    $totalBans = 0
    $totalBanTime = 0

    foreach ($event in $banEvents) {
        if ($event.Id -eq 1000) {  # Ban added event
            if ($event.Message -match '(\d+\.\d+\.\d+\.\d+).*expiring on ([\d-/:. ]+)') {
                $ip = $matches[1]
                $expireDate = [datetime]::ParseExact($matches[2], 'yyyy-MM-dd HH:mm:ss', $null)
                $duration = ($expireDate - $event.TimeCreated).TotalSeconds
                
                if (-not $ipStats.ContainsKey($ip)) {
                    $ipStats[$ip] = @{
                        BanCount = 0
                        TotalDuration = 0
                    }
                }
                
                $ipStats[$ip].BanCount++
                $ipStats[$ip].TotalDuration += $duration
                $totalBans++
                $totalBanTime += $duration
            }
        }
    }

    # IP Statistics Table
    _Html "<h2>IP Ban Statistics</h2>"
    _Html "<table border='1' cellpadding='4' style='border-collapse: collapse;'>"
    _Html "<tr><th>IP Address</th><th>Total Bans</th><th>Total Ban Time</th><th>Average Ban</th></tr>"
    
    foreach ($ip in $ipStats.Keys) {
        $total = $ipStats[$ip].TotalDuration
        $avg = $total / $ipStats[$ip].BanCount
        _Html "<tr>"
        _Html "<td>$ip</td>"
        _Html "<td>$($ipStats[$ip].BanCount)</td>"
        _Html "<td>$( [math]::Round($total/3600, 1) ) hours</td>"
        _Html "<td>$( [math]::Round($avg/3600, 1) ) hours</td>"
        _Html "</tr>"
    }
    
    _Html "</table>"

    # Summary Statistics
    _Html "<h2>Summary Statistics</h2>"
    _Html "<ul>"
    _Html "<li>Total IPs banned: $($ipStats.Count)</li>"
    _Html "<li>Total bans issued: $totalBans</li>"
    _Html "<li>Total ban time: $( [math]::Round($totalBanTime/3600, 1) ) hours</li>"
    _Html "<li>Average ban time per IP: $( if ($ipStats.Count -gt 0) { [math]::Round(($totalBanTime/$ipStats.Count)/3600, 1) } else { 0 } ) hours</li>"
    _Html "</ul>"

    _Html "</body></html>"
    Write-Host "Report generated: $reportPath"
}

function Main {
    _LoadBannedIPsState
    _HandleCli

    _Debug "START" "wail2ban" "wail2ban invoked"

    _Debug "CONFIG" "wail2ban" "Checking for a heap of events: "
    $CheckEventsTable | ForEach-Object { _Debug  "CONFIG" "wail2ban" " - $($_.EventLog) log event code $($_.EventID)" }
    _Debug "CONFIG" "wail2ban" "The Whitelist: $Whitelist"
    _Debug "CONFIG" "wail2ban" "The Self-list: $Selflist"

    _LogEventMessage "wail2ban invoked in $PSScriptRoot. SelfList: $SelfList $Whitelist" LOG OK

    while ($true) {
        $eventFilter = @{
            LogName = @($CheckEventsTable.EventLog | Get-Unique)
            ID = @($CheckEventsTable.EventID | Get-Unique)
            StartTime = (Get-Date).AddSeconds(-$LOOP_DURATION)
        }

        $events = Get-WinEvent -FilterHashtable $eventFilter -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($event in $events) {
                $message = $event.Message
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
        Start-Sleep -Seconds $LOOP_DURATION
    }
}


Main

