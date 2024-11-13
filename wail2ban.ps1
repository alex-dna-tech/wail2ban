################################################################################
#                        _ _ ____  _                 
#         __      ____ _(_) |___ \| |__   __ _ _ __  
#         \ \ /\ / / _` | | | __) | '_ \ / _` | '_ \ 
#          \ V  V / (_| | | |/ __/| |_) | (_| | | | |
#           \_/\_/ \__,_|_|_|_____|_.__/ \__,_|_| |_|
#   
################################################################################
# 
# For help, read the below function. 
#
function _Help {
    "`nwail2ban   `n"
    "wail2ban is an attempt to recreate fail2ban for windows, hence [w]indows f[ail2ban]."
    " "
    "wail2ban takes configured events known to be audit failures, or similar, checks for " + `
        "IPs in the event message, and given sufficient failures, bans them for a small amount" + `
        "of time."
    " "
    "Settings: "
    " -config    : show the settings that are being used "
    " -jail      : show the currently banned IPs"
    " -jailbreak : bust out all the currently banned IPs"
    " -unban     : release by IP"
    " -help      : This message."
    " "
}


$DebugPreference = "continue"

################################################################################
#  Constants

$CHECK_WINDOW = 600  # We check the most recent X seconds of log.        Default: 600 
$CHECK_COUNT = 5    # Ban after this many failures in search period.     Default: 5
$MAX_BANDURATION = 7776000 # 3 Months in seconds
	
################################################################################
#  Files

$wail2banInstall = "$PSScriptRoot\"
$logFile = $wail2banInstall + "wail2ban_log.log"
$ConfigFile = $wail2banInstall + "wail2ban_config.ini"
$BannedIPLog = $wail2banInstall + "bannedIPLog.ini"

################################################################################
# Constructs

$RecordEventLog = "Application"     # Where we store our own event messages
$FirewallRulePrefix = "wail2ban block:" # What we name our Rules

$EventTypes = "Application,Security,System"	  #Event logs we allow to be processed

New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')

# Ban Count structure
$BannedIPs = @{ }
# Incoming event structure
$CheckEvents = New-object system.data.datatable("CheckEvents")
$null = $CheckEvents.columns.add("EventLog")
$null = $CheckEvents.columns.add("EventID")
$null = $CheckEvents.columns.add("EventDescription")
	  
$WhiteList = @()
#$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(100,50)

$OSVersion = invoke-expression "wmic os get Caption /value"
$BLOCK_TYPE = "NETSH"

#Grep configuration file 
switch -regex -file $ConfigFile {
    "^\[(.+)\]$" {
        $Header = $matches[1].Trim()
    }
    "^\s*([^#].+?)\s*=\s*(.*)" {
        $Match1 = $matches[1]
        $Match2 = $matches[2]
		
        if ( $EventTypes -match $Header ) {
            $row = $CheckEvents.NewRow()
            $row.EventLog = $Header
            $row.EventID = $Match1
            $row.EventDescription = $Match2
            $CheckEvents.Rows.Add($row)
        }
        else {
            switch ($Header) {
                "Whitelist" { $WhiteList += $Match1; }
            }
        }
    }
	
} 


#We also want to whitelist this machine's NICs.
$SelfList = @() 
foreach ($listing in ((ipconfig | findstr [0-9].\.))) {
    if ($listing -match "IPv4" ) { $SelfList += $listing.Split()[-1] }
} 

################################################################################
# Functions

function _LogEventMessage ($text, $task, $result) {
    $event = new-object System.Diagnostics.EventLog($RecordEventLog)
    $event.Source = "wail2ban"
    switch ($task) {
        "ADD" { $logeventID = 1000 }
        "REMOVE" { $logeventID = 2000 }
    }
    switch ($result) {
        "FAIL" { $eventtype = [System.Diagnostics.EventLogEntryType]::Error; $logeventID += 1 }
        default { $eventtype = [System.Diagnostics.EventLogEntryType]::Information }
    }
    $event.WriteEntry($text, $eventType, $logeventID)
}

#Log type functions
function _Error       ($text) { _LogToFile "E" $text }
function _Warning     ($text) { _LogToFile "W" $text }
function _Debug       ($text) { _LogToFile "D" $text }
function _Actioned    ($text) { _LogToFile "A" $text }

#Log things to file and debug
function _LogToFile ($type, $text) {
    $output = "" + (Get-Date -format u).replace("Z", "") + " $tag $text"
    if ($type -eq "A") { $output | Out-File $logfile -append }
    switch ($type) {
        "D" { Write-Debug $output }
        "W" { Write-Warning "WARNING: $output" }
        "E" { Write-Error "ERROR: $output" }
        "A" { Write-Debug $output }
    }
}
	 
#Get the current list of wail2ban bans
function _GetJailList {
    $fw = New-Object -ComObject hnetcfg.fwpolicy2
    return $fw.rules | Where-Object { $_.name -match $FirewallRulePrefix } | Select-Object name, description
}

# Confirm if rule exists.
function _RuleExists ($IP) {
    switch ($BLOCK_TYPE) {
        "NETSH" { $Rule = "netsh advfirewall firewall show rule name=`"$FirewallRulePrefix $IP`"" }
        default { _Error "Don't have a known Block Type. $BLOCK_TYPE" }
    }
    if ($rule) {
        $result = Invoke-Expression $rule
        if ($result -match "----------") {
            return "Yes"
        }
        else {
            return "No"
        }
    }
}

#Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
function _Netmask($MaskLength) {
    $IPAddress = [UInt32]([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
    $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
            $Remainder = $IPAddress % [Math]::Pow(256, $i)
            ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
            $IPAddress = $Remainder
        } )

    Return [String]::Join('.', $DottedIP)
}
  
#check if IP is whitelisted
function _Whitelisted($IP) {
    foreach ($white in $Whitelist) {
        if ($IP -eq $white) { $Whitelisted = "Uniquely listed."; break }
        if ($white.contains("/")) {
            $Mask = _Netmask($white.Split("/")[1])
            $subnet = $white.Split("/")[0]
            if ((([net.ipaddress]$IP).Address -Band ([net.ipaddress]$Mask).Address ) -eq `
                (([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address )) {
                $Whitelisted = "Contained in subnet $white"; break;
            }
        }
    }
    return $Whitelisted
} 

#Read in the saved file of settings. Only called on script start, such as after reboot
function _PickupBanDuration {
    if (Test-Path $BannedIPLog) {
        Get-Content $BannedIPLog | ForEach-Object {
            if (!$BannedIPs.ContainsKey($_.split(" ")[0])) { $BannedIPs.Add($_.split(" ")[0], $_.split(" ")[1]) }
        }
        _Debug "$BannedIPLog ban counts loaded"
    }
    else { _Debug "No IPs to collect from BannedIPLog" }
} 

#Get the ban time for an IP, in seconds
function _GetBanDuration ($IP) {
    if ($BannedIPs.ContainsKey($IP)) {
        [int]$Setting = $BannedIPs.Get_Item($IP)
    }
    else {
        $Setting = 0
        $BannedIPs.Add($IP, $Setting)
    }
    $Setting++
    $BannedIPs.Set_Item($IP, $Setting)
    $BanDuration = [math]::min([math]::pow(5, $Setting) * 60, $MAX_BANDURATION)
    _Debug "IP $IP has the new setting of $setting, being $BanDuration seconds"
    if (Test-Path $BannedIPLog) { clear-content $BannedIPLog } else { New-Item $BannedIPLog -type file }
    $BannedIPs.keys | ForEach-Object { "$_ " + $BannedIPs.Get_Item($_) | Out-File $BannedIPLog -Append }
    return $BanDuration
}

# Ban the IP (with checking)
function _JailLockup ($IP, $ExpireDate) {
    $result = _Whitelisted($IP)
    if ($result) { _Warning "$IP is whitelisted, except from banning. Why? $result " }
    else {
        if (!$ExpireDate) {
            $BanDuration = _GetBanDuration($IP)
            $ExpireDate = (Get-Date).AddSeconds($BanDuration)
        }
        if ((_RuleExists $IP) -eq "Yes") {
            _Warning ("IP $IP already blocked.")
        }
        else {
            _FirewallAdd $IP $ExpireDate
        }
    }
}

# Unban the IP (with checking)
function _JailRelease ($IP) {
    if ((_RuleExists $IP) -eq "No") {
        _Debug "$IP firewall listing doesn't exist. Can't remove it. "
    }
    else {
        _FirewallRemove  $IP
    }
}

# Add the Firewall Rule
function _FirewallAdd ($IP, $ExpireDate) {
    $Expire = (Get-Date $ExpireDate -format u).replace("Z", "")
    switch ($BLOCK_TYPE) {
        "NETSH" { $Rule = "netsh advfirewall firewall add rule name=`"$FirewallRulePrefix $IP`" dir=in protocol=any action=block remoteip=$IP description=`"Expire: $Expire`"" }
        default { _Error "Don't have a known Block Type. $BLOCK_TYPE" }
    }
    if ($rule) {
        $result = Invoke-Expression $rule
        if ($LASTEXITCODE -eq 0) {
            $BanMsg = "Action Successful: Firewall rule added for $IP, expiring on $ExpireDate"
            _Actioned "$BanMsg"
            _LogEventMessage "$BanMsg" ADD OK
        }
        else {
            $Message = "Action Failure: could not add firewall rule for $IP,  error: `"$result`". Return code: $LASTEXITCODE"
            _Error $Message
            _LogEventMessage $Message ADD FAIL
        }
    }
}

# Remove the Filewall Rule
function _FirewallRemove ($IP) {
    switch ($BLOCK_TYPE) {
        "NETSH" { $Rule = "netsh advfirewall firewall delete rule name=`"$FirewallRulePrefix $IP`"" }
        default { _Error "Don't have a known Block Type. $BLOCK_TYPE" }
    }
    if ($rule) {
        $result = Invoke-Expression $rule
        if ($LASTEXITCODE -eq 0) {
            _Actioned "Action Successful: Firewall ban for $IP removed"
            _LogEventMessage "Removed IP $IP from firewall rules"  REMOVE OK
        }
        else {
            $Message = "Action Failure: could not remove firewall rule for $IP,  error: `"$result`". Return code: $LASTEXITCODE"
            _Error $Message
            _LogEventMessage $Message REMOVE FAIL
        }
    }
}

#Remove any expired bans
function _UnbanOldRecords {
    $jail = _GetJailList
    if ($jail) {
        foreach ($inmate in $jail) {
            $IP = $inmate.Name.substring($FirewallRulePrefix.length + 1)
            $ReleaseDate = $inmate.Description.substring("Expire: ".Length)
			
            if ($([int]([datetime]$ReleaseDate - (Get-Date)).TotalSeconds) -lt 0) {
                _Debug "Unban old records: $IP looks old enough $(Get-Date $ReleaseDate -format G)"
                _JailRelease $IP
            }
        }
    }
}

#Convert the TimeGenerated time into Epoch
function _WMIDateStringToDateTime( [String] $iSt ) {
    $iSt.Trim() > $null
    $iYear = [Int32]::Parse($iSt.SubString( 0, 4))
    $iMonth = [Int32]::Parse($iSt.SubString( 4, 2))
    $iDay = [Int32]::Parse($iSt.SubString( 6, 2))
    $iHour = [Int32]::Parse($iSt.SubString( 8, 2))
    $iMinute = [Int32]::Parse($iSt.SubString(10, 2))
    $iSecond = [Int32]::Parse($iSt.SubString(12, 2))
    $iMilliseconds = 0
    $iUtcOffsetMinutes = [Int32]::Parse($iSt.Substring(21, 4))
    if ( $iUtcOffsetMinutes -ne 0 ) { $dtkind = [DateTimeKind]::Local }
    else { $dtkind = [DateTimeKind]::Utc } 
    $ReturnDate = New-Object -TypeName DateTime -ArgumentList $iYear, $iMonth, $iDay, $iHour, $iMinute, $iSecond, $iMilliseconds, $dtkind
    return (Get-Date $ReturnDate -UFormat "%s")
} 


# Remove recorded access attempts, by IP, or expired records if no IP provided.
function _ClearAttempts ($IP = 0) {
    $Removes = @()
    foreach ($a in $Entry.GetEnumerator()) {
        if ($IP -eq 0) {
            if ([int]$a.Value[1] + $CHECK_WINDOW -lt (Get-Date ((Get-Date).ToUniversalTime()) -UFormat "%s").replace(",", ".")) { $Removes += $a.Key }
        }
        else {
            foreach ($a in $Entry.GetEnumerator()) { if ($a.Value[0] -eq $IP) {	$Removes += $a.Key } }
        }
    }
    foreach ($b in $Removes) { $Entry.Remove($b) }
}

################################################################################
#Process input parameters
if ($setting) { _Debug "wail2ban started. $setting" }

#Display current configuration.
if ($args -match "-config") { 
    Write-Host "`nwail2ban is currently configured to: `n ban IPs for " -nonewline
    for ($i = 1; $i -lt 5; $i++) { Write-Host ("" + [math]::pow(5, $i) + ", ") -foregroundcolor "cyan" -nonewline }
    Write-Host "... $($MAX_BANDURATION/60) " -foregroundcolor "cyan" -nonewline
    Write-Host " minutes, `n if more than " -nonewline
    Write-Host $CHECK_COUNT -foregroundcolor "cyan" -nonewline
    Write-Host " failed attempts are found in a " -nonewline
    Write-Host $CHECK_WINDOW -foregroundcolor "cyan" -nonewline
    Write-Host " second window. `nThis process will loop every time a new record appears. "
    Write-Host "`nIt's currently checking:"
    foreach ($event in $CheckEvents ) { "- " + $Event.EventLog + " event log for event ID " + $Event.EventDescription + " (Event " + $Event.EventID + ")" }
    Write-Host "`nAnd we're whitelisting: "
    foreach ($white in $whitelist) {
        Write-Host "- $($white)" -foregroundcolor "cyan" -nonewline
    }
    Write-Host "in addition to any IPs present on the network interfaces on the machine"
    exit
} 

# Release all current banned IPs
if ($args -match "-jailbreak") {
    _Actioned  "Jailbreak initiated by console. Removing ALL IPs currently banned"
    $EnrichmentCentre = _GetJailList
    if ($EnrichmentCentre) {
        "`nAre you trying to escape? [chuckle]"
        "Things have changed since the last time you left the building."
        "What's going on out there will make you wish you were back in here."
        " "
        foreach ($subject in $EnrichmentCentre) {
            $IP = $subject.name.substring($FirewallRulePrefix.length + 1)
            _FirewallRemove $IP
        }
        Clear-Content $BannedIPLog
    }
    else { "`nYou can't escape, you know. `n`n(No current firewall listings to remove.)" }
    exit
}

# Show the inmates in the jail.
if ($args -match "-jail") {
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


#Unban specific IP. Remove associated schtask, if exists. 
if ($args -match "-unban") {     
    $IP = $args[ [array]::indexOf($args, "-unban") + 1]
    _Actioned  "Unban IP invoked: going to unban $IP and remove from the log."
    _JailRelease $IP
    (Get-Content $BannedIPLog) | Where-Object { $_ -notmatch $IP } | Set-Content $BannedIPLog # remove IP from ban log
    exit
}

#Display Help Message
if ($args -match "-help") { 
    _Help; exit
}

#Display Help Message
if ($args -match "-p") {
    Write-Host $setting
}

################################################################################
#Setup for the loop

$SinkName = "LoginAttempt"
$Entry = @{ }
$eventlist = "("
foreach ($a in $CheckEvents) {
    $eventlist += "(TargetInstance.EventCode=$($a.EventID) and TargetInstance.LogFile='$($a.EventLog)') OR "
}
$eventlist = $eventlist.substring(0, $eventlist.length - 4) + ")"
$query = "SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND $eventlist"

_Actioned "wail2ban invoked"

_Actioned "Checking for a heap of events: "
$CheckEvents | ForEach-Object { _Actioned  " - $($_.EventLog) log event code $($_.EventID)" }
_Actioned "The Whitelist: $Whitelist"
_Actioned "The Self-list: $Selflist"

_LogEventMessage "wail2ban invoked in $wail2banInstall. SelfList: $SelfList $Whitelist" ADD OK
_PickupBanDuration


################################################################################
#Loop!

Register-WMIEvent -Query $query -sourceidentifier $SinkName
do {
    #bedobedo
    $new_event = Wait-Event -sourceidentifier $SinkName
    $TheEvent = $new_event.SourceeventArgs.NewEvent.TargetInstance
    Select-String $RegexIP -input $TheEvent.message -AllMatches | ForEach-Object { foreach ($a in $_.matches) {
            $IP = $a.Value
            if ($SelfList -match $IP) { _Debug "Whitelist of self-listed IPs! Do nothing. ($IP)" }
            else {
                $RecordID = $TheEvent.RecordNumber
                $EventDate = _WMIDateStringToDateTime($TheEvent.TIMEGenerated)
                $Entry.Add($RecordID, @($IP, $EventDate))

                $IPCount = 0
                foreach ($a in $Entry.Values) { if ($IP -eq $a[0]) { $IPCount++ } }
                _Debug "$($TheEvent.LogFile) Log Event captured: ID $($RecordID), IP $IP, Event Code $($TheEvent.EventCode), Attempt #$($IPCount). "
			
                if ($IPCount -ge $CHECK_COUNT) {
                    _JailLockup $IP
                    _ClearAttempts $IP
                }
                _ClearAttempts
                _UnbanOldRecords
            }
        }
    }

    Remove-Event -sourceidentifier $SinkName

} while ($true)
