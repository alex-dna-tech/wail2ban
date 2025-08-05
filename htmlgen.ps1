# Rewrite to use bannedIPs.json. AI!
#
#wail2ban  statistics
$BannedIPLog = $PSScriptRoot + "\bannedIPLog.ini"
$logFile = $PSScriptRoot + "\wail2ban_log.log"

$HTMLFile = $PSScriptRoot + "\public_html/index.html"
function _Html ($a) { $a | out-file $HTMLFile -append }
"" | out-file $HTMLFile; clear-content $HTMLFile

$BannedIPs = @{ }; if (Test-Path $BannedIPLog) {
    get-content $BannedIPLog | ForEach-Object {
        if (!$BannedIPs.ContainsKey($_.split(" ")[0])) { $BannedIPs.Add($_.split(" ")[0], $_.split(" ")[1]) }
    }
}

$BannedIPSum = 0; $BannedIPs.keys | ForEach-Object { $BannedIPSum += [int]($BannedIPs.Get_Item($_)) }
$TotalBans = 0; $BannedIPs.GetEnumerator() | ForEach-Object { $TotalBans += [math]::pow(5, $_.value) }
$MaxBanCount = ($BannedIPs.GetEnumerator() | Sort-Object value -descending | Select-Object -first 1).Value

Get-Content $logFile | ForEach-Object {	if ($_ -match "Firewall ban for ") { $BanCount-- }
    if ($_ -match "Firewall rule added for ") { $BanCount++ } }

$SinceLine = Get-Content $logfile | Select-Object -first 1
#Get-Content $logfile | ForEach-Object { if ($_ -match "jailbreak") { $SinceLine = $_ } }
$Since = $SinceLine.substring(0, $SinceLine.indexOf("  "))

$ExeTime = $([int]((Get-Date) - [datetime]$Since).TotalMinutes)
$nbsp = "&nbsp; &nbsp;  "

_Html "<title>wail2ban statistics for  $((Get-Content env:computername).ToLower())</title>"
_Html "<table><tr><td><img src=`"wail2ban.png`" alt=`"Saddest Whale`" /></p>"
_Html "</td><td>&nbsp;</td><td><H1>wail2ban statistics for $((Get-Content env:computername).ToLower())</H1>"
_Html "<p>Bans: $BanCount current, $BannedIPSum total ($([math]::round($TotalBans/60,0)) hours)</p>"
_Html "An IP is banned once every $([math]::round($ExeTime/$BannedIPSum,0)) minutes, on average.<br/>"
_Html "This script has dealt $([math]::round($TotalBans / $ExeTime,0)) minutes of banhammer per minute of script execution.</p>"
_Html "These IPs have all been banned $MaxBanCount times, and are currently serving $([math]::round([math]::pow(5,$MaxBanCount)/60,0))  hours in jail.<br/><br/>"

_Html "<table>"
$TableColumns = 4; $out = 0;
$BannedIPs.GetEnumerator() | Sort-Object name | ForEach-Object { if ($_.value -eq $MaxBanCount) {
        _Html "<td>$($_.Name)</td><td><a href=`"http://ip.robtex.com/$($_.name).html`#whois`" target=_blank><img src=`"http://api.hostip.info/flag.php?ip=$($_.Name)`" height=20 width=35> </a></td><td>$nbsp</td>"
        $out++
        if ($out % $TableColumns -eq 0) { _Html "</tr><tr>" }
    } }
_Html "</table>"

_Html "<br/><br/><small>click the flag for robtex information for the IP<br/>"
_Html "<i>Statistics started $(Get-Date $Since -format u), last updated $(Get-Date -format u)</i></small></table>"
