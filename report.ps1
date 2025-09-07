<#
.SYNOPSIS
    Generates an HTML report of wail2ban activity.
.DESCRIPTION
    This script reads the wail2ban event logs and creates an HTML report summarizing banned IPs.
.PARAMETER ReportDays
    Specifies the number of days to include in the report (default is 7).
#>
[CmdletBinding()]
param (
    [int]$ReportDays = 7
)

function Get-Wail2BanHTMLReport {
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
                             @{Name='Count'; Expression={($_.Group | Measure-Object BanCount -Maximum).Maximum}},
                             @{Name='TotalBanDuration'; Expression={
                                 $totalSeconds = ($_.Group | Measure-Object BanDurationSeconds -Sum).Sum
                                 $days = [math]::Floor($totalSeconds / 86400)
                                 $hours = [math]::Floor(($totalSeconds % 86400) / 3600)
                                 $minutes = [math]::Floor(($totalSeconds % 3600) / 60)
                                 "$days d $hours h $minutes m"
                             }} |
               Sort-Object Count -Descending

    $totalEvents = $jsonLog.Count
    $uniqueIPs = $ipStats.Count

    $dateRange = "$($startTime.ToString('yy-MM-dd')) - $((Get-Date).ToString('yy-MM-dd'))"
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
    <h1>WAIL2Ban Report $dateRange (Last $ReportDays Days)</h1>
    
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
    Write-Host "Report generated at $reportPath"
}

Get-Wail2BanHTMLReport
