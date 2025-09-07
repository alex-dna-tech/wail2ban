<#
.SYNOPSIS
    Generates an HTML report of wail2ban activity.
.DESCRIPTION
    This script reads the wail2ban event logs and creates an HTML report summarizing banned IPs.
.PARAMETER ReportDays
    Specifies the number of days to include in the report (default is 7).
.PARAMETER Mail
    If specified, the report will be sent via email.
.PARAMETER SmtpServer
    The address of the SMTP server. Required if -Mail is specified.
.PARAMETER SmtpPort
    The port to use on the SMTP server.
.PARAMETER EmailFrom
    The sender's email address. Required if -Mail is specified.
.PARAMETER EmailTo
    The recipient's email address(es). Required if -Mail is specified.
.PARAMETER Cred
    Path to the credential file for SMTP authentication. Required if -Mail is specified.
.PARAMETER GenCred
    If specified, prompts for SMTP credentials and saves them to the path specified by -Cred.
#>
[CmdletBinding()]
param (
    [int]$ReportDays = 7,
    [switch]$Mail,
    [string]$SmtpServer,
    [int]$SmtpPort = 587,
    [string]$EmailFrom,
    [string[]]$EmailTo,
    [string]$Cred,
    [switch]$GenCred
)

if ($Mail) {
    $missingParams = [System.Collections.Generic.List[string]]@()
    if (-not $SmtpServer) { $missingParams.Add('SmtpServer') }
    if (-not $EmailFrom)  { $missingParams.Add('EmailFrom') }
    if (-not $EmailTo)    { $missingParams.Add('EmailTo') }
    if (-not $Cred)       { $missingParams.Add('Cred') }

    if ($missingParams.Count -gt 0) {
        foreach ($p in $missingParams) {
            Write-Debug "Required parameter for -Mail is not set: -$p"
        }
        Write-Error "The following required parameters for -Mail are missing: $(($missingParams | ForEach-Object { "-$_" }) -join ', ')"
        exit 1
    }
}

if ($GenCred) {
    if (-not $Cred) {
        Write-Error "The -Cred parameter specifying the path for the credential file is required when using -GenCred."
        exit 1
    }

    $EmailLogin = Read-Host "Enter SMTP Username"
    
    $SecurePassword =  Read-Host "Enter SMTP Password" -AsSecureString

    $credential = New-Object System.Management.Automation.PSCredential ($EmailLogin, $SecurePassword)
    try {
        $credential | Export-Clixml -Path $Cred -Force
        Write-Host "Credential file saved to $Cred"
    } catch {
        Write-Error "Failed to save credential file to '$Cred'. Error: $_"
        exit 1
    }
    exit 0
}

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

    return [pscustomobject]@{
        Html      = $html
        DateRange = $dateRange
    }
}


if ($Mail) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    try {
        $credential = Import-Clixml -Path $Cred
    } catch {
        Write-Error "Failed to import credential file from '$Cred'. Error: $_"
        exit 1
    }

    $reportData = Get-Wail2BanHTMLReport
    $mailParams = @{
        From        = $EmailFrom
        To          = $EmailTo
        Subject     = "WAIL2Ban Report $($reportData.DateRange)"
        Body        = $reportData.Html
        BodyAsHtml  = $true
        SmtpServer  = $SmtpServer
        Port        = $SmtpPort
        Credential  = $credential
        UseSsl      = $true
    }

    try {
        Send-MailMessage @mailParams -ErrorAction Stop
        Write-Host "Email report sent successfully to $($EmailTo -join ', ')."
    } catch {
        Write-Error "Failed to send email report. Error: $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
        }
    }

    exit 0
}

$reportData = Get-Wail2BanHTMLReport
$reportPath = Join-Path $PSScriptRoot "report.html"
$reportData.Html | Out-File $reportPath -Force
Write-Host "Report generated at $reportPath"

