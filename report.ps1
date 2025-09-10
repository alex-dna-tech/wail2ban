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
    If specified, prompts for SMTP credentials and saves them to the given path, then exits.
.PARAMETER Install
    Installs the scheduled task for the script.
#>
[CmdletBinding()]
param (
    [int]$ReportDays = 7,
    [switch]$Mail,
    [string]$SmtpServer,
    [int]$SmtpPort = 587,
    [string]$From,
    [string[]]$To,
    [string]$Cred,
    [string]$GenCred,
    [switch]$Install
)

function _GenerateCredentialFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $EmailLogin = Read-Host "Enter SMTP Username"
    $SecurePassword =  Read-Host "Enter SMTP Password" -AsSecureString
    $credential = New-Object System.Management.Automation.PSCredential ($EmailLogin, $SecurePassword)
    try {
        $credential | Export-Clixml -Path $Path -Force
        Write-Host "Credential file saved to $Path"
        return $true
    } catch {
        Write-Error "Failed to save credential file to '$Path'. Error: $_"
        return $false
    }
}

function _InstallScheduledTask {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Installing the scheduled task requires administrative privileges. Please run it as an administrator."
        exit 1
    }

    $taskName = "wail2ban-report"

    # Prompt for required parameters
    Write-Host "Configuring scheduled task for wail2ban report."
    $CredPath = Read-Host "Enter path to credential file (e.g., .\email.xml)"

    if (-not (Test-Path $CredPath)) {
        $choice = Read-Host "Credential file '$CredPath' does not exist. Do you want to create it now? (y/n)"
        if ($choice -eq 'y') {
            if (-not (_GenerateCredentialFile -Path $CredPath)) {
                Write-Error "Could not create credential file. Aborting installation."
                exit 1
            }
        } else {
            Write-Error "Credential file not found. Aborting installation."
            exit 1
        }
    }

    $SmtpSrv = Read-Host "Enter SMTP server address (e.g., mail.service.com)"
    $FromAddr = Read-Host "Enter sender's email address (e.g., admin@service.com)"
    $ToAddr = Read-Host "Enter recipient's email address(es), comma-separated (e.g., test@example.com)"

    # Unregister existing task if any
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    
    $arguments = "-ExecutionPolicy Bypass -File `"$($PSScriptRoot)\report.ps1`" -Mail -Cred `"$CredPath`" -SmtpServer `"$SmtpSrv`" -From `"$FromAddr`" -To `"$ToAddr`""
    $action = New-ScheduledTaskAction -Execute (Get-Command 'powershell.exe').Path -Argument $arguments -WorkingDirectory $PSScriptRoot
    $trigger = New-ScheduledTaskTrigger -Daily -At "8am"
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -Hidden
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    
    Write-Host "Scheduled task '$taskName' installed successfully. It will run daily at 8:00 AM."
}

# Handle script argupments
function _HandleCli {
    if ($Install) {
        _InstallScheduledTask
        exit
    }

    if ($PSBoundParameters.ContainsKey('GenCred')) {
        if (-not $GenCred) {
            Write-Error "The -GenCred parameter requires a path argument for the credential file."
            exit 1
        }
        _GenerateCredentialFile -Path $GenCred
        exit 0
    }
}

_HandleCli

if ($Mail) {
    $missingParams = [System.Collections.Generic.List[string]]@()
    if (-not $SmtpServer) { $missingParams.Add('SmtpServer') }
    if (-not $From)  { $missingParams.Add('From') }
    if (-not $To)    { $missingParams.Add('To') }
    if (-not $Cred)       { $missingParams.Add('Cred') }

    if ($missingParams.Count -gt 0) {
        foreach ($p in $missingParams) {
            Write-Debug "Required parameter for -Mail is not set: -$p"
        }
        Write-Error "The following required parameters for -Mail are missing: $(($missingParams | ForEach-Object { "-$_" }) -join ', ')"
        exit 1
    }
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
	
	# Create SMTP client
	$smtp = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
	$smtp.EnableSsl = $true
	$NetCred = $credential.GetNetworkCredential()
	$smtp.Credentials = New-Object System.Net.NetworkCredential($NetCred.UserName, $NetCred.Password);

	# Create MailMessage
	$msg = New-Object System.Net.Mail.MailMessage
	$msg.From = $From
	$msg.To.Add($To)
	$msg.Subject = "WAIL2Ban Report $($reportData.DateRange)"
	$msg.Body = $reportData.Html
	$msg.IsBodyHtml = $true

	# Send
	$smtp.Send($msg)
    exit 0
}

$reportData = Get-Wail2BanHTMLReport
$reportPath = Join-Path $PSScriptRoot "report.html"
$reportData.Html | Out-File $reportPath -Force
Write-Host "Report generated at $reportPath"


