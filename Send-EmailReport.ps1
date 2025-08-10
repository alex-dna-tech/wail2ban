<#
.SYNOPSIS
Sends email reports using PowerShell

.DESCRIPTION
This script sends email messages with optional attachments using SMTP protocol.
Includes HTML formatting support and secure credential handling.

.PARAMETER Recipient
Email address(es) of the recipient(s) (comma-separated for multiple)

.PARAMETER Subject
Subject line of the email

.PARAMETER Body
Email body content (supports HTML)

.PARAMETER AttachmentPath
Path to file(s) to attach (comma-separated for multiple)

.EXAMPLE
Send-EmailReport -Recipient "admin@example.com" -Subject "Daily Report" -Body "<h1>Report</h1>"

.EXAMPLE
Send-EmailReport -Recipient "team@example.com" -Subject "Logs" -AttachmentPath "C:\logs\app.log"
#>

function Send-EmailReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Recipient,
        
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        
        [Parameter(Mandatory = $false)]
        [string]$Body = "",
        
        [Parameter(Mandatory = $false)]
        [string[]]$AttachmentPath
    )

    # Configuration - Set these values according to your environment
    $SmtpServer = "smtp.yourcompany.com"
    $Port = 587
    $EnableSSL = $true
    $FromAddress = "reports@yourcompany.com"
    
    # Secure credential handling
    $CredentialPath = "$env:USERPROFILE\.emailcred.xml"
    if (-not (Test-Path $CredentialPath)) {
        $cred = Get-Credential -Message "Enter SMTP credentials" -UserName $FromAddress
        $cred | Export-Clixml -Path $CredentialPath
    }
    $cred = Import-Clixml -Path $CredentialPath

    try {
        # Create MailMessage object
        $message = New-Object System.Net.Mail.MailMessage
        $message.From = $FromAddress
        foreach ($addr in $Recipient) {
            $message.To.Add($addr)
        }
        $message.Subject = $Subject
        $message.Body = $Body
        $message.IsBodyHtml = $Body -match "<[a-z][\s\S]*>"

        # Add attachments
        if ($AttachmentPath) {
            foreach ($file in $AttachmentPath) {
                if (Test-Path $file) {
                    $attachment = New-Object System.Net.Mail.Attachment($file)
                    $message.Attachments.Add($attachment)
                }
                else {
                    Write-Warning "Attachment file not found: $file"
                }
            }
        }

        # Create SMTP client
        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $Port)
        $smtp.EnableSsl = $EnableSSL
        $smtp.Credentials = $cred.GetNetworkCredential()

        # Send email
        $smtp.Send($message)
        Write-Host "Email successfully sent to $($Recipient -join ', ')" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to send email: $_"
    }
    finally {
        if ($message) { $message.Dispose() }
        if ($smtp) { $smtp.Dispose() }
    }
}
```
