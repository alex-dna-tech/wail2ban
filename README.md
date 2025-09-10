# Wail2ban

![Saddest Whale](http://i.imgur.com/NVlsY.png "Saddest Whale")

wail2ban is a Windows port of the basic functionality of [fail2ban](http://www.fail2ban.org/), inspired by elements of [ts_block](https://github.com/EvanAnderson/ts_block).

## Overview

wail2ban monitors Windows Event Logs for failed login attempts from specified event IDs. When multiple failed attempts originate from the same IP within a configurable time window, it automatically creates temporary Windows Firewall rules to block further access from those IPs.

## Installation
To install wail2ban:

1. Download or copy the `wail2ban.ps1` script to any folder.
2. Run it with the `-install` parameter.

## Prerequisites

The script checks for and requires:

- Administrative privileges (must be run as administrator)
- PowerShell version 5.1 or higher
- PowerShell execution policy set to 'RemoteSigned' or less restrictive

## Security Considerations

### Avoid Storing Plain-Text Passwords

When using the email feature in `report.ps1`, it is strongly recommended to use an encrypted credential file instead of passing passwords in plain text on the command line. You can create this file using the `-GenCred` parameter.

To manually create a credential file for use with the `-Cred` parameter:

```powershell
$SecurePassword = Read-Host "Enter Password" -AsSecureString
$Credential = New-Object System.Management.Automation.PSCredential ("user@domain.com", $SecurePassword)
$Credential | Export-Clixml -Path "C:\secure\creds.xml"
```

You can then use `C:\secure\creds.xml` with the `-Cred` parameter in `report.ps1`.

## Usage

### wail2ban.ps1

- To list current banned IPs:
  ```powershell
  .\wail2ban.ps1 -ListBans
  ```

- To unban a specific IP:
  ```powershell
  .\wail2ban.ps1 -UnbanIP "X.X.X.X"
  ```

- To unban all IPs:
  ```powershell
  .\wail2ban.ps1 -ClearAllBans
  ```

- To run the script silently (no console messages):
  ```powershell
  .\wail2ban.ps1 -Silent
  ```

- To install the scheduled task to run at startup:
  ```powershell
  .\wail2ban.ps1 -install
  ```

- To uninstall the scheduled task:
  ```powershell
  .\wail2ban.ps1 -uninstall
  ```

### report.ps1

- To generate an HTML report of recent activity:
  ```powershell
  .\report.ps1
  ```

- To create an encrypted credential file for sending emails:
  ```powershell
  .\report.ps1 -GenCred "C:\secure\wail2ban_creds.xml"
  ```

- To generate and email a report using a credential file:
  ```powershell
  .\report.ps1 -Mail -SmtpServer "smtp.example.com" -EmailFrom "sender@example.com" -EmailTo "recipient@example.com" -Cred "C:\secure\wail2ban_creds.xml"
  ```

### Parameters Overview

#### `wail2ban.ps1` Parameters
- `-ListBans`: Lists all the currently banned IP addresses.
- `-UnbanIP <IP>`: Removes the specified IP address from the ban list.
- `-ClearAllBans`: Removes all the IP addresses that have been banned by this script.
- `-Silent`: Runs the script without outputting messages to the console.
- `-install`: Installs the scheduled task for the script to run at startup.
- `-uninstall`: Uninstalls the scheduled task for the script.
- `-CheckWindow <int>`: Specifies the time window in seconds to check for failed login attempts (default is 120).
- `-CheckCount <int>`: Specifies the number of failed login attempts before banning an IP (default is 5).
- `-LoopDuration <int>`: Specifies the duration in seconds between checks for new events (default is 5).
- `-MaxBanDuration <int>`: Specifies the maximum duration in seconds for which an IP can be banned (default is 7776000).
- `-EventsToTrack <string>`: Specifies the event logs and event IDs to monitor for failed login attempts. Format must be space-separated pairs of Log Name (Application, Security, System) and EventID (integer) (e.g., "Security 4625 Application 1000"). Default is "Security 4625".
- `-WhiteList <string>`: Specifies IP addresses that should never be banned. Format must be space-separated IPv4 addresses or CIDR notations (e.g., "192.168.0.1 192.168.1.0/24").

#### `report.ps1` Parameters
- `-ReportDays <int>`: Specifies the number of days to include in the report (default is 7).
- `-Mail`: When specified, sends the generated HTML report via email.
- `-SmtpServer <string>`: The address of the SMTP server (required for `-Mail`).
- `-SmtpPort <int>`: The port for the SMTP server (default is 587).
- `-EmailFrom <string>`: The sender's email address (required for `-Mail`).
- `-EmailTo <string[]>`: One or more recipient email addresses (required for `-Mail`).
- `-Cred <string>`: Path to an encrypted credential file (XML) for SMTP authentication. Recommended for use with `-Mail`.
- `-EmailLogin <string>`: The username for SMTP authentication. Using this with `-EmailPass` is less secure than using `-Cred`.
- `-EmailPass <string>`: The password for SMTP authentication. Using this is insecure.
- `-GenCred <string>`: Generates an encrypted credential file. When used, the script will prompt for a username and password, save them to the specified path, and then exit.

## Functional Overview

- Monitors specified event logs for certain Event IDs related to failed login attempts.
- Tracks attempts from each IP address within a configurable time window (`$CheckWindow` seconds).
- If an IP exceeds the attempt threshold (`$CheckCount`) within the window, it is banned:
  - Adds a firewall rule with a name prefixed by `$FirewallRulePrefix`.
  - The ban duration scales exponentially based on previous bans, with a maximum cap (`$MaxBanDuration` seconds).
- Bans are automatically revoked after their expiry time, and rules are removed.
- Supports whitelists for IPs that should never be banned.
- Keeps the state of bans in a JSON file to allow persistence across runs.
- Provides CLI commands to list, unban, or clear bans.
- Generates HTML reports summarizing the bans and IP statistics.

## Limitations & Notes

- This script is intended for use on Windows systems where PowerShell 5.1+ and Windows Firewall are available.
- The system needs to be run with administrator privileges.
- The script relies on specific event IDs and log types; adjust the `$EventsToTrack` hashtable for your environment.
- Ban durations are exponential but capped to avoid excessively long bans.
- It does not run as a persistent service but can be scheduled to run at startup or on an interval.

## Additional

You can extend or customize the script by tweaking:

- `$EventsToTrack`: To monitor different logs or event IDs.
- `$Whitelist`: To prevent banning certain IPs.
- `$CheckWindow` and `$CheckCount`: To customize detection sensitivity.
- The firewall rule naming conventions in `$FirewallRulePrefix`.

> [!NOTE] 
> The script logs significant actions and errors, which can be retrieved by examining Windows Event Logs under the "Application" log with source "wail2ban".

---

For further customization or integration, review and modify the `wail2ban.ps1` script as needed.
