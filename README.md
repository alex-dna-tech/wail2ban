# Wail2ban

![Saddest Whale](http://i.imgur.com/NVlsY.png "Saddest Whale")

wail2ban is a Windows port of the basic functionality of [fail2ban](http://www.fail2ban.org/), inspired by elements of [ts_block](https://github.com/EvanAnderson/ts_block).

## Overview

wail2ban monitors Windows Event Logs for failed login attempts from specified event IDs. When multiple failed attempts originate from the same IP within a configurable time window, it automatically creates temporary Windows Firewall rules to block further access from those IPs.

## Installation

To set up wail2ban:

1. Copy all repository files to a directory on your Windows machine, e.g., `C:\scripts\wail2ban`.
2. Configure the `wail2ban.ps1` script, particularly the event log types and IDs to monitor, or modify the configuration as needed.
3. Use Task Scheduler to create a task that runs `wail2ban.ps1` at startup:
   - Import the provided `start-wail2ban-onstartup.xml` task definition.
   - Set it to run with administrator privileges.
4. Manually start the script by executing `wail2ban.ps1` or rely on the scheduled task.

prerequisites
-------------

The script checks for and requires:

- Administrative privileges (must be run as administrator)
- PowerShell version 5.1 or higher
- PowerShell execution policy set to 'RemoteSigned' or less restrictive

usage
-----

Run `wail2ban.ps1` with optional parameters:

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

functional overview
-------------------

- Monitors specified event logs for certain Event IDs related to failed login attempts.
- Tracks attempts from each IP address within a configurable time window (`$CHECK_WINDOW` seconds).
- If an IP exceeds the attempt threshold (`$CHECK_COUNT`) within the window, it is banned:
  - Adds a firewall rule with a name prefixed by `$FirewallRulePrefix`.
  - The ban duration scales exponentially based on previous bans, with a maximum cap (`$MAX_BANDURATION` seconds).
- Bans are automatically revoked after their expiry time, and rules are removed.
- Supports whitelists for IPs that should never be banned.
- Keeps state of bans in a JSON file to allow persistence across runs.
- Provides CLI commands to list, unban, or clear bans.

limitations & notes
-------------------

- This script is intended for use on Windows systems where PowerShell 5.1+ and Windows Firewall are available.
- The system needs to be run with administrator privileges.
- The script relies on specific event IDs and log types; adjust the `$EventsToTrack` hashtable for your environment.
- Ban durations are exponential but capped to avoid excessively long bans.
- It does not run as a persistent service but can be scheduled to run at startup or on an interval.

additional
----------

You can extend or customize the script by tweaking:

- `$EventsToTrack`: To monitor different logs or event IDs.
- `$Whitelist`: To prevent banning certain IPs.
- `$CHECK_WINDOW` and `$CHECK_COUNT`: To customize detection sensitivity.
- The firewall rule naming conventions in `$FirewallRulePrefix`.

Note: The script logs significant actions and errors, which can be retrieved by examining Windows Event Logs under the "Application" log with source "wail2ban".

---

For further customization or integration, review and modify the `wail2ban.ps1` script as needed.
