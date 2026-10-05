# TokenLatch

[![Platform](https://img.shields.io/badge/platform-Windows-0078D4.svg)](#requirements)
[![Status](https://img.shields.io/badge/status-pre--release-orange.svg)](#limitations)
[![License](https://img.shields.io/badge/license-choose%20one-lightgrey.svg)](#license)

TokenLatch is a Windows defense-in-depth utility for reducing the time that
Discord session storage remains exposed on disk. When Discord or a selected
browser is closed, TokenLatch moves the relevant local storage into a fresh,
randomly named vault. When the app starts, it restores the storage. A separate
Windows Security-log watcher can alert locally and through ntfy.sh, a Discord
webhook, or email when an unexpected process reads a live guarded path.

This project is intentionally defensive. It does not decrypt, extract, or
upload session tokens.

## Important disclaimer

TokenLatch is not a guarantee against account compromise. It cannot protect
files while a guarded app is open, cannot block a read that already happened,
and cannot stop malware that disables auditing, runs with sufficient
privileges, reads process memory, or steals credentials elsewhere. Keep
Windows Defender/antivirus enabled, install software only from sources you
trust, use MFA, and test the tool before relying on it.

## Contents

- [Features](#features)
- [Limitations](#limitations)
- [Requirements](#requirements)
- [Installation](#installation)
- [Setup and daily use](#setup-and-daily-use)
- [Configuration](#configuration)
- [Remote alerts](#remote-alerts)
- [How it works](#how-it-works)
- [Logs and recovery](#logs-and-recovery)
- [Uninstall and rollback](#uninstall-and-rollback)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- Discord desktop coverage for `discord.exe`, `discordptb.exe`, and
  `discordcanary.exe`.
- Optional browser coverage for Chrome, Edge, Brave, Firefox, Opera, Opera GX,
  Vivaldi, Chromium, and Yandex Browser.
- Chromium LevelDB coverage for each supported browser's **Default** profile.
- Firefox coverage for the default profile's `webappsstore.sqlite` and
  `storage` paths, discovered through `profiles.ini`.
- Toggle-based browser selection in `setup.bat`; Discord is always guarded.
- Random 24–32 character vault names generated with Python `secrets` for every
  new lock cycle.
- Current vault mappings protected with Windows DPAPI for the current Windows
  user.
- PID locks, stale-process detection, graceful stop, forced-stop fallback, and
  startup recovery for interrupted moves.
- Windows object-access auditing with Security Event ID 4663.
- Local notification plus optional parallel ntfy, Discord webhook, and SMTP
  email alerts.
- Optional current-user logon tasks; audit/SACL setup and the elevated watcher
  require UAC approval.

## Limitations

- Storage is moved, not encrypted. A sufficiently privileged attacker can
  inspect the running process, the vault, or the Windows account.
- Protection is strongest while the owning app is completely closed. Discord
  can leave background/tray processes alive; TokenLatch waits for all
  configured process names to disappear.
- The watcher is alert-only. Event 4663 is delivered after Windows records the
  access; it cannot undo or block a read.
- Object-access auditing is a global Windows audit-policy switch, although
  TokenLatch applies SACLs only to selected storage paths. Other SACLs can
  increase Security-log volume and disk writes.
- Only the Default Chromium profile is covered. Additional profiles require
  source changes.
- Firefox storage locking is newer and less battle-tested than Chromium
  LevelDB handling. Test it carefully, especially with multiple profiles.
- There is a race window during application startup and asynchronous event
  delivery. A malicious process may also disable auditing or bypass it with
  sufficient privilege.
- Only browsers listed in the setup menu are detected automatically.

## Requirements

- Windows 10 or Windows 11.
- Python 3.9 or newer, with `pythonw.exe` available on `PATH`.
- Python packages:

  ```powershell
  python -m pip install psutil pywin32 requests
  ```

Normal guarding does not require administrator rights. One-time audit setup
needs elevation to enable the `File System` audit subcategory and apply read
SACLs. The access watcher is launched elevated so it can read the Security
event log.

## Installation

1. Clone or download this repository.
2. Install the dependencies above.
3. Confirm that `pythonw.exe` works from a new terminal:

   ```powershell
   where.exe pythonw.exe
   ```

4. Run `setup.bat` from this folder.

`guard_config.json` is created locally and is ignored by Git. It can contain
webhook URLs, ntfy topic URLs, and an SMTP app password. Never commit it.

## Setup and daily use

### First run

`setup.bat` collects all answers before executing changes:

1. Confirm that TokenLatch should be enabled.
2. Toggle browser entries with their numbers. `[X]` means selected; enter `D`
   when finished. Selecting no browser is allowed if you confirm Discord-only
   mode.
3. Choose whether to start at Windows logon.
4. Configure any combination of the three remote alert channels.
5. Optionally send a test alert.
6. Confirm that TokenLatch may close currently running Discord/browser
   processes. It tries a graceful close first, waits, then force-closes only
   if necessary. Saying **N** cancels before setup/start.
7. Approve the UAC prompt for the one-time audit/SACL setup.

The execution phase is numbered and stops at the first error. It does not
continue to start background processes after a failed prerequisite.

### Control panel

Run `setup.bat` again after setup:

- If the guard is running, it asks whether to stop it and the access watcher.
- Stop waits for both Python processes to exit, force-terminates only as a
  fallback, and verifies that their PIDs are gone before reporting success.
- After a successful stop, the launcher removes `guard_config.json`, so the
  next run opens the full setup wizard again. Vault data, encrypted state, and
  logs are deliberately preserved; deleting those automatically could destroy
  session storage that still needs recovery.
- If the guard is stopped, it asks whether to start protection and repeats the
  selected-app close check.
- `setup.bat --reconfigure` reruns the wizard.

Process locks are:

```text
%LocalAppData%\.dguard\guard.pid
%LocalAppData%\.dguard\access_watch.pid
```

Optional logon tasks are named `TokenLatch - Session Protection` and
`TokenLatch - Access Watcher`.

## Configuration

The wizard writes `guard_config.json` beside the scripts. A minimal example:

```json
{
  "browsers": ["chrome", "firefox"],
  "autostart": true,
  "alerts": {
    "ntfy": {
      "enabled": true,
      "topic_url": "https://ntfy.sh/use-a-long-random-topic"
    },
    "discord_webhook": {
      "enabled": false,
      "url": ""
    },
    "email": {
      "enabled": false,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "from_addr": "",
      "app_password": "",
      "to_addr": ""
    }
  }
}
```

Treat this file as a secret. Topic and webhook URLs can be used by anyone who
obtains them, and the SMTP app password must not be committed or shared.

## Remote alerts

Channels are independent. They are dispatched in parallel, have network
timeouts, and cannot prevent the local notification from firing.

### ntfy.sh (recommended)

Install the ntfy mobile app, subscribe to a long random topic, and enter its
URL, for example:

```text
https://ntfy.sh/tokenlatch-<long-random-value>
```

No account or API key is required. Anyone who knows the topic can read or
publish messages, so treat the URL like a password.

### Discord webhook

Create a private server/channel, open **Channel Settings → Integrations →
Webhooks**, create a webhook, and paste its URL into the wizard. Anyone with
the URL can post to the channel. Never publish it in GitHub.

### Email

Configure the SMTP host, port, sender, app password, and destination. Port
`587` uses STARTTLS; port `465` uses SMTP over SSL. For Gmail, create a Google
**App Password** and use that value—not the normal account password.

## How it works

### Closed-app storage lock

The main guard polls configured process names approximately every 0.4 seconds.
After a close grace period, it moves selected storage out of its normal path.
When the owning process appears, it restores the storage immediately.

The vault uses one random folder per active target under:

```text
%LocalAppData%\.dguard\<random-name>\
```

The name is 24–32 characters from `a-z`, `A-Z`, and `0-9`, generated with
`secrets`, not `random`. The mapping is stored in `vault_state.bin` protected
with Windows DPAPI. DPAPI ties the state to the current Windows user account;
copying the state file to another account does not make it readable.

After a successful unlock, the mapping is cleared and the now-empty random
folder is removed. On startup, inactive empty folders are cleaned up. A
non-empty inactive folder is retained and logged because it may contain the
only recoverable copy after an interrupted move. There is one active folder
per target, so Discord and Chrome being locked at the same time normally means
two random folders.

If DPAPI state is unavailable, TokenLatch performs a warning-producing,
last-resort scan for random folders containing expected storage names. This
fallback can be ambiguous when multiple vaults exist; verify recovery before
deleting anything.

### Event ID 4663 access alerts

The elevated `audit_setup.ps1` script enables:

```powershell
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

It applies an Everyone/Read/Success SACL recursively to selected guarded
paths. The watcher reads Security Event ID 4663, matches the object path,
resolves process name/PID where possible, ignores expected owner processes,
and alerts on unexpected reads. Sysmon is not used because its common file
telemetry is focused on creation/deletion and is not a reliable plain-read
detector for this use case.

After every unlock, the main guard attempts to reapply the SACL because a move
may not preserve the security descriptor on every filesystem operation.

## Logs and recovery

| Item | Location |
| --- | --- |
| Main guard log | `%LocalAppData%\.dguard\guard.log` |
| Access alert log | `%LocalAppData%\.dguard\access_alerts.log` |
| Encrypted vault state | `%LocalAppData%\.dguard\vault_state.bin` |
| Main PID | `%LocalAppData%\.dguard\guard.pid` |
| Watcher PID | `%LocalAppData%\.dguard\access_watch.pid` |
| Random vault root | `%LocalAppData%\.dguard\` |

If an app does not start, do not delete the random vault or
`vault_state.bin`. Close the app, stop TokenLatch, inspect `guard.log`, and
restore only after identifying the active target mapping. Non-empty inactive
folders are intentionally not deleted automatically.

## Uninstall and rollback

1. Run `setup.bat` and stop TokenLatch. If necessary, remove the tasks:

   ```powershell
   schtasks /Delete /F /TN "TokenLatch - Session Protection"
   schtasks /Delete /F /TN "TokenLatch - Access Watcher"
   ```

2. From an elevated PowerShell window, disable the global audit subcategory:

   ```powershell
   auditpol /set /subcategory:"File System" /success:disable /failure:disable
   ```

3. Remove TokenLatch's Everyone/Success audit rules from the guarded paths.
   Use the paths selected on your machine and review each change first:

   ```powershell
   $paths = @(
     "$env:APPDATA\discord\Local Storage\leveldb",
     "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\leveldb"
     # Add selected Edge, Brave, Opera, Vivaldi, Chromium, Yandex, and Firefox paths.
   )
   $everyone = [System.Security.Principal.NTAccount]::new('Everyone')
   foreach ($path in $paths) {
     if (-not (Test-Path -LiteralPath $path)) { continue }
     $items = @(Get-Item -LiteralPath $path -Force) + @(Get-ChildItem -LiteralPath $path -Force -Recurse)
     foreach ($item in $items) {
       $acl = Get-Acl -LiteralPath $item.FullName
       $rules = $acl.GetAuditRules($true, $true, [System.Security.Principal.NTAccount])
       foreach ($rule in $rules) {
         if ($rule.IdentityReference -eq $everyone -and ($rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)) {
           [void]$acl.RemoveAuditRule($rule)
         }
       }
       Set-Acl -LiteralPath $item.FullName -AclObject $acl
     }
   }
   ```

4. Confirm storage is back in its normal location. Only then remove
   `%LocalAppData%\.dguard\` and local `guard_config.json` if you no longer
   need logs or saved alert settings.

Disabling the audit policy is system-wide. Removing TokenLatch's SACLs is
path-specific; do not remove audit rules belonging to other software.

## Troubleshooting

### “Python was not found”

Open a new terminal and run `where.exe pythonw.exe`. Install Python or repair
`PATH`, then rerun `setup.bat`. The launcher resolves `pythonw.exe` through
`PATH` for both start and scheduled-task registration.

### Files did not move after closing Discord

Check for remaining `Discord.exe`, `DiscordPTB.exe`, or
`DiscordCanary.exe` processes, including tray/background processes. Then
inspect `guard.log`. TokenLatch intentionally treats any matching process as
open until the close grace period completes.

### The control panel says a process is still running

This is a safety failure, not a success state. Check both PID files and
`guard.log`; close the process manually if needed, then run `setup.bat` again.

### Alerts do not arrive

Run the wizard's test-alert option. Check `access_alerts.log`, verify the URL
or SMTP settings, and confirm that Windows File System auditing and the SACL
exist on the selected paths.

## Contributing

Issues and pull requests are welcome. Do not include session storage, tokens,
`guard_config.json`, SMTP credentials, ntfy topics, webhook URLs, or private
Security-log exports in issues or pull requests. Contributions should preserve
the Windows-only scope, fail safely, and include validation steps for changes
to process lifecycle, vault recovery, auditing, or alert delivery.

Before opening a pull request, run:

```powershell
python -m py_compile discord_guard.py discord_guard.pyw access_watch.py access_watch.pyw
```

Also confirm that the `.py` and `.pyw` pairs remain identical.

## License

Choose and add an explicit open-source license before publishing this project.
Until a license file is committed, the repository should be treated as **all
rights reserved**; GitHub visibility alone does not grant permission to copy,
modify, or redistribute it.
