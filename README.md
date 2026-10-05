# TokenLatch

[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D4.svg)](#requirements) [![Status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)](#limitations) [![License: choose one](https://img.shields.io/badge/license-to%20be%20chosen-lightgrey.svg)](#license)

TokenLatch is a Windows defense-in-depth utility that moves Discord and
selected browser session storage out of their normal locations while the apps
are closed, restores it when they launch, and alerts locally and remotely if
an unexpected process reads the live files. It is designed to reduce the
attack window and improve time-to-detection—not to provide encryption or a
guarantee against token theft.

## Disclaimer

TokenLatch cannot prevent theft while a protected app is actively open and its
session files are unlocked. The Event ID 4663 watcher is alert-only: a read
may already have happened before notification. Do not run untrusted software,
keep antivirus active, use unique passwords, and enable strong account
security. Test this tool carefully before relying on it.

## Contents

- [What it does](#what-it-does)
- [What it does not do](#what-it-does-not-do)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration reference](#configuration-reference)
- [How detection works](#how-detection-works)
- [Logs and recovery](#logs-and-recovery)
- [Uninstalling and rollback](#uninstalling-and-rollback)
- [Contributing](#contributing)
- [License](#license)

## What it does

TokenLatch has two complementary protections:

1. **Closed-app storage locking.** Discord and selected browsers are polled.
   When an owning app closes, its session storage is moved into a fresh,
   randomly named vault folder. When the app launches, the storage is restored.
2. **Live-file access alerting.** Windows object-access auditing generates
   Security Event ID 4663 records for successful reads of the specifically
   audited paths. TokenLatch alerts when the reading process is not the
   expected Discord or browser executable.

Supported targets:

| Target | Process | Protected storage |
| --- | --- | --- |
| Discord desktop | `discord.exe`, `discordptb.exe`, `discordcanary.exe` | `%AppData%\discord\Local Storage\leveldb` |
| Chrome Default | `chrome.exe` | `%LocalAppData%\Google\Chrome\User Data\Default\Local Storage\leveldb` |
| Edge Default | `msedge.exe` | `%LocalAppData%\Microsoft\Edge\User Data\Default\Local Storage\leveldb` |
| Brave Default | `brave.exe` | `%LocalAppData%\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb` |
| Opera Stable Default | `opera.exe` | `%AppData%\Opera Software\Opera Stable\Local Storage\leveldb` |
| Opera GX Default | `opera_gx.exe` | `%AppData%\Opera Software\Opera GX Stable\Local Storage\leveldb` |
| Vivaldi Default | `vivaldi.exe` | `%LocalAppData%\Vivaldi\User Data\Default\Local Storage\leveldb` |
| Chromium Default | `chromium.exe` | `%LocalAppData%\Chromium\User Data\Default\Local Storage\leveldb` |
| Yandex Browser Default | `browser.exe` | `%LocalAppData%\Yandex\YandexBrowser\User Data\Default\Local Storage\leveldb` |
| Firefox default profile | `firefox.exe` | `webappsstore.sqlite` and `storage`, found through `%AppData%\Mozilla\Firefox\profiles.ini` |

Discord is always guarded. Browser coverage is selected in the setup wizard;
Discord-only mode is supported. The current browser detector supports Chrome,
Edge, Brave, Firefox, Opera, Opera GX, Vivaldi, Chromium, and Yandex Browser.
Other browsers are not automatically detected or protected by this release.

## What it does not do

- It does not encrypt session files.
- It does not block a process that reads files while Discord or a browser is
  open. It reports unexpected reads after Windows auditing records them.
- It cannot guarantee detection of malware that disables auditing, runs with
  sufficient privileges, reads memory, or steals credentials elsewhere.
- It covers only the Default profile for supported Chromium-based browsers.
  Other browsers are currently not detected unless explicitly added to the
  target mapping in the source.
- Firefox support is newer and less battle-tested than Chromium LevelDB
  handling. Multiple Firefox profiles require particular care.
- There is a short race window during app launch and asynchronous event
  delivery.

## Requirements

- Windows 10 or Windows 11.
- Python 3.9 or newer with `pythonw.exe` available on `PATH`.
- Python packages:

  ```powershell
  pip install psutil pywin32 requests
  ```

Normal file guarding does not require administrator rights. The first audit
setup and the elevated access watcher require administrator approval because
they use the Security event log and SACLs.

## Installation

1. Clone or download this repository.
2. Install the dependencies above.
3. Ensure `guard_config.json` is not committed. The repository includes this
   `.gitignore` entry:

   ```gitignore
   guard_config.json
   ```

   The file can contain webhook URLs, ntfy topic URLs, and an SMTP app
   password.
4. Double-click `setup.bat`.

The first run asks whether protection should be enabled, lets you toggle
Chrome, Edge, Brave, and Firefox, configures remote alerts, and asks whether
to start at Windows login. It then asks for one-time administrator approval
to enable the Windows `File System` audit subcategory and apply read-audit
SACLs to the selected paths.

## Usage

### First-time setup

1. Start `setup.bat`.
2. Confirm that TokenLatch should apply protection.
3. Toggle the browser entries with `1`–`9`; `[X]` means selected. The current
   entries are Chrome, Edge, Brave, Firefox, Opera, Opera GX, Vivaldi,
   Chromium, and Yandex Browser. Enter `D` when done.
4. Choose login auto-start, configure any combination of ntfy.sh, Discord
   webhook, and email alerts, and decide whether to send a test alert.
5. After all answers are collected, TokenLatch executes the setup in numbered
   steps. It checks Discord variants and the selected browsers. If any are
   open, it lists them and asks whether to close them. It first tries a graceful
   `taskkill /T`, waits two seconds, then force-closes anything still running
   with `/F`. Saying **N** cancels without changing processes or continuing.
6. It saves the configuration, enables audit protection, sends the optional
   test alert, registers login tasks, and starts the guard.
7. If any execution step fails, TokenLatch displays the error and stops at
   that step instead of continuing with a partial setup.

### Later starts and stops

When `setup.bat` is run with an existing configuration, it becomes a control
panel:

- If TokenLatch is running, it asks whether to stop the main guard and access
  watcher.
- Stopping waits for each Python process to exit, uses force termination only
  as a fallback, and verifies the PID is gone before reporting success. If a
  process cannot be stopped, the control panel reports an error and does not
  pretend the vault is safe to manipulate.
- If stopped, it asks whether to start protection.
- Before every manual start, it reloads the saved browser list, checks Discord
  and those browsers again, asks for confirmation, and performs graceful then
  forceful closure if needed.
- The PID locks are `%LocalAppData%\.dguard\guard.pid` and
  `%LocalAppData%\.dguard\access_watch.pid`.

To rerun the wizard:

```bat
setup.bat --reconfigure
```

The login tasks are current-user tasks. The access watcher task is configured
with highest available privileges so it can read the Security log.

## Configuration reference

The wizard writes `guard_config.json` beside the scripts. Keep it private and
out of version control. Its shape is:

```json
{
  "browsers": ["chrome", "firefox"],
  "autostart": true,
  "alerts": {
    "ntfy": {
      "enabled": true,
      "topic_url": "https://ntfy.sh/replace-with-a-long-random-topic"
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

### Remote alert channels

Channels are independent and are dispatched in parallel. Each request has a
timeout; a failed network channel is logged and does not stop local alerting.

#### ntfy.sh — recommended

Install the ntfy app, subscribe to a long random topic, then enter its URL in
the wizard, such as `https://ntfy.sh/tokenlatch-<random-value>`. No account or
API key is required. Anyone who knows the topic URL can read or publish to it,
so treat it as a secret.

#### Discord webhook

Create a private Discord server/channel, open **Channel Settings →
Integrations → Webhooks → New Webhook**, copy the URL, and enter it in the
wizard. Anyone with the URL can post to that channel; never publish it.

#### Email

Enter an SMTP server, port, sender, app password, and destination address. Port
`587` uses STARTTLS; port `465` uses SMTP over SSL. For Gmail, generate and use
an **App Password**, not the normal account password—Google generally blocks
plain SMTP authentication with the main password.

## How detection works

### Randomized DPAPI vault

Every new lock operation generates a new 24–32 character folder name using
Python’s `secrets` module and moves storage directly beneath:

```text
%LocalAppData%\.dguard\<random-name>\
```

The predictable `vault\<target_name>` layout is not used. The current
target-to-folder mapping is stored in `vault_state.bin`, encrypted with
Windows DPAPI through `win32crypt.CryptProtectData`. This ties the state to
the current Windows user account and prevents a copied state file from being
useful on another account.

There is one active random folder per guarded target. For example, selecting
Discord and Chrome normally produces two random folders at the same time;
that is expected, not duplicate storage. The encrypted mapping identifies
which folder belongs to which target.

After unlock, TokenLatch restores the files, clears the state entry, and
removes the now-empty random folder. If the process crashes during a move, the
next startup can use the encrypted mapping. If the state is missing or cannot
be decrypted, a last-resort scan looks for random-name folders containing
expected `leveldb`, `storage`, or `webappsstore.sqlite` entries and logs a
warning. That fallback can be ambiguous when multiple browser vaults exist.

TokenLatch also performs a conservative stale-folder cleanup on startup. It
automatically removes inactive random folders only when they are empty. A
non-empty inactive folder is retained and a warning is written to `guard.log`,
because it may be the only recoverable copy after an interrupted move. This is
why an old-looking random folder may still be visible under `.dguard`: it is
not disposable until its contents have been verified and restored. Never
delete a non-empty folder or `vault_state.bin` while a recovery may still be
needed.

The random folders remain under `.dguard` to keep permissions, logs, PIDs, and
audit support in one directory instead of making random entries in the user
profile root. This hides the reusable path pattern from published source code,
but it is not a substitute for encryption: a capable attacker can still scan
the filesystem or inspect the running process.

### SACL and Event ID 4663

During setup, `audit_setup.ps1` runs:

```powershell
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

It then applies an Everyone/Read/Success `FileSystemAuditRule` recursively to
the selected storage folders and Firefox storage files. The global audit
subcategory switch enables the event pipeline, but TokenLatch adds SACLs only
to its specific guarded paths. If other SACLs exist elsewhere, the Security
log may see additional traffic and disk writes.

`access_watch.pyw` reads new Security Event ID 4663 records, matches their
object paths against the current target paths, extracts `ProcessName` and
`ProcessId`, and compares the process with the target’s expected executable
allowlist. Sysmon is not used because its common file telemetry is focused on
creation/deletion and is not a reliable plain-read detector for this purpose.

After every unlock, the main guard attempts to reapply the SACL through
`audit_setup.ps1` in case a move did not preserve the security descriptor.

### Local and remote response

Unexpected reads are written to:

```text
%LocalAppData%\.dguard\access_alerts.log
```

The user receives a local Windows notification and, if configured, parallel
ntfy, Discord webhook, and email messages containing the process, PID,
timestamp, target, object path, and a reminder to reset the Discord password or
session token.

## Logs and recovery

| Item | Location |
| --- | --- |
| Main guard log | `%LocalAppData%\.dguard\guard.log` |
| Access alert log | `%LocalAppData%\.dguard\access_alerts.log` |
| Encrypted vault state | `%LocalAppData%\.dguard\vault_state.bin` |
| Main PID lock | `%LocalAppData%\.dguard\guard.pid` |
| Access watcher PID lock | `%LocalAppData%\.dguard\access_watch.pid` |
| Random vault root | `%LocalAppData%\.dguard\` |

Storage is moved, not deleted. If an app cannot start, close it and inspect
the log before manually restoring the relevant contents from the active random
folder. Do not delete an active random folder or `vault_state.bin` until the
storage has been recovered. If you intentionally confirm that an inactive
folder contains no needed data, it can then be removed manually; TokenLatch
will not silently delete non-empty vault data.

## Uninstalling and rollback

1. Run `setup.bat`, stop TokenLatch, and remove the two current-user scheduled
   tasks, or run:

   ```powershell
   schtasks /Delete /F /TN "TokenLatch - Session Protection"
   schtasks /Delete /F /TN "TokenLatch - Access Watcher"
   ```

2. Disable the global audit-policy switch from an elevated PowerShell window:

   ```powershell
   auditpol /set /subcategory:"File System" /success:disable /failure:disable
   ```

3. Remove TokenLatch’s successful-read audit rules from the guarded paths. Run
   this elevated PowerShell snippet with the actual paths selected on your
   machine:

   ```powershell
   $paths = @(
     "$env:APPDATA\discord\Local Storage\leveldb"
     "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\leveldb"
     # Add selected Edge, Brave, and Firefox paths here as applicable.
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

4. Confirm that Discord/browser storage is back in its normal location, then
   remove the `.dguard` directory if no active vault or logs are needed.
5. Remove `guard_config.json` manually if you want to delete saved alert
   credentials and URLs.

## Contributing

Issues and pull requests are welcome. Please do not include real session data,
webhook URLs, ntfy topics, SMTP credentials, or `guard_config.json` in bug
reports or pull requests. Contributions should preserve the Windows-only
scope and document any changes to the lock/unlock or audit behavior.

## License

Choose and add a license before publishing this repository. Until then, treat
the project as **all rights reserved** and do not assume permission to
redistribute modified copies.
