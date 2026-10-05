param(
    [switch]$Configure,
    [string]$ConfigPath,
    [string[]]$Paths
)

$ErrorActionPreference = "Stop"

function Set-ReadAuditRule {
    param([string]$TargetPath)

    if (-not (Test-Path -LiteralPath $TargetPath)) {
        Write-Warning "Target does not exist yet; skipped: $TargetPath"
        return
    }

    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule -ArgumentList @(
        "Everyone",
        [System.Security.AccessControl.FileSystemRights]::Read,
        $inheritanceFlags,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success
    )

    $items = @(Get-Item -LiteralPath $TargetPath -Force)
    if ($items[0].PSIsContainer) {
        $items += @(Get-ChildItem -LiteralPath $TargetPath -Force -Recurse -ErrorAction SilentlyContinue)
    }

    foreach ($item in $items) {
        $acl = Get-Acl -LiteralPath $item.FullName
        $acl.SetAuditRule($rule)
        Set-Acl -LiteralPath $item.FullName -AclObject $acl
    }
    Write-Host "Audit rule applied: $TargetPath"
}

function Find-FirefoxProfile {
    $iniPath = Join-Path $env:APPDATA "Mozilla\Firefox\profiles.ini"
    if (-not (Test-Path -LiteralPath $iniPath)) { return $null }

    $section = $null
    $profiles = @{}
    $current = $null
    foreach ($line in Get-Content -LiteralPath $iniPath -ErrorAction Stop) {
        if ($line -match '^\[(Profile\d+)\]$') {
            $current = $Matches[1]
            $profiles[$current] = @{}
        } elseif ($current -and $line -match '^([^=]+)=(.*)$') {
            $profiles[$current][$Matches[1]] = $Matches[2]
        }
    }
    foreach ($name in ($profiles.Keys | Sort-Object)) {
        if ($profiles[$name]["Default"] -eq "1") { $section = $name; break }
    }
    if (-not $section -and $profiles.Count -gt 0) {
        $section = ($profiles.Keys | Sort-Object | Select-Object -First 1)
    }
    if (-not $section) { return $null }

    $profilePath = $profiles[$section]["Path"]
    if (-not $profilePath) { return $null }
    if ($profiles[$section]["IsRelative"] -eq "1") {
        return (Join-Path (Split-Path -Parent $iniPath) $profilePath)
    }
    return $profilePath
}

if ($Configure) {
    & auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol could not enable File System auditing (exit code $LASTEXITCODE)."
    }

    if (-not $ConfigPath) { throw "ConfigPath is required with -Configure." }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $Paths = @(
        (Join-Path $env:APPDATA "discord\Local Storage\leveldb")
    )
    foreach ($browser in @($config.browsers)) {
        switch ([string]$browser) {
            "chrome" { $Paths += (Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\Local Storage\leveldb") }
            "edge" { $Paths += (Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data\Default\Local Storage\leveldb") }
            "brave" { $Paths += (Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb") }
            "opera" { $Paths += (Join-Path $env:APPDATA "Opera Software\Opera Stable\Local Storage\leveldb") }
            "opera_gx" { $Paths += (Join-Path $env:APPDATA "Opera Software\Opera GX Stable\Local Storage\leveldb") }
            "vivaldi" { $Paths += (Join-Path $env:LOCALAPPDATA "Vivaldi\User Data\Default\Local Storage\leveldb") }
            "chromium" { $Paths += (Join-Path $env:LOCALAPPDATA "Chromium\User Data\Default\Local Storage\leveldb") }
            "yandex" { $Paths += (Join-Path $env:LOCALAPPDATA "Yandex\YandexBrowser\User Data\Default\Local Storage\leveldb") }
            "firefox" {
                $profile = Find-FirefoxProfile
                if ($profile) {
                    $Paths += (Join-Path $profile "webappsstore.sqlite")
                    $Paths += (Join-Path $profile "storage")
                } else {
                    Write-Warning "Firefox is selected, but profiles.ini has no usable profile."
                }
            }
        }
    }
}

if (-not $Paths -or $Paths.Count -eq 0) {
    throw "No audit paths were supplied."
}

foreach ($path in $Paths) {
    try {
        Set-ReadAuditRule -TargetPath $path
    } catch {
        Write-Error "Could not apply the audit rule to $path : $($_.Exception.Message)"
        exit 1
    }
}
