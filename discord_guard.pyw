"""
Discord Session Guard
----------------------
Protects Discord's local session-token storage (and Chromium browsers'
storage, since Discord's desktop app can fall back to a logged-in browser
session) by moving the relevant "Local Storage/leveldb" folders to a hidden
vault whenever the owning app is CLOSED, and restoring them the moment the
app is launched again.

Threat model this defends against:
  A stealer / malicious script runs on your machine while Discord (and/or
  your browser) is NOT open, and tries to read the token files directly off
  disk. If the files have been moved to the vault, there's nothing there to
  steal.

Threat model this does NOT defend against:
  Malware that is actively running WHILE Discord/your browser is open and
  logged in (the token is decrypted in memory / unlocked on disk at that
  point, same as it always is). This tool shrinks the attack window, it
  doesn't eliminate it. Keep real AV / don't run untrusted files.

Run this as a persistent background process (see bottom of file for how to
add it to Windows Startup). Tested target: Windows 10/11, Python 3.9+.

Dependencies:
    pip install psutil pywin32
"""

import os
import sys
import time
import json
import shutil
import logging
import datetime
import signal
import configparser
import subprocess
import secrets
import string
from pathlib import Path

import psutil
import win32crypt

# --------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------

APPDATA = Path(os.environ.get("APPDATA", ""))            # Roaming
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", ""))   # Local

VAULT_ROOT = LOCALAPPDATA / ".dguard"
VAULT_STATE_FILE = VAULT_ROOT / "vault_state.bin"
LOG_FILE = LOCALAPPDATA / ".dguard" / "guard.log"
PID_FILE = LOCALAPPDATA / ".dguard" / "guard.pid"
CONFIG_FILE = Path(__file__).resolve().parent / "guard_config.json"
AUDIT_SCRIPT = Path(__file__).resolve().with_name("audit_setup.ps1")
_vault_state_read_failed = False

# Poll interval for process detection. Lower = faster reaction, more CPU.
POLL_SECONDS = 0.4

# How long to wait after a process disappears before re-locking, to avoid
# a false "closed" read during a crash-restart or update.
CLOSE_GRACE_SECONDS = 3

# Each entry: a friendly name, the process executable name(s) that "own"
# this storage, and the path to the storage folder/file to guard.
# Add more browser profiles by duplicating a Chromium entry with a
# different profile folder name (e.g. "Profile 1", "Profile 2").
GUARD_TARGETS = [
    {
        "name": "discord_desktop",
        "process_names": {"discord.exe", "discordptb.exe", "discordcanary.exe"},
        "path": APPDATA / "discord" / "Local Storage" / "leveldb",
    },
    {
        "name": "chrome_default",
        "process_names": {"chrome.exe"},
        "path": LOCALAPPDATA / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage" / "leveldb",
    },
    {
        "name": "edge_default",
        "process_names": {"msedge.exe"},
        "path": LOCALAPPDATA / "Microsoft" / "Edge" / "User Data" / "Default" / "Local Storage" / "leveldb",
    },
    {
        "name": "brave_default",
        "process_names": {"brave.exe"},
        "path": LOCALAPPDATA / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Local Storage" / "leveldb",
    },
    {
        "name": "opera_default",
        "process_names": {"opera.exe"},
        "path": APPDATA / "Opera Software" / "Opera Stable" / "Local Storage" / "leveldb",
    },
    {
        "name": "opera_gx_default",
        "process_names": {"opera_gx.exe"},
        "path": APPDATA / "Opera Software" / "Opera GX Stable" / "Local Storage" / "leveldb",
    },
    {
        "name": "vivaldi_default",
        "process_names": {"vivaldi.exe"},
        "path": LOCALAPPDATA / "Vivaldi" / "User Data" / "Default" / "Local Storage" / "leveldb",
    },
    {
        "name": "chromium_default",
        "process_names": {"chromium.exe"},
        "path": LOCALAPPDATA / "Chromium" / "User Data" / "Default" / "Local Storage" / "leveldb",
    },
    {
        "name": "yandex_default",
        "process_names": {"browser.exe"},
        "path": LOCALAPPDATA / "Yandex" / "YandexBrowser" / "User Data" / "Default" / "Local Storage" / "leveldb",
    },
    {
        "name": "firefox_default",
        "process_names": {"firefox.exe"},
        # Filled from profiles.ini when Firefox is selected in the config.
        "path": None,
    },
]

# --------------------------------------------------------------------------
# LOGGING
# --------------------------------------------------------------------------

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("dguard")


def load_config() -> dict:
    """Load launcher settings, using safe defaults for a missing/invalid file."""
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as fh:
            config = json.load(fh)
        browsers = config.get("browsers", [])
        if not isinstance(browsers, list):
            browsers = []
        alerts = config.get("alerts", {})
        if not isinstance(alerts, dict):
            alerts = {}
        return {
            "browsers": {str(browser).lower() for browser in browsers},
            "alerts": alerts,
        }
    except (OSError, ValueError, TypeError):
        return {"browsers": set(), "alerts": {}}


def selected_targets() -> list:
    """Always guard Discord, plus only browsers selected in the launcher."""
    selected = load_config()["browsers"]
    browser_target_names = {
        "chrome": "chrome_default",
        "edge": "edge_default",
        "brave": "brave_default",
        "opera": "opera_default",
        "opera_gx": "opera_gx_default",
        "vivaldi": "vivaldi_default",
        "chromium": "chromium_default",
        "yandex": "yandex_default",
        "firefox": "firefox_default",
    }
    allowed = {"discord_desktop"}
    allowed.update(
        browser_target_names[browser]
        for browser in selected
        if browser in browser_target_names
    )
    targets = [target for target in GUARD_TARGETS if target["name"] in allowed]
    if "firefox_default" in allowed:
        profile_dir = find_firefox_profile()
        if profile_dir is None:
            log.warning("Firefox selected, but no Firefox profile was found in profiles.ini.")
            targets = [target for target in targets if target["name"] != "firefox_default"]
        else:
            for index, target in enumerate(targets):
                if target["name"] == "firefox_default":
                    target = target.copy()
                    target["paths"] = [profile_dir / "webappsstore.sqlite", profile_dir / "storage"]
                    targets[index] = target
                    break
    return targets


def find_firefox_profile():
    """Return Firefox's default profile directory from profiles.ini."""
    profiles_ini = APPDATA / "Mozilla" / "Firefox" / "profiles.ini"
    if not profiles_ini.exists():
        return None

    parser = configparser.ConfigParser()
    try:
        parser.read(profiles_ini, encoding="utf-8")
    except (OSError, configparser.Error):
        return None

    sections = [section for section in parser.sections() if section.lower().startswith("profile")]
    sections.sort()
    selected_section = next(
        (section for section in sections if parser.get(section, "Default", fallback="0") == "1"),
        sections[0] if sections else None,
    )
    if selected_section is None:
        return None

    profile_path = parser.get(selected_section, "Path", fallback="").strip()
    if not profile_path:
        return None
    profile_dir = Path(profile_path)
    if parser.get(selected_section, "IsRelative", fallback="1") == "1":
        profile_dir = profiles_ini.parent / profile_dir
    return profile_dir


def write_pid_file():
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    pid_text = str(os.getpid())
    for _ in range(2):
        try:
            fd = os.open(str(PID_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(pid_text)
            return
        except FileExistsError:
            try:
                old_pid = int(PID_FILE.read_text(encoding="ascii").strip())
            except (OSError, ValueError, UnicodeError):
                old_pid = 0
            if old_pid and psutil.pid_exists(old_pid):
                raise RuntimeError(f"TokenLatch is already running (PID {old_pid}).")
            try:
                PID_FILE.unlink()
            except FileNotFoundError:
                pass
    raise RuntimeError("Could not create the TokenLatch PID lock.")


def load_vault_state() -> dict:
    """Decrypt the active random vault-folder mapping with Windows DPAPI."""
    global _vault_state_read_failed
    if not VAULT_STATE_FILE.exists():
        _vault_state_read_failed = False
        return {}
    try:
        _description, plaintext = win32crypt.CryptUnprotectData(
            VAULT_STATE_FILE.read_bytes(), None
        )
        state = json.loads(plaintext.decode("utf-8"))
        active = state.get("active", {})
        _vault_state_read_failed = False
        return active if isinstance(active, dict) else {}
    except Exception as exc:
        _vault_state_read_failed = True
        log.warning("Vault state could not be decrypted; using fallback scan: %s", exc)
        return {}


def save_vault_state(active: dict):
    if _vault_state_read_failed and VAULT_STATE_FILE.exists():
        raise RuntimeError(
            "Refusing to overwrite an unreadable DPAPI vault state file; "
            "recover it under the original Windows account first."
        )
    VAULT_ROOT.mkdir(parents=True, exist_ok=True)
    plaintext = json.dumps({"version": 1, "active": active}, separators=(",", ":")).encode("utf-8")
    protected = win32crypt.CryptProtectData(
        plaintext, "TokenLatch vault state", None, None, None, 0
    )
    temporary = VAULT_STATE_FILE.with_suffix(".tmp")
    temporary.write_bytes(protected)
    os.replace(temporary, VAULT_STATE_FILE)


def random_vault_name() -> str:
    alphabet = string.ascii_letters + string.digits
    length = secrets.choice(range(24, 33))
    return "".join(secrets.choice(alphabet) for _ in range(length))


def is_random_vault_name(name: str) -> bool:
    return 24 <= len(name) <= 32 and all(char in string.ascii_letters + string.digits for char in name)


def source_paths_for(target: dict) -> list:
    return [path for path in target.get("paths", [target.get("path")]) if path is not None]


def fallback_vault_for(target: dict):
    """Last-resort recovery when DPAPI state is missing or unreadable."""
    expected_names = {path.name for path in source_paths_for(target)}
    candidates = []
    if not VAULT_ROOT.exists():
        return None
    for candidate in VAULT_ROOT.iterdir():
        if not candidate.is_dir() or not is_random_vault_name(candidate.name):
            continue
        names = {item.name for item in candidate.iterdir()}
        score = len(expected_names.intersection(names))
        if score:
            candidates.append((score, candidate.stat().st_mtime, candidate))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    chosen = candidates[0][2]
    log.warning(
        "Vault state was unavailable; fallback scan selected %s for %s. "
        "Verify the restored files carefully.",
        chosen,
        target["name"],
    )
    return chosen


def cleanup_stale_vaults():
    """Remove only empty inactive vault containers.

    Non-empty inactive containers are deliberately retained: they may contain
    the only recoverable copy of a session store after an interrupted move.
    The encrypted state mapping is authoritative, so the active container is
    never considered stale.
    """
    if not VAULT_ROOT.exists():
        return

    active = load_vault_state()
    active_names = {
        value for value in active.values()
        if isinstance(value, str) and is_random_vault_name(value)
    }

    for candidate in VAULT_ROOT.iterdir():
        if not candidate.is_dir() or not is_random_vault_name(candidate.name):
            continue
        if candidate.name in active_names:
            continue
        try:
            remaining = list(candidate.iterdir())
            if not remaining:
                candidate.rmdir()
                log.info("Removed empty inactive vault folder: %s", candidate)
            else:
                names = ", ".join(item.name for item in remaining[:8])
                suffix = "..." if len(remaining) > 8 else ""
                log.warning(
                    "Retaining non-empty inactive vault folder %s; it contains "
                    "recoverable data (%s%s). Delete it only after verifying "
                    "that the session storage has been restored.",
                    candidate, names, suffix,
                )
        except OSError as exc:
            log.warning("Could not inspect inactive vault folder %s: %s", candidate, exc)


def remove_empty_vault_container(path: Path):
    """Remove a vault container only after its moved data is gone."""
    if not path.exists():
        return
    try:
        remaining = list(path.iterdir())
        if not remaining:
            path.rmdir()
            log.info("Removed empty vault folder: %s", path)
        else:
            names = ", ".join(item.name for item in remaining[:8])
            suffix = "..." if len(remaining) > 8 else ""
            log.warning(
                "Vault folder %s was not removed because it still contains: %s%s",
                path, names, suffix,
            )
    except OSError as exc:
        log.warning("Could not remove vault folder %s: %s", path, exc)


def remove_pid_file():
    try:
        if PID_FILE.read_text(encoding="ascii").strip() == str(os.getpid()):
            PID_FILE.unlink()
    except (FileNotFoundError, OSError, UnicodeError):
        pass


def reapply_audit_sacl(target: dict):
    """Best-effort SACL refresh after storage is restored from the vault."""
    paths = target.get("paths", [target.get("path")])
    paths = [path for path in paths if path is not None]
    if not paths or not AUDIT_SCRIPT.exists():
        log.warning("Cannot refresh the audit rule for %s.", target["name"])
        return
    try:
        result = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(AUDIT_SCRIPT), "-Paths",
                *[str(path) for path in paths],
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if result.returncode != 0:
            log.warning(
                "Could not refresh the audit rule for %s: %s",
                target["name"], result.stderr.strip(),
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("Could not refresh the audit rule for %s: %s", target["name"], exc)


def handle_shutdown(signum, frame):
    raise KeyboardInterrupt


# --------------------------------------------------------------------------
# CORE LOCK / UNLOCK LOGIC
# --------------------------------------------------------------------------

def vault_path_for(target: dict) -> Path:
    active_name = load_vault_state().get(target["name"])
    if active_name and is_random_vault_name(active_name):
        return VAULT_ROOT / active_name
    return fallback_vault_for(target)


def remove_path(path: Path):
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def is_running(process_names: set) -> bool:
    names = {n.lower() for n in process_names}
    for proc in psutil.process_iter(attrs=["name"]):
        try:
            pname = (proc.info["name"] or "").lower()
            if pname in names:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def lock_target(target: dict):
    """Move the leveldb folder into the vault (i.e. out of the normal path)."""
    paths = source_paths_for(target)
    state = load_vault_state()
    active_name = state.get(target["name"])
    dst_root = VAULT_ROOT / active_name if active_name and is_random_vault_name(active_name) else None
    if dst_root is not None and not dst_root.exists():
        state.pop(target["name"], None)
        save_vault_state(state)
        dst_root = None
    if dst_root is not None and any(path.exists() for path in paths):
        # A previous cycle left an active vault while the app recreated its
        # live storage. Never overwrite that recoverable copy; start this lock
        # cycle in a fresh random container instead.
        log.warning(
            "Both live storage and an existing vault were found for %s; "
            "creating a new random vault and retaining the old one for recovery.",
            target["name"],
        )
        dst_root = None
    if dst_root is None:
        while True:
            active_name = random_vault_name()
            dst_root = VAULT_ROOT / active_name
            if not dst_root.exists():
                break
        state[target["name"]] = active_name
        save_vault_state(state)

    if not any(path.exists() for path in paths):
        # If the active vault already exists, this target is correctly locked.
        # Keep its mapping: clearing it here would make the data recoverable
        # only through the ambiguous fallback scan after a restart.
        if dst_root is not None and dst_root.exists():
            log.info("ALREADY LOCKED %s: keeping active vault mapping", target["name"])
        else:
            state.pop(target["name"], None)
            save_vault_state(state)
        return

    if len(paths) > 1 or "paths" in target:
        moved = False
        for src in paths:
            if not src.exists():
                continue
            dst = dst_root / src.name
            dst_root.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                remove_path(dst)
            try:
                shutil.move(str(src), str(dst))
                moved = True
            except Exception as e:
                log.error(f"Failed to lock {target['name']} ({src.name}): {e}")
        if moved:
            log.info(f"LOCKED  {target['name']}: moved Firefox storage to vault")
        return

    src = paths[0]
    dst = dst_root / src.name

    if not src.exists():
        # Nothing there currently (already locked, or app never installed)
        return

    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        shutil.rmtree(dst)

    try:
        shutil.move(str(src), str(dst))
        log.info(f"LOCKED  {target['name']}: moved to vault")
    except Exception as e:
        log.error(f"Failed to lock {target['name']}: {e}")


def unlock_target(target: dict):
    """Move the leveldb folder back from the vault to its real location."""
    state = load_vault_state()
    src_root = vault_path_for(target)
    if src_root is None:
        reapply_audit_sacl(target)
        return
    paths = source_paths_for(target)
    if len(paths) > 1 or "paths" in target:
        restored = False
        had_error = False
        for dst in paths:
            src = src_root / dst.name
            if not src.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                remove_path(dst)
            try:
                shutil.move(str(src), str(dst))
                restored = True
            except Exception as e:
                log.error(f"Failed to unlock {target['name']} ({dst.name}): {e}")
                had_error = True
        if restored:
            log.info(f"UNLOCKED {target['name']}: restored Firefox storage")
        if not had_error:
            state.pop(target["name"], None)
            save_vault_state(state)
            remove_empty_vault_container(src_root)
        reapply_audit_sacl(target)
        return

    src = src_root / paths[0].name
    dst = paths[0]

    if not src.exists():
        # Nothing in the vault to restore (first run, or already unlocked)
        reapply_audit_sacl(target)
        return

    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        # Something already created a fresh folder (e.g. app made a new one
        # before we got to it) - merge by removing the fresh one, ours wins,
        # since ours has the real session history.
        shutil.rmtree(dst)

    try:
        shutil.move(str(src), str(dst))
        log.info(f"UNLOCKED {target['name']}: restored from vault")
    except Exception as e:
        log.error(f"Failed to unlock {target['name']}: {e}")
    else:
        state.pop(target["name"], None)
        save_vault_state(state)
        remove_empty_vault_container(src_root)
    reapply_audit_sacl(target)


# --------------------------------------------------------------------------
# WATCH LOOP
# --------------------------------------------------------------------------

def main():
    targets = selected_targets()
    write_pid_file()
    try:
        signal.signal(signal.SIGTERM, handle_shutdown)
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, handle_shutdown)

        log.info("Discord Session Guard starting.")
        log.info(f"Random vault root: {VAULT_ROOT}")
        cleanup_stale_vaults()

        # state[target_name] = "locked" | "unlocked"
        state = {}
        # when a target's process disappeared, remember when, to apply grace period
        pending_close_since = {}

        # --- initial pass: lock anything whose owning app isn't running ---
        for target in targets:
            running = is_running(target["process_names"])
            if running:
                unlock_target(target)
                state[target["name"]] = "unlocked"
            else:
                lock_target(target)
                state[target["name"]] = "locked"

        log.info("Initial state set. Entering watch loop. Ctrl+C to stop.")

        try:
            while True:
                for target in targets:
                    name = target["name"]
                    running = is_running(target["process_names"])

                    if running and state[name] == "locked":
                        # App just launched -> restore immediately
                        log.info("%s process detected; unlocking its session storage.", name)
                        unlock_target(target)
                        state[name] = "unlocked"
                        pending_close_since.pop(name, None)

                    elif not running and state[name] == "unlocked":
                        # App just closed -> start grace timer before locking
                        if name not in pending_close_since:
                            pending_close_since[name] = time.time()
                            log.info("%s processes are no longer running; close grace period started.", name)
                        elif time.time() - pending_close_since[name] >= CLOSE_GRACE_SECONDS:
                            log.info("%s close grace period finished; locking its session storage.", name)
                            lock_target(target)
                            state[name] = "locked"
                            pending_close_since.pop(name, None)

                    elif running:
                        # Still running, cancel any pending close timer
                        pending_close_since.pop(name, None)

                time.sleep(POLL_SECONDS)

        except KeyboardInterrupt:
            log.info("Stopping. Locking everything on exit for safety.")
            for target in targets:
                if not is_running(target["process_names"]):
                    lock_target(target)
    finally:
        remove_pid_file()


if __name__ == "__main__":
    if os.name != "nt":
        print("This tool is Windows-only (it targets Windows AppData paths).")
        sys.exit(1)
    main()
