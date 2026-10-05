"""TokenLatch Security event watcher.

Reads Windows Security Event ID 4663 entries and alerts when a process other
than the owning app reads a guarded session-storage path. This is alerting
only; it cannot block the read.
"""

import ctypes
import datetime
import logging
import os
import signal
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
import smtplib
import subprocess
import sys
from pathlib import Path

import psutil
import requests
import win32evtlog

from discord_guard import (
    selected_targets,
)

ACCESS_PID_FILE = Path(os.environ.get("LOCALAPPDATA", "")) / ".dguard" / "access_watch.pid"
ACCESS_LOG_FILE = ACCESS_PID_FILE.parent / "access_alerts.log"
STOP_FILE = ACCESS_PID_FILE.parent / "access_watch.stop"
POLL_SECONDS = 1.0
EVENT_QUERY = "*[System[(EventID=4663)]]"
READ_ACCESS_MASK = 0x1 | 0x8 | 0x80 | 0x100 | 0x20000 | 0x80000000

ACCESS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def handle_shutdown(signum, frame):
    raise KeyboardInterrupt

log = logging.getLogger("dguard.access")
log.setLevel(logging.INFO)
log.propagate = False
if not log.handlers:
    handler = logging.FileHandler(ACCESS_LOG_FILE, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(handler)


def write_pid_file():
    ACCESS_PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        STOP_FILE.unlink()
    except FileNotFoundError:
        pass
    pid_text = str(os.getpid())
    for _ in range(2):
        try:
            fd = os.open(str(ACCESS_PID_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(pid_text)
            return
        except FileExistsError:
            try:
                old_pid = int(ACCESS_PID_FILE.read_text(encoding="ascii").strip())
            except (OSError, ValueError, UnicodeError):
                old_pid = 0
            if old_pid and psutil.pid_exists(old_pid):
                raise RuntimeError(f"TokenLatch access watcher is already running (PID {old_pid}).")
            try:
                ACCESS_PID_FILE.unlink()
            except FileNotFoundError:
                pass
    raise RuntimeError("Could not create the access-watcher PID lock.")


def remove_pid_file():
    try:
        if ACCESS_PID_FILE.read_text(encoding="ascii").strip() == str(os.getpid()):
            ACCESS_PID_FILE.unlink()
    except (FileNotFoundError, OSError, UnicodeError):
        pass


def target_paths(target):
    return target.get("paths", [target["path"]])


def dos_device_variants(path: Path):
    """Return DOS and \\Device path spellings used by Security events."""
    resolved = str(path.resolve()).lower().rstrip("\\")
    variants = {resolved}
    if len(resolved) >= 2 and resolved[1] == ":":
        drive = resolved[:2].upper()
        buffer = ctypes.create_unicode_buffer(4096)
        if ctypes.windll.kernel32.QueryDosDeviceW(drive, buffer, len(buffer)):
            variants.add((buffer.value + resolved[2:]).lower().rstrip("\\"))
    return variants


def event_matches_path(object_name: str, path: Path) -> bool:
    object_name = object_name.lower().rstrip("\\")
    for variant in dos_device_variants(path):
        if object_name == variant or object_name.startswith(variant + "\\"):
            return True
    return False


def parse_event(event):
    xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
    root = ET.fromstring(xml)
    values = {}
    for node in root.findall(".//{*}EventData/{*}Data"):
        values[node.attrib.get("Name", "")] = node.text or ""
    system = root.find(".//{*}System")
    record_id = system.findtext("{*}EventRecordID", default="") if system is not None else ""
    return record_id, values


def is_read_access(values):
    """Ignore 4663 records that contain no file-read access bits."""
    raw = values.get("AccessMask", "")
    if not raw:
        # Some Windows builds omit AccessMask from rendered event data. Keep
        # those records rather than silently losing coverage.
        return True
    try:
        return bool(int(raw, 0) & READ_ACCESS_MASK)
    except (TypeError, ValueError):
        return True


def process_name_and_path(values):
    raw_name = values.get("ProcessName", "")
    name = Path(raw_name).name.lower() if raw_name else "unknown"
    pid_text = values.get("ProcessId", "")
    try:
        pid = int(pid_text, 0)
    except (TypeError, ValueError):
        pid = 0
    process_path = raw_name
    if pid:
        try:
            process_path = psutil.Process(pid).exe()
            name = Path(process_path).name.lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
    return name, pid, process_path


def notify(process_name, process_path, folder):
    message = (
        f"Unexpected process {process_name} accessed your Discord session files.\n\n"
        "Reset your Discord password/token now.\n\n"
        f"Folder: {folder}\nProcess: {process_path}"
    )
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast("TokenLatch ALERT", message, duration=10, threaded=True)
        return
    except Exception:
        pass
    try:
        import threading
        threading.Thread(
            target=ctypes.windll.user32.MessageBoxW,
            args=(0, message, "TokenLatch ALERT", 0x10 | 0x1000),
            daemon=True,
        ).start()
    except Exception:
        log.exception("Could not display the access alert notification.")


def alert_config():
    from discord_guard import load_config
    config = load_config().get("alerts", {})
    return config if isinstance(config, dict) else {}


def send_ntfy(alerts, message):
    settings = alerts.get("ntfy", {})
    if not isinstance(settings, dict):
        return
    url = settings.get("topic_url", "")
    if not settings.get("enabled") or not url:
        return
    response = requests.post(
        url,
        data=message.encode("utf-8"),
        headers={"Title": "TokenLatch ALERT", "Priority": "urgent", "Tags": "warning"},
        timeout=10,
    )
    response.raise_for_status()
    log.info("Remote alert sent through ntfy.sh.")


def send_discord_webhook(alerts, message):
    settings = alerts.get("discord_webhook", {})
    if not isinstance(settings, dict):
        return
    url = settings.get("url", "")
    if not settings.get("enabled") or not url:
        return
    response = requests.post(url, json={"content": message}, timeout=10)
    response.raise_for_status()
    log.info("Remote alert sent through Discord webhook.")


def send_email(alerts, message):
    settings = alerts.get("email", {})
    if not isinstance(settings, dict):
        return
    if not settings.get("enabled"):
        return
    host = settings.get("smtp_server", "")
    port = int(settings.get("smtp_port", 587))
    from_addr = settings.get("from_addr", "")
    app_password = settings.get("app_password", "")
    to_addr = settings.get("to_addr", "")
    if not all((host, from_addr, app_password, to_addr)):
        raise ValueError("email alert settings are incomplete")
    email = EmailMessage()
    email["Subject"] = "TokenLatch ALERT: unexpected session-file read"
    email["From"] = from_addr
    email["To"] = to_addr
    email.set_content(message)
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
            smtp.login(from_addr, app_password)
            smtp.send_message(email)
    else:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(from_addr, app_password)
            smtp.send_message(email)
    log.info("Remote alert sent by email.")


def send_remote_alerts(message):
    """Fan out without blocking the local alert or watcher loop."""
    alerts = alert_config()
    jobs = {
        "ntfy": send_ntfy,
        "discord_webhook": send_discord_webhook,
        "email": send_email,
    }
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            name: executor.submit(function, alerts, message)
            for name, function in jobs.items()
            if isinstance(alerts.get(name, {}), dict)
            and alerts.get(name, {}).get("enabled")
        }
        results = {}
        for name, future in futures.items():
            try:
                future.result(timeout=12)
                results[name] = (True, "ok")
            except Exception as exc:
                log.error("Remote %s alert failed: %s", name, exc)
                results[name] = (False, str(exc))
        return results


def enabled_alert_names():
    alerts = alert_config()
    return [
        name for name in ("ntfy", "discord_webhook", "email")
        if isinstance(alerts.get(name), dict) and alerts[name].get("enabled")
    ]


def dispatch_remote_alerts(message):
    """Send remote alerts off the event loop so detection stays responsive."""
    threading.Thread(
        target=send_remote_alerts,
        args=(message,),
        name="TokenLatchRemoteAlert",
        daemon=True,
    ).start()


def build_alert_message(process_name, pid, process_path, folder, object_name):
    timestamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    return (
        "TokenLatch ALERT: unexpected process accessed Discord session files.\n"
        f"Process: {process_name}\nPID: {pid}\nTime: {timestamp}\n"
        f"Target: {folder}\nObject: {object_name}\nPath: {process_path}\n"
        "Reset your Discord password/token now."
    )


def alert_for_event(values, targets):
    object_name = values.get("ObjectName", "")
    if not object_name or not is_read_access(values):
        return
    process_name, pid, process_path = process_name_and_path(values)
    for target in targets:
        if not any(event_matches_path(object_name, path) for path in target_paths(target)):
            continue
        allowed = {name.lower() for name in target["process_names"]}
        if process_name in allowed:
            return
        folder = target["name"]
        log.warning(
            "UNEXPECTED READ target=%s object=%s process=%s pid=%s path=%s",
            folder,
            object_name,
            process_name,
            pid,
            process_path,
        )
        notify(process_name, process_path, folder)
        dispatch_remote_alerts(build_alert_message(process_name, pid, process_path, folder, object_name))
        return


def send_test_alert():
    message = (
        "TokenLatch test alert: remote alert delivery is configured correctly.\n"
        f"Time: {datetime.datetime.now().astimezone().isoformat(timespec='seconds')}"
    )
    names = enabled_alert_names()
    if not names:
        print("[SKIP] No remote alert channels are enabled.")
        return 0
    results = send_remote_alerts(message)
    failed = 0
    for name in names:
        ok, detail = results.get(name, (False, "no result"))
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")
        failed += not ok
    print("Test message: TokenLatch diagnostic test alert")
    return 1 if failed else 0


def process_running(names):
    wanted = {name.lower() for name in names}
    found = set()
    for proc in psutil.process_iter(attrs=["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in wanted:
                found.add(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    return sorted(found)


def pid_status(path):
    try:
        pid = int(path.read_text(encoding="ascii").strip())
        alive = psutil.pid_exists(pid)
        return f"PID {pid} ({'running' if alive else 'not running'})"
    except (FileNotFoundError, OSError, UnicodeError, ValueError):
        return "not present"


def run_diagnostics():
    from discord_guard import CONFIG_FILE, GUARD_TARGETS, PID_FILE, selected_targets

    print("=" * 64)
    print("TokenLatch DIAGNOSTICS")
    print("=" * 64)
    print(f"Python: {sys.executable}")
    for module in ("psutil", "pywin32", "requests"):
        try:
            if module == "pywin32":
                import win32crypt, win32evtlog  # noqa: F401
            else:
                __import__(module)
            print(f"[OK] Dependency: {module}")
        except Exception as exc:
            print(f"[FAIL] Dependency: {module}: {exc}")

    print(f"[{'OK' if CONFIG_FILE.exists() else 'FAIL'}] Configuration: {CONFIG_FILE}")
    targets = selected_targets()
    for target in targets:
        paths = target.get("paths", [target.get("path")])
        for path in paths:
            if path is None:
                continue
            print(f"[{'OK' if path.exists() else 'WARN'}] {target['name']}: {path}")

    print(f"[INFO] Main guard: {pid_status(PID_FILE)}")
    print(f"[INFO] Access watcher: {pid_status(ACCESS_PID_FILE)}")
    print(f"[INFO] Discord processes: {', '.join(process_running({'discord.exe', 'discordptb.exe', 'discordcanary.exe'})) or 'none'}")
    for target in targets:
        if target["name"] == "discord_desktop":
            continue
        running = process_running(target["process_names"])
        print(f"[INFO] {target['name']} processes: {', '.join(running) or 'none'}")

    try:
        audit = subprocess.run(
            ['auditpol.exe', '/get', '/subcategory:File System'],
            capture_output=True, text=True, timeout=10, check=False,
        )
        enabled = "Success and Failure" in audit.stdout or "Success" in audit.stdout
        print(f"[{'OK' if enabled else 'WARN'}] File System audit policy: {audit.stdout.strip() or audit.stderr.strip()}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[WARN] File System audit policy could not be queried: {exc}")

    names = enabled_alert_names()
    for name in ("ntfy", "discord_webhook", "email"):
        print(f"[{'INFO' if name in names else 'SKIP'}] Alert channel: {name} ({'enabled' if name in names else 'disabled'})")
    if names:
        print("Sending diagnostic test alerts...")
        return send_test_alert()
    return 0


def read_recent_events():
    query = win32evtlog.EvtQuery(
        "Security",
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        EVENT_QUERY,
    )
    try:
        return win32evtlog.EvtNext(query, 100, 0)
    finally:
        # EvtClose is not exposed by every pywin32 build. The handle wrapper
        # is released by Python in those builds, so do not turn a successful
        # event read into a watcher failure just because the optional close
        # function is unavailable.
        close_event = getattr(win32evtlog, "EvtClose", None)
        if close_event is not None:
            close_event(query)


def main():
    write_pid_file()
    signal.signal(signal.SIGTERM, handle_shutdown)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, handle_shutdown)
    try:
        targets = selected_targets()
        seen = set()
        first_pass = True
        log.info("TokenLatch access watcher starting; auditing %d target(s).", len(targets))
        while True:
            if STOP_FILE.exists():
                try:
                    STOP_FILE.unlink()
                except OSError:
                    pass
                log.info("TokenLatch access watcher received a stop request.")
                break
            try:
                events = read_recent_events()
                for event in reversed(events):
                    record_id, values = parse_event(event)
                    if not record_id or record_id in seen:
                        continue
                    seen.add(record_id)
                    if not first_pass:
                        alert_for_event(values, targets)
                if len(seen) > 5000:
                    seen = set(list(seen)[-2500:])
                first_pass = False
            except Exception as exc:
                log.error("Security log read failed: %s", exc)
                time.sleep(5)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        log.info("TokenLatch access watcher stopping.")
    finally:
        remove_pid_file()


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("This watcher is Windows-only.")
    if "--test" in sys.argv:
        raise SystemExit(send_test_alert())
    if "--diagnose" in sys.argv:
        raise SystemExit(run_diagnostics())
    main()
