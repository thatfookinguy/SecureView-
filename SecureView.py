"""
Windows Silent Install & Malware Scanner  v7.0
-----------------------------------------------
Requirements (install once):
    pip install psutil pywin32 requests

Optional (better handle closing):
    Download handle.exe from https://learn.microsoft.com/en-us/sysinternals/downloads/handle
    and place it in the same folder as this script.

Run as Administrator for best results.
"""

import os
import sys
import time
import shutil
import ctypes
import hashlib
import subprocess
import threading
import winreg
import json
import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime
from pathlib import Path

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

try:
    import win32api, win32con, win32security
    HAVE_WIN32 = True
except ImportError:
    HAVE_WIN32 = False

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

# ── Palette ───────────────────────────────────────────────────────────────────
BG     = "#1a1a2e"
PANEL  = "#16213e"
ACCENT = "#0f3460"
FG     = "#e0e0e0"
BTN    = "#0f3460"
RED    = "#880000"
ORANGE = "#885500"
GREEN  = "#006633"
PURPLE = "#440066"
TEAL   = "#005566"

SEVERITY_COLORS = {
    "CRITICAL": "#ff3333",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44cc44",
    "CLEAN":    "#888888",
    "EXCLUDED": "#5588aa",
    "INFO":     "#aaaaaa",
}

# ── Constants ─────────────────────────────────────────────────────────────────

HIGH_RISK_DIRS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "INetCache"),
    "C:\\Windows\\Temp",
    "C:\\Users\\Public",
]

SCAN_ROOTS = [
    os.environ.get("PROGRAMFILES", "C:\\Program Files"),
    os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"),
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    "C:\\ProgramData",
    "C:\\Windows\\Temp",
    os.environ.get("TEMP", ""),
]

KNOWN_SAFE_PUBLISHERS = [
    "microsoft", "google", "adobe", "apple", "intel", "nvidia",
    "amd", "qualcomm", "realtek", "oracle", "mozilla", "valve",
    "zoom", "slack", "discord", "dropbox", "spotify", "amazon",
]

# Registry Run/RunOnce keys
AUTORUN_REG_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows NT\CurrentVersion\Windows\Load"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
]

# Startup folder paths
STARTUP_FOLDERS = [
    os.path.join(os.environ.get("APPDATA", ""),
                 "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
]

QUARANTINE_DIR  = os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Public"), "ScannerQuarantine")
EXCLUSIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_exclusions.json")

# Browser extension dangerous permissions
DANGEROUS_PERMS = {
    "<all_urls>":         "CRITICAL",
    "nativeMessaging":    "CRITICAL",
    "debugger":           "CRITICAL",
    "cookies":            "HIGH",
    "history":            "HIGH",
    "webRequest":         "HIGH",
    "webRequestBlocking": "HIGH",
    "clipboardRead":      "HIGH",
    "proxy":              "HIGH",
    "privacy":            "HIGH",
    "management":         "HIGH",
    "contentSettings":    "HIGH",
    "tabs":               "MEDIUM",
    "bookmarks":          "MEDIUM",
    "downloads":          "MEDIUM",
    "storage":            "LOW",
}

# ── Exclusions ────────────────────────────────────────────────────────────────

_exclusions: dict = {"paths": [], "publishers": [], "hashes": [], "ext_ids": [], "notes": {}}

def load_exclusions():
    global _exclusions
    try:
        if os.path.exists(EXCLUSIONS_FILE):
            with open(EXCLUSIONS_FILE, "r", encoding="utf-8") as f:
                _exclusions = json.load(f)
    except Exception:
        pass
    for k in ("paths", "publishers", "hashes", "ext_ids", "notes"):
        _exclusions.setdefault(k, [] if k != "notes" else {})

def save_exclusions():
    try:
        with open(EXCLUSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(_exclusions, f, indent=2)
    except Exception as e:
        messagebox.showerror("Exclusion save error", str(e))

def add_exclusion(kind, value, note=""):
    value = (value or "").strip()
    if not value:
        return False
    if value not in _exclusions.get(kind, []):
        _exclusions.setdefault(kind, []).append(value)
        _exclusions.setdefault("notes", {})[value] = note or ""
        save_exclusions()
        return True
    return False

def remove_exclusion(kind, value):
    try:
        _exclusions[kind].remove(value)
        _exclusions["notes"].pop(value, None)
        save_exclusions()
        return True
    except (ValueError, KeyError):
        return False

def is_excluded(filepath="", publisher="", md5="", ext_id=""):
    fp_lower = (filepath or "").lower()
    for exc in _exclusions.get("paths", []):
        el = exc.lower()
        if fp_lower == el or fp_lower.startswith(el + os.sep) or fp_lower.startswith(el + "/"):
            return True, f"Excluded path: {exc}"
    pub_lower = (publisher or "").lower()
    for exc in _exclusions.get("publishers", []):
        if exc.lower() in pub_lower:
            return True, f"Excluded publisher: {exc}"
    if md5 and md5 in _exclusions.get("hashes", []):
        return True, f"Excluded hash: {md5}"
    if ext_id and ext_id in _exclusions.get("ext_ids", []):
        return True, f"Excluded extension: {ext_id}"
    return False, ""

# ── Core helpers ──────────────────────────────────────────────────────────────

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def run_ps(command, timeout=25):
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

def get_signature_status(filepath):
    if not filepath or not os.path.exists(filepath):
        return "NotFound"
    return run_ps(f'(Get-AuthenticodeSignature -FilePath "{filepath}").Status', timeout=10) or "Unknown"

def get_file_publisher(filepath):
    try:
        if HAVE_WIN32 and filepath and os.path.exists(filepath):
            info = win32api.GetFileVersionInfo(filepath, "\\StringFileInfo\\040904B0\\CompanyName")
            if info:
                return info
    except Exception:
        pass
    return run_ps(f'try{{(Get-Item "{filepath}").VersionInfo.CompanyName}}catch{{""}}', timeout=8)

def get_install_date(filepath):
    try:
        return datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d")
    except Exception:
        return "Unknown"

def get_file_md5(filepath):
    try:
        h = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def assign_severity(filepath, sig_status, publisher):
    fp_lower  = (filepath or "").lower()
    pub_lower = (publisher or "").lower()
    if sig_status == "Valid":
        for safe in KNOWN_SAFE_PUBLISHERS:
            if safe in pub_lower:
                return "CLEAN", "Signed by known publisher"
        return "LOW", "Signed, publisher unrecognized"
    if sig_status == "HashMismatch":
        return "CRITICAL", "Signature tampered / hash mismatch"
    in_high_risk = any(fp_lower.startswith(d.lower()) for d in HIGH_RISK_DIRS if d)
    in_startup   = "startup" in fp_lower or "autorun" in fp_lower
    if in_startup:           return "CRITICAL", "Unsigned + startup location"
    if in_high_risk:         return "HIGH",     "Unsigned in temp/writeable location"
    if "\\appdata\\"   in fp_lower: return "HIGH",   "Unsigned in AppData"
    if "\\programdata\\" in fp_lower: return "MEDIUM", "Unsigned in ProgramData"
    return "MEDIUM", "Unsigned executable"

def extract_exe_from_cmdline(cmdline):
    if not cmdline:
        return ""
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        if end > 1:
            return cmdline[1:end]
    parts = cmdline.split()
    return parts[0] if parts else ""

def find_exe_files(root, max_files=2000, stop_event=None):
    count = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if stop_event and stop_event.is_set():
                return
            dirnames[:] = [d for d in dirnames
                           if d.lower() not in ("windows","syswow64","system32","winsxs","drivers")]
            for fname in filenames:
                if fname.lower().endswith(".exe"):
                    yield os.path.join(dirpath, fname)
                    count += 1
                    if count >= max_files:
                        return
    except PermissionError:
        pass

def get_processes_using_path(path):
    results = []
    if not HAVE_PSUTIL:
        return results
    path_lower = path.lower()
    try:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = (proc.info.get("exe") or "").lower()
                if path_lower in exe or exe.startswith(path_lower):
                    results.append((proc.pid, proc.info["name"]))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
    except Exception:
        pass
    return results

def kill_process(pid):
    if HAVE_PSUTIL:
        try:
            psutil.Process(pid).kill()
            return True
        except Exception as e:
            return str(e)
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=10)
        return True
    except Exception as e:
        return str(e)

def close_handles_to_path(path):
    for loc in ["handle.exe", "handle64.exe",
                os.path.join(os.path.dirname(__file__), "handle.exe"),
                os.path.join(os.path.dirname(__file__), "handle64.exe")]:
        if os.path.exists(loc):
            try:
                r = subprocess.run([loc, "-accepteula", "-c", path, "-y"],
                                   capture_output=True, text=True, timeout=20)
                return True, r.stdout
            except Exception as e:
                return False, str(e)
    return False, "handle.exe not found — download from Sysinternals"

def quarantine_file(path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest  = os.path.join(QUARANTINE_DIR, stamp + "_" + os.path.basename(path))
    try:
        shutil.move(path, dest)
        return True, dest
    except Exception as e:
        return False, str(e)

def force_delete(path):
    errors = []
    if HAVE_PSUTIL:
        for pid, _ in get_processes_using_path(path):
            kill_process(pid)
        time.sleep(0.4)
    close_handles_to_path(path)
    time.sleep(0.2)
    run_ps(f'takeown /f "{path}" /r /d y 2>$null')
    run_ps(f'icacls "{path}" /grant administrators:F /t 2>$null')
    try:
        shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
        return True, "Deleted"
    except Exception as e:
        errors.append(str(e))
    try:
        if HAVE_WIN32:
            win32api.MoveFileEx(path, None, win32con.MOVEFILE_DELAY_UNTIL_REBOOT)
            return True, "Scheduled for deletion on next reboot"
    except Exception as e:
        errors.append(str(e))
    try:
        cmd = ["cmd","/c","rd","/s","/q",path] if os.path.isdir(path) else ["cmd","/c","del","/f","/q",path]
        subprocess.run(cmd, capture_output=True, timeout=15)
        if not os.path.exists(path):
            return True, "Deleted via cmd"
    except Exception as e:
        errors.append(str(e))
    return False, " | ".join(errors)

def find_hidden_folders(roots):
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        try:
            for dirpath, dirnames, _ in os.walk(root):
                for d in list(dirnames):
                    full = os.path.join(dirpath, d)
                    try:
                        attrs = ctypes.windll.kernel32.GetFileAttributesW(full)
                        if attrs != -1 and (attrs & 0x2):
                            yield full
                    except Exception:
                        pass
        except PermissionError:
            pass

# ── Startup sources ───────────────────────────────────────────────────────────

def get_startup_folder_items():
    """Yield items found in Windows Startup folders."""
    for folder in STARTUP_FOLDERS:
        if not os.path.isdir(folder):
            continue
        try:
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                # Resolve .lnk shortcuts via PowerShell
                if fname.lower().endswith(".lnk"):
                    target = run_ps(
                        f'(New-Object -ComObject WScript.Shell).CreateShortcut("{fpath}").TargetPath',
                        timeout=8)
                    yield {
                        "source":   "Startup Folder",
                        "name":     fname,
                        "command":  target or fpath,
                        "exe_path": target or fpath,
                        "location": folder,
                    }
                else:
                    yield {
                        "source":   "Startup Folder",
                        "name":     fname,
                        "command":  fpath,
                        "exe_path": fpath,
                        "location": folder,
                    }
        except Exception:
            pass

def get_registry_autoruns():
    """Yield (source, name, command, exe_path) from all Run/RunOnce-style keys."""
    hive_names = {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}
    for hive, key_path in AUTORUN_REG_KEYS:
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    data_str = str(data)
                    exe = extract_exe_from_cmdline(data_str)
                    yield {
                        "source":   f"Registry ({hive_names.get(hive,'?')}\\...\\{key_path.split(chr(92))[-1]})",
                        "name":     name,
                        "command":  data_str,
                        "exe_path": exe,
                        "location": f"{hive_names.get(hive,'?')}\\{key_path}",
                    }
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

def get_appinit_dlls():
    """Check AppInit_DLLs — a classic malware injection point."""
    results = []
    for hive, path in [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"),
    ]:
        try:
            key  = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            val, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
            if val and str(val).strip():
                for dll in str(val).replace(",", " ").split():
                    results.append({
                        "source":   "AppInit_DLLs",
                        "name":     os.path.basename(dll),
                        "command":  dll,
                        "exe_path": dll,
                        "location": path,
                    })
            winreg.CloseKey(key)
        except Exception:
            pass
    return results

def get_ifeo_debuggers():
    """Image File Execution Options — malware hijacks legitimate exe names with a debugger entry."""
    results = []
    ifeo_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        root_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_path, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(root_key, i)
                try:
                    sub = winreg.OpenKey(root_key, subkey_name, 0, winreg.KEY_READ)
                    try:
                        dbg, _ = winreg.QueryValueEx(sub, "Debugger")
                        if dbg:
                            results.append({
                                "source":   "IFEO Debugger Hijack",
                                "name":     subkey_name,
                                "command":  str(dbg),
                                "exe_path": extract_exe_from_cmdline(str(dbg)),
                                "location": f"HKLM\\{ifeo_path}\\{subkey_name}",
                            })
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(sub)
                except Exception:
                    pass
                i += 1
            except OSError:
                break
        winreg.CloseKey(root_key)
    except Exception:
        pass
    return results

def get_wmi_subscriptions():
    """WMI event subscriptions — sophisticated malware persistence, invisible to most tools."""
    results = []
    ps = (
        "Get-WMIObject -Namespace root\\subscription -Class __EventFilter 2>$null | "
        "ForEach-Object { [PSCustomObject]@{Name=$_.Name; Query=$_.Query} } | ConvertTo-Json -Compress"
    )
    raw = run_ps(ps, timeout=20)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        for item in (data or []):
            results.append({
                "source":   "WMI Subscription",
                "name":     item.get("Name", "?"),
                "command":  item.get("Query", ""),
                "exe_path": "",
                "location": "root\\subscription",
            })
    except Exception:
        pass

    # Also check consumers (what runs when the event fires)
    ps2 = (
        "Get-WMIObject -Namespace root\\subscription -Class CommandLineEventConsumer 2>$null | "
        "ForEach-Object { [PSCustomObject]@{Name=$_.Name; Cmd=$_.CommandLineTemplate} } | ConvertTo-Json -Compress"
    )
    raw2 = run_ps(ps2, timeout=20)
    try:
        data2 = json.loads(raw2)
        if isinstance(data2, dict):
            data2 = [data2]
        for item in (data2 or []):
            cmd = item.get("Cmd", "")
            results.append({
                "source":   "WMI Consumer",
                "name":     item.get("Name", "?"),
                "command":  cmd,
                "exe_path": extract_exe_from_cmdline(cmd),
                "location": "root\\subscription::CommandLineEventConsumer",
            })
    except Exception:
        pass
    return results

def get_gp_logon_scripts():
    """Group Policy logon/logoff scripts — used by malware with domain access."""
    results = []
    gp_paths = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup"),
    ]
    for hive, path in gp_paths:
        label = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        try:
            root = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    gpo_name = winreg.EnumKey(root, i)
                    gpo_key  = winreg.OpenKey(root, gpo_name, 0, winreg.KEY_READ)
                    j = 0
                    while True:
                        try:
                            script_idx = winreg.EnumKey(gpo_key, j)
                            sk = winreg.OpenKey(gpo_key, script_idx, 0, winreg.KEY_READ)
                            try:
                                script, _ = winreg.QueryValueEx(sk, "Script")
                                results.append({
                                    "source":   "GP Logon/Startup Script",
                                    "name":     os.path.basename(str(script)),
                                    "command":  str(script),
                                    "exe_path": str(script),
                                    "location": f"{label}\\{path}\\{gpo_name}",
                                })
                            except Exception:
                                pass
                            winreg.CloseKey(sk)
                            j += 1
                        except OSError:
                            break
                    winreg.CloseKey(gpo_key)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(root)
        except Exception:
            pass
    return results

def get_lsa_packages():
    """LSA authentication packages — malware sometimes injects here for persistence."""
    results = []
    lsa_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
    for val_name in ("Authentication Packages", "Security Packages", "Notification Packages"):
        try:
            key  = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, lsa_path, 0, winreg.KEY_READ)
            data, _ = winreg.QueryValueEx(key, val_name)
            winreg.CloseKey(key)
            packages = data if isinstance(data, list) else [data]
            for pkg in packages:
                pkg = str(pkg).strip()
                if not pkg:
                    continue
                # Known safe LSA packages
                if pkg.lower() in ("msv1_0", "kerberos", "wdigest", "tspkg",
                                   "pku2u", "schannel", "credssp", "", '""'):
                    continue
                results.append({
                    "source":   f"LSA {val_name}",
                    "name":     pkg,
                    "command":  pkg,
                    "exe_path": "",
                    "location": f"HKLM\\{lsa_path}",
                })
        except Exception:
            pass
    return results

def get_scheduled_boot_tasks():
    """Scheduled tasks that run at boot or logon."""
    ps = (
        "Get-ScheduledTask | Where-Object { "
        "  $_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Boot|Logon' } "
        "} | ForEach-Object {"
        "  $a = $_.Actions | Select -First 1;"
        "  [PSCustomObject]@{"
        "    Name=$_.TaskName; Path=$_.TaskPath;"
        "    Execute=if($a){$a.Execute}else{''};"
        "    Args=if($a){$a.Arguments}else{''};"
        "    Author=$_.Author"
        "  }"
        "} | ConvertTo-Json -Compress"
    )
    raw = run_ps(ps, timeout=30)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        results = []
        for t in (data or []):
            exe = t.get("Execute") or ""
            results.append({
                "source":   "Scheduled Task (Boot/Logon)",
                "name":     t.get("Name", "?"),
                "command":  f"{exe} {t.get('Args','')}".strip(),
                "exe_path": exe,
                "location": t.get("Path", ""),
            })
        return results
    except Exception:
        return []

def get_all_startup_items():
    """Aggregate every startup source into a unified list of dicts."""
    items = []
    items.extend(get_startup_folder_items())
    items.extend(get_registry_autoruns())
    items.extend(get_appinit_dlls())
    items.extend(get_ifeo_debuggers())
    items.extend(get_wmi_subscriptions())
    items.extend(get_gp_logon_scripts())
    items.extend(get_lsa_packages())
    items.extend(get_scheduled_boot_tasks())
    return items

def get_boot_impact_map():
    """
    Return dict of {process_name_lower: delay_ms} using Windows Performance event log.
    Event 101 in Microsoft-Windows-Diagnostics-Performance/Operational tracks per-app boot delays.
    Falls back to Win32_StartupCommand impact hints.
    """
    impact = {}
    ps = (
        "$log = 'Microsoft-Windows-Diagnostics-Performance/Operational';"
        "Get-WinEvent -LogName $log -MaxEvents 200 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Id -eq 101 } | ForEach-Object {"
        "  $x = [xml]$_.ToXml();"
        "  $app = $x.Event.EventData.Data | Where-Object {$_.Name -eq 'FileName'} | Select -Expand '#text';"
        "  $ms  = $x.Event.EventData.Data | Where-Object {$_.Name -eq 'Duration'} | Select -Expand '#text';"
        "  if($app -and $ms){ \"$app|$ms\" }"
        "}"
    )
    raw = run_ps(ps, timeout=25)
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) == 2:
            try:
                name = os.path.basename(parts[0]).lower()
                ms   = int(parts[1])
                if name not in impact or impact[name] < ms:
                    impact[name] = ms
            except Exception:
                pass
    return impact

# ── Other scanners ────────────────────────────────────────────────────────────

def get_scheduled_tasks_all():
    ps = (
        "Get-ScheduledTask | ForEach-Object {"
        "  $a = $_.Actions | Select -First 1;"
        "  [PSCustomObject]@{"
        "    Name=$_.TaskName; Path=$_.TaskPath;"
        "    Execute=if($a){$a.Execute}else{''};"
        "    Args=if($a){$a.Arguments}else{''};"
        "    State=$_.State; Author=$_.Author"
        "  }"
        "} | ConvertTo-Json -Compress"
    )
    raw = run_ps(ps, timeout=30)
    try:
        data = json.loads(raw)
        return [data] if isinstance(data, dict) else (data or [])
    except Exception:
        return []

def get_windows_services():
    ps = (
        "Get-WmiObject Win32_Service | ForEach-Object {"
        "  [PSCustomObject]@{"
        "    Name=$_.Name; DisplayName=$_.DisplayName;"
        "    Path=$_.PathName; State=$_.State; StartMode=$_.StartMode"
        "  }"
        "} | ConvertTo-Json -Compress"
    )
    raw = run_ps(ps, timeout=30)
    try:
        data = json.loads(raw)
        return [data] if isinstance(data, dict) else (data or [])
    except Exception:
        return []

def virustotal_check(api_key, md5_hash):
    if not HAVE_REQUESTS:
        return None, None, "Install the 'requests' package"
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{md5_hash}",
                            headers={"x-apikey": api_key}, timeout=15)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            pos   = stats.get("malicious", 0) + stats.get("suspicious", 0)
            return pos, sum(stats.values()), f"https://www.virustotal.com/gui/file/{md5_hash}"
        elif resp.status_code == 404:
            return 0, 0, "Not found in VirusTotal"
        else:
            return None, None, f"API error {resp.status_code}"
    except Exception as e:
        return None, None, str(e)

# ── Silent install detector ───────────────────────────────────────────────────

# Registry uninstall hive paths
_UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
]

# Known Start Menu / shortcut search roots
_SHORTCUT_ROOTS = [
    os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu"),
    r"C:\ProgramData\Microsoft\Windows\Start Menu",
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
    r"C:\Users\Public\Desktop",
]

# Publishers considered safe — used to suppress false-positives from Windows components
_SAFE_UNINSTALL_PUBS = {
    "microsoft", "google", "adobe", "intel", "nvidia", "amd", "qualcomm",
    "realtek", "oracle", "mozilla", "valve", "zoom", "slack", "discord",
    "dropbox", "spotify", "amazon", "apple", "logitech", "corsair",
}


def _parse_uninstall_date(raw):
    """Convert YYYYMMDD registry date string → datetime, or None."""
    raw = (raw or "").strip()
    if len(raw) == 8 and raw.isdigit():
        try:
            return datetime(int(raw[:4]), int(raw[4:6]), int(raw[6:8]))
        except Exception:
            pass
    return None


def _shortcut_exists_for(display_name: str, install_location: str) -> bool:
    """
    Return True if a Start-Menu / Desktop shortcut probably exists for this program.
    Checks for any .lnk whose stem fuzzy-matches the display name or install location.
    """
    stem = display_name.lower().split()[0] if display_name else ""
    loc_lower = (install_location or "").lower()
    try:
        for root_dir in _SHORTCUT_ROOTS:
            if not os.path.isdir(root_dir):
                continue
            for dirpath, _, files in os.walk(root_dir):
                for f in files:
                    if not f.lower().endswith(".lnk"):
                        continue
                    f_lower = f.lower()
                    if stem and stem in f_lower:
                        return True
                    if loc_lower and len(loc_lower) > 4:
                        # Last path component of install dir inside shortcut name
                        tail = os.path.basename(loc_lower)
                        if tail and tail in f_lower:
                            return True
    except Exception:
        pass
    return False


def _is_system_component(vals: dict) -> bool:
    """Skip Windows Update entries, drivers, and system components."""
    if vals.get("SystemComponent", 0) == 1:
        return True
    if vals.get("ParentKeyName", ""):
        return True          # update rollup child
    name = (vals.get("DisplayName") or "").lower()
    if any(kw in name for kw in ("update for windows", "security update", "hotfix",
                                  "service pack", "language pack", "kb", "vc++ redist",
                                  "visual c++", "microsoft .net", "directx")):
        return True
    return False


def get_silent_installs(days_lookback: int = 30):
    """
    Yield dicts for programs that look like silent / stealth installs.

    Flags raised for each entry (combined → final severity):
      • UNSIGNED      – install exe not digitally signed
      • NO_SHORTCUT   – no Start Menu or Desktop shortcut found
      • NO_PUBLISHER  – publisher field blank
      • RECENT        – installed within `days_lookback` days
      • SILENT_FLAG   – has a QuietUninstallString (designed to uninstall silently)
      • HIDDEN        – SystemComponent=1 (hidden from Add/Remove Programs)
      • NO_URL        – no support / help URL at all
      • SMALL_SIZE    – InstallSize < 500 KB (unusual for a real app)
    """
    now = datetime.now()
    hive_names = {winreg.HKEY_LOCAL_MACHINE: "HKLM", winreg.HKEY_CURRENT_USER: "HKCU"}

    for hive, key_path in _UNINSTALL_KEYS:
        try:
            root = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        except Exception:
            continue

        i = 0
        while True:
            try:
                sub_name = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1

            try:
                sub = winreg.OpenKey(root, sub_name, 0, winreg.KEY_READ)
            except Exception:
                continue

            # Read all values into a dict
            vals = {}
            j = 0
            while True:
                try:
                    vname, vdata, _ = winreg.EnumValue(sub, j)
                    vals[vname] = vdata
                    j += 1
                except OSError:
                    break
            winreg.CloseKey(sub)

            display_name = (vals.get("DisplayName") or "").strip()
            if not display_name:
                continue
            if _is_system_component(vals):
                continue

            publisher   = (vals.get("Publisher") or "").strip()
            pub_lower   = publisher.lower()
            install_loc = (vals.get("InstallLocation") or "").strip()
            uninstall   = (vals.get("UninstallString") or "").strip()
            quiet_un    = (vals.get("QuietUninstallString") or "").strip()
            install_exe = extract_exe_from_cmdline(uninstall)
            install_date_raw = vals.get("InstallDate") or ""
            install_dt  = _parse_uninstall_date(install_date_raw)
            size_kb     = vals.get("EstimatedSize") or 0   # in KB
            help_url    = (vals.get("HelpLink") or vals.get("URLInfoAbout") or "").strip()
            hidden      = vals.get("SystemComponent", 0) == 1

            # Skip if publisher matches known-safe list
            if any(safe in pub_lower for safe in _SAFE_UNINSTALL_PUBS):
                continue

            # Signature check on uninstall exe
            sig = "NotFound"
            if install_exe and os.path.exists(install_exe):
                sig = get_signature_status(install_exe)
            elif install_loc:
                # Try finding any exe in the install folder
                try:
                    for f in os.listdir(install_loc):
                        if f.lower().endswith(".exe"):
                            candidate = os.path.join(install_loc, f)
                            sig = get_signature_status(candidate)
                            if sig == "Valid":
                                install_exe = candidate
                                break
                except Exception:
                    pass

            # Build flag list
            flags = []
            if sig not in ("Valid",):
                flags.append("UNSIGNED")
            if not publisher:
                flags.append("NO_PUBLISHER")
            if install_dt and (now - install_dt).days <= days_lookback:
                flags.append(f"RECENT({install_dt.strftime('%Y-%m-%d')})")
            if quiet_un:
                flags.append("SILENT_FLAG")
            if hidden:
                flags.append("HIDDEN")
            if not help_url:
                flags.append("NO_URL")
            if size_kb and size_kb < 500:
                flags.append("SMALL_SIZE")

            # Shortcut check (only if we have something to search by)
            has_shortcut = _shortcut_exists_for(display_name, install_loc)
            if not has_shortcut:
                flags.append("NO_SHORTCUT")

            if not flags:
                continue  # looks totally normal

            # Severity scoring
            score = 0
            score += 3 if "UNSIGNED"    in flags else 0
            score += 2 if "NO_SHORTCUT" in flags else 0
            score += 2 if "SILENT_FLAG" in flags else 0
            score += 2 if "HIDDEN"      in flags else 0
            score += 1 if "NO_PUBLISHER"in flags else 0
            score += 1 if "NO_URL"      in flags else 0
            score += 1 if "SMALL_SIZE"  in flags else 0
            score += 1 if any("RECENT" in f for f in flags) else 0

            if score >= 7:
                severity = "CRITICAL"
            elif score >= 5:
                severity = "HIGH"
            elif score >= 3:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            yield {
                "severity":     severity,
                "name":         display_name,
                "publisher":    publisher or "—",
                "install_date": install_date_raw or "Unknown",
                "install_loc":  install_loc or "—",
                "install_exe":  install_exe or "—",
                "signature":    sig,
                "flags":        ", ".join(flags),
                "score":        score,
                "hive":         hive_names.get(hive, "?"),
                "sub_key":      sub_name,
                "uninstall":    uninstall,
                "has_shortcut": has_shortcut,
                "size_kb":      size_kb,
            }

        winreg.CloseKey(root)


# ── Browser extensions ────────────────────────────────────────────────────────

def _ext_severity_from_perms(permissions):
    order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    worst_sev, worst_perm = "LOW", ""
    for p in permissions:
        p = str(p).strip()
        sev = DANGEROUS_PERMS.get(p)
        if not sev and (p.startswith("http") or p.startswith("*://") or p == "<all_urls>"):
            sev = "HIGH"
        if sev and order.index(sev) < order.index(worst_sev):
            worst_sev, worst_perm = sev, p
    return worst_sev, worst_perm

def _read_ext_manifest(ext_dir):
    mpath = os.path.join(ext_dir, "manifest.json")
    if not os.path.exists(mpath):
        try:
            for sub in os.listdir(ext_dir):
                c = os.path.join(ext_dir, sub, "manifest.json")
                if os.path.exists(c):
                    mpath = c
                    break
        except Exception:
            return None
    try:
        with open(mpath, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return None

def scan_browser_extensions():
    localappdata = os.environ.get("LOCALAPPDATA", "")
    appdata      = os.environ.get("APPDATA", "")
    chromium_browsers = [
        ("Chrome",  os.path.join(localappdata, "Google", "Chrome", "User Data")),
        ("Edge",    os.path.join(localappdata, "Microsoft", "Edge", "User Data")),
        ("Brave",   os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data")),
        ("Vivaldi", os.path.join(localappdata, "Vivaldi", "User Data")),
    ]
    for browser, user_data in chromium_browsers:
        if not os.path.isdir(user_data):
            continue
        try:
            profiles = [d for d in os.listdir(user_data)
                        if d == "Default" or d.startswith("Profile")]
        except Exception:
            continue
        for profile in profiles:
            ext_root = os.path.join(user_data, profile, "Extensions")
            if not os.path.isdir(ext_root):
                continue
            try:
                for ext_id in os.listdir(ext_root):
                    ext_dir  = os.path.join(ext_root, ext_id)
                    manifest = _read_ext_manifest(ext_dir)
                    if not manifest:
                        continue
                    name  = manifest.get("name", ext_id)
                    if name.startswith("__MSG_"):
                        name = ext_id
                    perms = ([str(p) for p in (manifest.get("permissions") or [])] +
                             [str(p) for p in (manifest.get("host_permissions") or [])])
                    sev, worst = _ext_severity_from_perms(perms)
                    yield {"browser": browser, "profile": profile, "ext_id": ext_id,
                           "name": name, "version": manifest.get("version","?"),
                           "severity": sev, "worst_perm": worst,
                           "perms": ", ".join(perms[:12]),
                           "date": get_install_date(ext_dir), "path": ext_dir}
            except Exception:
                pass
    ff_root = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff_root):
        try:
            for profile in os.listdir(ff_root):
                ext_root = os.path.join(ff_root, profile, "extensions")
                if not os.path.isdir(ext_root):
                    continue
                for item in os.listdir(ext_root):
                    item_path = os.path.join(ext_root, item)
                    ext_id    = item.replace(".xpi", "")
                    manifest  = _read_ext_manifest(item_path) if os.path.isdir(item_path) else None
                    perms = [str(p) for p in (manifest.get("permissions") or [])] if manifest else []
                    sev, worst = _ext_severity_from_perms(perms)
                    yield {"browser": "Firefox", "profile": profile, "ext_id": ext_id,
                           "name": manifest.get("name", ext_id) if manifest else ext_id,
                           "version": manifest.get("version","?") if manifest else "?",
                           "severity": sev, "worst_perm": worst,
                           "perms": ", ".join(perms[:12]),
                           "date": get_install_date(item_path), "path": item_path}
        except Exception:
            pass

# ── Widget helpers ────────────────────────────────────────────────────────────

def _btn(parent, text, command, bg, fg, **kw):
    return tk.Button(parent, text=text, command=command,
                     bg=bg, fg=fg, activebackground=bg, activeforeground=fg,
                     relief=tk.FLAT, padx=10, pady=4,
                     font=("Segoe UI", 9, "bold"), cursor="hand2", **kw)

def _tree(parent, cols, widths, heads):
    frame = tk.Frame(parent, bg=BG)
    frame.pack(fill=tk.BOTH, expand=True, padx=8)
    tv = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
    for c in cols:
        tv.heading(c, text=heads.get(c, c))
        tv.column(c, width=widths.get(c, 100), minwidth=40)
    sb_y = ttk.Scrollbar(frame, orient=tk.VERTICAL,   command=tv.yview)
    sb_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tv.xview)
    tv.configure(yscroll=sb_y.set, xscroll=sb_x.set)
    sb_y.pack(side=tk.RIGHT,  fill=tk.Y)
    sb_x.pack(side=tk.BOTTOM, fill=tk.X)
    tv.pack(fill=tk.BOTH, expand=True)
    return tv, frame

def _apply_sev_tags(tv):
    for sev, col in SEVERITY_COLORS.items():
        tv.tag_configure(sev, foreground=col)

# ══════════════════════════════════════════════════════════════════════════════
# App
# ══════════════════════════════════════════════════════════════════════════════

class ScannerApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("🛡️  Silent Install & Malware Scanner  v4.0")
        self.geometry("1200x800")
        self.configure(bg=BG)
        self.resizable(True, True)

        self._stop_event    = threading.Event()
        self._results       = []
        self._vt_key        = tk.StringVar()
        self._watch_running = False
        self._watch_known   = {}   # path → mtime
        self._watch_thread  = None
        self._abuseipdb_key = tk.StringVar()
        self._ip_rep_cache  = {}   # ip → result dict

        load_exclusions()
        self._build_ui()
        self._check_admin()

    def _check_admin(self):
        if not is_admin():
            self.admin_label.config(
                text="⚠  Not running as Administrator — right-click the .bat → 'Run as administrator'",
                fg="#ff8800")

    # ── UI scaffold ───────────────────────────────────────────────────────────

    def _build_ui(self):
        top = tk.Frame(self, bg=BG, pady=6)
        top.pack(fill=tk.X, padx=10)
        tk.Label(top, text="🛡️  Silent Install & Malware Scanner  v4.0",
                 bg=BG, fg="#e94560", font=("Segoe UI", 15, "bold")).pack(side=tk.LEFT)
        self.admin_label = tk.Label(top, text="✔  Running as Administrator",
                                    bg=BG, fg="#44cc44", font=("Segoe UI", 9))
        self.admin_label.pack(side=tk.RIGHT, padx=8)

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        tab_defs = [
            ("scan",       "  🔍 Exe Scanner  "),
            ("startup",    "  🚀 All Startup  "),
            ("silent",     "  🕵️ Silent Installs  "),
            ("tasks",      "  🗓️ Tasks  "),
            ("services",   "  ⚙️ Services  "),
            ("extensions", "  🧩 Browser Ext  "),
            ("hidden",     "  📂 Hidden Folders  "),
            ("network",    "  🌐 Network  "),
            ("processes",  "  💻 Processes  "),
            ("quarantine", "  🧪 Quarantine  "),
            ("exclusions", "  🚫 Exclusions  "),
            ("watcher",   "  🔴 Live Watcher  "),
            ("report",    "  📊 Report  "),
        ]
        self._tabs = {}
        for key, label in tab_defs:
            f = tk.Frame(nb, bg=BG)
            nb.add(f, text=label)
            self._tabs[key] = f

        self._build_scan_tab()
        self._build_startup_tab()
        self._build_silent_tab()
        self._build_tasks_tab()
        self._build_services_tab()
        self._build_extensions_tab()
        self._build_hidden_tab()
        self._build_network_tab()
        self._build_proc_tab()
        self._build_quarantine_tab()
        self._build_exclusions_tab()
        self._build_watcher_tab()
        self._build_report_tab()

        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status_var, bg="#0a0a1a", fg="#aaaaaa",
                 anchor=tk.W, font=("Segoe UI", 9)).pack(fill=tk.X, side=tk.BOTTOM)

    # ══════════════════════════════════════════════════════════════════════════
    # EXE SCANNER
    # ══════════════════════════════════════════════════════════════════════════

    def _build_scan_tab(self):
        p = self._tabs["scan"]
        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)
        tk.Label(ctrl, text="Location:", bg=BG, fg=FG).pack(side=tk.LEFT)
        self.scan_path_var = tk.StringVar(value="ALL (Program Files + AppData + Temp)")
        tk.Entry(ctrl, textvariable=self.scan_path_var, width=44,
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 10), relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        _btn(ctrl, "Browse", lambda: self._browse(self.scan_path_var), BTN, FG).pack(side=tk.LEFT)
        self.scan_btn = _btn(ctrl, "▶ Scan", self._start_scan, GREEN, FG)
        self.scan_btn.pack(side=tk.LEFT, padx=8)
        self.stop_btn = _btn(ctrl, "■ Stop", self._stop_scan, RED, FG)
        self.stop_btn.pack(side=tk.LEFT)
        self.stop_btn.config(state=tk.DISABLED)

        vt = tk.Frame(p, bg=BG)
        vt.pack(fill=tk.X, padx=8, pady=(0, 2))
        tk.Label(vt, text="VirusTotal API key (optional):", bg=BG, fg="#888888",
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)
        tk.Entry(vt, textvariable=self._vt_key, width=42, show="*",
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 9), relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        _btn(vt, "🦠 VT Check", self._vt_check_selected, PURPLE, FG).pack(side=tk.LEFT)

        filt = tk.Frame(p, bg=BG)
        filt.pack(fill=tk.X, padx=8, pady=(0, 4))
        tk.Label(filt, text="Show:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="ALL")
        for lbl in ("ALL","CRITICAL","HIGH","MEDIUM","LOW"):
            tk.Radiobutton(filt, text=lbl, variable=self.filter_var, value=lbl,
                           bg=BG, fg=SEVERITY_COLORS.get(lbl, FG),
                           selectcolor=ACCENT, activebackground=BG,
                           command=self._apply_filter,
                           font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=4)

        self.progress = ttk.Progressbar(p, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=8, pady=2)

        cols = ("severity","name","path","publisher","signature","date")
        self.tree, _ = _tree(p, cols,
            {"severity":88,"name":152,"path":305,"publisher":132,"signature":98,"date":82},
            {"severity":"Severity","name":"Name","path":"Path",
             "publisher":"Publisher","signature":"Signature","date":"Date"})
        _apply_sev_tags(self.tree)

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🔪 Kill",         self._kill_selected,        RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🧪 Quarantine",   self._quarantine_selected,  ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🗑️ Delete",       self._delete_selected,      RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Exclude",      self._exclude_scan,         TEAL,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📋 Copy Path",    self._copy_scan_path,       BTN,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Explorer",     self._open_scan_explorer,   BTN,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "💾 Export CSV",   self._export_csv,           BTN,    FG).pack(side=tk.RIGHT, padx=3)

        self._scan_rows = {}

    def _start_scan(self):
        self._stop_event.clear()
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.tree.delete(*self.tree.get_children())
        self._scan_rows.clear()
        self._results.clear()
        self.progress.start(12)
        raw   = self.scan_path_var.get()
        roots = SCAN_ROOTS if raw.startswith("ALL") else ([raw] if os.path.isdir(raw) else SCAN_ROOTS)
        threading.Thread(target=self._scan_worker,
                         args=([r for r in roots if r and os.path.isdir(r)],), daemon=True).start()

    def _stop_scan(self):
        self._stop_event.set()

    def _scan_worker(self, roots):
        seen, total = set(), 0
        for root in roots:
            for fpath in find_exe_files(root, stop_event=self._stop_event):
                if self._stop_event.is_set():
                    break
                if fpath in seen:
                    continue
                seen.add(fpath)
                total += 1
                self._status(f"Scanning… {total} — {fpath[-65:]}")
                try:
                    sig  = get_signature_status(fpath)
                    pub  = get_file_publisher(fpath)
                    sev, reason = assign_severity(fpath, sig, pub)
                    excl, er    = is_excluded(filepath=fpath, publisher=pub or "")
                    if excl:
                        sev, reason = "EXCLUDED", er
                    date  = get_install_date(fpath)
                    entry = {"severity": sev, "name": os.path.basename(fpath),
                             "path": fpath, "publisher": pub or "—",
                             "signature": sig, "date": date, "reason": reason}
                    self._results.append(entry)
                    self.after(0, self._add_scan_row, entry)
                except Exception:
                    pass
        self.after(0, self._scan_done, total)

    def _scan_done(self, total):
        self.progress.stop()
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self._status(f"Scan complete — {total} checked, {len(self._results)} flagged.")

    def _add_scan_row(self, entry):
        fv = self.filter_var.get()
        if entry["severity"] == "CLEAN":
            return
        if fv != "ALL" and entry["severity"] != fv:
            return
        iid = self.tree.insert("", tk.END,
            values=(entry["severity"],entry["name"],entry["path"],
                    entry["publisher"],entry["signature"],entry["date"]),
            tags=(entry["severity"],))
        self._scan_rows[iid] = entry

    def _apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        self._scan_rows.clear()
        for entry in self._results:
            self._add_scan_row(entry)

    def _selected_scan_entries(self):
        return [self._scan_rows[i] for i in self.tree.selection() if i in self._scan_rows]

    def _kill_selected(self):
        for e in self._selected_scan_entries():
            procs = get_processes_using_path(e["path"])
            if not procs:
                messagebox.showinfo("No process", f"No processes for:\n{e['path']}")
                continue
            if messagebox.askyesno("Kill?", "\n".join(f"PID {p}: {n}" for p,n in procs)):
                for pid,_ in procs:
                    kill_process(pid)

    def _quarantine_selected(self):
        for e in self._selected_scan_entries():
            ok, r = quarantine_file(e["path"])
            self._status(f"{'✔' if ok else '✘'} {r}")
            if ok:
                self._remove_scan_entry(e)
        self._refresh_quarantine()

    def _delete_selected(self):
        entries = self._selected_scan_entries()
        if not entries:
            return
        if not messagebox.askyesno("⚠ Delete?",
                "\n".join(e["path"] for e in entries[:5]) + "\n\nPermanently delete? Cannot undo."):
            return
        for e in entries:
            ok, msg = force_delete(e["path"])
            self._status(f"{'✔' if ok else '✘'} {msg}")
            if ok:
                self._remove_scan_entry(e)

    def _exclude_scan(self):
        for e in self._selected_scan_entries():
            kind = self._ask_exclusion_kind()
            if not kind:
                return
            value = e["path"] if kind == "paths" else (e["publisher"] if kind == "publishers" else e["path"])
            note  = simpledialog.askstring("Note", "Note (optional):", parent=self) or ""
            if add_exclusion(kind, value, note):
                self._remove_scan_entry(e)
                self._status(f"Excluded: {value}")
        self._refresh_exclusions_tab()

    def _remove_scan_entry(self, entry):
        for iid, e in list(self._scan_rows.items()):
            if e is entry:
                self.tree.delete(iid)
                del self._scan_rows[iid]
                break

    def _copy_scan_path(self):
        entries = self._selected_scan_entries()
        if entries:
            self.clipboard_clear()
            self.clipboard_append("\n".join(e["path"] for e in entries))

    def _open_scan_explorer(self):
        for e in self._selected_scan_entries():
            subprocess.Popen(["explorer", "/select,", e["path"]])

    def _export_csv(self):
        fp = filedialog.asksaveasfilename(defaultextension=".csv",
                                          filetypes=[("CSV","*.csv")])
        if not fp:
            return
        with open(fp, "w", encoding="utf-8") as f:
            f.write("Severity,Name,Path,Publisher,Signature,Date,Reason\n")
            for e in self._results:
                def q(v): return '"' + str(v).replace('"','""') + '"'
                f.write(",".join(q(e[k]) for k in
                    ["severity","name","path","publisher","signature","date","reason"]) + "\n")
        self._status(f"Exported → {fp}")

    def _vt_check_selected(self):
        key = self._vt_key.get().strip()
        if not key:
            messagebox.showwarning("No API Key",
                "Get a free key at:\nhttps://www.virustotal.com/gui/join-us")
            return
        for e in self._selected_scan_entries():
            md5 = get_file_md5(e["path"])
            if not md5:
                continue
            pos, total, link = virustotal_check(key, md5)
            if pos is None:
                messagebox.showerror("VT Error", link)
            elif pos > 0:
                messagebox.showwarning("⚠ Detected!",
                    f"{e['name']}\nMD5: {md5}\n{pos}/{total} engines\n{link}")
            else:
                messagebox.showinfo("Clean",
                    f"{e['name']}\nMD5: {md5}\nClean ({total} engines)\n{link}")

    # ══════════════════════════════════════════════════════════════════════════
    # ALL STARTUP TAB  ← NEW comprehensive view
    # ══════════════════════════════════════════════════════════════════════════

    def _build_startup_tab(self):
        p = self._tabs["startup"]

        info = tk.Frame(p, bg=BG, pady=4)
        info.pack(fill=tk.X, padx=8)
        tk.Label(info,
                 text="Scans every persistence location: Registry Run keys • Startup Folders • "
                      "WMI Subscriptions • AppInit DLLs • IFEO Debugger Hijacks • "
                      "Group Policy Scripts • LSA Packages • Boot/Logon Scheduled Tasks",
                 bg=BG, fg="#888888", font=("Segoe UI", 8), wraplength=1100).pack(side=tk.LEFT)

        ctrl = tk.Frame(p, bg=BG, pady=4)
        ctrl.pack(fill=tk.X, padx=8)
        _btn(ctrl, "🚀 Scan All Startup Sources", self._scan_all_startup, GREEN, FG).pack(side=tk.LEFT, padx=4)
        tk.Label(ctrl, text="Boot Impact:", bg=BG, fg="#888888",
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(20,4))
        self.boot_impact_label = tk.Label(ctrl, text="(run scan first)",
                                          bg=BG, fg="#888888", font=("Segoe UI", 9))
        self.boot_impact_label.pack(side=tk.LEFT)

        # Filter row
        filt = tk.Frame(p, bg=BG)
        filt.pack(fill=tk.X, padx=8, pady=(0,3))
        tk.Label(filt, text="Show:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.startup_filter_var = tk.StringVar(value="ALL")
        for lbl in ("ALL","CRITICAL","HIGH","MEDIUM","LOW"):
            tk.Radiobutton(filt, text=lbl, variable=self.startup_filter_var, value=lbl,
                           bg=BG, fg=SEVERITY_COLORS.get(lbl, FG),
                           selectcolor=ACCENT, activebackground=BG,
                           command=self._apply_startup_filter,
                           font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=4)
        tk.Label(filt, text="  Source:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(16,4))
        self.startup_src_var = tk.StringVar(value="ALL")
        self.startup_src_combo = ttk.Combobox(filt, textvariable=self.startup_src_var,
                                              values=["ALL"], width=28, state="readonly")
        self.startup_src_combo.pack(side=tk.LEFT)
        self.startup_src_combo.bind("<<ComboboxSelected>>", lambda _: self._apply_startup_filter())

        cols = ("severity","source","name","command","exe_path","signature","boot_ms","location")
        self.startup_tree, _ = _tree(p, cols,
            {"severity":82,"source":175,"name":150,"command":230,"exe_path":185,
             "signature":90,"boot_ms":75,"location":230},
            {"severity":"Severity","source":"Source","name":"Name","command":"Command / Data",
             "exe_path":"Exe Path","signature":"Signed?","boot_ms":"Boot ms","location":"Location"})
        _apply_sev_tags(self.startup_tree)
        self.startup_tree.tag_configure("IMPACT_HIGH", foreground="#ff6600")

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🔪 Kill Process",     self._startup_kill,       RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🧪 Quarantine Exe",   self._startup_quarantine, ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🗑️ Delete / Disable", self._startup_delete,     RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion",    self._startup_exclude,    TEAL,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open in Explorer", self._startup_explorer,   BTN,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📋 Copy Command",     self._startup_copy,       BTN,    FG).pack(side=tk.LEFT, padx=3)

        self._startup_rows = {}   # iid -> item dict
        self._startup_data = []   # all items

    def _scan_all_startup(self):
        self.startup_tree.delete(*self.startup_tree.get_children())
        self._startup_rows.clear()
        self._startup_data.clear()

        def worker():
            self._status("Loading boot impact data…")
            impact_map = {}
            try:
                impact_map = get_boot_impact_map()
            except Exception:
                pass

            total_impact = sum(impact_map.values())
            if total_impact:
                self.after(0, lambda: self.boot_impact_label.config(
                    text=f"Total logged boot delay: {total_impact//1000} s across {len(impact_map)} apps",
                    fg="#ffcc00"))

            self._status("Scanning all startup persistence locations…")
            items = get_all_startup_items()
            sources_seen = {"ALL"}
            flagged = 0

            for item in items:
                exe = item.get("exe_path", "")
                sig = get_signature_status(exe) if exe and os.path.exists(exe) else "NotFound"
                pub = get_file_publisher(exe) if exe and os.path.exists(exe) else ""

                sev, reason = assign_severity(exe or item.get("command",""), sig, pub)

                # WMI subscriptions and IFEO hijacks are always suspicious
                if item["source"].startswith("WMI"):
                    sev = "HIGH" if sev in ("LOW","CLEAN","MEDIUM") else sev
                    reason = "WMI persistence subscription"
                if item["source"].startswith("IFEO"):
                    sev = "CRITICAL"
                    reason = "Image File Execution Options debugger hijack"
                if item["source"].startswith("AppInit"):
                    sev = "HIGH" if sev in ("LOW","CLEAN","MEDIUM") else sev
                    reason = "AppInit_DLL injection point"
                if item["source"].startswith("LSA"):
                    sev = "HIGH" if sev in ("LOW","CLEAN","MEDIUM") else sev
                    reason = "LSA package — unusual entry"

                excl, er = is_excluded(filepath=exe or "", publisher=pub or "")
                if excl:
                    sev = "EXCLUDED"

                if sev in ("CLEAN","EXCLUDED"):
                    continue

                # Boot impact
                exe_name  = os.path.basename(exe).lower() if exe else ""
                boot_ms   = impact_map.get(exe_name, 0)
                item["severity"]  = sev
                item["signature"] = sig
                item["boot_ms"]   = boot_ms
                item["reason"]    = reason

                sources_seen.add(item["source"])
                self._startup_data.append(item)
                flagged += 1
                self.after(0, self._add_startup_row, item)

            # Update source combobox
            src_list = sorted(sources_seen)
            self.after(0, lambda sl=src_list: self.startup_src_combo.config(values=sl))
            self._status(f"Startup scan complete — {flagged} suspicious items across {len(items)} total.")

        threading.Thread(target=worker, daemon=True).start()

    def _add_startup_row(self, item):
        fv  = self.startup_filter_var.get()
        sv  = self.startup_src_var.get()
        sev = item["severity"]
        if fv != "ALL" and sev != fv:
            return
        if sv != "ALL" and item["source"] != sv:
            return
        tags = [sev]
        if item.get("boot_ms", 0) > 3000:
            tags.append("IMPACT_HIGH")
        boot_str = f"{item['boot_ms']//1000}s" if item.get("boot_ms") else "—"
        iid = self.startup_tree.insert("", tk.END,
            values=(sev, item["source"], item["name"],
                    item["command"][:80], item["exe_path"] or "—",
                    item["signature"], boot_str, item["location"]),
            tags=tuple(tags))
        self._startup_rows[iid] = item

    def _apply_startup_filter(self):
        self.startup_tree.delete(*self.startup_tree.get_children())
        self._startup_rows.clear()
        for item in self._startup_data:
            self._add_startup_row(item)

    def _startup_kill(self):
        for iid in self.startup_tree.selection():
            item = self._startup_rows.get(iid)
            if not item:
                continue
            exe   = item.get("exe_path","")
            procs = get_processes_using_path(exe) if exe else []
            if not procs:
                messagebox.showinfo("No process", f"No running process found for:\n{exe}")
                continue
            if messagebox.askyesno("Kill?", "\n".join(f"PID {p}: {n}" for p,n in procs)):
                for pid,_ in procs:
                    kill_process(pid)
                self._status("Killed.")

    def _startup_quarantine(self):
        for iid in self.startup_tree.selection():
            item = self._startup_rows.get(iid)
            if not item:
                continue
            exe = item.get("exe_path","")
            if exe and os.path.exists(exe):
                ok, r = quarantine_file(exe)
                self._status(f"{'✔' if ok else '✘'} {r}")
                self._refresh_quarantine()

    def _startup_delete(self):
        for iid in self.startup_tree.selection():
            item = self._startup_rows.get(iid)
            if not item:
                continue
            source = item["source"]

            # Startup folder item — delete the file
            if "Startup Folder" in source:
                cmd  = item.get("command","")
                if os.path.exists(cmd) and messagebox.askyesno("Delete?", f"Delete:\n{cmd}"):
                    ok, msg = force_delete(cmd)
                    self._status(f"{'✔' if ok else '✘'} {msg}")
                    if ok:
                        self.startup_tree.delete(iid)
                        self._startup_rows.pop(iid, None)

            # WMI subscriptions — remove via PowerShell
            elif "WMI" in source:
                name = item["name"]
                if messagebox.askyesno("Delete WMI subscription?", f"Remove WMI entry:\n{name}"):
                    run_ps(f'Get-WMIObject -Namespace root\\subscription -Class __EventFilter -Filter "Name=\'{name}\'" | Remove-WMIObject')
                    run_ps(f'Get-WMIObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter "Name=\'{name}\'" | Remove-WMIObject')
                    self.startup_tree.delete(iid)
                    self._startup_rows.pop(iid, None)
                    self._status(f"Removed WMI entry: {name}")

            # Scheduled task
            elif "Scheduled Task" in source:
                name = item["name"]
                loc  = item.get("location","\\")
                if messagebox.askyesno("Delete task?", f"Delete task:\n{name}"):
                    run_ps(f'Unregister-ScheduledTask -TaskName "{name}" -TaskPath "{loc}" -Confirm:$false')
                    self.startup_tree.delete(iid)
                    self._startup_rows.pop(iid, None)
                    self._status(f"Deleted task: {name}")

            # Registry entry — guide user
            elif "Registry" in source or "LSA" in source or "AppInit" in source or "IFEO" in source:
                loc = item["location"]
                messagebox.showinfo("Registry entry",
                    f"To remove this entry:\n\n{loc}\nValue: {item['name']}\n\n"
                    "Open regedit.exe, navigate to the key above, and delete the value.\n\n"
                    "Or use the Registry/Startup tab for direct deletion.")

    def _startup_exclude(self):
        for iid in self.startup_tree.selection():
            item = self._startup_rows.get(iid)
            if not item:
                continue
            kind = self._ask_exclusion_kind()
            if not kind:
                return
            value = item.get("exe_path","") if kind == "paths" else item.get("name","")
            note  = simpledialog.askstring("Note", "Note:", parent=self) or ""
            if add_exclusion(kind, value, note):
                self.startup_tree.delete(iid)
                self._startup_rows.pop(iid, None)
                self._status(f"Excluded: {value}")
                self._refresh_exclusions_tab()

    def _startup_explorer(self):
        for iid in self.startup_tree.selection():
            item = self._startup_rows.get(iid)
            if not item:
                continue
            exe = item.get("exe_path","")
            if exe and os.path.exists(exe):
                subprocess.Popen(["explorer", "/select,", exe])
            else:
                loc = item.get("location","")
                if os.path.isdir(loc):
                    subprocess.Popen(["explorer", loc])

    def _startup_copy(self):
        items = [self._startup_rows[i] for i in self.startup_tree.selection() if i in self._startup_rows]
        if items:
            self.clipboard_clear()
            self.clipboard_append("\n".join(it.get("command","") for it in items))

    # ══════════════════════════════════════════════════════════════════════════
    # TASKS TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_tasks_tab(self):
        p = self._tabs["tasks"]
        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)
        _btn(ctrl, "🔍 Scan All Tasks", self._scan_tasks, BTN, FG).pack(side=tk.LEFT, padx=4)
        tk.Label(ctrl, text="All scheduled tasks — Microsoft tasks hidden unless suspicious",
                 bg=BG, fg="#888888", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8)

        cols = ("name","path","execute","args","state","author","severity")
        self.ttree, _ = _tree(p, cols,
            {"name":175,"path":130,"execute":230,"args":130,"state":68,"author":115,"severity":72},
            {"name":"Task Name","path":"Folder","execute":"Executable",
             "args":"Arguments","state":"State","author":"Author","severity":"Severity"})
        _apply_sev_tags(self.ttree)

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🚫 Disable",         self._disable_task,         ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🗑️ Delete",          self._delete_task,          RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🧪 Quarantine Exe",  self._quarantine_task_exe,  ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion",   self._exclude_task,         TEAL,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📋 Copy Exe Path",   self._copy_task_path,       BTN,    FG).pack(side=tk.LEFT, padx=3)

    def _scan_tasks(self):
        self.ttree.delete(*self.ttree.get_children())

        def worker():
            self._status("Scanning scheduled tasks…")
            tasks = get_scheduled_tasks_all()
            flagged = 0
            for t in tasks:
                exe  = t.get("Execute") or ""
                sig  = get_signature_status(exe) if exe and os.path.exists(exe) else "NotFound"
                pub  = get_file_publisher(exe) if exe and os.path.exists(exe) else ""
                sev, _ = assign_severity(exe or t.get("Name",""), sig, pub)
                if "microsoft" in (t.get("Author") or "").lower() and sig == "Valid":
                    continue
                excl, _ = is_excluded(filepath=exe, publisher=pub or "")
                if excl or sev == "CLEAN":
                    continue
                flagged += 1
                self.after(0, lambda t2=t,s=sev:
                    self.ttree.insert("",tk.END,
                        values=(t2.get("Name",""),t2.get("Path",""),t2.get("Execute",""),
                                t2.get("Args",""),t2.get("State",""),t2.get("Author",""),s),
                        tags=(s,)))
            self._status(f"Tasks done — {flagged} suspicious of {len(tasks)} total.")

        threading.Thread(target=worker, daemon=True).start()

    def _disable_task(self):
        for iid in self.ttree.selection():
            v = self.ttree.item(iid)["values"]
            run_ps(f'Disable-ScheduledTask -TaskName "{v[0]}" -TaskPath "{v[1]}"')
            self._status(f"Disabled: {v[0]}")

    def _delete_task(self):
        for iid in self.ttree.selection():
            v = self.ttree.item(iid)["values"]
            if messagebox.askyesno("Delete?", f"Delete task: {v[0]}"):
                run_ps(f'Unregister-ScheduledTask -TaskName "{v[0]}" -TaskPath "{v[1]}" -Confirm:$false')
                self.ttree.delete(iid)

    def _quarantine_task_exe(self):
        for iid in self.ttree.selection():
            exe = str(self.ttree.item(iid)["values"][2])
            if exe and os.path.exists(exe):
                ok, r = quarantine_file(exe)
                self._status(f"{'✔' if ok else '✘'} {r}")
                self._refresh_quarantine()

    def _exclude_task(self):
        for iid in self.ttree.selection():
            exe  = str(self.ttree.item(iid)["values"][2])
            note = simpledialog.askstring("Note","Note:",parent=self) or ""
            if add_exclusion("paths", exe, note):
                self.ttree.delete(iid)
                self._status(f"Excluded: {exe}")
                self._refresh_exclusions_tab()

    def _copy_task_path(self):
        for iid in self.ttree.selection():
            self.clipboard_clear()
            self.clipboard_append(str(self.ttree.item(iid)["values"][2]))

    # ══════════════════════════════════════════════════════════════════════════
    # SERVICES TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_services_tab(self):
        p = self._tabs["services"]
        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)
        _btn(ctrl, "🔍 Scan Services", self._scan_services, BTN, FG).pack(side=tk.LEFT, padx=4)

        cols = ("display","name","path","state","start","severity")
        self.srtree, _ = _tree(p, cols,
            {"display":195,"name":135,"path":330,"state":68,"start":75,"severity":78},
            {"display":"Display Name","name":"Service Name","path":"Executable",
             "state":"State","start":"Startup","severity":"Severity"})
        _apply_sev_tags(self.srtree)

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "⏹ Stop",           self._stop_service,    ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Disable",       self._disable_service, ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🗑️ Delete",        self._delete_service,  RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion", self._exclude_service, TEAL,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open Location", self._open_svc_loc,    BTN,    FG).pack(side=tk.LEFT, padx=3)

    def _scan_services(self):
        self.srtree.delete(*self.srtree.get_children())

        def worker():
            self._status("Scanning services…")
            svcs = get_windows_services()
            flagged = 0
            for svc in svcs:
                raw = svc.get("Path") or ""
                exe = extract_exe_from_cmdline(raw).strip('"')
                sig = get_signature_status(exe) if exe and os.path.exists(exe) else "NotFound"
                pub = get_file_publisher(exe) if exe and os.path.exists(exe) else ""
                sev, _ = assign_severity(exe or svc.get("Name",""), sig, pub)
                excl, _ = is_excluded(filepath=exe, publisher=pub or "")
                if excl or sev == "CLEAN":
                    continue
                flagged += 1
                self.after(0, lambda s2=svc,sv=sev:
                    self.srtree.insert("",tk.END,
                        values=(s2.get("DisplayName",""),s2.get("Name",""),s2.get("Path",""),
                                s2.get("State",""),s2.get("StartMode",""),sv),
                        tags=(sv,)))
            self._status(f"Services done — {flagged} flagged of {len(svcs)}.")

        threading.Thread(target=worker, daemon=True).start()

    def _stop_service(self):
        for iid in self.srtree.selection():
            name = str(self.srtree.item(iid)["values"][1])
            run_ps(f'Stop-Service -Name "{name}" -Force')
            self._status(f"Stopped: {name}")

    def _disable_service(self):
        for iid in self.srtree.selection():
            name = str(self.srtree.item(iid)["values"][1])
            run_ps(f'Set-Service -Name "{name}" -StartupType Disabled')
            self._status(f"Disabled: {name}")

    def _delete_service(self):
        for iid in self.srtree.selection():
            name = str(self.srtree.item(iid)["values"][1])
            if messagebox.askyesno("Delete service?", f"Delete '{name}'?"):
                run_ps(f'sc.exe delete "{name}"')
                self.srtree.delete(iid)

    def _exclude_service(self):
        for iid in self.srtree.selection():
            raw  = str(self.srtree.item(iid)["values"][2])
            exe  = extract_exe_from_cmdline(raw).strip('"')
            note = simpledialog.askstring("Note","Note:",parent=self) or ""
            if add_exclusion("paths", exe, note):
                self.srtree.delete(iid)
                self._refresh_exclusions_tab()

    def _open_svc_loc(self):
        for iid in self.srtree.selection():
            raw = str(self.srtree.item(iid)["values"][2])
            exe = extract_exe_from_cmdline(raw).strip('"')
            if exe and os.path.exists(exe):
                subprocess.Popen(["explorer", "/select,", exe])

    # ══════════════════════════════════════════════════════════════════════════
    # BROWSER EXTENSIONS TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_extensions_tab(self):
        p = self._tabs["extensions"]
        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)
        _btn(ctrl, "🔍 Scan Extensions", self._scan_extensions, BTN, FG).pack(side=tk.LEFT, padx=4)
        tk.Label(ctrl, text="Chrome · Edge · Brave · Vivaldi · Firefox",
                 bg=BG, fg="#888888", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8)

        filt = tk.Frame(p, bg=BG)
        filt.pack(fill=tk.X, padx=8, pady=(0,4))
        tk.Label(filt, text="Show:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.ext_filter_var = tk.StringVar(value="ALL")
        for lbl in ("ALL","CRITICAL","HIGH","MEDIUM","LOW"):
            tk.Radiobutton(filt, text=lbl, variable=self.ext_filter_var, value=lbl,
                           bg=BG, fg=SEVERITY_COLORS.get(lbl, FG),
                           selectcolor=ACCENT, activebackground=BG,
                           command=self._apply_ext_filter,
                           font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=4)

        cols = ("severity","browser","name","worst_perm","perms","version","date","ext_id")
        self.etree, _ = _tree(p, cols,
            {"severity":80,"browser":70,"name":180,"worst_perm":110,"perms":280,
             "version":60,"date":85,"ext_id":230},
            {"severity":"Severity","browser":"Browser","name":"Extension Name",
             "worst_perm":"Riskiest Perm","perms":"All Permissions",
             "version":"Ver","date":"Installed","ext_id":"Extension ID"})
        _apply_sev_tags(self.etree)

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🗑️ Remove Ext",     self._remove_extension,  RED,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion",  self._exclude_extension, TEAL,  FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open Folder",    self._open_ext_folder,   BTN,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📋 Copy ID",        self._copy_ext_id,       BTN,   FG).pack(side=tk.LEFT, padx=3)

        tk.Label(p,
                 text="⚠  Severity = permissions requested, not confirmed malicious. "
                      "Review HIGH/CRITICAL before removing.",
                 bg=BG, fg="#888888", font=("Segoe UI", 8)).pack(pady=3)

        self._ext_rows = {}
        self._ext_data = []

    def _scan_extensions(self):
        self.etree.delete(*self.etree.get_children())
        self._ext_rows.clear()
        self._ext_data.clear()

        def worker():
            self._status("Scanning browser extensions…")
            count = 0
            for ext in scan_browser_extensions():
                excl, _ = is_excluded(ext_id=ext["ext_id"])
                if excl:
                    continue
                self._ext_data.append(ext)
                count += 1
                self.after(0, self._add_ext_row, ext)
            self._status(f"Extension scan done — {count} found.")

        threading.Thread(target=worker, daemon=True).start()

    def _add_ext_row(self, ext):
        fv = self.ext_filter_var.get()
        if fv != "ALL" and ext["severity"] != fv:
            return
        iid = self.etree.insert("", tk.END,
            values=(ext["severity"],ext["browser"],ext["name"],ext["worst_perm"],
                    ext["perms"],ext["version"],ext["date"],ext["ext_id"]),
            tags=(ext["severity"],))
        self._ext_rows[iid] = ext

    def _apply_ext_filter(self):
        self.etree.delete(*self.etree.get_children())
        self._ext_rows.clear()
        for ext in self._ext_data:
            self._add_ext_row(ext)

    def _remove_extension(self):
        for iid in self.etree.selection():
            ext = self._ext_rows.get(iid)
            if not ext:
                continue
            if messagebox.askyesno("Remove?", f"Delete extension folder:\n{ext['path']}"):
                ok, msg = force_delete(ext["path"])
                self._status(f"{'✔' if ok else '✘'} {msg}")
                if ok:
                    self.etree.delete(iid)
                    self._ext_rows.pop(iid, None)

    def _exclude_extension(self):
        for iid in self.etree.selection():
            ext  = self._ext_rows.get(iid)
            if not ext:
                continue
            note = simpledialog.askstring("Note", f"Note for '{ext['name']}':", parent=self) or ""
            if add_exclusion("ext_ids", ext["ext_id"], note):
                self.etree.delete(iid)
                self._ext_rows.pop(iid, None)
                self._refresh_exclusions_tab()

    def _open_ext_folder(self):
        for iid in self.etree.selection():
            ext = self._ext_rows.get(iid)
            if ext and os.path.isdir(ext["path"]):
                subprocess.Popen(["explorer", ext["path"]])

    def _copy_ext_id(self):
        ids = [self._ext_rows[i]["ext_id"] for i in self.etree.selection() if i in self._ext_rows]
        if ids:
            self.clipboard_clear()
            self.clipboard_append("\n".join(ids))

    # ══════════════════════════════════════════════════════════════════════════
    # HIDDEN FOLDERS TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_hidden_tab(self):
        p = self._tabs["hidden"]
        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)
        self.hidden_path_var = tk.StringVar(value="; ".join(r for r in SCAN_ROOTS if r))
        tk.Label(ctrl, text="Root(s):", bg=BG, fg=FG).pack(side=tk.LEFT)
        tk.Entry(ctrl, textvariable=self.hidden_path_var, width=56,
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 10), relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        _btn(ctrl, "🔍 Find Hidden Folders", self._scan_hidden, BTN, FG).pack(side=tk.LEFT)

        cols = ("path","handles")
        self.htree, _ = _tree(p, cols,
            {"path":520,"handles":420},
            {"path":"Hidden Folder Path","handles":"Open Handles / Processes"})

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🔓 Close Handles",    self._close_handles_hidden, ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🗑️ Force Delete",     self._delete_hidden,        RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion",    self._exclude_hidden,       TEAL,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open in Explorer", self._open_hidden_explorer, BTN,    FG).pack(side=tk.LEFT, padx=3)
        tk.Label(p, text="Tip: Drop handle.exe (Sysinternals) next to this script to unlock files.",
                 bg=BG, fg="#888888", font=("Segoe UI", 8)).pack(pady=4)

    def _scan_hidden(self):
        self.htree.delete(*self.htree.get_children())
        roots = [r.strip() for r in self.hidden_path_var.get().split(";") if r.strip()]

        def worker():
            self._status("Scanning for hidden folders…")
            count = 0
            for hdir in find_hidden_folders(roots):
                excl, _ = is_excluded(filepath=hdir)
                if excl:
                    continue
                count += 1
                procs = get_processes_using_path(hdir)
                info  = (", ".join(f"{n}(PID {p})" for p,n in procs) if procs
                         else "No processes detected")
                self.after(0, lambda d=hdir, h=info:
                           self.htree.insert("", tk.END, values=(d, h)))
            self._status(f"Found {count} hidden folder(s).")

        threading.Thread(target=worker, daemon=True).start()

    def _close_handles_hidden(self):
        for iid in self.htree.selection():
            path  = str(self.htree.item(iid)["values"][0])
            procs = get_processes_using_path(path)
            for pid, name in procs:
                if messagebox.askyesno("Kill?", f"Kill {name} (PID {pid})?"):
                    kill_process(pid)
            ok, msg = close_handles_to_path(path)
            self._status(f"Handle close: {msg}")

    def _delete_hidden(self):
        for iid in self.htree.selection():
            path = str(self.htree.item(iid)["values"][0])
            if messagebox.askyesno("⚠ Delete?", f"Delete:\n{path}"):
                ok, msg = force_delete(path)
                self._status(f"{'✔' if ok else '✘'} {msg}")
                if ok:
                    self.htree.delete(iid)

    def _exclude_hidden(self):
        for iid in self.htree.selection():
            path = str(self.htree.item(iid)["values"][0])
            note = simpledialog.askstring("Note","Note:",parent=self) or ""
            if add_exclusion("paths", path, note):
                self.htree.delete(iid)
                self._refresh_exclusions_tab()

    def _open_hidden_explorer(self):
        for iid in self.htree.selection():
            subprocess.Popen(["explorer", str(self.htree.item(iid)["values"][0])])

    # ══════════════════════════════════════════════════════════════════════════
    # NETWORK TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_network_tab(self):
        p = self._tabs["network"]

        # Row 1 — API keys
        api_row = tk.Frame(p, bg=BG, pady=2)
        api_row.pack(fill=tk.X, padx=8)
        tk.Label(api_row, text="AbuseIPDB key:", bg=BG, fg=FG,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)
        tk.Entry(api_row, textvariable=self._abuseipdb_key, width=40, show="*",
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 9), relief=tk.FLAT).pack(side=tk.LEFT, padx=(4,20))
        tk.Label(api_row, text="(free at abuseipdb.com — leave blank to use VirusTotal only)",
                 bg=BG, fg="#777777", font=("Segoe UI", 8)).pack(side=tk.LEFT)

        # Row 2 — controls
        ctrl = tk.Frame(p, bg=BG, pady=4)
        ctrl.pack(fill=tk.X, padx=8)
        _btn(ctrl, "🔄 Refresh", self._refresh_network, BTN, FG).pack(side=tk.LEFT, padx=4)
        self.net_filter_var = tk.StringVar()
        tk.Label(ctrl, text="Filter:", bg=BG, fg=FG).pack(side=tk.LEFT, padx=(20,4))
        tk.Entry(ctrl, textvariable=self.net_filter_var, width=22,
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 10), relief=tk.FLAT).pack(side=tk.LEFT)

        cols = ("pid","process","proto","local","remote","status","rep","exe")
        self.ntree, _ = _tree(p, cols,
            {"pid":55,"process":130,"proto":50,"local":150,"remote":165,"status":80,"rep":110,"exe":250},
            {"pid":"PID","process":"Process","proto":"Proto","local":"Local",
             "remote":"Remote","status":"Status","rep":"IP Reputation","exe":"Executable"})
        self.ntree.tag_configure("suspicious",  foreground="#ff8800")
        self.ntree.tag_configure("rep_bad",     foreground="#ff3333", font=("Segoe UI",9,"bold"))
        self.ntree.tag_configure("rep_high",    foreground="#ff8800", font=("Segoe UI",9,"bold"))
        self.ntree.tag_configure("rep_clean",   foreground="#44cc44")
        self.ntree.tag_configure("rep_c2",      foreground="#ff3333", font=("Segoe UI",9,"bold"))

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🛡️ Check IP Reputation", self._check_ip_reputation, ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🛡️ Check All IPs",       self._check_all_ip_rep,    ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🔪 Kill Process",         self._kill_net_proc,       RED,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🌐 Lookup DNS",           self._lookup_ip,           BTN,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open Exe Loc",         self._open_net_exe,        BTN,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Exclude Exe",          self._exclude_net,         TEAL,  FG).pack(side=tk.LEFT, padx=3)

        if HAVE_PSUTIL:
            self._refresh_network()

    def _refresh_network(self):
        if not HAVE_PSUTIL:
            return
        self.ntree.delete(*self.ntree.get_children())

        def worker():
            filt = self.net_filter_var.get().lower()
            pid_cache = {}
            for conn in psutil.net_connections(kind="inet"):
                try:
                    pid = conn.pid or 0
                    if pid not in pid_cache:
                        try:
                            proc = psutil.Process(pid)
                            pid_cache[pid] = (proc.name(), proc.exe())
                        except Exception:
                            pid_cache[pid] = ("?", "")
                    pname, exe = pid_cache[pid]
                    laddr  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr  = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    proto  = "TCP" if conn.type == 1 else "UDP"
                    status = conn.status or "—"
                    excl, _ = is_excluded(filepath=exe)
                    if excl:
                        continue
                    rep_label = self._ip_rep_cache.get(raddr.split(":")[0], {}).get("label","") if raddr else ""
                    row = (pid, pname, proto, laddr, raddr, status, rep_label, exe)
                    if filt and not any(filt in str(v).lower() for v in row):
                        continue
                    suspicious = exe and get_signature_status(exe) not in ("Valid",)
                    tag = ("suspicious",) if suspicious else ()
                    self.after(0, lambda r=row,t=tag:
                               self.ntree.insert("",tk.END,values=r,tags=t))
                except Exception:
                    pass
            self._status("Network refresh complete.")

        threading.Thread(target=worker, daemon=True).start()

    def _kill_net_proc(self):
        for iid in self.ntree.selection():
            pid, name = self.ntree.item(iid)["values"][:2]
            if messagebox.askyesno("Kill?", f"Kill {name} (PID {pid})?"):
                kill_process(pid)
                self.ntree.delete(iid)

    def _lookup_ip(self):
        for iid in self.ntree.selection():
            remote = str(self.ntree.item(iid)["values"][4])
            if not remote:
                continue
            ip = remote.split(":")[0]
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                host = "Could not resolve"
            messagebox.showinfo("IP Lookup", f"IP: {ip}\nHostname: {host}")

    def _open_net_exe(self):
        for iid in self.ntree.selection():
            exe = str(self.ntree.item(iid)["values"][6])
            if exe and os.path.exists(exe):
                subprocess.Popen(["explorer", "/select,", exe])

    def _exclude_net(self):
        for iid in self.ntree.selection():
            exe  = str(self.ntree.item(iid)["values"][7])   # col index shifted
            note = simpledialog.askstring("Note","Note:",parent=self) or ""
            if add_exclusion("paths", exe, note):
                self.ntree.delete(iid)
                self._refresh_exclusions_tab()

    def _kill_net_proc(self):
        pass   # defined below to avoid duplicate; original moved here

    # ══════════════════════════════════════════════════════════════════════════
    # IP REPUTATION ENGINE
    # ══════════════════════════════════════════════════════════════════════════

    # ── Offline known-bad C2 / malware infrastructure ─────────────────────────
    # Sources: Abuse.ch URLhaus, MalwareBazaar, public threat intel feeds.
    # This is a curated *sample* — the live API checks are the primary signal.
    _C2_BLOCKLIST_DOMAINS = {
        # Emotet / Trickbot / Qakbot C2 patterns
        "bazaar.abuse.ch","feodotracker.abuse.ch","urlhaus.abuse.ch",
        # Known C2 / bulletproof hosting often abused
        "ftp.dedikserver.de","185.220.101.0","185.220.102.0",
        # Common RAT / info-stealer exfil endpoints
        "pastebin.com","hastebin.com","transfer.sh",
        # Common malware download staging
        "cdn.discordapp.com","discord.com",        # frequently abused for payload hosting
        "raw.githubusercontent.com",               # script delivery
        # Cobalt Strike default C2 ports often on these
        "94.102.49.0","185.220.100.0","185.220.101.0",
    }

    _C2_BLOCKLIST_IPS = {
        # Feodo Tracker top botnet C2s (sample, updated quarterly)
        "198.23.181.32","198.23.182.167","172.93.201.219",
        "198.199.94.59","139.180.134.167","5.252.176.48",
        "45.90.58.201","45.142.212.100","91.229.76.183",
        "85.208.136.134","212.83.177.34","185.36.74.49",
        # Known Tor exit nodes frequently flagged
        "185.220.101.5","185.220.101.33","185.220.101.47",
        "185.220.101.6","185.220.101.34","185.220.101.48",
    }

    _PRIVATE_RANGES = (
        "127.","10.","192.168.","172.16.","172.17.","172.18.","172.19.",
        "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
        "172.26.","172.27.","172.28.","172.29.","172.30.","172.31.",
        "169.254.","::1","fe80","fc","fd",
    )

    def _is_private_ip(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self._PRIVATE_RANGES)

    def _offline_c2_check(self, ip: str):
        """Return (is_bad, reason) from offline blocklist."""
        if ip in self._C2_BLOCKLIST_IPS:
            return True, "Known C2 (offline blocklist)"
        # Reverse-lookup and check domain blocklist
        try:
            host = socket.gethostbyaddr(ip)[0].lower()
            for bad in self._C2_BLOCKLIST_DOMAINS:
                if bad in host:
                    return True, f"Blocklisted domain ({bad})"
        except Exception:
            pass
        return False, ""

    def _query_abuseipdb(self, ip: str, key: str) -> dict:
        """Query AbuseIPDB v2 check endpoint. Returns parsed dict or raises."""
        import requests
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=10,
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        score   = d.get("abuseConfidenceScore", 0)
        reports = d.get("totalReports", 0)
        country = d.get("countryCode", "?")
        isp     = d.get("isp", "")
        usage   = d.get("usageType", "")
        domain  = d.get("domain", "")
        is_tor  = d.get("isTor", False)
        last_rpt= d.get("lastReportedAt", "")
        return {
            "source":   "AbuseIPDB",
            "score":    score,
            "reports":  reports,
            "country":  country,
            "isp":      isp,
            "usage":    usage,
            "domain":   domain,
            "is_tor":   is_tor,
            "last":     last_rpt,
            "label":    f"Abuse {score}%  ({reports} rpts)" if reports else f"Clean (AbuseIPDB)",
            "severity": "CRITICAL" if score >= 75 else "HIGH" if score >= 25 else "LOW",
        }

    def _query_vt_ip(self, ip: str, key: str) -> dict:
        """Query VirusTotal IP-address endpoint."""
        import requests
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=10,
        )
        resp.raise_for_status()
        attrs    = resp.json().get("data", {}).get("attributes", {})
        stats    = attrs.get("last_analysis_stats", {})
        mal      = stats.get("malicious", 0)
        sus      = stats.get("suspicious", 0)
        harm     = stats.get("harmless", 0)
        country  = attrs.get("country", "?")
        asowner  = attrs.get("as_owner", "")
        asn      = attrs.get("asn", "")
        rep      = attrs.get("reputation", 0)
        return {
            "source":   "VirusTotal",
            "malicious": mal,
            "suspicious": sus,
            "harmless":  harm,
            "country":   country,
            "as_owner":  asowner,
            "asn":       asn,
            "reputation": rep,
            "label":     f"VT {mal}✗/{sus}?/{harm}✓" if (mal or sus) else "VT Clean",
            "severity":  "CRITICAL" if mal >= 5 else "HIGH" if mal >= 1 else "LOW",
        }

    def _check_ip_reputation(self):
        """Check reputation of selected rows' remote IPs."""
        iids = list(self.ntree.selection())
        if not iids:
            messagebox.showinfo("No selection", "Select one or more rows first.")
            return
        ips = []
        iid_map = {}  # ip → iid list
        for iid in iids:
            vals   = self.ntree.item(iid)["values"]
            remote = str(vals[4])
            if not remote or remote == "—":
                continue
            ip = remote.split(":")[0]
            if self._is_private_ip(ip):
                self._net_set_rep(iid, "Private / LAN", "rep_clean")
                continue
            ips.append(ip)
            iid_map.setdefault(ip, []).append(iid)
        if not ips:
            return
        self._status(f"Checking reputation of {len(ips)} IP(s)…")
        threading.Thread(target=self._ip_rep_worker,
                         args=(ips, iid_map, True), daemon=True).start()

    def _check_all_ip_rep(self):
        """Check all non-private remote IPs in the table."""
        iid_map = {}
        for iid in self.ntree.get_children():
            remote = str(self.ntree.item(iid)["values"][4])
            if not remote or remote == "—":
                continue
            ip = remote.split(":")[0]
            if self._is_private_ip(ip):
                self._net_set_rep(iid, "Private / LAN", "rep_clean")
                continue
            iid_map.setdefault(ip, []).append(iid)
        ips = list(iid_map.keys())
        if not ips:
            self._status("No public IPs to check.")
            return
        self._status(f"Checking {len(ips)} unique public IP(s)…")
        threading.Thread(target=self._ip_rep_worker,
                         args=(ips, iid_map, False), daemon=True).start()

    def _ip_rep_worker(self, ips, iid_map, show_dialog_for_first):
        abuse_key = self._abuseipdb_key.get().strip()
        vt_key    = self._vt_key.get().strip()
        first     = True
        for ip in ips:
            if ip in self._ip_rep_cache:
                result = self._ip_rep_cache[ip]
            else:
                result = self._resolve_ip_rep(ip, abuse_key, vt_key)
                self._ip_rep_cache[ip] = result
            # Update tree rows
            for iid in iid_map.get(ip, []):
                label = result.get("label", "")
                sev   = result.get("severity","LOW")
                c2    = result.get("c2_hit", False)
                tag   = "rep_c2" if c2 else ("rep_bad" if sev=="CRITICAL" else
                                              "rep_high" if sev=="HIGH" else "rep_clean")
                self.after(0, lambda i=iid, lb=label, tg=tag: self._net_set_rep(i, lb, tg))
            if show_dialog_for_first and first:
                first = False
                self.after(0, lambda r=result, i2=ip: self._show_ip_rep_dialog(i2, r))
        self.after(0, lambda: self._status(f"IP reputation check complete — {len(ips)} IP(s) checked."))

    def _resolve_ip_rep(self, ip: str, abuse_key: str, vt_key: str) -> dict:
        """Run offline check, then live API(s). Returns merged result dict."""
        # 1. Offline C2 blocklist (instant, no API key needed)
        is_c2, c2_reason = self._offline_c2_check(ip)
        # 2. AbuseIPDB (primary)
        abuse_result = {}
        if abuse_key:
            try:
                abuse_result = self._query_abuseipdb(ip, abuse_key)
            except Exception as e:
                abuse_result = {"source":"AbuseIPDB","error":str(e)}
        # 3. VirusTotal IP (fallback / supplementary)
        vt_result = {}
        if vt_key:
            try:
                vt_result = self._query_vt_ip(ip, vt_key)
            except Exception as e:
                vt_result = {"source":"VirusTotal","error":str(e)}

        # Merge into one result
        result = {**abuse_result, **{f"vt_{k}": v for k, v in vt_result.items()}}
        result["ip"]      = ip
        result["c2_hit"]  = is_c2
        result["c2_why"]  = c2_reason

        # Compute combined severity
        sevs = []
        if is_c2:
            sevs.append("CRITICAL")
        if abuse_result.get("severity"):
            sevs.append(abuse_result["severity"])
        if vt_result.get("severity"):
            sevs.append(vt_result["severity"])
        rank = {"CRITICAL":3,"HIGH":2,"LOW":1}
        top  = max(sevs, key=lambda s: rank.get(s,0)) if sevs else "LOW"
        result["severity"] = top

        # Build combined label for tree column
        parts = []
        if is_c2:
            parts.append("🚨C2")
        if abuse_result.get("score") is not None:
            parts.append(f"Abuse:{abuse_result['score']}%")
        if vt_result.get("malicious") is not None:
            parts.append(f"VT:{vt_result['malicious']}✗")
        if not parts:
            parts.append("Clean (offline only)")
        result["label"] = "  ".join(parts)
        return result

    def _net_set_rep(self, iid, label, tag):
        """Update the IP Reputation cell and tags for a tree row."""
        try:
            vals = list(self.ntree.item(iid)["values"])
            if len(vals) >= 7:
                vals[6] = label
                existing = list(self.ntree.item(iid)["tags"])
                new_tags = [t for t in existing
                            if t not in ("rep_bad","rep_high","rep_clean","rep_c2")] + [tag]
                self.ntree.item(iid, values=vals, tags=new_tags)
        except Exception:
            pass

    def _show_ip_rep_dialog(self, ip: str, result: dict):
        """Show detailed reputation dialog for a single IP."""
        win = tk.Toplevel(self)
        win.title(f"IP Reputation — {ip}")
        win.configure(bg=BG)
        win.geometry("640x500")
        win.resizable(True, True)

        sev   = result.get("severity","LOW")
        sev_c = {"CRITICAL":"#ff3333","HIGH":"#ff8800","LOW":"#44cc44"}.get(sev, FG)
        tk.Label(win, text=f"🛡️  IP Reputation Report", bg=BG, fg=FG,
                 font=("Segoe UI",14,"bold")).pack(pady=(12,0))
        tk.Label(win, text=ip, bg=BG, fg="#88aaff",
                 font=("Segoe UI",12,"bold")).pack()
        tk.Label(win, text=f"Overall Severity: {sev}", bg=BG, fg=sev_c,
                 font=("Segoe UI",11,"bold")).pack(pady=(4,10))

        txt = tk.Text(win, bg=PANEL, fg=FG, font=("Courier New",9),
                      relief=tk.FLAT, wrap=tk.WORD, padx=10, pady=8)
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,8))

        def append(label, val, color=FG):
            txt.insert(tk.END, f"  {label:<26}", ("lbl",))
            txt.insert(tk.END, f"{val}\n", ("val",))
        txt.tag_configure("lbl", foreground="#888888")
        txt.tag_configure("val", foreground=FG)

        # Offline
        txt.insert(tk.END, "── Offline Blocklist ────────────────────────────────\n", ("hdr",))
        txt.tag_configure("hdr", foreground="#88aaff", font=("Courier New",9,"bold"))
        c2_hit = result.get("c2_hit", False)
        append("C2 / Blocklist hit:", ("YES — " + result.get("c2_why","")) if c2_hit else "No match",
               "#ff3333" if c2_hit else "#44cc44")

        # AbuseIPDB
        txt.insert(tk.END, "\n── AbuseIPDB ────────────────────────────────────────\n", ("hdr",))
        if "error" in result and result.get("source","") == "AbuseIPDB":
            append("Error:", result["error"], "#ff8800")
        elif result.get("score") is not None:
            append("Abuse Confidence:",  f"{result['score']}%")
            append("Total Reports:",     str(result.get("reports",0)))
            append("Country:",           result.get("country","?"))
            append("ISP:",               result.get("isp",""))
            append("Usage Type:",        result.get("usage",""))
            append("Domain:",            result.get("domain",""))
            append("Tor Exit Node:",     "Yes" if result.get("is_tor") else "No")
            append("Last Reported:",     result.get("last","—"))
        else:
            append("Status:", "No API key set — enter AbuseIPDB key above", "#888888")

        # VirusTotal
        txt.insert(tk.END, "\n── VirusTotal ───────────────────────────────────────\n", ("hdr",))
        if result.get("vt_error"):
            append("Error:", result["vt_error"], "#ff8800")
        elif result.get("vt_malicious") is not None:
            append("Malicious engines:",  str(result.get("vt_malicious",0)))
            append("Suspicious engines:", str(result.get("vt_suspicious",0)))
            append("Harmless engines:",   str(result.get("vt_harmless",0)))
            append("Country:",            result.get("vt_country","?"))
            append("AS Owner:",           result.get("vt_as_owner",""))
            append("ASN:",                str(result.get("vt_asn","")))
            append("VT Reputation:",      str(result.get("vt_reputation",0)))
        else:
            append("Status:", "No VT API key set — enter VirusTotal key in Exe Scanner tab", "#888888")

        txt.config(state=tk.DISABLED)
        _btn(win, "Close", win.destroy, BTN, FG).pack(pady=(0,10))

    # ══════════════════════════════════════════════════════════════════════════
    # PROCESSES TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_proc_tab(self):
        p = self._tabs["processes"]
        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)
        _btn(ctrl, "🔄 Refresh", self._refresh_procs, BTN, FG).pack(side=tk.LEFT, padx=4)
        self.proc_filter_var = tk.StringVar()
        self.proc_filter_var.trace_add("write", lambda *_: self._refresh_procs())
        tk.Label(ctrl, text="Filter:", bg=BG, fg=FG).pack(side=tk.LEFT, padx=(20,4))
        tk.Entry(ctrl, textvariable=self.proc_filter_var, width=26,
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 10), relief=tk.FLAT).pack(side=tk.LEFT)

        cols = ("pid","name","exe","signed","user","mem")
        self.ptree, _ = _tree(p, cols,
            {"pid":55,"name":145,"exe":375,"signed":85,"user":130,"mem":75},
            {"pid":"PID","name":"Name","exe":"Executable","signed":"Signed?","user":"User","mem":"MB"})
        self.ptree.tag_configure("unsigned", foreground="#ff8800")

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🔪 Kill",          self._kill_proc_tab,      RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🧪 Quarantine",    self._quarantine_proc,    ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open Location", self._open_proc_location, BTN,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🦠 VT Check",      self._vt_proc_check,      PURPLE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion", self._exclude_proc,       TEAL,   FG).pack(side=tk.LEFT, padx=3)

        if HAVE_PSUTIL:
            self._refresh_procs()

    def _refresh_procs(self, *_):
        if not HAVE_PSUTIL:
            return
        filt = self.proc_filter_var.get().lower()

        def worker():
            rows = []
            for proc in psutil.process_iter(["pid","name","exe","username","memory_info"]):
                try:
                    info = proc.info
                    exe  = info.get("exe") or ""
                    name = info.get("name") or ""
                    if filt and filt not in name.lower() and filt not in exe.lower():
                        continue
                    excl, _ = is_excluded(filepath=exe)
                    if excl:
                        continue
                    sig  = get_signature_status(exe) if exe and os.path.exists(exe) else "—"
                    user = info.get("username") or "—"
                    mem  = round(getattr(info.get("memory_info"), "rss", 0) / 1048576, 1)
                    rows.append((info["pid"], name, exe or "—", sig, user, mem))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
            self.after(0, lambda: self._populate_procs(rows))

        threading.Thread(target=worker, daemon=True).start()

    def _populate_procs(self, rows):
        self.ptree.delete(*self.ptree.get_children())
        for row in rows:
            tag = "unsigned" if row[3] not in ("Valid","—") else ""
            self.ptree.insert("", tk.END, values=row, tags=(tag,) if tag else ())

    def _kill_proc_tab(self):
        for iid in self.ptree.selection():
            pid, name = self.ptree.item(iid)["values"][:2]
            if messagebox.askyesno("Kill?", f"Kill {name} (PID {pid})?"):
                r = kill_process(pid)
                if r is True:
                    self.ptree.delete(iid)

    def _quarantine_proc(self):
        for iid in self.ptree.selection():
            vals = self.ptree.item(iid)["values"]
            pid, exe = vals[0], str(vals[2])
            if exe == "—" or not os.path.exists(exe):
                continue
            kill_process(pid)
            time.sleep(0.4)
            ok, r = quarantine_file(exe)
            self._status(f"{'✔' if ok else '✘'} {r}")
            if ok:
                self.ptree.delete(iid)
            self._refresh_quarantine()

    def _open_proc_location(self):
        for iid in self.ptree.selection():
            exe = str(self.ptree.item(iid)["values"][2])
            if exe and exe != "—" and os.path.exists(exe):
                subprocess.Popen(["explorer", "/select,", exe])

    def _vt_proc_check(self):
        key = self._vt_key.get().strip()
        if not key:
            messagebox.showwarning("No API Key",
                "Add your VirusTotal API key in the Exe Scanner tab.")
            return
        for iid in self.ptree.selection():
            exe = str(self.ptree.item(iid)["values"][2])
            if not exe or exe == "—" or not os.path.exists(exe):
                continue
            md5 = get_file_md5(exe)
            if not md5:
                continue
            pos, total, link = virustotal_check(key, md5)
            if pos is None:
                messagebox.showerror("VT Error", link)
            elif pos > 0:
                messagebox.showwarning("⚠ Detected!", f"{os.path.basename(exe)}\n{pos}/{total}\n{link}")
            else:
                messagebox.showinfo("Clean", f"{os.path.basename(exe)}\nClean ({total})\n{link}")

    def _exclude_proc(self):
        for iid in self.ptree.selection():
            exe  = str(self.ptree.item(iid)["values"][2])
            kind = self._ask_exclusion_kind()
            if not kind:
                return
            note = simpledialog.askstring("Note","Note:",parent=self) or ""
            if add_exclusion(kind, exe, note):
                self.ptree.delete(iid)
                self._refresh_exclusions_tab()

    # ══════════════════════════════════════════════════════════════════════════
    # QUARANTINE TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_quarantine_tab(self):
        p = self._tabs["quarantine"]
        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)
        tk.Label(ctrl, text=f"Quarantine: {QUARANTINE_DIR}",
                 bg=BG, fg="#888888", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        _btn(ctrl, "🔄 Refresh", self._refresh_quarantine, BTN, FG).pack(side=tk.RIGHT, padx=4)

        cols = ("name","date","size")
        self.qtree, _ = _tree(p, cols,
            {"name":360,"date":145,"size":100},
            {"name":"File","date":"Quarantined On","size":"Size"})

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🗑️ Permanently Delete", self._delete_quarantined,  RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "↩️ Restore",            self._restore_quarantined, ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open Folder",        self._open_quarantine_dir, BTN,    FG).pack(side=tk.LEFT, padx=3)
        tk.Label(p,
                 text="Quarantined files cannot run. Delete permanently when sure, or restore if it was a false alarm.",
                 bg=BG, fg="#888888", font=("Segoe UI", 8)).pack(pady=5)
        self._refresh_quarantine()

    def _refresh_quarantine(self):
        self.qtree.delete(*self.qtree.get_children())
        if not os.path.isdir(QUARANTINE_DIR):
            return
        for fname in sorted(os.listdir(QUARANTINE_DIR)):
            fp = os.path.join(QUARANTINE_DIR, fname)
            try:
                sz    = os.path.getsize(fp)
                mtime = datetime.fromtimestamp(os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M")
                self.qtree.insert("", tk.END, values=(fname, mtime, f"{sz//1024} KB"))
            except Exception:
                pass

    def _delete_quarantined(self):
        for iid in self.qtree.selection():
            fname = str(self.qtree.item(iid)["values"][0])
            fp    = os.path.join(QUARANTINE_DIR, fname)
            if messagebox.askyesno("Permanently Delete?", f"Delete:\n{fname}"):
                try:
                    shutil.rmtree(fp) if os.path.isdir(fp) else os.remove(fp)
                    self.qtree.delete(iid)
                except Exception as e:
                    messagebox.showerror("Error", str(e))

    def _restore_quarantined(self):
        for iid in self.qtree.selection():
            fname = str(self.qtree.item(iid)["values"][0])
            fp    = os.path.join(QUARANTINE_DIR, fname)
            dest  = filedialog.askdirectory(title="Restore to which folder?")
            if not dest:
                continue
            try:
                shutil.move(fp, os.path.join(dest, fname))
                self.qtree.delete(iid)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _open_quarantine_dir(self):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        subprocess.Popen(["explorer", QUARANTINE_DIR])

    # ══════════════════════════════════════════════════════════════════════════
    # EXCLUSIONS TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_exclusions_tab(self):
        p = self._tabs["exclusions"]

        tk.Label(p,
                 text="Items here are silently skipped across ALL scan tabs. "
                      "Add by path prefix, publisher name, MD5 hash, or browser extension ID.",
                 bg=BG, fg="#aaaaaa", font=("Segoe UI", 9), wraplength=1100).pack(padx=8, pady=(8,4))

        add_row = tk.Frame(p, bg=BG, pady=4)
        add_row.pack(fill=tk.X, padx=8)
        tk.Label(add_row, text="Add:", bg=BG, fg=FG, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        self.excl_kind_var  = tk.StringVar(value="paths")
        self.excl_value_var = tk.StringVar()
        self.excl_note_var  = tk.StringVar()
        ttk.Combobox(add_row, textvariable=self.excl_kind_var, width=12,
                     values=["paths","publishers","hashes","ext_ids"],
                     state="readonly").pack(side=tk.LEFT, padx=6)
        tk.Entry(add_row, textvariable=self.excl_value_var, width=40,
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 10), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        tk.Label(add_row, text="Note:", bg=BG, fg="#888888",
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(6,2))
        tk.Entry(add_row, textvariable=self.excl_note_var, width=22,
                 bg=ACCENT, fg=FG, insertbackground=FG,
                 font=("Segoe UI", 9), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        _btn(add_row, "➕ Add",        self._manual_add_exclusion,          GREEN, FG).pack(side=tk.LEFT, padx=4)
        _btn(add_row, "📂 Browse Path",
             lambda: self._browse_to_excl("paths"), BTN, FG).pack(side=tk.LEFT, padx=2)

        cols = ("kind","value","note")
        self.xtree, _ = _tree(p, cols,
            {"kind":90,"value":580,"note":310},
            {"kind":"Type","value":"Excluded Value","note":"Note"})
        self.xtree.tag_configure("paths",      foreground="#88ccff")
        self.xtree.tag_configure("publishers", foreground="#aaffaa")
        self.xtree.tag_configure("hashes",     foreground="#ffaa88")
        self.xtree.tag_configure("ext_ids",    foreground="#ffccff")

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🗑️ Remove Selected", self._remove_exclusion,  RED,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "💾 Export List",     self._export_exclusions, BTN,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📥 Import List",     self._import_exclusions, BTN,   FG).pack(side=tk.LEFT, padx=3)

        tk.Label(p, text=f"Saved to: {EXCLUSIONS_FILE}",
                 bg=BG, fg="#555577", font=("Segoe UI", 8)).pack(pady=3)

        self._refresh_exclusions_tab()

    def _refresh_exclusions_tab(self):
        self.xtree.delete(*self.xtree.get_children())
        for kind in ("paths","publishers","hashes","ext_ids"):
            for value in _exclusions.get(kind, []):
                note = _exclusions.get("notes", {}).get(value, "")
                self.xtree.insert("", tk.END,
                    values=(kind, value, note), tags=(kind,))

    def _manual_add_exclusion(self):
        kind  = self.excl_kind_var.get()
        value = self.excl_value_var.get().strip()
        note  = self.excl_note_var.get().strip()
        if not value:
            messagebox.showwarning("Empty", "Enter a value.")
            return
        if add_exclusion(kind, value, note):
            self.excl_value_var.set("")
            self.excl_note_var.set("")
            self._refresh_exclusions_tab()
        else:
            self._status("Already in exclusions list.")

    def _browse_to_excl(self, kind):
        path = filedialog.askdirectory(title="Select folder to exclude") or \
               filedialog.askopenfilename(title="Or select a file to exclude")
        if path:
            self.excl_kind_var.set(kind)
            self.excl_value_var.set(path)

    def _remove_exclusion(self):
        for iid in self.xtree.selection():
            vals  = self.xtree.item(iid)["values"]
            kind, value = str(vals[0]), str(vals[1])
            remove_exclusion(kind, value)
            self.xtree.delete(iid)

    def _export_exclusions(self):
        fp = filedialog.asksaveasfilename(defaultextension=".json",
                                          filetypes=[("JSON","*.json")])
        if fp:
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(_exclusions, f, indent=2)
            self._status(f"Exported → {fp}")

    def _import_exclusions(self):
        fp = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if not fp:
            return
        try:
            with open(fp, "r", encoding="utf-8") as f:
                imported = json.load(f)
            for kind in ("paths","publishers","hashes","ext_ids"):
                for v in imported.get(kind, []):
                    add_exclusion(kind, v, imported.get("notes",{}).get(v,""))
            self._refresh_exclusions_tab()
            self._status(f"Imported from {fp}")
        except Exception as e:
            messagebox.showerror("Import error", str(e))

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _ask_exclusion_kind(self):
        dlg = tk.Toplevel(self)
        dlg.title("Exclude by…")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.grab_set()
        tk.Label(dlg, text="Exclude this item by:", bg=BG, fg=FG,
                 font=("Segoe UI", 11, "bold")).pack(padx=20, pady=(16,8))
        result = tk.StringVar(value="")
        for val, label in [
            ("paths",      "📂  Path — skip this file or entire folder"),
            ("publishers", "🏢  Publisher — skip all files from this company"),
            ("hashes",     "🔑  MD5 Hash — skip this exact file version"),
        ]:
            tk.Button(dlg, text=label, bg=ACCENT, fg=FG, activebackground=ACCENT,
                      relief=tk.FLAT, padx=12, pady=6, font=("Segoe UI", 10), cursor="hand2",
                      command=lambda v=val: (result.set(v), dlg.destroy())
                      ).pack(fill=tk.X, padx=20, pady=3)
        tk.Button(dlg, text="Cancel", bg=RED, fg=FG, activebackground=RED,
                  relief=tk.FLAT, padx=12, pady=6, font=("Segoe UI", 10), cursor="hand2",
                  command=dlg.destroy).pack(fill=tk.X, padx=20, pady=(3,16))
        self.wait_window(dlg)
        return result.get() or None

    # ══════════════════════════════════════════════════════════════════════════
    # SILENT INSTALLS TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_silent_tab(self):
        p = self._tabs["silent"]

        # Header description
        tk.Label(p,
                 text="Scans the Windows uninstall registry for programs that show signs of a silent / stealth install. "
                      "Each entry is scored by: unsigned exe, no Start-Menu shortcut, no publisher, "
                      "installed recently, silent-uninstall flag, hidden from Add/Remove Programs, tiny install size.",
                 bg=BG, fg="#aaaaaa", font=("Segoe UI", 8), wraplength=1140).pack(padx=8, pady=(6, 2))

        ctrl = tk.Frame(p, bg=BG, pady=4)
        ctrl.pack(fill=tk.X, padx=8)

        # Days lookback spinner
        tk.Label(ctrl, text="Flag installs from the last", bg=BG, fg=FG,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.si_days_var = tk.IntVar(value=30)
        tk.Spinbox(ctrl, from_=1, to=365, textvariable=self.si_days_var, width=5,
                   bg=ACCENT, fg=FG, insertbackground=FG, buttonbackground=ACCENT,
                   font=("Segoe UI", 9), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        tk.Label(ctrl, text="days", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        _btn(ctrl, "🕵️ Scan Silent Installs", self._scan_silent, GREEN, FG).pack(side=tk.LEFT, padx=18)

        # Severity filter
        filt = tk.Frame(p, bg=BG)
        filt.pack(fill=tk.X, padx=8, pady=(0, 3))
        tk.Label(filt, text="Show:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.si_filter_var = tk.StringVar(value="ALL")
        for lbl in ("ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"):
            tk.Radiobutton(filt, text=lbl, variable=self.si_filter_var, value=lbl,
                           bg=BG, fg=SEVERITY_COLORS.get(lbl, FG),
                           selectcolor=ACCENT, activebackground=BG,
                           command=self._apply_si_filter,
                           font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=4)
        self.si_count_lbl = tk.Label(filt, text="", bg=BG, fg="#aaaaaa",
                                     font=("Segoe UI", 9))
        self.si_count_lbl.pack(side=tk.RIGHT, padx=10)

        cols = ("severity", "score", "name", "publisher", "install_date",
                "signature", "flags", "install_loc")
        self.sitree, _ = _tree(p, cols,
            {"severity": 82, "score": 46, "name": 210, "publisher": 145,
             "install_date": 90, "signature": 88, "flags": 280, "install_loc": 280},
            {"severity": "Severity", "score": "Score", "name": "Program Name",
             "publisher": "Publisher", "install_date": "Install Date",
             "signature": "Signed?", "flags": "⚑ Flags", "install_loc": "Install Location"})
        _apply_sev_tags(self.sitree)

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🗑️ Uninstall Program",    self._si_uninstall,     RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🧪 Quarantine Exe",        self._si_quarantine,    ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open Install Folder",   self._si_open_folder,   BTN,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🦠 VT Check",              self._si_vt_check,      PURPLE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion",         self._si_exclude,       TEAL,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📋 Copy Name",             self._si_copy_name,     BTN,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "💾 Export CSV",            self._si_export_csv,    BTN,    FG).pack(side=tk.RIGHT, padx=3)

        tk.Label(p,
                 text="⚠  Score ≥ 7 = CRITICAL · ≥ 5 = HIGH · ≥ 3 = MEDIUM · < 3 = LOW. "
                      "Higher score = more suspicious signals. Always verify before uninstalling.",
                 bg=BG, fg="#666688", font=("Segoe UI", 8)).pack(pady=(2, 4))

        self._si_rows = {}   # iid → entry dict
        self._si_data = []

    # ── Silent scan logic ────────────────────────────────────────────────────

    def _scan_silent(self):
        self.sitree.delete(*self.sitree.get_children())
        self._si_rows.clear()
        self._si_data.clear()
        days = self.si_days_var.get()

        def worker():
            self._status("Scanning for silent/suspicious installs…")
            count = 0
            for entry in get_silent_installs(days_lookback=days):
                excl, _ = is_excluded(
                    filepath=entry.get("install_exe", ""),
                    publisher=entry.get("publisher", ""))
                if excl:
                    continue
                self._si_data.append(entry)
                count += 1
                self.after(0, self._add_si_row, entry)
            self.after(0, lambda: self.si_count_lbl.config(
                text=f"{count} flagged entries"))
            self._status(f"Silent install scan complete — {count} suspicious programs found.")

        threading.Thread(target=worker, daemon=True).start()

    def _add_si_row(self, entry):
        fv = self.si_filter_var.get()
        if fv != "ALL" and entry["severity"] != fv:
            return
        iid = self.sitree.insert("", tk.END,
            values=(entry["severity"], entry["score"], entry["name"],
                    entry["publisher"], entry["install_date"],
                    entry["signature"], entry["flags"], entry["install_loc"]),
            tags=(entry["severity"],))
        self._si_rows[iid] = entry

    def _apply_si_filter(self):
        self.sitree.delete(*self.sitree.get_children())
        self._si_rows.clear()
        for entry in self._si_data:
            self._add_si_row(entry)

    def _selected_si_entries(self):
        return [self._si_rows[i] for i in self.sitree.selection() if i in self._si_rows]

    def _si_uninstall(self):
        for entry in self._selected_si_entries():
            uninstall_cmd = entry.get("uninstall", "")
            if not uninstall_cmd:
                messagebox.showwarning("No uninstall command",
                    f"No UninstallString found for:\n{entry['name']}")
                continue
            if not messagebox.askyesno("Uninstall?",
                    f"Run the uninstaller for:\n{entry['name']}\n\n"
                    f"Command: {uninstall_cmd}\n\n"
                    "This will launch the program's own uninstaller. Proceed?"):
                continue
            try:
                subprocess.Popen(uninstall_cmd, shell=True)
                self._status(f"Uninstaller launched for: {entry['name']}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _si_quarantine(self):
        for entry in self._selected_si_entries():
            exe = entry.get("install_exe", "")
            if exe and exe != "—" and os.path.exists(exe):
                ok, r = quarantine_file(exe)
                self._status(f"{'✔' if ok else '✘'} {r}")
                self._refresh_quarantine()
            else:
                loc = entry.get("install_loc", "")
                if loc and loc != "—" and os.path.isdir(loc):
                    if messagebox.askyesno("Quarantine entire folder?",
                            f"No single exe found. Quarantine entire install folder?\n{loc}"):
                        ok, r = quarantine_file(loc)
                        self._status(f"{'✔' if ok else '✘'} {r}")
                        self._refresh_quarantine()

    def _si_open_folder(self):
        for entry in self._selected_si_entries():
            loc = entry.get("install_loc", "")
            exe = entry.get("install_exe", "")
            if exe and exe != "—" and os.path.exists(exe):
                subprocess.Popen(["explorer", "/select,", exe])
            elif loc and loc != "—" and os.path.isdir(loc):
                subprocess.Popen(["explorer", loc])
            else:
                messagebox.showinfo("Not found",
                    f"Install location not found on disk:\n{loc}\n\n"
                    "The program may have already been removed or installed to a non-standard location.")

    def _si_vt_check(self):
        key = self._vt_key.get().strip()
        if not key:
            messagebox.showwarning("No API Key",
                "Add your VirusTotal API key in the Exe Scanner tab.")
            return
        for entry in self._selected_si_entries():
            exe = entry.get("install_exe", "")
            if not exe or exe == "—" or not os.path.exists(exe):
                self._status(f"No exe on disk for: {entry['name']}")
                continue
            md5 = get_file_md5(exe)
            if not md5:
                continue
            pos, total, link = virustotal_check(key, md5)
            if pos is None:
                messagebox.showerror("VT Error", link)
            elif pos > 0:
                messagebox.showwarning("⚠ Detected!",
                    f"{entry['name']}\nMD5: {md5}\n{pos}/{total} engines\n{link}")
            else:
                messagebox.showinfo("Clean",
                    f"{entry['name']}\nMD5: {md5}\nClean ({total} engines)\n{link}")

    def _si_exclude(self):
        for entry in self._selected_si_entries():
            kind = self._ask_exclusion_kind()
            if not kind:
                return
            if kind == "paths":
                value = entry.get("install_exe","") or entry.get("install_loc","")
            elif kind == "publishers":
                value = entry.get("publisher", "")
            else:
                value = entry.get("install_exe","")
            note = simpledialog.askstring("Note", f"Note for '{entry['name']}':",
                                          parent=self) or ""
            if value and add_exclusion(kind, value, note):
                # Remove from tree
                for iid, e in list(self._si_rows.items()):
                    if e is entry:
                        self.sitree.delete(iid)
                        del self._si_rows[iid]
                        break
                self._status(f"Excluded: {value}")
                self._refresh_exclusions_tab()

    def _si_copy_name(self):
        entries = self._selected_si_entries()
        if entries:
            self.clipboard_clear()
            self.clipboard_append("\n".join(e["name"] for e in entries))

    def _si_export_csv(self):
        fp = filedialog.asksaveasfilename(defaultextension=".csv",
                                          filetypes=[("CSV", "*.csv")])
        if not fp:
            return
        fields = ["severity","score","name","publisher","install_date",
                  "signature","flags","install_loc","install_exe","uninstall"]
        with open(fp, "w", encoding="utf-8") as f:
            f.write(",".join(fields) + "\n")
            for e in self._si_data:
                def q(v): return '"' + str(v).replace('"', '""') + '"'
                f.write(",".join(q(e.get(k,"")) for k in fields) + "\n")
        self._status(f"Exported → {fp}")

    # ══════════════════════════════════════════════════════════════════════════
    # LIVE FILE WATCHER TAB
    # ══════════════════════════════════════════════════════════════════════════

    # Extensions considered suspicious when dropped into monitored folders
    _WATCH_EXTS = {".exe",".dll",".bat",".cmd",".ps1",".vbs",".js",".wsf",".hta",".scr",".pif"}

    def _build_watcher_tab(self):
        p = self._tabs["watcher"]

        tk.Label(p,
                 text="Monitors directories every few seconds. Alerts immediately when a new unsigned "
                      "or suspicious file appears in Temp, AppData, Startup folders, or any custom path you add.",
                 bg=BG, fg="#aaaaaa", font=("Segoe UI", 8), wraplength=1140).pack(padx=8, pady=(6,2))

        # Directory list
        dir_frame = tk.Frame(p, bg=BG)
        dir_frame.pack(fill=tk.X, padx=8, pady=(2,0))
        tk.Label(dir_frame, text="Watched directories:", bg=BG, fg=FG,
                 font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        _btn(dir_frame, "➕ Add", self._watch_add_dir, BTN, FG).pack(side=tk.LEFT, padx=6)
        _btn(dir_frame, "➖ Remove", self._watch_remove_dir, BTN, FG).pack(side=tk.LEFT, padx=2)

        self.watch_dir_lb = tk.Listbox(p, bg=ACCENT, fg=FG, selectbackground=PURPLE,
                                        font=("Segoe UI", 9), height=4, relief=tk.FLAT,
                                        selectmode=tk.EXTENDED)
        self.watch_dir_lb.pack(fill=tk.X, padx=8, pady=(2,4))
        # Populate with default high-risk dirs
        for d in [os.environ.get("TEMP",""), os.environ.get("APPDATA",""),
                  os.environ.get("LOCALAPPDATA",""),
                  os.path.join(os.environ.get("APPDATA",""),
                               "Microsoft","Windows","Start Menu","Programs","Startup"),
                  r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                  "C:\\Users\\Public"]:
            if d:
                self.watch_dir_lb.insert(tk.END, d)

        # Control bar
        ctrl = tk.Frame(p, bg=BG, pady=4)
        ctrl.pack(fill=tk.X, padx=8)
        tk.Label(ctrl, text="Poll every", bg=BG, fg=FG, font=("Segoe UI",9)).pack(side=tk.LEFT)
        self.watch_interval_var = tk.IntVar(value=5)
        tk.Spinbox(ctrl, from_=2, to=60, textvariable=self.watch_interval_var, width=4,
                   bg=ACCENT, fg=FG, insertbackground=FG, buttonbackground=ACCENT,
                   font=("Segoe UI",9), relief=tk.FLAT).pack(side=tk.LEFT, padx=4)
        tk.Label(ctrl, text="seconds", bg=BG, fg=FG, font=("Segoe UI",9)).pack(side=tk.LEFT)

        self.watch_alert_var = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl, text="Alert popup on detection",
                       variable=self.watch_alert_var, bg=BG, fg=FG,
                       selectcolor=ACCENT, activebackground=BG,
                       font=("Segoe UI",9)).pack(side=tk.LEFT, padx=16)

        self.watch_btn = _btn(ctrl, "▶ Start Watching", self._watch_toggle, GREEN, FG)
        self.watch_btn.pack(side=tk.LEFT, padx=8)
        self.watch_status_lbl = tk.Label(ctrl, text="Stopped", bg=BG, fg="#888888",
                                          font=("Segoe UI",9,"bold"))
        self.watch_status_lbl.pack(side=tk.LEFT, padx=10)
        _btn(ctrl, "🗑️ Clear Log", self._watch_clear, BTN, FG).pack(side=tk.RIGHT, padx=4)

        # Event log tree
        cols = ("time","severity","event","path","signature","action")
        self.wtree, _ = _tree(p, cols,
            {"time":80,"severity":80,"event":130,"path":420,"signature":90,"action":160},
            {"time":"Time","severity":"Severity","event":"Event",
             "path":"File Path","signature":"Signed?","action":"Auto-Action"})
        _apply_sev_tags(self.wtree)

        act = tk.Frame(p, bg=BG, pady=5)
        act.pack(fill=tk.X, padx=8)
        _btn(act, "🧪 Quarantine Selected", self._watch_quarantine, ORANGE, FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🗑️ Delete Selected",     self._watch_delete,     RED,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "🚫 Add Exclusion",        self._watch_exclude,    TEAL,   FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "📂 Open in Explorer",     self._watch_explorer,   BTN,    FG).pack(side=tk.LEFT, padx=3)
        _btn(act, "💾 Export Log",           self._watch_export,     BTN,    FG).pack(side=tk.RIGHT, padx=3)

        self._watch_row_paths = {}   # iid → filepath

    # ── Watcher logic ─────────────────────────────────────────────────────────

    def _watch_add_dir(self):
        d = filedialog.askdirectory(title="Add directory to watch")
        if d:
            self.watch_dir_lb.insert(tk.END, d)

    def _watch_remove_dir(self):
        for idx in reversed(self.watch_dir_lb.curselection()):
            self.watch_dir_lb.delete(idx)

    def _watch_toggle(self):
        if self._watch_running:
            self._watch_running = False
            self.watch_btn.config(text="▶ Start Watching", bg=GREEN)
            self.watch_status_lbl.config(text="Stopped", fg="#888888")
        else:
            self._watch_running = True
            self._watch_known.clear()
            # Snapshot current state so we only alert on *new* files
            self._watch_snapshot()
            self.watch_btn.config(text="■ Stop Watching", bg=RED)
            self.watch_status_lbl.config(text="● Watching…", fg="#ff4444")
            self._watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
            self._watch_thread.start()

    def _watch_snapshot(self):
        """Record all current files so we don't alert on pre-existing ones."""
        dirs = list(self.watch_dir_lb.get(0, tk.END))
        for d in dirs:
            if not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    fp = os.path.join(d, fname)
                    if os.path.isfile(fp):
                        try:
                            self._watch_known[fp] = os.path.getmtime(fp)
                        except Exception:
                            pass
            except Exception:
                pass

    def _watch_loop(self):
        while self._watch_running:
            interval = self.watch_interval_var.get()
            dirs     = list(self.watch_dir_lb.get(0, tk.END))
            for d in dirs:
                if not os.path.isdir(d):
                    continue
                try:
                    for fname in os.listdir(d):
                        if not self._watch_running:
                            return
                        fp  = os.path.join(d, fname)
                        ext = os.path.splitext(fname)[1].lower()
                        if not os.path.isfile(fp):
                            continue
                        if ext not in self._WATCH_EXTS:
                            continue
                        try:
                            mtime = os.path.getmtime(fp)
                        except Exception:
                            continue
                        if fp in self._watch_known and self._watch_known[fp] == mtime:
                            continue
                        # New or modified file detected
                        self._watch_known[fp] = mtime
                        self._watch_analyse(fp, "New file" if fp not in self._watch_known else "Modified")
                except Exception:
                    pass
            time.sleep(interval)

    def _watch_analyse(self, filepath, event_type="New file"):
        excl, _ = is_excluded(filepath=filepath)
        if excl:
            return
        sig = get_signature_status(filepath)
        pub = get_file_publisher(filepath)
        sev, _ = assign_severity(filepath, sig, pub)
        if sev == "CLEAN":
            return   # signed by known publisher — ignore
        ts = datetime.now().strftime("%H:%M:%S")
        action = ""
        # Auto-quarantine CRITICAL files if watcher is running
        if sev == "CRITICAL":
            ok, dest = quarantine_file(filepath)
            action = f"Auto-quarantined → {os.path.basename(dest)}" if ok else "Quarantine failed"
            self.after(0, self._refresh_quarantine)
        self.after(0, lambda: self._watch_add_event(ts, sev, event_type, filepath, sig, action))
        if self.watch_alert_var.get() and sev in ("CRITICAL","HIGH"):
            self.after(0, lambda s=sev,f=filepath,sg=sig,a=action:
                messagebox.showwarning(
                    f"🚨 Live Watcher — {s} Alert",
                    f"Suspicious file detected!\n\n"
                    f"File: {f}\nSignature: {sg}\n"
                    + (f"\nAuto-action: {a}" if a else "")
                ))

    def _watch_add_event(self, ts, sev, event_type, filepath, sig, action):
        iid = self.wtree.insert("", 0,   # insert at top
            values=(ts, sev, event_type, filepath, sig, action or "—"),
            tags=(sev,))
        self._watch_row_paths[iid] = filepath

    def _watch_clear(self):
        self.wtree.delete(*self.wtree.get_children())
        self._watch_row_paths.clear()

    def _watch_quarantine(self):
        for iid in self.wtree.selection():
            fp = self._watch_row_paths.get(iid,"")
            if fp and os.path.exists(fp):
                ok, r = quarantine_file(fp)
                self._status(f"{'✔' if ok else '✘'} {r}")
                self._refresh_quarantine()
                if ok:
                    self.wtree.delete(iid)
                    self._watch_row_paths.pop(iid, None)

    def _watch_delete(self):
        for iid in self.wtree.selection():
            fp = self._watch_row_paths.get(iid,"")
            if fp and messagebox.askyesno("Delete?", f"Permanently delete:\n{fp}"):
                ok, msg = force_delete(fp)
                self._status(f"{'✔' if ok else '✘'} {msg}")
                if ok:
                    self.wtree.delete(iid)
                    self._watch_row_paths.pop(iid, None)

    def _watch_exclude(self):
        for iid in self.wtree.selection():
            fp   = self._watch_row_paths.get(iid,"")
            note = simpledialog.askstring("Note","Note:",parent=self) or ""
            if add_exclusion("paths", fp, note):
                self.wtree.delete(iid)
                self._watch_row_paths.pop(iid, None)
                self._refresh_exclusions_tab()

    def _watch_explorer(self):
        for iid in self.wtree.selection():
            fp = self._watch_row_paths.get(iid,"")
            if fp and os.path.exists(fp):
                subprocess.Popen(["explorer", "/select,", fp])

    def _watch_export(self):
        fp = filedialog.asksaveasfilename(defaultextension=".csv",
                                          filetypes=[("CSV","*.csv")])
        if not fp:
            return
        with open(fp, "w", encoding="utf-8") as f:
            f.write("Time,Severity,Event,Path,Signature,Action\n")
            for iid in self.wtree.get_children():
                vals = self.wtree.item(iid)["values"]
                def q(v): return '"' + str(v).replace('"','""') + '"'
                f.write(",".join(q(v) for v in vals) + "\n")
        self._status(f"Watcher log exported → {fp}")

    # ══════════════════════════════════════════════════════════════════════════
    # THREAT REPORT TAB
    # ══════════════════════════════════════════════════════════════════════════

    def _build_report_tab(self):
        p = self._tabs["report"]

        tk.Label(p,
                 text="Generate an HTML threat report summarising every finding across all scan tabs. "
                      "Run the scans you want first, then click Generate.",
                 bg=BG, fg="#aaaaaa", font=("Segoe UI", 8), wraplength=1140).pack(padx=8, pady=(8,4))

        ctrl = tk.Frame(p, bg=BG, pady=6)
        ctrl.pack(fill=tk.X, padx=8)

        # Checkboxes for which sections to include
        tk.Label(ctrl, text="Include:", bg=BG, fg=FG,
                 font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=(0,12))
        self.rpt_vars = {}
        sections = [
            ("scan",       "Exe Scanner"),
            ("startup",    "All Startup"),
            ("silent",     "Silent Installs"),
            ("tasks",      "Scheduled Tasks"),
            ("services",   "Services"),
            ("extensions", "Browser Ext"),
            ("hidden",     "Hidden Folders"),
            ("network",    "Network"),
            ("processes",  "Processes"),
            ("watcher",    "Live Watcher"),
        ]
        for col, (key, label) in enumerate(sections):
            v = tk.BooleanVar(value=True)
            self.rpt_vars[key] = v
            tk.Checkbutton(ctrl, text=label, variable=v,
                           bg=BG, fg=FG, selectcolor=ACCENT, activebackground=BG,
                           font=("Segoe UI", 9)).grid(row=0, column=col+1, padx=4)

        btn_row = tk.Frame(p, bg=BG, pady=6)
        btn_row.pack(fill=tk.X, padx=8)
        _btn(btn_row, "📊 Generate & Open HTML Report",
             self._generate_report, GREEN, FG, font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT, padx=4)
        _btn(btn_row, "💾 Save Report As…",
             lambda: self._generate_report(save_as=True), BTN, FG).pack(side=tk.LEFT, padx=4)

        # Preview summary counts
        self.rpt_summary = tk.Text(p, bg=PANEL, fg=FG, height=20,
                                   font=("Courier New", 9), relief=tk.FLAT,
                                   state=tk.DISABLED, wrap=tk.WORD)
        self.rpt_summary.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4,8))

    # ── Report logic ──────────────────────────────────────────────────────────

    def _collect_tree_rows(self, tree: ttk.Treeview):
        """Return list of value-tuples for every row in a Treeview."""
        return [tree.item(iid)["values"] for iid in tree.get_children()]

    def _generate_report(self, save_as=False):
        ts_label = datetime.now().strftime("%Y-%m-%d %H:%M")
        ts_file  = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Collect data from all visible trees
        sections = []

        def _add(key, title, tree, col_headers):
            if not self.rpt_vars.get(key, tk.BooleanVar(value=False)).get():
                return
            rows = self._collect_tree_rows(tree)
            if rows:
                sections.append((title, col_headers, rows))

        _add("scan",       "Exe Scanner",           self.tree,    ["Severity","Name","Path","Publisher","Signature","Date"])
        _add("startup",    "All Startup Sources",   self.startup_tree, ["Severity","Source","Name","Command","Exe","Signed?","Boot ms","Location"])
        _add("silent",     "Silent Installs",       self.sitree,  ["Severity","Score","Program","Publisher","Install Date","Signed?","Flags","Location"])
        _add("tasks",      "Scheduled Tasks",       self.ttree,   ["Name","Path","Execute","Args","State","Author","Severity"])
        _add("services",   "Services",              self.srtree,  ["Display","Name","Path","State","Startup","Severity"])
        _add("extensions", "Browser Extensions",    self.etree,   ["Severity","Browser","Name","Riskiest Perm","Permissions","Ver","Installed","ID"])
        _add("hidden",     "Hidden Folders",        self.htree,   ["Path","Handles"])
        _add("network",    "Network Connections",   self.ntree,   ["PID","Process","Proto","Local","Remote","Status","Exe"])
        _add("processes",  "Running Processes",     self.ptree,   ["PID","Name","Exe","Signed?","User","MB"])
        _add("watcher",    "Live Watcher Events",   self.wtree,   ["Time","Severity","Event","Path","Signed?","Action"])

        total_rows = sum(len(s[2]) for s in sections)

        # Build HTML
        sev_css = {
            "CRITICAL": "#ff3333", "HIGH": "#ff8800", "MEDIUM": "#ffcc00",
            "LOW": "#44cc44", "CLEAN": "#888888", "EXCLUDED": "#5588aa",
        }

        def row_bg(vals):
            sev = str(vals[0]).upper()
            c   = sev_css.get(sev, "")
            return f'style="background:rgba({int(c[1:3],16)},{int(c[3:5],16)},{int(c[5:7],16)},0.08)"' if c else ""

        table_html = ""
        summary_lines = [f"Threat Report — {ts_label}", "=" * 52]
        for title, headers, rows in sections:
            count = len(rows)
            crit  = sum(1 for r in rows if str(r[0]).upper() == "CRITICAL")
            high  = sum(1 for r in rows if str(r[0]).upper() == "HIGH")
            summary_lines.append(f"\n  {title}: {count} findings  (CRITICAL:{crit}  HIGH:{high})")

            th = "".join(f"<th>{h}</th>" for h in headers)
            trs = ""
            for row in rows:
                tds = "".join(f"<td>{str(v)[:200]}</td>" for v in row)
                trs += f"<tr {row_bg(row)}>{tds}</tr>\n"
            table_html += (
                f"<h2 id='{title}'>{title}</h2>"
                f"<p>{count} findings &mdash; "
                f"<span style='color:#ff3333'>CRITICAL:{crit}</span>  "
                f"<span style='color:#ff8800'>HIGH:{high}</span></p>"
                f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>\n"
            )

        summary_lines.append(f"\n  TOTAL: {total_rows} findings across {len(sections)} scanned areas")

        nav = "".join(f"<a href='#{k}'>{t}</a> &nbsp;" for t, _, r in sections for k, _ in
                      [next(((k2, None) for k2, t2, _ in [(k3, s[0], s[2]) for k3,s in
                       zip([x[0] for x in [("scan",""),("startup",""),("silent",""),
                            ("tasks",""),("services",""),("extensions",""),
                            ("hidden",""),("network",""),("processes",""),("watcher","")]], sections)
                       if t2 == t], ("","",None))])]) if False else \
              " &nbsp;".join(f"<a href='#{s[0]}'>{s[0].title()}</a>" for s in sections)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Threat Report — {ts_label}</title>
<style>
  body {{ background:#0d0d1f; color:#e0e0e0; font-family:'Segoe UI',Arial,sans-serif;
          margin:0; padding:20px; }}
  h1   {{ color:#e94560; border-bottom:2px solid #e94560; padding-bottom:8px; }}
  h2   {{ color:#88aaff; margin-top:32px; border-left:4px solid #0f3460;
          padding-left:10px; }}
  p    {{ color:#aaaaaa; font-size:0.9em; }}
  nav  {{ background:#16213e; padding:10px 16px; border-radius:6px;
          margin-bottom:20px; font-size:0.85em; }}
  nav a {{ color:#88aaff; text-decoration:none; margin-right:12px; }}
  nav a:hover {{ color:#e94560; }}
  table {{ width:100%; border-collapse:collapse; font-size:0.82em;
           margin-bottom:24px; }}
  th   {{ background:#0f3460; color:#fff; padding:6px 8px; text-align:left; }}
  td   {{ padding:5px 8px; border-bottom:1px solid #1a2a4a;
          word-break:break-all; max-width:320px; }}
  tr:hover td {{ background:#1a2a4a; }}
  .badge-CRITICAL {{ color:#ff3333; font-weight:bold; }}
  .badge-HIGH     {{ color:#ff8800; font-weight:bold; }}
  .badge-MEDIUM   {{ color:#ffcc00; }}
  .badge-LOW      {{ color:#44cc44; }}
  .meta {{ color:#666688; font-size:0.8em; margin-top:40px; border-top:1px solid #333; padding-top:8px; }}
</style>
</head>
<body>
<h1>🛡️ Threat Report</h1>
<p>Generated: {ts_label} &nbsp;|&nbsp; Host: {socket.gethostname()} &nbsp;|&nbsp;
   Total findings: <strong>{total_rows}</strong></p>
<nav>{nav}</nav>
{table_html}
<div class="meta">Generated by Silent Install &amp; Malware Scanner v6.0</div>
</body>
</html>"""

        # Save
        if save_as:
            out = filedialog.asksaveasfilename(
                defaultextension=".html", filetypes=[("HTML","*.html")],
                initialfile=f"threat_report_{ts_file}.html")
        else:
            import tempfile
            out = os.path.join(tempfile.gettempdir(), f"threat_report_{ts_file}.html")

        if not out:
            return
        try:
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
            os.startfile(out)    # open in default browser
            self._status(f"Report saved & opened: {out}")
        except Exception as e:
            messagebox.showerror("Report error", str(e))
            return

        # Update summary text widget
        summary_text = "\n".join(summary_lines)
        self.rpt_summary.config(state=tk.NORMAL)
        self.rpt_summary.delete("1.0", tk.END)
        self.rpt_summary.insert(tk.END, summary_text)
        self.rpt_summary.config(state=tk.DISABLED)

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _browse(self, var):
        d = filedialog.askdirectory()
        if d:
            var.set(d)

    def _status(self, msg):
        self.after(0, lambda: self.status_var.set(msg))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("Treeview",
                    background="#16213e", foreground="#e0e0e0",
                    fieldbackground="#16213e", rowheight=22,
                    font=("Segoe UI", 9))
    style.configure("Treeview.Heading",
                    background="#0f3460", foreground="#ffffff",
                    font=("Segoe UI", 9, "bold"), relief=tk.FLAT)
    style.map("Treeview", background=[("selected","#0f3460")])
    style.configure("TNotebook", background="#1a1a2e", borderwidth=0)
    style.configure("TNotebook.Tab",
                    background="#0f3460", foreground="#ffffff",
                    padding=(9,5), font=("Segoe UI", 9))
    style.map("TNotebook.Tab", background=[("selected","#e94560")])
    style.configure("TCombobox", fieldbackground="#0f3460", background="#0f3460",
                    foreground="#e0e0e0")

    app = ScannerApp()
    app.mainloop()
