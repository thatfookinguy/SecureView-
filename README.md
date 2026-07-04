# SecureView — Windows Security Scanner

A standalone desktop tool for Windows that scans your PC for hidden folders, unsigned/suspicious files, risky startup entries, malicious services, silent/background installs, running processes, and live network connections — then lets you inspect, copy the file location, quarantine, permanently delete, force-stop, or exclude them, right from a graphical window with tabs.

This is a script you run locally on your Windows PC (not a website), because it has to read System32, your registry, running processes, and network connections directly.

## Requirements

- Windows, Python 3.9+ (comes with `tkinter` built in)
- Recommended packages for full functionality:
  ```
  pip install psutil pywin32 requests
  ```
  - `psutil` — process & network connection scanning
  - `pywin32` — file ownership / handle checks
  - `requests` — VirusTotal / AbuseIPDB reputation lookups
  - The tool still runs without these, but some tabs (Network, Processes, reputation checks) will be limited.
- Run as **Administrator** for best results (needed to see everything in System32, protected registry keys, and to force-stop/quarantine some processes).

## How to run it

1. Copy the `SecureView` folder to your Windows PC (anywhere, e.g. your Desktop).
2. Open a terminal (or right-click → "Run with PowerShell"/Command Prompt) **as Administrator** in that folder.
3. Run:
   ```
   python SecureView.py
   ```

No installation beyond the optional pip packages above — everything else uses tools already built into Windows.

## What it does — tabs

- **🔍 Exe Scanner** — scans common folders (Program Files, AppData, ProgramData, Temp, etc.) or any folder you point it at. Finds hidden folders/files, unsigned or suspicious executables, and flags NTFS Alternate Data Streams (data hidden behind an ordinary-looking file), download "Mark of the Web" zone info, and file entropy (a sign of packed/encrypted malware).
- **🚀 All Startup** — everything set to run automatically: registry Run/RunOnce keys, the Startup folder, AppInit_DLLs, Image File Execution Options (IFEO) debugger hijacks, Group Policy logon scripts, LSA security packages, and scheduled boot tasks — all in one place, with a "boot impact" view.
- **🕵️ Silent Installs** — detects software that installed itself recently without a normal visible install flow (no shortcut created, no uninstall entry visible, suspicious install timing) — a common sign of bundled adware or silently-dropped malware.
- **🗓️ Tasks** — every Scheduled Task, its trigger, action, and author, so you can spot ones that re-launch malware after every reboot or on a timer.
- **⚙️ Services** — every Windows service, its executable path, state, and startup type. Flags non-Microsoft services running from unusual locations.
- **🧩 Browser Ext** — scans installed Chrome/Edge/Firefox extensions and flags ones with dangerous permissions (e.g. reading all your browsing data, intercepting requests) — common for ad-injectors and info-stealers disguised as extensions.
- **📂 Hidden Folders** — finds folders with the Windows "hidden" attribute set across common malware hiding spots.
- **🌐 Network** — every active network connection, which process owns it, and where it's going. Includes:
  - **🛡️ Check IP Reputation / Check All IPs** — looks up a remote IP against AbuseIPDB and VirusTotal (bring your own free API key, entered right in the tab) to see its abuse score, **country/geolocation**, ISP, and whether it matches known botnet C2 or Tor exit-node lists — so you can tell if a connection is a spyware/trojan/keylogger phoning home to a remote attacker, or just legitimate traffic.
  - **🔪 Kill Process**, **🌐 Lookup DNS** (reverse hostname), **📂 Open Exe Location**, **🚫 Exclude Exe** from future scans.
- **💻 Processes** — every running program, its file path, signature status, owning user, and memory use. Force-stop, or force-stop and quarantine its file, in one click.
- **🧪 Quarantine** — a safe holding area. Quarantined files are moved (not destroyed) so you can restore them if you change your mind, or delete them forever once you're sure.
- **🚫 Exclusions** — paths, publishers, file hashes, or browser extension IDs you never want flagged again. Anything listed here is silently skipped across **every** scan tab. Add manually or with one click ("Exclude Exe") from a result.
- **🔴 Live Watcher** — a background monitor that keeps watching for new suspicious startup entries, new unsigned processes, or new outbound connections while the tool is open, and logs each event with a timestamp — this is how it catches scripts/background processes that try to install or phone home *after* your last scan, not just at the moment you clicked Scan.
- **📊 Report** — generates a self-contained HTML threat report (with a summary chart) combining every tab's findings, which you can save and share.

Every result gets a **risk/severity level** — Critical, High, Medium, Low, Clean, or Excluded — based on digital signature status, publisher trust, file location, filename pattern matching (known keylogger/clipper/RAT/trojan naming), entropy, and (for network) live reputation data.

## Notes on API keys (optional, free)

- **VirusTotal** and **AbuseIPDB** keys are optional and only used for reputation/geolocation lookups on the Network tab. Get a free key at virustotal.com or abuseipdb.com and paste it into the field in that tab — nothing is sent anywhere until you click a "Check" button, and keys are never written to disk by this tool.
- Without a key, the tool still shows connections and offline C2/Tor-exit blocklist matches, just without live reputation/country data.

## Safety

- Quarantine moves files to a holding folder rather than deleting them immediately — always available to restore.
- Force-stop and delete actions ask for confirmation before acting.
- Nothing is uploaded anywhere except the IP/hash you explicitly submit to VirusTotal/AbuseIPDB when you click a "Check" button (and only if you've entered an API key).
