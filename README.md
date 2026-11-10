# SafeSync 🛡️

> **A macOS folder sync utility with optional SHA-256 comparison and repair.**

[![Platform](https://img.shields.io/badge/platform-macOS%20only-lightgrey.svg)](https://apple.com/macos)
[![macOS Version](https://img.shields.io/badge/macOS-14%20and%20above-blue.svg)](https://apple.com/macos)
[![Dependencies](https://img.shields.io/badge/dependencies-none%20(zero%20installs)-brightgreen.svg)](#dependencies)
[![Privacy](https://img.shields.io/badge/privacy-100%25%20offline-blue.svg)](#privacy--security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What SafeSync checks

- Default sync uses rsync's normal size and modification-time comparisons to decide what to copy. It does not checksum files that rsync skips.
- Newly copied files in smart mode are compared with SHA-256 hashes of the source and destination.
- Full audit hashes the regular files it finds, reports content differences, and can replace mismatched destination files from the source.
- A bandwidth limit controls rsync's transfer rate. It is not a thermal guarantee or a hardware corruption safeguard.
- The optional macOS `F_NOCACHE` request avoids retaining hashed file data in the kernel file cache when supported. It cannot bypass a drive's controller cache or establish NAND-level durability.

For a consistent audit or backup, close applications that may be changing the source (including Photos for a Photos library) and wait for the operation to finish. Keep another independent backup. A checksum match verifies the bytes returned by the filesystem during that read; it does not certify the drive or cable.

---

## ⚡ The Default Mode: Smart Incremental

**You don't need to remember any complex flags!** By default, running:

```bash
safesync <SOURCE_FOLDER> <DESTINATION_FOLDER>
```

executes **Smart Incremental Mode**:
1. **Incremental Selection:** Rsync compares file size and modification time to select files to copy. Scan time depends on the filesystem and number of files.
2. **Rate-limited Transfer:** By default, rsync is limited to 120 MB/s (subject to the installed rsync implementation).
3. **Content Check:** Newly transferred files are SHA-256 compared with their source files after copying.
4. **Incremental Copy:** Unchanged files selected by rsync are skipped.

---

## Quick Start (Finder Drag-and-Drop)

1. Open **Terminal**.
2. Type `safesync ` *(with a trailing space)*.
3. **Drag and drop** your **Source folder** from Finder into Terminal.
4. **Drag and drop** your **Destination folder** from Finder into Terminal.
5. Press **Enter**.

```bash
# Example syntax:
safesync "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

> [!TIP]
> **No trailing-slash anxiety!** `safesync` automatically normalizes folder paths behind the scenes.
>
> **Finder Drag-and-Drop Tip:** When you drag a folder into Terminal, macOS automatically escapes spaces with backslashes (e.g. `Photos\ Library.photoslibrary`). Leave it as is—do **not** remove the slashes or add extra quotes, it works out of the box!

---

## Available Modes & Options

```text
USAGE:
  safesync [OPTIONS] <SOURCE_FOLDER> <DESTINATION_FOLDER>

OPTIONS:
  (default)            Smart Incremental Mode. Fast size/time scan + full SHA-256 hash verification
                       of newly transferred files; skipped files are not checksummed.
  -a, --full-audit     Hash source and destination files, then repair content mismatches.
  -q, --quick          Quick-scan mode. Size + timestamp comparison only (skips post-transfer hashing).
  -n, -d, --dry-run    Simulation mode. Does not modify the destination; writes a local report.
  -i, --confirm        Interactive mode. Scans first and prompts [Y/n] before transferring files.
  -p, --prune          Prune / Mirror mode. Deletes files from destination that no longer exist in
                       source (gated behind confirmation to protect against accidental loss).
  -v, --verbose        Verbose mode. Streams per-file logs and displays full transfer report in terminal.
  -b, --bw <LIMIT>     Rsync bandwidth limit (e.g. 120M, 250M, 50M). Default is 120M.
  -m, --max, --full    Remove the rsync bandwidth limit.
  -h, --help           Show help message.
  -V, --version        Show version number.
```

### Examples

#### 1. Routine Smart Backup
```bash
safesync "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

#### 2. Full Content Audit and Repair
```bash
safesync -a "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

#### 3. Dry-Run Simulation (Does Not Modify the Destination)
```bash
safesync -d "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

#### 4. Interactive Pre-Flight Confirmation (Prompts Before Copying)
```bash
safesync -i "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

#### 5. Mirror / Prune Backup (Cleans up deleted files at destination)
```bash
safesync -p "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

#### 6. Small Transfer (< 20 GB) at Full Throttle
```bash
safesync -m "/Users/<username>/Movies/Trip_Video" "/Volumes/BackupSSD/Trip_Video"
```

#### 7. Verbose Mode with Report Displayed in Terminal
```bash
safesync -v "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

---

## The Terminal Dashboard

During execution, `safesync` displays an in-place, unbuffered progress bar driven by a background heartbeat thread, and upon completion commits a static **100% completed progress bar** directly to your terminal history:

```text
# 1. Live Transfer Progress:
 [✓] [01:15] ⚡ [SmartSync] [====================] 100.0% (27,297/27,297) [🟢 40 | 🟡 2] | Transfer complete [6.3 GB]

# 2. SHA-256 Content Comparison:
 [✓] [01:45] 🔒 [Comparing file contents] [====================] 100.0% (42/42) | Hashes match

# 3. High-Visibility Final Outcome Banner (Green for Success, Yellow for Simulation, Red for Issues):
══════════════════════════════════════════════════════════════
 [✓] ✨ SMART SYNC SUCCESS (01m 45s):
     - 📦 42 files (6.3 GB) transferred and checksum compared (40 new, 2 modified).
     - ⚡ Historical files skipped instantly in seconds.
     📄 Detailed report: file:///Users/<username>/Library/Logs/safesync/safesync_report.txt
     💡 Quick view:      open ~/Library/Logs/safesync/safesync_report.txt
     📂 In Finder:       open -R ~/Library/Logs/safesync/safesync_report.txt
══════════════════════════════════════════════════════════════
```

* **`[✓]`:** Static completion checkmark (replaces the active spinner `⠋` when the phase completes).
* **`[01:15]`:** Real-time elapsed timer.
* **`⚡ [SmartSync]`:** Active mode indicator (`🔍 [Simulating]`, `🛡️  [FullAudit]`, or `⚡ [SmartSync]`).
* **`[====================]`:** High-contrast 20-character visual progress bar.
* **`[🟢 40 | 🟡 2]`:** Categorized breakdown of **🟢 New** and **🟡 Modified** files.
* **`[6.3 GB]`:** Real-time human-readable volume of data transferred (in B, KB, MB, GB, or TB).
* **Checksum match:** Source and destination file contents returned the same SHA-256 digest during comparison.
* **Theme-Adaptive Dimming:** Metadata headers utilize ANSI SGR 2 (`\033[2m`) to subtly dim configuration details across dark, light, and solarized palettes.
* **Yellow Attention Gates:** Prompts awaiting user approval (such as creating a new destination folder) are framed in bold yellow border boxes.

### 📄 Audit & Transfer Reports

After every operation, SafeSync writes a full audit report to the macOS standard logging folder:
```
~/Library/Logs/safesync/safesync_report.txt
```
- Saved with secure `0600` permissions (owner read/write only).
- Stays neatly out of sight from your Desktop.
- Easily inspected anytime via `cat ~/Library/Logs/safesync/safesync_report.txt` or opened in macOS Console / TextEdit via `open ~/Library/Logs/safesync/safesync_report.txt`.

---

## Common Error Codes Reference

If `rsync` ever exits with an error status code, use this reference table:

| Exit Code | Meaning | Cause & Recommended Action |
| :---: | :--- | :--- |
| **0** | **Success** | The selected operation completed without a reported error. |
| **1** | **Syntax / Usage Error** | Missing path or unrecognized flag. Check `safesync --help`. |
| **11** | **File I/O Error** | Disk is full, file system error, or hardware failure. Check free disk space. |
| **12** | **Protocol Stream Error** | Cable was unseated or drive controller disconnected during transfer. |
| **20** | **Interrupted** | The user pressed `Ctrl + C` or process was terminated. Safe to re-run. |
| **23** | **Partial Transfer** | A transfer did not complete. Review the rsync error and rerun after resolving it. |
| **24** | **Vanished Source File** | A source file changed or disappeared during transfer. SafeSync treats this run as incomplete. |
| **30** | **Timeout** | Communication timed out (e.g. drive went to sleep or USB hub crashed). |

---

## Best Practices for External SSDs (Samsung T7, SanDisk Extreme, Crucial X-Series)

1. **Direct Port Connection:** Always connect directly to a Mac Thunderbolt/USB-C port using the original brand cable. Avoid unpowered USB hubs during large transfers.
2. **Drive Filesystem:** If using the drive exclusively on macOS, format it as **APFS (GUID Partition Table)**. Avoid splitting a single drive into both exFAT and APFS partitions for backups.
3. **The 3-2-1 Rule:** Never purge camera cards or source volumes until verified files exist on **two separate physical drives**.

---

## License

Distributed under the [MIT License](LICENSE). 100% Free and Open Source.
