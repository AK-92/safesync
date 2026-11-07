# SafeSync 🛡️

> **Hardened, air-gapped media backup for macOS.**  
> Zero silent corruption, thermal throttling protection, and automatic cryptographic verification for external SSDs.

[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://apple.com/macos)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#dependencies)
[![Privacy](https://img.shields.io/badge/privacy-100%25%20offline-blue.svg)](#privacy--security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚠️ The Silent Corruption Problem: Why Fast SSDs Corrupt Media

Even when modern external NVMe SSDs (such as the Samsung T7, SanDisk Extreme, or Crucial X-Series) advertise high-speed ratings of 1,050–2,800 MB/s, operating sustained high-throughput transfers—especially on drives with **APFS Encryption** enabled—frequently leads to **silent data corruption**:

1. **Thermal Sags & Silent Packet Drops:** Sustained, unthrottled burst writes heat compact external drive controllers past 70°C. To prevent thermal shutdown, the controller aggressively throttles voltage and I/O. Under sustained load combined with on-the-fly APFS encryption, USB packet drops and bus resets occur silently without throwing OS error codes. Corrupted blocks are written to physical NAND flash—leaving permanent **horizontal grey or black bars across high-resolution photos, frame tearing in 4K videos, or damaged SQLite databases inside `.photoslibrary` bundles**.
2. **The macOS RAM Buffer Deception:** macOS buffers file writes in the Unified Buffer Cache in RAM. If you run standard checksum or copy verification tools immediately after a transfer, macOS reads the clean file copies lingering in RAM rather than reading the physical SSD silicon. The verification tool gives a false-positive **100% MATCH**, leading you to believe your backup succeeded, only to discover corrupted photos months later when it is too late.
3. **Apple Photos Library Traps:** Backing up live Apple Photos libraries (`.photoslibrary`) with standard tools risks creating nested library folders, crashing on volatile daemon cache journals (`photolibraryd`, `photoanalysisd`), or littering AppleDouble `._*` sidecar files that corrupt library databases.

### 🛡️ How SafeSync Solves This
SafeSync was engineered specifically to eliminate these hardware and operating system failure modes:
- **Thermal-Safe Rate Limiting:** Default throttled transfer speed (`120 MB/s`) keeps external drive bridge controllers cool and prevents USB bus voltage drops.
- **Uncached Cryptographic Verification:** All new files are verified using `fcntl(F_NOCACHE)` SHA-256 hashes—bypassing macOS RAM cache to read directly from physical NAND flash silicon.
- **Photos Library & macOS Bundle Intelligence:** Automatically ignores transient Apple daemon cache journals, normalizes paths to prevent nested bundles, and enforces safety boundaries with zero third-party dependencies.

---

## ⚡ The Default Mode: Smart Incremental

**You don't need to remember any complex flags!** By default, running:

```bash
safesync <SOURCE_FOLDER> <DESTINATION_FOLDER>
```

executes **Smart Incremental Mode**:
1. **Instant Skip for Historical Files:** Scans 50–100+ GB of older, unchanged media by size and timestamp in **~5 to 10 seconds**.
2. **Thermal-Safe Transfer:** Copies only new or modified files at a cool, throttled 120 MB/s to protect the SSD controller from thermal throttling.
3. **Automatic Cryptographic Verification:** Immediately runs uncached **SHA-256 cryptographic hash checks** on all newly transferred files, reading them back directly from physical disk to guarantee zero bit-rot or packet drops.
4. **Fast Runtime:** Routine incremental backups finish in minutes instead of requiring a prolonged full-drive rewrite.

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
                       of all newly transferred files. Perfect for routine backups!
  -a, --full-audit     Full Audit / Scrub Mode. Runs cryptographic checksum verification across 100%
                       of historical files via rsync (recommended periodically or before wiping a Mac).
  -q, --quick          Quick-scan mode. Size + timestamp comparison only (skips post-transfer hashing).
  -n, -d, --dry-run    Simulation mode. Simulates the sync without writing any files to disk.
  -i, --confirm        Interactive mode. Scans first and prompts [Y/n] before transferring files.
  -p, --prune          Prune / Mirror mode. Deletes files from destination that no longer exist in
                       source (gated behind confirmation to protect against accidental loss).
  -v, --verbose        Verbose mode. Streams per-file logs and displays full transfer report in terminal.
  -b, --bw <LIMIT>     Bandwidth rate limit (e.g. 120M, 250M, 50M). Default is 120M (thermal-safe).
  -m, --max, --full    Uncapped full throttle (no bandwidth limit). Recommended for transfers < 20 GB.
  -h, --help           Show help message.
  -V, --version        Show version number.
```

### Examples

#### 1. Routine Smart Backup (Default — Fast & Cryptographically Verified)
```bash
safesync "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

#### 2. Annual Full Scrub (Audits 100% of Historical Files)
Use this periodically or before wiping/reformatting a Mac:
```bash
safesync -a "/Users/<username>/Pictures/Photos Library.photoslibrary" "/Volumes/BackupSSD/Photos Library.photoslibrary"
```

#### 3. Dry-Run Simulation (Test without Modifying Files)
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

During execution, `safesync` displays an in-place, unbuffered progress bar driven by a background heartbeat thread:

```text
 ⠋ [01:15] [SmartSync] [==========----------] 52.0% (14,200/27,297) [New/Mod: 42] | originals/2/228F1A3E.mov
```

Followed by automatic hash verification of all new files:
```text
 ⠋ [01:45] [Verifying Hashes] [====================] 100.0% (42/42) | originals/2/228F1A3E.mov
```

* **`⠋ ⠙ ⠹...`:** Active drive heartbeat (spins continuously even while multi-gigabyte video files hash).
* **`[01:15]`:** Real-time elapsed timer.
* **`[SmartSync]`:** Active mode indicator (`[Simulating]`, `[FullAudit]`, or `[SmartSync]`).
* **`[===---]`:** Visual completion bar.
* **`[New/Mod: 42]`:** Live count of new or modified files transferred.
* **`originals/...mov`:** Active file currently being checked.

---

## Common Error Codes Reference

If `rsync` ever exits with an error status code, use this reference table:

| Exit Code | Meaning | Cause & Recommended Action |
| :---: | :--- | :--- |
| **0** | **Success** | All files verified bit-for-bit identical. |
| **1** | **Syntax / Usage Error** | Missing path or unrecognized flag. Check `safesync --help`. |
| **11** | **File I/O Error** | Disk is full, file system error, or hardware failure. Check free disk space. |
| **12** | **Protocol Stream Error** | Cable was unseated or drive controller disconnected during transfer. |
| **20** | **Interrupted** | The user pressed `Ctrl + C` or process was terminated. Safe to re-run. |
| **23** | **Partial Transfer** | A temporary file vanished before copying. *(Safe to ignore if media matches)*. |
| **24** | **Vanished Source File** | A temporary file was deleted while `rsync` was reading. Handled automatically by `safesync`. |
| **30** | **Timeout** | Communication timed out (e.g. drive went to sleep or USB hub crashed). |

---

## Best Practices for External SSDs (Samsung T7, SanDisk Extreme, Crucial X-Series)

1. **Direct Port Connection:** Always connect directly to a Mac Thunderbolt/USB-C port using the original brand cable. Avoid unpowered USB hubs during large transfers.
2. **Drive Filesystem:** If using the drive exclusively on macOS, format it as **APFS (GUID Partition Table)**. Avoid splitting a single drive into both exFAT and APFS partitions for backups.
3. **The 3-2-1 Rule:** Never purge camera cards or source volumes until verified files exist on **two separate physical drives**.

---

## License

Distributed under the [MIT License](LICENSE). 100% Free and Open Source.
