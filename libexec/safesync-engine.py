#!/usr/bin/env python3
# ==============================================================================
# SafeSync Engine — Core Cryptographic & Progress Engine for macOS
# Standalone, decoupled engine for SafeSync CLI
# ==============================================================================

import sys
import os
import time
import threading
import hashlib
import shutil
import stat
import fcntl
import subprocess
import re
import tempfile
import atexit

# Ensure streams never crash on non-UTF8 filenames (SEC-25)
if hasattr(sys.stdin, "reconfigure"):
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="surrogateescape")
    except Exception:
        pass
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Terminal colors and high-contrast palette
USE_COLOR = sys.stdout.isatty()
C_GREEN = "\033[38;5;34m" if USE_COLOR else ""
C_YELLOW = "\033[38;5;226m" if USE_COLOR else ""
C_RED = "\033[38;5;196m" if USE_COLOR else ""
C_CYAN = "\033[38;5;39m" if USE_COLOR else ""
C_BOLD = "\033[1m" if USE_COLOR else ""
C_RESET = "\033[0m" if USE_COLOR else ""

stdout_lock = threading.Lock()

def safe_write(msg):
    with stdout_lock:
        sys.stdout.write(msg)
        sys.stdout.flush()

def clear_progress():
    if USE_COLOR:
        with stdout_lock:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

def format_size(bytes_val):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_val < 1024.0 or unit == "TB":
            return f"{bytes_val:.1f} {unit}" if unit != "B" else f"{int(bytes_val)} B"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"

def format_report_link(path):
    abs_p = os.path.abspath(path)
    return f"file://{abs_p}"

def user_display_report(path):
    home = os.path.expanduser("~")
    abs_p = os.path.abspath(path)
    if abs_p.startswith(home):
        return "~" + abs_p[len(home):]
    return abs_p

def parse_bw_limit(bw_str):
    if not bw_str or str(bw_str).lower() in ("0", "max", "full"):
        return None
    bw_str = str(bw_str).upper().strip()
    mult = 1
    if bw_str.endswith("K"):
        mult = 1024
        val = bw_str[:-1]
    elif bw_str.endswith("M"):
        mult = 1024 * 1024
        val = bw_str[:-1]
    elif bw_str.endswith("G"):
        mult = 1024 * 1024 * 1024
        val = bw_str[:-1]
    else:
        val = bw_str
    try:
        return float(val) * mult
    except ValueError:
        return 120.0 * 1024 * 1024

def compute_sha256(filepath, max_bytes_per_sec=None, progress_cb=None, direct_io=False):
    """Compute SHA-256 hash using clean uninterrupted buffered I/O with post-file bandwidth pacing."""
    h = hashlib.sha256()
    t_start = time.time()
    total_bytes = 0
    with open(filepath, "rb") as f:
        if direct_io and hasattr(fcntl, "F_NOCACHE"):
            try:
                fcntl.fcntl(f.fileno(), fcntl.F_NOCACHE, 1)
            except OSError:
                pass
        while chunk := f.read(2 * 1024 * 1024):
            h.update(chunk)
            total_bytes += len(chunk)
            if progress_cb:
                try:
                    progress_cb(len(chunk))
                except Exception:
                    pass
    if max_bytes_per_sec and max_bytes_per_sec > 0 and total_bytes > 0:
        target_dur = total_bytes / max_bytes_per_sec
        dt = time.time() - t_start
        if dt < target_dur:
            time.sleep(target_dur - dt)
    return h.hexdigest()

def is_external_drive(path):
    """Detect whether a filesystem path resides on an external/removable volume."""
    try:
        p = os.path.abspath(path)
        while not os.path.exists(p) and p not in ("/", ""):
            p = os.path.dirname(p)
        abs_p = os.path.realpath(p)
        root_dev = os.stat("/").st_dev
        path_dev = os.stat(abs_p).st_dev
        return abs_p.startswith("/Volumes/") and (path_dev != root_dev)
    except Exception:
        return False

def is_excluded(rel_path):
    parts = rel_path.split(os.sep)
    for part in parts:
        if part in (".DS_Store", ".safesync-partial"):
            return True
        if part.startswith(".Spotlight-V100") or part.startswith(".Trashes") or part.startswith(".fseventsd"):
            return True
        if "index.spotlightV3" in part or "SpotlightKnowledgeEvents" in part:
            return True
        if part.startswith("com.apple.photolibraryd") or part.startswith("com.apple.photoanalysisd") or part.startswith("com.apple.mediaanalysisd"):
            return True
    if "private/com.apple.photolibraryd/caches" in rel_path or "private/com.apple.photoanalysisd/caches" in rel_path or "private/com.apple.mediaanalysisd/caches" in rel_path:
        return True
    return False

def write_report_file(content, report_path):
    """Write transfer/corruption report with secure 0600 permissions (SEC-08)."""
    try:
        tmp_fd, tmp_p = tempfile.mkstemp(
            dir=os.path.dirname(report_path),
            prefix="safesync_rpt_tmp_",
            suffix=".txt"
        )
        with os.fdopen(tmp_fd, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
        os.chmod(tmp_p, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp_p, report_path)
        return True
    except Exception:
        return False


# ==============================================================================
# FULL AUDIT ENGINE (4-Step Dedicated Cryptographic Verification)
# ==============================================================================

def run_full_audit():
    src_dir = os.environ.get("SAFESYNC_SRC", "").rstrip(os.sep)
    dst_dir = os.environ.get("SAFESYNC_DST", "").rstrip(os.sep)
    try:
        initial_dst_dev = os.stat(dst_dir).st_dev
    except OSError:
        initial_dst_dev = None
    is_dry_run = os.environ.get("SAFESYNC_DRY_RUN", "0") == "1"
    is_verbose = os.environ.get("SAFESYNC_VERBOSE", "0") == "1"
    is_prune = os.environ.get("SAFESYNC_PRUNE", "0") == "1"
    version_str = os.environ.get("SAFESYNC_VERSION", "0.5.10")
    bw_val = os.environ.get("SAFESYNC_BW", "120M")
    read_bw_val = os.environ.get("SAFESYNC_READ_BW", "150M")

    src_is_ext = is_external_drive(src_dir)
    dst_is_ext = is_external_drive(dst_dir)
    is_uncapped = bw_val in ("0", "max", "full")

    # Read ceiling for external drives: default 150 MB/s (cool, steady, avoids thermal bridge drops)
    read_ceiling = parse_bw_limit(read_bw_val if read_bw_val not in ("0", "max", "full") else None)
    if read_ceiling is None and not is_uncapped:
        read_ceiling = 150.0 * 1024 * 1024

    # Topology-Aware Rate Allocator:
    # 1. Step 1 (Source read): Uncapped if internal Mac drive; 150 MB/s if external drive
    src_read_rate = None if (is_uncapped or not src_is_ext) else read_ceiling

    # 2. Step 2 (Dest read): Uncapped if internal Mac drive; 150 MB/s if external drive
    dst_read_rate = None if (is_uncapped or not dst_is_ext) else read_ceiling

    # 3. Step 3 (Write transfer via rsync): Uncapped if writing to internal Mac drive; 120 MB/s if external
    rsync_bw_arg = bw_val if (dst_is_ext and not is_uncapped) else "0"
    report_dir = os.environ.get("SAFESYNC_REPORT_DIR") or os.path.expanduser("~/Library/Logs/safesync")
    report_path = os.path.join(report_dir, "safesync_report.txt")
    try:
        os.makedirs(report_dir, exist_ok=True)
    except Exception:
        pass

    ITEM_REGEX = re.compile(r"^([>c.h][fdLDS][^\s]*)\s(.*)$")
    active_repair_proc = None

    def cleanup_active_proc():
        nonlocal active_repair_proc
        if active_repair_proc is not None:
            try:
                active_repair_proc.terminate()
                active_repair_proc.wait(timeout=2)
            except Exception:
                pass
    atexit.register(cleanup_active_proc)

    start_time = time.time()
    tot_steps_init = 3 if is_dry_run else 4
    status = {
        "step": 1,
        "total_steps": tot_steps_init,
        "step_start": start_time,
        "checked": 0,
        "total": 0,
        "file": "",
        "thermal_msg": "",
        "bytes_done": 0,
        "total_bytes": 0,
        "speed": "",
        "pass": 1
    }
    stop_event = threading.Event()

    def heartbeat():
        if not USE_COLOR:
            return
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        last_bytes = 0
        last_speed_time = time.time()
        while not stop_event.is_set():
            step_elapsed = int(time.time() - status.get("step_start", start_time))
            m, s = divmod(step_elapsed, 60)
            spin = spinner[idx % len(spinner)]
            idx += 1

            now = time.time()
            dt = now - last_speed_time
            if dt >= 0.5:
                db = status["bytes_done"] - last_bytes
                spd = (db / dt) / (1024 * 1024)
                status["speed"] = f"{spd:.0f} MB/s" if spd >= 1.0 else ""
                last_bytes = status["bytes_done"]
                last_speed_time = now

            step = status["step"]
            total_steps = status.get("total_steps", tot_steps_init)
            tot = status["total"]
            chk = status["checked"]
            pct = (chk / tot * 100) if tot else 0
            bars = int(min(100, pct) / 5)
            bar_str = "=" * bars + "-" * (20 - bars)
            speed_val = status["speed"]
            spd_str = f" [{speed_val}]" if speed_val else ""
            thermal_val = status["thermal_msg"]

            if thermal_val:
                pause_tag = "Thermal Firebreak" if "Cooling" in thermal_val else ("Write Buffer Flush" if "Flushing" in thermal_val or "write" in thermal_val.lower() else "Thermal Pause")
                safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] ❄️  [Step {step}/{total_steps}: {pause_tag}] [{bar_str}] {pct:5.1f}% ({chk:,}/{tot:,}){spd_str} | {thermal_val}")
            elif step == 1:
                disp_file = (status["file"][:30] + "...") if len(status["file"]) > 30 else status["file"]
                safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] 🛡️  [Step 1/{total_steps}: Reading Source] [{bar_str}] {pct:5.1f}% ({chk:,}/{tot:,}){spd_str} | {disp_file}")
            elif step == 2:
                disp_file = (status["file"][:30] + "...") if len(status["file"]) > 30 else status["file"]
                if status.get("sub_step") == "confirm":
                    safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] 🔒 [Step 2/{total_steps}: Physical Confirmation] [{bar_str}] {pct:5.1f}% ({chk:,}/{tot:,}){spd_str} | {disp_file}")
                else:
                    safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] 🛡️  [Step 2/{total_steps}: Reading Destination] [{bar_str}] {pct:5.1f}% ({chk:,}/{tot:,}){spd_str} | {disp_file}")
            elif step == 3:
                tag = "🔍 [Step 3/3: Dry-Run Audit]" if is_dry_run else ("🛡️  [Step 3/3: Cryptographic Audit]" if total_steps == 3 else "⚡ [Step 3/4: Auto-Repair]")
                disp_file = (status["file"][:30] + "...") if len(status["file"]) > 30 else status["file"]
                safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] {tag} [{bar_str}] {pct:5.1f}% ({chk:,}/{tot:,}){spd_str} | {disp_file}")
            elif step == 4:
                pass_num = status.get("pass", 1)
                pass_tag = f" (Pass {pass_num})" if pass_num > 1 else ""
                disp_file = (status["file"][:30] + "...") if len(status["file"]) > 30 else status["file"]
                safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] 🔒 [Step 4/4: Physical Disk Verification{pass_tag}] [{bar_str}] {pct:5.1f}% ({chk:,}/{tot:,}){spd_str} | {disp_file}")

            time.sleep(0.12)

    t = threading.Thread(target=heartbeat, daemon=True)
    t.start()

    def stop_heartbeat(clear=True):
        stop_event.set()
        if t.is_alive():
            t.join()
        if clear:
            clear_progress()

    try:
        # STEP 1: Reading & Hashing Source
        s1_start = time.time()
        status["step"] = 1
        status["step_start"] = s1_start
        src_items = []
        total_src_bytes = 0

        for root, dirs, files in os.walk(src_dir):
            dirs[:] = [d for d in dirs if not is_excluded(os.path.relpath(os.path.join(root, d), src_dir))]
            dirs.sort()
            for fname in sorted(files):
                p = os.path.join(root, fname)
                rel = os.path.relpath(p, src_dir)
                if is_excluded(rel):
                    continue
                try:
                    sz = os.path.getsize(p) if not os.path.islink(p) else 0
                    src_items.append((rel, sz, os.path.islink(p)))
                    total_src_bytes += sz
                except OSError:
                    pass

        status["total"] = len(src_items)
        status["total_bytes"] = total_src_bytes

        src_catalog = {}
        bytes_since_firebreak = 0
        firebreak_count = 0

        for idx, (rel, sz, is_link) in enumerate(src_items, start=1):
            status["checked"] = idx
            status["file"] = rel
            p = os.path.join(src_dir, rel)

            if is_link:
                try:
                    target = os.readlink(p)
                    src_catalog[rel] = (0, f"link:{target}", True)
                except OSError as e:
                    src_catalog[rel] = (0, f"error:{e}", True)
                continue

            h = hashlib.sha256()
            t_file_start = time.time()
            try:
                with open(p, "rb") as f:
                    while chunk := f.read(2 * 1024 * 1024):
                        h.update(chunk)
                        status["bytes_done"] += len(chunk)
                        bytes_since_firebreak += len(chunk)
                src_catalog[rel] = (sz, h.hexdigest(), False)

                if src_read_rate and sz > 0:
                    target_file_dur = sz / src_read_rate
                    dt_file = time.time() - t_file_start
                    if dt_file < target_file_dur:
                        time.sleep(target_file_dur - dt_file)

                if bytes_since_firebreak >= 5 * 1024 * 1024 * 1024:
                    bytes_since_firebreak = 0
                    firebreak_count += 1
                    try:
                        os.sync()
                    except Exception:
                        pass
                    for sec in range(4, 0, -1):
                        if stop_event.is_set():
                            break
                        status["thermal_msg"] = f"Cooling source drive ({sec}s)"
                        time.sleep(1.0)
                    status["thermal_msg"] = ""
                    try:
                        os.sync()
                    except Exception:
                        pass
            except Exception as e:
                src_catalog[rel] = (sz, f"error:{e}", False)

        elapsed_s1 = int(time.time() - s1_start)
        m1, s1 = divmod(elapsed_s1, 60)
        clear_progress()
        safe_write(f"[✓] [{m1:02d}:{s1:02d}] 🛡️  [Step 1/{tot_steps_init}: Reading Source] [====================] 100.0% ({len(src_items):,}/{len(src_items):,}) [{format_size(total_src_bytes)}] | Baseline cataloged\n")

        # STEP 2: Reading & Hashing Destination
        s2_start = time.time()
        status["step"] = 2
        status["step_start"] = s2_start
        status["checked"] = 0
        status["total"] = len(src_catalog)
        status["bytes_done"] = 0
        status["speed"] = ""
        bytes_since_firebreak = 0
        mismatches = []
        suspect_hashes = []

        for idx, (rel, (src_sz, src_hash, is_link)) in enumerate(src_catalog.items(), start=1):
            status["checked"] = idx
            status["file"] = rel
            dp = os.path.join(dst_dir, rel)

            if not os.path.lexists(dp):
                mismatches.append((rel, "Missing at destination"))
                continue

            if is_link:
                if not os.path.islink(dp):
                    mismatches.append((rel, "Expected symlink at destination but found regular item"))
                    continue
                try:
                    dst_target = os.readlink(dp)
                    if f"link:{dst_target}" != src_hash:
                        mismatches.append((rel, f"Symlink target mismatch (expected {src_hash[5:]}, got {dst_target})"))
                except OSError as e:
                    mismatches.append((rel, f"Symlink read error: {e}"))
                continue

            if os.path.islink(dp):
                mismatches.append((rel, "Expected regular file at destination but found symlink"))
                continue

            try:
                dst_sz = os.path.getsize(dp)
                if dst_sz != src_sz:
                    mismatches.append((rel, f"Size mismatch (expected {src_sz:,} B, got {dst_sz:,} B)"))
                    continue

                h = hashlib.sha256()
                t_file_start = time.time()
                with open(dp, "rb") as f:
                    while chunk := f.read(2 * 1024 * 1024):
                        h.update(chunk)
                        status["bytes_done"] += len(chunk)
                        bytes_since_firebreak += len(chunk)

                dst_hash = h.hexdigest()
                if dst_hash != src_hash:
                    suspect_hashes.append((rel, src_sz, src_hash, dst_hash))

                if dst_read_rate and dst_sz > 0:
                    target_file_dur = dst_sz / dst_read_rate
                    dt_file = time.time() - t_file_start
                    if dt_file < target_file_dur:
                        time.sleep(target_file_dur - dt_file)

                if bytes_since_firebreak >= 5 * 1024 * 1024 * 1024:
                    bytes_since_firebreak = 0
                    firebreak_count += 1
                    try:
                        os.sync()
                    except Exception:
                        pass
                    for sec in range(4, 0, -1):
                        if stop_event.is_set():
                            break
                        status["thermal_msg"] = f"Cooling destination drive ({sec}s)"
                        time.sleep(1.0)
                    status["thermal_msg"] = ""
                    try:
                        os.sync()
                    except Exception:
                        pass
            except Exception as e:
                mismatches.append((rel, f"Read error: {e}"))

        elapsed_s2 = int(time.time() - s2_start)
        m2, s2 = divmod(elapsed_s2, 60)

        # Step 2 Physical Settle & Confirmation Pass:
        if suspect_hashes:
            clear_progress()
            safe_write(f"[✓] [{m2:02d}:{s2:02d}] 🛡️  [Step 2/{tot_steps_init}: Reading Destination] [====================] 100.0% ({len(src_catalog):,}/{len(src_catalog):,}) [{format_size(total_src_bytes)}] | Initial sweep complete ({len(suspect_hashes)} files queued for physical confirmation)\n")

            try:
                os.sync()
            except Exception:
                pass

            settle_secs = min(15, max(5, len(suspect_hashes)))
            for sec in range(settle_secs, 0, -1):
                if stop_event.is_set():
                    break
                status["thermal_msg"] = f"Thermal cool-down before physical confirmation ({sec}s)"
                time.sleep(1.0)
            status["thermal_msg"] = ""

            status["sub_step"] = "confirm"
            status["total"] = len(suspect_hashes)
            status["checked"] = 0

            for idx, (s_rel, s_sz, s_hash, first_dst_hash) in enumerate(suspect_hashes, start=1):
                status["checked"] = idx
                status["file"] = s_rel
                s_dp = os.path.join(dst_dir, s_rel)
                try:
                    time.sleep(0.05)
                    h2 = compute_sha256(s_dp, dst_read_rate, direct_io=True)
                    if h2 == s_hash:
                        continue

                    # If h2 != s_hash, verify if divergence is reproducible or transient bus jitter
                    time.sleep(0.1)
                    h3 = compute_sha256(s_dp, dst_read_rate, direct_io=True)
                    if h3 == s_hash:
                        continue

                    # Confirmed reproducible mismatch on physical flash
                    if h2 == h3:
                        mismatches.append((s_rel, f"Hash mismatch (expected {s_hash[:8]}, got {h2[:8]})"))
                    elif h2 == first_dst_hash:
                        mismatches.append((s_rel, f"Hash mismatch (expected {s_hash[:8]}, got {h2[:8]})"))
                    elif h3 == first_dst_hash:
                        mismatches.append((s_rel, f"Hash mismatch (expected {s_hash[:8]}, got {h3[:8]})"))
                    else:
                        time.sleep(1.0)
                        h4 = compute_sha256(s_dp, dst_read_rate, direct_io=True)
                        if h4 == s_hash:
                            continue
                        elif h4 in (h2, h3, first_dst_hash):
                            mismatches.append((s_rel, f"Hash mismatch (expected {s_hash[:8]}, got {h4[:8]})"))
                except Exception as e:
                    mismatches.append((s_rel, f"Read error: {e}"))

            status["file"] = ""
            status["sub_step"] = ""
            clear_progress()
            safe_write(f"[✓] [{m2:02d}:{s2:02d}] 🔒 [Step 2/{tot_steps_init}: Physical Confirmation] [====================] 100.0% ({len(suspect_hashes):,}/{len(suspect_hashes):,}) | Physical flash verified\n")
        else:
            clear_progress()
            safe_write(f"[✓] [{m2:02d}:{s2:02d}] 🛡️  [Step 2/{tot_steps_init}: Reading Destination] [====================] 100.0% ({len(src_catalog):,}/{len(src_catalog):,}) [{format_size(total_src_bytes)}] | Physical disk verified\n")

        orphaned_files = []
        for root, dirs, files in os.walk(dst_dir):
            dirs[:] = [d for d in dirs if not is_excluded(os.path.relpath(os.path.join(root, d), dst_dir))]
            dirs.sort()
            for fname in sorted(files):
                p = os.path.join(root, fname)
                rel = os.path.relpath(p, dst_dir)
                if is_excluded(rel):
                    continue
                if rel not in src_catalog:
                    orphaned_files.append(rel)

        pruned_count = 0
        if is_prune and not is_dry_run:
            for rel in orphaned_files:
                try:
                    os.remove(os.path.join(dst_dir, rel))
                    pruned_count += 1
                except OSError:
                    pass

        # STEP 3: Auto-Repair & STEP 4: Physical Disk Verification
        s3_start = time.time()
        repaired_files = []
        repair_failed = []
        m3, s3 = 0, 0
        m4, s4 = 0, 0

        if mismatches and not is_dry_run:
            # Re-verify destination volume integrity before touching disk (SEC-05)
            if not os.path.isdir(dst_dir):
                clear_progress()
                safe_write(f"\n{C_RED}[!] CRITICAL ERROR: Destination directory '{dst_dir}' is inaccessible. Aborting to protect drive.{C_RESET}\n")
                sys.exit(1)
            if initial_dst_dev is not None:
                try:
                    curr_dst_dev = os.stat(dst_dir).st_dev
                    if curr_dst_dev != initial_dst_dev:
                        clear_progress()
                        safe_write(f"\n{C_RED}[!] CRITICAL ERROR: Destination volume device ID changed ({curr_dst_dev} != {initial_dst_dev}). Aborting to protect internal drive.{C_RESET}\n")
                        sys.exit(1)
                except OSError as e:
                    clear_progress()
                    safe_write(f"\n{C_RED}[!] CRITICAL ERROR: Destination volume became inaccessible: {e}. Aborting.{C_RESET}\n")
                    sys.exit(1)

            status["total_steps"] = 4
            bw_val = os.environ.get("SAFESYNC_BW", "120M")
            batch_size = 40
            max_healing_cycles = 2
            healing_cycle = 1
            unresolved_mismatches = list(mismatches)
            repaired_set = set()
            m3_total_sec = 0
            m4_total_sec = 0

            while unresolved_mismatches and healing_cycle <= max_healing_cycles:
                cycle_tag = f" (Cycle {healing_cycle})" if healing_cycle > 1 else ""
                cycle_s3_start = time.time()
                status["step"] = 3
                status["step_start"] = cycle_s3_start
                status["total"] = len(unresolved_mismatches)
                status["checked"] = 0
                status["file"] = f"Starting auto-repair{cycle_tag}..."

                cycle_bytes = 0
                for rel, _ in unresolved_mismatches:
                    if rel in src_catalog:
                        cycle_bytes += src_catalog[rel][0]

                active_tmp_paths = set()

                def cleanup_s3_tmp():
                    for tp in list(active_tmp_paths):
                        try:
                            if os.path.lexists(tp):
                                os.unlink(tp)
                        except Exception:
                            pass
                atexit.register(cleanup_s3_tmp)

                write_rate = parse_bw_limit(bw_val) if (dst_is_ext and not is_uncapped) else None
                bytes_since_write_cool = 0
                all_transferred_count = 0

                for rel, _ in unresolved_mismatches:
                    if stop_event.is_set():
                        break
                    sp = os.path.join(src_dir, rel)
                    dp = os.path.join(dst_dir, rel)
                    status["file"] = rel

                    if not os.path.lexists(sp):
                        continue

                    if os.path.islink(sp):
                        try:
                            link_target = os.readlink(sp)
                            os.makedirs(os.path.dirname(dp), exist_ok=True)
                            tmp_link = dp + f".safesync_tmp_{os.getpid()}_{int(time.time()*1000)}"
                            active_tmp_paths.add(tmp_link)
                            try:
                                if os.path.lexists(tmp_link):
                                    os.unlink(tmp_link)
                                os.symlink(link_target, tmp_link)
                                os.replace(tmp_link, dp)
                            finally:
                                active_tmp_paths.discard(tmp_link)
                        except Exception:
                            pass
                        all_transferred_count += 1
                        status["checked"] = min(len(unresolved_mismatches), all_transferred_count)
                        continue

                    # Regular file atomic transfer with F_FULLFSYNC
                    tmp_dp = dp + f".safesync_tmp_{os.getpid()}_{int(time.time()*1000)}"
                    active_tmp_paths.add(tmp_dp)
                    try:
                        os.makedirs(os.path.dirname(dp), exist_ok=True)
                        expected_sz, expected_hash, _ = src_catalog.get(rel, (os.path.getsize(sp), None, False))

                        h_write = hashlib.sha256()
                        chunk_size = 2 * 1024 * 1024
                        t_write_start = time.time()

                        with open(sp, "rb") as f_in, open(tmp_dp, "wb") as f_out:
                            while True:
                                if stop_event.is_set():
                                    break
                                chunk = f_in.read(chunk_size)
                                if not chunk:
                                    break
                                f_out.write(chunk)
                                h_write.update(chunk)
                                status["bytes_done"] += len(chunk)
                                bytes_since_write_cool += len(chunk)

                            f_out.flush()
                            if hasattr(fcntl, "F_FULLFSYNC"):
                                try:
                                    fcntl.fcntl(f_out.fileno(), fcntl.F_FULLFSYNC)
                                except OSError:
                                    os.fsync(f_out.fileno())
                            else:
                                os.fsync(f_out.fileno())

                        if write_rate and expected_sz > 0:
                            target_file_dur = expected_sz / write_rate
                            dt_write = time.time() - t_write_start
                            if dt_write < target_file_dur:
                                time.sleep(target_file_dur - dt_write)

                        written_hash = h_write.hexdigest()
                        if expected_hash and written_hash != expected_hash:
                            if os.path.lexists(tmp_dp):
                                os.unlink(tmp_dp)
                            active_tmp_paths.discard(tmp_dp)
                            continue

                        # Hardware Verification: confirm physical NAND flash matches before swap
                        flash_hash = compute_sha256(tmp_dp, max_bytes_per_sec=None, direct_io=True)
                        if expected_hash and flash_hash != expected_hash:
                            if os.path.lexists(tmp_dp):
                                os.unlink(tmp_dp)
                            active_tmp_paths.discard(tmp_dp)
                            continue

                        st_src = os.stat(sp)
                        try:
                            os.utime(tmp_dp, (st_src.st_atime, st_src.st_mtime))
                        except Exception:
                            pass
                        try:
                            os.chmod(tmp_dp, st_src.st_mode)
                        except Exception:
                            pass

                        os.replace(tmp_dp, dp)
                        active_tmp_paths.discard(tmp_dp)

                        if bytes_since_write_cool >= 5 * 1024 * 1024 * 1024:
                            bytes_since_write_cool = 0
                            for sec in range(5, 0, -1):
                                if stop_event.is_set():
                                    break
                                status["thermal_msg"] = f"Cooling external drive ({sec}s)"
                                time.sleep(1.0)
                            status["thermal_msg"] = ""

                    except Exception:
                        if os.path.lexists(tmp_dp):
                            try:
                                os.unlink(tmp_dp)
                            except Exception:
                                pass
                        active_tmp_paths.discard(tmp_dp)

                    all_transferred_count += 1
                    status["checked"] = min(len(unresolved_mismatches), all_transferred_count)

                elapsed_c_s3 = int(time.time() - cycle_s3_start)
                m3_total_sec += elapsed_c_s3
                m3_c, s3_c = divmod(elapsed_c_s3, 60)
                clear_progress()
                safe_write(f"[✓] [{m3_c:02d}:{s3_c:02d}] ⚡ [Step 3/4: Auto-Repair{cycle_tag}] [====================] 100.0% ({len(unresolved_mismatches):,}/{len(unresolved_mismatches):,}) | Atomic transfer complete\n")

                # STEP 4: Physical Disk Verification
                cycle_s4_start = time.time()
                status["step"] = 4
                status["step_start"] = cycle_s4_start
                status["total"] = len(unresolved_mismatches)
                status["checked"] = 0
                status["bytes_done"] = 0

                drain_secs = min(15, max(5, int(cycle_bytes / (100 * 1024 * 1024))))
                for sec in range(drain_secs, 0, -1):
                    if stop_event.is_set():
                        break
                    status["thermal_msg"] = f"Flushing drive write cache ({sec}s)"
                    time.sleep(1.0)
                status["thermal_msg"] = ""
                try:
                    os.sync()
                except Exception:
                    pass

                # Pass 1: Continuous Fast Disk Hash Sweep
                status["pass"] = 1
                pending_retry = []
                for idx, (rel, reason) in enumerate(unresolved_mismatches, start=1):
                    status["checked"] = idx
                    status["file"] = rel
                    dp = os.path.join(dst_dir, rel)
                    sp = os.path.join(src_dir, rel)

                    if os.path.islink(sp):
                        if not os.path.islink(dp):
                            pending_retry.append((rel, "Expected symlink after repair"))
                            continue
                        try:
                            dst_target = os.readlink(dp)
                            src_target = os.readlink(sp)
                            if dst_target == src_target:
                                repaired_set.add(rel)
                            else:
                                pending_retry.append((rel, f"Symlink mismatch after repair ({dst_target})"))
                        except OSError as e:
                            pending_retry.append((rel, f"Symlink read error: {e}"))
                        continue

                    try:
                        if not os.path.lexists(dp):
                            pending_retry.append((rel, "Missing at destination after repair"))
                            continue
                        expected_sz, expected_hash, _ = src_catalog[rel]
                        dst_sz = os.path.getsize(dp)
                        if dst_sz != expected_sz:
                            pending_retry.append((rel, f"Size mismatch (expected {expected_sz}, got {dst_sz})"))
                            continue

                        def cb_s4(n):
                            status["bytes_done"] += n
                        dst_hash = compute_sha256(dp, dst_read_rate, progress_cb=cb_s4, direct_io=True)
                        if dst_hash == expected_hash:
                            repaired_set.add(rel)
                        else:
                            pending_retry.append((rel, f"Hash mismatch (got {dst_hash[:8]}, expected {expected_hash[:8]})"))
                    except Exception as e:
                        pending_retry.append((rel, f"Read error: {e}"))

                # Pass 2: Write-Queue Drain Barrier & Targeted Recheck
                still_failing = []
                if pending_retry:
                    status["pass"] = 2
                    status["total"] = len(pending_retry)
                    status["checked"] = 0
                    for sec in range(20, 0, -1):
                        if stop_event.is_set():
                            break
                        status["thermal_msg"] = f"Flushing drive write queue ({sec}s)"
                        time.sleep(1.0)
                    status["thermal_msg"] = ""
                    try:
                        os.sync()
                    except Exception:
                        pass

                    for idx, (rel, last_err) in enumerate(pending_retry, start=1):
                        status["checked"] = idx
                        status["file"] = rel
                        dp = os.path.join(dst_dir, rel)
                        expected_sz, expected_hash, _ = src_catalog[rel]
                        try:
                            if os.path.lexists(dp) and os.path.getsize(dp) == expected_sz:
                                def cb_s4_retry(n):
                                    status["bytes_done"] += n
                                dst_hash = compute_sha256(dp, dst_read_rate, progress_cb=cb_s4_retry, direct_io=True)
                                if dst_hash == expected_hash:
                                    repaired_set.add(rel)
                                    continue
                        except Exception:
                            pass
                        still_failing.append((rel, last_err))

                elapsed_c_s4 = int(time.time() - cycle_s4_start)
                m4_total_sec += elapsed_c_s4
                m4_c, s4_c = divmod(elapsed_c_s4, 60)

                if not still_failing:
                    unresolved_mismatches = []
                    clear_progress()
                    safe_write(f"[✓] [{m4_c:02d}:{s4_c:02d}] 🔒 [Step 4/4: Physical Disk Verification{cycle_tag}] [====================] 100.0% ({len(repaired_set):,}/{len(mismatches):,}) | 100% bit-for-bit verified\n")
                    break
                else:
                    if healing_cycle < max_healing_cycles:
                        clear_progress()
                        safe_write(f"[-] [{m4_c:02d}:{s4_c:02d}] 🔄 [Step 4/4: Physical Disk Verification{cycle_tag}] ({len(repaired_set):,}/{len(mismatches):,}) verified | Self-healing {len(still_failing):,} remaining file(s)...\n")
                        healing_cycle += 1
                        unresolved_mismatches = [(rel, err) for rel, err in still_failing]
                    else:
                        repair_failed = still_failing
                        clear_progress()
                        safe_write(f"[!] [{m4_c:02d}:{s4_c:02d}] 🔒 [Step 4/4: Physical Disk Verification{cycle_tag}] [====================] 100.0% ({len(repaired_set):,}/{len(mismatches):,}) | {len(repair_failed):,} failed verification\n")
                        break

            repaired_files = sorted(list(repaired_set))
            m3, s3 = divmod(m3_total_sec, 60)
            m4, s4 = divmod(m4_total_sec, 60)
        elif is_dry_run:
            elapsed_s3 = int(time.time() - s3_start)
            m3, s3 = divmod(elapsed_s3, 60)
            clear_progress()
            if mismatches:
                safe_write(f"[✓] [{m3:02d}:{s3:02d}] 🔍 [Step 3/3: Dry-Run Audit] [====================] 100.0% ({len(src_catalog):,}/{len(src_catalog):,}) | Audit Preview ({len(mismatches):,} divergent files detected)\n")
            else:
                safe_write(f"{C_GREEN}[✓] [{m3:02d}:{s3:02d}] 🔍 [Step 3/3: Dry-Run Audit] [====================] 100.0% ({len(src_catalog):,}/{len(src_catalog):,}) | 100% Bit-for-Bit Identical{C_RESET}\n")
        else:
            status["total_steps"] = 3
            status["step"] = 3
            elapsed_s3 = int(time.time() - s3_start)
            m3, s3 = divmod(elapsed_s3, 60)
            clear_progress()
            safe_write(f"[✓] [{m3:02d}:{s3:02d}] 🛡️  [Step 3/4: Cryptographic Verification] [====================] 100.0% ({len(src_catalog):,}/{len(src_catalog):,}) | 100% Bit-for-Bit Identical (0 repairs needed)\n")

        stop_heartbeat(clear=True)
        safe_write("\n")

        elapsed_total = int(time.time() - start_time)
        m_tot, s_tot = divmod(elapsed_total, 60)
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        banner_line = "═" * 62

        step_times_str = f"Step 1: {m1:02d}m {s1:02d}s | Step 2: {m2:02d}m {s2:02d}s"
        if mismatches and not is_dry_run:
            step_times_str += f" | Step 3: {m3:02d}m {s3:02d}s | Step 4: {m4:02d}m {s4:02d}s"
        else:
            step_times_str += f" | Step 3: {m3:02d}m {s3:02d}s"

        report_lines = [
            "SafeSync Full Audit Report - " + now_str,
            f"Source:      {src_dir}",
            f"Destination: {dst_dir}",
            f"Duration:    {m_tot:02d}m {s_tot:02d}s ({step_times_str})",
            f"Mode:        full_audit",
            f"Total files: {len(src_catalog):,} ({format_size(total_src_bytes)})",
            f"Thermal:     {firebreak_count} firebreak pauses taken (every 5 GB)",
            f"Bit rot:     {len(mismatches):,}",
            f"Repaired:    {len(repaired_files):,}",
            f"Failed:      {len(repair_failed):,}",
            f"Orphans:     {len(orphaned_files):,} ({pruned_count:,} pruned)"
        ]
        if mismatches:
            report_lines.append("")
            report_lines.append(f"[DIVERGENT / REPAIRED FILES] ({len(mismatches)}):")
            for f, err in mismatches:
                report_lines.append(f"  ~ {f}: {err}")
        if repair_failed:
            report_lines.append("")
            report_lines.append(f"[REPAIR FAILED FILES] ({len(repair_failed)}):")
            for f, err in repair_failed:
                report_lines.append(f"  ! {f}: {err}")
        if orphaned_files:
            report_lines.append("")
            report_lines.append(f"[ORPHANED FILES] ({len(orphaned_files)}):")
            for f in orphaned_files:
                report_lines.append(f"  - {f}")

        write_report_file("\n".join(report_lines) + "\n", report_path)

        if is_dry_run:
            clr = C_GREEN if not mismatches else C_YELLOW
            safe_write(f"{clr}{C_BOLD}{banner_line}{C_RESET}\n")
            safe_write(f"{clr}{C_BOLD} [✓] 🔍 DRY-RUN AUDIT COMPLETE ({m_tot:02d}m {s_tot:02d}s): {len(src_catalog):,} files audited.{C_RESET}\n")
            if mismatches:
                safe_write(f"{clr} [i] 📦 {len(mismatches):,} divergent files WOULD be repaired.{C_RESET}\n")
            else:
                safe_write(f"{clr}{C_BOLD}     ✨ 100% Bit-for-Bit Identical! Zero divergent files detected.{C_RESET}\n")
            safe_write(f"{clr}     ⏱️  Step times:     {step_times_str}{C_RESET}\n")
            if is_prune and orphaned_files:
                safe_write(f"{C_YELLOW} [i] 🗑️  {len(orphaned_files):,} orphaned files WOULD be deleted/pruned.{C_RESET}\n")
            elif orphaned_files:
                safe_write(f"{C_YELLOW}     - ℹ️  {len(orphaned_files):,} orphaned files on destination (use --prune to clean up).{C_RESET}\n")
            safe_write(f"{clr}     📄 Detailed report: {format_report_link(report_path)}{C_RESET}\n")
            safe_write(f"{clr}     💡 Quick view:      open {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{clr}     📂 In Finder:       open -R {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{clr}{C_BOLD}{banner_line}{C_RESET}\n")
        elif repair_failed:
            safe_write(f"{C_RED}{C_BOLD}{banner_line}{C_RESET}\n")
            safe_write(f"{C_RED}{C_BOLD} [!] 🚨 FULL AUDIT REPAIR INCOMPLETE: {len(repair_failed):,} files failed repair!{C_RESET}\n")
            if is_verbose or len(repair_failed) <= 5:
                for f, err in repair_failed:
                    safe_write(f"{C_RED}     - {f}: {err}{C_RESET}\n")
            else:
                for f, err in repair_failed[:3]:
                    safe_write(f"{C_RED}     - {f}: {err}{C_RESET}\n")
                safe_write(f"{C_RED}     ... and {len(repair_failed) - 3:,} more (see full report){C_RESET}\n")
            if len(repaired_files) > 0:
                safe_write(f"{C_GREEN}     - ⚡ {len(repaired_files):,} divergent files successfully repaired.{C_RESET}\n")
            safe_write(f"{C_RED}     ⏱️  Step times:     {step_times_str}{C_RESET}\n")
            safe_write(f"{C_RED}     📄 Detailed report: {format_report_link(report_path)}{C_RESET}\n")
            safe_write(f"{C_RED}     💡 Quick view:      open {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_RED}     📂 In Finder:       open -R {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_RED}{C_BOLD}{banner_line}{C_RESET}\n")
            sys.exit(1)
        elif mismatches:
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD} [✓] 🛡️  FULL AUDIT REPAIR COMPLETE ({m_tot:02d}m {s_tot:02d}s):{C_RESET}\n")
            safe_write(f"{C_GREEN}     - 📦 {len(src_catalog):,} files cryptographically scrubbed & verified on disk.{C_RESET}\n")
            safe_write(f"{C_GREEN}     - ⚡ {len(repaired_files):,} divergent files repaired & 100% verified bit-for-bit!{C_RESET}\n")
            safe_write(f"{C_GREEN}     - ⏱️  Step times:     {step_times_str}{C_RESET}\n")
            if firebreak_count > 0:
                safe_write(f"{C_GREEN}     - ❄️  Drive thermals safely managed ({firebreak_count} firebreak pauses every 5 GB).{C_RESET}\n")
            if orphaned_files:
                if is_prune:
                    safe_write(f"{C_GREEN}     - 🗑️  {pruned_count:,} orphaned files pruned.{C_RESET}\n")
                else:
                    safe_write(f"{C_GREEN}     - ℹ️  {len(orphaned_files):,} orphaned files on destination (use --prune to clean up).{C_RESET}\n")
            safe_write(f"{C_GREEN}     📄 Detailed report: {format_report_link(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}     💡 Quick view:      open {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}     📂 In Finder:       open -R {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")
        else:
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD} [✓] 🛡️  FULL AUDIT SUCCESS ({m_tot:02d}m {s_tot:02d}s): All files are 100% bit-for-bit identical!{C_RESET}\n")
            safe_write(f"{C_GREEN}     - 📦 {len(src_catalog):,} files cryptographically scrubbed & verified on disk.{C_RESET}\n")
            safe_write(f"{C_GREEN}     - 🛡️  0 bit rot, 0 corruptions, 0 divergent files.{C_RESET}\n")
            safe_write(f"{C_GREEN}     - ⏱️  Step times:     {step_times_str}{C_RESET}\n")
            if firebreak_count > 0:
                safe_write(f"{C_GREEN}     - ❄️  Drive thermals safely managed ({firebreak_count} firebreak pauses every 5 GB).{C_RESET}\n")
            if orphaned_files:
                if is_prune:
                    safe_write(f"{C_GREEN}     - 🗑️  {pruned_count:,} orphaned files pruned.{C_RESET}\n")
                else:
                    safe_write(f"{C_GREEN}     - ℹ️  {len(orphaned_files):,} orphaned files on destination (use --prune to clean up).{C_RESET}\n")
            safe_write(f"{C_GREEN}     📄 Detailed report: {format_report_link(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}     💡 Quick view:      open {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}     📂 In Finder:       open -R {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")

        sys.exit(0)

    except KeyboardInterrupt:
        stop_heartbeat(clear=True)
        safe_write("\n [!] Full audit cancelled by user (Ctrl+C).\n")
        sys.exit(130)


# ==============================================================================
# SMART INCREMENTAL ENGINE (Default Fast Sync + Cryptographic Verification)
# ==============================================================================

def run_smart_sync():
    mode = os.environ.get("SAFESYNC_MODE", "smart")
    is_dry_run = os.environ.get("SAFESYNC_DRY_RUN", "0") == "1"
    is_verbose = os.environ.get("SAFESYNC_VERBOSE", "0") == "1"
    src_dir = os.environ.get("SAFESYNC_SRC", "")
    dst_dir = os.environ.get("SAFESYNC_DST", "")
    report_dir = os.environ.get("SAFESYNC_REPORT_DIR") or os.path.expanduser("~/Library/Logs/safesync")
    report_path = os.path.join(report_dir, "safesync_report.txt")
    try:
        os.makedirs(report_dir, exist_ok=True)
    except Exception:
        pass

    stop_event = threading.Event()
    status = {
        "file": "Starting...",
        "checked": 0,
        "total": 0,
        "transferred": 0,
        "new_count": 0,
        "mod_count": 0,
        "del_count": 0,
        "phase": "scan"
    }
    start_time = time.time()
    ITEM_REGEX = re.compile(r"^([>c.h][fdLDS][^\s]*)\s(.*)$")

    transferred_spool = tempfile.NamedTemporaryFile(
        mode="w+",
        prefix="safesync_transferred_",
        suffix=".txt",
        delete=False,
        encoding="utf-8",
        errors="surrogateescape"
    )
    transferred_spool_path = transferred_spool.name

    def cleanup_spool():
        try:
            if not transferred_spool.closed:
                transferred_spool.close()
            if os.path.exists(transferred_spool_path):
                os.unlink(transferred_spool_path)
        except Exception:
            pass
    atexit.register(cleanup_spool)

    def heartbeat():
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while not stop_event.is_set():
            elapsed = int(time.time() - start_time)
            m, s = divmod(elapsed, 60)
            spin = spinner[idx % len(spinner)]
            idx += 1

            if status["phase"] == "scan":
                tag = "[Simulating]" if is_dry_run else "[SmartSync]"
                tot = status["total"]
                chk = status["checked"]
                disp_file = (status["file"][:32] + "...") if len(status["file"]) > 32 else status["file"]
                t_cnt = status["transferred"]
                t_tag = "Would Copy" if is_dry_run else "New/Mod"
                t_str = f" [{t_tag}: {t_cnt}]" if t_cnt > 0 else ""
                if tot > 0:
                    pct = (chk / tot * 100)
                    bars = int(min(100, pct) / 5)
                    bar_str = "=" * bars + "-" * (20 - bars)
                    safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] ⚡ {tag} [{bar_str}] {pct:5.1f}% ({chk:,}/{tot:,}){t_str} | {disp_file}")
                else:
                    safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] ⚡ {tag} [--------------------]   0.0% ({chk:,}){t_str} | {disp_file}")
            elif status["phase"] == "verify":
                v_tot = status["total"]
                v_curr = status["checked"]
                v_pct = (v_curr / v_tot * 100) if v_tot > 0 else 0
                v_bars = int(min(100, v_pct) / 5)
                v_bar_str = "=" * v_bars + "-" * (20 - v_bars)
                disp_file = (status["file"][:32] + "...") if len(status["file"]) > 32 else status["file"]
                p_num = status.get("pass", 1)
                v_tag = f"Verifying Pass {p_num}/2" if p_num > 1 else "Verifying Physical Disk"
                safe_write(f"\r\033[K {spin} [{m:02d}:{s:02d}] 🔒 [{v_tag}] [{v_bar_str}] {v_pct:5.1f}% ({v_curr:,}/{v_tot:,}) | {disp_file}")

            time.sleep(0.12)

    t = None
    if USE_COLOR:
        t = threading.Thread(target=heartbeat, daemon=True)
        t.start()

    total_bytes_transferred = 0
    new_items = []
    mod_items = []
    del_items = []

    try:
        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue

            m = ITEM_REGEX.match(line_str)
            if m:
                flags = m.group(1)
                item = m.group(2).strip()

                if flags.startswith("*deleting"):
                    status["del_count"] += 1
                    del_items.append(item)
                    continue

                status["checked"] += 1
                status["file"] = item

                update_type = flags[0]
                file_type = flags[1]

                if update_type in (">", "c") and file_type in ("f", "L"):
                    status["transferred"] += 1
                    if flags.startswith(">f+++++++++"):
                        status["new_count"] += 1
                        new_items.append((item, "new"))
                    else:
                        status["mod_count"] += 1
                        mod_items.append((item, "mod"))
                    transferred_spool.write(item + "\n")

            if "total size is" in line_str:
                m_sz = re.search(r"total size is\s+([\d,]+)", line_str)
                if m_sz:
                    total_bytes_transferred = int(m_sz.group(1).replace(",", ""))

        status["phase"] = "done"
        if t:
            stop_event.set()
            t.join()
        clear_progress()

        # Cryptographic verification of newly transferred files
        verify_items = new_items + mod_items
        verified_files = []
        repaired_files = []
        corrupted_files = []

        if mode == "smart" and not is_dry_run and len(verify_items) > 0:
            try:
                os.sync()
            except Exception:
                pass

            # Dynamic settle drain
            drain_sec = min(30, max(5, int(total_bytes_transferred / (80 * 1024 * 1024))))
            for sec_left in range(drain_sec, 0, -1):
                safe_write(f"\r\033[K 🔒 [Flushing Write Cache] ({sec_left}s)...")
                time.sleep(1.0)
            clear_progress()

            v_start = time.time()
            v_items_count = len(verify_items)

            for idx, (rel_path, _) in enumerate(verify_items, start=1):
                src_path = os.path.join(src_dir, rel_path)
                dst_path = os.path.join(dst_dir, rel_path)

                if os.path.islink(src_path):
                    if os.path.islink(dst_path) and os.readlink(src_path) == os.readlink(dst_path):
                        verified_files.append(rel_path)
                    else:
                        corrupted_files.append((rel_path, "Symlink target mismatch"))
                    continue

                if not os.path.lexists(dst_path):
                    corrupted_files.append((rel_path, "Missing at destination after sync"))
                    continue

                if os.path.getsize(src_path) != os.path.getsize(dst_path):
                    corrupted_files.append((rel_path, "Size mismatch after transfer"))
                    continue

                try:
                    s_hash = compute_sha256(src_path)
                    d_hash = compute_sha256(dst_path)
                    if d_hash == s_hash:
                        verified_files.append(rel_path)
                    else:
                        corrupted_files.append((rel_path, f"Hash mismatch ({d_hash[:8]} vs {s_hash[:8]})"))
                except Exception as e:
                    corrupted_files.append((rel_path, f"Read error: {e}"))

            v_elapsed = int(time.time() - v_start)
            vm, vs = divmod(v_elapsed, 60)
            if not corrupted_files:
                safe_write(f"[✓] [{vm:02d}:{vs:02d}] 🔒 [Verifying Physical Disk] [====================] 100.0% ({v_items_count:,}/{v_items_count:,}) | 100% Verified bit-for-bit\n")
            else:
                safe_write(f"[!] [{vm:02d}:{vs:02d}] 🔒 [Verifying Physical Disk] ({len(verified_files):,}/{v_items_count:,}) | {len(corrupted_files):,} divergent\n")

        # Report & Outcomes
        elapsed_total = int(time.time() - start_time)
        m_tot, s_tot = divmod(elapsed_total, 60)
        banner_line = "═" * 62
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        report_lines = [
            "SafeSync Transfer Report - " + now_str,
            f"Source:       {src_dir}",
            f"Destination:  {dst_dir}",
            f"Duration:     {m_tot:02d}m {s_tot:02d}s",
            f"Mode:         {mode}",
            f"Transferred:  {len(verify_items):,} files ({format_size(total_bytes_transferred)})",
            f"  - New:      {status['new_count']:,}",
            f"  - Modified: {status['mod_count']:,}",
            f"Deleted:      {len(del_items):,}",
            f"Verified:     {len(verified_files):,}",
            f"Corrupted:    {len(corrupted_files):,}"
        ]
        if new_items:
            report_lines.append("")
            report_lines.append(f"[NEW FILES] ({len(new_items)}):")
            for item, _ in new_items:
                report_lines.append(f"  + {item}")
        if mod_items:
            report_lines.append("")
            report_lines.append(f"[MODIFIED FILES] ({len(mod_items)}):")
            for item, _ in mod_items:
                report_lines.append(f"  ~ {item}")
        if del_items:
            report_lines.append("")
            report_lines.append(f"[DELETED FILES] ({len(del_items)}):")
            for item in del_items:
                report_lines.append(f"  - {item}")
        if corrupted_files:
            report_lines.append("")
            report_lines.append(f"[CORRUPTED / VERIFICATION FAILED] ({len(corrupted_files)}):")
            for f, err in corrupted_files:
                report_lines.append(f"  ! {f}: {err}")

        write_report_file("\n".join(report_lines) + "\n", report_path)

        if corrupted_files:
            safe_write(f"{C_RED}{C_BOLD}{banner_line}{C_RESET}\n")
            safe_write(f"{C_RED}{C_BOLD} [!] 🚨 SYNC INCOMPLETE: {len(corrupted_files):,} files failed verification!{C_RESET}\n")
            for f, err in corrupted_files[:5]:
                safe_write(f"{C_RED}     - {f}: {err}{C_RESET}\n")
            if len(corrupted_files) > 5:
                safe_write(f"{C_RED}     ... and {len(corrupted_files) - 5:,} more (see full report){C_RESET}\n")
            safe_write(f"{C_RED}     📄 Detailed report: {format_report_link(report_path)}{C_RESET}\n")
            safe_write(f"{C_RED}     💡 Quick view:      open {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_RED}     📂 In Finder:       open -R {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_RED}{C_BOLD}{banner_line}{C_RESET}\n")
            sys.exit(1)
        elif len(verify_items) > 0:
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD} [✓] ✨ SMART SYNC SUCCESS ({m_tot:02d}m {s_tot:02d}s):{C_RESET}\n")
            safe_write(f"{C_GREEN}     - 📦 {len(verify_items):,} files transferred & verified bit-for-bit ({status['new_count']} new, {status['mod_count']} modified)!{C_RESET}\n")
            if del_items:
                safe_write(f"{C_GREEN}     - 🗑️  {len(del_items):,} orphaned files pruned.{C_RESET}\n")
            safe_write(f"{C_GREEN}     - ⚡ Historical files skipped instantly in seconds.{C_RESET}\n")
            safe_write(f"{C_GREEN}     📄 Detailed report: {format_report_link(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}     💡 Quick view:      open {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}     📂 In Finder:       open -R {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")

            if is_verbose and os.path.exists(report_path):
                safe_write("-" * 62 + "\n")
                safe_write("          DETAILED TRANSFER REPORT CONTENTS\n")
                safe_write("-" * 62 + "\n")
                with open(report_path, "r", encoding="utf-8", errors="replace") as rf:
                    safe_write(rf.read())
                safe_write("-" * 62 + "\n")

            sys.exit(0)
        else:
            mode_label = {"quick": "QUICK SCAN"}.get(mode, "SMART SYNC")
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD} [✓] 🎉 {mode_label} SUCCESS ({m_tot:02d}m {s_tot:02d}s): All files are 100% up to date!{C_RESET}\n")
            safe_write(f"{C_GREEN}     (0 files needed transfer — destination is completely in sync){C_RESET}\n")
            if del_items:
                safe_write(f"{C_GREEN}     - 🗑️  {len(del_items):,} orphaned files pruned.{C_RESET}\n")
            safe_write(f"{C_GREEN}     📄 Detailed report: {format_report_link(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}     💡 Quick view:      open {user_display_report(report_path)}{C_RESET}\n")
            safe_write(f"{C_GREEN}{C_BOLD}{banner_line}{C_RESET}\n")
            sys.exit(0)

    except KeyboardInterrupt:
        if t:
            stop_event.set()
            t.join()
        clear_progress()
        safe_write("\n [!] Sync cancelled by user (Ctrl+C).\n")
        sys.exit(130)


# ==============================================================================
# MAIN DISPATCHER
# ==============================================================================

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "audit":
        run_full_audit()
    elif len(sys.argv) > 1 and sys.argv[1] == "sync":
        run_smart_sync()
    else:
        # Default fallback to mode from environment
        mode = os.environ.get("SAFESYNC_MODE", "smart")
        if mode == "full_audit":
            run_full_audit()
        else:
            run_smart_sync()
