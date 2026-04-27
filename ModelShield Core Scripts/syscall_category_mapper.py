"""
ModelShield Syscall Category Mapper

This stage performs the semantic decoding step of ModelShield by mapping
raw syscall names to normalized categories and sub-operations used by
the downstream attack behavior classifier.

It reads the phase-separated JSON event files produced by the inspector,
adds `category` and `sub_op` labels to each event in memory, and returns
a TaggedEvents container for the next stage. The input JSON files are
not modified on disk.

Usage:
    python syscall_category_mapper.py <events_dir>
    python syscall_category_mapper.py <loading_events.json> <execution_events.json>
    python syscall_category_mapper.py <single_phase_events.json>

As a module:
    from syscall_category_mapper import SyscallCategoryMapper

    mapper = SyscallCategoryMapper()
    tagged = mapper.load_and_tag("/path/to/model_folder/events/")
"""

import json
import os
import sys
from collections import OrderedDict


# ═══════════════════════════════════════════════════════════════════════════════
# SYSCALL -> (CATEGORY, SUB_OPERATION) LOOKUP TABLE
# Semantic normalization layer:
# syscall variants with equivalent behavioral meaning are collapsed into a
# shared (category, sub_op) representation for downstream pattern matching.
# ═══════════════════════════════════════════════════════════════════════════════

SYSCALL_MAP = {

    # ── System ────────────────────────────────────────────────────────────
    "uname":              ("System", "System.info"),
    "sysinfo":            ("System", "System.info"),
    "sched_getaffinity":  ("System", "System.info"),
    "ioctl":              ("System", "System.ioctl"),
    "getrandom":          ("System", "System.random"),
    "gethostname":        ("System", "System.identity"),
    "sethostname":        ("System", "System.identity_set"),
    "setdomainname":      ("System", "System.identity_set"),

    # ── File: open / create ───────────────────────────────────────────────
    "open":               ("File", "File.open"),
    "openat":             ("File", "File.open"),
    "openat2":             ("File", "File.open"),
    "creat":              ("File", "File.open"),

    # ── File: read ────────────────────────────────────────────────────────
    "read":               ("File", "File.read"),
    "pread":            ("File", "File.read"),
    "pread64":            ("File", "File.read"),
    "readv":              ("File", "File.read"),

    # ── File: write ───────────────────────────────────────────────────────
    "write":              ("File", "File.write"),
    "pwrite":           ("File", "File.write"),
    "pwrite64":           ("File", "File.write"),
    "writev":             ("File", "File.write"),

    # ── File: stat / metadata ─────────────────────────────────────────────
    "stat":               ("File", "File.stat"),
    "fstat":              ("File", "File.stat"),
    "newfstatat":         ("File", "File.stat"),
    "statx":              ("File", "File.stat"),

    # ── File: access check ────────────────────────────────────────────────
    "access":             ("File", "File.access"),
    "faccessat":          ("File", "File.access"),

    # ── File: rename ──────────────────────────────────────────────────────
    "rename":             ("File", "File.rename"),
    "renameat":           ("File", "File.rename"),
    "renameat2":          ("File", "File.rename"),

    # ── File: link / symlink ──────────────────────────────────────────────
    "link":               ("File", "File.link"),
    "linkat":             ("File", "File.link"),
    "symlink":            ("File", "File.symlink"),
    "symlinkat":          ("File", "File.symlink"),

    # ── File: delete ──────────────────────────────────────────────────────
    "unlink":             ("File", "File.delete"),
    "unlinkat":           ("File", "File.delete"),
    "rmdir":              ("File", "File.delete"),

    # ── File: permission ──────────────────────────────────────────────────
    "chmod":              ("File", "File.permission"),
    "fchmod":             ("File", "File.permission"),
    "fchmodat":           ("File", "File.permission"),

    # ── File: ownership ───────────────────────────────────────────────────
    "chown":              ("File", "File.ownership"),
    "fchown":             ("File", "File.ownership"),
    "fchownat":           ("File", "File.ownership"),
    "lchown":             ("File", "File.ownership"),

    # ── File: directory enumeration ───────────────────────────────────────
    "getdents64":         ("File", "File.enumerate"),

    # ── File: directory creation ──────────────────────────────────────────
    "mkdir":              ("File", "File.mkdir"),
    "mkdirat":            ("File", "File.mkdir"),

    # ── File: readlink ────────────────────────────────────────────────────
    "readlink":           ("File", "File.readlink"),
    "readlinkat":         ("File", "File.readlink"),

    # ── File: truncate ────────────────────────────────────────────────────
    "truncate":           ("File", "File.truncate"),
    "ftruncate":          ("File", "File.truncate"),

    # ── File: fd duplication ──────────────────────────────────────────────
    "dup":                ("File", "File.dup"),
    "dup2":               ("File", "File.dup"),
    "dup3":               ("File", "File.dup"),

    # ── File: extended attributes ─────────────────────────────────────────
    "setxattr":           ("File", "File.xattr_set"),
    "lsetxattr":          ("File", "File.xattr_set"),
    "fsetxattr":          ("File", "File.xattr_set"),
    "removexattr":        ("File", "File.xattr_remove"),
    "lremovexattr":       ("File", "File.xattr_remove"),
    "fremovexattr":       ("File", "File.xattr_remove"),

    # ── File: misc ────────────────────────────────────────────────────────
    "fcntl":              ("File", "File.control"),
    "chdir":              ("File", "File.chdir"),
    "fchdir":             ("File", "File.chdir"),
    "sendfile":           ("File", "File.sendfile"),
    "getcwd":             ("File", "File.getcwd"),
    "lseek":              ("File", "File.seek"),
    "close":              ("File", "File.close"),
    "pipe":               ("File", "File.pipe"),
    "pipe2":              ("File", "File.pipe"),

    # ── File: inotify (filesystem monitoring) ─────────────────────────────
    "inotify_init":       ("File", "File.inotify_init"),
    "inotify_init1":      ("File", "File.inotify_init"),
    "inotify_add_watch":  ("File", "File.inotify_watch"),
    "inotify_rm_watch":   ("File", "File.inotify_remove"),

    # ── Network ───────────────────────────────────────────────────────────
    "socket":             ("Network", "Network.socket"),
    "bind":               ("Network", "Network.bind"),
    "listen":             ("Network", "Network.listen"),
    "accept":             ("Network", "Network.accept"),
    "accept4":            ("Network", "Network.accept"),
    "connect":            ("Network", "Network.connect"),
    "send":               ("Network", "Network.send"),
    "sendto":             ("Network", "Network.send"),
    "sendmsg":            ("Network", "Network.send"),
    "recv":               ("Network", "Network.recv"),
    "recvfrom":           ("Network", "Network.recv"),
    "recvmsg":            ("Network", "Network.recv"),
    "getsockname":        ("Network", "Network.info"),
    "getpeername":        ("Network", "Network.info"),
    "getsockopt":         ("Network", "Network.info"),
    "setsockopt":         ("Network", "Network.sockopt"),

    # ── Process ───────────────────────────────────────────────────────────
    "fork":               ("Process", "Process.fork"),
    "vfork":              ("Process", "Process.fork"),
    "clone":              ("Process", "Process.fork"),
    "clone3":             ("Process", "Process.fork"),
    "prctl":              ("Process", "Process.control"),
    "ptrace":             ("Process", "Process.ptrace"),
    "setsid":             ("Process", "Process.session"),
    "unshare":            ("Process", "Process.namespace"),
    "setns":              ("Process", "Process.namespace"),

    # ── Memory ────────────────────────────────────────────────────────────
    "mmap":               ("Memory", "Memory.map"),
    "mprotect":           ("Memory", "Memory.protect"),
    "memfd_create":       ("Memory", "Memory.anon_fd"),

    # ── Kernel module loading ─────────────────────────────────────────────
    "init_module":        ("CodeExec", "CodeExec.kmod_load"),
    "finit_module":       ("CodeExec", "CodeExec.kmod_load"),
    "delete_module":      ("CodeExec", "CodeExec.kmod_unload"),

    # ── Permission: query ─────────────────────────────────────────────────
    "getuid":             ("Permission", "Permission.query"),
    "geteuid":            ("Permission", "Permission.query"),
    "getgid":             ("Permission", "Permission.query"),
    "getegid":            ("Permission", "Permission.query"),
    "getgroups":          ("Permission", "Permission.query"),

    # ── Permission: elevate / modify ──────────────────────────────────────
    "setuid":             ("Permission", "Permission.elevate"),
    "setgid":             ("Permission", "Permission.elevate"),
    "setreuid":           ("Permission", "Permission.elevate"),
    "setresuid":          ("Permission", "Permission.elevate"),
    "setregid":           ("Permission", "Permission.elevate"),
    "setresgid":          ("Permission", "Permission.elevate"),
    "setgroups":          ("Permission", "Permission.elevate"),
    "capset":             ("Permission", "Permission.capability"),

    # ── Code Execution ────────────────────────────────────────────────────
    "execve":             ("CodeExec", "CodeExec.exec"),
    "execveat":           ("CodeExec", "CodeExec.exec"),
    "fexecve":            ("CodeExec", "CodeExec.exec"),
}


# ═══════════════════════════════════════════════════════════════════════════════
# TAGGED EVENTS CONTAINER
# ═══════════════════════════════════════════════════════════════════════════════

class TaggedEvents:
    """
    Container for phase-separated tagged events.

    The loading and execution phases are preserved separately because the
    classifier reasons about the same syscall sequence differently depending
    on when it occurs.
    """

    def __init__(self, model_name, events_dir):
        self.model_name = model_name
        self.events_dir = events_dir
        self.loading_events = []
        self.execution_events = []

    def print_summary(self):
        """Print category/sub-op counts for both phases."""
        for phase_name, events in [("LOADING", self.loading_events),
                                   ("EXECUTION", self.execution_events)]:
            if not events:
                print(f"\n  {phase_name}: no events")
                continue

            print(f"\n{'='*60}")
            print(f"  {phase_name} PHASE - {len(events)} events")
            print(f"{'='*60}")

            # Category counts
            cat_counts = {}
            for ev in events:
                cat = ev.get("category", "Untagged")
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            print(f"\n  Categories:")
            for cat in sorted(cat_counts.keys()):
                print(f"    {cat:12s}: {cat_counts[cat]}")

            # Sub-op counts
            sub_counts = {}
            for ev in events:
                sub = ev.get("sub_op", "Untagged")
                sub_counts[sub] = sub_counts.get(sub, 0) + 1
            print(f"\n  Sub-operations:")
            for sub in sorted(sub_counts.keys()):
                print(f"    {sub:24s}: {sub_counts[sub]}")


# ═══════════════════════════════════════════════════════════════════════════════
# THE MAPPER
# ═══════════════════════════════════════════════════════════════════════════════

class SyscallCategoryMapper:
    """
    Apply semantic decoding to raw event JSON files.

    Each event is annotated with a normalized `category` and `sub_op`
    derived from its raw syscall name, then returned in a TaggedEvents
    container for downstream classification.
    """

    def __init__(self):
        self.syscall_map = SYSCALL_MAP

    def tag_event(self, event):
        """Add category and sub_op to one event dict."""
        operation = event.get("operation", "")

        # Unknown operations are retained and labeled explicitly so coverage
        # gaps can be inspected without discarding the underlying event.
        category, sub_op = self.syscall_map.get(operation, ("Unknown", "Unknown.unknown"))

        event["category"] = category
        event["sub_op"] = sub_op

    def load_and_tag(self, events_dir):
      """
      Read event JSON files from `events_dir`, tag all events, and return
      a single TaggedEvents object.

      If multiple loading/execution file pairs exist in the directory, the
      mapper groups them by shared stem and aggregates all complete pairs.
      Unpaired files are skipped with a warning.
      """
      if not os.path.isdir(events_dir):
        print(f"Error: {events_dir} is not a directory")
        return None

      # Group files by shared stem so each loading/execution pair is kept
      # together as one analysis unit.
      groups = {}
      for fname in sorted(os.listdir(events_dir)):
        full_path = os.path.join(events_dir, fname)

        if fname.endswith("_loading_events.json"):
            stem = fname[:-len("_loading_events.json")]
            groups.setdefault(stem, {})["loading"] = full_path

        elif fname.endswith("_execution_events.json"):
            stem = fname[:-len("_execution_events.json")]
            groups.setdefault(stem, {})["execution"] = full_path

      if not groups:
        print(f"No event JSON files found in {events_dir}")
        return None

      tagged = TaggedEvents("combined", events_dir)

      paired_count = 0

      for stem in sorted(groups.keys()):
        loading_file = groups[stem].get("loading")
        execution_file = groups[stem].get("execution")

        # Skip incomplete pairs to avoid mixing partial evidence into the
        # downstream classifier.
        if not loading_file or not execution_file:
            missing = []
            if not loading_file:
                missing.append("loading")
            if not execution_file:
                missing.append("execution")
            print(f"  Skipping stem '{stem}' — missing {' and '.join(missing)} file")
            continue

        paired_count += 1

        # Load + tag loading events
        with open(loading_file, "r") as f:
            loading_events = json.load(f)

        for event in loading_events:
            self.tag_event(event)

        tagged.loading_events.extend(loading_events)
        print(f"  Tagged {len(loading_events)} loading events from {os.path.basename(loading_file)}")

        # Load + tag execution events
        with open(execution_file, "r") as f:
            execution_events = json.load(f)

        for event in execution_events:
            self.tag_event(event)

        tagged.execution_events.extend(execution_events)
        print(f"  Tagged {len(execution_events)} execution events from {os.path.basename(execution_file)}")

      if paired_count == 0:
        print(f"No complete loading/execution pairs found in {events_dir}")
        return None

      return tagged

    def load_and_tag_files(self, loading_file, execution_file):
        """
        Alternative entry point for directly supplied event files.

        Either argument may be None when only one phase is available, which is
        useful for debugging or partial pipeline inspection.
        """
        if loading_file:
            model_name = os.path.basename(loading_file).replace("_loading_events.json", "")
            events_dir = os.path.dirname(loading_file) or "."
        elif execution_file:
            model_name = os.path.basename(execution_file).replace("_execution_events.json", "")
            events_dir = os.path.dirname(execution_file) or "."
        else:
            print("No files provided")
            return None
        tagged = TaggedEvents(model_name, events_dir)

        if loading_file and os.path.exists(loading_file):
            with open(loading_file, 'r') as f:
                tagged.loading_events = json.load(f)
            for event in tagged.loading_events:
                self.tag_event(event)
            print(f"  Tagged {len(tagged.loading_events)} loading events")

        if execution_file and os.path.exists(execution_file):
            with open(execution_file, 'r') as f:
                tagged.execution_events = json.load(f)
            for event in tagged.execution_events:
                self.tag_event(event)
            print(f"  Tagged {len(tagged.execution_events)} execution events")

        return tagged


# ═══════════════════════════════════════════════════════════════════════════════
# CLI 
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python syscall_category_mapper.py <events_dir>")
        print("  python syscall_category_mapper.py <loading_events.json> <execution_events.json>")
        print("  python syscall_category_mapper.py <single_phase_events.json>")
        sys.exit(1)

    mapper = SyscallCategoryMapper()

    if len(sys.argv) == 2:
        arg = sys.argv[1]
        if os.path.isdir(arg):
            tagged = mapper.load_and_tag(arg)
        elif arg.endswith("_loading_events.json"):
            tagged = mapper.load_and_tag_files(arg, None)
        elif arg.endswith("_execution_events.json"):
            tagged = mapper.load_and_tag_files(None, arg)
        else:
            print(f"Error: {arg} is not a directory or a recognized event file")
            sys.exit(1)
    elif len(sys.argv) == 3:
        tagged = mapper.load_and_tag_files(sys.argv[1], sys.argv[2])
    else:
        print("Too many arguments")
        sys.exit(1)

    if tagged:
        tagged.print_summary()
