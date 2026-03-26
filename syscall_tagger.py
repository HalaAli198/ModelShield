"""
Step 1: Syscall Category Mapper

Reads the loading and execution event JSON files produced by the main
analyzer, tags every event with category and sub_op, and holds the
tagged events in memory for the next processing step.

Does NOT write back to the JSON files.

Usage:
    python syscall_category_mapper.py /path/to/model_folder/events/

    This reads:
      <events_dir>/<model>_loading_events.json
      <events_dir>/<model>_execution_events.json

    The tagged events are stored in a TaggedEvents object that the
    next step in the pipeline will consume.

As a module:
    from syscall_category_mapper import SyscallCategoryMapper

    mapper = SyscallCategoryMapper()
    tagged = mapper.load_and_tag("/path/to/model_folder/events/")

    # tagged.loading_events  -> list of dicts, each with category and sub_op added
    # tagged.execution_events -> same
    # Pass tagged directly to Stage 2

"""

import json
import os
import sys
from collections import OrderedDict


# ═══════════════════════════════════════════════════════════════════════════════
# SYSCALL -> (CATEGORY, SUB_OPERATION) LOOKUP TABLE
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
    Holds the tagged loading and execution events in memory.
    This object is passed directly to Stage 2 (pattern matching).
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
    Reads event JSON files, tags each event with category and sub_op,
    returns a TaggedEvents object holding everything in memory.
    """

    def __init__(self):
        self.syscall_map = SYSCALL_MAP

    def tag_event(self, event):
        """Add category and sub_op to one event dict."""
        operation = event.get("operation", "")
        category, sub_op = self.syscall_map.get(operation, ("Unknown", "Unknown.unknown"))
        event["category"] = category
        event["sub_op"] = sub_op

    def load_and_tag(self, events_dir):
        """
        Read JSON files from events_dir, tag all events, return TaggedEvents.

        Expects files named:
          <model_name>_loading_events.json
          <model_name>_execution_events.json

        If multiple models' events are in the same directory, processes
        the first pair found.
        """
        if not os.path.isdir(events_dir):
            print(f"Error: {events_dir} is not a directory")
            return None

        # Find the event files
        loading_file = None
        execution_file = None
        model_name = "unknown"

        for fname in os.listdir(events_dir):
            if fname.endswith("_loading_events.json"):
                loading_file = os.path.join(events_dir, fname)
                model_name = fname.replace("_loading_events.json", "")
            elif fname.endswith("_execution_events.json"):
                execution_file = os.path.join(events_dir, fname)

        tagged = TaggedEvents(model_name, events_dir)

        # Load and tag loading events
        if loading_file and os.path.exists(loading_file):
            with open(loading_file, 'r') as f:
                tagged.loading_events = json.load(f)
            for event in tagged.loading_events:
                self.tag_event(event)
            print(f"  Tagged {len(tagged.loading_events)} loading events from {os.path.basename(loading_file)}")
        else:
            print(f"  No loading events file found in {events_dir}")

        # Load and tag execution events
        if execution_file and os.path.exists(execution_file):
            with open(execution_file, 'r') as f:
                tagged.execution_events = json.load(f)
            for event in tagged.execution_events:
                self.tag_event(event)
            print(f"  Tagged {len(tagged.execution_events)} execution events from {os.path.basename(execution_file)}")
        else:
            print(f"  No execution events file found in {events_dir}")

        return tagged

    def load_and_tag_files(self, loading_file, execution_file):
        """
        Alternative: pass the two file paths directly instead of a directory.
        Either argument can be None if you only have one file.
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
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python syscall_category_mapper.py /path/to/model_folder/events/")
        print("  python syscall_category_mapper.py loading.json execution.json")
        print("  python syscall_category_mapper.py single_file.json")
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
