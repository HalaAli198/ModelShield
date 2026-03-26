"""
Attack Behavior Classifier — Ordered Subsequence Matching

Classifies syscall event sequences into AB1–AB8 attack behaviors.

Approach (7 steps):
  1. Pre-filter: remove O_DIRECTORY events
  2. Define patterns: sub_op + path + flags per step
  3. One-pass scan: all patterns tracked simultaneously
  4. Binary match: all required steps found or not
  5. Loop detection: AB5 (mining) and AB7 (ransomware)
  6. Cross-behavior correlation: compound attack detection
  7. Collect results: group by behavior, report with MITRE mappings

Usage:
    from syscall_category_mapper import SyscallCategoryMapper
    from attack_behavior_classifier import AttackBehaviorClassifier

    mapper = SyscallCategoryMapper()
    tagged = mapper.load_and_tag("/path/to/events/")

    classifier = AttackBehaviorClassifier()
    verdict = classifier.classify(tagged.loading_events, tagged.execution_events,
                                  model_path="/path/to/model")

"""

import json
import re
import os
import sys
import fnmatch
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set, Tuple
from collections import defaultdict
import time


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class MITREMapping:
    tactic: str
    technique_id: str
    technique_name: str


@dataclass
class PatternStep:
    """
    One step in an ordered pattern.
    All three constraints must be true on the same event for the step to match.
    """
    sub_op: Any               # str or set of str (e.g., "File.open" or {"File.open", "File.read"})
    path_match: Any = None    # callable(filename) -> bool, or None = any path
    flag_match: Any = None    # callable(extra_details) -> bool, or None = any flags
    description: str = ""
    optional: bool = False
    capture_fd: str = ""      # name to store fd under (e.g., "file_fd", "sock_fd")
    require_fd: str = ""      # name of previously captured fd to require match
    capture_path: str = ""    # name to store path under (e.g., "file_path")
    require_path: str = ""    # name of previously captured path to match
    
    def matches(self, event: dict) -> bool:
        ev_sub_op = event.get("sub_op", "")

        # Check sub_op
        if isinstance(self.sub_op, str):
            if ev_sub_op != self.sub_op:
                return False
        elif isinstance(self.sub_op, (set, frozenset, list, tuple)):
            if ev_sub_op not in self.sub_op:
                return False
        else:
            return False

        # Check path
        if self.path_match is not None:
            filename = event.get("filename", "")
            if not self.path_match(filename):
                return False

        # Check flags
        if self.flag_match is not None:
            details = event.get("extra_details", {})
            if not self.flag_match(details):
                return False

        return True


@dataclass
class SequencePattern:
    pattern_id: str           # e.g., "AB1-CRED-SSH-EXFIL"
    behavior_id: str          # e.g., "AB1"
    sub_behavior: str         # e.g., "SSH key theft + exfiltration"
    steps: List[PatternStep]
    mitre: List[MITREMapping] = field(default_factory=list)
    repeatable: bool = False  # If True, pattern can match multiple times
    #same_tid: bool = False 
    @property
    def required_count(self):
        return sum(1 for s in self.steps if not s.optional)


@dataclass
class PatternMatch:
    """Result of one matched pattern."""
    pattern: SequencePattern
    matched_events: List[dict]       # events that matched each step
    matched_step_indices: List[int]  # which step indices matched
    phase: str                       # "LOADING" or "EXECUTION"


@dataclass
class LoopMatch:
    """Result of loop detection (AB5/AB7)."""
    behavior_id: str
    sub_behavior: str
    loop_count: int                  # how many repetitions detected
    sample_events: List[dict]        # a few example events
    mitre: List[MITREMapping] = field(default_factory=list)
    phase: str = ""


@dataclass
class BehaviorResult:
    behavior_id: str
    behavior_name: str
    sub_behaviors: List[str]
    pattern_matches: List[PatternMatch]
    loop_matches: List[LoopMatch]
    mitre_techniques: List[MITREMapping]
    phase: str


@dataclass
class ClassificationVerdict:
    model_path: str
    is_malicious: bool
    behaviors: List[BehaviorResult]
    #compound_attacks: List[str]      # e.g., ["AB1+AB6: credential theft + reverse shell"]
    total_loading_events: int
    total_execution_events: int

    def to_dict(self):
        result = {
            "model_path": self.model_path,
            "is_malicious": self.is_malicious,
            "total_loading_events": self.total_loading_events,
            "total_execution_events": self.total_execution_events,
            #"compound_attacks": self.compound_attacks,
            "behaviors": [],
        }
        for b in self.behaviors:
            bdict = {
                "behavior_id": b.behavior_id,
                "behavior_name": b.behavior_name,
                "sub_behaviors": b.sub_behaviors,
                "phase": b.phase,
                "mitre_techniques": [
                    {"tactic": m.tactic, "technique_id": m.technique_id,
                     "technique_name": m.technique_name}
                    for m in b.mitre_techniques
                ],
                "pattern_matches": [],
                "loop_matches": [],
            }
            for pm in b.pattern_matches:
                pmdict = {
                    "pattern_id": pm.pattern.pattern_id,
                    "sub_behavior": pm.pattern.sub_behavior,
                    "matched_events": [
                        {
                            "operation": e.get("operation"),
                            "filename": e.get("filename"),
                            "sub_op": e.get("sub_op"),
                            "timestamp": e.get("timestamp"),
                            "tid": e.get("tid"),
                            "extra_details": e.get("extra_details", {}),
                        }
                        for e in pm.matched_events
                    ],
                    "mitre": [
                        {"tactic": m.tactic, "technique_id": m.technique_id,
                         "technique_name": m.technique_name}
                        for m in pm.pattern.mitre
                    ],
                }
                bdict["pattern_matches"].append(pmdict)
            for lm in b.loop_matches:
                lmdict = {
                    "behavior_id": lm.behavior_id,
                    "sub_behavior": lm.sub_behavior,
                    "loop_count": lm.loop_count,
                    "mitre": [
                        {"tactic": m.tactic, "technique_id": m.technique_id,
                         "technique_name": m.technique_name}
                        for m in lm.mitre
                    ],
                }
                bdict["loop_matches"].append(lmdict)
            result["behaviors"].append(bdict)
        return result




 
def _extract_fd(event: dict) -> Optional[int]:
    """
    Extract file descriptor from an event.
    
    Works with your actual eBPF event format:
      - read/write/close/sendmsg/recvmsg: fd in extra_details["fd"]
      - some events: fd encoded in filename as "fd=N"
    
    Returns None if fd cannot be determined.
    """
    details = event.get("extra_details", {})
    
    # Direct fd field (read, write, close, sendto, recvfrom, sendmsg, etc.)
    fd = details.get("fd")
    if fd is not None:
        try:
            return int(fd)
        except (ValueError, TypeError):
            pass
    
    # Filename encodes "fd=N" (e.g., "fd=320" or "fd=314")
    filename = event.get("filename", "")
    if filename and filename.startswith("fd="):
        try:
            fd_str = filename.split("=")[1].split()[0].split("[")[0]
            return int(fd_str)
        except (ValueError, IndexError):
            pass
    
    return None
 
 
def _extract_path(event: dict) -> str:
    """
    Extract the file path from an event.
    
    Your eBPF events resolve paths for read/write operations:
      - openat: filename = "/proc/cpuinfo"
      - read:   filename = "/proc/cpuinfo" (resolved from fd)
      - write:  filename = "/home/hala/.ssh/authorized_keys.temp..."
    
    Returns empty string if no path.
    """
    filename = event.get("filename", "")
    if not filename:
        return ""
    # Skip non-path filenames
    if filename.startswith("fd=") or filename in ("stdout", "stderr", "stdin"):
        return ""
    if filename in ("uname", "sysinfo", "sethostname", "gethostname", "getcwd"):
        return ""
    return filename
 
 
def _paths_match(captured_path: str, event_path: str) -> bool:
    """
    Check if two paths refer to the same file.
    Strict equality only — no substring matching.
    """
    if not captured_path or not event_path:
        return False
    return captured_path == event_path
# ============================================================================
# PATH / FLAG MATCHING HELPERS
# ============================================================================

def path_contains(*substrings):
    """Match if filename contains ANY of the substrings (case-insensitive)."""
    lower_subs = [s.lower() for s in substrings]
    def _match(filename):
        fn = (filename or "").lower()
        return any(s in fn for s in lower_subs)
    return _match


def path_regex(pattern):
    """Match filename against regex."""
    compiled = re.compile(pattern)
    def _match(filename):
        return bool(compiled.search(filename or ""))
    return _match


def path_glob(*patterns):
    """Match filename against glob patterns."""
    def _match(filename):
        fn = filename or ""
        return any(fnmatch.fnmatch(fn, p) for p in patterns)
    return _match


def flag_readonly():
    """File opened read-only (no write flags)."""
    def _match(details):
        flags = str(details.get("flags", ""))
        return "O_WRONLY" not in flags and "O_RDWR" not in flags
    return _match


def flag_writable():
    """File opened with write flags."""
    def _match(details):
        flags = str(details.get("flags", ""))
        return any(f in flags for f in ["O_WRONLY", "O_RDWR", "O_CREAT",
                                         "O_APPEND", "O_TRUNC"])
    return _match


def flag_family(*families):
    """Match network socket family."""
    def _match(details):
        return details.get("family", "") in families
    return _match


def flag_nonstandard_port():
    """Connect/bind to a non-standard port (not 80/443/8080/8443/53/22)."""
    standard = {80, 443, 8080, 8443, 53, 22}
    def _match(details):
        port = details.get("port", 0)
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                return False
        return port > 0 and port not in standard
    return _match


def flag_nonlocal_address():
    """Connect to a non-localhost address."""
    local_prefixes = ("127.", "0.0.0.0", "::1", "0:0:0:0")
    def _match(details):
        addr = str(details.get("address", ""))
        if not addr:
            return True  # if we can't tell, assume non-local
        return not any(addr.startswith(p) for p in local_prefixes)
    return _match


def flag_inet_connect():
    """Network connect to non-local, non-standard port over AF_INET/AF_INET6."""
    _family = flag_family("AF_INET", "AF_INET6")
    _port = flag_nonstandard_port()
    _addr = flag_nonlocal_address()
    def _match(details):
        return _family(details) and _port(details) and _addr(details)
    return _match

def flag_inet_remote():
    """Connect to any non-localhost AF_INET/AF_INET6 address (any port)."""
    _family = flag_family("AF_INET", "AF_INET6")
    _addr = flag_nonlocal_address()
    def _match(details):
        return _family(details) and _addr(details)
    return _match
    
def flag_inet_any():
    """Any AF_INET/AF_INET6 connection (including standard ports)."""
    def _match(details):
        return details.get("family", "") in ("AF_INET", "AF_INET6")
    return _match


def flag_netlink_route():
    """Socket family is AF_NETLINK with NETLINK_ROUTE protocol."""
    def _match(details):
        return (details.get("family", "") == "AF_NETLINK" and
                details.get("protocol", "") == "NETLINK_ROUTE")
    return _match


def flag_netlink_netfilter():
    """Socket family is AF_NETLINK with NETLINK_NETFILTER protocol."""
    def _match(details):
        return (details.get("family", "") == "AF_NETLINK" and
                details.get("protocol", "") == "NETLINK_NETFILTER")
    return _match


def flag_ioctl_netif():
    """ioctl request is a network interface query."""
    net_ioctls = {"SIOCGIFCONF", "SIOCGIFADDR", "SIOCGIFNETMASK",
                  "SIOCGIFBRDADDR", "SIOCGIFFLAGS", "SIOCGIFHWADDR"}
    def _match(details):
        req = str(details.get("request", ""))
        return any(i in req for i in net_ioctls)
    return _match


def flag_ioctl_netif_set():
    """ioctl request is a network interface modification."""
    set_ioctls = {"SIOCSIFFLAGS", "SIOCSIFADDR", "SIOCSIFNETMASK",
                  "SIOCSIFBRDADDR", "SIOCSIFMTU", "SIOCADDRT", "SIOCDELRT"}
    def _match(details):
        req = str(details.get("request", ""))
        return any(i in req for i in set_ioctls)
    return _match


def flag_sockopt_iptables():
    """setsockopt for iptables manipulation."""
    def _match(details):
        optname = str(details.get("optname", ""))
        return "IPT_SO_SET_REPLACE" in optname or "IP6T_SO_SET_REPLACE" in optname
    return _match


def flag_wx_prot(details):
    """mmap/mprotect with both PROT_WRITE and PROT_EXEC."""
    prot = str(details.get("protection", ""))
    return "PROT_WRITE" in prot and "PROT_EXEC" in prot


def flag_exec_prot(details):
    """mprotect adding PROT_EXEC (not library loading with MAP_FIXED)."""
    prot = str(details.get("protection", ""))
    flags = str(details.get("flags", ""))
    if "PROT_EXEC" not in prot:
        return False
    if "MAP_FIXED" in flags:
        return False
    return True


def flag_mining_port():
    """Connect to a common mining pool port."""
    mining_ports = {3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700}
    def _match(details):
        port = details.get("port", 0)
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                return False
        return port in mining_ports
    return _match

def flag_root_elevation():
    """Check if privilege elevation targets root (uid=0/gid=0).
    Checks both filename field and extra_details for flexibility
    across different eBPF event formats."""
    def _match_path(filename):
        fn = (filename or "").lower()
        return "uid=0" in fn or "gid=0" in fn or "=0" in fn
    return _match_path


def flag_root_elevation_details():
    """Check extra_details for root elevation indicators."""
    def _match(details):
        for key in ("uid", "ruid", "euid", "suid", "gid", "rgid", "egid", "sgid"):
            val = details.get(key)
            if val is not None:
                try:
                    if int(val) == 0:
                        return True
                except (ValueError, TypeError):
                    pass
        # Also check if filename-style encoding is in any detail value
        for v in details.values():
            if isinstance(v, str) and ("uid=0" in v or "gid=0" in v):
                return True
        return False
    return _match
    
def _match_keygen(filename):
    """Match key generation events: /dev/urandom reads or getrandom with size >= 16."""
    fn = filename or ""
    if "/dev/urandom" in fn:
        return True
    if "getrandom_size=" in fn:
        try:
            size_str = fn.split("getrandom_size=")[-1].split()[0]
            return int(size_str) >= 16
        except (ValueError, IndexError):
            return False
    if "getrandom" in fn:
        return True
    return False
    
def _flag_remote_service_port():
    """Connect to a common remote service port (SSH, RDP, SMB, VNC)."""
    remote_ports = {22, 3389, 445, 5900, 5901, 5985, 5986}
    def _match(details):
        fam = details.get("family", "")
        if fam not in ("AF_INET", "AF_INET6"):
            return False
        port = details.get("port", 0)
        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                return False
        addr = str(details.get("address", ""))
        local_prefixes = ("127.", "0.0.0.0", "::1", "0:0:0:0")
        if any(addr.startswith(p) for p in local_prefixes):
            return False
        return port in remote_ports
    return _match   
    
# ============================================================================
# SENSITIVE PATH LISTS (from taxonomy)
# ============================================================================

_SYS_INFO_PATHS = [
    "/proc/version", "/proc/sys/kernel/ostype", "/proc/sys/kernel/osrelease",
    "/etc/os-release", "/etc/lsb-release", "/etc/redhat-release",
]

_HOSTNAME_PATHS = [
    "/proc/sys/kernel/hostname", "/etc/hostname", "/proc/sys/kernel/domainname",
]

_NET_CONFIG_PATHS = [
    "/proc/net/route", "/proc/net/if_inet6", "/proc/net/arp",
    "/proc/net/dev", "/proc/net/wireless",
    "/proc/net/dev_mcast", "/proc/net/igmp",
    "/etc/resolv.conf", "/etc/hosts",
    "/sys/class/net/",
]

_NET_CONNECTIONS_PATHS = [
    "/proc/net/tcp", "/proc/net/tcp6",
    "/proc/net/udp", "/proc/net/udp6",
]

_HARDWARE_PATHS = [
    "/proc/cpuinfo", "/proc/meminfo", "/proc/uptime",
    "/proc/partitions", "/proc/loadavg", "/proc/cgroups",
    "/sys/devices/system/cpu/", "/sys/class/dmi/id/",
]

_ENV_PATHS = [
    "/proc/self/environ", "/etc/environment",
]

_USER_ACCOUNT_PATHS = [
    "/etc/subuid", "/etc/subgid", "/etc/login.defs",
    "/etc/passwd", "/etc/group", "/etc/shadow",
]

_CRED_LOGIN = [
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group",
    "/var/backups/shadow", "/etc/security/opasswd",
    "/var/log/auth.log", "/var/log/secure",
    "/var/log/lastlog", "/var/log/btmp", "/var/log/wtmp",
]

_CRED_BROWSER = [
    ".config/google-chrome/", ".config/chromium/",
    ".config/BraveSoftware/", ".config/microsoft-edge/",
    ".mozilla/firefox/", "Cookies", "Login Data",
    "logins.json", "key4.db", "key3.db", "cookies.sqlite", "cert9.db",
]

_CRED_SSH = [
    ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa",
    ".ssh/id_ed25519_sk", ".ssh/authorized_keys", ".ssh/config",
    ".ssh/known_hosts", "/etc/ssh/ssh_host_", "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config", ".ssh/",
]

_CRED_CLOUD = [
    ".aws/credentials", ".aws/config",
    ".azure/accessTokens.json", ".azure/azureProfile.json", ".azure/msal_token_cache",
    ".config/gcloud/application_default_credentials.json",
    ".config/gcloud/credentials.db",
    ".config/gh/hosts.yml", ".docker/config.json",
    ".kube/config", "kubernetes.io/serviceaccount/token",
]

_CRED_CRYPTO = [
    ".ethereum/keystore/", ".bitcoin/wallets/",
    ".electrum/wallets/", ".local/share/Ethereum/keystore/",
]

_CRED_TOKENS = [
    ".netrc", ".git-credentials", ".npmrc", ".pypirc",
    ".terraform.d/credentials.tfrc.json", ".gem/credentials",
    ".config/rclone/rclone.conf", ".config/s3cmd/s3cfg",
]

_CRED_DISCORD = [
    ".config/discord/Local Storage/leveldb/",
    ".config/discordcanary/Local Storage/leveldb/",
    ".config/discordptb/Local Storage/leveldb/",
]

_CRED_KEYRING = [
    ".local/share/keyrings/", ".gnupg/",
    ".local/share/kwalletd/", ".cache/kwalletd/",
    ".config/keepassxc/", "/etc/krb5.keytab",
    ".config/kwalletrc", ".k5login",
     "gnupg/",
]

_FILE_CONFIG = [
    ".gitconfig", ".bashrc", ".zshrc", ".profile",
    ".bash_profile", ".zprofile", ".zshenv", ".vimrc", ".tmux.conf",
]

_FILE_HISTORY = [
    ".bash_history", ".zsh_history",
]

_FILE_LOGS = ["/var/log/"]

_FILE_TMP = ["/tmp/", "/var/tmp/", "/dev/shm/", ".cache/"]

# Persistence paths
_PERSIST_CRON = [
    "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/",
    "/var/spool/cron/crontabs/",
]

_PERSIST_SYSTEMD = [
    "/etc/systemd/system/", "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
]

_PERSIST_INIT = [
    "/etc/init.d/", "/etc/rc.local", "/etc/rc.d/",
]

_PERSIST_PROFILE = [
    ".bashrc", ".profile", ".bash_profile", ".zshrc",
    "/etc/profile", "/etc/profile.d/",
]

_PERSIST_BOOT = [
    "/etc/default/grub", "/boot/grub", "/boot/grub2",
    "/boot/loader/entries/", "/sys/firmware/efi/efivars/",
]

# Desktop autostart persistence
_PERSIST_AUTOSTART = [
    ".config/autostart/",
]

# LD linker paths (preload and conf)
_PERSIST_LDCONF = [
    "/etc/ld.so.conf", "/etc/ld.so.conf.d/",
]

# Kernel module config persistence
_PERSIST_KMOD_CONFIG = [
    "/etc/modprobe.d/", "/etc/modules-load.d/",
    "/lib/modules/",
]

# Cron access control
_PERSIST_CRON_ACCESS = [
    "/etc/cron.allow", "/etc/cron.deny",
    "/etc/at.allow", "/etc/at.deny",
]

# System manipulation paths
_MAC_PATHS = [
    "/sys/fs/selinux/", "/sys/kernel/security/apparmor/",
    "/etc/selinux/config",
]

_FIREWALL_PATHS = [
    "/etc/nftables.conf", "/etc/iptables/",
    "/etc/ufw/", "/etc/firewalld/",
]

_LOGGING_PATHS = [
    "/etc/rsyslog.conf", "/etc/rsyslog.d/", "/etc/syslog-ng/",
    "/etc/systemd/journald.conf",
]

_NET_MANIP_PATHS = [
    "/proc/sys/net/", "/etc/network/", "/etc/netplan/",
    "/etc/sysconfig/network", "/etc/NetworkManager/",
]

_SECURITY_SETTING_PATHS = [
    "/proc/sys/kernel/kptr_restrict", "/proc/sys/kernel/dmesg_restrict",
    "/proc/sys/kernel/yama/ptrace_scope", "/proc/sys/kernel/unprivileged_bpf_disabled",
]

_AUDIT_PATHS = [
    "/proc/sys/kernel/audit", "/etc/audit/", "/etc/audisp/",
    "/etc/default/auditd",
]


_SHELL_PATHS = ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh",
                "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh"]

# Paths for AB3 policy manipulation (sudoers + PAM + security config)
_POLICY_PATHS = [
    "/etc/sudoers", "/etc/sudoers.d/",
    "/etc/pam.d/", "/etc/security/",
    "/etc/securetty", "/etc/polkit-1/rules.d/",
]

# Fstab
_FSTAB_PATHS = ["/etc/fstab"]

# Core pattern hijack
_CORE_PATTERN_PATHS = ["/proc/sys/kernel/core_pattern"]

# Sysctl persistence
_SYSCTL_PATHS = ["/etc/sysctl.conf", "/etc/sysctl.d/"]

# Hosts access control
_HOSTS_ACCESS_PATHS = ["/etc/hosts.allow", "/etc/hosts.deny"]

# Database config paths (credential stores)
_DB_CONFIG_PATHS = [
    "/etc/mysql/", "/root/.my.cnf",
    ".pgpass", "/var/lib/pgsql/data/pg_hba.conf",
    "/etc/redis/redis.conf", "/etc/mongod.conf",
]

# Container runtime paths
_CONTAINER_PATHS = [
    "/etc/docker/", "/etc/containerd/", "/etc/crio/",
    "/var/lib/docker/",
]

# SSL/TLS private keys
_SSL_KEY_PATHS = [
    "/etc/ssl/private/", "/etc/pki/tls/private/",
    "/etc/letsencrypt/live/",
]

_NET_PREP_PATHS = [
    "/usr/lib/ssl/openssl.cnf", "/usr/lib/ssl/cert.pem",
    "/usr/lib/ssl/certs/", "/etc/ssl/openssl.cnf",
    "/etc/ssl/cert.pem", "/etc/ssl/certs/",
    "/etc/pki/tls/", "/etc/ca-certificates/",
    "/usr/share/ca-certificates/",
]

_DNS_RESOLVE_PATHS = [
    "/etc/resolv.conf", "/etc/nsswitch.conf",
    "/etc/host.conf", "/etc/hosts",
    "/etc/gai.conf",
]


# ============================================================================
# STEP 1: PRE-FILTER
# ============================================================================

def prefilter_events(events: list) -> list:
    """
    Remove File.open events where flags contain O_DIRECTORY.
    These are directory existence checks, not file access.
    """
    filtered = []
    for ev in events:
        if ev.get("sub_op") == "File.open":
            flags = str(ev.get("extra_details", {}).get("flags", ""))
            if "O_DIRECTORY" in flags:
                continue
        filtered.append(ev)
    return filtered


# ============================================================================
# STEP 2: PATTERN DEFINITIONS
# ============================================================================

def _ab1_exfil(pid, sub, paths, mitre_list):
    """AB1 helper: open(sensitive, readonly) → read → connect(suspicious) → send."""
    return SequencePattern(
        pattern_id=pid,
        behavior_id="AB1",
        sub_behavior=sub,
        mitre=mitre_list,
        #same_tid=True, 
        steps=[
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*paths),
                flag_match=flag_readonly(),
                description=f"Open sensitive file ({sub})",
                capture_path="file_path",  
            ),
            PatternStep(
                sub_op="File.read",
                description="Read file contents",
                require_path="file_path",
            ),
            PatternStep(
                sub_op="Network.socket",
                description="Create network socket",
                optional=True,
            ),
            PatternStep(
                sub_op="Network.connect",
                flag_match=flag_inet_remote(),
                description="Connect to suspicious remote server",
            ),
            PatternStep(
               sub_op={"Network.send", "File.sendfile", "File.write"},
               path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
               description="Send stolen data",
            ),
        ],
    )



def _ab1_exfil_udp(pid, sub, paths, mitre_list):
    """AB1 helper: open(sensitive, readonly) → read → socket(AF_INET) → sendto (UDP, no connect)."""
    return SequencePattern(
        pattern_id=pid,
        behavior_id="AB1",
        sub_behavior=sub,
        mitre=mitre_list,
        #same_tid=True,
        steps=[
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*paths),
                flag_match=flag_readonly(),
                description=f"Open sensitive file ({sub})",
                capture_path="file_path",     
            ),
            PatternStep(
                sub_op="File.read",
                description="Read file contents",
                require_path="file_path"
            ),
            PatternStep(
                sub_op="Network.socket",
                flag_match=flag_family("AF_INET", "AF_INET6"),
                description="Create UDP socket (AF_INET/AF_INET6)",
            ),
            PatternStep(
                sub_op="Network.send",
                description="Send stolen data (UDP sendto)",
            ),
        ],
    )




def build_ab1_patterns() -> List[SequencePattern]:
    patterns = []

    # ------------------------------------------------------------------
    # System info exfil variants (TCP + UDP + read-only)
    # ------------------------------------------------------------------
    for pid, sub, paths, mitre in [
        ("AB1-SYS-EXFIL", "OS/kernel version theft + exfiltration", _SYS_INFO_PATHS,
         [MITREMapping("Discovery", "T1082", "System Information Discovery"),
          MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]),
        ("AB1-HOST-EXFIL", "Hostname theft + exfiltration", _HOSTNAME_PATHS,
         [MITREMapping("Discovery", "T1082", "System Information Discovery"),
          MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]),
        ("AB1-NET-EXFIL", "Network config theft + exfiltration", _NET_CONFIG_PATHS,
         [MITREMapping("Discovery", "T1016", "System Network Configuration Discovery"),
          MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]),
        ("AB1-NETCONN-EXFIL", "Network connections theft + exfiltration", _NET_CONNECTIONS_PATHS,
         [MITREMapping("Discovery", "T1049", "System Network Connections Discovery"),
          MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]),
          
        ("AB1-ENV-EXFIL", "Environment variable theft + exfiltration", _ENV_PATHS,
         [MITREMapping("Discovery", "T1082", "System Information Discovery"),
          MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]),
        ("AB1-USERACCT-EXFIL", "User account info theft + exfiltration", _USER_ACCOUNT_PATHS,
         [MITREMapping("Discovery", "T1033", "System Owner/User Discovery"),
          MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]),
    ]:
        patterns.append(_ab1_exfil(pid, sub, paths, mitre))
        patterns.append(_ab1_exfil_udp(pid + "-UDP", sub + " (UDP)", paths,
                                        [m for m in mitre if m.technique_id != "T1041"] +
                                        [MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")]))
        

    # Hardware — exfil only, read-only is framework noise
    patterns.append(_ab1_exfil(
        "AB1-HW-EXFIL", "Hardware info theft + exfiltration", _HARDWARE_PATHS,
        [MITREMapping("Discovery", "T1082", "System Information Discovery"),
         MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]))
    patterns.append(_ab1_exfil_udp(
        "AB1-HW-EXFIL-UDP", "Hardware info theft + exfiltration (UDP)", _HARDWARE_PATHS,
        [MITREMapping("Discovery", "T1082", "System Information Discovery"),
         MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")]))

    # ------------------------------------------------------------------
    # uname/sysinfo/gethostname → connect → send (TCP)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-UNAME-EXFIL",
        behavior_id="AB1",
        sub_behavior="System fingerprint via syscall + exfiltration",
        mitre=[MITREMapping("Discovery", "T1082", "System Information Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,       
        steps=[
            PatternStep(sub_op={"System.info", "System.identity"},
                        description="System fingerprint syscall"),
            PatternStep(sub_op="Network.socket", description="Create socket", optional=True),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"},
                        path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Transmit fingerprint"),
        ],
    ))

    # ------------------------------------------------------------------
    # uname/sysinfo/gethostname → socket → sendto (UDP)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-UNAME-EXFIL-UDP",
        behavior_id="AB1",
        sub_behavior="System fingerprint via syscall + exfiltration (UDP)",
        mitre=[MITREMapping("Discovery", "T1082", "System Information Discovery"),
               MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op={"System.info", "System.identity"},
                        description="System fingerprint syscall"),
            PatternStep(sub_op="Network.socket",
                        flag_match=flag_family("AF_INET", "AF_INET6"),
                        description="Create UDP socket (AF_INET/AF_INET6)"),
            PatternStep(sub_op="Network.send",
                        description="Send fingerprint (UDP sendto)"),
        ],
    ))
    # ------------------------------------------------------------------
    # Netlink discovery + TCP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-NETLINK-RECON-EXFIL",
        behavior_id="AB1",
        sub_behavior="Netlink-based network discovery + exfiltration",
        mitre=[MITREMapping("Discovery", "T1016", "System Network Configuration Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="Network.socket", flag_match=flag_netlink_route(),
                        description="Create AF_NETLINK NETLINK_ROUTE socket"),
            PatternStep(sub_op="Network.bind", description="Bind netlink socket", optional=True),
            PatternStep(sub_op="Network.send", description="Send RTM_GET* request"),
            PatternStep(sub_op="Network.recv", description="Receive netlink response"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"},
                        path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Exfiltrate network config"),
        ],
    ))

    # ------------------------------------------------------------------
    # Netlink discovery + UDP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-NETLINK-RECON-EXFIL-UDP",
        behavior_id="AB1",
        sub_behavior="Netlink-based network discovery + exfiltration (UDP)",
        mitre=[MITREMapping("Discovery", "T1016", "System Network Configuration Discovery"),
               MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="Network.socket", flag_match=flag_netlink_route(),
                        description="Create AF_NETLINK NETLINK_ROUTE socket"),
            PatternStep(sub_op="Network.bind", description="Bind netlink socket", optional=True),
            PatternStep(sub_op="Network.send", description="Send RTM_GET* request"),
            PatternStep(sub_op="Network.recv", description="Receive netlink response"),
            PatternStep(sub_op="Network.socket",
                        flag_match=flag_family("AF_INET", "AF_INET6"),
                        description="Create UDP socket"),
            PatternStep(sub_op="Network.send", description="Exfiltrate (UDP sendto)"),
        ],
    ))
    
    # ------------------------------------------------------------------
    # ioctl discovery + TCP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-IOCTL-NETIF-EXFIL",
        behavior_id="AB1",
        sub_behavior="ioctl-based network discovery + exfiltration",
        mitre=[MITREMapping("Discovery", "T1016", "System Network Configuration Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="System.ioctl", flag_match=flag_ioctl_netif(),
                        description="ioctl SIOCGIF* network interface query"),
            PatternStep(sub_op="Network.socket", description="Create socket", optional=True),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"},
                        path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Exfiltrate network config"),
        ],
    ))

    # ------------------------------------------------------------------
    # ioctl discovery + UDP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-IOCTL-NETIF-EXFIL-UDP",
        behavior_id="AB1",
        sub_behavior="ioctl-based network discovery + exfiltration (UDP)",
        mitre=[MITREMapping("Discovery", "T1016", "System Network Configuration Discovery"),
               MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="System.ioctl", flag_match=flag_ioctl_netif(),
                        description="ioctl SIOCGIF* network interface query"),
            PatternStep(sub_op="Network.socket",
                        flag_match=flag_family("AF_INET", "AF_INET6"),
                        description="Create UDP socket"),
            PatternStep(sub_op="Network.send", description="Exfiltrate (UDP sendto)"),
        ],
    ))
    
    
    # ------------------------------------------------------------------
    # Socket info discovery + TCP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-SOCKINFO-EXFIL",
        behavior_id="AB1",
        sub_behavior="Socket-based network discovery + exfiltration",
        mitre=[MITREMapping("Discovery", "T1016", "System Network Configuration Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="Network.info",
                        description="Query socket info (getsockname/getsockopt)"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"},
                        path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Exfiltrate network info"),
        ],
    ))

    # ------------------------------------------------------------------
    # Socket info discovery + UDP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-SOCKINFO-EXFIL-UDP",
        behavior_id="AB1",
        sub_behavior="Socket-based network discovery + exfiltration (UDP)",
        mitre=[MITREMapping("Discovery", "T1016", "System Network Configuration Discovery"),
               MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="Network.info",
                        description="Query socket info (getsockname/getsockopt)"),
            PatternStep(sub_op="Network.socket",
                        flag_match=flag_family("AF_INET", "AF_INET6"),
                        description="Create UDP socket"),
            PatternStep(sub_op="Network.send",
                        description="Exfiltrate (UDP sendto)"),
        ],
    ))
    # ------------------------------------------------------------------
    # File/directory discovery (T1083)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-DIR-DISCOVERY",
        behavior_id="AB1",
        sub_behavior="File and directory discovery + exfiltration",
        mitre=[MITREMapping("Discovery", "T1083", "File and Directory Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="File.enumerate",
                        path_match=path_contains("/home", "/etc", "/var", "/opt", "/usr"),
                        description="Enumerate sensitive directories"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"}, path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"), description="Exfiltrate listing"),
        ],
    ))

    # ------------------------------------------------------------------
    # getcwd discovery + exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-CWD-EXFIL",
        behavior_id="AB1",
        sub_behavior="Current working directory discovery + exfiltration",
        mitre=[MITREMapping("Discovery", "T1083", "File and Directory Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="File.getcwd", description="Get current working directory"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"}, path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Send CWD info"),
        ],
    ))

    # ------------------------------------------------------------------
    # Process enumeration (TCP)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-PROC-ENUM-EXFIL",
        behavior_id="AB1",
        sub_behavior="Process enumeration + exfiltration",
        mitre=[MITREMapping("Discovery", "T1057", "Process Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="File.enumerate", path_match=path_contains("/proc"),
                        description="Enumerate /proc"),
            PatternStep(sub_op="File.open",
                        path_match=path_regex(r"/proc/\d+/(cmdline|comm|status|environ|maps|cgroup)"),
                        flag_match=flag_readonly(),
                        description="Open process info file", capture_path="file_path"),
            PatternStep(sub_op="File.read", description="Read process data", require_path="file_path"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"},
                        path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Exfiltrate"),
        ],
    ))

    # ------------------------------------------------------------------
    # Process enumeration (UDP)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-PROC-ENUM-EXFIL-UDP",
        behavior_id="AB1",
        sub_behavior="Process enumeration + exfiltration (UDP)",
        mitre=[MITREMapping("Discovery", "T1057", "Process Discovery"),
               MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="File.enumerate", path_match=path_contains("/proc"),
                        description="Enumerate /proc"),
            PatternStep(sub_op="File.open",
                        path_match=path_regex(r"/proc/\d+/(cmdline|comm|status|environ|maps|cgroup)"),
                        flag_match=flag_readonly(),
                        description="Open process info file",capture_path="file_path"),
            PatternStep(sub_op="File.read", description="Read process data",require_path="file_path"),
            PatternStep(sub_op="Network.socket",
                        flag_match=flag_family("AF_INET", "AF_INET6"),
                        description="Create UDP socket"),
            PatternStep(sub_op="Network.send",
                        description="Exfiltrate (UDP sendto)"),
        ],
    ))
    
    
    # ------------------------------------------------------------------
    # Permission query discovery + TCP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-PERMQUERY-EXFIL",
        behavior_id="AB1",
        sub_behavior="User/group ID discovery + exfiltration",
        mitre=[MITREMapping("Discovery", "T1033", "System Owner/User Discovery"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="Permission.query",
                        description="Query UID/GID (getuid/geteuid/getgid/getegid/getgroups)"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"},
                        path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Exfiltrate user/group info"),
        ],
    ))

    # ------------------------------------------------------------------
    # Permission query discovery + UDP exfiltration
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-PERMQUERY-EXFIL-UDP",
        behavior_id="AB1",
        sub_behavior="User/group ID discovery + exfiltration (UDP)",
        mitre=[MITREMapping("Discovery", "T1033", "System Owner/User Discovery"),
               MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="Permission.query",
                        description="Query UID/GID (getuid/geteuid/getgid/getegid/getgroups)"),
            PatternStep(sub_op="Network.socket",
                        flag_match=flag_family("AF_INET", "AF_INET6"),
                        description="Create UDP socket"),
            PatternStep(sub_op="Network.send",
                        description="Exfiltrate (UDP sendto)"),
        ],
    ))
    # ------------------------------------------------------------------
    # Credential theft variants (TCP + UDP + read-only)
    # ------------------------------------------------------------------
    for pid, sub, paths, mitre in [
        ("AB1-CRED-LOGIN", "Login credential theft", _CRED_LOGIN,
         [MITREMapping("Credential Access", "T1003.008", "/etc/passwd and /etc/shadow")]),
        ("AB1-CRED-BROWSER", "Browser credential theft", _CRED_BROWSER,
         [MITREMapping("Credential Access", "T1555.003", "Credentials from Web Browsers")]),
        ("AB1-CRED-SSH", "SSH key theft", _CRED_SSH,
         [MITREMapping("Credential Access", "T1552.004", "Private Keys")]),
        ("AB1-CRED-CLOUD", "Cloud credential theft", _CRED_CLOUD,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),
        ("AB1-CRED-CRYPTO", "Cryptocurrency wallet theft", _CRED_CRYPTO,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),
        ("AB1-CRED-TOKEN", "Auth token theft", _CRED_TOKENS,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),
        ("AB1-CRED-DISCORD", "Discord token theft", _CRED_DISCORD,
         [MITREMapping("Credential Access", "T1550.004", "Web Session Cookie")]),
        ("AB1-CRED-KEYRING", "Keyring content theft", _CRED_KEYRING,
         [MITREMapping("Credential Access", "T1555.005", "Password Managers")]),
        ("AB1-CRED-SSL", "SSL/TLS private key theft", _SSL_KEY_PATHS,
         [MITREMapping("Credential Access", "T1552.004", "Private Keys")]),
        ("AB1-CRED-DBCONFIG", "Database config credential theft", _DB_CONFIG_PATHS,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),
        ("AB1-CRED-CONTAINER", "Container runtime credential theft", _CONTAINER_PATHS,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),
    ]:
        exfil_mitre = mitre + [MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]
        patterns.append(_ab1_exfil(pid + "-EXFIL", sub + " + exfiltration", paths, exfil_mitre))
        udp_mitre = mitre + [MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")]
        patterns.append(_ab1_exfil_udp(pid + "-EXFIL-UDP", sub + " + exfiltration (UDP)", paths, udp_mitre))
     

    # ------------------------------------------------------------------
    # File theft variants (TCP + UDP)
    # ------------------------------------------------------------------
    for pid, sub, paths, mitre in [
        ("AB1-FILE-CONFIG", "Configuration file theft", _FILE_CONFIG,
         [MITREMapping("Collection", "T1005", "Data from Local System")]),
        ("AB1-FILE-HISTORY", "Command history theft", _FILE_HISTORY,
         [MITREMapping("Credential Access", "T1552.003", "Bash History")]),
        ("AB1-FILE-LOGS", "Log file theft", _FILE_LOGS,
         [MITREMapping("Collection", "T1005", "Data from Local System")]),
        ("AB1-FILE-TMP", "Temporary/cache file theft", _FILE_TMP,
         [MITREMapping("Collection", "T1005", "Data from Local System")]),
    ]:
        exfil_mitre = mitre + [MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]
        patterns.append(_ab1_exfil(pid + "-EXFIL", sub + " + exfiltration", paths, exfil_mitre))
        udp_mitre = mitre + [MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")]
        patterns.append(_ab1_exfil_udp(pid + "-EXFIL-UDP", sub + " + exfiltration (UDP)", paths, udp_mitre))

    # ------------------------------------------------------------------
    # Archive before exfil (T1560)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-ARCHIVE-EXFIL",
        behavior_id="AB1",
        sub_behavior="Archive collected data before exfiltration",
        mitre=[MITREMapping("Collection", "T1560", "Archive Collected Data"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains("tar", "gzip", "zip", "bzip2", "xz", "7z"),
                        description="Execute archive/compression tool"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"}, path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"), description="Exfiltrate archive"),
        ],
    ))
    # ------------------------------------------------------------------
    # Keylogging via /dev/input (T1056.001)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-KEYLOG",
        behavior_id="AB1",
        sub_behavior="Keylogging via /dev/input",
        mitre=[MITREMapping("Credential Access", "T1056.001", "Keylogging")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains("/dev/input/event", "/dev/input/by-"),
                        flag_match=flag_readonly(),
                        description="Open input device",capture_path="file_path"),
            PatternStep(sub_op="File.read",
                        description="Read input events",require_path="file_path"),
        ],
    ))

    # Keylogging + exfiltration
    patterns.append(SequencePattern(
        pattern_id="AB1-KEYLOG-EXFIL",
        behavior_id="AB1",
        sub_behavior="Keylogging + exfiltration",
        mitre=[MITREMapping("Credential Access", "T1056.001", "Keylogging"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains("/dev/input/event", "/dev/input/by-"),
                        flag_match=flag_readonly(),
                        description="Open input device",capture_path="file_path"),
            PatternStep(sub_op="File.read",
                        description="Read input events",require_path="file_path"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"}, path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Exfiltrate keystrokes"),
        ],
    ))
    
    # ------------------------------------------------------------------
    # Network shared drive data theft (T1039)
    # ------------------------------------------------------------------
    patterns.append(_ab1_exfil(
        "AB1-NETSHARE-EXFIL", "Network share data theft + exfiltration",
        ["/mnt/", "/nfs/", "/smb/", "/cifs/"],
        [MITREMapping("Collection", "T1039", "Data from Network Shared Drive"),
         MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]))
    patterns.append(_ab1_exfil_udp(
        "AB1-NETSHARE-EXFIL-UDP", "Network share data theft + exfiltration (UDP)",
        ["/mnt/", "/nfs/", "/smb/", "/cifs/"],
        [MITREMapping("Collection", "T1039", "Data from Network Shared Drive"),
         MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")]))

    # ------------------------------------------------------------------
    # Removable media data theft (T1025)
    # ------------------------------------------------------------------
    patterns.append(_ab1_exfil(
        "AB1-REMOVABLE-EXFIL", "Removable media data theft + exfiltration",
        ["/media/", "/run/media/"],
        [MITREMapping("Collection", "T1025", "Data from Removable Media"),
         MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")]))
    patterns.append(_ab1_exfil_udp(
        "AB1-REMOVABLE-EXFIL-UDP", "Removable media data theft + exfiltration (UDP)",
        ["/media/", "/run/media/"],
        [MITREMapping("Collection", "T1025", "Data from Removable Media"),
         MITREMapping("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")]))
    
    # ------------------------------------------------------------------
    # Command-based sensitive file access (os.system / subprocess)
    # Catches: os.system('cat /etc/passwd'), subprocess.run(['grep', 'root', '/etc/shadow'])
    # The exec of a file-reading tool followed by open+read of sensitive files
    # is the primary attack vector for malicious pickle payloads.
    # ------------------------------------------------------------------

    # Aggregate all credential paths into one list for command-based patterns
    # For command-based patterns, exclude /etc/passwd and /etc/group
    # which are read by glibc getpwuid() in every command execution
    _CRED_LOGIN_CMD = [p for p in _CRED_LOGIN
                       if p not in ("/etc/passwd", "/etc/group")]
    _CRED_ALL_PATHS = (
        _CRED_LOGIN_CMD + _CRED_SSH + _CRED_CLOUD + _CRED_TOKENS +
        _CRED_BROWSER + _CRED_CRYPTO + _CRED_KEYRING + _CRED_DISCORD +
        _SSL_KEY_PATHS + _DB_CONFIG_PATHS + _CONTAINER_PATHS
    )

    # File-reading commands that are suspicious when targeting sensitive files
    _FILE_READ_COMMANDS = [
        "cat", "head", "tail", "xxd", "base64", "strings",
        "grep", "awk", "sed", "less", "more", "tac",
        "sort", "cut", "od", "hexdump",
    ]

    # exec(file-reading tool) → open(credential file) → read
    patterns.append(SequencePattern(
        pattern_id="AB1-EXEC-CRED-ACCESS",
        behavior_id="AB1",
        sub_behavior="Command-based credential file access",
        mitre=[
            MITREMapping("Credential Access", "T1003.008", "/etc/passwd and /etc/shadow"),
            MITREMapping("Execution", "T1059.004", "Unix Shell"),
        ],
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(*_FILE_READ_COMMANDS),
                description="Execute file-reading command (cat/head/grep/etc.)",
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_CRED_ALL_PATHS),
                flag_match=flag_readonly(),
                description="Open credential/sensitive file",capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read credential data",require_path="file_path"
            ),
        ],
    ))

    # exec(file-reading tool) → open(system info file) → read
    _USER_ACCOUNT_CMD = [p for p in _USER_ACCOUNT_PATHS
                         if p not in ("/etc/passwd", "/etc/group")]
    _SYSINFO_ALL_PATHS = (
        _SYS_INFO_PATHS + _HOSTNAME_PATHS + _NET_CONFIG_PATHS +
        _NET_CONNECTIONS_PATHS + _ENV_PATHS +
        _USER_ACCOUNT_CMD
    )
    # NOTE: _HARDWARE_PATHS intentionally excluded from command-based patterns.
    # Reading /proc/cpuinfo, /sys/devices/system/cpu/, etc. is standard
    # behavior for ML frameworks (NumPy, PyTorch, OpenMP) doing CPU
    # feature/topology detection. Hardware info is only flagged when
    # followed by network exfiltration (AB1-HW-EXFIL patterns).

    patterns.append(SequencePattern(
        pattern_id="AB1-EXEC-SYSINFO-ACCESS",
        behavior_id="AB1",
        sub_behavior="Command-based system info access",
        mitre=[
            MITREMapping("Discovery", "T1082", "System Information Discovery"),
            MITREMapping("Execution", "T1059.004", "Unix Shell"),
        ],
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(*_FILE_READ_COMMANDS),
                description="Execute file-reading command", 
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_SYSINFO_ALL_PATHS),
                flag_match=flag_readonly(),
                description="Open system info file",capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read system info",require_path="file_path"
            ),
        ],
    ))

    # exec(shell) → open(credential file) → read
    # Catches os.system('cat /etc/passwd') where we see the shell exec
    # before the inner command's file access
    patterns.append(SequencePattern(
        pattern_id="AB1-SHELL-CRED-ACCESS",
        behavior_id="AB1",
        sub_behavior="Shell-based credential file access",
        mitre=[
            MITREMapping("Credential Access", "T1003.008", "/etc/passwd and /etc/shadow"),
            MITREMapping("Execution", "T1059.004", "Unix Shell"),
        ],
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(*_SHELL_PATHS),
                description="Execute shell interpreter",
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_CRED_ALL_PATHS),
                flag_match=flag_readonly(),
                description="Open credential file from shell command",capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read credential data",require_path="file_path"
            ),
        ],
    ))

    # exec(shell) → open(system info) → read
    patterns.append(SequencePattern(
        pattern_id="AB1-SHELL-SYSINFO-ACCESS",
        behavior_id="AB1",
        sub_behavior="Shell-based system info access",
        mitre=[
            MITREMapping("Discovery", "T1082", "System Information Discovery"),
            MITREMapping("Execution", "T1059.004", "Unix Shell"),
        ],
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(*_SHELL_PATHS),
                description="Execute shell interpreter",
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_SYSINFO_ALL_PATHS),
                flag_match=flag_readonly(),
                description="Open system info file from shell command",capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read system info",require_path="file_path"
            ),
        ],
    ))

    # Command-based credential access + network exfiltration
    # exec(curl/wget/nc with credential file) or exec(cat) → open → read → connect → send
    patterns.append(SequencePattern(
        pattern_id="AB1-EXEC-CRED-EXFIL",
        behavior_id="AB1",
        sub_behavior="Command-based credential theft + exfiltration",
        mitre=[
            MITREMapping("Credential Access", "T1003.008", "/etc/passwd and /etc/shadow"),
            MITREMapping("Execution", "T1059.004", "Unix Shell"),
            MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
        ],
        #same_tid=True,
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(*(
                    _FILE_READ_COMMANDS + _SHELL_PATHS +
                    ["curl", "wget", "nc", "ncat"]
                )),
                description="Execute command",
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_CRED_ALL_PATHS),
                flag_match=flag_readonly(),
                description="Open credential file", capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read credential data", require_path="file_path"
            ),
            PatternStep(
                sub_op="Network.connect",
                flag_match=flag_inet_remote(),
                description="Connect to remote server",
            ),
            PatternStep(
                sub_op={"Network.send", "File.sendfile", "File.write"},
                path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                description="Exfiltrate stolen credentials",
            ),
        ],
    ))

    # Command-based system info + exfiltration
    patterns.append(SequencePattern(
        pattern_id="AB1-EXEC-SYSINFO-EXFIL",
        behavior_id="AB1",
        sub_behavior="Command-based system info theft + exfiltration",
        mitre=[
            MITREMapping("Discovery", "T1082", "System Information Discovery"),
            MITREMapping("Execution", "T1059.004", "Unix Shell"),
            MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
        ],
        #same_tid=True,
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(*(
                    _FILE_READ_COMMANDS + _SHELL_PATHS +
                    ["curl", "wget", "nc", "ncat"]
                )),
                description="Execute command",
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_SYSINFO_ALL_PATHS),
                flag_match=flag_readonly(),
                description="Open system info file", capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read system info",require_path="file_path"
            ),
            PatternStep(
                sub_op="Network.connect",
                flag_match=flag_inet_remote(),
                description="Connect to remote server",
            ),
            PatternStep(
                sub_op={"Network.send", "File.sendfile", "File.write"},
                path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                description="Exfiltrate system info",
            ),
        ],
    )) 
    
    # ==================================================================
    # LOCAL SENSITIVE FILE ACCESS (no exec, no exfil required)
    #
    # Only files that NO legitimate ML framework ever reads.
    # /etc/passwd, /proc/cpuinfo, /etc/hosts, .bashrc etc. are excluded
    # because frameworks read them routinely.
    #
    # /etc/passwd via os.system('cat /etc/passwd') is caught by
    # AB1-EXEC-CRED-ACCESS above (exec → open → read).
    # /etc/passwd with exfil is caught by AB1-CRED-LOGIN-EXFIL.
    # ==================================================================

    # Shadow files and auth logs — never read by any framework
    _CRED_LOGIN_HIGH_SIGNAL = [
        "/etc/shadow", "/etc/gshadow",
        "/var/backups/shadow", "/etc/security/opasswd",
        "/var/log/auth.log", "/var/log/secure",
        "/var/log/lastlog", "/var/log/btmp", "/var/log/wtmp",
    ]

    patterns.append(SequencePattern(
        pattern_id="AB1-CRED-SHADOW-LOCAL",
        behavior_id="AB1",
        sub_behavior="Shadow/auth log access during model execution",
        mitre=[MITREMapping("Credential Access", "T1003.008",
                            "/etc/passwd and /etc/shadow")],
        steps=[
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_CRED_LOGIN_HIGH_SIGNAL),
                flag_match=flag_readonly(),
                description="Open shadow/auth file", capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read credential data",require_path="file_path"
            ),
        ],
    ))

    # Credential files no framework ever touches
    for pid, sub, paths, mitre in [
        ("AB1-CRED-SSH-LOCAL",
         "SSH key access during model execution",
         _CRED_SSH,
         [MITREMapping("Credential Access", "T1552.004", "Private Keys")]),

        ("AB1-CRED-CLOUD-LOCAL",
         "Cloud credential access during model execution",
         _CRED_CLOUD,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),

        ("AB1-CRED-TOKEN-LOCAL",
         "Auth token access during model execution",
         _CRED_TOKENS,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),

        ("AB1-CRED-BROWSER-LOCAL",
         "Browser credential access during model execution",
         _CRED_BROWSER,
         [MITREMapping("Credential Access", "T1555.003", "Credentials from Web Browsers")]),

        ("AB1-CRED-CRYPTO-LOCAL",
         "Cryptocurrency wallet access during model execution",
         _CRED_CRYPTO,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),

        ("AB1-CRED-KEYRING-LOCAL",
         "Keyring access during model execution",
         _CRED_KEYRING,
         [MITREMapping("Credential Access", "T1555.005", "Password Managers")]),

        ("AB1-CRED-SSL-LOCAL",
         "SSL private key access during model execution",
         _SSL_KEY_PATHS,
         [MITREMapping("Credential Access", "T1552.004", "Private Keys")]),

        ("AB1-CRED-DBCONFIG-LOCAL",
         "Database credential access during model execution",
         _DB_CONFIG_PATHS,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),

        ("AB1-CRED-DISCORD-LOCAL",
         "Discord token access during model execution",
         _CRED_DISCORD,
         [MITREMapping("Credential Access", "T1550.004", "Web Session Cookie")]),

        ("AB1-CRED-CONTAINER-LOCAL",
         "Container credential access during model execution",
         _CONTAINER_PATHS,
         [MITREMapping("Credential Access", "T1552.001", "Credentials In Files")]),
    ]:
        patterns.append(SequencePattern(
            pattern_id=pid,
            behavior_id="AB1",
            sub_behavior=sub,
            mitre=mitre,
            steps=[
                PatternStep(
                    sub_op="File.open",
                    path_match=path_contains(*paths),
                    flag_match=flag_readonly(),
                    description=f"Open credential file ({sub})",capture_path="file_path"
                ),
                PatternStep(
                    sub_op="File.read",
                    description="Read credential data",require_path="file_path"
                ),
            ],
        ))

    # Command history — no framework reads these
    patterns.append(SequencePattern(
        pattern_id="AB1-FILE-HISTORY-LOCAL",
        behavior_id="AB1",
        sub_behavior="Command history access during model execution",
        mitre=[MITREMapping("Credential Access", "T1552.003", "Bash History")],
        steps=[
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_FILE_HISTORY),
                flag_match=flag_readonly(),
                description="Open command history file",capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read command history",require_path="file_path"
            ),
        ],
    ))  
    
     # ------------------------------------------------------------------
    # Network preparation: SSL init + DNS resolver config reading
    # Catches urllib.request.urlopen(), requests.get(), etc.
    # even when the TCP connection fails before completing.
    # No legitimate ML framework reads SSL/DNS config during model loading.
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB1-NET-PREP-SSL-DNS",
        behavior_id="AB1",
        sub_behavior="SSL/DNS initialization (outbound HTTPS attempt)",
        mitre=[MITREMapping("Command and Control", "T1071.001", "Web Protocols"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        steps=[
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_NET_PREP_PATHS),
                flag_match=flag_readonly(),
                description="Open SSL/TLS configuration or certificates",capture_path="ssl_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read SSL/TLS config",require_path="ssl_path"
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_DNS_RESOLVE_PATHS),
                flag_match=flag_readonly(),
                description="Open DNS resolver configuration", capture_path="dns_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read DNS resolver config",require_path="dns_path"
            ),
        ],
    ))

    # Reverse order: DNS first, then SSL (some HTTP clients do DNS before SSL)
    patterns.append(SequencePattern(
        pattern_id="AB1-NET-PREP-DNS-SSL",
        behavior_id="AB1",
        sub_behavior="DNS/SSL initialization (outbound HTTPS attempt, reverse order)",
        mitre=[MITREMapping("Command and Control", "T1071.001", "Web Protocols"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        steps=[
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_DNS_RESOLVE_PATHS),
                flag_match=flag_readonly(),
                description="Open DNS resolver configuration",capture_path="dns_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read DNS resolver config",require_path="dns_path"
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_NET_PREP_PATHS),
                flag_match=flag_readonly(),
                description="Open SSL/TLS configuration or certificates",capture_path="ssl_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read SSL/TLS config",require_path="ssl_path"
            ),
        ],
    ))

    # SSL init only (no DNS — might use cached DNS or /etc/hosts)
    patterns.append(SequencePattern(
        pattern_id="AB1-NET-PREP-SSL-ONLY",
        behavior_id="AB1",
        sub_behavior="SSL/TLS initialization during model loading",
        mitre=[MITREMapping("Command and Control", "T1071.001", "Web Protocols")],
        steps=[
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(
                    "/usr/lib/ssl/openssl.cnf", "/etc/ssl/openssl.cnf",
                    "/usr/lib/ssl/cert.pem", "/etc/ssl/cert.pem",
                    "/etc/pki/tls/",
                ),
                flag_match=flag_readonly(),
                description="Open SSL/TLS config (openssl.cnf or CA certs)",capture_path="ssl_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read SSL config", require_path="ssl_path"
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(
                    "/usr/lib/ssl/cert.pem", "/etc/ssl/cert.pem",
                    "/etc/ssl/certs/", "/usr/share/ca-certificates/",
                    "/etc/ca-certificates/", "/etc/pki/tls/certs/",
                ),
                flag_match=flag_readonly(),
                description="Open CA certificate store",capture_path="ca_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read CA certificates",require_path="ca_path"
            ),
        ],
    ))

    # DNS resolver reading + AF_UNIX socket (nscd/systemd-resolved)
    # This catches the exact pattern from model #25
    patterns.append(SequencePattern(
        pattern_id="AB1-NET-PREP-DNS-NSCD",
        behavior_id="AB1",
        sub_behavior="DNS resolution via nscd/systemd-resolved during model loading",
        mitre=[MITREMapping("Command and Control", "T1071.001", "Web Protocols")],
        steps=[
            PatternStep(
                sub_op="Network.socket",
                flag_match=flag_family("AF_UNIX"),
                description="Create AF_UNIX socket (nscd/resolved connection)",
            ),
            PatternStep(
                sub_op="Network.connect",
                description="Connect to nscd/resolved",
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(*_DNS_RESOLVE_PATHS),
                flag_match=flag_readonly(),
                description="Open DNS resolver config", capture_path="dns_path"
            ),
            PatternStep(
                sub_op="File.read",
                description="Read DNS resolver config",require_path="dns_path"
            ),
        ],
    ))
  
    return patterns


def build_ab2_patterns() -> List[SequencePattern]:
    patterns = []

    # ------------------------------------------------------------------
    # Cron job: open(cron path, writable) → write
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-CRON-WRITE",
        behavior_id="AB2",
        sub_behavior="Cron job installation",
        mitre=[MITREMapping("Persistence", "T1053.003", "Cron")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_CRON),
                        flag_match=flag_writable(), description="Open cron file for writing",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write cron entry",require_path="file_path"),
        ],
    ))

    # Cron via execve
    patterns.append(SequencePattern(
        pattern_id="AB2-CRON-EXEC",
        behavior_id="AB2",
        sub_behavior="Cron installation via crontab command",
        mitre=[MITREMapping("Persistence", "T1053.003", "Cron")],
        steps=[
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains("crontab"),
                        description="Execute crontab"),
        ],
    ))

    # Cron access control manipulation
    patterns.append(SequencePattern(
        pattern_id="AB2-CRON-ACCESS",
        behavior_id="AB2",
        sub_behavior="Cron access control manipulation",
        mitre=[MITREMapping("Persistence", "T1053.003", "Cron")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_CRON_ACCESS),
                        flag_match=flag_writable(), description="Open cron access control file",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify cron access control",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Systemd service: open(.service, writable) → write → [symlink] → [systemctl]
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-SYSTEMD",
        behavior_id="AB2",
        sub_behavior="Systemd service creation",
        mitre=[MITREMapping("Persistence", "T1543.002", "Systemd Service")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_SYSTEMD),
                        flag_match=flag_writable(), description="Create/open systemd service file",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write service definition",require_path="file_path"),
            PatternStep(sub_op="File.symlink", path_match=path_contains("target.wants", "systemd"),
                        description="Create enable symlink", optional=True),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains("systemctl"),
                        description="Run systemctl", optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # Init script: open(init path, writable) → write → [chmod] → [symlink]
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-INIT",
        behavior_id="AB2",
        sub_behavior="Init script modification",
        mitre=[MITREMapping("Persistence", "T1037.004", "RC Scripts")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_INIT),
                        flag_match=flag_writable(), description="Open init script",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write init script content",require_path="file_path"),
            PatternStep(sub_op="File.permission", description="chmod executable", optional=True),
            PatternStep(sub_op="File.symlink", path_match=path_contains("/etc/rc"),
                        description="Create runlevel symlink", optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # Boot config: open(grub/efi, writable) → write
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-BOOT",
        behavior_id="AB2",
        sub_behavior="Boot configuration modification",
        mitre=[MITREMapping("Persistence", "T1542.001", "System Firmware")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_BOOT),
                        flag_match=flag_writable(), description="Open boot config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify boot config",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Shell profile: open(.bashrc etc, writable) → write
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-PROFILE",
        behavior_id="AB2",
        sub_behavior="Shell profile modification",
        mitre=[MITREMapping("Persistence", "T1546.004", "Unix Shell Configuration Modification")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_PROFILE),
                        flag_match=flag_writable(), description="Open shell profile",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Append malicious commands",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # SSH authorized_keys injection
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-SSH-KEYS",
        behavior_id="AB2",
        sub_behavior="SSH authorized_keys injection",
        mitre=[MITREMapping("Persistence", "T1098.004", "SSH Authorized Keys")],
        steps=[
            PatternStep(sub_op="File.mkdir", path_match=path_contains(".ssh"),
                        description="Create .ssh directory", optional=True),
            PatternStep(sub_op="File.open", path_match=path_contains("authorized_keys"),
                        flag_match=flag_writable(), description="Open authorized_keys",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write SSH public key",require_path="file_path"),
            PatternStep(sub_op="File.permission", description="Set permissions", optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # PAM bypass
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-PAM",
        behavior_id="AB2",
        sub_behavior="PAM authentication bypass",
        mitre=[MITREMapping("Persistence", "T1556.003", "Pluggable Authentication Modules")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains("/etc/pam.d/"),
                        flag_match=flag_writable(), description="Open PAM config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify PAM rules",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # User account creation
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-USERADD",
        behavior_id="AB2",
        sub_behavior="Backdoor user account creation",
        mitre=[MITREMapping("Persistence", "T1136.001", "Local Account"),
               MITREMapping("Persistence", "T1098", "Account Manipulation")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains("/etc/passwd", "/etc/shadow"),
                        flag_match=flag_writable(), description="Open /etc/passwd for writing",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Append new user entry",require_path="file_path"),
        ],
    ))

    # useradd via execve
    patterns.append(SequencePattern(
        pattern_id="AB2-USERADD-EXEC",
        behavior_id="AB2",
        sub_behavior="User creation via useradd command",
        mitre=[MITREMapping("Persistence", "T1136.001", "Local Account"),
               MITREMapping("Persistence", "T1098", "Account Manipulation")],
        steps=[
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains("useradd", "adduser"),
                        description="Execute useradd"),
        ],
    ))

    # ------------------------------------------------------------------
    # Sudoers modification
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-SUDOERS",
        behavior_id="AB2",
        sub_behavior="Sudoers modification",
        mitre=[MITREMapping("Persistence", "T1548.003", "Sudo and Sudo Caching")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains("/etc/sudoers"),
                        flag_match=flag_writable(), description="Open sudoers",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write NOPASSWD rule",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Binary replacement
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-BINARY-REPLACE",
        behavior_id="AB2",
        sub_behavior="Binary replacement/trojanization",
        mitre=[MITREMapping("Persistence", "T1574.007", "Path Interception by PATH Environment Variable")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                                                  "/usr/local/bin/", "/usr/local/lib/",
                                                  "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"),
                        flag_match=flag_writable(), description="Open system binary/lib for writing",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write trojanized content",require_path="file_path"),
            PatternStep(sub_op="File.permission", description="Set executable", optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # LD_PRELOAD library injection
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-LDPRELOAD",
        behavior_id="AB2",
        sub_behavior="LD_PRELOAD library injection",
        mitre=[MITREMapping("Persistence", "T1574.006", "Dynamic Linker Hijacking")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains("/etc/ld.so.preload"),
                        flag_match=flag_writable(), description="Open ld.so.preload",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write library path",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # LD_CONF manipulation (ld.so.conf / ld.so.conf.d)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-LDCONF",
        behavior_id="AB2",
        sub_behavior="Dynamic linker config manipulation",
        mitre=[MITREMapping("Persistence", "T1574.006", "Dynamic Linker Hijacking")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_LDCONF),
                        flag_match=flag_writable(), description="Open ld.so.conf",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write malicious library path",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Desktop autostart persistence
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-AUTOSTART",
        behavior_id="AB2",
        sub_behavior="Desktop autostart persistence",
        mitre=[MITREMapping("Persistence", "T1547.001", "Registry Run Keys / Startup Folder")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_AUTOSTART),
                        flag_match=flag_writable(), description="Open autostart .desktop file",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write autostart entry",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Kernel module config persistence
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-KMOD-CONFIG",
        behavior_id="AB2",
        sub_behavior="Kernel module config persistence",
        mitre=[MITREMapping("Persistence", "T1547.006", "Kernel Modules and Extensions")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_KMOD_CONFIG),
                        flag_match=flag_writable(), description="Open kernel module config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write module config",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Core pattern hijack (execution via crash handler)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-CORE-PATTERN",
        behavior_id="AB2",
        sub_behavior="Core pattern hijack for persistence",
        mitre=[MITREMapping("Persistence", "T1546", "Event Triggered Execution")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_CORE_PATTERN_PATHS),
                        flag_match=flag_writable(), description="Open /proc/sys/kernel/core_pattern",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write malicious core handler",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Sysctl persistence
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB2-SYSCTL",
        behavior_id="AB2",
        sub_behavior="Sysctl configuration persistence",
        mitre=[MITREMapping("Persistence", "T1546", "Event Triggered Execution")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_SYSCTL_PATHS),
                        flag_match=flag_writable(), description="Open sysctl config", capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write sysctl persistence entry",require_path="file_path"),
        ],
    ))
    
    patterns.append(SequencePattern(
      pattern_id="AB2-PYTHON-MODULE-SHADOW",
      behavior_id="AB2",
      sub_behavior="Python module shadowing (trojanized module file)",
      mitre=[MITREMapping("Persistence", "T1574.001", "Hijack Execution Flow")],
      steps=[
        PatternStep(sub_op="File.open",
                    path_match=lambda fn: fn and (
                        fn.endswith("tensorflow.py") or
                        fn.endswith("torch.py") or
                        fn.endswith("numpy.py")
                    ),
                    flag_match=flag_writable(),
                    description="Create trojanized Python module file", capture_path="file_path"),
        PatternStep(sub_op="File.write",
                    description="Write malicious module content",require_path="file_path"),
      ],
    ))

    patterns.append(SequencePattern(
      pattern_id="AB2-PYTHON-MODULE-SHADOW-ATTEMPT",
      behavior_id="AB2",
      sub_behavior="Python module shadowing attempt (write may have been blocked)",
      mitre=[MITREMapping("Persistence", "T1574.001", "Hijack Execution Flow")],
      steps=[
        PatternStep(sub_op="File.open",
                    path_match=lambda fn: fn and (
                        fn.endswith("tensorflow.py") or
                        fn.endswith("torch.py") or
                        fn.endswith("numpy.py")
                    ),
                    description="Attempt to create trojanized Python module file"),
      ],
    ))

    return patterns


def build_ab3_patterns() -> List[SequencePattern]:
    patterns = []

    # ------------------------------------------------------------------
    # File deletion
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-DELETE",
        behavior_id="AB3",
        sub_behavior="System/log file deletion",
        mitre=[MITREMapping("Defense Evasion", "T1070.004", "File Deletion"),
               MITREMapping("Impact", "T1485", "Data Destruction")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="File.delete",
                        path_match=lambda fn: (
                            path_contains("/var/log", "/etc/")(fn) or
                            (path_contains("/home")(fn) and
                             not path_contains(".cache/", ".local/share/",
                                               ".cache/huggingface/", ".cache/torch/",
                                               ".cache/pip/")(fn))
                        ),
                        description="Delete system/log file"),
        ],
    ))

    # Mass deletion: enumerate → delete
    patterns.append(SequencePattern(
        pattern_id="AB3-MASS-DELETE",
        behavior_id="AB3",
        sub_behavior="Directory enumeration + mass deletion",
        mitre=[MITREMapping("Impact", "T1485", "Data Destruction")],
        steps=[
            PatternStep(sub_op="File.enumerate", description="Enumerate directory"),
            PatternStep(sub_op="File.delete",
                        path_match=lambda fn: (
                            path_contains("/etc/", "/var/log/", "/usr/")(fn) or
                            (path_contains("/home/")(fn) and
                             not path_contains(".cache/", ".local/share/",
                                               ".cache/huggingface/", ".cache/torch/",
                                               ".cache/pip/")(fn))
                        ),
                        description="Delete system files"),
        ],
    ))

    # ------------------------------------------------------------------
    # File modification
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-MODIFY",
        behavior_id="AB3",
        sub_behavior="System file modification",
        mitre=[MITREMapping("Impact", "T1565.001", "Stored Data Manipulation")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains(
                            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
                            "/etc/sudoers", "/etc/hosts", "/etc/hostname",
                            "/etc/resolv.conf", "/etc/nsswitch.conf",
                            "/etc/ssh/", "/etc/pam.d/", "/etc/security/",
                            "/etc/crontab", "/etc/cron.d/",
                            "/etc/systemd/", "/etc/init.d/",
                            "/etc/ld.so.preload", "/etc/ld.so.conf",
                            "/etc/profile", "/etc/environment",
                            "/etc/fstab", "/etc/motd",
                            "/var/log/",
                        ),
                        flag_match=flag_writable(), description="Open sensitive system file for writing",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write modified content",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Log truncation
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-LOG-TRUNC",
        behavior_id="AB3",
        sub_behavior="Log file truncation",
        mitre=[MITREMapping("Defense Evasion", "T1070.002", "Clear Linux System Logs")],
        steps=[
            PatternStep(sub_op="File.truncate", path_match=path_contains("/var/log"),
                        description="Truncate log file"),
        ],
    ))

    # ------------------------------------------------------------------
    # Permission modification on system files
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-CHMOD",
        behavior_id="AB3",
        sub_behavior="Permission modification on system files",
        mitre=[MITREMapping("Defense Evasion", "T1222.002", "Linux File Permissions Modification")],
        steps=[
            PatternStep(sub_op="File.permission",
                        path_match=path_contains("/etc/", "/usr/bin/", "/usr/sbin/", "/var/"),
                        description="chmod on system file"),
        ],
    ))

    # ------------------------------------------------------------------
    # Ownership change
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-CHOWN",
        behavior_id="AB3",
        sub_behavior="Ownership change on system files",
        mitre=[MITREMapping("Defense Evasion", "T1222.002", "Linux File Permissions Modification")],
        steps=[
            PatternStep(sub_op="File.ownership",
                        path_match=path_contains("/etc/", "/usr/", "/var/"),
                        description="chown on system file"),
        ],
    ))

    # ------------------------------------------------------------------
    # Symlink attack: delete → symlink
    # ------------------------------------------------------------------
    _sensitive_symlink_paths = (
        "/etc/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/",
        "/bin/", "/sbin/", "/lib/", "/lib64/",
        "/var/log/", "/var/spool/cron/",
        ".ssh/", ".bashrc", ".profile", ".bash_profile",
    )
    patterns.append(SequencePattern(
        pattern_id="AB3-SYMLINK",
        behavior_id="AB3",
        sub_behavior="Symlink/hardlink attack on sensitive file",
        mitre=[MITREMapping("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism")],
        steps=[
            PatternStep(sub_op="File.delete",
                        path_match=path_contains(*_sensitive_symlink_paths),
                        description="Remove sensitive file"),
            PatternStep(sub_op={"File.symlink", "File.link"},
                        description="Create replacement symlink or hardlink"),
        ],
    ))

    # ------------------------------------------------------------------
    # Hostname/domain manipulation
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-HOSTNAME",
        behavior_id="AB3",
        sub_behavior="System identity manipulation",
        mitre=[MITREMapping("Defense Evasion", "T1036", "Masquerading")],
        steps=[
            PatternStep(sub_op="System.identity_set", description="Change hostname/domain"),
        ],
    ))

    # Hostname via file write (taxonomy lists /etc/hostname, /etc/hosts, /etc/machine-info)
    patterns.append(SequencePattern(
        pattern_id="AB3-HOSTNAME-FILE",
        behavior_id="AB3",
        sub_behavior="System identity manipulation via file write",
        mitre=[MITREMapping("Defense Evasion", "T1036", "Masquerading")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains("/etc/hostname", "/etc/machine-info"),
                        flag_match=flag_writable(), description="Open hostname/identity file",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write new identity", require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # SELinux/AppArmor disable
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-MAC-DISABLE",
        behavior_id="AB3",
        sub_behavior="MAC policy manipulation",
        mitre=[MITREMapping("Defense Evasion", "T1562.001", "Disable or Modify Tools")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_MAC_PATHS),
                        flag_match=flag_writable(), description="Open MAC policy file",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify MAC policy",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Firewall manipulation (file-based)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-FIREWALL",
        behavior_id="AB3",
        sub_behavior="Firewall rule manipulation",
        mitre=[MITREMapping("Defense Evasion", "T1562.004", "Disable or Modify System Firewall")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_FIREWALL_PATHS),
                        flag_match=flag_writable(), description="Open firewall config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify firewall rules",require_path="file_path"),
        ],
    ))

    # Firewall via Netlink (nftables)
    patterns.append(SequencePattern(
        pattern_id="AB3-FIREWALL-NETLINK",
        behavior_id="AB3",
        sub_behavior="Firewall manipulation via Netlink (nftables)",
        mitre=[MITREMapping("Defense Evasion", "T1562.004", "Disable or Modify System Firewall")],
        steps=[
            PatternStep(sub_op="Network.socket", flag_match=flag_netlink_netfilter(),
                        description="Create AF_NETLINK NETLINK_NETFILTER socket"),
            PatternStep(sub_op="Network.send", description="Send NFT_MSG modification"),
        ],
    ))

    # Firewall via setsockopt (iptables)
    patterns.append(SequencePattern(
        pattern_id="AB3-FIREWALL-SOCKOPT",
        behavior_id="AB3",
        sub_behavior="Firewall manipulation via setsockopt (iptables)",
        mitre=[MITREMapping("Defense Evasion", "T1562.004", "Disable or Modify System Firewall")],
        steps=[
            PatternStep(sub_op="Network.sockopt", flag_match=flag_sockopt_iptables(),
                        description="setsockopt IPT_SO_SET_REPLACE"),
        ],
    ))

    # ------------------------------------------------------------------
    # Logging config tampering
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-LOGGING",
        behavior_id="AB3",
        sub_behavior="Logging configuration tampering",
        mitre=[MITREMapping("Defense Evasion", "T1562.003", "Impair Command History Logging")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_LOGGING_PATHS),
                        flag_match=flag_writable(), description="Open logging config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify logging config",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Network config manipulation (file-based)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-NETCONFIG",
        behavior_id="AB3",
        sub_behavior="Network configuration manipulation",
        mitre=[MITREMapping("Defense Evasion", "T1562.004", "Disable or Modify System Firewall")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_NET_MANIP_PATHS),
                        flag_match=flag_writable(), description="Open network config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify network config",require_path="file_path"),
        ],
    ))

    # Network manipulation via Netlink (route changes)
    patterns.append(SequencePattern(
        pattern_id="AB3-NETCONFIG-NETLINK",
        behavior_id="AB3",
        sub_behavior="Network manipulation via Netlink (route/address changes)",
        mitre=[MITREMapping("Defense Evasion", "T1562.004", "Disable or Modify System Firewall")],
        steps=[
            PatternStep(sub_op="Network.socket", flag_match=flag_netlink_route(),
                        description="Create AF_NETLINK NETLINK_ROUTE socket"),
            PatternStep(sub_op="Network.send",
                        description="Send RTM_NEW*/RTM_SET*/RTM_DEL* modification"),
        ],
    ))

    # Network manipulation via ioctl
    patterns.append(SequencePattern(
        pattern_id="AB3-NETCONFIG-IOCTL",
        behavior_id="AB3",
        sub_behavior="Network manipulation via ioctl",
        mitre=[MITREMapping("Defense Evasion", "T1562.004", "Disable or Modify System Firewall")],
        steps=[
            PatternStep(sub_op="System.ioctl", flag_match=flag_ioctl_netif_set(),
                        description="ioctl SIOCS* network interface modification"),
        ],
    ))

    # DNS manipulation (resolv.conf, hosts, nsswitch)
    patterns.append(SequencePattern(
        pattern_id="AB3-DNS-MANIP",
        behavior_id="AB3",
        sub_behavior="DNS/resolver configuration manipulation",
        mitre=[MITREMapping("Defense Evasion", "T1562.004", "Disable or Modify System Firewall")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"),
                        flag_match=flag_writable(), description="Open DNS/resolver config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify DNS config",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Security setting weakening
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-SECURITY",
        behavior_id="AB3",
        sub_behavior="Security setting weakening",
        mitre=[MITREMapping("Defense Evasion", "T1562.001", "Disable or Modify Tools")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_SECURITY_SETTING_PATHS),
                        flag_match=flag_writable(), description="Open security setting",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Weaken security setting",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Policy manipulation (sudoers/PAM/security under AB3)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-POLICY",
        behavior_id="AB3",
        sub_behavior="Authentication/authorization policy manipulation",
        mitre=[MITREMapping("Defense Evasion", "T1556", "Modify Authentication Process"),
               MITREMapping("Persistence", "T1098", "Account Manipulation")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_POLICY_PATHS),
                        flag_match=flag_writable(), description="Open policy file", capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify policy", require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Hosts access control (hosts.allow / hosts.deny)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-HOSTS-ACCESS",
        behavior_id="AB3",
        sub_behavior="Hosts access control manipulation",
        mitre=[MITREMapping("Defense Evasion", "T1562.001", "Disable or Modify Tools")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_HOSTS_ACCESS_PATHS),
                        flag_match=flag_writable(), description="Open hosts access control", capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify hosts access rules",require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Fstab manipulation
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-FSTAB",
        behavior_id="AB3",
        sub_behavior="Filesystem mount table manipulation",
        mitre=[MITREMapping("Impact", "T1565.001", "Stored Data Manipulation")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_FSTAB_PATHS),
                        flag_match=flag_writable(), description="Open /etc/fstab", capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify fstab", require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Boot modification under AB3 (different intent from AB2 persistence)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-BOOT",
        behavior_id="AB3",
        sub_behavior="Boot configuration tampering",
        mitre=[MITREMapping("Impact", "T1565.001", "Stored Data Manipulation")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains(*_PERSIST_BOOT),
                        flag_match=flag_writable(), description="Open boot config",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Tamper with boot config", require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Capability modification
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-CAPS",
        behavior_id="AB3",
        sub_behavior="Capability modifications",
        mitre=[MITREMapping("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism")],
        steps=[
            PatternStep(sub_op={"File.xattr_set", "File.xattr_remove"},
                        path_match=path_contains("security.capability"),
                        description="Modify file capabilities"),
        ],
    ))
    
    # ------------------------------------------------------------------
    # ACL tampering
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-ACL",
        behavior_id="AB3",
        sub_behavior="ACL tampering",
        mitre=[MITREMapping("Defense Evasion", "T1222.002", "Linux File Permissions Modification")],
        steps=[
            PatternStep(sub_op={"File.xattr_set", "File.xattr_remove"},
                        path_match=path_contains("system.posix_acl"),
                        description="Modify ACL via xattr"),
        ],
    ))
    # ------------------------------------------------------------------
    # Process name manipulation (masquerading)
    # ------------------------------------------------------------------
    # Masquerading: only flag PR_SET_NAME after a network connection
    # to a remote server (hiding a C2 process), not after any exec
    # (which fires on every browser/subprocess thread naming)
    patterns.append(SequencePattern(
        pattern_id="AB3-MASQUERADE",
        behavior_id="AB3",
        sub_behavior="Process name manipulation after network connection",
        mitre=[MITREMapping("Defense Evasion", "T1036", "Masquerading")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="Network.connect",
                        flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op="Process.control",
                        path_match=path_contains("PR_SET_NAME"),
                        description="Rename process via prctl(PR_SET_NAME)"),
        ],
    ))
    # ------------------------------------------------------------------
    # Audit/security monitoring disabling (T1562.006)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB3-AUDIT-DISABLE",
        behavior_id="AB3",
        sub_behavior="Audit/security monitoring disabling",
        mitre=[MITREMapping("Defense Evasion", "T1562.006", "Indicator Blocking")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains(*_AUDIT_PATHS),
                        flag_match=flag_writable(),
                        description="Open audit configuration",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Modify audit configuration",require_path="file_path"),
        ],
    ))
    patterns.append(SequencePattern(
        pattern_id="AB3-TRUNC",
        behavior_id="AB3",
        sub_behavior="System file truncation",
        mitre=[MITREMapping("Impact", "T1565.001", "Stored Data Manipulation")],
        steps=[
            PatternStep(sub_op="File.truncate",
                        path_match=path_contains("/etc/", "/var/log", "/usr/"),
                        description="Truncate system file"),
        ],
    ))
    
    patterns.append(SequencePattern(
        pattern_id="AB3-RENAME",
        behavior_id="AB3",
        sub_behavior="System file rename",
        mitre=[MITREMapping("Defense Evasion", "T1036", "Masquerading"),
               MITREMapping("Impact", "T1565.001", "Stored Data Manipulation")],
        steps=[
            PatternStep(sub_op="File.rename",
                        path_match=path_contains("/etc/", "/var/log/", "/usr/bin/", "/usr/sbin/"),
                        description="Rename system file"),
        ],
    ))
    patterns.append(SequencePattern(
        pattern_id="AB3-EFI-XATTR",
        behavior_id="AB3",
        sub_behavior="EFI variable tampering via xattr removal",
        mitre=[MITREMapping("Impact", "T1565.001", "Stored Data Manipulation")],
        steps=[
            PatternStep(sub_op="File.xattr_remove",
                        path_match=path_contains("/sys/firmware/efi/efivars/"),
                        description="Remove EFI variable via removexattr"),
        ],
    ))
    
    patterns.append(SequencePattern(
      pattern_id="AB3-TMP-SCRIPT-STAGE",
      behavior_id="AB3",
      sub_behavior="Temporary shell script staging for potential execution",
      mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell")],
      steps=[
        PatternStep(sub_op="File.open",
                    path_match=path_regex(
                        r"(/tmp/|/var/tmp/|/dev/shm/).*\.(sh|py|pl|rb|bash|csh|ksh|zsh)"
                    ),
                    description="Create script file in temp directory", capture_path="file_path"),
        PatternStep(sub_op="File.write",
                    path_match=path_regex(
                        r"(/tmp/|/var/tmp/|/dev/shm/).*\.(sh|py|pl|rb|bash|csh|ksh|zsh)"
                    ),
                    description="Write script content",  require_path="file_path"),
      ],
    ))
    patterns.append(SequencePattern(
      pattern_id="AB3-TMP-SCRIPT-STAGE-ATTEMPT",
      behavior_id="AB3",
      sub_behavior="Temporary shell script staging for potential execution (write may have been blocked)",
      mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell")],
      steps=[
        PatternStep(sub_op="File.open",
                    path_match=path_regex(
                        r"(/tmp/|/var/tmp/|/dev/shm/).*\.(sh|py|pl|rb|bash|csh|ksh|zsh)"
                    ),
                    description="Attempt to stage script in temp directory"),
      ],
    ))
    return patterns


def build_ab4_patterns() -> List[SequencePattern]:
    patterns = []

    # ------------------------------------------------------------------
    # Shell execution
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-SHELL",
        behavior_id="AB4",
        sub_behavior="Shell interpreter spawning",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Execute shell"),
        ],
    ))

    # ------------------------------------------------------------------
    # Python interpreter execution (T1059.006)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-PYTHON",
        behavior_id="AB4",
        sub_behavior="Python interpreter execution",
        mitre=[MITREMapping("Execution", "T1059.006", "Python")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains("python", "python3", "python2"),
                        description="Execute Python interpreter"),
        ],
    ))

    # ------------------------------------------------------------------
    # High-signal system binary execution (recon, network, and destructive tools)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-SYSBIN-RECON",
        behavior_id="AB4",
        sub_behavior="Reconnaissance/network binary execution",
        mitre=[MITREMapping("Execution", "T1106", "Native API")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains(
                            "/usr/bin/nc", "/usr/bin/ncat",
                            "/usr/bin/ss", "/usr/bin/netstat",
                            "/usr/bin/curl", "/usr/bin/wget",
                            "/usr/bin/find",
                            "/usr/bin/id", "/usr/bin/whoami",
                            "/bin/nc",
                            "/bin/id", "/bin/whoami"),
                        description="Execute recon/network binary"),
        ],
    ))

     
    # ------------------------------------------------------------------
    # Script injection: open(tmp, writable) → write → [chmod] → execve
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-SCRIPT",
        behavior_id="AB4",
        sub_behavior="Malicious script injection",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains("/tmp/", ".sh"),
                        flag_match=flag_writable(), description="Create script file", capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write script content", require_path="file_path"),
            PatternStep(sub_op="File.permission", description="chmod executable", optional=True),
            PatternStep(sub_op="CodeExec.exec", description="Execute script"),
        ],
    ))

    # ------------------------------------------------------------------
    # Download + execute (direct)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-DOWNLOAD-EXEC",
        behavior_id="AB4",
        sub_behavior="Download and execute payload",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1105", "Ingress Tool Transfer")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains("curl", "wget"),
                        description="Download payload"),
        ],
    ))

    # ------------------------------------------------------------------
    # Download → write to disk → execute (staged)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-DOWNLOAD-STAGE-EXEC",
        behavior_id="AB4",
        sub_behavior="Download, stage to disk, and execute payload",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1105", "Ingress Tool Transfer")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to download server"),
            PatternStep(sub_op="Network.recv", description="Receive payload data"),
            PatternStep(sub_op="File.open", flag_match=flag_writable(),
                        description="Create payload file", capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write payload to disk", require_path="file_path"),
            PatternStep(sub_op="File.permission", description="chmod executable", optional=True),
            PatternStep(sub_op="CodeExec.exec", description="Execute staged payload"),
        ],
    ))

    

    
    # ------------------------------------------------------------------
    # Fileless: memfd_create → write → execve
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-FILELESS",
        behavior_id="AB4",
        sub_behavior="Fileless execution via memfd_create",
        mitre=[MITREMapping("Defense Evasion", "T1620", "Reflective Code Loading")],
        steps=[
            PatternStep(sub_op="Memory.anon_fd", description="Create anonymous fd"),
            PatternStep(sub_op="File.write", description="Write ELF to memfd"),
            PatternStep(sub_op="CodeExec.exec", description="Execute from memfd"),
        ],
    ))

    # ------------------------------------------------------------------
    # Ptrace injection
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-PTRACE",
        behavior_id="AB4",
        sub_behavior="Process injection via ptrace",
        mitre=[MITREMapping("Defense Evasion", "T1055.008", "Ptrace System Calls")],
        steps=[
            PatternStep(sub_op="Process.ptrace",
                        path_match=path_contains("PTRACE_ATTACH", "PTRACE_SEIZE"),
                        description="Attach to target"),
            PatternStep(sub_op="Process.ptrace",
                        path_match=path_contains("PTRACE_POKETEXT", "PTRACE_POKEDATA"),
                        description="Inject code"),
            PatternStep(sub_op="Process.ptrace",
                        path_match=path_contains("PTRACE_CONT", "PTRACE_DETACH"),
                        description="Resume target"),
        ],
    ))
    # ------------------------------------------------------------------
    # Suspicious command execution targeting sensitive paths
    # Catches os.system() running ANY command that then touches sensitive files
    # This is broader than AB1's file-reading-tool patterns
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-EXEC-SENSITIVE-WRITE",
        behavior_id="AB4",
        sub_behavior="Command execution with sensitive file modification",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Impact", "T1565.001", "Stored Data Manipulation")],
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(*_SHELL_PATHS),
                description="Execute shell",
            ),
            PatternStep(
                sub_op="File.open",
                path_match=path_contains(
                    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                    "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/",
                    "/etc/ssh/", ".ssh/authorized_keys",
                    "/etc/systemd/system/", "/etc/init.d/",
                    "/etc/ld.so.preload",
                ),
                flag_match=flag_writable(),
                description="Open sensitive system file for writing",capture_path="file_path"
            ),
            PatternStep(
                sub_op="File.write",
                description="Write to sensitive file",  require_path="file_path"
            ),
        ],
    ))
    
    # ------------------------------------------------------------------
    # Unexpected external program execution during ML inference
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-UNEXPECTED-EXEC",
        behavior_id="AB4",
        sub_behavior="Unexpected external program execution during model inference",
        mitre=[MITREMapping("Execution", "T1204", "User Execution"),
               MITREMapping("Execution", "T1059.004", "Unix Shell")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains(
                            "firefox", "chromium", "chrome", "brave",
                            "microsoft-edge", "opera", "vivaldi",
                            "iceweasel", "iceape", "seamonkey",
                            "mozilla-firefox", "mozilla-firebird",
                            "konqueror", "netscape",
                            "xdg-open", "sensible-browser", "x-www-browser",
                            "gnome-open", "kde-open",
                            "/usr/bin/ssh", "/bin/ssh",
                            "/usr/bin/scp", "/bin/scp",
                            "/usr/bin/nc", "/usr/bin/ncat",
                            "/usr/bin/curl", "/usr/bin/wget",
                            "/usr/bin/gcc", "/usr/bin/cc", "/usr/bin/make",
                            "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/node",
                            "/usr/bin/pip", "/usr/bin/pip3",
                        ),
                        description="Execute program unexpected during ML inference"),
        ],
    ))

    # ------------------------------------------------------------------
    # Subprocess spawning (pipe → fork → dup2 → exec)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-SUBPROCESS",
        behavior_id="AB4",
        sub_behavior="Suspicious subprocess spawning via pipe+fork+redirect",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Execution", "T1106", "Native API")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="File.pipe", description="Create pipe for IPC"),
            PatternStep(sub_op="Process.fork", description="Fork child process"),
            PatternStep(sub_op="File.dup", description="Redirect child stdio"),
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains(
                            # Browsers and URL openers
                            "firefox", "chrome", "chromium", "brave",
                            "opera", "vivaldi", "xdg-open",
                            "sensible-browser", "x-www-browser",
                            "gnome-open", "kde-open",
                            # Network tools
                            "/usr/bin/nc", "/usr/bin/ncat",
                            "/usr/bin/curl", "/usr/bin/wget",
                            "/usr/bin/ssh", "/usr/bin/scp",
                            # Discovery tools
                            "/usr/bin/find",
                            # Shells (when spawned as subprocess, not Python itself)
                            *_SHELL_PATHS,
                            # Compilers / package managers
                            "/usr/bin/gcc", "/usr/bin/cc", "/usr/bin/make",
                            "/usr/bin/pip", "/usr/bin/pip3",
                            "/usr/bin/npm", "/usr/bin/gem",
                            # Credential access tools
                            "cat /etc/shadow", "base64",
                        ),
                        description="Execute suspicious command in child"),
        ],
    ))

    # ------------------------------------------------------------------
    # Browser discovery scan (webbrowser.open fingerprint)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB4-BROWSER-DISCOVERY",
        behavior_id="AB4",
        sub_behavior="Browser discovery scan (webbrowser.open fingerprint)",
        mitre=[MITREMapping("Execution", "T1204", "User Execution"),
               MITREMapping("Discovery", "T1083", "File and Directory Discovery")],
        steps=[
            PatternStep(sub_op="File.stat",
                        path_match=path_contains(
                            "firefox", "chrome", "chromium",
                            "x-www-browser", "xdg-open",
                            "iceweasel", "iceape", "seamonkey",
                            "mozilla", "konqueror", "netscape",
                            "opera", "brave", "vivaldi",
                            "sensible-browser", "gnome-open"),
                        description="Stat browser binary in PATH"),
            PatternStep(sub_op={"File.stat", "File.access"},
                        path_match=path_contains(
                            "firefox", "chrome", "chromium",
                            "x-www-browser", "xdg-open",
                            "iceweasel", "iceape", "seamonkey",
                            "mozilla", "konqueror", "netscape",
                            "opera", "brave", "vivaldi",
                            "sensible-browser", "gnome-open"),
                        description="Verify browser accessibility"),
        ],
    ))
    return patterns


def build_ab5_patterns() -> List[SequencePattern]:
    patterns = []

    # ------------------------------------------------------------------
    # Full mining: profile → socket → connect(pool) → send → recv
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-FULL",
        behavior_id="AB5",
        sub_behavior="Cryptojacking: profile → connect pool → mine",
        mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking")],
        #same_tid=True,
        steps=[
            PatternStep(sub_op="System.info", description="Resource profiling"),
            PatternStep(sub_op="Network.socket", description="Create socket", optional=True),
            PatternStep(sub_op="Network.connect", flag_match=flag_mining_port(),
                        description="Connect to mining pool"),
            PatternStep(sub_op="Network.send", description="Submit hash", capture_fd="pool_fd"),
            PatternStep(sub_op="Network.recv", description="Receive work", require_fd="pool_fd", optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # Known miner execution
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-MINER-EXEC",
        behavior_id="AB5",
        sub_behavior="Known miner binary execution",
        mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking"),
               MITREMapping("Execution", "T1059.004", "Unix Shell")],
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains("xmrig", "minerd", "cpuminer",
                                                  "ccminer", "ethminer"),
                        description="Execute miner"),
        ],
    ))

    # ------------------------------------------------------------------
    # Miner deployment via file write + execute
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-MINER-DEPLOY",
        behavior_id="AB5",
        sub_behavior="Miner deployment (write + execute)",
        mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking"),
               MITREMapping("Command and Control", "T1105", "Ingress Tool Transfer")],
        steps=[
            PatternStep(sub_op="File.open", flag_match=flag_writable(),
                        description="Create miner binary file", capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write miner binary", require_path="file_path"),
            PatternStep(sub_op="File.permission", description="chmod executable", optional=True),
            PatternStep(sub_op="CodeExec.exec", description="Execute deployed miner"),
        ],
    ))

    # ------------------------------------------------------------------
    # Fileless miner deployment (memfd_create → write → fexecve)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-MINER-FILELESS",
        behavior_id="AB5",
        sub_behavior="Fileless miner deployment",
        mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking"),
               MITREMapping("Defense Evasion", "T1620", "Reflective Code Loading")],
        steps=[
            PatternStep(sub_op="Memory.anon_fd", description="Create anonymous fd (memfd_create)"),
            PatternStep(sub_op="File.write", description="Write miner to memfd"),
            PatternStep(sub_op="CodeExec.exec", description="Execute miner from memfd"),
        ],
    ))

    # ------------------------------------------------------------------
    # Miner download via curl/wget + execute
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-MINER-DOWNLOAD",
        behavior_id="AB5",
        sub_behavior="Miner download and execution",
        mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking"),
               MITREMapping("Command and Control", "T1105", "Ingress Tool Transfer")],
        steps=[
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains("curl", "wget"),
                        description="Download miner"),
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains("xmrig", "minerd", "cpuminer",
                                                  "ccminer", "ethminer"),
                        description="Execute downloaded miner", optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # Mining pool port connection
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-POOL-PORT",
        behavior_id="AB5",
        sub_behavior="Connection to mining pool port",
        mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_mining_port(),
                        description="Connect to mining pool port"),
        ],
    ))
    '''
    # ------------------------------------------------------------------
    # Process masquerading as kernel thread
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-MASQUERADE",
        behavior_id="AB5",
        sub_behavior="Process masquerading (hiding miner)",
        mitre=[MITREMapping("Defense Evasion", "T1036", "Masquerading")],
        steps=[
            PatternStep(sub_op="Process.control", path_match=path_contains("PR_SET_NAME"),
                        description="Rename process"),
        ],
    ))
    '''
    # ------------------------------------------------------------------
    # Persistent mining via scheduled task
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB5-PERSISTENT",
        behavior_id="AB5",
        sub_behavior="Persistent mining via scheduled task",
        mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking"),
               MITREMapping("Persistence", "T1053", "Scheduled Task/Job")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains("/etc/crontab", "/etc/cron.d/",
                                                  "/var/spool/cron/", "/etc/systemd/system/"),
                        flag_match=flag_writable(), description="Open scheduling config",  capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write mining task schedule", require_path="file_path"),
        ],
    ))
    
  
    return patterns


def build_ab6_patterns() -> List[SequencePattern]:
    patterns = []

    # ------------------------------------------------------------------
    # Reverse shell: socket → connect → dup2(0) → dup2(1) → dup2(2) → execve(shell)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-REVSHELL",
        behavior_id="AB6",
        sub_behavior="Reverse shell",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.socket", description="Create TCP socket"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to attacker"),
            PatternStep(sub_op="File.dup", path_match=path_contains("->0"),
                        description="Redirect stdin"),
            PatternStep(sub_op="File.dup", path_match=path_contains("->1"),
                        description="Redirect stdout"),
            PatternStep(sub_op="File.dup", path_match=path_contains("->2"),
                        description="Redirect stderr"),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Spawn shell"),
        ],
    ))

    # Reverse shell relaxed (with fd redirect info): connect → 2 dup2s → exec
    patterns.append(SequencePattern(
        pattern_id="AB6-REVSHELL-RELAXED",
        behavior_id="AB6",
        sub_behavior="Reverse shell (relaxed)",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to attacker"),
            PatternStep(sub_op="File.dup", path_match=path_regex(r"->[012]"),
                        description="Redirect first stdio"),
            PatternStep(sub_op="File.dup", path_match=path_regex(r"->[012]"),
                        description="Redirect second stdio"),
            PatternStep(sub_op="CodeExec.exec", description="Spawn process"),
        ],
    ))

    # Reverse shell minimal (no fd format dependency): connect → any dup2s → exec
    patterns.append(SequencePattern(
        pattern_id="AB6-REVSHELL-MINIMAL",
        behavior_id="AB6",
        sub_behavior="Reverse shell (minimal — no fd format dependency)",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to attacker"),
            PatternStep(sub_op="File.dup", description="Redirect stdio (first)"),
            PatternStep(sub_op="File.dup", description="Redirect stdio (second)"),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Spawn shell"),
        ],
    ))

    # ------------------------------------------------------------------
    # Reverse shell with setsid (daemonized)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-REVSHELL-DAEMON",
        behavior_id="AB6",
        sub_behavior="Daemonized reverse shell",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to attacker"),
            PatternStep(sub_op="Process.session", description="setsid to daemonize"),
            PatternStep(sub_op="File.dup", path_match=path_regex(r"->[012]"),
                        description="Redirect stdio"),
            PatternStep(sub_op="CodeExec.exec", description="Spawn shell"),
        ],
    ))

    # Daemonized reverse shell minimal (no fd format dependency)
    patterns.append(SequencePattern(
        pattern_id="AB6-REVSHELL-DAEMON-MINIMAL",
        behavior_id="AB6",
        sub_behavior="Daemonized reverse shell (minimal — no fd format dependency)",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to attacker"),
            PatternStep(sub_op="Process.session", description="setsid to daemonize"),
            PatternStep(sub_op="File.dup", description="Redirect stdio"),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Spawn shell"),
        ],
    ))
    # ------------------------------------------------------------------
    # Bind shell
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-BINDSHELL",
        behavior_id="AB6",
        sub_behavior="Bind shell",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.socket", description="Create socket"),
            PatternStep(sub_op="Network.bind", description="Bind to port"),
            PatternStep(sub_op="Network.listen", description="Listen"),
            PatternStep(sub_op="Network.accept", description="Accept connection"),
            PatternStep(sub_op="File.dup", path_match=path_regex(r"->[012]"),
                        description="Redirect stdio"),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Spawn shell"),
        ],
    ))

    # Bind shell minimal (no fd format dependency)
    patterns.append(SequencePattern(
        pattern_id="AB6-BINDSHELL-MINIMAL",
        behavior_id="AB6",
        sub_behavior="Bind shell (minimal — no fd format dependency)",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.socket", description="Create socket"),
            PatternStep(sub_op="Network.bind", description="Bind to port"),
            PatternStep(sub_op="Network.listen", description="Listen"),
            PatternStep(sub_op="Network.accept", description="Accept connection"),
            PatternStep(sub_op="File.dup", description="Redirect stdio"),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Spawn shell"),
        ],
    ))
    # ------------------------------------------------------------------
    # Pipe-based shell
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-PIPESHELL",
        behavior_id="AB6",
        sub_behavior="Pipe-based shell",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell")],
        steps=[
            PatternStep(sub_op="File.pipe", description="Create pipe"),
            PatternStep(sub_op="Process.fork", description="Fork child"),
            PatternStep(sub_op="File.dup", path_match=path_regex(r"->[012]"),
                        description="Redirect stdio"),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Spawn shell"),
        ],
    ))

    # Pipe-based shell minimal (no fd format dependency)
    patterns.append(SequencePattern(
        pattern_id="AB6-PIPESHELL-MINIMAL",
        behavior_id="AB6",
        sub_behavior="Pipe-based shell (minimal — no fd format dependency)",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell")],
        steps=[
            PatternStep(sub_op="File.pipe", description="Create pipe"),
            PatternStep(sub_op="Process.fork", description="Fork child"),
            PatternStep(sub_op="File.dup", description="Redirect stdio"),
            PatternStep(sub_op="CodeExec.exec", path_match=path_contains(*_SHELL_PATHS),
                        description="Spawn shell"),
        ],
    ))

    # ------------------------------------------------------------------
    # Remote command: connect → recv → exec → [send]
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-REMOTE-CMD",
        behavior_id="AB6",
        sub_behavior="Remote command execution",
        mitre=[MITREMapping("Execution", "T1059.004", "Unix Shell"),
               MITREMapping("Command and Control", "T1071.001", "Web Protocols")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to C2"),
            PatternStep(sub_op="Network.recv", description="Receive command", capture_fd="c2_fd"),
            PatternStep(sub_op="CodeExec.exec", description="Execute command"),
            PatternStep(sub_op="Network.send", description="Send results", require_fd="c2_fd", optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # Shell process masquerading (hiding shell)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-SHELL-MASQUERADE",
        behavior_id="AB6",
        sub_behavior="Shell process masquerading",
        mitre=[MITREMapping("Defense Evasion", "T1036", "Masquerading"),
               MITREMapping("Command and Control", "T1095", "Non-Application Layer Protocol")],
        steps=[
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to remote server"),
            PatternStep(sub_op="Process.control", path_match=path_contains("PR_SET_NAME"),
                        description="Rename shell process"),
            PatternStep(sub_op="CodeExec.exec", description="Execute shell"),
        ],
    ))
    # ------------------------------------------------------------------
    # Lateral movement via remote services (T1021)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-LATERAL-SSH",
        behavior_id="AB6",
        sub_behavior="Lateral movement via SSH",
        mitre=[MITREMapping("Lateral Movement", "T1021.004", "SSH"),
               MITREMapping("Lateral Movement", "T1021", "Remote Services")],
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains("/usr/bin/ssh", "/bin/ssh",
                                                  "/usr/bin/scp", "/bin/scp",
                                                  "/usr/bin/sftp", "/bin/sftp"),
                        description="Execute SSH/SCP/SFTP client"),
        ],
    ))

    patterns.append(SequencePattern(
        pattern_id="AB6-LATERAL-CONNECT",
        behavior_id="AB6",
        sub_behavior="Connection to remote service port",
        mitre=[MITREMapping("Lateral Movement", "T1021", "Remote Services")],
        steps=[
            PatternStep(sub_op="Network.connect",
                        flag_match=_flag_remote_service_port(),
                        description="Connect to remote service port (SSH/RDP/SMB/VNC)"),
        ],
    ))
    # ------------------------------------------------------------------
    # Proxy / port forwarding (T1090)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-PROXY",
        behavior_id="AB6",
        sub_behavior="Proxy / port forwarding",
        mitre=[MITREMapping("Command and Control", "T1090", "Proxy")],
        steps=[
            PatternStep(sub_op="Network.socket", description="Create listening socket"),
            PatternStep(sub_op="Network.bind", description="Bind to local port"),
            PatternStep(sub_op="Network.listen", description="Listen for connections"),
            PatternStep(sub_op="Network.accept", description="Accept inbound connection"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to forwarding target"),
        ],
    ))
    
    # ------------------------------------------------------------------
    # Remote system discovery / network scanning (T1018)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-SCAN",
        behavior_id="AB6",
        sub_behavior="Remote system discovery / network scanning",
        mitre=[MITREMapping("Discovery", "T1018", "Remote System Discovery")],
        repeatable=True,
        steps=[
            PatternStep(sub_op="Network.socket", description="Create socket"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Probe remote host"),
        ],
    ))
    #------------------------------------------------------------------
    # Browser-based C2 / phishing URL open
    # Catches webbrowser.open() from malicious pickle payloads
    # exec(shell/xdg-open/browser) → socket → connect(remote)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB6-BROWSER-C2",
        behavior_id="AB6",
        sub_behavior="Browser-based URL open (potential C2/phishing)",
        mitre=[
            MITREMapping("Execution", "T1204.001", "Malicious Link"),
            MITREMapping("Command and Control", "T1071.001", "Web Protocols"),
        ],
        steps=[
            PatternStep(
                sub_op="CodeExec.exec",
                path_match=path_contains(
                    "xdg-open", "sensible-browser", "x-www-browser",
                    "gnome-open", "kde-open", "open",
                    "firefox", "chrome", "chromium", "brave",
                ),
                description="Execute browser/URL opener",
            ),
            PatternStep(
                sub_op="Network.socket",
                flag_match=flag_family("AF_INET", "AF_INET6"),
                description="Create network socket",
                optional=True,
            ),
            PatternStep(
                sub_op="Network.connect",
                flag_match=flag_inet_remote(),
                description="Connect to external URL",
            ),
        ],
    ))
    return patterns


def build_ab7_patterns() -> List[SequencePattern]:
    patterns = []

     # Paths that are normal Python/framework imports — NOT ransomware targets
    _BENIGN_LIB_PATHS = (
        "site-packages/", "/usr/lib/python", "/usr/local/lib/python",
        "/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/",
        "__pycache__/", ".pyc", "/etc/ld.so",
        "/proc/", "/sys/", "/dev/",
    )

    def _not_library_path(fn: str) -> bool:
        """Return True only if the path is NOT a standard library/framework path."""
        if not fn:
            return False
        return not any(excl in fn for excl in _BENIGN_LIB_PATHS)

    def _is_file_not_stdio(fn: str) -> bool:
        """Return True only if the write target is a real file, not stdout/stderr."""
        if not fn:
            return False
        if fn in ("stdout", "stderr", "stdin"):
            return False
        if fn.startswith("fd="):
            return False
        if "/dev/shm" in fn or "/tmp/" in fn:
            return False
        if any(excl in fn for excl in _BENIGN_LIB_PATHS):
            return False
        return True

    patterns.append(SequencePattern(
        pattern_id="AB7-INPLACE",
        behavior_id="AB7",
        sub_behavior="Ransomware (in-place overwrite)",
        mitre=[MITREMapping("Impact", "T1486", "Data Encrypted for Impact"),
               MITREMapping("Impact", "T1490", "Inhibit System Recovery"),
               MITREMapping("Discovery", "T1083", "File and Directory Discovery")],
        steps=[
            PatternStep(sub_op={"System.random", "File.open"},
                        path_match=lambda fn: _match_keygen(fn),
                        description="Generate encryption key (>= 16 bytes)"),
            PatternStep(sub_op="File.enumerate",
                        path_match=lambda fn: path_contains("/home", "/mnt", "/var", "/opt")(fn)
                                              and _not_library_path(fn or ""),
                        description="Enumerate user data directories"),
            PatternStep(sub_op="File.open",
                        path_match=lambda fn: _not_library_path(fn or ""),
                        description="Open target file (not a library)", capture_path="target_path"),
            PatternStep(sub_op="File.read",
                        description="Read plaintext", require_path="target_path"),
            PatternStep(sub_op="File.write",
                        path_match=lambda fn: _is_file_not_stdio(fn or ""),
                        description="Write encrypted data to file"),
            PatternStep(sub_op="File.rename", description="Rename with .locked extension",
                        optional=True),
        ],
    ))

    # ------------------------------------------------------------------
    # Ransomware copy-delete
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB7-COPY-DELETE",
        behavior_id="AB7",
        sub_behavior="Ransomware (copy-delete)",
        mitre=[MITREMapping("Impact", "T1486", "Data Encrypted for Impact"),
               MITREMapping("Discovery", "T1083", "File and Directory Discovery")],
        steps=[
            PatternStep(sub_op="File.enumerate", description="Enumerate files"),
            PatternStep(sub_op="File.open", flag_match=flag_readonly(),
                        description="Open original (read)", capture_path="src_path"),
            PatternStep(sub_op="File.read", description="Read plaintext", require_path="src_path"),
            PatternStep(sub_op="File.open",
                        path_match=path_contains(".enc", ".locked", ".encrypted", ".cry"),
                        flag_match=flag_writable(), description="Create encrypted output",  capture_path="dst_path"),
            PatternStep(sub_op="File.write", description="Write encrypted content", require_path="dst_path"),
            PatternStep(sub_op="File.delete", description="Delete original"),
        ],
    ))

    # ------------------------------------------------------------------
    # Key exfiltration to C2
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB7-KEY-EXFIL",
        behavior_id="AB7",
        sub_behavior="Encryption key exfiltration to C2",
        mitre=[MITREMapping("Impact", "T1486", "Data Encrypted for Impact"),
               MITREMapping("Exfiltration", "T1041", "Exfiltration Over C2 Channel")],
        #same_tid=True, 
        steps=[
            PatternStep(sub_op={"System.random", "File.open"},
                        path_match=lambda fn: _match_keygen(fn),
                        description="Generate encryption key"),
            PatternStep(sub_op="Network.connect", flag_match=flag_inet_remote(),
                        description="Connect to C2 server"),
            PatternStep(sub_op={"Network.send", "File.sendfile", "File.write"}, path_match=lambda fn: not fn or fn.startswith("fd=") or fn in ("stdout", "stderr"),
                        description="Exfiltrate encryption key"),
        ],
    ))

    # ------------------------------------------------------------------
    # Ransom note creation
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB7-RANSOM-NOTE",
        behavior_id="AB7",
        sub_behavior="Ransom note creation",
        mitre=[MITREMapping("Impact", "T1491.001", "Internal Defacement")],
        steps=[
            PatternStep(sub_op="File.open",
                        path_match=path_contains("readme", "ransom", "decrypt", "locked",
                                                  "recover", "restore", "payment",
                                                  "bitcoin", ".onion", "/etc/motd"),
                        flag_match=flag_writable(), description="Create ransom note",  capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write ransom demands", require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # Recovery prevention: delete backups
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB7-ANTI-RECOVERY",
        behavior_id="AB7",
        sub_behavior="Recovery prevention (backup deletion)",
        mitre=[MITREMapping("Impact", "T1490", "Inhibit System Recovery")],
        steps=[
            PatternStep(sub_op="File.delete",
                        path_match=path_contains("/var/backups/", ".backup", "shadow.backup"),
                        description="Delete backup files"),
        ],
    ))

    # ------------------------------------------------------------------
    # Recovery prevention: fstab manipulation
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB7-FSTAB-TRAP",
        behavior_id="AB7",
        sub_behavior="Recovery prevention (fstab reboot trap)",
        mitre=[MITREMapping("Impact", "T1490", "Inhibit System Recovery")],
        steps=[
            PatternStep(sub_op="File.open", path_match=path_contains("/etc/fstab"),
                        flag_match=flag_writable(), description="Open /etc/fstab",capture_path="file_path"),
            PatternStep(sub_op="File.write", description="Write malicious fstab entry", require_path="file_path"),
        ],
    ))

    # ------------------------------------------------------------------
    # inotify-based file monitoring for new targets
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB7-INOTIFY-WATCH",
        behavior_id="AB7",
        sub_behavior="inotify-based new file target monitoring",
        mitre=[MITREMapping("Impact", "T1486", "Data Encrypted for Impact"),
               MITREMapping("Discovery", "T1083", "File and Directory Discovery")],
        steps=[
            PatternStep(sub_op="File.inotify_init", description="Initialize inotify"),
            PatternStep(sub_op="File.inotify_watch",
                        path_match=path_contains("/home", "/mnt", "/var", "/opt"),
                        description="Watch directories for new files"),
        ],
    ))

    # ------------------------------------------------------------------
    # Network share discovery for lateral ransomware spread
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB7-SHARE-DISCOVERY",
        behavior_id="AB7",
        sub_behavior="Network share discovery for ransomware spread",
        mitre=[MITREMapping("Discovery", "T1135", "Network Share Discovery")],
        steps=[
            PatternStep(sub_op="File.enumerate",
                        path_match=path_contains("/mnt/", "/media/", "/nfs/", "/smb/"),
                        description="Enumerate network mount points"),
        ],
    ))
    
    return patterns


def build_ab8_patterns() -> List[SequencePattern]:
    patterns = []

    # ------------------------------------------------------------------
    # setuid(0) — direct elevation (checks both filename and extra_details)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB8-SETUID-ROOT",
        behavior_id="AB8",
        sub_behavior="Direct privilege elevation (setuid to root)",
        mitre=[MITREMapping("Privilege Escalation", "T1548.001", "Setuid and Setgid")],
        steps=[
            PatternStep(sub_op="Permission.elevate",
                        path_match=flag_root_elevation(),
                        flag_match=flag_root_elevation_details(),
                        description="Set UID/GID to root"),
        ],
    ))

    # Fallback: setuid(0) detected only via filename encoding
    patterns.append(SequencePattern(
        pattern_id="AB8-SETUID-ROOT-PATH",
        behavior_id="AB8",
        sub_behavior="Direct privilege elevation (setuid to root — path-based detection)",
        mitre=[MITREMapping("Privilege Escalation", "T1548.001", "Setuid and Setgid")],
        steps=[
            PatternStep(sub_op="Permission.elevate",
                        path_match=flag_root_elevation(),
                        description="Set UID/GID to root (filename-encoded)"),
        ],
    ))

    # Fallback: setuid(0) detected only via extra_details
    patterns.append(SequencePattern(
        pattern_id="AB8-SETUID-ROOT-DETAILS",
        behavior_id="AB8",
        sub_behavior="Direct privilege elevation (setuid to root — details-based detection)",
        mitre=[MITREMapping("Privilege Escalation", "T1548.001", "Setuid and Setgid")],
        steps=[
            PatternStep(sub_op="Permission.elevate",
                        flag_match=flag_root_elevation_details(),
                        description="Set UID/GID to root (extra_details)"),
        ],
    ))

    # ------------------------------------------------------------------
    # setgroups(0, []) — group elevation
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB8-SETGROUPS",
        behavior_id="AB8",
        sub_behavior="Group privilege manipulation",
        mitre=[MITREMapping("Privilege Escalation", "T1548.001", "Setuid and Setgid")],
        steps=[
            PatternStep(sub_op="Permission.elevate",
                        path_match=path_contains("gid=0", "=0", "setgroups"),
                        description="Modify group membership via setgroups (to root)"),
        ],
    ))
    # ------------------------------------------------------------------
    # exec → setuid (execute then elevate)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB8-EXEC-ELEVATE",
        behavior_id="AB8",
        sub_behavior="Execute then elevate",
        mitre=[MITREMapping("Privilege Escalation", "T1548.001", "Setuid and Setgid"),
               MITREMapping("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation")],
        steps=[
            PatternStep(sub_op="CodeExec.exec", description="Execute binary"),
            PatternStep(sub_op="Permission.elevate", description="Elevate privileges"),
        ],
    ))

    # ------------------------------------------------------------------
    # SUID binary abuse (implicit elevation — exec of known SUID binaries)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB8-SUID-ABUSE",
        behavior_id="AB8",
        sub_behavior="SUID binary abuse (implicit privilege elevation)",
        mitre=[MITREMapping("Privilege Escalation", "T1548.001", "Setuid and Setgid")],
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains(
                            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/pkexec",
                            "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
                            "/usr/bin/passwd", "/usr/bin/gpasswd",
                            "/usr/bin/mount", "/usr/bin/umount",
                            "/usr/bin/at", "/usr/bin/crontab",
                            "/usr/sbin/usermod", "/usr/sbin/groupmod",
                            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
                            "/usr/lib/openssh/ssh-keysign",
                            "/usr/lib/polkit-1/polkit-agent-helper-1",
                        ),
                        description="Execute known SUID binary"),
        ],
    ))

    # ------------------------------------------------------------------
    # capset
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB8-CAPSET",
        behavior_id="AB8",
        sub_behavior="Capability manipulation",
        mitre=[MITREMapping("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism")],
        steps=[
            PatternStep(sub_op="Permission.capability", description="Modify capabilities"),
        ],
    ))

    # ------------------------------------------------------------------
    # Kernel module loading via syscall (init_module / finit_module)
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB8-KMOD-SYSCALL",
        behavior_id="AB8",
        sub_behavior="Kernel module loading via syscall",
        mitre=[MITREMapping("Persistence", "T1547.006", "Kernel Modules and Extensions")],
        steps=[
            PatternStep(sub_op="CodeExec.kmod_load",
                        description="Load kernel module (init_module/finit_module)"),
        ],
    ))

    # ------------------------------------------------------------------
    # Kernel module loading via insmod/modprobe exec
    # ------------------------------------------------------------------
    patterns.append(SequencePattern(
        pattern_id="AB8-KMOD-EXEC",
        behavior_id="AB8",
        sub_behavior="Kernel module loading via command",
        mitre=[MITREMapping("Persistence", "T1547.006", "Kernel Modules and Extensions")],
        steps=[
            PatternStep(sub_op="CodeExec.exec",
                        path_match=path_contains("insmod", "modprobe"),
                        description="Execute insmod/modprobe"),
        ],
    ))

    # Namespace escape — only suspicious when not from a browser sandbox
    # Single unshare(NEWPID) is done by Chrome/Firefox for sandboxing
    # Suspicious: exec(non-browser) → unshare, or elevate → unshare
    patterns.append(SequencePattern(
        pattern_id="AB8-NS-ESCAPE-EXEC",
        behavior_id="AB8",
        sub_behavior="Namespace manipulation after suspicious execution",
        mitre=[MITREMapping("Privilege Escalation", "T1611", "Escape to Host")],
        steps=[
             PatternStep(sub_op="CodeExec.exec",
                        path_match=lambda fn: (
                            fn and
                            not path_contains(
                                # Browsers and desktop apps
                                "firefox", "chrome", "chromium", "brave",
                                "opera", "vivaldi", "thunderbird",
                                "electron", "xdg-open", "sensible-browser",
                                "x-www-browser", "gnome-open",
                                # Desktop integration (launched by browsers)
                                "dbus-send", "dbus-launch", "dbus-daemon",
                                "gdbus", "gconftool",
                                "xprop", "xdotool", "xwininfo","xdg-mime",
                                # Common utilities (not suspicious before unshare)
                                "which", "whereis", "grep", "sed", "awk",
                                "cat", "head", "tail", "uname", "hostname",
                                "id", "whoami", "ps", "env",
                            )(fn)
                        ),
                        description="Execute non-browser binary"),
            PatternStep(sub_op="Process.namespace",
                        description="Namespace manipulation (unshare/setns)"),
        ],
    ))

    # Namespace escape via setns (joining existing namespace) — always suspicious
    # setns is not used by browser sandboxes (they use unshare)
    patterns.append(SequencePattern(
        pattern_id="AB8-NS-SETNS",
        behavior_id="AB8",
        sub_behavior="Namespace joining (potential container escape)",
        mitre=[MITREMapping("Privilege Escalation", "T1611", "Escape to Host")],
        steps=[
            PatternStep(sub_op="Process.namespace",
                        path_match=path_contains("setns"),
                        description="Join existing namespace via setns"),
        ],
    ))
    return patterns


# ============================================================================
# STEP 3: ONE-PASS SCANNER
# ============================================================================
# original one
'''
def scan_all_patterns(events: list, patterns: list) -> List[Tuple[SequencePattern, List[dict], List[int]]]:
    """
    Walk events once, tracking all patterns simultaneously.
    Each pattern has its own step pointer.

    Repeatable patterns (single-step) reset after each match to collect
    all occurrences. Non-repeatable patterns complete after first match.

    Returns list of (pattern, matched_events, matched_step_indices) for
    patterns that fully matched (all required steps found in order).
    """
    n_patterns = len(patterns)
    step_ptrs = [0] * n_patterns
    matched_evs = [[] for _ in range(n_patterns)]
    matched_idxs = [[] for _ in range(n_patterns)]
    completed = [False] * n_patterns
    # For repeatable patterns, store each complete match separately
    repeat_matches = [[] for _ in range(n_patterns)]  # list of (events, indices) tuples

    for event in events:
        for pi in range(n_patterns):
            if completed[pi]:
                continue

            pat = patterns[pi]
            si = step_ptrs[pi]

            while si < len(pat.steps):
                step = pat.steps[si]

                if step.matches(event):
                    matched_evs[pi].append(event)
                    matched_idxs[pi].append(si)
                    si += 1
                    step_ptrs[pi] = si
                    break
                elif step.optional:
                    si += 1
                    step_ptrs[pi] = si
                else:
                    break

            # Check completion
            pattern_done = False
            if step_ptrs[pi] >= len(pat.steps):
                pattern_done = True
            else:
                all_remaining_optional = all(
                    pat.steps[s].optional for s in range(step_ptrs[pi], len(pat.steps))
                )
                if all_remaining_optional and len(matched_evs[pi]) > 0:
                    pattern_done = True

            if pattern_done:
                if pat.repeatable:
                    # Save this match, reset for next occurrence
                    repeat_matches[pi].append(
                        (list(matched_evs[pi]), list(matched_idxs[pi]))
                    )
                    step_ptrs[pi] = 0
                    matched_evs[pi] = []
                    matched_idxs[pi] = []
                else:
                    completed[pi] = True

    results = []
    for pi in range(n_patterns):
        pat = patterns[pi]

        if pat.repeatable:
            # Combine all repeated matches into one result
            all_evs = []
            all_idxs = []
            for evs, idxs in repeat_matches[pi]:
                all_evs.extend(evs)
                all_idxs.extend(idxs)
            if all_evs:
                results.append((pat, all_evs, all_idxs))
        else:
            required_matched = sum(
                1 for si in matched_idxs[pi] if not pat.steps[si].optional
            )
            if required_matched >= pat.required_count:
                results.append((pat, matched_evs[pi], matched_idxs[pi]))

    return results
'''
# The following    scan_all_patterns consider same_tid 
'''        
def scan_all_patterns(events: list, patterns: list) -> List[Tuple[SequencePattern, List[dict], List[int]]]:
    """
    Walk events once, tracking all patterns simultaneously.
    Each pattern has its own step pointer.

    When pattern.same_tid is True, all steps after step 0 must occur
    on the same TID as the event that matched step 0.

    Repeatable patterns (single-step) reset after each match to collect
    all occurrences. Non-repeatable patterns complete after first match.

    Returns list of (pattern, matched_events, matched_step_indices) for
    patterns that fully matched (all required steps found in order).
    """
    n_patterns = len(patterns)
    step_ptrs = [0] * n_patterns
    matched_evs = [[] for _ in range(n_patterns)]
    matched_idxs = [[] for _ in range(n_patterns)]
    completed = [False] * n_patterns
    anchor_tids = [None] * n_patterns  # TID from step 0 match (for same_tid patterns)
    repeat_matches = [[] for _ in range(n_patterns)]

    for event in events:
        ev_tid = event.get("tid")

        for pi in range(n_patterns):
            if completed[pi]:
                continue

            pat = patterns[pi]
            si = step_ptrs[pi]

            # same_tid enforcement: skip this event if TID doesn't match anchor
            if pat.same_tid and si > 0 and anchor_tids[pi] is not None:
                if ev_tid != anchor_tids[pi]:
                    continue

            while si < len(pat.steps):
                step = pat.steps[si]

                if step.matches(event):
                    # Record anchor TID on first step match
                    if si == 0 and pat.same_tid:
                        anchor_tids[pi] = ev_tid

                    matched_evs[pi].append(event)
                    matched_idxs[pi].append(si)
                    si += 1
                    step_ptrs[pi] = si
                    break
                elif step.optional:
                    si += 1
                    step_ptrs[pi] = si
                else:
                    break

            # Check completion
            pattern_done = False
            if step_ptrs[pi] >= len(pat.steps):
                pattern_done = True
            else:
                all_remaining_optional = all(
                    pat.steps[s].optional for s in range(step_ptrs[pi], len(pat.steps))
                )
                if all_remaining_optional and len(matched_evs[pi]) > 0:
                    pattern_done = True

            if pattern_done:
                if pat.repeatable:
                    repeat_matches[pi].append(
                        (list(matched_evs[pi]), list(matched_idxs[pi]))
                    )
                    step_ptrs[pi] = 0
                    matched_evs[pi] = []
                    matched_idxs[pi] = []
                    anchor_tids[pi] = None  # Reset anchor for next match
                else:
                    completed[pi] = True

    results = []
    for pi in range(n_patterns):
        pat = patterns[pi]

        if pat.repeatable:
            all_evs = []
            all_idxs = []
            for evs, idxs in repeat_matches[pi]:
                all_evs.extend(evs)
                all_idxs.extend(idxs)
            if all_evs:
                results.append((pat, all_evs, all_idxs))
        else:
            required_matched = sum(
                1 for si in matched_idxs[pi] if not pat.steps[si].optional
            )
            if required_matched >= pat.required_count:
                results.append((pat, matched_evs[pi], matched_idxs[pi]))

    return results
'''

# This scan_all_patterns consider the fd and file paths acroess the syscalls of the same pattern. 
def scan_all_patterns(events: list, patterns: list) -> List[Tuple[SequencePattern, List[dict], List[int]]]:
    """
    Walk events once, tracking all patterns simultaneously.
 
    Object correlation (fail-closed):
      - capture_path/require_path: link open→read and open→write by file path
      - capture_fd/require_fd: link connect→send and connect→recv by socket fd
 
    When require_fd or require_path is set on a step:
      - If captured value exists AND event has the value → must match exactly
      - If captured value exists but event has NO value → reject (fail closed)
      - If captured value is None (capture step hasn't fired) → reject (fail closed)
    """
    n_patterns = len(patterns)
    step_ptrs = [0] * n_patterns
    matched_evs = [[] for _ in range(n_patterns)]
    matched_idxs = [[] for _ in range(n_patterns)]
    completed = [False] * n_patterns
    captured_fds = [{} for _ in range(n_patterns)]
    captured_paths = [{} for _ in range(n_patterns)]
    repeat_matches = [[] for _ in range(n_patterns)]
 
    for event in events:
        for pi in range(n_patterns):
            if completed[pi]:
                continue
 
            pat = patterns[pi]
            si = step_ptrs[pi]
 
            while si < len(pat.steps):
                step = pat.steps[si]
 
                if step.matches(event):
                    # --- Object correlation checks (fail-closed) ---
 
                    # Check fd requirement
                    if step.require_fd:
                        required_fd = captured_fds[pi].get(step.require_fd)
                        event_fd = _extract_fd(event)
                        if required_fd is None or event_fd is None or event_fd != required_fd:
                            break  # fail closed: missing or mismatched fd
 
                    # Check path requirement
                    if step.require_path:
                        required_path = captured_paths[pi].get(step.require_path)
                        event_path = _extract_path(event)
                        if not required_path or not event_path or not _paths_match(required_path, event_path):
                            break  # fail closed: missing or mismatched path
 
                    # --- Capture values for future steps ---
 
                    if step.capture_fd:
                        fd_val = _extract_fd(event)
                        if fd_val is not None:
                            captured_fds[pi][step.capture_fd] = fd_val
 
                    if step.capture_path:
                        path_val = _extract_path(event)
                        if path_val:
                            captured_paths[pi][step.capture_path] = path_val
 
                    # --- Record match ---
                    matched_evs[pi].append(event)
                    matched_idxs[pi].append(si)
                    si += 1
                    step_ptrs[pi] = si
                    break
                elif step.optional:
                    si += 1
                    step_ptrs[pi] = si
                else:
                    break
 
            # Check completion
            pattern_done = False
            if step_ptrs[pi] >= len(pat.steps):
                pattern_done = True
            else:
                all_remaining_optional = all(
                    pat.steps[s].optional for s in range(step_ptrs[pi], len(pat.steps))
                )
                if all_remaining_optional and len(matched_evs[pi]) > 0:
                    pattern_done = True
 
            if pattern_done:
                if pat.repeatable:
                    repeat_matches[pi].append(
                        (list(matched_evs[pi]), list(matched_idxs[pi]))
                    )
                    step_ptrs[pi] = 0
                    matched_evs[pi] = []
                    matched_idxs[pi] = []
                    captured_fds[pi] = {}
                    captured_paths[pi] = {}
                else:
                    completed[pi] = True
 
    results = []
    for pi in range(n_patterns):
        pat = patterns[pi]
        if pat.repeatable:
            all_evs = []
            all_idxs = []
            for evs, idxs in repeat_matches[pi]:
                all_evs.extend(evs)
                all_idxs.extend(idxs)
            if all_evs:
                results.append((pat, all_evs, all_idxs))
        else:
            required_matched = sum(
                1 for si in matched_idxs[pi] if not pat.steps[si].optional
            )
            if required_matched >= pat.required_count:
                results.append((pat, matched_evs[pi], matched_idxs[pi]))
 
    return results
# ============================================================================
# STEP 5: LOOP DETECTION (AB5 mining, AB7 ransomware)
# ============================================================================

def detect_ransomware_loops(events: list, threshold: int = 10) -> List[LoopMatch]:
    """
    Detect repeated File.open → File.read → File.write cycles where
    the write is to a DIFFERENT file than the read (or same file opened writable).
    Excludes: stdout/stderr, fd-only filenames, framework model files.
    """
    cycle_count = 0
    seen_files = set()
    state = 0
    current_file = None

    # Paths that are framework noise, not ransomware targets
    _noise_paths = ("/proc/", "/sys/", "/dev/", "/usr/lib/", "/usr/share/",
                    "site-packages/", ".so", ".pyc", "pytorch_model.bin",
                    "model.bin", ".safetensors", ".h5", ".keras", ".onnx",
                    ".msgpack", ".joblib", ".pkl", ".pickle", ".pt", ".pth",
                    ".bin", ".pb", ".tflite", ".params", ".pdmodel",
                    ".pdiparams", ".cbm", ".xgb", ".bst", ".ubj", ".lgb",
                    "config.json", "tokenizer.json", "vocab.txt",
                    ".cache/huggingface/", ".cache/torch/")

    def _is_real_file(filename):
        """Filter out fd references, stdout/stderr, and framework paths."""
        if not filename:
            return False
        if filename.startswith("fd=") or filename in ("stdout", "stderr", "stdin"):
            return False
        fn_lower = filename.lower()
        return not any(p in fn_lower for p in _noise_paths)

    for ev in events:
        sub_op = ev.get("sub_op", "")
        filename = ev.get("filename", "")

        if state == 0 and sub_op == "File.open" and _is_real_file(filename):
            current_file = filename
            state = 1
        elif state == 1 and sub_op == "File.read":
            state = 2
        elif (state == 1 or state == 2) and sub_op == "File.write":
            write_file = filename
            if _is_real_file(write_file) and current_file and current_file not in seen_files:
                seen_files.add(current_file)
                cycle_count += 1
            state = 0
            current_file = None
        elif sub_op == "File.open" and _is_real_file(filename):
            current_file = filename
            state = 1
        elif sub_op not in ("File.stat", "File.seek", "File.close",
                            "System.ioctl", "File.control", "File.access",
                            "File.enumerate", "File.readlink", "File.chdir",
                            "File.rename", "File.delete", "File.permission",
                            "File.ownership", "File.truncate",
                            "Network.send", "Network.recv", "Network.connect",
                            "Network.socket", "Network.info", "Network.sockopt",
                            "System.random", "System.info",
                            "Memory.map", "Memory.protect",
                            "Permission.query", "Permission.elevate"):
            # Only reset on truly unrelated operations (e.g., fork/exec)
            # Allow file metadata ops, network ops (key exfil mid-encryption),
            # memory ops, and permission checks to interleave
            if state == 1 or state == 2:
                pass  # Allow interleaved ops within a partial cycle
            else:
                state = 0
                current_file = None

    if cycle_count >= threshold:
        return [LoopMatch(
            behavior_id="AB7",
            sub_behavior=f"Ransomware encryption loop ({cycle_count} files)",
            loop_count=cycle_count,
            sample_events=[],
            mitre=[MITREMapping("Impact", "T1486", "Data Encrypted for Impact")],
        )]
    return []

def detect_mining_loops(events: list, threshold: int = 20) -> List[LoopMatch]:
    """
    Detect sustained Network.send → Network.recv alternations on the same fd.
    If count >= threshold, flag as mining stratum protocol loop.
    """
    send_recv_count = 0
    last_was_send = False

    for ev in events:
        sub_op = ev.get("sub_op", "")
        if sub_op == "Network.send":
            last_was_send = True
        elif sub_op == "Network.recv" and last_was_send:
            send_recv_count += 1
            last_was_send = False
        else:
            last_was_send = False

    if send_recv_count >= threshold:
        return [LoopMatch(
            behavior_id="AB5",
            sub_behavior=f"Mining stratum loop ({send_recv_count} send/recv cycles)",
            loop_count=send_recv_count,
            sample_events=[],
            mitre=[MITREMapping("Impact", "T1496", "Resource Hijacking")],
        )]
    return []


# ============================================================================
# STEP 6: CROSS-BEHAVIOR CORRELATION
# ============================================================================

_COMPOUND_RULES = [
    ({"AB1", "AB6"}, "Credential theft + reverse shell (data exfil via interactive access)"),
    ({"AB1", "AB2"}, "Credential theft + backdoor installation (persistent access after theft)"),
    ({"AB4", "AB6"}, "Code execution + remote control (malware deployment with C2)"),
    ({"AB7", "AB3"}, "Ransomware + system manipulation (encrypt then tamper recovery)"),
    ({"AB4", "AB2"}, "Code execution + persistence (execute payload then persist)"),
    ({"AB1", "AB5"}, "Information theft + cryptojacking (recon then mine)"),
    ({"AB8", "AB2"}, "Privilege escalation + backdoor (elevate then persist)"),
    ({"AB8", "AB4"}, "Privilege escalation + code execution (elevate then execute)"),
    ({"AB7", "AB8"}, "Ransomware + privilege escalation (elevate then encrypt)"),
    ({"AB6", "AB2"}, "Remote control + persistence (C2 with persistent access)"),
    ({"AB7", "AB6"}, "Ransomware + remote control (encrypt with C2 channel)"),
]


def detect_compound_attacks(behavior_ids: Set[str]) -> List[str]:
    compounds = []
    for required_ids, description in _COMPOUND_RULES:
        if required_ids.issubset(behavior_ids):
            compounds.append(f"{'+'.join(sorted(required_ids))}: {description}")
    return compounds


# ============================================================================
# STEP 7: MAIN CLASSIFIER
# ============================================================================

_BEHAVIOR_NAMES = {
    "AB1": "Sensitive Information Theft",
    "AB2": "Backdoor Installation / Persistence",
    "AB3": "System Manipulation",
    "AB4": "Malicious Code Execution",
    "AB5": "Cryptojacking",
    "AB6": "Remote Control",
    "AB7": "Ransomware",
    "AB8": "Privilege Escalation",
}


class AttackBehaviorClassifier:

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.patterns = self._build_all_patterns()

    def _build_all_patterns(self) -> List[SequencePattern]:
        all_patterns = []
        all_patterns.extend(build_ab1_patterns())
        all_patterns.extend(build_ab2_patterns())
        all_patterns.extend(build_ab3_patterns())
        all_patterns.extend(build_ab4_patterns())
        all_patterns.extend(build_ab5_patterns())
        all_patterns.extend(build_ab6_patterns())
        all_patterns.extend(build_ab7_patterns())
        all_patterns.extend(build_ab8_patterns())
        return all_patterns

    def classify(self, loading_events: list, execution_events: list,
                 model_path: str = "unknown") -> ClassificationVerdict:

        if self.verbose:
            print(f"\n{'='*70}")
            print(f"ATTACK BEHAVIOR CLASSIFICATION")
            print(f"Model: {model_path}")
            print(f"Loading events: {len(loading_events)}")
            print(f"Execution events: {len(execution_events)}")
            print(f"Patterns defined: {len(self.patterns)}")
            print(f"{'='*70}")

        all_pattern_matches = []
        all_loop_matches = []

        for phase_name, raw_events in [("LOADING", loading_events),
                                        ("EXECUTION", execution_events)]:
            if not raw_events:
                continue

            # Step 1: Pre-filter
            events = prefilter_events(raw_events)
            if self.verbose:
                removed = len(raw_events) - len(events)
                if removed:
                    print(f"\n  [{phase_name}] Pre-filtered: removed {removed} O_DIRECTORY events")

            # Step 3: One-pass scan
            matches = scan_all_patterns(events, self.patterns)

            for pat, matched_evs, matched_idxs in matches:
                pm = PatternMatch(
                    pattern=pat,
                    matched_events=matched_evs,
                    matched_step_indices=matched_idxs,
                    phase=phase_name,
                )
                all_pattern_matches.append(pm)

                if self.verbose:
                    print(f"\n  [{phase_name}] {pat.pattern_id}: {pat.sub_behavior}")
                    for i, ev in enumerate(matched_evs):
                        si = matched_idxs[i] if i < len(matched_idxs) else "?"
                        step_desc = pat.steps[si].description if isinstance(si, int) and si < len(pat.steps) else ""
                        print(f"    Step {si}: {ev.get('operation')} -> "
                              f"{ev.get('filename', '')[:60]}  ({step_desc})")
                    for m in pat.mitre:
                        print(f"    MITRE: {m.tactic} / {m.technique_id} ({m.technique_name})")

            # Step 5: Loop detection
            ransomware_loops = detect_ransomware_loops(events)
            mining_loops = detect_mining_loops(events)
            for lm in ransomware_loops + mining_loops:
                lm.phase = phase_name
                all_loop_matches.append(lm)
                if self.verbose:
                    print(f"\n  [{phase_name}] LOOP: {lm.sub_behavior}")

        # Group by behavior ID
        behavior_groups = defaultdict(lambda: {"patterns": [], "loops": []})
        for pm in all_pattern_matches:
            behavior_groups[pm.pattern.behavior_id]["patterns"].append(pm)
        for lm in all_loop_matches:
            behavior_groups[lm.behavior_id]["loops"].append(lm)

        # Build BehaviorResult objects
        behaviors = []
        for ab_id in sorted(behavior_groups.keys()):
            group = behavior_groups[ab_id]
            pattern_matches = group["patterns"]
            loop_matches = group["loops"]

            # Collect unique MITRE
            seen = set()
            all_mitre = []
            for pm in pattern_matches:
                for m in pm.pattern.mitre:
                    if m.technique_id not in seen:
                        seen.add(m.technique_id)
                        all_mitre.append(m)
            for lm in loop_matches:
                for m in lm.mitre:
                    if m.technique_id not in seen:
                        seen.add(m.technique_id)
                        all_mitre.append(m)

            sub_behaviors = list(set(
                [pm.pattern.sub_behavior for pm in pattern_matches] +
                [lm.sub_behavior for lm in loop_matches]
            ))

            phases = set()
            for pm in pattern_matches:
                phases.add(pm.phase)
            for lm in loop_matches:
                phases.add(lm.phase)

            behaviors.append(BehaviorResult(
                behavior_id=ab_id,
                behavior_name=_BEHAVIOR_NAMES.get(ab_id, ab_id),
                sub_behaviors=sub_behaviors,
                pattern_matches=pattern_matches,
                loop_matches=loop_matches,
                mitre_techniques=all_mitre,
                phase=", ".join(sorted(phases)),
            ))

        # Step 6: Cross-behavior correlation
        detected_ids = set(b.behavior_id for b in behaviors)
        #compound_attacks = detect_compound_attacks(detected_ids)

        # Verdict
        is_malicious = len(behaviors) > 0
        verdict = ClassificationVerdict(
            model_path=model_path,
            is_malicious=is_malicious,
            behaviors=behaviors,
            #compound_attacks=compound_attacks,
            total_loading_events=len(loading_events),
            total_execution_events=len(execution_events),
        )

        if self.verbose:
            print(f"\n{'='*70}")
            if is_malicious:
                print(f"  VERDICT: MALICIOUS — {len(behaviors)} attack behavior(s) detected")
                for b in behaviors:
                    print(f"    {b.behavior_id}: {b.behavior_name}")
                    for sb in b.sub_behaviors:
                        print(f"      - {sb}")
                    for m in b.mitre_techniques:
                        print(f"      MITRE: {m.technique_id} ({m.technique_name})")
                #if compound_attacks:
                 #   print(f"\n  COMPOUND ATTACKS:")
                   # for ca in compound_attacks:
                      #  print(f"    {ca}")
            else:
                print(f"  VERDICT: BENIGN — no attack behaviors detected")
            print(f"{'='*70}")

        return verdict


# ============================================================================
# CLI
# ============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Classify eBPF events into AB1-AB8")
    parser.add_argument("events_dir", help="Directory with tagged event JSON files")
    parser.add_argument("--verbose", "-v", action="store_true", default=True)
    parser.add_argument("--output", "-o", type=str, default=None)
    args = parser.parse_args()

    try:
        from syscall_category_mapper import SyscallCategoryMapper
    except ImportError:
        print("Error: syscall_category_mapper.py must be in the same directory")
        sys.exit(1)

    mapper = SyscallCategoryMapper()
    tagged = mapper.load_and_tag(args.events_dir)

    if not tagged:
        print("Failed to load events")
        sys.exit(1)

    classifier = AttackBehaviorClassifier(verbose=args.verbose)
    verdict = classifier.classify(
        tagged.loading_events,
        tagged.execution_events,
        model_path=args.events_dir,
    )

    if args.output:
        with open(args.output, "w") as f:
            json.dump(verdict.to_dict(), f, indent=2, default=str)
        print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
