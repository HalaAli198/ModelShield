#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>


// System Operations
#define OP_UNAME 1
#define OP_SYSINFO 2
#define OP_SCHED_GETAFFINITY 3
#define OP_IOCTL 4
#define OP_GETRANDOM 5
#define OP_SETHOSTNAME 6
//#define OP_GETHOSTNAME 7
#define OP_SETDOMAINNAME 8


// File Operations
#define OP_OPEN 9
#define OP_OPENAT 10
#define OP_CREAT 11
#define OP_READ 12
#define OP_PREAD64  13
#define OP_READV 14
#define OP_WRITE 15
#define OP_PWRITE64  16
#define OP_WRITEV 17
#define OP_STAT 18
#define OP_FSTAT 19
#define OP_NEWFSTATAT 20 
#define OP_STATX 21
#define OP_ACCESS 22
#define OP_FACCESSAT 23
#define OP_RENAME 24
#define OP_RENAMEAT 25
#define OP_RENAMEAT2 26
#define OP_LINK  27
#define OP_LINKAT 28
#define OP_UNLINK  29
#define OP_UNLINKAT 30
#define OP_SYMLINK 31
#define OP_SYMLINKAT 32
#define OP_CHMOD 33
#define OP_FCHMOD 34
#define OP_FCHMODAT 35
#define OP_CHOWN 36
#define OP_FCHOWN 37
#define OP_FCHOWNAT 38
#define OP_LCHOWN 39
#define OP_GETDENTS64 40
#define OP_MKDIR 41
#define OP_MKDIRAT 42
#define OP_RMDIR 43
#define OP_READLINK 44 
#define OP_READLINKAT 45
#define OP_TRUNCATE 46
#define OP_FTRUNCATE 47
#define OP_FCNTL 48
#define OP_CHDIR 49
#define OP_FCHDIR 50
#define OP_SENDFILE 51
#define OP_DUP 52
#define OP_DUP2 53
#define OP_DUP3 54
#define OP_GETCWD 55
#define OP_LSEEK  56
#define OP_CLOSE 57
#define OP_SETXATTR 58            
#define OP_LSETXATTR  59        
#define OP_FSETXATTR  60       
#define OP_REMOVEXATTR 61     
#define OP_LREMOVEXATTR 62   
#define OP_FREMOVEXATTR 63

  
// Network Operations 
#define OP_SOCKET 64
#define OP_BIND  65
#define OP_LISTEN  66
#define OP_ACCEPT 67
#define OP_ACCEPT4  68
#define OP_CONNECT 69
#define OP_SENDTO 70
#define OP_SENDMSG 71
#define OP_RECVFROM 72
#define OP_RECVMSG  73
#define OP_GETSOCKNAME 74
#define OP_GETPEERNAME 75
#define OP_GETSOCKOPT 76
#define OP_SETSOCKOPT 77
#define OP_FORK 78
#define OP_VFORK 79
#define OP_CLONE 80
#define OP_CLONE3 81
#define OP_PRCTL 82
#define OP_PTRACE 83
#define OP_SETSID  84
 
// Memory Operations 
#define OP_MMAP 85
#define OP_MPROTECT 86 
#define OP_MEMFD_CREATE 87 
   
// Permission Operations
#define OP_GETUID 88
#define OP_GETEUID 89
#define OP_GETGID 90
#define OP_GETEGID 91
#define OP_GETGROUPS 92
#define OP_SETUID 93
#define OP_SETGID 94
#define OP_SETREUID 95
#define OP_SETRESUID 96
#define OP_SETREGID 97
#define OP_SETRESGID 98
#define OP_SETGROUPS 99
#define OP_CAPSET 100


// Code Execution OPerations
#define OP_EXECVE 101
#define OP_EXECVEAT 102
// #define OP_FEXECVE  103
//----------------------------------------------------------------------------------
// Extra- Process Operations
#define OP_PROCESS_VM_READV 104
#define OP_PROCESS_VM_WRITEV 105
#define OP_KILL 106
#define OP_TKILL 107
#define OP_TGKILL 108
// Extra- Kernel & System operations
#define OP_INIT_MODULE 109
#define OP_FINIT_MODULE 110
#define OP_DELETE_MODULE 111
#define OP_BPF 112
#define OP_MOUNT 113
#define OP_UMOUNT2 114
#define OP_PIVOT_ROOT 115
#define OP_CHROOT 116
#define OP_SECCOMP 118
#define OP_SETNS 119
#define OP_UNSHARE 120
#define OP_KEYCTL      121    // need TRACEPOINT_PROBE    
#define OP_IOPRIO_SET  122        // need TRACEPOINT_PROBE   
#define OP_MINCORE   123   // need TRACEPOINT_PROBE 
// Extra- File operations (medi um priority)
#define OP_MKNOD 124
#define OP_MKNODAT 125
#define OP_FALLOCATE 126
#define OP_COPY_FILE_RANGE 127
// Extra-  IPC & Data Transfer
#define OP_PIPE 128
#define OP_PIPE2 129
#define OP_SPLICE 130
#define OP_TEE 131
#define OP_VMSPLICE 132
#define OP_SYSFS 133   // need TRACEPOINT_PROBE 
#define OP_GETRLIMIT 134  // need TRACEPOINT_PROBE 
#define OP_PRLIMIT64 135 // need TRACEPOINT_PROBE 
// Extra- Process Control
#define OP_WAIT4 136
#define OP_WAITID 137  // need TRACEPOINT_PROBE 
#define OP_RT_SIGACTION 138  // need TRACEPOINT_PROBE 
#define OP_RT_SIGPROCMASK 139  // need TRACEPOINT_PROBE 
//Extra-  Shared Memory
#define OP_SHMGET 140
#define OP_SHMAT 141
//Extra- Other
#define OP_PERF_EVENT_OPEN 142
#define OP_PERSONALITY 143
#define OP_MADVISE 144
#define OP_USERFAULTFD 145
#define OP_REBOOT 146
#define OP_IOPL 147
#define OP_IOPERM 148  
//----------------------------------------------------------------------------------

// Define correlation_info struct FIRST
struct correlation_info {
    char correlation_id[16];
    u8 phase;
    u64 start_time;
};

// Optimized threat_event struct - reduced size
struct threat_event {
    u32 pid;
    u32 tid;
    u32 ppid;
    char comm[16];
    u8 operation_id;  
    
    // Union for operation-specific data to save space
    union {
        // For file operations
        struct {
            char path[64];  // Reduced from 256
        } file;
        
        // For network operations - raw data, no formatting
        struct {
         u32 ip_addr;      // IPv4, host order (after bpf_ntohl)
         u16 port;         // host order (after bpf_ntohs)
         u8  family;       // AF_*
         u8  sock_type;    // optional; not set by connect()
         u8  ip6[16];      // IPv6 raw bytes (valid when family == AF_INET6)
         } net;
        // For process operations
        struct {
            u32 uid;
            u32 gid;
            u32 flags;
        } proc;
        
        // Generic numeric arguments
        struct {
            u64 arg1;
            u64 arg2;
            u32 arg3;
        } generic;
    } data;
    
    int user_stack_id;
    u64 timestamp;
    char correlation_id[16];
    u8 phase;
};

struct thread_event {
    u32 parent_pid;
    u32 parent_tid;
    u32 child_pid;
    u32 child_tid;
    char parent_correlation_id[16];
    u8 parent_phase;
    u64 timestamp;
    char comm[16];
};

struct fd_info {
    char path[64];  // Reduced from 256
    u64 timestamp;
    u32 pid;
};

struct iovec {
    void *iov_base;
    __kernel_size_t iov_len;
};

struct user_msghdr {
    void *msg_name;
    int msg_namelen;
    struct iovec *msg_iov;
    __kernel_size_t msg_iovlen;
    void *msg_control;
    __kernel_size_t msg_controllen;
    unsigned int msg_flags;
};

struct syscall_data {
    u64 fd;
    u64 buff_ptr;
    u64 msg_ptr;
    u64 flags;
};


// Hash maps
BPF_HASH(target_pids, u32, u8);
BPF_HASH(model_threads, u32, u64);
BPF_HASH(thread_context, u32, struct correlation_info);
BPF_HASH(fd_paths, u64, struct fd_info);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERF_OUTPUT(thread_events);
BPF_HASH(syscall_args, u32, struct syscall_data);

static inline bool should_trace(u32 pid, u32 tid) {
    u8 *val = target_pids.lookup(&pid);
    if (val != NULL) {
        u64 timestamp = bpf_ktime_get_ns();
        model_threads.update(&tid, &timestamp);
        return true;
    }
    
    u64 *thread_val = model_threads.lookup(&tid);
    return thread_val != NULL;
}

static inline void copy_correlation_context(struct threat_event *event, u32 tid) {
    struct correlation_info *ctx = thread_context.lookup(&tid);
    if (ctx != NULL) {
        // Use bpf_probe_read for efficiency
        bpf_probe_read(event->correlation_id, sizeof(event->correlation_id), ctx->correlation_id);
        event->phase = ctx->phase;
    } else {
        __builtin_memcpy(event->correlation_id, "unknown", 8);
        event->phase = 0;
    }
}

//---------------------------------------------------------------------------------------------------------------------------------------
// OP_UNAME 
TRACEPOINT_PROBE(syscalls, sys_enter_newuname) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_UNAME;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// -------------------------------------------// System Operations //-------------------------------------------//
// Add tracepoint probe
TRACEPOINT_PROBE(syscalls, sys_enter_sysinfo) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SYSINFO;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

//OP_SCHED_GETAFFINITY
TRACEPOINT_PROBE(syscalls, sys_enter_sched_getaffinity) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SCHED_GETAFFINITY;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->pid;
    event.data.generic.arg2 = (u64)args->len;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

//OP_IOCTL
TRACEPOINT_PROBE(syscalls, sys_enter_ioctl) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_IOCTL;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->cmd;
    event.data.generic.arg3 = (u32)args->arg;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// OP_GETRANDOM
TRACEPOINT_PROBE(syscalls, sys_enter_getrandom) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETRANDOM;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->len;
    event.data.generic.arg2 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// OP_SETHOSTNAME
TRACEPOINT_PROBE(syscalls, sys_enter_sethostname) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SETHOSTNAME;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->name);
    event.data.generic.arg1 = (u64)args->len;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
/*
// OP_GETHOSTNAME
TRACEPOINT_PROBE(syscalls, sys_enter_gethostname) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETHOSTNAME;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->len;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
*/

// OP_SETDOMAINNAME
TRACEPOINT_PROBE(syscalls, sys_enter_setdomainname) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SETDOMAINNAME;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->name);
    event.data.generic.arg1 = (u64)args->len;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// -------------------------------------------// File Operations //-------------------------------------------//

TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_OPEN;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    event.data.generic.arg1 = (u64)args->flags;
    event.data.generic.arg2 = (u64)args->mode;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
   
    bpf_trace_printk("C size=%d\n", sizeof(struct threat_event)); 
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_OPENAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Single efficient read - no loops!
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);


    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    
    // Store FD mapping for later use
    struct fd_info info = {};
    bpf_probe_read_user_str(info.path, sizeof(info.path), (void *)args->filename);
    info.timestamp = bpf_ktime_get_ns();
    info.pid = pid;
    
    u64 temp_key = ((u64)pid << 32) | tid;
    fd_paths.update(&temp_key, &info);
      
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_creat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_CREAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    event.data.generic.arg1 = (u64)args->mode;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_READ;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Store fd and count as raw data - no formatting!
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->count;
    
    // Look up path if available
    u64 fd_key = ((u64)pid << 32) | (u32)args->fd;
    struct fd_info *path_info = fd_paths.lookup(&fd_key);
    if (path_info != NULL) {
        bpf_probe_read(event.data.file.path, sizeof(event.data.file.path), path_info->path);
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pread64) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PREAD64;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->count;
    event.data.generic.arg3 = (u32)(args->pos & 0xFFFFFFFF);  // Store offset
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_readv) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_READV;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->vlen;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_WRITE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->count;
    
    u64 fd_key = ((u64)pid << 32) | (u32)args->fd;
    struct fd_info *path_info = fd_paths.lookup(&fd_key);
    if (path_info != NULL) {
        bpf_probe_read(event.data.file.path, sizeof(event.data.file.path), path_info->path);
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PWRITE64;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->count;
    event.data.generic.arg3 = (u32)(args->pos & 0xFFFFFFFF);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}



TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_WRITEV;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->vlen;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_newstat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_STAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_newfstat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FSTAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_newfstatat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_NEWFSTATAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->dfd;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}




TRACEPOINT_PROBE(syscalls, sys_enter_statx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_STATX;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->dfd;
    event.data.generic.arg2 = (u64)args->flags;
    event.data.generic.arg3 = (u32)args->mask;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_access) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_ACCESS;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    event.data.generic.arg1 = (u64)args->mode;
   // Validate pointer before reading
    if (args->filename != NULL) {
        bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    } else {
        // Mark as null pointer
        event.data.file.path[0] = '\0';
    }
 
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


    


TRACEPOINT_PROBE(syscalls, sys_enter_faccessat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FACCESSAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->dfd;
    event.data.generic.arg2 = (u64)args->mode;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_RENAME;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   // Just store old name in path, new name we'll pass via arg
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->oldname);
   // Store first 8 bytes of new name in arg1 for reference
   bpf_probe_read_user(&event.data.generic.arg1, 8, (void *)args->newname);
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_RENAMEAT;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   event.data.generic.arg1 = (u64)args->olddfd;
   event.data.generic.arg2 = (u64)args->newdfd;
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->oldname);
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_RENAMEAT2;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->olddfd;
    event.data.generic.arg2 = (u64)args->newdfd;
    event.data.generic.arg3 = (u32)args->flags;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->oldname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_link) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_LINK;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->oldname);
    // Store first 8 bytes of newname in arg1
    bpf_probe_read_user(&event.data.generic.arg1, 8, (void *)args->newname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_linkat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_LINKAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->olddfd;
    event.data.generic.arg2 = (u64)args->newdfd;
    event.data.generic.arg3 = (u32)args->flags;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->oldname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_UNLINK;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_UNLINKAT;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   event.data.generic.arg1 = (u64)args->dfd;
   event.data.generic.arg2 = (u64)args->flag;
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlink) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SYMLINK;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->oldname);
    bpf_probe_read_user(&event.data.generic.arg1, 8, (void *)args->newname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlinkat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SYMLINKAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->oldname);
    event.data.generic.arg1 = (u64)args->newdfd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_CHMOD;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
   event.data.generic.arg1 = (u64)args->mode;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fchmod) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FCHMOD;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->mode;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FCHMODAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->dfd;
    event.data.generic.arg2 = (u64)args->mode;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_chown) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_CHOWN;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
   event.data.proc.uid = (u32)args->user;
   event.data.proc.gid = (u32)args->group;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchown) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FCHOWN;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.proc.uid = (u32)args->user;
    event.data.proc.gid = (u32)args->group;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchownat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FCHOWNAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->dfd;
    event.data.proc.uid = (u32)args->user;
    event.data.proc.gid = (u32)args->group;
    event.data.proc.flags = (u32)args->flag;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_lchown) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_LCHOWN;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    event.data.proc.uid = (u32)args->user;
    event.data.proc.gid = (u32)args->group;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents64) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETDENTS64;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    int fd = args->fd;
    event.data.generic.arg1 = (u64)fd;
    
    // Try to get path from fd_paths
    u64 fd_key = ((u64)pid << 32) | (u32)fd;
    struct fd_info *path_info = fd_paths.lookup(&fd_key);
    if (path_info != NULL) {
        bpf_probe_read(event.data.file.path, sizeof(event.data.file.path), path_info->path);
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mkdir) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MKDIR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    event.data.generic.arg1 = (u64)args->mode;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MKDIRAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->dfd;
    event.data.generic.arg2 = (u64)args->mode;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rmdir) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_RMDIR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_readlink) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_READLINK;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->path);
    //event.data.generic.arg1 = (u64)args->bufsiz;
    event.data.proc.flags = (u32)args->bufsiz;
   
   
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_readlinkat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_READLINKAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->dfd;
    event.data.generic.arg2 = (u64)args->bufsiz;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_truncate) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_TRUNCATE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->path);
    event.data.generic.arg1 = (u64)args->length;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FTRUNCATE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->length;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fcntl) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FCNTL;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->cmd;
    event.data.generic.arg3 = (u32)args->arg;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}



TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_CHDIR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fchdir) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FCHDIR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendfile64) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SENDFILE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->out_fd;
    event.data.generic.arg2 = (u64)args->in_fd;
    event.data.generic.arg3 = (u32)args->count;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_dup) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_DUP;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fildes;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_DUP2;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->oldfd;
    event.data.generic.arg2 = (u64)args->newfd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup3) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_DUP3;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->oldfd;
    event.data.generic.arg2 = (u64)args->newfd;
    event.data.generic.arg3 = (u32)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_getcwd) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETCWD;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->size;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_lseek) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_LSEEK;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->offset;
    event.data.generic.arg3 = (u32)args->whence;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_CLOSE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    
    // Clean up fd mapping after submitting event
    u64 fd_key = ((u64)pid << 32) | (u32)args->fd;
    fd_paths.delete(&fd_key);
    
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    long fd = args->ret;
    if (fd < 0) {
        u64 temp_key = ((u64)pid << 32) | tid;
        fd_paths.delete(&temp_key);
        return 0;
    }
    
    u64 temp_key = ((u64)pid << 32) | tid;
    struct fd_info *info = fd_paths.lookup(&temp_key);
    
    if (info != NULL) {
        u64 fd_key = ((u64)pid << 32) | (u32)fd;
        fd_paths.update(&fd_key, info);
        fd_paths.delete(&temp_key);
    }
    
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_setxattr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SETXATTR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    event.data.generic.arg1 = (u64)args->size;
    event.data.generic.arg2 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_lsetxattr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_LSETXATTR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    event.data.generic.arg1 = (u64)args->size;
    event.data.generic.arg2 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fsetxattr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FSETXATTR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->size;
    event.data.generic.arg3 = (u32)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_removexattr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_REMOVEXATTR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_lremovexattr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_LREMOVEXATTR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->pathname);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fremovexattr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FREMOVEXATTR;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


// -------------------------------------------// Network Operations //-------------------------------------------//

TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SOCKET;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Store raw values - no formatting
    event.data.net.family = (u8)args->family;
    event.data.net.sock_type = (u8)(args->type & 0xF);  // Remove flags
    event.data.generic.arg3 = (u32)args->protocol;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}




TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_BIND;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), (void *)args->umyaddr);
    event.data.net.family = (u8)family;
    
    if (family == 2) {  // AF_INET
        struct sockaddr_in {
            u16 sin_family;
            u16 sin_port;
            u32 s_addr;
            char sin_zero[8];
        };
        
        struct sockaddr_in addr;
        bpf_probe_read_user(&addr, sizeof(addr), (void *)args->umyaddr);
        
        event.data.net.ip_addr = addr.s_addr;
        event.data.net.port = addr.sin_port;
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_listen) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_LISTEN;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->backlog;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}





TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_ACCEPT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_ACCEPT4;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    if (!should_trace(pid, tid)) return 0;

    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_CONNECT;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), (void *)args->uservaddr);
    event.data.net.family = (u8)family;

    if (family == 2 /* AF_INET */) {
        struct sockaddr_in {
            u16 sin_family;
            u16 sin_port;   /* network order */
            u32 s_addr;     /* network order */
            char sin_zero[8];
        } a4 = {};
        bpf_probe_read_user(&a4, sizeof(a4), (void *)args->uservaddr);

        event.data.net.ip_addr = bpf_ntohl(a4.s_addr);
        event.data.net.port    = bpf_ntohs(a4.sin_port);
    } else if (family == 10 /* AF_INET6 */) {
        struct sockaddr_in6 {
            u16 sin6_family;
            u16 sin6_port;      /* network order */
            u32 sin6_flowinfo;
            u8  sin6_addr[16];  /* raw bytes */
            u32 sin6_scope_id;
        } a6 = {};
        bpf_probe_read_user(&a6, sizeof(a6), (void *)args->uservaddr);

        event.data.net.port = bpf_ntohs(a6.sin6_port);
        __builtin_memcpy(event.data.net.ip6, a6.sin6_addr, 16);
    }

    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// For sendto - capture outgoing message content
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = 70;  // OP_SENDTO
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->len;
    event.data.generic.arg3 = (u64)args->flags;
    
    // Capture message content
    if (args->buff && args->len > 0) {
        u64 copy_len = args->len < 63 ? args->len : 63;
        bpf_probe_read_user_str(&event.data.file.path, 
                                sizeof(event.data.file.path),
                                (void *)args->buff);
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = 71;  // OP_SENDMSG
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->flags;
    
    struct user_msghdr msg = {};
    if (args->msg) {
        bpf_probe_read_user(&msg, sizeof(msg), (void *)args->msg);
        
        if (msg.msg_iov && msg.msg_iovlen > 0) {
            struct iovec iov = {};
            bpf_probe_read_user(&iov, sizeof(iov), msg.msg_iov);
            
            if (iov.iov_base && iov.iov_len > 0) {
                u64 copy_len = iov.iov_len < 63 ? iov.iov_len : 63;
                bpf_probe_read_user_str(&event.data.file.path,
                                        sizeof(event.data.file.path),
                                        iov.iov_base);
                event.data.generic.arg3 = iov.iov_len;
            }
        }
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// ========== RECVFROM ENTER ==========
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u32 tid = bpf_get_current_pid_tgid();
    
    struct syscall_data data = {};
    data.fd = args->fd;
    data.buff_ptr = (u64)args->ubuf;
    data.flags = args->flags;
    syscall_args.update(&tid, &data);
    
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    long ret = (long)args->ret;
    if (ret <= 0) return 0;
    
    struct syscall_data *data = syscall_args.lookup(&tid);
    if (!data) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = 72;  // OP_RECVFROM
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = data->fd;
    event.data.generic.arg2 = (u64)ret;  // Actual bytes received
    event.data.generic.arg3 = data->flags;
    
    // Capture received content
    if (data->buff_ptr && ret > 0) {
        u64 copy_len = ret < 63 ? ret : 63;
        bpf_probe_read_user_str(&event.data.file.path,
                                sizeof(event.data.file.path),
                                (void *)data->buff_ptr);
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    
    syscall_args.delete(&tid);
    return 0;
}

// ========== RECVMSG ENTER - Fixed ==========
TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct syscall_data data = {};
    data.fd = (u64)args->fd;  // Make sure to cast properly
    data.msg_ptr = (u64)args->msg;
    data.flags = (u64)args->flags;
    syscall_args.update(&tid, &data);
    
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    long ret = (long)args->ret;
    if (ret <= 0) return 0;
    
    struct syscall_data *data = syscall_args.lookup(&tid);
    if (!data) {
        // If we don't have stored data, still report the event
        struct threat_event event = {};
        event.pid = pid;
        event.tid = tid;
        event.timestamp = bpf_ktime_get_ns();
        event.operation_id = 73;  // OP_RECVMSG
        
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        
        // We don't have fd, so mark it as unknown
        event.data.generic.arg1 = 0xFFFFFFFF;  // Invalid fd marker
        event.data.generic.arg2 = 0;
        event.data.generic.arg3 = (u64)ret;
        
        event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
        copy_correlation_context(&event, tid);
        events.perf_submit(args, &event, sizeof(event));
        return 0;
    }
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = 73;  // OP_RECVMSG
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = data->fd;  // This should now be correct
    event.data.generic.arg2 = data->flags;
    event.data.generic.arg3 = (u64)ret;  // Actual bytes received
    
    // Read user_msghdr to get buffer location
    struct user_msghdr msg = {};
    if (data->msg_ptr) {
        bpf_probe_read_user(&msg, sizeof(msg), (void *)data->msg_ptr);
        
        // Capture received data from first iovec
        if (msg.msg_iov && msg.msg_iovlen > 0 && ret > 0) {
            struct iovec iov = {};
            bpf_probe_read_user(&iov, sizeof(iov), msg.msg_iov);
            
            if (iov.iov_base) {
                u64 copy_len = ret < 63 ? ret : 63;
                bpf_probe_read_user_str(&event.data.file.path,
                                        sizeof(event.data.file.path),
                                        iov.iov_base);
            }
        }
    }
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    
    syscall_args.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getsockname) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETSOCKNAME;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getpeername) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETPEERNAME;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getsockopt) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETSOCKOPT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->level;
    event.data.generic.arg3 = (u32)args->optname;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setsockopt) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SETSOCKOPT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->level;
    event.data.generic.arg3 = (u32)args->optname;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_fork) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_FORK;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vfork) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_VFORK;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_CLONE;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   event.data.proc.flags = (u32)(args->clone_flags & 0xFFFFFFFF);
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone3) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_CLONE3;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}




TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PTRACE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->request;  // PTRACE_* request
    event.data.generic.arg2 = (u64)args->pid;      // Target PID
    event.data.generic.arg3 = (u32)args->addr;     // Address (truncated)
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setsid) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SETSID;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// -------------------------------------------// Memory Operations //-------------------------------------------//

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MMAP;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Store mmap parameters
    event.data.generic.arg1 = (u64)args->addr;  // Requested address
    event.data.generic.arg2 = (u64)args->len;   // Length
    event.data.generic.arg3 = (u32)args->prot;  // Protection flags
    event.data.proc.flags = (u32)args->flags;   // MAP_* flags
    
    
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MPROTECT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->start;  // Changed from addr to start
    event.data.generic.arg2 = (u64)args->len;    // Length
    event.data.generic.arg3 = (u32)args->prot;   // New protection
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MEMFD_CREATE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get the name
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->uname);
    event.data.generic.arg1 = (u64)args->flags;  // MFD_* flags
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// -------------------------------------------// Permission Operations //-------------------------------------------//
TRACEPOINT_PROBE(syscalls, sys_enter_getuid) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETUID;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_geteuid) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETEUID;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getgid) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETGID;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getegid) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETEGID;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_getgroups) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_GETGROUPS;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->gidsetsize;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_SETUID;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   event.data.proc.uid = (u32)args->uid;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_SETGID;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   event.data.proc.gid = (u32)args->gid;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setreuid) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_SETREUID;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   event.data.proc.uid = (u32)args->ruid;
   event.data.proc.gid = (u32)args->euid;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setresuid) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_SETRESUID;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   // Pack ruid, euid, suid into available fields
   event.data.proc.uid = (u32)args->ruid;
   event.data.proc.gid = (u32)args->euid;
   event.data.proc.flags = (u32)args->suid;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setregid) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_SETREGID;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   event.data.proc.uid = (u32)args->rgid;
   event.data.proc.gid = (u32)args->egid;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setresgid) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_SETRESGID;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   // Pack rgid, egid, sgid into available fields
   event.data.proc.uid = (u32)args->rgid;
   event.data.proc.gid = (u32)args->egid;
   event.data.proc.flags = (u32)args->sgid;
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_setgroups) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SETGROUPS;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->gidsetsize;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_capset) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_CAPSET;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


// -------------------------------------------// Code Execution Operations //-------------------------------------------//

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_EXECVE;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u32 tid = bpf_get_current_pid_tgid();
   
   if (!should_trace(pid, tid)) return 0;
   
   struct threat_event event = {};
   event.pid = pid;
   event.tid = tid;
   event.timestamp = bpf_ktime_get_ns();
   event.operation_id = OP_EXECVEAT;
   
   bpf_get_current_comm(&event.comm, sizeof(event.comm));
   
   event.data.generic.arg1 = (u64)args->fd;
   bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
   
   event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
   copy_correlation_context(&event, tid);
   events.perf_submit(args, &event, sizeof(event));
   return 0;
}

/*
TRACEPOINT_PROBE(syscalls, sys_enter_fexecve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FEXECVE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
*/
// -------------------------------------------// Extra OPerations //-------------------------------------------//

TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_readv) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PROCESS_VM_READV;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->pid;    // Target PID
    event.data.generic.arg2 = (u64)args->liovcnt;  // Local iovec count
    event.data.generic.arg3 = (u32)args->riovcnt;  // Remote iovec count
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_process_vm_writev) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PROCESS_VM_WRITEV;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->pid;      // Target PID
    event.data.generic.arg2 = (u64)args->liovcnt;  // Local iovec count
    event.data.generic.arg3 = (u32)args->riovcnt;  // Remote iovec count
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_KILL;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->pid;  // Target PID
    event.data.generic.arg2 = (u64)args->sig;  // Signal number
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tkill) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_TKILL;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->pid;  // Changed from tid to pid (it's actually the target TID despite the name)
    event.data.generic.arg2 = (u64)args->sig;  // Signal number
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tgkill) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_TGKILL;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->tgid;  // Thread group ID
    event.data.generic.arg2 = (u64)args->pid;   // Changed from tid to pid (target TID)
    event.data.generic.arg3 = (u32)args->sig;   // Signal number
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_init_module) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_INIT_MODULE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->umod;  // Module image
    event.data.generic.arg2 = (u64)args->len;   // Module length
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_finit_module) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FINIT_MODULE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;     // File descriptor
    event.data.generic.arg3 = (u32)args->flags;  // Module flags
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_delete_module) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_DELETE_MODULE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->name_user);
    event.data.generic.arg1 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bpf) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_BPF;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->cmd;  // BPF command
    event.data.generic.arg2 = (u64)args->uattr;  // Attributes
    event.data.generic.arg3 = (u32)args->size;   // Size
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MOUNT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
   
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->dir_name);

    event.data.proc.flags = (u32)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_umount) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_UMOUNT2;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->name);
    event.data.generic.arg1 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pivot_root) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PIVOT_ROOT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->new_root);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chroot) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_CHROOT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_prctl) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PRCTL;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->option;
    event.data.generic.arg2 = (u64)args->arg2;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_seccomp) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SECCOMP;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->op;
    event.data.generic.arg2 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setns) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SETNS;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    event.data.generic.arg2 = (u64)args->flags;
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unshare) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_UNSHARE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.data.generic.arg1 = (u64)args->unshare_flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknod) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MKNOD;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    event.data.generic.arg1 = (u64)args->mode;
    event.data.generic.arg2 = (u64)args->dev;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknodat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MKNODAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->dfd;
    event.data.generic.arg2 = (u64)args->mode;
    event.data.generic.arg3 = (u32)args->dev;
    bpf_probe_read_user_str(event.data.file.path, sizeof(event.data.file.path), (void *)args->filename);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_fallocate) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_FALLOCATE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->mode;
    // Store offset and len in limited space
    event.data.generic.arg3 = (u32)(args->len & 0xFFFFFFFF);
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_copy_file_range) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_COPY_FILE_RANGE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd_in;
    event.data.generic.arg2 = (u64)args->fd_out;
    event.data.generic.arg3 = (u32)args->len;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_pipe) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PIPE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pipe2) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PIPE2;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_splice) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SPLICE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd_in;
    event.data.generic.arg2 = (u64)args->fd_out;
    event.data.generic.arg3 = (u32)args->len;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tee) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_TEE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fdin;
    event.data.generic.arg2 = (u64)args->fdout;
    event.data.generic.arg3 = (u32)args->len;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_vmsplice) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_VMSPLICE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->fd;
    event.data.generic.arg2 = (u64)args->nr_segs;
    event.data.generic.arg3 = (u32)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_shmget) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SHMGET;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->key;
    event.data.generic.arg2 = (u64)args->size;
    event.data.generic.arg3 = (u32)args->shmflg;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_shmat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_SHMAT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->shmid;
    event.data.generic.arg2 = (u64)args->shmaddr;
    event.data.generic.arg3 = (u32)args->shmflg;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_perf_event_open) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PERF_EVENT_OPEN;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->pid;
    event.data.generic.arg2 = (u64)args->cpu;
    event.data.generic.arg3 = (u32)args->group_fd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_personality) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_PERSONALITY;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->personality;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_madvise) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_MADVISE;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->start;
    event.data.generic.arg2 = (u64)args->len_in;
    event.data.generic.arg3 = (u32)args->behavior;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_userfaultfd) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_USERFAULTFD;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->flags;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_reboot) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_REBOOT;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->magic1;
    event.data.generic.arg2 = (u64)args->magic2;
    event.data.generic.arg3 = (u32)args->cmd;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_iopl) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_IOPL;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->level;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_ioperm) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    if (!should_trace(pid, tid)) return 0;
    
    struct threat_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp = bpf_ktime_get_ns();
    event.operation_id = OP_IOPERM;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.data.generic.arg1 = (u64)args->from;
    event.data.generic.arg2 = (u64)args->num;
    event.data.generic.arg3 = (u32)args->turn_on;
    
    event.user_stack_id = stack_traces.get_stackid(args, BPF_F_USER_STACK);
    copy_correlation_context(&event, tid);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    // Only process if parent is tracked
    if (!should_trace(pid, tid)) return 0;
    
    // The return value contains the child PID/TID
    long ret = args->ret;
    if (ret <= 0) return 0;  // Clone failed or invalid
    
    u32 child_pid = (u32)ret;
    
    // Add child process to target_pids for tracking
    u8 val = 1;
    target_pids.update(&child_pid, &val);
    
    // Also track as a model thread
    u64 timestamp = bpf_ktime_get_ns();
    model_threads.update(&child_pid, &timestamp);
    
    // Propagate correlation context to child
    struct correlation_info *parent_ctx = thread_context.lookup(&tid);
    if (parent_ctx) {
        thread_context.update(&child_pid, parent_ctx);
        
        // Log the child creation
        struct thread_event tevent = {};
        tevent.parent_pid = pid;
        tevent.parent_tid = tid;
        tevent.child_pid = child_pid;  // Note: using child_pid field
        tevent.child_tid = child_pid;  // For processes, PID == TID initially
        tevent.timestamp = timestamp;
        bpf_get_current_comm(&tevent.comm, sizeof(tevent.comm));
        
        // Copy parent correlation
        __builtin_memcpy(tevent.parent_correlation_id, 
                        parent_ctx->correlation_id, 16);
        tevent.parent_phase = parent_ctx->phase;
        
        thread_events.perf_submit(args, &tevent, sizeof(tevent));
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fork) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    // Only process if parent is tracked
    if (!should_trace(pid, tid)) return 0;
    
    // The return value contains the child PID
    long ret = args->ret;
    if (ret <= 0) return 0;  // Fork failed or returned 0 (child's perspective)
    
    u32 child_pid = (u32)ret;
    
    // Add child process to target_pids for tracking
    u8 val = 1;
    target_pids.update(&child_pid, &val);
    
    // Also track as a model thread
    u64 timestamp = bpf_ktime_get_ns();
    model_threads.update(&child_pid, &timestamp);
    
    // Propagate correlation context to child
    struct correlation_info *parent_ctx = thread_context.lookup(&tid);
    if (parent_ctx) {
        thread_context.update(&child_pid, parent_ctx);
        
        // Log the child creation
        struct thread_event tevent = {};
        tevent.parent_pid = pid;
        tevent.parent_tid = tid;
        tevent.child_pid = child_pid;
        tevent.child_tid = child_pid;
        tevent.timestamp = timestamp;
        bpf_get_current_comm(&tevent.comm, sizeof(tevent.comm));
        
        // Copy parent correlation
        __builtin_memcpy(tevent.parent_correlation_id, 
                        parent_ctx->correlation_id, 16);
        tevent.parent_phase = parent_ctx->phase;
        
        thread_events.perf_submit(args, &tevent, sizeof(tevent));
    }
    
    return 0;
}

// Handler for when vfork() completes - captures child PID
TRACEPOINT_PROBE(syscalls, sys_exit_vfork) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    // Only process if parent is tracked
    if (!should_trace(pid, tid)) return 0;
    
    // The return value contains the child PID
    long ret = args->ret;
    if (ret <= 0) return 0;  // Vfork failed or returned 0 (child's perspective)
    
    u32 child_pid = (u32)ret;
    
    // Add child process to target_pids for tracking
    u8 val = 1;
    target_pids.update(&child_pid, &val);
    
    // Also track as a model thread
    u64 timestamp = bpf_ktime_get_ns();
    model_threads.update(&child_pid, &timestamp);
    
    // Propagate correlation context to child
    struct correlation_info *parent_ctx = thread_context.lookup(&tid);
    if (parent_ctx) {
        thread_context.update(&child_pid, parent_ctx);
        
        // Log the child creation
        struct thread_event tevent = {};
        tevent.parent_pid = pid;
        tevent.parent_tid = tid;
        tevent.child_pid = child_pid;
        tevent.child_tid = child_pid;
        tevent.timestamp = timestamp;
        bpf_get_current_comm(&tevent.comm, sizeof(tevent.comm));
        
        // Copy parent correlation
        __builtin_memcpy(tevent.parent_correlation_id, 
                        parent_ctx->correlation_id, 16);
        tevent.parent_phase = parent_ctx->phase;
        
        thread_events.perf_submit(args, &tevent, sizeof(tevent));
    }
    
    return 0;
}

// Handler for clone3 exit (newer clone variant)
TRACEPOINT_PROBE(syscalls, sys_exit_clone3) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    // Only process if parent is tracked
    if (!should_trace(pid, tid)) return 0;
    
    // The return value contains the child PID/TID
    long ret = args->ret;
    if (ret <= 0) return 0;  // Clone3 failed or returned 0 (child's perspective)
    
    u32 child_pid = (u32)ret;
    
    // Add child process to target_pids for tracking
    u8 val = 1;
    target_pids.update(&child_pid, &val);
    
    // Also track as a model thread
    u64 timestamp = bpf_ktime_get_ns();
    model_threads.update(&child_pid, &timestamp);
    
    // Propagate correlation context to child
    struct correlation_info *parent_ctx = thread_context.lookup(&tid);
    if (parent_ctx) {
        thread_context.update(&child_pid, parent_ctx);
        
        // Log the child creation
        struct thread_event tevent = {};
        tevent.parent_pid = pid;
        tevent.parent_tid = tid;
        tevent.child_pid = child_pid;
        tevent.child_tid = child_pid;
        tevent.timestamp = timestamp;
        bpf_get_current_comm(&tevent.comm, sizeof(tevent.comm));
        
        // Copy parent correlation
        __builtin_memcpy(tevent.parent_correlation_id, 
                        parent_ctx->correlation_id, 16);
        tevent.parent_phase = parent_ctx->phase;
        
        thread_events.perf_submit(args, &tevent, sizeof(tevent));
    }
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    long ret = args->ret;
    
    // Check if already tracked
    u8 *already_tracked = target_pids.lookup(&pid);
    if (already_tracked != NULL) {
        u64 timestamp = bpf_ktime_get_ns();
        model_threads.update(&tid, &timestamp);
        return 0;
    }
    
    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    
    u8 *parent_tracked = target_pids.lookup(&ppid);
    if (parent_tracked != NULL) {
        // Add child to tracking
        u8 val = 1;
        target_pids.update(&pid, &val);
        
        u64 timestamp = bpf_ktime_get_ns();
        model_threads.update(&tid, &timestamp);
        
        // Propagate correlation context
        struct correlation_info *parent_ctx = thread_context.lookup(&ppid);
        if (parent_ctx) {
            // INITIALIZE ENTIRE STRUCT TO ZERO FIRST
            struct correlation_info child_ctx = {};  // ← THIS IS CRITICAL
            
            // Now copy data
            __builtin_memcpy(child_ctx.correlation_id, 
                           parent_ctx->correlation_id, 16);
            child_ctx.phase = parent_ctx->phase;
            child_ctx.start_time = timestamp;
            
            thread_context.update(&tid, &child_ctx);
            
            // Log thread event
            struct thread_event tevent = {};
            tevent.parent_pid = ppid;
            tevent.parent_tid = ppid;
            tevent.child_pid = pid;
            tevent.child_tid = tid;
            tevent.timestamp = timestamp;
            bpf_get_current_comm(&tevent.comm, sizeof(tevent.comm));
            
            __builtin_memcpy(tevent.parent_correlation_id, 
                           parent_ctx->correlation_id, 16);
            tevent.parent_phase = parent_ctx->phase;
            
            thread_events.perf_submit(args, &tevent, sizeof(tevent));
        }
    }
    
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_exit_execveat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    long ret = args->ret;
    
    u8 *already_tracked = target_pids.lookup(&pid);
    if (already_tracked != NULL) {
        u64 timestamp = bpf_ktime_get_ns();
        model_threads.update(&tid, &timestamp);
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    
    u8 *parent_tracked = target_pids.lookup(&ppid);
    if (parent_tracked != NULL) {
        u8 val = 1;
        target_pids.update(&pid, &val);
        
        u64 timestamp = bpf_ktime_get_ns();
        model_threads.update(&tid, &timestamp);
        
        struct correlation_info *parent_ctx = thread_context.lookup(&ppid);
        if (parent_ctx) {
            struct correlation_info child_ctx = {};  // ← INITIALIZE
            
            __builtin_memcpy(child_ctx.correlation_id, 
                           parent_ctx->correlation_id, 16);
            child_ctx.phase = parent_ctx->phase;
            child_ctx.start_time = timestamp;
            
            thread_context.update(&tid, &child_ctx);
        }
    }
    
    return 0;
}
