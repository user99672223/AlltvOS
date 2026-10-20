#ifndef TVOSRecon_Bridging_Header_h
#define TVOSRecon_Bridging_Header_h

#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#if __has_include(<sys/shm.h>)
#include <sys/shm.h>
#endif
#if __has_include(<sys/sem.h>)
#include <sys/sem.h>
#endif
#if __has_include(<sys/msg.h>)
#include <sys/msg.h>
#endif
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/attr.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/errno.h>

#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_host.h>
#include <mach/mach_port.h>
#include <mach/mach_time.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/host_info.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <mach/processor_set.h>
#include <mach/clock.h>
#include <mach/clock_types.h>
#include <mach/exception_types.h>
#include <mach/machine.h>
#include <mach/thread_policy.h>
#include <mach/vm_prot.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>

#include <dlfcn.h>
#include <objc/runtime.h>
#include <objc/message.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>

// net/route.h is unavailable in the tvOS SDK; define routing constants manually
#ifndef NET_RT_DUMP
#define NET_RT_DUMP     1
#define NET_RT_FLAGS    2
#define NET_RT_IFLIST   3
#endif
#ifndef AF_ROUTE
#define AF_ROUTE        17
#endif
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#if __has_include(<resolv.h>)
#include <resolv.h>
#endif
#include <spawn.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <fts.h>
#include <glob.h>

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <Security/Security.h>

#if __has_include(<xpc/xpc.h>)
#include <xpc/xpc.h>
#endif
#if __has_include(<bsm/libbsm.h>)
#include <bsm/libbsm.h>
#endif
#if __has_include(<asl.h>)
#include <asl.h>
#endif

// MARK: - proc functions (libproc.h may not declare all of them for tvOS)
extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
extern int proc_pidfdinfo(int pid, int fd, int flavor, void *buffer, int buffersize);
extern int proc_name(int pid, void *buffer, uint32_t buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

// MARK: - proc_info constants
#ifndef PROC_PIDTBSDINFO
#define PROC_PIDTBSDINFO        3
#endif
#ifndef PROC_PIDTASKINFO
#define PROC_PIDTASKINFO        4
#endif
#ifndef PROC_PIDLISTFDS
#define PROC_PIDLISTFDS         1
#endif
#ifndef PROC_PIDTASKALLINFO
#define PROC_PIDTASKALLINFO     2
#endif

// MARK: - fd types
#ifndef PROX_FDTYPE_VNODE
#define PROX_FDTYPE_VNODE       1
#define PROX_FDTYPE_SOCKET      2
#define PROX_FDTYPE_PSHM        3
#define PROX_FDTYPE_PSEM        4
#define PROX_FDTYPE_KQUEUE      5
#define PROX_FDTYPE_PIPE        6
#define PROX_FDTYPE_FSEVENTS    7
#define PROX_FDTYPE_ATALK       0
#define PROX_FDTYPE_NETPOLICY   9
#endif

// MARK: - libproc structs and flavors (absent from the tvOS SDK)
// Mirrors XNU bsd/sys/proc_info.h. ProcessEnumerationModule compares the byte
// count returned for PROC_PIDTBSDINFO and PROC_PIDTASKINFO against
// MemoryLayout<T>.size, so those two layouts must be exact, as must the fd-info
// layouts whose fields are read. socket_info's protocol union is not modelled:
// it is padded well past the kernel's struct so the copy-out always fits, and
// only the leading fields are read.
#ifndef MAXCOMLEN
#define MAXCOMLEN                16
#endif
#ifndef MAXPATHLEN
#define MAXPATHLEN               1024
#endif
#ifndef PROC_PIDPATHINFO_MAXSIZE
#define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)
#endif
#ifndef PROC_PIDFDVNODEPATHINFO
#define PROC_PIDFDVNODEPATHINFO  2
#endif
#ifndef PROC_PIDFDSOCKETINFO
#define PROC_PIDFDSOCKETINFO     3
#endif
#ifndef PROC_PIDFDPIPEINFO
#define PROC_PIDFDPIPEINFO       6
#endif

struct proc_bsdinfo {
    uint32_t pbi_flags;
    uint32_t pbi_status;
    uint32_t pbi_xstatus;
    uint32_t pbi_pid;
    uint32_t pbi_ppid;
    uid_t    pbi_uid;
    gid_t    pbi_gid;
    uid_t    pbi_ruid;
    gid_t    pbi_rgid;
    uid_t    pbi_svuid;
    gid_t    pbi_svgid;
    uint32_t rfu_1;
    char     pbi_comm[MAXCOMLEN];
    char     pbi_name[2 * MAXCOMLEN];
    uint32_t pbi_nfiles;
    uint32_t pbi_pgid;
    uint32_t pbi_pjobc;
    uint32_t e_tdev;
    uint32_t e_tpgid;
    int32_t  pbi_nice;
    uint64_t pbi_start_tvsec;
    uint64_t pbi_start_tvusec;
};

struct proc_taskinfo {
    uint64_t pti_virtual_size;
    uint64_t pti_resident_size;
    uint64_t pti_total_user;
    uint64_t pti_total_system;
    uint64_t pti_threads_user;
    uint64_t pti_threads_system;
    int32_t  pti_policy;
    int32_t  pti_faults;
    int32_t  pti_pageins;
    int32_t  pti_cow_faults;
    int32_t  pti_messages_sent;
    int32_t  pti_messages_received;
    int32_t  pti_syscalls_mach;
    int32_t  pti_syscalls_unix;
    int32_t  pti_csw;
    int32_t  pti_threadnum;
    int32_t  pti_numrunning;
    int32_t  pti_priority;
};

struct proc_fdinfo {
    int32_t  proc_fd;
    uint32_t proc_fdtype;
};

struct proc_fileinfo {
    uint32_t fi_openflags;
    uint32_t fi_status;
    off_t    fi_offset;
    int32_t  fi_type;
    uint32_t fi_guardflags;
};

struct vinfo_stat {
    uint32_t vst_dev;
    uint16_t vst_mode;
    uint16_t vst_nlink;
    uint64_t vst_ino;
    uid_t    vst_uid;
    gid_t    vst_gid;
    int64_t  vst_atime;
    int64_t  vst_atimensec;
    int64_t  vst_mtime;
    int64_t  vst_mtimensec;
    int64_t  vst_ctime;
    int64_t  vst_ctimensec;
    int64_t  vst_birthtime;
    int64_t  vst_birthtimensec;
    off_t    vst_size;
    int64_t  vst_blocks;
    int32_t  vst_blksize;
    uint32_t vst_flags;
    uint32_t vst_gen;
    uint32_t vst_rdev;
    int64_t  vst_qspare[2];
};

struct vnode_info {
    struct vinfo_stat vi_stat;
    int               vi_type;
    int               vi_pad;
    fsid_t            vi_fsid;
};

struct vnode_info_path {
    struct vnode_info vip_vi;
    char              vip_path[MAXPATHLEN];
};

struct vnode_fdinfowithpath {
    struct proc_fileinfo   pfi;
    struct vnode_info_path pvip;
};

struct sockbuf_info {
    uint32_t sbi_cc;
    uint32_t sbi_hiwat;
    uint32_t sbi_mbcnt;
    uint32_t sbi_mbmax;
    uint32_t sbi_lowat;
    int16_t  sbi_flags;
    int16_t  sbi_timeo;
};

struct socket_info {
    struct vinfo_stat   soi_stat;
    uint64_t            soi_so;
    uint64_t            soi_pcb;
    int                 soi_type;
    int                 soi_protocol;
    int                 soi_family;
    int16_t             soi_options;
    int16_t             soi_linger;
    int16_t             soi_state;
    int16_t             soi_qlen;
    int16_t             soi_incqlen;
    int16_t             soi_qlimit;
    int16_t             soi_timeo;
    uint16_t            soi_error;
    uint32_t            soi_oobmark;
    struct sockbuf_info soi_rcv;
    struct sockbuf_info soi_snd;
    int                 soi_kind;
    uint32_t            rfu_1;
    uint8_t             soi_proto[1024]; /* protocol-specific union: not modelled, not read */
};

struct socket_fdinfo {
    struct proc_fileinfo pfi;
    struct socket_info   psi;
};

struct pipe_info {
    struct vinfo_stat pipe_stat;
    uint64_t          pipe_handle;
    uint64_t          pipe_peerhandle;
    int               pipe_status;
    int               rfu_1;
};

struct pipe_fdinfo {
    struct proc_fileinfo pfi;
    struct pipe_info     pipeinfo;
};

// MARK: - csops
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS           0
#define CS_OPS_MARKINVALID      1
#define CS_OPS_MARKHARD         2
#define CS_OPS_MARKKILL         3
#define CS_OPS_ENTITLEMENTS_BLOB 7
#define CS_OPS_CLEARINSTALLER   9
#define CS_OPS_SET_STATUS       14
#endif

// CS flags
#ifndef CS_VALID
#define CS_VALID                0x00000001
#define CS_GET_TASK_ALLOW       0x00000004
#define CS_INSTALLER            0x00000008
#define CS_HARD                 0x00000100
#define CS_KILL                 0x00000200
#define CS_RESTRICT             0x00000800
#define CS_ENFORCEMENT          0x00001000
#define CS_REQUIRE_LV           0x00002000
#define CS_PLATFORM_BINARY      0x04000000
#define CS_PLATFORM_PATH        0x08000000
#define CS_DEBUGGED             0x10000000
#define CS_SIGNED               0x20000000
#define CS_DEV_CODE             0x40000000
#endif

// MARK: - bootstrap
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);

// MARK: - memorystatus
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
#ifndef MEMORYSTATUS_CMD_GET_PRIORITY_LIST
#define MEMORYSTATUS_CMD_GET_PRIORITY_LIST      1
#define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK 5
#endif

// MARK: - kas_info
extern int kas_info(int selector, void *value, size_t *size);
#ifndef KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR
#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR 0
#endif

// MARK: - sandbox private API function types
typedef int (*sandbox_check_func_t)(pid_t, const char *, int, ...);
typedef char* (*sandbox_extension_issue_file_func_t)(const char *, const char *, int);
typedef int64_t (*sandbox_extension_consume_func_t)(const char *);
typedef char* (*sandbox_container_path_for_pid_func_t)(pid_t);

// MARK: - IOKit forward declarations for dlsym usage
typedef unsigned int io_object_t;
typedef io_object_t io_iterator_t;
typedef io_object_t io_registry_entry_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef unsigned int IOOptionBits;

#ifndef kIORegistryIterateRecursively
#define kIORegistryIterateRecursively 0x00000001
#endif

#ifndef kNilOptions
#define kNilOptions 0
#endif

// MARK: - ptrace
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#ifndef PT_TRACE_ME
#define PT_TRACE_ME 0
#endif
#ifndef PT_ATTACHEXC
#define PT_ATTACHEXC 14
#endif

// MARK: - Misc
#ifndef BOOTSTRAP_MAX_NAME_LEN
#define BOOTSTRAP_MAX_NAME_LEN 128
#endif

#ifndef MNT_SNAPSHOT
#define MNT_SNAPSHOT 0x40000000
#endif

#ifndef MNT_REMOVABLE
#define MNT_REMOVABLE 0x00000020
#endif

// MARK: - task flavor aliases that might not be defined
#ifndef TASK_POWER_INFO
#define TASK_POWER_INFO 21
#endif

#ifndef TASK_FLAGS_INFO
#define TASK_FLAGS_INFO 22
#endif

// MARK: - thread state
#ifndef ARM_THREAD_STATE64
#define ARM_THREAD_STATE64 6
#endif

#ifndef ARM_NEON_STATE64
#define ARM_NEON_STATE64 17
#endif

#ifndef ARM_EXCEPTION_STATE64
#define ARM_EXCEPTION_STATE64 9
#endif

#ifndef ARM_DEBUG_STATE64
#define ARM_DEBUG_STATE64 15
#endif

// MARK: - Mach zone info
#if __has_include(<mach_debug/zone_info.h>)
#include <mach_debug/zone_info.h>
#else
typedef struct mach_zone_name {
    char mzn_name[80];
} mach_zone_name_t;

typedef struct mach_zone_info {
    uint64_t mzi_count;
    uint64_t mzi_cur_size;
    uint64_t mzi_max_size;
    uint64_t mzi_elem_size;
    uint64_t mzi_alloc_size;
    uint64_t mzi_sum_size;
    uint64_t mzi_exhaustible;
    uint64_t mzi_collectable;
} mach_zone_info_t;
#endif

#if __has_include(<mach_debug/mach_debug.h>)
#include <mach_debug/mach_debug.h>
#else
extern kern_return_t mach_zone_info(
    host_priv_t host,
    mach_zone_name_t **names, mach_msg_type_number_t *namesCnt,
    mach_zone_info_t **info, mach_msg_type_number_t *infoCnt
);
#endif

// MARK: - Variadic IPC wrappers
// shm_open and semctl are C variadic functions, so Swift imports them as unavailable.
// Calling them from C lets clang emit the real variadic call. A dlsym'd non-variadic
// pointer would not work: Apple arm64 passes variadic arguments on the stack, so `mode`
// would be passed where shm_open never reads it.
static inline int tvr_shm_open(const char *name, int oflag, mode_t mode) {
    return shm_open(name, oflag, mode);
}

#if __has_include(<sys/sem.h>)
static inline int tvr_semctl(int semid, int semnum, int cmd) {
    return semctl(semid, semnum, cmd);
}
#endif

// syscall() is explicitly unavailable on tvOS. Resolve at runtime via dlsym.
static inline int tvr_syscall0(int number) {
    typedef int (*syscall_fn_t)(int, ...);
    syscall_fn_t fn = (syscall_fn_t)dlsym(RTLD_DEFAULT, "syscall");
    if (!fn) { errno = ENOSYS; return -1; }
    return fn(number);
}
static inline int tvr_syscall3(int number, int a1, void *a2, void *a3) {
    typedef int (*syscall_fn_t)(int, ...);
    syscall_fn_t fn = (syscall_fn_t)dlsym(RTLD_DEFAULT, "syscall");
    if (!fn) { errno = ENOSYS; return -1; }
    return fn(number, a1, a2, a3);
}

// MARK: - host_get_clock_service clock IDs
#ifndef REALTIME_CLOCK
#define REALTIME_CLOCK 0
#endif
#ifndef CALENDAR_CLOCK
#define CALENDAR_CLOCK 1
#endif
#ifndef SYSTEM_CLOCK
#define SYSTEM_CLOCK 0
#endif

#endif /* TVOSRecon_Bridging_Header_h */
