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
#define PROX_FDTYPE_ATALK       8
#define PROX_FDTYPE_NETPOLICY   9
#endif

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

extern kern_return_t mach_zone_info(
    host_priv_t host,
    mach_zone_name_t **names, mach_msg_type_number_t *namesCnt,
    mach_zone_info_t **info, mach_msg_type_number_t *infoCnt
);

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
