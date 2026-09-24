export const COMMON = {
    AF_INET6: 28,
    IPPROTO_IPV6: 41,
    IPV6_RTHDR: 51,
    IP6_RTHDR0_SIZE: 8,
    IN6_ADDR_SIZE: 0x10,
    SOL_SOCKET: 0xffff,
    RTP: 0x100,
    RTP_SET: 1,
    RTP_PRIO_REALTIME: 2,
    MAIN_CORE: 7,
    CPU_LEVEL_WHICH: 3,
    CPU_WHICH_TID: 1,
    JSVALUE_UNDEFINED: 0xa,
};

/* LAPSE_SYS -- the Internet Browser's syscall set.
 *
 * lapse.js runs inside the browser (libkernel_web.sprx), NOT a userland app
 * (libkernel.sprx), so this table must list ONLY syscalls whose stubs exist
 * in libkernel_web. lapth-vue.js's table was transcribed from a full
 * libkernel build and carried entries the web image does not expose
 * (getpeername, thr_new, thr_exit, dup, sendmsg, recvmsg); demanding those
 * aborted the primitive before any work began.
 *
 * Every entry below is CALLED by lapse.js. pipe/mmap/jitshm_create/kexec are
 * confirmed present in libkernel_web -- netctrl drives all four and works
 * end to end. getsockname and is_in_sandbox are called by lapse's TCP
 * listener and jailbreak proof respectively; if either is absent in a given
 * web image, the stage-1 REQUIRED_STUBS gate now reports it by name instead
 * of silently aborting. */
export const LAPSE_SYS = {
    read: 3, write: 4, close: 6, getpid: 20, setuid: 23, getuid: 24,
    geteuid: 25, open: 5, accept: 30, socket: 97, connect: 98, bind: 104,
    getsockname: 32, setsockopt: 105, listen: 106, getsockopt: 118,
    socketpair: 135, nanosleep: 240, sched_yield: 331, thr_self: 432,
    rtprio_thread: 466, fcntl: 92, ioctl: 54, pipe: 42,
    evf_create: 538, evf_delete: 539, evf_set: 544, evf_clear: 545,
    cpuset_getaffinity: 487, cpuset_setaffinity: 488,
    aio_multi_delete: 662, aio_multi_wait: 663, aio_multi_poll: 664,
    aio_multi_cancel: 666, aio_submit_cmd: 669,
    mmap: 477, jitshm_create: 533, kexec: 661, is_in_sandbox: 585,
    /* The reference's race_one is a SUSPEND/RESUME race (lapse-vue.js:392,
       520). These two were previously believed absent from libkernel_web --
       they are NOT: the bare syscall probe found both as plain syscall
       stubs (632 @ libkernel+0x2b270, 633 @ libkernel+0x2bf50 on 11.00). An
       earlier discoverStubs bug (extra map pushed names, not numbers) made
       them read as "none". thr_exit is the reference thread's last call. */
    thr_suspend_ucontext: 632, thr_resume_ucontext: 633, thr_exit: 431,
};

export const NETCTRL_SYS = {
    read: 3, write: 4, close: 6, getpid: 20, setuid: 0x17, getuid: 0x18,
    geteuid: 0x19, dup: 0x29, sendmsg: 0x1c, recvmsg: 0x1b,
    socket: 0x61, netcontrol: 0x63, socketpair: 0x87, kqueue: 0x16a,
    readv: 0x78, writev: 0x79, sysctl: 0xca, pipe: 0x2a, fcntl: 0x5c,
    setsockopt: 0x69, getsockopt: 0x76, sched_yield: 0x14b,
    rtprio_thread: 0x1d2, cpuset_setaffinity: 0x1e8,
    cpuset_getaffinity: 0x1e7, thr_self: 432, ioctl: 0x36,
    mmap: 0x1dd, jitshm_create: 0x215, kexec: 0x295,
    // FreeBSD thread control. thr_kill is used by the teardown to hard-kill a
    // worker's kernel thread when its ROP gate is wedged; thr_exit lets a
    // worker retire itself. Both were in the vue reference and were missing here.
    thr_kill: 0x1b1, thr_exit: 0x1af,
};

export const NETCTRL = {
    AF_UNIX: 1,
    SOCK_STREAM: 1,
    UCRED_SIZE: 0x168,
    KQUEUE_SIZE: 0x100,
    NUM_UIO_IOV: 0x14,
    UIO_SIZE: 0x30,
    IP6_RTHDR0_SIZE: 8,
    IN6_ADDR_SIZE: 0x10,
    IOVEC_SIZE: 0x10,
    MSGHDR_SIZE: 0x30,
    NUM_MSG_IOV: 0x17,
};

/* RELAPSE_SYS -- the syscall set relapse.js drives.
 *
 * relapse is the `_aio_multi_wait` chain (src/kernel_bug/sys_aio_multi_wait.c),
 * NOT the `_aio_multi_delete` chain lapse.js owns. But that is a statement about
 * the BUG, not about which syscalls the chain issues -- relapse's own transcribed
 * body really does call aio_multi_delete, in two places:
 *
 *   PR-REAPLEAK   cancel + poll + delete, retiring the leak batch
 *   reapNow()     cancel + poll + delete, retiring a pass's batch
 *
 * Those are batch-retirement calls on the SAME ids relapse submitted. They are
 * NOT lapse's double-free -- lapse's bug IS _aio_multi_delete's own internal
 * queue_ent[] handling, reached by racing a thread parked inside it. Issuing the
 * syscall is not the same as being that bug, and this table only lists what gets
 * called. Do not "clean" 662 out of here on the strength of the bug names; the
 * chain needs it.
 *
 * discoverStubs() reports any missing entry by name rather than letting the
 * chain fault on a null stub.
 */
export const RELAPSE_SYS = {
    getpid: 20, getuid: 24, geteuid: 25, close: 6,
    socket: 97, socketpair: 135, setsockopt: 105, getsockopt: 118,
    sysctl: 202,
    mmap: 477, munmap: 73, thr_self: 432, getgroups: 79, getgid: 47,
    cpuset_getaffinity: 487, cpuset_setaffinity: 488,
    aio_multi_delete: 662, aio_multi_wait: 663, aio_multi_poll: 664,
    aio_multi_cancel: 666, aio_submit_cmd: 669,
    getegid: 43, kill: 37, getppid: 39,
};

/* Constants relapse shares with netctrl's netcontrol/ucred work. Only the ones
 * relapse reads are listed; UCRED_SIZE is the rthdr spray length lapse/netctrl
 * both build, and relapse uses the same 0x48 IP6_RTHDR0 header. */
export const RELAPSE = {
    AF_UNIX: 1,
    SOCK_STREAM: 1,
    IP6_RTHDR0_SIZE: 8,
    IN6_ADDR_SIZE: 0x10,
    UCRED_SIZE: 0x168,
    CPU_LEVEL_WHICH: 3,
    CPU_WHICH_TID: 1,
};
