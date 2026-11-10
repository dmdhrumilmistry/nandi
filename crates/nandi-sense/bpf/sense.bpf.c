// SPDX-License-Identifier: GPL-2.0-only
//
// nandi host sensor: kernel side of the eBPF backend.
//
// This BPF object is licensed under the GPL (the kernel only grants some
// helpers to GPL programs); the rest of nandi is Apache-2.0. The object is
// built by crates/nandi-sense/build.rs and loaded by src/ebpf.rs.
//
// Hooks (stable tracepoints, no CO-RE or vmlinux.h needed):
//   task/task_newtask            fork bookkeeping (parent map, watch inheritance)
//   raw_syscalls/sys_enter       execve/execveat arguments, held until...
//   sched/sched_process_exec     ...the exec succeeded, then reported
//   raw_syscalls/sys_enter       openat/openat2/open and AF_INET/AF_INET6
//                                connect by watched processes
//   sched/sched_process_exit     process exits
//
// Syscalls are hooked through the raw sys_enter tracepoint rather than the
// per-syscall syscalls/sys_enter_* events: on some kernels (7.0) the latter
// only run BPF programs after the tracing core managed to copy the
// syscall's user strings, so they silently skip events. The raw tracepoint
// has no such dependency; it costs one early-returning program run per
// syscall. Syscall numbers and argument registers are per architecture
// (x86_64 and arm64 are supported; build.rs passes __TARGET_ARCH_*).
//
// Records are fixed-size structs with a type tag, delivered through one
// BPF ring buffer. Their layout is mirrored in src/ebpf.rs; the
// _Static_asserts below pin the offsets userspace relies on.
//
// Volume control: execs and exits are reported for every process (user
// space needs them for attribution), opens and connects only for
// processes in the `watched` map. User space adds agent trees to that map
// and the kernel extends it to children forked afterwards, so short-lived
// children of a watched agent are never missed.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define PATH_LEN 256
#define ARG_LEN 128
#define MAX_ARGS 8

#define REC_EXEC 1
#define REC_OPEN 2
#define REC_CONNECT 3
#define REC_EXIT 4

#define CLONE_THREAD 0x00010000
#define AF_INET 2
#define AF_INET6 10

// Index of the own tgid in the `config` array.
#define CFG_OWN_TGID 0

// Indexes of the `stats` counters (read by user space for diagnostics).
#define STAT_EXEC_ENTER 0
#define STAT_EXEC_EMIT 1
#define STAT_DROPPED 2
#define STAT_EXEC_SEEN 3
#define STAT_EXEC_ENTER_FAIL 4
#define STAT_COUNT 8

struct hdr {
	__u32 type;
	__u32 pid; // tgid
	__u32 ppid; // parent tgid, 0 when unknown
	__u32 uid;
};

struct exec_rec {
	struct hdr h;
	char comm[TASK_COMM_LEN];
	__u32 argc; // entries captured in args (at most MAX_ARGS)
	__u32 truncated; // 1 when argv had more than MAX_ARGS entries
	char filename[PATH_LEN];
	char args[MAX_ARGS][ARG_LEN];
};

struct open_rec {
	struct hdr h;
	__s32 dfd;
	__u32 flags;
	char path[PATH_LEN];
};

struct connect_rec {
	struct hdr h;
	__u16 family;
	__u16 port; // network byte order
	__u32 _pad;
	__u8 addr[16];
};

_Static_assert(sizeof(struct hdr) == 16, "hdr layout");
_Static_assert(__builtin_offsetof(struct exec_rec, comm) == 16, "exec_rec layout");
_Static_assert(__builtin_offsetof(struct exec_rec, argc) == 32, "exec_rec layout");
_Static_assert(__builtin_offsetof(struct exec_rec, filename) == 40, "exec_rec layout");
_Static_assert(__builtin_offsetof(struct exec_rec, args) == 296, "exec_rec layout");
_Static_assert(sizeof(struct exec_rec) == 1320, "exec_rec layout");
_Static_assert(__builtin_offsetof(struct open_rec, path) == 24, "open_rec layout");
_Static_assert(sizeof(struct open_rec) == 280, "open_rec layout");
_Static_assert(__builtin_offsetof(struct connect_rec, addr) == 24, "connect_rec layout");
_Static_assert(sizeof(struct connect_rec) == 40, "connect_rec layout");

// Syscall numbers and the offsets of the first syscall arguments in
// struct pt_regs (the user registers at syscall entry).
#if defined(__TARGET_ARCH_x86)
#define NR_open 2
#define NR_connect 42
#define NR_execve 59
#define NR_openat 257
#define NR_execveat 322
#define NR_openat2 437
#define REG_ARG0 112 // di
#define REG_ARG1 104 // si
#define REG_ARG2 96 // dx
#elif defined(__TARGET_ARCH_arm64)
#define NR_openat 56
#define NR_connect 203
#define NR_execve 221
#define NR_execveat 281
#define NR_openat2 437
#define REG_ARG0 0 // regs[0]
#define REG_ARG1 8
#define REG_ARG2 16
#else
#error "unsupported architecture: define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif

#define AT_FDCWD -100

// task/task_newtask has kept this layout since it was introduced.
struct task_newtask_ctx {
	__u64 common;
	__s32 pid;
	char comm[TASK_COMM_LEN];
	__u32 _pad;
	__u64 clone_flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} events SEC(".maps");

// [CFG_OWN_TGID] = tgid of the nandi process (its own activity is ignored).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} config SEC(".maps");

// tgid -> 1 for processes in agent trees.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u8);
} watched SEC(".maps");

// child tgid -> parent tgid, for processes forked while loaded.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u32);
} parents SEC(".maps");

// Event counters, see STAT_*.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

// tgid -> exec record captured at syscall entry, reported by
// sched_process_exec once the exec succeeded. Keyed by tgid because a
// successful exec from a non-leader thread continues as the leader. Entries
// of failed execs are overwritten by the next exec or removed at exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct exec_rec);
} pending_execs SEC(".maps");

// Scratch space: an exec record is too large for the 512 byte BPF stack.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_rec);
} scratch SEC(".maps");

static __always_inline void count(__u32 stat)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &stat);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline __u32 current_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline int is_self(__u32 tgid)
{
	__u32 key = CFG_OWN_TGID;
	__u32 *own = bpf_map_lookup_elem(&config, &key);
	return own && *own == tgid;
}

static __always_inline int is_watched(__u32 tgid)
{
	return bpf_map_lookup_elem(&watched, &tgid) != 0;
}

static __always_inline __u32 parent_of(__u32 tgid)
{
	__u32 *ppid = bpf_map_lookup_elem(&parents, &tgid);
	return ppid ? *ppid : 0;
}

static __always_inline void fill_hdr(struct hdr *h, __u32 type, __u32 tgid)
{
	h->type = type;
	h->pid = tgid;
	h->ppid = parent_of(tgid);
	h->uid = (__u32)bpf_get_current_uid_gid();
}

SEC("tracepoint/task/task_newtask")
int handle_newtask(struct task_newtask_ctx *ctx)
{
	if (ctx->clone_flags & CLONE_THREAD)
		return 0;
	__u32 parent = current_tgid();
	__u32 child = (__u32)ctx->pid;
	bpf_map_update_elem(&parents, &child, &parent, BPF_ANY);
	if (is_watched(parent)) {
		__u8 one = 1;
		bpf_map_update_elem(&watched, &child, &one, BPF_ANY);
	}
	return 0;
}

static __always_inline int exec_enter(const char *filename, const char *const *argv)
{
	__u32 tgid = current_tgid();
	if (is_self(tgid))
		return 0;
	__u32 zero = 0;
	struct exec_rec *r = bpf_map_lookup_elem(&scratch, &zero);
	if (!r)
		return 0;
	r->filename[0] = 0;
	bpf_probe_read_user_str(r->filename, sizeof(r->filename), filename);
	r->argc = 0;
	r->truncated = 0;
#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *arg = 0;
		if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0 || !arg)
			goto done;
		if (bpf_probe_read_user_str(r->args[i], ARG_LEN, arg) < 0)
			goto done;
		r->argc = i + 1;
	}
	{
		const char *more = 0;
		if (bpf_probe_read_user(&more, sizeof(more), &argv[MAX_ARGS]) == 0 && more)
			r->truncated = 1;
	}
done:
	if (bpf_map_update_elem(&pending_execs, &tgid, r, BPF_ANY))
		count(STAT_EXEC_ENTER_FAIL);
	else
		count(STAT_EXEC_ENTER);
	return 0;
}

// Fires in the new image once an exec succeeded.
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
	__u32 tgid = current_tgid();
	count(STAT_EXEC_SEEN);
	struct exec_rec *r = bpf_map_lookup_elem(&pending_execs, &tgid);
	if (!r)
		return 0;
	fill_hdr(&r->h, REC_EXEC, tgid);
	bpf_get_current_comm(r->comm, sizeof(r->comm));
	// A child forked before its parent was watched joins the tree at
	// exec time.
	if (r->h.ppid && is_watched(r->h.ppid)) {
		__u8 one = 1;
		bpf_map_update_elem(&watched, &tgid, &one, BPF_ANY);
	}
	if (bpf_ringbuf_output(&events, r, sizeof(*r), 0))
		count(STAT_DROPPED);
	else
		count(STAT_EXEC_EMIT);
	bpf_map_delete_elem(&pending_execs, &tgid);
	return 0;
}

static __always_inline int report_open(__s32 dfd, const char *filename, __u32 flags)
{
	__u32 tgid = current_tgid();
	if (!is_watched(tgid) || is_self(tgid))
		return 0;
	struct open_rec *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r) {
		count(STAT_DROPPED);
		return 0;
	}
	fill_hdr(&r->h, REC_OPEN, tgid);
	r->dfd = dfd;
	r->flags = flags;
	// Absolute paths are reported as is; relative ones are resolved by
	// user space against the process cwd or dfd. Empty paths carry no
	// information and are dropped.
	if (bpf_probe_read_user_str(r->path, sizeof(r->path), filename) <= 1) {
		bpf_ringbuf_discard(r, 0);
		return 0;
	}
	bpf_ringbuf_submit(r, 0);
	return 0;
}

static __always_inline int report_connect(const char *uaddr, __u64 len)
{
	__u32 tgid = current_tgid();
	if (!is_watched(tgid) || is_self(tgid))
		return 0;
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
		return 0;
	if (family != AF_INET && family != AF_INET6)
		return 0;
	if ((family == AF_INET && len < 8) || (family == AF_INET6 && len < 24))
		return 0;
	struct connect_rec *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r) {
		count(STAT_DROPPED);
		return 0;
	}
	fill_hdr(&r->h, REC_CONNECT, tgid);
	r->family = family;
	r->_pad = 0;
	__builtin_memset(r->addr, 0, sizeof(r->addr));
	// sockaddr_in: port at 2, address at 4. sockaddr_in6: port at 2,
	// address at 8.
	bpf_probe_read_user(&r->port, sizeof(r->port), uaddr + 2);
	if (family == AF_INET)
		bpf_probe_read_user(r->addr, 4, uaddr + 4);
	else
		bpf_probe_read_user(r->addr, 16, uaddr + 8);
	bpf_ringbuf_submit(r, 0);
	return 0;
}

static __always_inline __u64 sys_arg(const char *regs, int off)
{
	__u64 v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), regs + off);
	return v;
}

// raw_syscalls/sys_enter(struct pt_regs *regs, long id): runs for every
// syscall, so everything but the few hooked ones returns immediately.
SEC("raw_tracepoint/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	const char *regs = (const char *)ctx->args[0];
	long id = (long)ctx->args[1];
	switch (id) {
	case NR_execve:
		return exec_enter((const char *)sys_arg(regs, REG_ARG0),
				  (const char *const *)sys_arg(regs, REG_ARG1));
	case NR_execveat:
		return exec_enter((const char *)sys_arg(regs, REG_ARG1),
				  (const char *const *)sys_arg(regs, REG_ARG2));
	case NR_openat:
		return report_open((__s32)sys_arg(regs, REG_ARG0), (const char *)sys_arg(regs, REG_ARG1),
				   (__u32)sys_arg(regs, REG_ARG2));
	case NR_openat2: {
		// struct open_how starts with the u64 flags.
		__u64 flags = 0;
		bpf_probe_read_user(&flags, sizeof(flags), (const void *)sys_arg(regs, REG_ARG2));
		return report_open((__s32)sys_arg(regs, REG_ARG0), (const char *)sys_arg(regs, REG_ARG1),
				   (__u32)flags);
	}
#ifdef NR_open
	case NR_open:
		return report_open(AT_FDCWD, (const char *)sys_arg(regs, REG_ARG0), (__u32)sys_arg(regs, REG_ARG1));
#endif
	case NR_connect:
		return report_connect((const char *)sys_arg(regs, REG_ARG1), sys_arg(regs, REG_ARG2));
	}
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	// Only the thread group leader's exit ends the process.
	if ((__u32)id != tgid)
		return 0;
	bpf_map_delete_elem(&watched, &tgid);
	bpf_map_delete_elem(&pending_execs, &tgid);
	if (is_self(tgid))
		return 0;
	struct hdr *h = bpf_ringbuf_reserve(&events, sizeof(*h), 0);
	if (!h) {
		count(STAT_DROPPED);
		return 0;
	}
	fill_hdr(h, REC_EXIT, tgid);
	bpf_ringbuf_submit(h, 0);
	bpf_map_delete_elem(&parents, &tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
