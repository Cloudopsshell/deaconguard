// SPDX-License-Identifier: MIT OR GPL-2.0
//
// DeaconGuard's live detection watchers. They run in the kernel, on the
// system-call and scheduler tracepoints, whose formats the kernel keeps
// stable, so one build works on every supported kernel without reading
// the kernel's internal structures.
//
// They report six kinds of event to the agent through a ring buffer:
// programs that start (with the program that started them and their
// arguments); files opened for writing, renamed or linked under a short
// list of sensitive paths; network connections made by shells, by
// programs started from a temporary folder (and the processes they start),
// or to a short list of ports; a process that isn't root switching to
// root; kernel modules loaded; and one process taking control of another
// (ptrace attach) or writing into its memory. Everything else is dropped
// here, in the kernel, so the agent only sees the few events its rules
// look at.
//
// Build with scripts/build-bpf.sh. Every function is inlined and no string
// constants are used, so the object needs no relocations but its maps'.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;
typedef long long s64;

#define SEC(name) __attribute__((section(name), used))
#define INLINE static inline __attribute__((always_inline))

// Map types, from the kernel's bpf_map_type.
#define MAP_HASH 1
#define MAP_ARRAY 2
#define MAP_PERCPU_ARRAY 6
#define MAP_LRU_HASH 9
#define MAP_RINGBUF 27

// A map, as DeaconGuard's loader reads it from the "maps" section.
struct dg_map {
	u32 type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 flags;
};

// Kernel helpers, by their number in the kernel's bpf_func_id.
static void *(*map_lookup)(void *map, const void *key) = (void *)1;
static long (*map_update)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*map_delete)(void *map, const void *key) = (void *)3;
static u64 (*ktime_ns)(void) = (void *)5;
static u64 (*current_pid_tgid)(void) = (void *)14;
static u64 (*current_uid_gid)(void) = (void *)15;
static long (*current_comm)(void *buf, u32 size) = (void *)16;
static u64 (*current_cgroup)(void) = (void *)80;
static long (*read_user)(void *dst, u32 size, const void *src) = (void *)112;
static long (*read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static long (*read_user_str)(void *dst, u32 size, const void *src) = (void *)114;
static long (*read_kernel_str)(void *dst, u32 size, const void *src) = (void *)115;
static void *(*ring_reserve)(void *ring, u64 size, u64 flags) = (void *)131;
static void (*ring_submit)(void *data, u64 flags) = (void *)132;

#define COMM_LEN 16
#define PATH_LEN 256
#define ARGS_LEN 512
#define ARG_MAX 256
#define MAX_ARGS 20

#define KIND_EXEC 1
#define KIND_WRITE 2
#define KIND_CONNECT 3
#define KIND_PRIVILEGE 4
#define KIND_MODULE 5
#define KIND_TRACE 6

// How a file was written: the agent says so in its alert.
#define HOW_OPEN 1
#define HOW_RENAME 2
#define HOW_LINK 3

// One event for the agent. internal/live/event.go reads it at fixed
// offsets: keep the two in step. For KIND_CONNECT, how is the port
// connected to, args_len the address family, path the address's 4 or 16
// bytes, and args[0] why the connection was reported (the WHY_ bits).
//
// For KIND_PRIVILEGE, KIND_MODULE and KIND_TRACE, the system call's result
// is what the event says happened: how is which call (the CALL_ values),
// args_len its target (the process traced, or the module's file
// descriptor), path holds a struct outcome, and args, for a module, its
// parameters.
struct event {
	u32 kind;
	u32 pid;
	u32 tid;
	u32 uid;
	u64 time_ns;
	u64 cgroup;
	u32 how;
	u32 args_len;
	char comm[COMM_LEN];
	char parent_comm[COMM_LEN];
	char path[PATH_LEN];
	char args[ARGS_LEN];
};

// What a watched system call was asked to do, from its entry until it
// returns: whether it worked decides whether it is reported.
struct call {
	u32 kind;
	u32 how;
	u32 uid;
	u32 target;
	u32 ids[3];
	u32 pad;
	u64 pointer;
};

// The start of path, for the events made from a struct call.
struct outcome {
	s64 result;
	u32 ids[3];
	u32 marked;
};

// Which call: the user ID calls, the module calls, and ptrace's attach
// requests, by their numbers, or a write into another process's memory.
#define CALL_SETUID 1
#define CALL_SETREUID 2
#define CALL_SETRESUID 3
#define CALL_FINIT_MODULE 1
#define CALL_INIT_MODULE 2
#define PTRACE_ATTACH 16
#define PTRACE_SEIZE 0x4206
#define CALL_VM_WRITE 0x10000

// What sys_enter_execve saw, until the program has started.
struct pending {
	char comm[COMM_LEN];
	u32 args_len;
	u32 pad;
	char args[ARGS_LEN];
};

// A path the agent wants to hear about: a prefix of up to 48 bytes, as
// words and the masks that select its bytes, so a path is compared eight
// bytes at a time. For KIND_THEN, such as /home/NAME/.ssh/, the path must
// go on, after one more folder, with "after".
struct watched {
	u64 prefix[6];
	u64 mask[6];
	u64 after;
	u64 after_mask;
	u32 len;
	u32 kind;
};

#define KIND_PREFIX 1
#define KIND_THEN 2

// A file name the agent wants to hear about when a program writes it by a
// relative path, such as "passwd" from inside /etc: up to 31 bytes, with
// the terminating zero inside the mask, so only the exact name matches.
struct name {
	u64 word[4];
	u64 mask[4];
};

#define WATCHED_MAX 24
#define NAMES_MAX 16
#define EXEC_PATHS_MAX 8
#define PORTS_MAX 32

// Why a connection was reported.
#define WHY_MARKED 1
#define WHY_PORT 2
#define WHY_COMM 4

#define AF_INET 2
#define AF_INET6 10

// Counters: programs started, writes looked at, events lost because the
// ring buffer was full, connections looked at, and user ID, module and
// ptrace calls looked at.
#define COUNT_EXEC 0
#define COUNT_WRITE 1
#define COUNT_LOST 2
#define COUNT_CONNECT 3
#define COUNT_CALL 4
#define COUNTERS 5

struct dg_map events SEC("maps") = {MAP_RINGBUF, 0, 0, 1 << 18, 0};
struct dg_map pending_execs SEC("maps") = {MAP_LRU_HASH, sizeof(u32), sizeof(struct pending), 4096, 0};
struct dg_map scratch SEC("maps") = {MAP_PERCPU_ARRAY, sizeof(u32), sizeof(struct pending), 1, 0};
// Twice PATH_LEN, so reading a word past a path's end stays in the value.
struct dg_map paths SEC("maps") = {MAP_PERCPU_ARRAY, sizeof(u32), 2 * PATH_LEN, 1, 0};
struct dg_map watched_paths SEC("maps") = {MAP_ARRAY, sizeof(u32), sizeof(struct watched), WATCHED_MAX, 0};
struct dg_map watched_names SEC("maps") = {MAP_ARRAY, sizeof(u32), sizeof(struct name), NAMES_MAX, 0};
struct dg_map counters SEC("maps") = {MAP_PERCPU_ARRAY, sizeof(u32), sizeof(u64), COUNTERS, 0};
// The agent's own process, whose writes and programs are its own business.
struct dg_map self SEC("maps") = {MAP_ARRAY, sizeof(u32), sizeof(u32), 1, 0};
// Folders a program started from is marked for, and the processes marked,
// by process ID: a marked process's connections are reported, and the
// processes it starts are marked in turn.
struct dg_map exec_paths SEC("maps") = {MAP_ARRAY, sizeof(u32), sizeof(struct watched), EXEC_PATHS_MAX, 0};
struct dg_map marked SEC("maps") = {MAP_LRU_HASH, sizeof(u32), sizeof(u32), 4096, 0};
// Process names whose connections are reported (shells), and ports.
struct dg_map connect_comms SEC("maps") = {MAP_ARRAY, sizeof(u32), sizeof(struct name), NAMES_MAX, 0};
struct dg_map watched_ports SEC("maps") = {MAP_HASH, sizeof(u32), sizeof(u32), PORTS_MAX, 0};
// Settings from the agent: [0] where sched_process_fork keeps the new
// process's ID, which changed between kernels (0: don't follow forks).
struct dg_map settings SEC("maps") = {MAP_ARRAY, sizeof(u32), sizeof(u32), 1, 0};
// Watched system calls in progress, by thread.
struct dg_map calls SEC("maps") = {MAP_LRU_HASH, sizeof(u32), sizeof(struct call), 1024, 0};
// Processes that were root when they changed their user IDs, and the
// processes they start before a new program: a root process that lowers
// its IDs for a while (PAM, runuser, cron, sshd do) may take root back.
// A new program starts without it.
struct dg_map was_root SEC("maps") = {MAP_LRU_HASH, sizeof(u32), sizeof(u32), 4096, 0};

char dg_license[] SEC("license") = "Dual MIT/GPL";

// The fixed part of every sys_enter tracepoint: the common header, the
// system call's number, then its six arguments.
struct sys_enter {
	u64 common;
	long id;
	unsigned long args[6];
};

INLINE void count(u32 which) {
	u64 *value = map_lookup(&counters, &which);
	if (value)
		*value += 1;
}

INLINE int is_self(void) {
	u32 zero = 0;
	u32 *pid = map_lookup(&self, &zero);
	return pid && *pid != 0 && *pid == (u32)(current_pid_tgid() >> 32);
}

// Remembers the program that is about to start: who starts it, and its
// arguments, which are only readable now.
INLINE int remember_exec(const char *const *argv) {
	u32 zero = 0;
	struct pending *pending = map_lookup(&scratch, &zero);
	if (!pending)
		return 0;
	current_comm(pending->comm, COMM_LEN);
	u32 offset = 0;
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *arg = 0;
		if (read_user(&arg, sizeof(arg), &argv[i]) < 0 || !arg)
			break;
		offset &= ARG_MAX - 1;
		long n = read_user_str(&pending->args[offset], ARG_MAX, arg);
		if (n <= 0)
			break;
		offset += n;
		// Arguments are joined by a space, as on a command line.
		pending->args[(offset - 1) & (ARGS_LEN - 1)] = ' ';
		if (offset >= ARG_MAX)
			break;
	}
	pending->args_len = offset;
	u32 tid = (u32)current_pid_tgid();
	map_update(&pending_execs, &tid, pending, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int enter_execve(struct sys_enter *ctx) {
	return remember_exec((const char *const *)ctx->args[1]);
}

SEC("tp/syscalls/sys_enter_execveat")
int enter_execveat(struct sys_enter *ctx) {
	return remember_exec((const char *const *)ctx->args[2]);
}

// sched_process_exec: after the common header, the program's path as a
// __data_loc (offset and length in the record), the pid, and the old pid,
// the thread that called exec.
struct process_exec {
	u64 common;
	u32 filename_loc;
	s32 pid;
	s32 old_pid;
};

// Whether a path, read into buf, starts with one of the folders in
// exec_paths, compared a word at a time as in watched below.
INLINE int marked_path(const char *buf) {
	const u64 *words = (const u64 *)buf;
	for (u32 i = 0; i < EXEC_PATHS_MAX; i++) {
		u32 key = i;
		struct watched *w = map_lookup(&exec_paths, &key);
		if (!w || w->kind == 0)
			break;
		u64 diff = 0;
		for (int j = 0; j < 6; j++)
			diff |= (words[j] ^ w->prefix[j]) & w->mask[j];
		if (!diff)
			return 1;
	}
	return 0;
}

SEC("tp/sched/sched_process_exec")
int process_exec(struct process_exec *ctx) {
	count(COUNT_EXEC);
	u32 old = (u32)ctx->old_pid;
	struct pending *pending = map_lookup(&pending_execs, &old);
	if (is_self()) {
		if (pending)
			map_delete(&pending_execs, &old);
		return 0;
	}
	struct event *e = ring_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		count(COUNT_LOST);
		if (pending)
			map_delete(&pending_execs, &old);
		return 0;
	}
	u64 id = current_pid_tgid();
	e->kind = KIND_EXEC;
	e->pid = id >> 32;
	e->tid = (u32)id;
	e->uid = (u32)current_uid_gid();
	e->time_ns = ktime_ns();
	e->cgroup = current_cgroup();
	e->how = 0;
	current_comm(e->comm, COMM_LEN);
	read_kernel_str(e->path, PATH_LEN, (char *)ctx + (ctx->filename_loc & 0xffff));
	if (marked_path(e->path)) {
		u32 pid = e->pid, why = WHY_MARKED;
		map_update(&marked, &pid, &why, 0);
	}
	{
		u32 pid = e->pid;
		map_delete(&was_root, &pid);
	}
	e->args_len = 0;
	e->parent_comm[0] = 0;
	e->args[0] = 0;
	if (pending) {
		__builtin_memcpy(e->parent_comm, pending->comm, COMM_LEN);
		__builtin_memcpy(e->args, pending->args, ARGS_LEN);
		e->args_len = pending->args_len;
		map_delete(&pending_execs, &old);
	}
	ring_submit(e, 0);
	return 0;
}

// Whether path, read into buf, is one the agent watches: under a watched
// prefix, or, for a relative path, named like a watched file. Comparing
// whole words keeps the kernel's checker, and the CPU, to a few steps.
INLINE int watched(const char *buf) {
	if (buf[0] == '/') {
		const u64 *words = (const u64 *)buf;
		for (u32 i = 0; i < WATCHED_MAX; i++) {
			u32 key = i;
			struct watched *w = map_lookup(&watched_paths, &key);
			if (!w || w->kind == 0)
				break;
			u64 diff = 0;
			for (int j = 0; j < 6; j++)
				diff |= (words[j] ^ w->prefix[j]) & w->mask[j];
			if (diff)
				continue;
			if (w->kind == KIND_PREFIX)
				return 1;
			// KIND_THEN: skip one folder, then compare "after".
			u32 at = 0;
			u32 start = w->len & 63;
			for (u32 j = 0; j < 64; j++) {
				char c = buf[(start + j) & (PATH_LEN - 1)];
				if (c == 0)
					break;
				if (c == '/') {
					at = start + j + 1;
					break;
				}
			}
			if (at == 0)
				continue;
			u64 next = 0;
			read_kernel(&next, sizeof(next), buf + (at & (PATH_LEN - 1)));
			if (((next ^ w->after) & w->after_mask) == 0)
				return 1;
		}
		return 0;
	}
	// A relative path, such as "passwd" written from inside /etc: compare
	// it, less a leading "./", with the watched names. Paths with folders
	// in them ("ssh/sshd_config") aren't compared: finding their last part
	// would cost a loop per write.
	u32 base = 0;
	if (buf[0] == '.' && buf[1] == '/')
		base = 2;
	u64 last[4] = {0, 0, 0, 0};
	read_kernel(last, sizeof(last), buf + base);
	for (u32 i = 0; i < NAMES_MAX; i++) {
		u32 key = i;
		struct name *w = map_lookup(&watched_names, &key);
		if (!w || w->mask[0] == 0)
			break;
		u64 diff = 0;
		for (int j = 0; j < 4; j++)
			diff |= (last[j] ^ w->word[j]) & w->mask[j];
		if (!diff)
			return 1;
	}
	return 0;
}

// Reports a write to a watched path.
INLINE int written(const char *user_path, u32 how) {
	count(COUNT_WRITE);
	if (!user_path || is_self())
		return 0;
	u32 zero = 0;
	char *buf = map_lookup(&paths, &zero);
	if (!buf)
		return 0;
	long n = read_user_str(buf, PATH_LEN, user_path);
	if (n <= 1 || !watched(buf))
		return 0;
	struct event *e = ring_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		count(COUNT_LOST);
		return 0;
	}
	u64 id = current_pid_tgid();
	e->kind = KIND_WRITE;
	e->pid = id >> 32;
	e->tid = (u32)id;
	e->uid = (u32)current_uid_gid();
	e->time_ns = ktime_ns();
	e->cgroup = current_cgroup();
	e->how = how;
	e->args_len = 0;
	current_comm(e->comm, COMM_LEN);
	e->parent_comm[0] = 0;
	e->args[0] = 0;
	__builtin_memcpy(e->path, buf, PATH_LEN);
	ring_submit(e, 0);
	return 0;
}

// Open flags that write: O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND.
#define WRITE_FLAGS (0x1 | 0x2 | 0x40 | 0x200 | 0x400)

SEC("tp/syscalls/sys_enter_openat")
int enter_openat(struct sys_enter *ctx) {
	if (!(ctx->args[2] & WRITE_FLAGS))
		return 0;
	return written((const char *)ctx->args[1], HOW_OPEN);
}

SEC("tp/syscalls/sys_enter_openat2")
int enter_openat2(struct sys_enter *ctx) {
	u64 flags = 0;
	// struct open_how starts with the flags.
	if (read_user(&flags, sizeof(flags), (const void *)ctx->args[2]) < 0 || !(flags & WRITE_FLAGS))
		return 0;
	return written((const char *)ctx->args[1], HOW_OPEN);
}

// x86-64 also has open, creat, rename and symlink; arm64 only the *at forms.
SEC("tp/syscalls/sys_enter_open")
int enter_open(struct sys_enter *ctx) {
	if (!(ctx->args[1] & WRITE_FLAGS))
		return 0;
	return written((const char *)ctx->args[0], HOW_OPEN);
}

SEC("tp/syscalls/sys_enter_creat")
int enter_creat(struct sys_enter *ctx) {
	return written((const char *)ctx->args[0], HOW_OPEN);
}

SEC("tp/syscalls/sys_enter_renameat2")
int enter_renameat2(struct sys_enter *ctx) {
	return written((const char *)ctx->args[3], HOW_RENAME);
}

SEC("tp/syscalls/sys_enter_renameat")
int enter_renameat(struct sys_enter *ctx) {
	return written((const char *)ctx->args[3], HOW_RENAME);
}

SEC("tp/syscalls/sys_enter_rename")
int enter_rename(struct sys_enter *ctx) {
	return written((const char *)ctx->args[1], HOW_RENAME);
}

SEC("tp/syscalls/sys_enter_symlinkat")
int enter_symlinkat(struct sys_enter *ctx) {
	return written((const char *)ctx->args[2], HOW_LINK);
}

SEC("tp/syscalls/sys_enter_symlink")
int enter_symlink(struct sys_enter *ctx) {
	return written((const char *)ctx->args[1], HOW_LINK);
}

SEC("tp/syscalls/sys_enter_linkat")
int enter_linkat(struct sys_enter *ctx) {
	return written((const char *)ctx->args[3], HOW_LINK);
}

// sched_process_fork, in the parent: the new process inherits the parent's
// mark. The record's layout changed between kernels, so the agent reads it
// from tracefs and says where the new process's ID is.
struct process_fork {
	u64 common;
	u32 words[10];
};

SEC("tp/sched/sched_process_fork")
int process_fork(struct process_fork *ctx) {
	u32 tgid = current_pid_tgid() >> 32;
	// Values, not the pointers: the checker refuses arithmetic on two
	// pointers, which testing both at once compiles to.
	u32 why = 0, root = 0;
	u32 *marked_why = map_lookup(&marked, &tgid);
	if (marked_why)
		why = *marked_why;
	if (map_lookup(&was_root, &tgid))
		root = 1;
	if (why == 0 && root == 0)
		return 0;
	u32 zero = 0;
	u32 *offset = map_lookup(&settings, &zero);
	if (!offset)
		return 0;
	// The two layouts the agent knows: child_pid at 44 before Linux 6.x
	// moved the names out of the record, at 20 after. The record is copied
	// first: the checker refuses reads at an offset chosen at run time.
	struct process_fork copy = {};
	read_kernel(&copy, sizeof(copy), ctx);
	s32 child = 0;
	if (*offset == 44)
		child = (s32)copy.words[9];
	else if (*offset == 20)
		child = (s32)copy.words[3];
	if (child <= 0)
		return 0;
	u32 key = (u32)child, one = 1;
	if (why)
		map_update(&marked, &key, &why, 0);
	if (root)
		map_update(&was_root, &key, &one, 0);
	return 0;
}

// sched_process_exit: a process that ends takes its mark with it, so its
// ID, once reused, starts unmarked.
SEC("tp/sched/sched_process_exit")
int process_exit(void *ctx) {
	u64 id = current_pid_tgid();
	u32 pid = (u32)id;
	if (pid == (u32)(id >> 32)) {
		map_delete(&marked, &pid);
		map_delete(&was_root, &pid);
	}
	return 0;
}

// Whether the current process's name is one in connect_comms.
INLINE int comm_watched(void) {
	u64 comm[4] = {0, 0, 0, 0};
	current_comm(comm, COMM_LEN);
	for (u32 i = 0; i < NAMES_MAX; i++) {
		u32 key = i;
		struct name *w = map_lookup(&connect_comms, &key);
		if (!w || w->mask[0] == 0)
			break;
		u64 diff = 0;
		for (int j = 0; j < 4; j++)
			diff |= (comm[j] ^ w->word[j]) & w->mask[j];
		if (!diff)
			return 1;
	}
	return 0;
}

// connect(fd, address, length): reports IPv4 and IPv6 connections from
// marked processes and shells, and to watched ports. Local sockets, which
// most connections on a server are, are dropped first.
SEC("tp/syscalls/sys_enter_connect")
int enter_connect(struct sys_enter *ctx) {
	count(COUNT_CONNECT);
	const char *address = (const char *)ctx->args[1];
	u16 family = 0;
	if (!address || read_user(&family, sizeof(family), address) < 0)
		return 0;
	if (family != AF_INET && family != AF_INET6)
		return 0;
	if (is_self())
		return 0;
	u16 network_port = 0;
	read_user(&network_port, sizeof(network_port), address + 2);
	u32 port = ((network_port & 0xff) << 8) | (network_port >> 8);
	u64 id = current_pid_tgid();
	u32 tgid = id >> 32;
	u32 why = 0;
	if (map_lookup(&marked, &tgid))
		why |= WHY_MARKED;
	if (map_lookup(&watched_ports, &port))
		why |= WHY_PORT;
	if (comm_watched())
		why |= WHY_COMM;
	if (!why)
		return 0;
	struct event *e = ring_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		count(COUNT_LOST);
		return 0;
	}
	e->kind = KIND_CONNECT;
	e->pid = tgid;
	e->tid = (u32)id;
	e->uid = (u32)current_uid_gid();
	e->time_ns = ktime_ns();
	e->cgroup = current_cgroup();
	e->how = port;
	e->args_len = family;
	current_comm(e->comm, COMM_LEN);
	e->parent_comm[0] = 0;
	__builtin_memset(e->path, 0, 16);
	// sockaddr_in keeps the address at 4, sockaddr_in6 at 8.
	if (family == AF_INET)
		read_user(e->path, 4, address + 4);
	else
		read_user(e->path, 16, address + 8);
	e->args[0] = why;
	e->args[1] = 0;
	ring_submit(e, 0);
	return 0;
}

// The fixed part of every sys_exit tracepoint: the common header, the
// system call's number, then what it returned.
struct sys_exit {
	u64 common;
	long id;
	long ret;
};

// Remembers a watched call until it returns.
INLINE int called(u32 kind, u32 how, u32 target, u32 a, u32 b, u32 c, u64 pointer) {
	if (is_self())
		return 0;
	struct call call = {};
	call.kind = kind;
	call.how = how;
	call.uid = (u32)current_uid_gid();
	call.target = target;
	call.ids[0] = a;
	call.ids[1] = b;
	call.ids[2] = c;
	call.pointer = pointer;
	u32 tid = (u32)current_pid_tgid();
	map_update(&calls, &tid, &call, 0);
	return 0;
}

// A user ID call is remembered only when a process that isn't root, and
// wasn't since its program started, asks for root (0) as one of its IDs:
// nothing else is a gain in privilege. A root process's call marks it as
// one that was root. (u32)-1 leaves an ID as it is.
INLINE int asks_root(u32 a, u32 b, u32 c) {
	count(COUNT_CALL);
	u32 tgid = current_pid_tgid() >> 32;
	if ((u32)current_uid_gid() == 0) {
		u32 one = 1;
		map_update(&was_root, &tgid, &one, 0);
		return 0;
	}
	if (map_lookup(&was_root, &tgid))
		return 0;
	return a == 0 || b == 0 || c == 0;
}

SEC("tp/syscalls/sys_enter_setuid")
int enter_setuid(struct sys_enter *ctx) {
	u32 id = (u32)ctx->args[0];
	if (!asks_root(id, -1, -1))
		return 0;
	return called(KIND_PRIVILEGE, CALL_SETUID, 0, id, -1, -1, 0);
}

SEC("tp/syscalls/sys_enter_setreuid")
int enter_setreuid(struct sys_enter *ctx) {
	u32 real = (u32)ctx->args[0], effective = (u32)ctx->args[1];
	if (!asks_root(real, effective, -1))
		return 0;
	return called(KIND_PRIVILEGE, CALL_SETREUID, 0, real, effective, -1, 0);
}

SEC("tp/syscalls/sys_enter_setresuid")
int enter_setresuid(struct sys_enter *ctx) {
	u32 real = (u32)ctx->args[0], effective = (u32)ctx->args[1], saved = (u32)ctx->args[2];
	if (!asks_root(real, effective, saved))
		return 0;
	return called(KIND_PRIVILEGE, CALL_SETRESUID, 0, real, effective, saved, 0);
}

// finit_module(fd, parameters, flags) and init_module(image, length,
// parameters): every module load is remembered; they are rare.
SEC("tp/syscalls/sys_enter_finit_module")
int enter_finit_module(struct sys_enter *ctx) {
	count(COUNT_CALL);
	return called(KIND_MODULE, CALL_FINIT_MODULE, (u32)ctx->args[0], -1, -1, -1, ctx->args[1]);
}

SEC("tp/syscalls/sys_enter_init_module")
int enter_init_module(struct sys_enter *ctx) {
	count(COUNT_CALL);
	return called(KIND_MODULE, CALL_INIT_MODULE, -1, -1, -1, -1, ctx->args[2]);
}

// ptrace(request, pid, ...): only the requests that take control of a
// process, once per process traced; a debugger's reads and writes after
// that aren't looked at.
SEC("tp/syscalls/sys_enter_ptrace")
int enter_ptrace(struct sys_enter *ctx) {
	count(COUNT_CALL);
	long request = (long)ctx->args[0];
	if (request != PTRACE_ATTACH && request != PTRACE_SEIZE)
		return 0;
	return called(KIND_TRACE, (u32)request, (u32)ctx->args[1], -1, -1, -1, 0);
}

// process_vm_writev(pid, ...): writing straight into another process.
SEC("tp/syscalls/sys_enter_process_vm_writev")
int enter_process_vm_writev(struct sys_enter *ctx) {
	count(COUNT_CALL);
	return called(KIND_TRACE, CALL_VM_WRITE, (u32)ctx->args[0], -1, -1, -1, 0);
}

// Reports a remembered call once it returns: user ID changes and ptrace
// that worked, and every module load, with its result.
INLINE int returned(struct sys_exit *ctx) {
	u64 id = current_pid_tgid();
	u32 tid = (u32)id;
	struct call *call = map_lookup(&calls, &tid);
	if (!call)
		return 0;
	long result = ctx->ret;
	int report = call->kind == KIND_MODULE || (call->how == CALL_VM_WRITE ? result > 0 : result == 0);
	if (!report) {
		map_delete(&calls, &tid);
		return 0;
	}
	struct event *e = ring_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		count(COUNT_LOST);
		map_delete(&calls, &tid);
		return 0;
	}
	u32 tgid = id >> 32;
	e->kind = call->kind;
	e->pid = tgid;
	e->tid = tid;
	e->uid = call->uid;
	e->time_ns = ktime_ns();
	e->cgroup = current_cgroup();
	e->how = call->how;
	e->args_len = call->target;
	current_comm(e->comm, COMM_LEN);
	e->parent_comm[0] = 0;
	struct outcome *outcome = (struct outcome *)e->path;
	outcome->result = result;
	outcome->ids[0] = call->ids[0];
	outcome->ids[1] = call->ids[1];
	outcome->ids[2] = call->ids[2];
	outcome->marked = map_lookup(&marked, &tgid) ? 1 : 0;
	e->args[0] = 0;
	if (call->kind == KIND_MODULE && call->pointer)
		read_user_str(e->args, ARG_MAX, (const char *)call->pointer);
	map_delete(&calls, &tid);
	ring_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_setuid")
int exit_setuid(struct sys_exit *ctx) { return returned(ctx); }

SEC("tp/syscalls/sys_exit_setreuid")
int exit_setreuid(struct sys_exit *ctx) { return returned(ctx); }

SEC("tp/syscalls/sys_exit_setresuid")
int exit_setresuid(struct sys_exit *ctx) { return returned(ctx); }

SEC("tp/syscalls/sys_exit_finit_module")
int exit_finit_module(struct sys_exit *ctx) { return returned(ctx); }

SEC("tp/syscalls/sys_exit_init_module")
int exit_init_module(struct sys_exit *ctx) { return returned(ctx); }

SEC("tp/syscalls/sys_exit_ptrace")
int exit_ptrace(struct sys_exit *ctx) { return returned(ctx); }

SEC("tp/syscalls/sys_exit_process_vm_writev")
int exit_process_vm_writev(struct sys_exit *ctx) { return returned(ctx); }
