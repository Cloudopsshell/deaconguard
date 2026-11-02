// SPDX-License-Identifier: MIT OR GPL-2.0
//
// DeaconGuard's live detection watchers. They run in the kernel, on the
// system-call and scheduler tracepoints, whose formats the kernel keeps
// stable, so one build works on every supported kernel without reading
// the kernel's internal structures.
//
// They report two kinds of event to the agent through a ring buffer:
// programs that start (with the program that started them and their
// arguments), and files opened for writing, renamed or linked under a
// short list of sensitive paths. Everything else is dropped here, in the
// kernel, so the agent only sees the few events its rules look at.
//
// Build with scripts/build-bpf.sh. Every function is inlined and no string
// constants are used, so the object needs no relocations but its maps'.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define INLINE static inline __attribute__((always_inline))

// Map types, from the kernel's bpf_map_type.
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

// How a file was written: the agent says so in its alert.
#define HOW_OPEN 1
#define HOW_RENAME 2
#define HOW_LINK 3

// One event for the agent. internal/live/event.go reads it at fixed
// offsets: keep the two in step.
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

// Counters: programs started, writes looked at, events lost because the
// ring buffer was full.
#define COUNT_EXEC 0
#define COUNT_WRITE 1
#define COUNT_LOST 2
#define COUNTERS 4

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
