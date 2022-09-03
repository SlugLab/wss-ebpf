#undef BUILD_BUG_ON_MSG
#define BUILD_BUG_ON_MSG(...)

#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/sched.h>
#include <linux/unistd.h>

struct sys_record {
    u64 timestamp;
};

struct req_msg {
    u64 timestamp;
    u32 count;
    u32 flag;
    u32 complete;
};

struct req_record {
    u64 timestamp;
    u32 flag;
};

BPF_RINGBUF_OUTPUT(req_output, 1 << 12);

BPF_HASH(sys_hash, u64, struct sys_record);
BPF_HASH(req_hash, struct sys_record *, struct req_record);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sys_record sys_record = {};
    sys_record.timestamp = bpf_ktime_get_ns();
    sys_hash.insert(&pid_tgid, &sys_record);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    sys_hash.delete(&pid_tgid);

    return 0;
}

int trace_req_start(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sys_record *sys_record = sys_hash.lookup(&pid_tgid);

    struct req_record req_record = {};
    req_record.timestamp = bpf_ktime_get_ns();
    req_hash.update(&sys_record, &req_record);

    return 0;
}

int trace_req_done(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sys_record *sys_record = sys_hash.lookup(&pid_tgid);
    struct req_record *req_record = req_hash.lookup(&sys_record);
    if (!req_record) {
        return 0;
    }
    struct page *arg0 = (struct page *)PT_REGS_PARM1(ctx);

    u64 time = bpf_ktime_get_ns();

    struct req_msg req_msg = {};
    /** know which type of the page is */
    if (!(arg0->flags & PG_idle)) {
        req_msg.count++;
    }

    req_msg.flag = req_record->flag;
    req_msg.timestamp = req_record->timestamp;
    req_msg.complete = time - req_record->timestamp;

    req_output.ringbuf_output(&req_msg, sizeof(req_msg), 0);

    req_hash.delete(&sys_record);

    return 0;
}