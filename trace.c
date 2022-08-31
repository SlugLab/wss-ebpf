#undef BUILD_BUG_ON_MSG
#define BUILD_BUG_ON_MSG(...)

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>

struct sys_record {
    u64 timestamp;
    s32 sys_num;
};

struct req_msg {
    u64 timestamp;
    s32 sys_num;
    u32 type;
    u32 flag;
    u32 len;
    u32 issue;
    u32 complete;
};

struct req_record {
    u64 timestamp;
    s32 sys_num;
    u32 flag;
    u32 len;
    u32 issue;
};

BPF_RINGBUF_OUTPUT(req_output, 1 << 12);

BPF_HASH(sys_hash, u64, struct sys_record);
BPF_HASH(req_hash, struct request *, struct req_record);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sys_record sys_record = {};
    sys_record.timestamp = bpf_ktime_get_ns();
    sys_record.sys_num = args->id;
    sys_hash.insert(&pid_tgid, &sys_record);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    sys_hash.delete(&pid_tgid);

    return 0;
}

int trace_req_start(struct pt_regs *ctx, struct request *req) {
    struct gendisk *dev = req->rq_disk;
    if (dev->major != MAJOR || dev->first_minor != MINOR) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sys_record *sys_record = sys_hash.lookup(&pid_tgid);

    s64 sys_num = -1;
    if (sys_record) { sys_num = sys_record->sys_num; }

    struct req_record req_record = {};
    req_record.sys_num = sys_num;
    req_record.timestamp = bpf_ktime_get_ns();
    req_record.len = req->__data_len;
    req_hash.update(&req, &req_record);

    return 0;
}

int trace_req_done(struct pt_regs *ctx, struct request *req) {
    struct req_record *req_record = req_hash.lookup(&req);
    if (!req_record) { return 0; }

    u64 time = bpf_ktime_get_ns();

    struct req_msg req_msg = {};

    req_msg.type = (u8) req->cmd_flags;
    req_msg.flag = req_record->flag;
    req_msg.timestamp = req_record->timestamp;
    req_msg.sys_num = req_record->sys_num;
    req_msg.len = req_record->len;
    req_msg.issue = req_record->issue;
    req_msg.complete = time - req_record->timestamp;

    req_output.ringbuf_output(&req_msg, sizeof(req_msg), 0);

    req_hash.delete(&req);

    return 0;
}