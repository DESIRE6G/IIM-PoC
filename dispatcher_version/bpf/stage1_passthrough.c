#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define STAGE_DROP      0
#define STAGE_PASS      1
#define STAGE_CALL_NEXT 2
#define STAGE_RETURN    3

struct pkt_metadata {
    __u32 stage1_visits;
    __u32 stage2_visits;
    __u32 routing_decision;
    __u32 flow_id;
};

SEC("freplace/stage1")
int stage1(struct xdp_md *ctx, struct pkt_metadata *meta) {
    if (!meta)
        return XDP_PASS;
    
    meta->routing_decision = STAGE_CALL_NEXT;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
