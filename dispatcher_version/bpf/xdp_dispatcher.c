#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1U << 0)
#endif

#define STAGE_PASS       0  
#define STAGE_DROP       1  
#define STAGE_CALL_NEXT  2 
#define STAGE_RETURN     3 

struct pkt_metadata {
    __u32 stage1_visits;    
    __u32 stage2_visits;     
    __u32 routing_decision;  
    __u32 flow_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} control_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct pkt_metadata);
    __uint(max_entries, 1);
} pkt_meta_map SEC(".maps");

/* Interface configuration: 
 * key 0 = peer_ifindex (for bridge mode)
 * key 1 = bridge_mode (0=disabled, 1=enabled)
 * key 2 = output_ifindex (for stage pipeline routing - veth2)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 3);
} iface_config SEC(".maps");

/* Weak default implementations - will be replaced via freplace */
__weak int stage1(struct xdp_md *ctx, struct pkt_metadata *meta) {
    if (!meta)
        return XDP_PASS;
    meta->routing_decision = STAGE_PASS;
    return XDP_PASS;
}

__weak int stage2(struct xdp_md *ctx, struct pkt_metadata *meta) {
    if (!meta)
        return XDP_PASS;
    meta->routing_decision = STAGE_PASS;
    return XDP_PASS;
}

/* Helper function to redirect packet to output interface */
static __always_inline int redirect_to_output(struct xdp_md *ctx, __u32 *output_ifindex)
{
    if (!output_ifindex || *output_ifindex == 0)
        return XDP_PASS;
    
    return XDP_PASS;
}

SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx)
{
    struct pkt_metadata *meta;
    __u32 key = 0;
    __u64 *pcnt;
    int rc;
    
    /* Max iterations to prevent infinite loops */
    #define MAX_STAGE_HOPS 8
    int hops = 0;

    pcnt = bpf_map_lookup_elem(&counters, &key);
    if (pcnt)
        __sync_fetch_and_add(pcnt, 1);

    key = 1;
    __u32 *bridge_mode = bpf_map_lookup_elem(&iface_config, &key);
    if (bridge_mode && *bridge_mode == 1) {
        key = 0;
        __u32 *peer_ifindex = bpf_map_lookup_elem(&iface_config, &key);
        if (peer_ifindex && *peer_ifindex > 0) {
            return bpf_redirect(*peer_ifindex, 0);
        }
    }

    key = 0;
    meta = bpf_map_lookup_elem(&pkt_meta_map, &key);
    if (!meta)
        return XDP_PASS;

    meta->stage1_visits = 0;
    meta->stage2_visits = 0;
    meta->routing_decision = STAGE_PASS;
    meta->flow_id = 0;

    __u32 *stage1_enabled = bpf_map_lookup_elem(&control_map, &key);
    if (!stage1_enabled || *stage1_enabled != 1)
        return XDP_PASS;

    #pragma unroll
    for (hops = 0; hops < MAX_STAGE_HOPS; hops++) {
        if (meta->stage1_visits < 4) {  /* Loop prevention */
            meta->stage1_visits++;
            
            key = 1;
            pcnt = bpf_map_lookup_elem(&counters, &key);
            if (pcnt)
                __sync_fetch_and_add(pcnt, 1);
            
            rc = stage1(ctx, meta);
            
            if (rc == XDP_DROP || meta->routing_decision == STAGE_DROP)
                return XDP_DROP;
            
            if (meta->routing_decision == STAGE_PASS) {
                key = 2;
                __u32 *output_ifindex = bpf_map_lookup_elem(&iface_config, &key);
                if (output_ifindex && *output_ifindex > 0) {
                    return redirect_to_output(ctx, output_ifindex);
                }
                return XDP_PASS;
            }
            
            if (meta->routing_decision != STAGE_CALL_NEXT) {
                /* Unknown decision, forward to output interface (veth2) */
                key = 2;
                __u32 *output_ifindex = bpf_map_lookup_elem(&iface_config, &key);
                if (output_ifindex && *output_ifindex > 0) {
                    return redirect_to_output(ctx, output_ifindex);
                }
                return XDP_PASS;
            }
            
            key = 1;
            __u32 *stage2_enabled = bpf_map_lookup_elem(&control_map, &key);
            if (!stage2_enabled || *stage2_enabled != 1)
                return XDP_PASS;
        }
        
        if (meta->stage2_visits < 4) {  /* Loop prevention */
            meta->stage2_visits++;
            
            key = 2;
            pcnt = bpf_map_lookup_elem(&counters, &key);
            if (pcnt)
                __sync_fetch_and_add(pcnt, 1);
            
            rc = stage2(ctx, meta);
            
            if (rc == XDP_DROP || meta->routing_decision == STAGE_DROP)
                return XDP_DROP;
            
            if (meta->routing_decision == STAGE_PASS) {
                key = 2;
                __u32 *output_ifindex = bpf_map_lookup_elem(&iface_config, &key);
                if (output_ifindex && *output_ifindex > 0) {
                    return redirect_to_output(ctx, output_ifindex);
                }
                return XDP_PASS;
            }
            
            if (meta->routing_decision == STAGE_RETURN) {
                meta->routing_decision = STAGE_CALL_NEXT;
                continue;
            }
            
            key = 2;
            __u32 *output_ifindex = bpf_map_lookup_elem(&iface_config, &key);
            if (output_ifindex && *output_ifindex > 0) {
                return redirect_to_output(ctx, output_ifindex);
            }
            return XDP_PASS;
        }
        
        break;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
