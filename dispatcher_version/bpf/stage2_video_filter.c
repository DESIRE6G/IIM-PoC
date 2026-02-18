#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define RTP_PORT 6970
#define RTP_PAYLOAD_TYPE_H265 96
#define ROBOT_POSITION_PORT 5555


#define NUM_CAMERAS 200
#define NUM_HORIZONTAL_STRIPS 50
#define NUM_VERTICAL_STRIPS 50

#define COORD_MIN 0
#define COORD_MAX 1000
#define STRIP_WIDTH 20

struct pkt_metadata {
    __u32 stage1_visits;
    __u32 stage2_visits;
    __u32 routing_decision;
    __u32 flow_id;
};

struct robot_coords_hdr {
    __be32 coord_x;
    __be32 coord_y;
} __attribute__((packed));

struct rtp_hdr {
    __u8 vpxcc;
    __u8 mpt;
    __be16 sequence;
    __be32 timestamp;
    __be32 ssrc;
} __attribute__((packed));

struct h265_payload_hdr {
    __u8 byte0;
    __u8 byte1;
} __attribute__((packed));

struct h265_fu_hdr {
    __u8 s_e_r_type;
} __attribute__((packed));

struct h265_nal_hdr {
    __be16 data;
} __attribute__((packed));

#define FILTER_OFF 0
#define FILTER_DROP_P 1
#define FILTER_FORWARD_P 2


enum {
    STAT_TOTAL_PKTS = 0,
    STAT_RTP_PKTS,
    STAT_FU_START,
    STAT_P_SLICES,
    STAT_DROPPED,
    STAT_FORWARDED,
    STAT_ROBOT_POSITION_PKTS,
    STAT_MODE_OFF,
    STAT_MODE_DROP_P,
    STAT_MODE_FORWARD_P,
    STAT_CAMERA_OUT_OF_RANGE,
    STAT_MAP_LOOKUP_FAILED,
    STAT_ROBOT_COORDS_UPDATED,
    STAT_ROBOT_PORT_MATCHED,
    STAT_STAGE2_ENTRY,
    STAT_IPV4_PACKETS,
    STAT_UDP_PACKETS,
    STAT_PRE_PORT_CHECK,
    STAT_WRONG_IP,
    STAT_WRONG_PORT_RANGE,
    STAT_RTP_VERSION_FAIL,
    STAT_MAX
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filtering_mode SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_CAMERAS);
    __type(key, __u32);
    __type(value, __u32);
} camera_filtering_mode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} video_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} p_frame_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} drop_state SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} robot_coords_debug SEC(".maps");

static __always_inline void inc_stat(__u32 stat_id) {
    __u64 *count = bpf_map_lookup_elem(&video_stats, &stat_id);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}


static __always_inline __u32 camera_can_see_position(__u32 camera_id, __u32 x, __u32 y)
{

    if (camera_id < NUM_HORIZONTAL_STRIPS) {
        __u32 y_min = camera_id * STRIP_WIDTH;
        __u32 y_max = (camera_id + 1) * STRIP_WIDTH;
        
        if (y >= y_min && y < y_max) {
            return 0;
        }
        return 1;
    }
    
    if (camera_id < NUM_CAMERAS) {
        __u32 strip_index = camera_id - NUM_HORIZONTAL_STRIPS;
        __u32 x_min = strip_index * STRIP_WIDTH;
        __u32 x_max = (strip_index + 1) * STRIP_WIDTH;
        
        if (x >= x_min && x < x_max) {
            return 0;
        }
        return 1;
    }
    
    return 1;
}

static __always_inline int process_robot_coordinates(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    inc_stat(STAT_ROBOT_POSITION_PKTS);
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;
    
    if (bpf_ntohs(udph->dest) != ROBOT_POSITION_PORT)
        return XDP_PASS;
    
    struct robot_coords_hdr *coords = (void *)(udph + 1);
    if ((void *)(coords + 1) > data_end)
        return XDP_PASS;
    
    __u32 coord_x = bpf_ntohl(coords->coord_x);
    __u32 coord_y = bpf_ntohl(coords->coord_y);
    
    __u32 key_x = 0, key_y = 1;
    bpf_map_update_elem(&robot_coords_debug, &key_x, &coord_x, BPF_ANY);
    bpf_map_update_elem(&robot_coords_debug, &key_y, &coord_y, BPF_ANY);
    
    if (coord_x >= COORD_MAX || coord_y >= COORD_MAX)
        return XDP_PASS;
    
    
    __u32 camera_id;
    __u32 mode;
    
    // Cameras 0-9
    camera_id = 0; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 1; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 2; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 3; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 4; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 5; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 6; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 7; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 8; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 9; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 10-19
    camera_id = 10; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 11; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 12; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 13; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 14; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 15; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 16; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 17; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 18; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 19; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 20-29
    camera_id = 20; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 21; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 22; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 23; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 24; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 25; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 26; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 27; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 28; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 29; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 30-39
    camera_id = 30; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 31; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 32; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 33; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 34; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 35; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 36; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 37; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 38; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 39; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 40-49
    camera_id = 40; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 41; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 42; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 43; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 44; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 45; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 46; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 47; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 48; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 49; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 50-59
    camera_id = 50; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 51; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 52; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 53; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 54; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 55; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 56; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 57; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 58; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 59; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 60-69
    camera_id = 60; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 61; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 62; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 63; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 64; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 65; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 66; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 67; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 68; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 69; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 70-79
    camera_id = 70; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 71; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 72; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 73; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 74; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 75; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 76; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 77; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 78; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 79; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 80-89
    camera_id = 80; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 81; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 82; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 83; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 84; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 85; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 86; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 87; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 88; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 89; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    // Cameras 90-99
    camera_id = 90; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 91; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 92; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 93; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 94; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 95; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 96; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 97; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 98; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    camera_id = 99; mode = camera_can_see_position(camera_id, coord_x, coord_y); bpf_map_update_elem(&camera_filtering_mode, &camera_id, &mode, BPF_ANY);
    
    inc_stat(STAT_ROBOT_COORDS_UPDATED);
    
    return XDP_PASS;
}

static __always_inline int process_video_filter(struct xdp_md *ctx, struct pkt_metadata *meta) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    inc_stat(STAT_TOTAL_PKTS);
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    if (iph->protocol != IPPROTO_UDP) {
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    inc_stat(STAT_UDP_PACKETS);
    
    if (iph->daddr != bpf_htonl(0x0A010102)) {  // 10.1.1.2
        inc_stat(STAT_WRONG_IP);
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;
    

    __u32 dst_port = bpf_ntohs(udph->dest);
    if (dst_port < 5000 || dst_port >= 5000 + NUM_CAMERAS) {
        inc_stat(STAT_WRONG_PORT_RANGE);
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    __u32 camera_id = dst_port - 5000;
    
    if (camera_id >= NUM_CAMERAS) {
        inc_stat(STAT_CAMERA_OUT_OF_RANGE);
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    struct rtp_hdr *rtp = (void *)(udph + 1);
    if ((void *)(rtp + 1) > data_end)
        return XDP_PASS;
    
    __u8 version = (rtp->vpxcc >> 6) & 0x03;
    if (version != 2) {
        inc_stat(STAT_RTP_VERSION_FAIL);
        return XDP_PASS;
    }
    
    inc_stat(STAT_RTP_PKTS);
    
    __u32 *camera_mode = bpf_map_lookup_elem(&camera_filtering_mode, &camera_id);
    
    __u32 active_mode = FILTER_OFF;
    if (camera_mode) {
        active_mode = *camera_mode;
    } else {
        inc_stat(STAT_MAP_LOOKUP_FAILED);
        __u32 mode_key = 0;
        __u32 *mode = bpf_map_lookup_elem(&filtering_mode, &mode_key);
        if (mode) {
            active_mode = *mode;
        }
    }
    
    if (active_mode == FILTER_OFF) {
        inc_stat(STAT_MODE_OFF);
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    } else if (active_mode == FILTER_DROP_P) {
        inc_stat(STAT_MODE_DROP_P);
    } else if (active_mode == FILTER_FORWARD_P) {
        inc_stat(STAT_MODE_FORWARD_P);
    }
    
    struct h265_payload_hdr *ph = (void *)(rtp + 1);
    if ((void *)(ph + 1) > data_end) {
        inc_stat(STAT_FORWARDED);
        return XDP_PASS;
    }
    
    __u8 nal_type = (ph->byte0 >> 1) & 0x3F;
    
    __u32 state_key = 0;
    __u32 *p_frame_flag = bpf_map_lookup_elem(&p_frame_state, &state_key);
    __u32 is_p_frame = p_frame_flag ? *p_frame_flag : 0;
    
    if (active_mode == FILTER_DROP_P) {
        __u8 is_p_slice = 0;
        
        if (nal_type == 49) {
            struct h265_fu_hdr *fu = (void *)(ph + 1);
            if ((void *)(fu + 1) > data_end) {
                inc_stat(STAT_FORWARDED);
                return XDP_PASS;
            }
            
            __u8 start_bit = (fu->s_e_r_type >> 7) & 0x1;
            __u8 end_bit = (fu->s_e_r_type >> 6) & 0x1;
            
            if (start_bit) {
                inc_stat(STAT_FU_START);
                
                __u8 fu_nal_type = fu->s_e_r_type & 0x3F;
                
                if (fu_nal_type >= 1 && fu_nal_type <= 9) {
                    is_p_slice = 1;
                    __u32 new_state = 1;
                    bpf_map_update_elem(&p_frame_state, &state_key, &new_state, BPF_ANY);
                    is_p_frame = 1;
                }
            }
            
            if (is_p_frame) {
                inc_stat(STAT_P_SLICES);
                inc_stat(STAT_DROPPED);
                
                if (end_bit) {
                    __u32 new_state = 0;
                    bpf_map_update_elem(&p_frame_state, &state_key, &new_state, BPF_ANY);
                }
                
                return XDP_DROP;
            }
        } else {
            if (nal_type >= 1 && nal_type <= 9) {
                inc_stat(STAT_P_SLICES);
                inc_stat(STAT_DROPPED);
                return XDP_DROP;
            }
        }
    }
    
    inc_stat(STAT_FORWARDED);
    return XDP_PASS;
}

SEC("freplace/stage2")
int stage2(struct xdp_md *ctx, struct pkt_metadata *meta) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    inc_stat(STAT_STAGE2_ENTRY);
    
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&video_stats, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return process_video_filter(ctx, meta);
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return process_video_filter(ctx, meta);
    
    inc_stat(STAT_IPV4_PACKETS);
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return process_video_filter(ctx, meta);
    
    if (iph->protocol != IPPROTO_UDP)
        return process_video_filter(ctx, meta);
    
    inc_stat(STAT_UDP_PACKETS);
    
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end)
        return process_video_filter(ctx, meta);
    
    inc_stat(STAT_PRE_PORT_CHECK);
    __u32 dst_port = bpf_ntohs(udph->dest);
    
    if (dst_port == ROBOT_POSITION_PORT) {
        inc_stat(STAT_ROBOT_PORT_MATCHED);
        return process_robot_coordinates(ctx);
    }
    
    return process_video_filter(ctx, meta);
}

char _license[] SEC("license") = "GPL";
