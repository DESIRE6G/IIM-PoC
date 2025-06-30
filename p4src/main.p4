#include <core.p4>
#include <psa.p4>

#include "headers.p4"
#include "a_headers.p4"

#define RTP_SRC_PORT 6970
#define RTP_DST_PORT 6970
#define P_SLICE_TYPE 2

header bridged_md_h {
}

struct ingress_metadata_t{
    bit<32> ingress_port;
    bit<32> camera_id;
}

struct headers_t {
    bridged_md_h bridged_meta;
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h  udp;
    rtp_h rtp;
    payload_header_h ph;
    fu_h fu;
    h265_nal_unit_h nal;

    #include "a_hdrlist.p4"
}

parser packet_parser(packet_in pkt, 
                     out headers_t hdr, 
                     inout ingress_metadata_t ig_md,
                     in psa_ingress_parser_input_metadata_t standard_metadata,
                     in empty_t resub_meta,
                     in empty_t recirc_meta) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet{
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4{
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            17 : parse_udp;
            6  : chain_ipv4_tcp; 
            default: accept;
        }
    }

    state parse_udp{
        pkt.extract(hdr.udp);
        transition select(hdr.udp.srcPort){
            RTP_SRC_PORT : parse_rtp;
            default: rtp_versions;
        }
    }

    state rtp_versions{
        transition select(hdr.udp.dstPort){
            RTP_DST_PORT : parse_rtp;
            default: chain_ipv4_udp;
        }
    }

    #include "a_chains.p4"

    #ifndef CHAIN_IPV4_UDP
    state chain_ipv4_udp{
        transition accept;
    }
    #endif

    #ifndef CHAIN_IPV4_TCP
    state chain_ipv4_tcp{
        transition accept;
    }
    #endif

    state parse_rtp{
        pkt.extract(hdr.rtp);
        transition select(hdr.rtp.pt){
             96: parse_payload_header; // parse_fu;
             default: accept;
        }
    }

    state parse_payload_header{
        pkt.extract(hdr.ph);
        transition select(hdr.ph.type){
             49: parse_fu;
             default: accept;
        }
    }

    state parse_fu{
        pkt.extract(hdr.fu); 
        transition check_nal;
    }
    
    state check_nal{
        transition select(hdr.fu.start_bit){
            1: parse_nal;
            default: accept;
        }
    }

    state parse_nal{
        pkt.extract(hdr.nal);
        transition accept;
    }

}

control packet_deparser(packet_out pkt,
                        out empty_t clone_i2e_meta,
                        out empty_t resubmit_meta, 
                        out empty_t normal_meta, 
                        inout headers_t hdr, 
                        in ingress_metadata_t ig_md,
                        in psa_ingress_output_metadata_t istd) {

    apply {
        pkt.emit(hdr);
    }
}

control ingress(inout headers_t hdr,
                inout ingress_metadata_t ig_md,
                in psa_ingress_input_metadata_t standard_metadata,
                inout psa_ingress_output_metadata_t ostd) {

    // *** MANAGING STREAM STATE
    Register<bit<32>,bit<32>>(256,0) filtering_mode; // 0: off ; 1: drop all P frames ; 2: drop every second p-frame
    Register<bit<32>,bit<32>>(256,0) is_it_a_p_frame_r;
    Register<bit<32>,bit<32>>(256,0) drop_state_r;
    Random<bit<32>>(0,1) rnd05;
    
    // *** LOGGING
    Register<bit<32>,bit<32>>(256,0) logger_r;
    Register<bit<16>,bit<16>>(1024,0) terminal_r;

    // *** STATS
    Counter<bit<64>,bit<32>>(256,PSA_CounterType_t.BYTES) stats_c;
    Counter<bit<64>,bit<32>>(256,PSA_CounterType_t.BYTES) drop_stats_c;

    // *** BOTTLENECK
    Meter<bit<32>>(256,PSA_MeterType_t.BYTES) bottleneck_m;

    action print(bit<16> data){
        bit<16> t_index = 0;
        bit<16> t_value = terminal_r.read(t_index);
        t_index = t_value+1;
        if (t_index==0) t_index=1;
        terminal_r.write(t_index,data);
        t_value = t_index;
        t_index = 0;
        terminal_r.write(t_index,t_value);
    }

    action inc_log(bit<32> index){
        bit<32> value = logger_r.read(index);
        value = value + 1;
        logger_r.write(index,value);
    }

    bit<32> camera_id = 0;
    bit<32> mode = 0;
    bit<32> index = 0;
    bit<32> value = 0;
    bit<32> is_p_frame;
    bool is_p_slice = false;


    action drop(){
        ingress_drop(ostd);
    }

    action send_to(bit<32> port){
        PortIdUint_t tmp = (PortIdUint_t)port;
        send_to_port(ostd,(PortId_t)tmp);
    }

    action send_to2(PortId_t port){
        send_to_port(ostd,port);
    }


    table static_port_fwd{
        key = { standard_metadata.ingress_port: exact; }
        actions = { NoAction; send_to2; }
        const default_action = NoAction;
    }

    action set_camera_id(bit<32> cid){
        camera_id = cid;
        ig_md.camera_id = cid;
    }

    table ip_to_camera_id{
        key = { hdr.ipv4.src_addr: exact; }
        actions = { NoAction; set_camera_id; }
        const default_action = NoAction;
        const entries = {
            0x0a000101 : set_camera_id(1);
            0x0a000201 : set_camera_id(2);
            0x0a000301 : set_camera_id(3);
            0x0a000401 : set_camera_id(4);
        }
    }

    action set_is_p_slice(bool b){
        is_p_slice = b;
    }

    table p_slice_detector{
        key = { hdr.nal.data: ternary; }
        actions = { set_is_p_slice; }
        const default_action = set_is_p_slice(false);
        const entries = {
           0b1101_0000_0000_0000 &&& 0b1011_1000_0000_0000 : set_is_p_slice(true);
           0b0100_0000_0000_0010 &&& 0b1000_0000_0000_0111 : set_is_p_slice(true);    
        }
    }

    action set_filtering_mode(bit<32> camera_id,bit<32> mode){
        filtering_mode.write(camera_id,mode);
    }

    #include "a_declarations.p4"

    apply {
        ostd.drop = false;

        // *** simple static forwarding
        PortIdUint_t tmp = (PortIdUint_t) standard_metadata.ingress_port;
        ig_md.ingress_port = (bit<32>) tmp;
        static_port_fwd.apply();

        // *** stream management
        if (hdr.fu.isValid()){
                // get camera id
                ip_to_camera_id.apply();

                // check the filtering configuration
                mode = filtering_mode.read(camera_id);
            
            if (mode==1){ // MODE 1: FILTER OUT EVERY P FRAME
                // log total number of inspected packets
                inc_log(0);
                
                // check if it is the start of a p-frame
                if (hdr.fu.start_bit == 1){
                    // log the start fragments
                    inc_log(2);

                    //print(hdr.nal.data);
                    p_slice_detector.apply();
                    if (is_p_slice){
                        // log the p-slice start fragments
                        inc_log(3);

                        // store that we are transmitting a p-frame
                        value = 1;
                        is_it_a_p_frame_r.write(camera_id,value);
                    }
                }

                // drop if this packet belongs to a p-frame
                is_p_frame = is_it_a_p_frame_r.read(camera_id);
                if (is_p_frame == 1){
                    // log dropped packets
                    inc_log(1);

                    // drop the packet
                    drop();
                }
                
                // check if it is the end of a p-frame
                if (hdr.fu.end_bit == 1 && is_p_frame == 1){
                    value = 0;
                    is_it_a_p_frame_r.write(camera_id,value);
                }
            }
            else if (mode==2){ // MODE 2: FILTER OUT EVERY SECOND P FRAME
                // log total number of inspected packets
                inc_log(0);
                
                // check if it is the start of a p-frame
                if (hdr.fu.start_bit == 1){
                    // log the start fragments
                    inc_log(2);

                    //print(hdr.nal.data);
                    p_slice_detector.apply();

                    if (is_p_slice){
                        // update drop state (looking for every second p-frame)
                        bit<32> should_drop = drop_state_r.read(camera_id);
                        should_drop = (should_drop + 1) % 2;
                        drop_state_r.write(camera_id,should_drop);
                        if (should_drop==1){
                            is_p_slice = false;
                        }
                    }

                    if (is_p_slice){
                        // log the p-slice start fragments
                        inc_log(3);

                        // store that we are transmitting a p-frame
                        value = 1;
                        is_it_a_p_frame_r.write(camera_id,value);
                    }
                }

                // drop if this packet belongs to a p-frame
                is_p_frame = is_it_a_p_frame_r.read(camera_id);
                if (is_p_frame == 1){
                    // log dropped packets
                    inc_log(1);

                    // drop the packet
                    drop();
                }
                
                // check if it is the end of a p-frame
                if (hdr.fu.end_bit == 1 && is_p_frame == 1){
                    value = 0;
                    is_it_a_p_frame_r.write(camera_id,value);
                }
            }
            else if (mode==3){ // MODE 3: FILTER OUT P FRAMES WITH A 0.5 PROBABILITY
                // log total number of inspected packets
                inc_log(0);
                
                // check if it is the start of a p-frame
                if (hdr.fu.start_bit == 1){
                    // log the start fragments
                    inc_log(2);

                    //print(hdr.nal.data);
                    p_slice_detector.apply();

                    if (is_p_slice){
                        // update drop state (looking for every second p-frame)
                        bit<32> should_drop = rnd05.read();
                        if (should_drop==1){
                            is_p_slice = false;
                        }
                    }

                    if (is_p_slice){
                        // log the p-slice start fragments
                        inc_log(3);

                        // store that we are transmitting a p-frame
                        value = 1;
                        is_it_a_p_frame_r.write(camera_id,value);
                    }
                }

                // drop if this packet belongs to a p-frame
                is_p_frame = is_it_a_p_frame_r.read(camera_id);
                if (is_p_frame == 1){
                    // log dropped packets
                    inc_log(1);

                    // drop the packet
                    drop();
                }
                
                // check if it is the end of a p-frame
                if (hdr.fu.end_bit == 1 && is_p_frame == 1){
                    value = 0;
                    is_it_a_p_frame_r.write(camera_id,value);
                }
            }




        }
        else{
            #include "a_apply.p4"
        }

        // *** artifical bottleneck
        if (!ostd.drop){
            bit<32> index = 0;
            PSA_MeterColor_t color = bottleneck_m.execute(index);
            if (color!=PSA_MeterColor_t.GREEN){
                drop();
            }
        }

        // *** calculate stats
        bit<32> index = 0;
        if (!ostd.drop){
            stats_c.count(index); // total bw
            if (camera_id!=0)
                stats_c.count(camera_id); // per flow bw
        }
        else{
            if (camera_id!=0)
                drop_stats_c.count(camera_id);
        }
    }

}

control egress(inout headers_t hdr,
               inout empty_t eg_md,
               in psa_egress_input_metadata_t istd,
               inout psa_egress_output_metadata_t ostd) {

    apply {
    }
}

parser egress_parser(packet_in pkt,
                     out headers_t hdr,
                     inout empty_t eg_md,
                     in psa_egress_parser_input_metadata_t istd,
                     in empty_t normal_meta,
                     in empty_t clone_i2e_meta,
                     in empty_t clone_e2e_meta) {

    state start {
        pkt.extract(hdr.bridged_meta);
        transition accept;
    }
}

control egress_deparser(packet_out pkt,
                        out empty_t clone_e2e_meta, 
                        out empty_t recirculate_meta, 
                        inout headers_t hdr, 
                        in empty_t eg_md, 
                        in psa_egress_output_metadata_t istd, 
                        in psa_egress_deparser_input_metadata_t edstd) {

    apply {
        pkt.emit(hdr);
    }
}


IngressPipeline(packet_parser(), ingress(), packet_deparser()) ip;

EgressPipeline(egress_parser(), egress(), egress_deparser()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
