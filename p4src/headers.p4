
struct empty_t {
}

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4>  ver;
    bit<4>  ihl;
    bit<8>  tos;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header rtp_h{
    bit<2> version;
    bit<1> p;
    bit<1> x;
    bit<4> cc;
    bit<1> m;
    bit<7> pt;
    bit<16> sequence_number;
    bit<32> timestamp;
    bit<32> ssrc_id; 
}

header payload_header_h{
    // H.265 / FU identifier
    bit<1> f;
    bit<6> type;
    bit<6> layer_id;
    bit<3> tid;
}

header fu_h{
    // H.265 / FU Header 
    bit<1> start_bit;
    bit<1> end_bit;
    bit<1> _reserved;
    bit<5> nal_unit_type;
}

header h265_nal_unit_h{
    //NOTE: the representation should look like this, bit the bit<11> filed is not compiled correctly
    //bit<1>  _reserved;
    //bit<1>  slice_pic_parameter_set_id;
    //bit<11> slice_segment_address;
    //bit<3>  slice_type;
    bit<16> data;
}

