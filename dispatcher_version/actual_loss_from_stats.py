#!/usr/bin/env python3
"""
Calculate ACTUAL loss by combining TX pcap analysis with XDP drop stats.
Calculate ACTUAL delay by matching TX and RX packets.
This gives a real measurement of what XDP actually dropped and real latency.

Usage:
    python actual_loss_from_stats.py --tx-pcap <tx.pcap> --rx-pcap <rx.pcap> --interval 0.5
"""

import argparse
import json
import os
import time
import signal
import sys
import subprocess
from scapy.all import PcapReader, IP, UDP
import struct


def parse_port_range(range_str: str):
    start_s, end_s = range_str.split("-")
    return int(start_s), int(end_s)


def extract_rtp_seq(udp_payload):
    """Extract RTP sequence number and timestamp"""
    if len(udp_payload) < 12:
        return None, None
    payload = bytes(udp_payload)
    version = (payload[0] >> 6) & 0x03
    if version != 2:
        return None, None
    seq = struct.unpack("!H", payload[2:4])[0]
    rtp_ts = struct.unpack("!I", payload[4:8])[0]
    return seq, rtp_ts


def in_range(port: int, port_range):
    start, end = port_range
    return start <= port <= end


def normalize_flow_port(src_port: int, dst_port: int, port_range):
    if in_range(dst_port, port_range):
        return dst_port
    if in_range(src_port, port_range):
        return src_port
    return None


def is_p_slice(pkt):
    """Detect if packet contains H.265 P-slice"""
    try:
        udp_payload = bytes(pkt[UDP].payload)
        if len(udp_payload) < 12:
            return False
        rtp_payload = udp_payload[12:]
        if len(rtp_payload) < 2:
            return False
        
        # H.265 NAL unit type detection
        nal_type = (rtp_payload[0] >> 1) & 0x3F
        
        if nal_type == 49 and len(rtp_payload) >= 3:
            fu_header = rtp_payload[2]
            fu_nal_type = fu_header & 0x3F
            return 1 <= fu_nal_type <= 9
        
        return 1 <= nal_type <= 9
    except Exception:
        return False


def read_xdp_stat(stat_key):
    """Read XDP stat from BPF map"""
    try:
        result = subprocess.run(
            ["sudo", "bpftool", "map", "dump", "pinned", "/sys/fs/bpf/xdp_pipeline/video_stats"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode != 0:
            return 0
        
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if f'"key": {stat_key},' in line:
                if i + 1 < len(lines):
                    value_line = lines[i + 1]
                    if '"value":' in value_line:
                        value_str = value_line.split('"value":')[1].strip().rstrip(',')
                        return int(value_str)
        return 0
    except Exception:
        return 0


class ActualLossMonitor:
    def __init__(self, tx_pcap, rx_pcap, interval, port_range):
        self.tx_pcap = tx_pcap
        self.rx_pcap = rx_pcap
        self.interval = interval
        self.port_range = port_range
        
        self.window_start_time = None
        self.tx_packets = {}
        self.rx_packets = {}
        self.last_debug_time = 0
        self.prev_xdp_dropped = 0
        self.prev_xdp_forwarded = 0

    def process_tx_packet(self, pkt, pkt_time):
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return
        port = normalize_flow_port(int(pkt[UDP].sport), int(pkt[UDP].dport), self.port_range)
        if port is None:
            return
        
        seq, rtp_ts = extract_rtp_seq(pkt[UDP].payload)
        if seq is None or rtp_ts is None:
            return
        
        if self.window_start_time is None:
            self.window_start_time = pkt_time
        
        key = (port, seq, rtp_ts)
        is_p = is_p_slice(pkt)
        self.tx_packets[key] = (pkt_time, is_p)
    
    def process_rx_packet(self, pkt, pkt_time):
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return
        port = normalize_flow_port(int(pkt[UDP].sport), int(pkt[UDP].dport), self.port_range)
        if port is None:
            return
        
        seq, rtp_ts = extract_rtp_seq(pkt[UDP].payload)
        if seq is None or rtp_ts is None:
            return
        
        key = (port, seq, rtp_ts)
        self.rx_packets[key] = pkt_time

    def calculate_and_send(self):
        if not self.tx_packets:
            return

        xdp_dropped = read_xdp_stat(4)
        xdp_forwarded = read_xdp_stat(5)
        
        dropped_delta = xdp_dropped - self.prev_xdp_dropped
        forwarded_delta = xdp_forwarded - self.prev_xdp_forwarded
        
        self.prev_xdp_dropped = xdp_dropped
        self.prev_xdp_forwarded = xdp_forwarded
        
        total_tx = len(self.tx_packets)
        p_frame_tx = sum(1 for (_, (_, is_p)) in self.tx_packets.items() if is_p)
        non_p_tx = total_tx - p_frame_tx
        
        matched_count = 0
        delay_sum_ms = 0.0
        delay_count = 0
        for key, (tx_ts, is_p) in self.tx_packets.items():
            rx_ts = self.rx_packets.get(key)
            if rx_ts is not None and rx_ts >= tx_ts:
                matched_count += 1
                delay_sum_ms += (rx_ts - tx_ts) * 1000.0
                delay_count += 1
        
        avg_delay_ms = (delay_sum_ms / delay_count) if delay_count else 0.0
        total_lost = total_tx - matched_count
        intended_lost = dropped_delta
        unintended_lost = max(0, total_lost - intended_lost)
        
        loss_percent = (total_lost / total_tx * 100) if total_tx else 0.0
        intended_loss_percent = (intended_lost / total_tx * 100) if total_tx else 0.0
        unintended_loss_percent = (unintended_lost / total_tx * 100) if total_tx else 0.0
        
        now = time.time()
        if now - self.last_debug_time >= 10:
            print(
                f"[DEBUG] TX: {total_tx} pkts ({p_frame_tx} P={p_frame_tx*100//total_tx if total_tx else 0}%, {non_p_tx} non-P), "
                f"RX: {matched_count} matched, "
                f"XDP: {dropped_delta} dropped (intended), "
                f"Total loss: {total_lost} ({loss_percent:.1f}%), "
                f"Intended: {intended_lost} ({intended_loss_percent:.1f}%), "
                f"Unintended: {unintended_lost} ({unintended_loss_percent:.1f}%), "
                f"Delay: {avg_delay_ms:.3f}ms",
                file=sys.stderr,
                flush=True,
            )
            self.last_debug_time = now

        payload = {
            "delay_ms": round(avg_delay_ms, 3),
            "loss_percent": round(loss_percent, 3),
            "unintended_loss_percent": round(unintended_loss_percent, 3),
            "total_tx_packets": total_tx,
            "total_rx_packets": matched_count,
            "total_lost_packets": total_lost,
            "total_unintended_lost_packets": unintended_lost,
            "intended_loss_percent": round(intended_loss_percent, 3),
            "intended_lost_packets": intended_lost,
        }
        print(json.dumps(payload), flush=True)
        
        self.tx_packets = {}
        self.rx_packets = {}
        self.window_start_time = None

    def run(self):
        print(f"[STARTUP] Monitoring TX={self.tx_pcap}, RX={self.rx_pcap}, + XDP stats", file=sys.stderr, flush=True)
        
        self.prev_xdp_dropped = read_xdp_stat(4)
        self.prev_xdp_forwarded = read_xdp_stat(5)
        print(f"[STARTUP] XDP baseline: {self.prev_xdp_dropped} dropped, {self.prev_xdp_forwarded} forwarded", file=sys.stderr, flush=True)
        
        while not os.path.exists(self.tx_pcap) or not os.path.exists(self.rx_pcap):
            time.sleep(0.5)

        tx_reader = None
        rx_reader = None
        last_metrics = time.time()

        try:
            while True:
                now = time.time()

                if tx_reader is None:
                    try:
                        tx_reader = PcapReader(self.tx_pcap)
                    except Exception:
                        pass
                
                if tx_reader:
                    try:
                        pkt = tx_reader.read_packet()
                        if pkt:
                            pkt_time = float(pkt.time) if hasattr(pkt, "time") else now
                            self.process_tx_packet(pkt, pkt_time)
                    except EOFError:
                        pass

                if rx_reader is None:
                    try:
                        rx_reader = PcapReader(self.rx_pcap)
                    except Exception:
                        pass
                
                if rx_reader:
                    try:
                        pkt = rx_reader.read_packet()
                        if pkt:
                            pkt_time = float(pkt.time) if hasattr(pkt, "time") else now
                            self.process_rx_packet(pkt, pkt_time)
                    except EOFError:
                        pass

                if now - last_metrics >= self.interval:
                    self.calculate_and_send()
                    last_metrics = now

                time.sleep(0.001)
        except KeyboardInterrupt:
            print("[SHUTDOWN] Stopping...", file=sys.stderr, flush=True)
        finally:
            if tx_reader:
                tx_reader.close()
            if rx_reader:
                rx_reader.close()


def main():
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser()
    parser.add_argument("--tx-pcap", required=True)
    parser.add_argument("--rx-pcap", required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--port-range", default="5000-5099")

    args = parser.parse_args()
    try:
        port_range = parse_port_range(args.port_range)
        ActualLossMonitor(args.tx_pcap, args.rx_pcap, args.interval, port_range).run()
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    main()
