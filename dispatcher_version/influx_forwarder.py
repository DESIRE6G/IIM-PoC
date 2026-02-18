#!/usr/bin/env python3
"""
InfluxDB Forwarder
Reads JSON metrics from stdin and forwards to InfluxDB
"""

import sys
import json
from datetime import datetime
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# InfluxDB Configuration
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "my-super-secret-auth-token"
INFLUXDB_ORG = "myorg"
INFLUXDB_BUCKET = "network_metrics"

def main():
    # Initialize InfluxDB client
    print(f"Connecting to InfluxDB at {INFLUXDB_URL}...", file=sys.stderr)
    client = InfluxDBClient(
        url=INFLUXDB_URL,
        token=INFLUXDB_TOKEN,
        org=INFLUXDB_ORG
    )
    write_api = client.write_api(write_options=SYNCHRONOUS)
    
    try:
        health = client.health()
        print(f"InfluxDB Status: {health.status}", file=sys.stderr)
        
        for line in sys.stdin:
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
                
            try:
                data = json.loads(line)
                
                # Create InfluxDB point
                measurement_type = "aggregate"
                if "intended_loss_percent" in data or "intended_lost_packets" in data:
                    measurement_type = "loss"
                point = (
                    Point("network_metrics")
                    .tag("measurement_type", measurement_type)
                    .field("delay_ms", data["delay_ms"])
                    .field("loss_percent", data["loss_percent"])
                    .field("unintended_loss_percent", data["unintended_loss_percent"])
                    .field("total_tx_packets", data["total_tx_packets"])
                    .field("total_rx_packets", data["total_rx_packets"])
                    .field("total_lost_packets", data["total_lost_packets"])
                    .field("total_unintended_lost_packets", data["total_unintended_lost_packets"])
                )

                if "intended_loss_percent" in data:
                    point = point.field("intended_loss_percent", data["intended_loss_percent"])
                if "intended_lost_packets" in data:
                    point = point.field("intended_lost_packets", data["intended_lost_packets"])
                
                write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] "
                      f"Forwarded: delay={data['delay_ms']:.2f}ms, loss={data['loss_percent']:.1f}%, "
                      f"unintended={data['unintended_loss_percent']:.1f}%", file=sys.stderr)
                      
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error forwarding to InfluxDB: {e}", file=sys.stderr)
                
    finally:
        client.close()

if __name__ == "__main__":
    main()
