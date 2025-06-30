import socket
import struct
import argparse
import time

# Try to reach InfluxDB if possible
try:
    from influxdb_client import InfluxDBClient, Point, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS, ASYNCHRONOUS

    token = 'my-token'
    org = 'my-org'
    bucket = 'my-bucket'

    client = InfluxDBClient(url="http://localhost:8086", token=token)
    write_api = client.write_api(SYNCHRONOUS)

    measurement = "entity_position"
    tags = {"entity_id": "1"}
except:
    print("Couldn't connect to InfluxDB")


parser = argparse.ArgumentParser()
parser.add_argument("--interactive", help="read positions from the standard input interactively",
                    action="store_true")
parser.add_argument("--step-interval", help="time (s) between two steps",default=0.1,type=float)
parser.add_argument("--dst-ip", help="IPv4 address of the destination",default="20.0.0.2",type=str)
parser.add_argument("--dst-port", help="UDP destination port",default="5555",type=int)


args = parser.parse_args()

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)


def report_position(x:int,y:int):
    s.sendto(struct.pack('!II',x,y),(args.dst_ip,args.dst_port))
    try:
            write_api.write(bucket=bucket, org=org, record=[{"measurement": measurement, "tags": tags, "fields": {"x":x,"y":y}}])
    except:
        print("Couldn't write InfluxDB")
    print('Sent:',x,y)

def interactive_mode():
    print("type 'quit' to exit")
    while True:
        try:
            cmd = input('x,y> ')
            if cmd.strip()=='quit':
                break
            x,y = cmd.split()
            x,y = int(x),int(y)
            report_position(x,y)
        except Exception as e:
            print(e)


def get_rectangle_trajectory(ax,ay,bx,by):
    return (
        [ (ax,ay) ]*10 
        +
        [ ( x,ay) for x in range(ax,bx)]
        + 
        [ (bx,ay) ]*10
        +
        [ (bx, y) for y in range(ay,by)]
        +
        [ (bx,by) ]*10
        +
        [ ( x,by) for x in reversed(range(ax,bx))]
        + 
        [ (ax,by) ]*10
        +
        [ (ax, y) for y in reversed(range(ay,by))]
    )


def automated_mode():
    while True:
        for x,y in get_rectangle_trajectory(25,25,75,75):
            report_position(x,y)
            time.sleep(args.step_interval)


if args.interactive:
    interactive_mode()
else:
    automated_mode()