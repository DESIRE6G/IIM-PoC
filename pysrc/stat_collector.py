import subprocess
import json
import time
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS, ASYNCHRONOUS

NIKKS_CTL='./nikss/build/nikss-ctl' 
PIPE_ID = 5
BUFFER_SIZE= 256

token = 'my-token'
org = 'my-org'
bucket = 'my-bucket'

client = InfluxDBClient(url="http://localhost:8086", token=token)
write_api = client.write_api(SYNCHRONOUS)


def parse_counter_data(json_object,counter_name:str):
    data = [ (slot['key']['field0'],slot['value']['bytes']) for slot in json_object[counter_name]['entries'] ]
    data = sorted(data,key=lambda x: int(x[0].split('x')[1],base=16))
    return [ int(x.split('x')[1],base=16) for _,x in data ]


def get_counter_values(counter_name:str):
    p = subprocess.Popen([NIKKS_CTL,'counter','get','pipe',str(PIPE_ID),counter_name],stdout=subprocess.PIPE)
    stdout,_ = p.communicate()
    stdout = stdout.decode()
    data = json.loads(stdout)
    data = parse_counter_data(data,counter_name)
    return data


def main():
    while True:
        stats = get_counter_values('ingress_stats_c')
        drop_stats = get_counter_values('ingress_drop_stats_c')
        print('bytes sent:',stats[0])

        data = [
            Point('BW')
            .tag("kind","total")
            .field("value",stats[0])
            ,
            Point('BW')
            .tag("kind","s1")
            .field("value",stats[1])
            ,
            Point('BW')
            .tag("kind","s2")
            .field("value",stats[2])
            ,
            Point('BW')
            .tag("kind","s3")
            .field("value",stats[3])
            ,
            Point('BW')
            .tag("kind","s4")
            .field("value",stats[4])
            ,
            # drop stats
            Point('D')
            .tag("kind","s1")
            .field("value",drop_stats[1])
            ,
            Point('D')
            .tag("kind","s2")
            .field("value",drop_stats[2])
            ,
            Point('D')
            .tag("kind","s3")
            .field("value",drop_stats[3])
            ,
            Point('D')
            .tag("kind","s4")
            .field("value",drop_stats[4])
        ]
        write_api.write(bucket, org , data,write_precision='ns')

        time.sleep(0.20)


if __name__=='__main__':
    main()