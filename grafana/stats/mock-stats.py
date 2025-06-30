
import random
import math
import time
from datetime import datetime
import os
from influxdb_client import InfluxDBClient, Point, WritePrecision

from influxdb_client.client.write_api import SYNCHRONOUS, ASYNCHRONOUS
# You can generate a Token from the "Tokens Tab" in the UI
token = 'my-token'
org = 'my-org'
bucket = 'my-bucket'

client = InfluxDBClient(url="http://localhost:8086", token=token)
write_api = client.write_api(SYNCHRONOUS)

bw = [0]*4
i=0
while True:
    i+=1
    bw = [ b+round((2+math.sin((i+50*s)/50))*200) for b,s in zip(bw,range(4)) ] 
    data = [
        Point('BW')
        .tag("kind","total")
        .field("value",sum(bw))
#        .time(int(datetime.now().timestamp()))
    
    ,Point('BW')
        .tag("kind","s1")
        .field("value",bw[0])
    ,Point('BW')
        .tag("kind","s2")
        .field("value",bw[1])
    ,Point('BW')
        .tag("kind","s3")
        .field("value",bw[2])
    ,Point('BW')
        .tag("kind","s4")
        .field("value",bw[3])

    ]
    write_api.write(bucket, org , data,write_precision='ns')
    print(bw)
    time.sleep(0.1)