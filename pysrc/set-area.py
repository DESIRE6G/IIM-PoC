
import random
import time
from datetime import datetime
import os
from influxdb_client import InfluxDBClient, Point, WritePrecision
import random
import sys

from influxdb_client.client.write_api import SYNCHRONOUS, ASYNCHRONOUS
# You can generate a Token from the "Tokens Tab" in the UI
token = 'my-token'
org = 'my-org'
bucket = 'my-bucket'


ENTITY_ID = sys.argv[1]
A_X,A_Y,B_X,B_Y = [ int(x) for x in sys.argv[2:6] ] 


client = InfluxDBClient(url="http://localhost:8086", token=token)
write_api = client.write_api(SYNCHRONOUS)

measurement = "area_position"
tags = {"entity_id": ENTITY_ID}
fields = {f"x_{ENTITY_ID}": None, f"y_{ENTITY_ID}": None}

area_a = [(A_X,A_Y), (A_X,B_Y), (B_X,B_Y), (B_X,A_Y), (A_X,A_Y)]
for i in area_a:
    fields[f"x_{ENTITY_ID}"] = i[0]
    fields[f"y_{ENTITY_ID}"] = i[1]
    write_api.write(bucket=bucket, org=org, record=[{"measurement": measurement, "tags": tags, "fields": fields}])

