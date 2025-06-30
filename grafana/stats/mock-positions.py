
import random
import time
from datetime import datetime
import os
from influxdb_client import InfluxDBClient, Point, WritePrecision
import random

from influxdb_client.client.write_api import SYNCHRONOUS, ASYNCHRONOUS
# You can generate a Token from the "Tokens Tab" in the UI
token = 'my-token'
org = 'my-org'
bucket = 'my-bucket'

client = InfluxDBClient(url="http://localhost:8086", token=token)
write_api = client.write_api(SYNCHRONOUS)

measurement = "entity_position"
tags = {"entity_id": "1"}
fields = {"x": 50, "y": 50}
pathx = list(range(10,50)) #[10, 20, 10, 20, 30, 40, 50, 40, 30, 20]
pathy = list(range(20,60)) #[30, 30, 20, 30, 40, 30, 20, 30, 20, 20]
i = 0
while True:
    i = (i+1) % len(pathx)
    print(i)
    fields["x"] = pathx[i]
    fields["y"] = pathy[i]
    write_api.write(bucket=bucket, org=org, record=[{"measurement": measurement, "tags": tags, "fields": fields}])
    time.sleep(0.1)

