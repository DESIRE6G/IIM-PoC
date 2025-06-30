#!/bin/bash

# This script streams a sample video between multiple sender and receiver pairs.
# The netns testbed should be set up befor executing this script.
#   - $P-host_a is the streamer
#   - $P-host_b is the receiver
#
# $1: the ID of the sender receiver pair (1..4)

I=$1
P=P$I

VIDEO_FILE=sample-videos/test_1280x720_HEVC-v2.mp4


# * start streaming
ip netns exec $P-host_a sudo -H -u gycsaba vlc --intf dummy -vvv $VIDEO_FILE --loop --sout "#rtp{sdp=rtsp://10.0.$I.1:8080/test.sdp}" 2> capture/$P-camera.log &
CAMERA_PID=$!

sleep 2

# * receive stream
ip netns exec $P-host_b ffmpeg  -min_port 6970 -max_port 6972 -i "rtsp://10.0.$I.1:8080/test.sdp?Port=6970" -vcodec copy -acodec copy -f segment -segment_time 120 -segment_format mp4 "capture/$P-received-%03d.mp4" > capture/$P-receiver-stdout.log 2> capture/$P-receiver-stderr.log &
RECEIVER_PID=$!

# * wait until the end and kill processes if neccessaire
trap "kill $TCPDUMP_PID $RECEIVER_PID $CAMERA_PID" EXIT
sleep 90
sudo kill $TCPDUMP_PID $RECEIVER_PID $CAMERA_PID
echo OK
