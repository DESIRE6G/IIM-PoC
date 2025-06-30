#!/bin/bash

# This script streams a sample video file and captures it using vlc.
# The netns testbed should be set up befor executing this script.
#   - host_a is the streamer
#   - host_b is the receiver
# The logs and other artifacts are stored in the "capture" folder.

VIDEO_FILE=sample-videos/test_1280x720_HEVC-v2.mp4

alias myvlc='vlc-wrapper'
#'sudo -H -u gycsaba vlc '

# * clean
rm -f -r capture
sudo -H -u gycsaba mkdir capture

# * start tcpdum to capture the received stream
ip netns exec host_b tcpdump -i b-veth1 -w capture/capture.pcap udp &
TCPDUMP_PID=$!

# * start streaming
ip netns exec host_a sudo -H -u gycsaba vlc --intf dummy -vvv $VIDEO_FILE --loop --sout '#rtp{sdp=rtsp://10.0.1.1:8080/test.sdp}' 2> capture/camera.log &
CAMERA_PID=$!

sleep 2

# * receive stream
ip netns exec host_b ffmpeg  -min_port 6970 -max_port 6972 -i 'rtsp://10.0.1.1:8080/test.sdp?Port=6970' -vcodec copy -acodec copy -f segment -segment_time 120 -segment_format mp4 "capture/received-%03d.mp4" > capture/receiver-stdout.log 2> capture/receiver-stderr.log &
RECEIVER_PID=$!

# * wait until the end and kill processes if neccessaire
trap "kill $TCPDUMP_PID $RECEIVER_PID $CAMERA_PID" EXIT
sleep 90
sudo kill $TCPDUMP_PID $RECEIVER_PID $CAMERA_PID
echo OK
