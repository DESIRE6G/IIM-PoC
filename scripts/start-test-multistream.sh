#!/bin/bash

# This script streams a sample video between a given sender and receiver pairs.
# The netns testbed should be set up befor executing this script.
#   - $P-host_a is the streamer
#   - $P-host_b is the receiver
#
# $1: the ID of the sender receiver pair (1..4)

I=$1
P=P$I

VIDEO_FILE=sample-videos/test_1280x720_HEVC-v2.mp4

# * clean
rm -f -r capture
sudo -H -u gycsaba mkdir capture

# * starting workers
for I in $(seq 4)
do
    sleep 10
    bash scripts/start-test-multistream-worker.sh $I &
done

sleep 150

# * killing subprocesses
for pid in $(pstree -ATp $$ | grep '([0-9]*)' -o | grep '[0-9]*' -o )
do
    if [ $$ != $pid ]
    then
        kill $pid
    fi
done
