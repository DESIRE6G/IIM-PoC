#!/bin/bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo"
    exit 1
fi

ACTUAL_USER=${SUDO_USER:-$USER}
NUM_STREAMS=${1:-100}
BOTTLENECK_MBPS=${2:-200}

INFLUXDB_URL="http://localhost:8086"
INFLUXDB_TOKEN="my-super-secret-auth-token"
INFLUXDB_ORG="myorg"
INFLUXDB_BUCKET="network_metrics"

if [ -d "/home/$ACTUAL_USER/dispatcher/venv" ]; then
    PYTHON_BIN="/home/$ACTUAL_USER/dispatcher/venv/bin/python3"
elif [ -d "venv" ]; then
    PYTHON_BIN="$PWD/venv/bin/python3"
else
    PYTHON_BIN="python3"
fi

if [ $NUM_STREAMS -lt 1 ] || [ $NUM_STREAMS -gt 100 ]; then
    echo "Error: num_streams must be between 1 and 100"
    echo "Usage: sudo $0 [num_streams]"
    exit 1
fi

echo "==== Robot-Based Filtering Test (100 Cameras) ===="

# Cleanup
cleanup() {
    echo "Cleaning up..."
    
    # Stop packet captures
    if [ ! -z "$TCPDUMP_TX_PID" ]; then
        kill $TCPDUMP_TX_PID 2>/dev/null || true
    fi
    if [ ! -z "$TCPDUMP_RX_PID" ]; then
        kill $TCPDUMP_RX_PID 2>/dev/null || true
    fi
    
    # Stop metrics monitor
    if [ ! -z "$METRICS_MONITOR_PID" ]; then
        kill $METRICS_MONITOR_PID 2>/dev/null || true
    fi
    
    pkill -f "mock-robot.py" 2>/dev/null || true
    pkill -f "robot_simulator.py" 2>/dev/null || true
    pkill -f "live_metrics_monitor.py" 2>/dev/null || true
    pkill -f "loss_to_influx.py" 2>/dev/null || true
    pkill -f "influx_forwarder.py" 2>/dev/null || true
    pkill -f "vlc.*HEVC" 2>/dev/null || true  
    pkill -f "ffmpeg.*udp" 2>/dev/null || true
    pkill -f "tcpdump.*veth" 2>/dev/null || true

    ip netns exec testns tc qdisc del dev veth1 ingress 2>/dev/null || true
    ip netns exec testns tc qdisc del dev ifb0 root 2>/dev/null || true
    ip netns exec testns ip link set ifb0 down 2>/dev/null || true
    ip netns exec testns ip link del ifb0 2>/dev/null || true

    ip link set veth1 xdp off 2>/dev/null || true
    ip netns del testns 2>/dev/null || true
    rm -rf /sys/fs/bpf/xdp* 2>/dev/null || true
}

trap cleanup EXIT

echo "Setting up network namespace..."
ip netns del testns 2>/dev/null || true
ip link del veth0 2>/dev/null || true
ip netns add testns
ip link add veth0 type veth peer name veth1
ip addr add 10.1.1.1/24 dev veth0
ip link set veth0 up
ip addr add 10.1.1.3/24 dev veth1
ip link set veth1 up

echo "Compiling eBPF..."
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c bpf/xdp_dispatcher.c -o bpf/xdp_dispatcher.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c bpf/stage1_passthrough.c -o bpf/stage1_passthrough.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c bpf/stage2_video_filter.c -o bpf/stage2_video_filter.o

echo "Loading XDP programs..."
rm -rf /sys/fs/bpf/xdp* /sys/fs/bpf/stage* 2>/dev/null || true
mkdir -p /sys/fs/bpf/xdp_pipeline

bpftool prog load bpf/xdp_dispatcher.o /sys/fs/bpf/xdp_disp \
    type xdp pinmaps /sys/fs/bpf/xdp_pipeline 2>&1 | grep -v "libbpf:"

ip link set dev veth1 xdpgeneric pinned /sys/fs/bpf/xdp_disp 2>&1

DISP_ID=$(bpftool prog show pinned /sys/fs/bpf/xdp_disp --json | jq -r '.id')
if [ -f "./attach_ext" ]; then
    ./attach_ext bpf/stage1_passthrough.o $DISP_ID stage1 /sys/fs/bpf/stage1_ext 2>&1 | grep -v "libbpf:"
else
    bpftool prog load bpf/stage1_passthrough.o /sys/fs/bpf/stage1_ext \
        type ext pinmaps /sys/fs/bpf/xdp_pipeline 2>&1 | grep -v "libbpf:"
    bpftool prog attach pinned /sys/fs/bpf/stage1_ext \
        freplace pinned /sys/fs/bpf/xdp_disp target_name stage1 2>&1
fi

if [ -f "./attach_ext" ]; then
    ./attach_ext bpf/stage2_video_filter.o $DISP_ID stage2 /sys/fs/bpf/stage2_ext 2>&1 | grep -v "libbpf:"
else
    bpftool prog load bpf/stage2_video_filter.o /sys/fs/bpf/stage2_ext \
        type ext pinmaps /sys/fs/bpf/xdp_pipeline 2>&1 | grep -v "libbpf:"
    bpftool prog attach pinned /sys/fs/bpf/stage2_ext \
        freplace pinned /sys/fs/bpf/xdp_disp target_name stage2 2>&1
fi

bpftool map update pinned /sys/fs/bpf/xdp_pipeline/control_map \
    key hex 00 00 00 00 value hex 01 00 00 00 2>&1

bpftool map update pinned /sys/fs/bpf/xdp_pipeline/control_map \
    key hex 01 00 00 00 value hex 01 00 00 00 2>&1

ip link set veth1 down
ip addr del 10.1.1.3/24 dev veth1 2>/dev/null || true
ip link set veth1 netns testns
ip netns exec testns ip addr add 10.1.1.2/24 dev veth1
ip netns exec testns ip link set veth1 up
ip netns exec testns ip link set lo up

modprobe ifb numifbs=1 2>/dev/null || true
ip netns exec testns ip link add ifb0 type ifb 2>/dev/null || ip netns exec testns ip link set ifb0 down
ip netns exec testns ip link set ifb0 up

ip netns exec testns tc qdisc del dev veth1 ingress 2>/dev/null || true
ip netns exec testns tc qdisc add dev veth1 ingress
ip netns exec testns tc filter add dev veth1 parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0

ip netns exec testns tc qdisc del dev ifb0 root 2>/dev/null || true
ip netns exec testns tc qdisc add dev ifb0 root tbf rate ${BOTTLENECK_MBPS}mbit burst 32kbit latency 400ms


for camera_id in {0..99}; do
    key_hex=$(printf "%02x %02x %02x %02x" $((camera_id & 0xFF)) $(((camera_id >> 8) & 0xFF)) $(((camera_id >> 16) & 0xFF)) $(((camera_id >> 24) & 0xFF)))
    sudo bpftool map update pinned /sys/fs/bpf/xdp_pipeline/camera_filtering_mode \
        key hex $key_hex value hex 00 00 00 00 2>/dev/null
done

sleep 2

echo "Starting $NUM_STREAMS camera stream(s)..."

mkdir -p logs

VLC_PIDS=()
FFMPEG_PIDS=()

for i in $(seq 0 $((NUM_STREAMS - 1))); do
    RTP_PORT=$((5000 + i))
    
    sudo -u $ACTUAL_USER ffmpeg \
        -f lavfi -i testsrc=size=1280x720:rate=30 \
        -c:v libx265 \
        -preset ultrafast \
        -x265-params "keyint=4:min-keyint=4:scenecut=0:bframes=0" \
        -g 4 \
        -sc_threshold 0 \
        -pix_fmt yuv420p \
        -f rtp rtp://10.1.1.2:$RTP_PORT \
        > logs/ffmpeg_streamer_camera${i}.log 2>&1 &
    
    VLC_PIDS+=($!)
    
    ip netns exec testns ffmpeg -i "udp://10.1.1.2:$RTP_PORT" \
        -vcodec copy -acodec copy -f null - \
        > logs/ffmpeg_receiver_camera${i}.log 2>&1 &
    FFMPEG_PIDS+=($!)
done

sleep 5

STREAMER_RUNNING=$(ps aux | grep 'ffmpeg.*rtp://10.1.1.2:50' | grep -v grep | wc -l)
RECEIVER_RUNNING=$(ps aux | grep 'ffmpeg.*udp://10.1.1.2:50' | grep -v grep | wc -l)
SOCKETS_LISTENING=$(netstat -an 2>/dev/null | grep -E ':(500[0-9]|50[1-9][0-9])' | wc -l)

ROBOT_PKTS=$(sudo bpftool map dump pinned /sys/fs/bpf/xdp_pipeline/video_stats 2>/dev/null | grep -A1 '"key": 6,' | grep value | awk '{print $2}' | tr -d ',' || echo 0)
ROBOT_UPDATES=$(sudo bpftool map dump pinned /sys/fs/bpf/xdp_pipeline/video_stats 2>/dev/null | grep -A1 '"key": 12,' | grep value | awk '{print $2}' | tr -d ',' || echo 0)
ROBOT_PORT_MATCHED=$(sudo bpftool map dump pinned /sys/fs/bpf/xdp_pipeline/video_stats 2>/dev/null | grep -A1 '"key": 13,' | grep value | awk '{print $2}' | tr -d ',' || echo 0)

if [ "$ROBOT_PORT_MATCHED" -gt "$ROBOT_PKTS" ]; then
    echo "    ⚠ More port matches than processed packets - validation failing!"
fi

if [ "$ROBOT_PKTS" -gt 0 ] && [ "$ROBOT_UPDATES" -lt "$ROBOT_PKTS" ]; then
    LOSS_PCT=$(echo "scale=1; ($ROBOT_PKTS - $ROBOT_UPDATES) * 100 / $ROBOT_PKTS" | bc)
    echo "    ⚠ ${LOSS_PCT}% of robot packets didn't complete full camera mode updates!"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_DIR="pcaps_robot_${TIMESTAMP}"
mkdir -p $PCAP_DIR

tcpdump -i veth0 -w ${PCAP_DIR}/tx_before_filter.pcap -n -s 65535 'udp portrange 5000-5099' &
TCPDUMP_TX_PID=$!

ip netns exec testns tcpdump -i veth1 -w ${PCAP_DIR}/rx_after_filter.pcap -n -s 65535 'udp portrange 5000-5099' &
TCPDUMP_RX_PID=$!

$PYTHON_BIN -u actual_loss_from_stats.py \
    --tx-pcap ${PCAP_DIR}/tx_before_filter.pcap \
    --rx-pcap ${PCAP_DIR}/rx_after_filter.pcap \
    --interval 0.5 \
    2> logs/loss_to_influx.log | \
    sudo -u $ACTUAL_USER $PYTHON_BIN -u influx_forwarder.py \
    2> logs/influx_forwarder.log &
METRICS_MONITOR_PID=$!

echo
echo "Monitoring network metrics"
echo "Touch /tmp/enable_filtering to activate robot-based filtering"
echo "To stop the test, press Ctrl+C"
echo

FILTERING_ENABLED=false
ROBOT_PID=""
MEASUREMENT_INTERVAL=5
ITERATION=0
PREV_TX_BYTES=$(cat /sys/class/net/veth0/statistics/tx_bytes 2>/dev/null || echo 0)
PREV_IP_STATS=""

while true; do
    sleep $MEASUREMENT_INTERVAL
    ITERATION=$((ITERATION + 1))
    
    if [ "$FILTERING_ENABLED" = "false" ] && [ -f /tmp/enable_filtering ]; then
        echo
        echo "FILTERING ACTIVATION TRIGGERED!"
        echo
        
        sudo -E "$PYTHON_BIN" -u robot_simulator.py \
            --center-x 500 \
            --center-y 500 \
            --radius 0 \
            --duration 60 \
            --update-hz 2 \
            --loops 0 \
            > logs/robot_simulator.log 2>&1 &
        
        ROBOT_PID=$!
        FILTERING_ENABLED=true
        
        sleep 3
        
        if ! ps -p $ROBOT_PID > /dev/null 2>&1; then
            echo "WARNING: Robot process died"
        fi
        
        echo "Filtering now ACTIVE"
        
        rm -f /tmp/enable_filtering
    fi
    
    active_count=$(sudo bpftool map dump pinned /sys/fs/bpf/xdp_pipeline/camera_filtering_mode 2>/dev/null | \
        grep -c '"value": 0' || echo 0)
    filtering_count=$(sudo bpftool map dump pinned /sys/fs/bpf/xdp_pipeline/camera_filtering_mode 2>/dev/null | \
        grep -c '"value": 1' || echo 0)
    
    if [ "$FILTERING_ENABLED" = "true" ]; then
        MODE_STATUS="FILTERING ACTIVE ($filtering_count cameras)"
    else
        MODE_STATUS="NO FILTERING ($active_count cameras unfiltered)"
    fi
    
    CUR_TX_BYTES=$(cat /sys/class/net/veth0/statistics/tx_bytes 2>/dev/null || echo 0)
    BYTES_DELTA=$((CUR_TX_BYTES - PREV_TX_BYTES))
    PREV_TX_BYTES=$CUR_TX_BYTES
    THROUGHPUT_MBPS=$(echo "scale=1; $BYTES_DELTA * 8 / $MEASUREMENT_INTERVAL / 1000000" | bc)
    
    if [ $((ITERATION % 12)) -eq 0 ]; then
        IP_STATS=$(ip -s link show veth0 2>/dev/null | grep -A1 "TX:" | tail -1 | awk '{print $1}')
        if [ ! -z "$IP_STATS" ]; then
            if [ ! -z "$PREV_IP_STATS" ]; then
                IP_DELTA=$((IP_STATS - PREV_IP_STATS))
                IP_THROUGHPUT=$(echo "scale=1; $IP_DELTA * 8 / 60 / 1000000" | bc)
            fi
            PREV_IP_STATS=$IP_STATS
        fi
    fi
    
    if [ "$FILTERING_ENABLED" = "true" ]; then
        DROPPED_NOW=$(sudo bpftool map dump pinned /sys/fs/bpf/xdp_pipeline/video_stats 2>/dev/null | grep -A1 '"key": 4,' | grep value | awk '{print $2}' | tr -d ',' || echo 0)
        echo "T+$((ITERATION*MEASUREMENT_INTERVAL))s: $MODE_STATUS P-drops: $DROPPED_NOW"
    else
        echo "T+$((ITERATION*MEASUREMENT_INTERVAL))s: $MODE_STATUS"
    fi
done

