set -e

function get_camera_ip
{
	# 192.168.1.1: the local ip that connects to the camera
	nmap -sn 192.168.1.1/24 | grep -o -P -e '192\.168\.1\.\d+' | grep -v -e "192.168.1.1$"
}

#CAMERA_IP=$(get_camera_ip)
#echo "RUN THE FOLLOWING ON THE PKTGEN SERVER:"
#echo "route add -host $CAMERA_IP dev enp10s0"
#sleep 10


# load eBPF pipeline
./nikss/build/nikss-ctl pipeline load id 5 ./out/out.o

# add interfaces
sudo ip link set dev enp2s0 up
sudo ip link set dev enp4s0 up
tc qdisc del dev enp2s0 clsact || true
tc qdisc del dev enp4s0 clsact || true
sudo ip link set enp2s0 promisc on
sudo ip link set enp4s0 promisc on
PORT_A=$(./nikss/build/nikss-ctl add-port pipe 5 dev enp2s0 | jq -r '.port_id' ) # this is for the camera
PORT_B=$(./nikss/build/nikss-ctl add-port pipe 5 dev enp4s0 | jq -r '.port_id' ) # this is for the pktgen server as 11.11.11.2
echo "P4 ports: $PORT_A $PORT_B"

# add ports
echo "P4 ports: $PORT_A $PORT_B"
./nikss/build/nikss-ctl table add pipe 5 ingress_static_port_fwd action name ingress_send_to2 key $PORT_A data $PORT_B
./nikss/build/nikss-ctl table add pipe 5 ingress_static_port_fwd action name ingress_send_to2 key $PORT_B data $PORT_A

echo "ports added"

echo DONE
