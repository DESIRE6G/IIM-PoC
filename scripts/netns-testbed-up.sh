set -e

# load ebpf pipeline
./nikss/build/nikss-ctl pipeline load id 5 ./out/out.o

# add a link for the robot
ip link add R-veth1 type veth peer name R-veth0
ifconfig R-veth0 up
ifconfig R-veth1 up
./nikss/build/nikss-ctl add-port pipe 5 dev R-veth0
ip addr add 20.0.0.1/16 dev R-veth1
arp -s 20.0.0.2 00:aa:bb:aa:bb:aa

# add camera-receiver pairs
for I in $(echo "1 2 3 4") 
do
    P=P$I
    echo "# Setting up $P sender-receiver pair"

    # create network namespaces an veth-pairs
    ip netns add $P-host_a
    ip netns add $P-host_b
    ip link add $P-a-veth1 type veth peer name $P-a-veth0
    ip link add $P-b-veth1 type veth peer name $P-b-veth0
    ip link set $P-a-veth1 netns $P-host_a
    ip link set $P-b-veth1 netns $P-host_b
    ip -n $P-host_a addr add 10.0.$I.1/16 dev $P-a-veth1
    ip -n $P-host_b addr add 10.0.$I.2/16 dev $P-b-veth1

    # add links to the p4-switch and set static forwarding rules
    PORT_A=$(./nikss/build/nikss-ctl add-port pipe 5 dev $P-a-veth0 | jq -r '.port_id' )
    PORT_B=$(./nikss/build/nikss-ctl add-port pipe 5 dev $P-b-veth0 | jq -r '.port_id' )
    echo "P4 ports: $PORT_A $PORT_B"
    ./nikss/build/nikss-ctl table add pipe 5 ingress_static_port_fwd action name ingress_send_to2 key $PORT_A data $PORT_B
    ./nikss/build/nikss-ctl table add pipe 5 ingress_static_port_fwd action name ingress_send_to2 key $PORT_B data $PORT_A

    # bring up interfaces
    ip netns exec $P-host_a ifconfig $P-a-veth1 up
    ip netns exec $P-host_b ifconfig $P-b-veth1 up
    ip netns exec $P-host_a ifconfig lo up
    ip netns exec $P-host_b ifconfig lo up
    ifconfig $P-a-veth0 up
    ifconfig $P-b-veth0 up

    echo "# $P configured"
done

echo DONE
