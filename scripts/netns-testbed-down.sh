set -e

./nikss/build/nikss-ctl pipeline unload id 5

arp -d 20.0.0.2
ip link delete R-veth0

for I in $(echo "1 2 3 4")
do
    P=P$I
    ip link delete $P-a-veth0
    ip link delete $P-b-veth0
    ip netns del $P-host_a
    ip netns del $P-host_b
done

echo DONE