for I in $(echo "1 2 3 4")
do
    P=P$I
    echo "### Testing $P"
    ip netns exec $P-host_a ping -c 10 10.0.$I.2
done