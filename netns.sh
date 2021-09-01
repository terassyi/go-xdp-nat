#!/bin/bash

BUILD="build"
CLEAN="clean"

if [ "$BUILD" = "$1" ]; then
	sudo ip netns add node1 # end node
	sudo ip netns add node2 # router
	sudo ip netns add napt0 # self host napt

	sudo ip link add veth0 type veth peer np-veth0 netns napt0
	sudo ip link add np-veth1 type veth peer n1-veth0 netns node1
	sudo ip link add n1-veth1 type veth peer n2-veth0 netns node2
	sudo ip link set np-veth1 netns napt0
	sudo ip link set n1-veth1 netns node1

	sudo ip addr add 192.168.0.254/24 dev veth0
	sudo ip netns exec napt0 ip addr add 192.168.0.1/24 dev np-veth0
	sudo ip netns exec napt0 ip addr add 192.168.1.1/24 dev np-veth1
	sudo ip netns exec node1 ip addr add 192.168.1.254/24 dev n1-veth0
	sudo ip netns exec node1 ip addr add 192.168.2.1/24 dev n1-veth1
	sudo ip netns exec node2 ip addr add 192.168.2.2/24 dev n2-veth0

	sudo ip link set up dev veth0
	sudo ip netns exec napt0 ip link set up dev np-veth0
	sudo ip netns exec napt0 ip link set up dev np-veth1
	sudo ip netns exec node1 ip link set up dev n1-veth0
	sudo ip netns exec node1 ip link set up dev n1-veth1
	sudo ip netns exec node2 ip link set up dev n2-veth0

	sudo ip route add 192.168.2.0/24 via 192.168.0.254 dev veth0
	sudo ip netns exec napt0 ip route add default via 192.168.0.1 dev np-veth0
	sudo ip netns exec node1 ip route add default via 192.168.1.254 dev n1-veth0
	sudo ip netns exec node2 ip route add default via 192.168.2.2 dev n2-veth0

elif [ "$CLEAN" = "$1" ]; then
	sudo ip netns del node1
	sudo ip netns del node2
	sudo ip netns del napt0
	sudo ip link del dev veth0
else
	echo "help:"
	echo "	build: build a network to test with netns"
	echo "	clean: clean up a network"
fi
