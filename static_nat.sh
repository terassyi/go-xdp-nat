#!/bin/bash

BUILD="build"
CLEAN="clean"

if [ "$BUILD" = "$1" ]; then
	sudo ip netns add r-router # regional router
	sudo ip netns add nat1 # stub router nat for lan a
	sudo ip netns add nat2 # stub router nat for lan b
	sudo ip netns add host1 # host1 in lan a
	sudo ip netns add host2 # host2 in lan b
	sudo ip netns add host3 # host3 in lan a(test for proxy arp)

	sudo ip link add h1-v0 type veth peer n1-l
	sudo ip link add h2-v0 type veth peer n2-l
	sudo ip link add h1-v1 type veth peer h3-v0
	sudo ip link add n1-w type veth peer rr-n1
	sudo ip link add n2-w type veth peer rr-n2

	sudo ip link set h1-v0 netns host1
	sudo ip link set h1-v1 netns host1
	sudo ip link set h2-v0 netns host2
	sudo ip link set h3-v0 netns host3
	sudo ip link set n1-l netns nat1
	sudo ip link set n2-l netns nat2
	sudo ip link set n1-w netns nat1
	sudo ip link set n2-w netns nat2
	sudo ip link set rr-n1 netns r-router
	sudo ip link set rr-n2 netns r-router

	sudo ip netns exec host1 ip addr add 10.33.96.5/8 dev h1-v0
	sudo ip netns exec host1 ip addr add 10.33.96.6/8 dev h1-v1
	sudo ip netns exec host2 ip addr add 10.81.13.22/8 dev h2-v0
	sudo ip netns exec host3 ip addr add 10.33.96.7/8 dev h3-v0
	sudo ip netns exec nat1 ip addr add 198.76.29.7/24 dev n1-w
	sudo ip netns exec nat1 ip addr add 10.33.96.1/8 dev n1-l
	sudo ip netns exec nat2 ip addr add 198.76.28.4/24 dev n2-w
	sudo ip netns exec nat2 ip addr add 10.81.13.1/8 dev n2-l
	sudo ip netns exec r-router ip addr add 198.76.29.1/24 dev rr-n1
	sudo ip netns exec r-router ip addr add 198.76.28.1/24 dev rr-n2

	sudo ip netns exec host1 ip link set up h1-v0
	sudo ip netns exec host1 ip link set up h1-v1
	sudo ip netns exec host1 ip link set up lo
	sudo ip netns exec host2 ip link set up h2-v0
	sudo ip netns exec host2 ip link set up lo
	sudo ip netns exec host3 ip link set up lo
	sudo ip netns exec host3 ip link set up h3-v0
	sudo ip netns exec nat1 ip link set up n1-l
	sudo ip netns exec nat1 ip link set up n1-w
	sudo ip netns exec nat1 ip link set up lo
	sudo ip netns exec nat2 ip link set up n2-l
	sudo ip netns exec nat2 ip link set up n2-w
	sudo ip netns exec nat2 ip link set up lo
	sudo ip netns exec r-router ip link set up rr-n1
	sudo ip netns exec r-router ip link set up rr-n2
	sudo ip netns exec r-router ip link set up lo

	sudo ip netns exec host1 ip route add default via 10.33.96.5
	sudo ip netns exec host2 ip route add default via 10.81.13.22
	sudo ip netns exec nat1 ip route add default via 198.76.29.1
	sudo ip netns exec nat2 ip route add default via 198.76.28.1
	sudo ip netns exec nat1 ip route add 10.0.0.0/8 via 10.33.96.1
	sudo ip netns exec nat2 ip route add 10.0.0.0/8 via 10.81.13.1
	sudo ip netns exec r-router ip route add 198.76.28.0/24 via 198.76.28.1
	sudo ip netns exec r-router ip route add 198.76.29.0/24 via 198.76.29.1


elif [ "$CLEAN" = "$1" ]; then
	sudo ip netns del r-router
	sudo ip netns del nat1
	sudo ip netns del nat2
	sudo ip netns del host1
	sudo ip netns del host2
	sudo ip netns del host3
else
	echo "help:"
	echo "	build: build a network to test with netns"
	echo "	clean: clean up a network"
fi


