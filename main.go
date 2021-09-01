package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dropbox/goebpf"
)

var NAT_TYPE_LIST []string = []string{"icmp_only"}

func main() {
	var natType, in, out, inAddr, outAddr, mapedAddr string
	flag.StringVar(&natType, "type", "", "NAT type")
	flag.StringVar(&in, "in", "", "inside LAN interface.")
	flag.StringVar(&out, "out", "", "outside LAN interface.")
	flag.StringVar(&inAddr, "in_addr", "", "inside interface address.")
	flag.StringVar(&outAddr, "out_addr", "", "outside interface address.")
	flag.StringVar(&mapedAddr, "maped", "", "static maped local address.")
	flag.Parse()

	typ, err := NewNatType(natType)
	if err != nil {
		fmt.Println("Please specify NAT type: ", err)
		os.Exit(1)
	}

	nat, err := newNat(typ, in, out, inAddr, outAddr, mapedAddr)
	if err != nil {
		fmt.Println("NAT configuration error: ", err)
		os.Exit(1)
	}

	fmt.Println("--- NAT by Golang + XDP ---")
	showIfaceInfo(nat.in)
	showIfaceInfo(nat.out)

	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.LoadElf("bpf/" + nat.typ.String() + ".elf"); err != nil {
		fmt.Println("failed to load elf: ", err)
		os.Exit(1)
	}
	prog := bpf.GetProgramByName(nat.typ.String())
	if prog == nil {
		fmt.Println("failed to get a xdp program: ", nat.typ.String())
		os.Exit(1)
	}
	ifRedirectMap := bpf.GetMapByName("if_redirect")
	if ifRedirectMap == nil {
		fmt.Println("failed to get a bpf map: if_redirect")
	}
	ifIndexMap := bpf.GetMapByName("ifindex_map")
	if ifIndexMap == nil {
		fmt.Println("failed to get a bpf map: ifindex_map")
		os.Exit(1)
	}
	ifAddrMap := bpf.GetMapByName("ifaddr_map")
	if ifAddrMap == nil {
		fmt.Println("failed to get a bpf map: ifaddr_map")
		os.Exit(1)
	}
	ifMacMap := bpf.GetMapByName("if_mac_map")
	if ifMacMap == nil {
		fmt.Println("failed to get a bpf map: if_mac_map")
		os.Exit(1)
	}
	if err := prog.Load(); err != nil {
		fmt.Println("failed to laod xdp program: ", err)
		os.Exit(1)
	}
	if err := nat.attachXdp(prog, ifRedirectMap, ifIndexMap, ifAddrMap, ifMacMap); err != nil {
		fmt.Println("failed to attachXdp: ", err)
		os.Exit(1)
	}
	defer prog.Detach()

	for {}
}

