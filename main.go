package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	STATIC_ELF string = "bpf/static.elf"
)

func main() {
	var natType, in, out, inAddr, outAddr, mapedAddr string
	flag.StringVar(&natType, "type", "", "NAT type")
	flag.StringVar(&in, "in", "", "inside LAN interface.")
	flag.StringVar(&out, "out", "", "outside LAN interface.")
	flag.StringVar(&inAddr, "in_addr", "", "inside interface address.")
	flag.StringVar(&outAddr, "out_addr", "", "outside interface address.")
	flag.StringVar(&mapedAddr, "maped", "", "static maped local address.")
	flag.Parse()

	typ := NewNatType(natType)
	if typ == UNKNOWN {
		fmt.Println("Please specify NAT type.")
		os.Exit(1)
	}

	switch typ {
	case STATIC:
		sMap, err := newStaticNatMap(in, out, inAddr, outAddr, mapedAddr, STATIC_ELF)
		if err != nil {
			panic(err)
		}
		sNat, err := newStaticNat(*sMap)
		if err != nil {
			panic(err)
		}
		if err := sNat.Attach(); err != nil {
			panic(err)
		}
		defer sNat.Detach()
		if err := sNat.Prepare(); err != nil {
			panic(err)
		}

	}

	for {}
}

