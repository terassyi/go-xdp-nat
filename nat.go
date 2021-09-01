package main

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/dropbox/goebpf"
)

type Nat struct {
	typ NatType
	in netlink.Link
	out netlink.Link
	inAddr net.IP
	outAddr net.IP
	local net.IP
}

type NatType int

const (
	ICMP_ONLY NatType = iota

	INVALID NatType = iota
)

func newNat(typ NatType, in, out, inAddr, outAddr, local string) (*Nat, error) {
	inL, err := netlink.LinkByName(in)
	if err != nil {
		return nil, err
	}
	outL, err := netlink.LinkByName(out)
	if err != nil {
		return nil, err
	}
	return &Nat {
		typ: typ,
		in: inL,
		out: outL,
		inAddr: net.ParseIP(inAddr),
		outAddr: net.ParseIP(outAddr),
		local : net.ParseIP(local),
	}, nil
}

func (n *Nat) attachXdp(prog goebpf.Program, ifRedirectMap, ifInfoMap, ifAddrMap, ifMacMap goebpf.Map) error {
	// in
	if err := prog.Attach(&goebpf.XdpAttachParams{
		Interface: n.in.Attrs().Name,
		Mode: goebpf.XdpAttachModeSkb,
	}); err != nil {
		return err
	}
	if err := ifRedirectMap.Upsert(n.in.Attrs().Index, n.in.Attrs().Index); err != nil {
// 	if err := ifRedirectMap.Insert(1, 1); err != nil {
		return err
	}
	if err := ifInfoMap.Insert(uint32(0), uint32(n.in.Attrs().Index)); err != nil {
		return err
	}
	if err := ifAddrMap.Insert(uint32(n.in.Attrs().Index), ipv4ToUint32Little(n.inAddr)); err != nil {
		return err
	}
	if err := ifMacMap.Insert(uint32(n.in.Attrs().Index), []byte(n.in.Attrs().HardwareAddr)); err != nil {
		return err
	}
	// out
	if err := prog.Attach(&goebpf.XdpAttachParams{
		Interface: n.out.Attrs().Name,
		Mode: goebpf.XdpAttachModeSkb,
	}); err != nil {
		return err
	}
	if err := ifRedirectMap.Upsert(n.out.Attrs().Index, n.out.Attrs().Index); err != nil {
		return err
	}
	if err := ifInfoMap.Insert(uint32(1), uint32(n.out.Attrs().Index)); err != nil {
		return err
	}
	if err := ifAddrMap.Insert(uint32(n.out.Attrs().Index), ipv4ToUint32Big(n.outAddr)); err != nil {
		return err
	}
	if err := ifMacMap.Insert(uint32(n.out.Attrs().Index), []byte(n.out.Attrs().HardwareAddr)); err != nil {
		return err
	}
	if err := ifAddrMap.Upsert(uint32(0), ipv4ToUint32Big(n.local)); err != nil {
		fmt.Println("hogehoge")
		return err
	}
	return nil
}

func (nt NatType) String() string {
	switch nt {
	case ICMP_ONLY:
		return "icmp_only"
	default:
		return ""
	}
}

func NewNatType(typ string) (NatType, error) {
	switch typ {
	case ICMP_ONLY.String():
		return ICMP_ONLY, nil
	default:
		return INVALID, fmt.Errorf("invalid NAT type.")
	}
}


func showIfaceInfo(iface netlink.Link) {
	addrs, _ := netlink.AddrList(iface, 4)
	fmt.Printf("- name: %s\n", iface.Attrs().Name)
	fmt.Printf("\t- index: %d\n", iface.Attrs().Index)
	fmt.Printf("\t- ip_addr: %v\n", addrs)
	fmt.Printf("\t- mac_addr: %s\n", iface.Attrs().HardwareAddr)
}

func parseMacAddr(addr []byte) string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x", addr[0],addr[1],addr[2],addr[3],addr[4],addr[5])
}
