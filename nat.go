package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

type Nat interface {
	Type() NatType
	Attach() error
	Prepare() error
	Run() error
	Detach() error
}

type NatMap interface {
	Type() NatType
}

type NatType int

const (
	STATIC NatType = iota
	DYNAMIC NatType = iota
	NAPT NatType = iota
	UNKNOWN NatType = -1
)

const (
	NAT_PROG_NAME string = "nat_prog"
)

func NewNatType(typ string) NatType {
	switch typ {
	case STATIC.String():
		return STATIC
	case DYNAMIC.String():
		return DYNAMIC
	case NAPT.String():
		return NAPT
	default:
		return UNKNOWN
	}

}
func (t NatType) String() string {
	switch t {
	case STATIC:
		return "static"
	case DYNAMIC:
		return "dynamic"
	case NAPT:
		return "napt"
	default:
		return ""
	}
}

func New(typ NatType, natMap NatMap) (Nat, error) {
	switch typ {
	case STATIC:
		return newStaticNat(natMap.(staticNatMap))
	default:
		return nil, fmt.Errorf("invalid NAT type")
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
