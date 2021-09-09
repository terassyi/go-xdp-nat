package main

import (
	"fmt"
	"net"

	"github.com/dropbox/goebpf"
	"github.com/vishvananda/netlink"
)

type static struct {
	staticNatMap
	bpf goebpf.System
	ifRedirectMap goebpf.Map
	ifIndexMap goebpf.Map
	ifAddrMap goebpf.Map
	ifMacMap goebpf.Map
	natTable goebpf.Map
	program goebpf.Program
}

type staticNatMap struct {
	in netlink.Link
	out netlink.Link
	inAddr net.IP
	outAddr net.IP
	localAddr net.IP
	elfPath string
}

func newStaticNatMap(in, out, inAddr, outAddr, localAddr, elfPath string) (*staticNatMap, error) {
	inL, err := netlink.LinkByName(in)
	if err != nil {
		return nil, err
	}
	outL, err := netlink.LinkByName(out)
	if err != nil {
		return nil, err
	}
	return &staticNatMap {
		in: inL,
		out: outL,
		inAddr: net.ParseIP(inAddr),
		outAddr: net.ParseIP(outAddr),
		localAddr: net.ParseIP(localAddr),
		elfPath: elfPath,
	}, nil
}

func (staticNatMap) Type() NatType {
	return STATIC
}

func newStaticNat(natMap staticNatMap) (*static, error) {
	st := &static{
		staticNatMap: natMap,
	}
	st.bpf = goebpf.NewDefaultEbpfSystem()
	if err := st.bpf.LoadElf(natMap.elfPath); err != nil {
		return nil, err
	}
	st.program = st.bpf.GetProgramByName(NAT_PROG_NAME)
	if st.program == nil {
		return nil, fmt.Errorf("failed to get bpf program: %s", NAT_PROG_NAME)
	}
	st.ifRedirectMap = st.bpf.GetMapByName("if_redirect")
	if st.ifRedirectMap == nil {
		return nil, fmt.Errorf("failed to get bpf map: if_redirect")
	}
	st.ifIndexMap = st.bpf.GetMapByName("if_index_map")
	if st.ifRedirectMap == nil {
		return nil, fmt.Errorf("failed to get bpf map: if_index_map")
	}
	st.ifAddrMap = st.bpf.GetMapByName("if_addr_map")
	if st.ifAddrMap == nil {
		return nil, fmt.Errorf("failed to get bpf map: if_addr_map")
	}
	st.ifMacMap = st.bpf.GetMapByName("if_mac_map")
	if st.ifMacMap == nil {
		return nil, fmt.Errorf("failed to get bpf map: if_mac_map")
	}
	st.natTable = st.bpf.GetMapByName("nat_table")
	if st.natTable == nil {
		return nil, fmt.Errorf("failed to get bpf map: nat_table")
	}
	if err := st.program.Load(); err != nil {
		return nil, err
	}
	return st, nil
}

func (*static) Type() NatType {
	return STATIC
}

func (s *static) Attach() error {
	// in
	if err := s.program.Attach(&goebpf.XdpAttachParams {
		Interface: s.in.Attrs().Name,
		Mode: goebpf.XdpAttachModeSkb,
	}); err != nil {
		return err
	}
	// out
	if err := s.program.Attach(&goebpf.XdpAttachParams {
		Interface: s.out.Attrs().Name,
		Mode: goebpf.XdpAttachModeSkb,
	}); err != nil {
		return err
	}
	return nil
}

func (s *static) Detach() error {
	return s.program.Detach()
}

func (s *static) Prepare() error {
	if err := s.ifRedirectMap.Upsert(uint32(s.in.Attrs().Index), uint32(s.in.Attrs().Index)); err != nil {
		return err
	}
	if err := s.ifRedirectMap.Upsert(uint32(s.out.Attrs().Index), uint32(s.out.Attrs().Index)); err != nil {
		return err
	}
	if err := s.ifIndexMap.Insert(uint32(0), uint32(s.in.Attrs().Index)); err != nil {
		return err
	}
	if err := s.ifIndexMap.Insert(uint32(1), uint32(s.out.Attrs().Index)); err != nil {
		return err
	}
	if err := s.ifAddrMap.Insert(uint32(s.in.Attrs().Index), ipv4ToUint32Little(s.inAddr)); err != nil {
		return err
	}
	if err := s.ifAddrMap.Insert(uint32(s.out.Attrs().Index), ipv4ToUint32Little(s.outAddr)); err != nil {
		return err
	}
	if err := s.ifMacMap.Insert(uint32(s.in.Attrs().Index), []byte(s.in.Attrs().HardwareAddr)); err != nil {
		return err
	}
	if err := s.ifMacMap.Insert(uint32(s.out.Attrs().Index), []byte(s.out.Attrs().HardwareAddr)); err != nil {
		return err
	}
	if err := s.ifAddrMap.Insert(uint32(0), ipv4ToUint32Little(s.localAddr)); err != nil {
		return err
	}
	return nil
}

func (s *static) Run() error {
	for {}
}
