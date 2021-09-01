package main

import (
	"net"
	"testing"
)

func TestIpv4ToUint32(t *testing.T) {
	addr := net.ParseIP("192.168.1.1")
	val := ipv4ToUint32Big([]byte(addr))
	if val != 3232235777 {
		t.Fatalf("actual: %d(%x)", val, val)
	}
}

func TestPutUint32ToUint64(t *testing.T) {
	val := putUint32ToUint64(uint32(3232235777), uint32(1))
	if val != 0xc0a8010100000001 {
		t.Fatalf("actual: %d(%x)", val, val)
	}
}

func TestToLittleEndian(t *testing.T) {
	big := []byte{0x86,0x51,0x58,0x4b,0x4d,0x90}
	little := []byte{0x90,0x4d,0x4b,0x58,0x51,0x86}
	res := toLittleEndian(big)
	for i, r := range res {
		if r != little[i] {
			t.Fatalf("failed to convert to little endian.")
		}
	}
}
