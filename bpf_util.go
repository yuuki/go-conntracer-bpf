package conntracer

import (
	"encoding/binary"
	"math"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func bumpMemlockRlimit() error {
	rl := unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return err
	}
	return nil
}

func ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&i)))[:])
}

func inetNtop(i uint16) net.IP {
	return net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&i)))[:])
}
