package conntracer

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"syscall"
	"unsafe"

	"github.com/elastic/gosigar/sys"
	"github.com/elastic/gosigar/sys/linux"
	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
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

func inetNtop(i uint32) net.IP {
	return net.IP((*(*[net.IPv4len]byte)(unsafe.Pointer(&i)))[:])
}

var (
	byteOrder = sys.GetEndian()
)

func inetDiagReqToBytes(r linux.InetDiagReqV2) []byte {
	buf := bytes.NewBuffer(make([]byte, int(unsafe.Sizeof(linux.InetDiagReqV2{}))))
	buf.Reset()
	if err := binary.Write(buf, byteOrder, r); err != nil {
		// This never returns an error.
		panic(err)
	}
	return buf.Bytes()
}

// getLocalListeningPorts returns the local listening ports
// with netlink API.
func getLocalListeningPorts(protocol uint8) ([]uint16, error) {
	hdr := syscall.NlMsghdr{
		Type:  uint16(linux.SOCK_DIAG_BY_FAMILY),
		Flags: uint16(syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST),
		Pid:   uint32(0),
	}
	var req linux.InetDiagReqV2
	switch protocol {
	case syscall.IPPROTO_TCP:
		req = linux.InetDiagReqV2{
			Family:   uint8(linux.AF_INET),
			Protocol: protocol,
			States:   uint32(linux.TCP_LISTEN),
		}
	case syscall.IPPROTO_UDP:
		req = linux.InetDiagReqV2{
			Family:   uint8(linux.AF_INET),
			Protocol: protocol,
			States:   1<<linux.TCP_CLOSE | 1<<linux.TCP_LISTEN,
		}
	default:
		return []uint16{}, xerrors.Errorf("unexpected protocol %d", protocol)
	}
	nlmsg := syscall.NetlinkMessage{Header: hdr, Data: inetDiagReqToBytes(req)}

	msgs, err := linux.NetlinkInetDiag(nlmsg)
	if err != nil {
		return []uint16{}, xerrors.Errorf("NetlinkInetDiag: %w", err)
	}

	ports := make([]uint16, 0, len(msgs))
	m := map[int]bool{}
	for _, msg := range msgs {
		port := msg.SrcPort()
		if !m[port] {
			m[port] = true
			ports = append(ports, uint16(port))
		}
	}

	return ports, nil
}
