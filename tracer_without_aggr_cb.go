package conntracer

/*
// Due to the restriction of //export,
// function definitions must be placed in preambles in other files.
// https://golang.org/cmd/cgo/#hdr-C_references_to_Go

#cgo CFLAGS: -I${SRCDIR}/include

#include "conntracer.skel.h"
#include "conntracer.h"
*/
import "C"
import (
	"unsafe"
)

//export handleFlow
func handleFlow(ctx unsafe.Pointer, data unsafe.Pointer, dataSZ C.__u32) C.int {
	cflow := (*C.struct_flow)(data)
	saddr := inetNtop((uint32)(cflow.saddr))
	daddr := inetNtop((uint32)(cflow.daddr))
	globalFlowChan <- &Flow{
		SAddr:       &saddr,
		DAddr:       &daddr,
		ProcessName: C.GoString((*C.char)(unsafe.Pointer(&cflow.task))),
		LPort:       ntohs((uint16)(cflow.lport)),
		Direction:   flowDirectionFrom((C.flow_direction)(cflow.direction)),
		LastPID:     (uint32)(cflow.pid),
	}
	return 0
}
