package conntracer

/*
// Due to the restriction of //export,
// function definitions must be placed in preambles in other files.
// https://golang.org/cmd/cgo/#hdr-C_references_to_Go
#cgo CFLAGS: -I${SRCDIR}/include

#include <stddef.h>

#include "conntracer.skel.h"
#include "conntracer.h"

int handleFlow(void *ctx, void *data, size_t data_sz);
*/
import "C"
import (
	"log"
	"unsafe"
)

//export handleFlow
func handleFlow(ctx unsafe.Pointer, data unsafe.Pointer, dataSZ C.size_t) C.int {
	cflow := (*C.struct_flow)(data)
	saddr := inetNtop((uint32)(cflow.saddr))
	daddr := inetNtop((uint32)(cflow.daddr))
	log.Printf("insert flow: %s\n", saddr)
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
