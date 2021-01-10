// +build linux
// +build 386 arm amd64

package conntracer_test

import (
	"fmt"
	"time"

	conntracer "github.com/yuuki/go-conntracer-bpf"
)

func Example() {
	// Load bpf program to kernel.
	t, err := conntracer.NewTracer()
	if err != nil {
		fmt.Println("failed to prepare tracer: ", err)
		return
	}
	defer t.Close()

	cb := func(flows []*conntracer.Flow) error {
		for _, flow := range flows {
			fmt.Printf("%v\n", flow)
		}
		return nil
	}

	// Start process of periodically polling network flows.
	t.Start(cb, 1*time.Second)

	// Stop process of polling them.
	t.Stop()
}
