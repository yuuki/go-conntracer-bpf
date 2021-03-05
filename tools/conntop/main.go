package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"time"

	conntracer "github.com/yuuki/go-conntracer-bpf"
)

var interval time.Duration
var userAggr bool
var kernelAggr bool
var prof bool

func init() {
	log.SetFlags(0)
	runtime.GOMAXPROCS(1)

	flag.DurationVar(&interval, "interval", 3*time.Second, "polling interval (default 3s)")
	flag.BoolVar(&userAggr, "user-aggr", false, "in user space aggregation")
	flag.BoolVar(&kernelAggr, "kernel-aggr", false, "in kernel space aggregation")
	flag.BoolVar(&prof, "prof", false, "pprof http://localhost:6060")
	flag.Parse()
}

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	log.Printf("Waiting interval %s for flows to be collected...\n", interval)

	if prof {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	if !kernelAggr && !userAggr {
		// default is kernelAggr
		kernelAggr = true
	}

	if kernelAggr {
		runKernelAggr(sig)
		return
	}
	if userAggr {
		runUserAggr(sig)
		return
	}
}

func runKernelAggr(sig chan os.Signal) {
	t, err := conntracer.NewTracer()
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer t.Close()

	printFlow := func(flows []*conntracer.Flow) error {
		for _, flow := range flows {
			switch flow.Direction {
			case conntracer.FlowActive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-20s %-10d\n", flow.SAddr, flow.DAddr, flow.LPort, flow.LastPID, flow.ProcessName, flow.Stat.NewConnections)
			case conntracer.FlowPassive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-20s %-10d\n", flow.DAddr, flow.SAddr, flow.LPort, flow.LastPID, flow.ProcessName, flow.Stat.NewConnections)
			default:
				log.Printf("wrong direction '%d'\n", flow.Direction)
			}
		}
		return nil
	}

	if err := t.Start(printFlow, interval); err != nil {
		log.Println(err)
		return
	}

	// print header
	fmt.Printf("%-25s %-25s %-20s %-10s %-20s %-10s\n", "LADDR", "RADDR", "LPORT", "PID", "COMM", "CONNECTIONS")

	ret := <-sig
	t.Stop()

	log.Printf("Received %v, Goodbye\n", ret)
}

type connAggrTuple struct {
	SAddr string
	DAddr string
	LPort uint16
}

func runUserAggr(sig chan os.Signal) {
	t, err := conntracer.NewTracerWithoutAggr()
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer t.Close()

	flowChan := make(chan *conntracer.Flow)
	go t.Start(flowChan)

	printFlow := func(flow *conntracer.Flow) {
		switch flow.Direction {
		case conntracer.FlowActive:
			fmt.Printf("%-25s %-25s %-20d %-10d %-10s\n",
				flow.SAddr, flow.DAddr, flow.LPort, flow.LastPID, flow.ProcessName)
		case conntracer.FlowPassive:
			fmt.Printf("%-25s %-25s %-20d %-10d %-10s\n",
				flow.DAddr, flow.SAddr, flow.LPort, flow.LastPID, flow.ProcessName)
		}
	}

	// print header
	fmt.Printf("%-25s %-25s %-20s %-10s %-10s\n", "LADDR", "RADDR", "LPORT", "PID", "COMM")

	var aggrFlows sync.Map

	// polling aggrFlows
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				aggrFlows.Range(func(key, value interface{}) bool {
					printFlow(value.(*conntracer.Flow))
					aggrFlows.Delete(key)
					return true
				})
			}
		}
	}()

	for {
		select {
		case flow := <-flowChan:
			tuple := connAggrTuple{SAddr: flow.SAddr.String(), DAddr: flow.DAddr.String(), LPort: flow.LPort}
			aggrFlows.Store(tuple, flow)
		case ret := <-sig:
			t.Stop()
			log.Printf("Received %v, Goodbye\n", ret)
			return
		}
	}

	return
}
