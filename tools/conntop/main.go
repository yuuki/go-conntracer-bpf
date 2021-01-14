package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	conntracer "github.com/yuuki/go-conntracer-bpf"
)

var interval time.Duration
var streaming bool

func init() {
	log.SetFlags(0)

	flag.DurationVar(&interval, "interval", 3*time.Second, "polling interval (default 3s)")
	flag.BoolVar(&streaming, "streaming", false, "without aggregation (default false)")
	flag.Parse()
}

func main() {
	if streaming {
		runStreaming()
		return
	}

	t, err := conntracer.NewTracer()
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer t.Close()

	printFlows := func() {
		flows, err := t.DumpFlows()
		if err != nil {
			log.Printf("could not dump flows: %v", err)
			return
		}
		for _, flow := range flows {
			switch flow.Direction {
			case conntracer.FlowActive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-10d\n", flow.SAddr, flow.DAddr, flow.LPort, flow.LastPID, flow.Stat.NewConnections)
			case conntracer.FlowPassive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-10d\n", flow.DAddr, flow.SAddr, flow.LPort, flow.LastPID, flow.Stat.NewConnections)
			}
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	log.Printf("Waiting interval %s for flows to be collected...\n", interval)
	// print header
	fmt.Printf("%-25s %-25s %-20s %-10s %-10s\n", "LADDR", "RADDR", "LPORT", "PID", "CONNECTIONS")

	stopChan := make(chan struct{})
	go func() {
		tick := time.NewTicker(interval)
		printFlows()
		for {
			select {
			case <-tick.C:
				printFlows()
			case <-stopChan:
				tick.Stop()
				return
			}
		}
	}()

	ret := <-sig
	stopChan <- struct{}{}

	log.Printf("Received %v, Goodbye\n", ret)
}

func runStreaming() {
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	log.Printf("Waiting interval %s for flows to be collected...\n", interval)
	// print header
	fmt.Printf("%-25s %-25s %-20s %-10s %-10s\n", "LADDR", "RADDR", "LPORT", "PID", "COMM")

	for {
		select {
		case flow := <-flowChan:
			printFlow(flow)
		case ret := <-sig:
			log.Printf("Received %v, Goodbye\n", ret)
			return
		}
	}

	return
}
