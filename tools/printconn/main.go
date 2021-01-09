package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	conntracer "github.com/yuuki/go-conntracer-bpf"
)

var interval time.Duration

func init() {
	log.SetFlags(0)

	flag.DurationVar(&interval, "interval", 3*time.Second, "polling interval (default 3s)")
	flag.Parse()
}

func printFlows(flows []*conntracer.Flow) error {
	for _, flow := range flows {
		switch flow.Direction {
		case conntracer.FlowActive:
			fmt.Printf("%-25s %-25s %-20d %-10d %-10d\n", flow.SAddr, flow.DAddr, flow.LPort, flow.Stat.PID, flow.Stat.NewConnections)
		case conntracer.FlowPassive:
			fmt.Printf("%-25s %-25s %-20d %-10d %-10d\n", flow.DAddr, flow.SAddr, flow.LPort, flow.Stat.PID, flow.Stat.NewConnections)
		}
	}
	return nil
}

func main() {
	t, err := conntracer.NewTracer(printFlows)
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer t.Close()

	t.Start(interval)

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGTERM, syscall.SIGINT)
	log.Printf("Waiting interval %s for flows to be collected...\n", interval)

	// print header
	fmt.Printf("%-25s %-25s %-20s %-10s %-10s\n", "LADDR", "RADDR", "RPORT", "PID", "CONNECTIONS")

	sig := <-sigch
	log.Printf("Received %s, Goodbye\n", sig)
}
