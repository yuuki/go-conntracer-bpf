package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	conntracer "github.com/yuuki/gobpf-conntracer"
)

var interval time.Duration

func init() {
	flag.DurationVar(&interval, "interval", 3*time.Second, "polling interval (default 3s)")
	flag.Parse()
}

func printFlows(flows []*conntracer.Flow) error {
	for _, flow := range flows {
		fmt.Printf("%v\n", flow)
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
	sig := <-sigch
	log.Printf("Received %s, Goodbye\n", sig)
}
