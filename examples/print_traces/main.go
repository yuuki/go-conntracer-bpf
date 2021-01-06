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
		panic(err)
	}
	defer t.Close()
	t.Start(interval)

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGTERM, syscall.SIGINT)
	log.Println("Waiting for collecting flows...")
	sig := <-sigch
	log.Println("Received %s, Goodbye", sig)
}
