package main

import (
	"log"
	"os"

	"github.com/yuuki/go-conntracer-bpf"
)

func init() {
	log.SetFlags(0)
}

func main() {
	log.Println("Loading conntracer...")
	t1, err := conntracer.NewTracer()
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	t1.Close()

	log.Println("Loading conntracer without aggregation...")
	t2, err := conntracer.NewTracerStreaming()
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	t2.Close()

	log.Println("bpf programs have been verified.")
}
