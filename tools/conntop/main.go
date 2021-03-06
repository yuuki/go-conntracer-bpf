package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

var (
	interval   time.Duration
	inFlowAggr bool
	userAggr   bool
	kernelAggr bool
	prof       bool
)

func init() {
	log.SetFlags(0)
	runtime.GOMAXPROCS(1)

	flag.DurationVar(&interval, "interval", 3*time.Second, "polling interval (default 3s)")
	flag.BoolVar(&inFlowAggr, "in-flow-aggr", false, "in-kernel in-flow aggregation")
	flag.BoolVar(&userAggr, "user-aggr", false, "in-user-space aggregation")
	flag.BoolVar(&kernelAggr, "kernel-aggr", false, "in-kernel multi-flow aggregation")
	flag.BoolVar(&prof, "prof", false, "bpf prof and pprof http://localhost:6060")
	flag.Parse()
}

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	log.Printf("Waiting interval %s for flows to be collected...\n", interval)

	if !kernelAggr && !userAggr && !inFlowAggr {
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
	if inFlowAggr {
		runInFlowAggr(sig)
		return
	}
}

func serveProfiler(getStats func() (map[int]*conntracer.BpfProgramStats, error)) {
	http.HandleFunc("/bpf/stats", func(w http.ResponseWriter, req *http.Request) {
		stats, err := getStats()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, fmt.Sprintf("%+v", err))
			return
		}
		res, err := json.Marshal(stats)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, fmt.Sprintf("%+v", err))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(res)
	})
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}

func runKernelAggr(sig chan os.Signal) {
	t, err := conntracer.NewTracer(&conntracer.TracerParam{Stats: true})
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer t.Close()

	if prof {
		serveProfiler(t.GetStats)
	}

	printFlow := func(flows []*conntracer.Flow) error {
		for _, flow := range flows {
			switch flow.Direction {
			case conntracer.FlowActive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-20s %-10.2f %-10.2f\n", flow.SAddr, flow.DAddr, flow.LPort, flow.LastPID, flow.ProcessName, flow.Stat.SentBytes(interval), flow.Stat.RecvBytes(interval))
			case conntracer.FlowPassive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-20s %-10.2f %-10.2f\n", flow.DAddr, flow.SAddr, flow.LPort, flow.LastPID, flow.ProcessName, flow.Stat.SentBytes(interval), flow.Stat.RecvBytes(interval))
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
	fmt.Printf("%-25s %-25s %-20s %-10s %-20s %-10s %-10s\n", "LADDR", "RADDR", "LPORT", "PID", "COMM", "SENT_BYTES(kB/s)", "RECV_BYTES(kB/s)")

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
	t, err := conntracer.NewTracerStreaming(&conntracer.TracerParam{Stats: true})
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer t.Close()

	if prof {
		serveProfiler(t.GetStats)
	}

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

func runInFlowAggr(sig chan os.Signal) {
	t, err := conntracer.NewTracerInFlowAggr(&conntracer.TracerParam{Stats: true})
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer t.Close()

	if prof {
		serveProfiler(t.GetStats)
	}

	printFlow := func(flows []*conntracer.SingleFlow) error {
		var aggrFlows sync.Map
		for _, flow := range flows {
			tuple := connAggrTuple{SAddr: flow.SAddr.String(), DAddr: flow.DAddr.String(), LPort: flow.LPort}
			aggrFlows.Store(tuple, flow)
		}
		aggrFlows.Range(func(key, value interface{}) bool {
			flow := value.(*conntracer.SingleFlow)
			switch flow.Direction {
			case conntracer.FlowActive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-20s %-10.2f %-10.2f\n", flow.SAddr, flow.DAddr, flow.LPort, flow.PID, flow.ProcessName, flow.Stat.SentBytes(interval), flow.Stat.RecvBytes(interval))
			case conntracer.FlowPassive:
				fmt.Printf("%-25s %-25s %-20d %-10d %-20s %-10.2f %-10.2f\n", flow.DAddr, flow.SAddr, flow.LPort, flow.PID, flow.ProcessName, flow.Stat.SentBytes(interval), flow.Stat.RecvBytes(interval))
			default:
				log.Printf("wrong direction '%d', %+v\n", flow.Direction, flow)
			}
			return true
		})
		return nil
	}

	if err := t.Start(printFlow, interval); err != nil {
		log.Println(err)
		return
	}

	// print header
	fmt.Printf("%-25s %-25s %-20s %-10s %-20s %-10s %-10s\n", "LADDR", "RADDR", "LPORT", "PID", "COMM", "SENT(kB/s)", "RECV(kB/s)")

	ret := <-sig
	t.Stop()

	log.Printf("Received %v, Goodbye\n", ret)
}
