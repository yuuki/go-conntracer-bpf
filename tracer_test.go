// +build linux

package conntracer

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	defaultInterval = 1 * time.Second
)

func TestNewTracer(t *testing.T) {
	cb := func(flows []*Flow) error {
		assert.Empty(t, flows, "flows should be empty")
		return nil
	}
	tracer, err := NewTracer(cb)
	defer tracer.Close()

	assert.NoError(t, err, "err should be nil")
}

func TestStart(t *testing.T) {
	cb := func(flows []*Flow) error {
		assert.Empty(t, flows, "flows should be empty")
		return nil
	}
	tracer, _ := NewTracer(cb)
	tracer.Start(defaultInterval)

	tracer.Close()
}

func TestClose(t *testing.T) {
	cb := func(flows []*Flow) error {
		assert.Empty(t, flows, "flows should be empty")
		return nil
	}
	tracer, _ := NewTracer(cb)
	tracer.Close()
}

//TODO: replacement of using ip addrs on docker container
func TestDumpFlows(t *testing.T) {
	cb := func(flows []*Flow) error {
		assert.Empty(t, flows, "flows should be empty")
		return nil
	}
	tracer, _ := NewTracer(cb)
	defer tracer.Close()

	tracer.batchSize = 2

	addrs := []string{
		"93.184.216.34",   // example.com
		"192.185.44.208",  // example1.com
		"173.231.210.103", // example2.com
		"107.164.66.184",  // example1.org
		"95.216.2.95",     // example2.org
	}

	wg := &sync.WaitGroup{}
	for _, addr := range addrs {
		addr := addr
		wg.Add(1)
		go func() {
			client := &http.Client{Timeout: 3 * time.Second}
			// no redirect
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			_, err := client.Get(fmt.Sprintf("http://%s/", addr))
			if err != nil {
				panic(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	flows, err := dumpFlows(tracer.flowsMapFD())

	assert.NoError(t, err, "err should be nil")

	var daddrs []string
	for _, flow := range flows {
		// filter out unecpedted connections occured outside of this test
		for _, addr := range addrs {
			if addr == flow.DAddr.String() {
				daddrs = append(daddrs, addr)
			}
		}
	}
	assert.Equal(t, len(addrs), len(flows), "the number of flows should be the number of addrs")
	assert.ElementsMatch(t, addrs, daddrs)
}
