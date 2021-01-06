package conntracer

import (
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
	_, err := NewTracer(cb, defaultInterval)
	assert.NoError(t, err, "err should be nil")
}
