package conntracer

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBumpMemlockRlimit(t *testing.T) {
	err := bumpMemlockRlimit()
	assert.NoError(t, err, "err should be nil")
}

func TestNtohs(t *testing.T) {
	input := binary.BigEndian.Uint16([]byte{0x1f, 0x90})
	got := ntohs(input)
	var want uint16 = 36895
	assert.Equal(t, want, got, "ntohs(0x1f90) should be 0x901f")
}

func TestInetNtop(t *testing.T) {
	var addr uint32
	addr |= 0x04
	addr |= 0x03<<8
	addr |= 0x02<<16
	addr |= 0x01<<24

	got := inetNtop(addr)
	assert.EqualValues(t, "4.3.2.1", got.String())
}
