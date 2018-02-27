package awsrand

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterface(t *testing.T) {
	i := new(io.Reader)
	k := KMSRand{
		KMSsrv: MockKMS{},
	}
	assert.Implements(t, i, k, "MockKMSRand does not implement io.Reader")
}

func TestKMSRand_Read(t *testing.T) {
	k := KMSRand{
		KMSsrv: MockKMSRand{},
	}
	var sizes = []int{
		1024,
		1023,
		1025,
		2048,
		2047,
		2049,
	}
	for _, s := range sizes {
		p := make([]byte, s)
		n, err := k.Read(p)
		if err != nil {
			t.Errorf("Failed to read when size was %d", s)
		}
		if s != n {
			t.Errorf("returned int of bytes read not as expected for test size %d", s)
		}
		for i := range p {
			if p[i] != byte(1) {
				t.Errorf("byte value at %d not as expected for size %d", i, s)
			}
		}
	}
}
