package awsrand

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/kmsiface"
)

type mockkms struct {
	kmsiface.KMSAPI
}

func (k mockkms) GenerateRandomRequest(i *kms.GenerateRandomInput) kms.GenerateRandomRequest {
	b := make([]byte, *i.NumberOfBytes)
	for i := range b {
		b[i] = 1
	}
	return kms.GenerateRandomRequest{
		Request: &aws.Request{
			Data: &kms.GenerateRandomOutput{
				Plaintext: b,
			},
		},
	}
}

func TestKMSRand_Read(t *testing.T) {
	k := KMSRand{
		KMSsrv: mockkms{},
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
