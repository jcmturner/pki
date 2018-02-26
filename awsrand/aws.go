package awsrand

import (
	"fmt"
	"math"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/kmsiface"
)

const maxBytesPerRequest = 1024

type KMSRand struct {
	KMSsrv kmsiface.KMSAPI
}

func (k KMSRand) randomBytes(n int64) ([]byte, error) {
	if n > int64(maxBytesPerRequest) {
		return []byte{}, fmt.Errorf("number of bytes requested (%d) is larger than maximum (%d)", n, maxBytesPerRequest)
	}
	in := &kms.GenerateRandomInput{
		NumberOfBytes: &n,
	}
	r := k.KMSsrv.GenerateRandomRequest(in)
	out, err := r.Send()
	if err != nil {
		return []byte{}, err
	}
	return out.Plaintext, nil
}

func (k KMSRand) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	extra := int(math.Mod(float64(len(p)), float64(maxBytesPerRequest)))
	n := (len(p) - extra) / maxBytesPerRequest
	var s int
	for i := 0; i < n; i++ {
		b, err := k.randomBytes(int64(maxBytesPerRequest))
		if err != nil {
			s += copy(p[s:], b)
			return s, err
		}
		s += copy(p[s:], b)
	}
	if extra > 0 {
		b, err := k.randomBytes(int64(extra))
		if err != nil {
			s += copy(p[s:], b)
			return s, err
		}
		s += copy(p[s:], b)
	}
	return s, nil
}
