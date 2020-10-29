package kmsrand

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/kmsiface"
)

const maxBytesPerRequest = 1024

type Reader struct {
	KMSsrv kmsiface.ClientAPI
}

func (k Reader) randomBytes(n int64) ([]byte, error) {
	if n > int64(maxBytesPerRequest) {
		return []byte{}, fmt.Errorf("number of bytes requested (%d) is larger than maximum (%d)", n, maxBytesPerRequest)
	}
	in := &kms.GenerateRandomInput{
		NumberOfBytes: &n,
	}
	r := k.KMSsrv.GenerateRandomRequest(in)
	out, err := r.Send(context.Background())
	if err != nil {
		return []byte{}, err
	}
	return out.Plaintext, nil
}

func (k Reader) Read(p []byte) (int, error) {
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

// KMS returns the AWS KMS service client.
func GetReader(cl *http.Client, cmkarn arn.ARN) (Reader, error) {
	cfg, err := loadAWSConfig(cl, cmkarn)
	if err != nil {
		return Reader{}, err
	}
	return Reader{
		KMSsrv: kms.New(cfg),
	}, nil
}

// loadAWSConfig loads the AWS API credentials and sets the region and HTTPClient returning an aws.Config.
func loadAWSConfig(cl *http.Client, arn arn.ARN) (aws.Config, error) {
	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to load AWS SDK config: %v", err)
	}
	cfg.Region = arn.Region
	cfg.HTTPClient = cl
	return cfg, nil
}

type MockKMS struct {
	kmsiface.ClientAPI
}

func (k MockKMS) GenerateRandomRequest(i *kms.GenerateRandomInput) kms.GenerateRandomRequest {
	b := make([]byte, *i.NumberOfBytes)
	rand.Read(b)
	// Replace any zero bytes so we can easily test all elements are set byt the random generator.
	for i := range b {
		if b[i] == byte(0) {
			b[i] = 1
		}
	}
	return kms.GenerateRandomRequest{
		Request: &aws.Request{
			Data: &kms.GenerateRandomOutput{
				Plaintext: b,
			},
		},
	}
}
