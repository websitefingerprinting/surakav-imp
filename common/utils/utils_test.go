package utils

import (
	"fmt"
	"math"
	"testing"
)

func TestReadFloatFromFile(t *testing.T) {
	arr :=ReadFloatFromFile("../../transports/wfgan/grpc/time_feature_0-100x0-1000_o2o.ipt")
	if math.Abs(arr[0] - 0.002031) >= 1e-6 {
		t.Fatal("error")
	}
	if len(arr) != 10000000+1 {
		t.Fatal("Error")
	}
}

func TestSampleIPT(t *testing.T) {
	arr := ReadFloatFromFile("../../transports/wfgan/grpc/time_feature_0-100x0-1000_o2o.ipt")
	n := 3000
	samples := make([]int, n)
	for i := 0; i < len(samples); i++ {
		samples[i] = SampleIPT(arr)
	}

	total := 0
	for _, sample := range samples {
		total += sample
	}
	mean := float64(total) / float64(n)
	fmt.Printf("mean: %v\n", mean)
}