package utils

import (
	expRand "golang.org/x/exp/rand"
	"gonum.org/v1/gonum/stat/distuv"
	"math/rand"
	"time"
)

func IntMin(a int, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func IntMax(a int, b int) int {
	if a > b {
		return a
	} else {
		return b
	}
}

func IntAbs(a int) int {
	if a<= 0{
		return -a
	}
	return a
}

func RandomBernoulli(p float64) int {
	betaDist := distuv.Beta{
		Alpha: p * 10.0 + 1,
		Beta: (1-p) * 10.0 + 1,
		Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano())),
	}

	randomP := betaDist.Rand()
	//fmt.Printf("%v\n", randomP)

	berDist := distuv.Bernoulli{
		P:   randomP,
		Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano())),
	}
	return int(berDist.Rand())
}

func Uniform(min int, max int) int {
	// sample a number between [min, max]
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return r.Intn(max - min + 1) + min
	//dist := distuv.Uniform{
	//	Min: min,
	//	Max: max,
	//	Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano())),
	//}
	//return int(dist.Rand())
}



