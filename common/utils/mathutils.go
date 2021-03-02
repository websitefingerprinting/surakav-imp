package utils

import (
	expRand "golang.org/x/exp/rand"
	"gonum.org/v1/gonum/stat/distuv"
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

func Bernoulli(p float64) int {
	dist := distuv.Bernoulli{
		P:   p,
		Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano())),
	}
	return int(dist.Rand())
}

func Uniform(min float64, max float64) int {
	dist := distuv.Uniform{
		Min: min,
		Max: max,
		Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano())),
	}
	return int(dist.Rand())
}



