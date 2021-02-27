package utils

import "time"

func SleepRho(lastSend time.Time, rho time.Duration)  {
	deltaT := time.Now().Sub(lastSend)
	if remainingDelay := rho - deltaT; remainingDelay > 0 {
		// We got data faster than the pacing rate, sleep
		// for the remaining time.
		time.Sleep(remainingDelay)
	}
}
