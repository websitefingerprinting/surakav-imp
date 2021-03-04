package utils

import (
	"fmt"
	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"
	"strings"
)

func SleepRho(lastSend time.Time, rho time.Duration)  {
	deltaT := time.Now().Sub(lastSend)
	if remainingDelay := rho - deltaT; remainingDelay > 0 {
		// We got data faster than the pacing rate, sleep
		// for the remaining time.
		time.Sleep(remainingDelay)
	}
}


func ParseArgByKey(args *pt.Args, key string, kind string) (interface{}, error) {
	kind = strings.ToLower(kind)
	Str, Ok := args.Get(key)
	if !Ok {
		return nil, fmt.Errorf("missing argument '%s'", key)
	}
	if kind == "int" {
		arg, err := strconv.Atoi(Str)
		if err != nil {
			return nil, fmt.Errorf("malformed '%s': '%s'", key, Str)
		}
		return arg, nil
	} else if kind == "float32" || kind == "float64" {
		precision, err := strconv.Atoi(kind[5:5+2])
		if err != nil {
			return nil, err
		}
		arg, err := strconv.ParseFloat(Str, precision)
		if err != nil {
			return nil, fmt.Errorf("malformed '%s': '%s'", key, Str)
		}
		return arg, nil
	}
	return nil, fmt.Errorf("wrong kind: '%s'", kind)
}

//we need to detect connection loss
func CheckConn(conn net.Conn) error {
	var sysErr error = nil
	rc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	err = rc.Read(func(fd uintptr) bool {
		var buf = []byte{0}
		n, _, err := syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case n == 0 && err == nil:
			sysErr = io.EOF
		case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
			sysErr = nil
		default:
			sysErr = err
		}
		return true
	})
	if err != nil {
		return err
	}

	return sysErr
}