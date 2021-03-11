/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// package null provides an implementation of the Tor Project's null
// obfuscation protocol.
package null // import "github.com/websitefingerprinting/wfdef.git/transports/null"

import (
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/transports/pb"
	"google.golang.org/grpc"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/transports/base"
)

const (
	transportName      = "null"
	maxCloseDelay      = 60
	gRPCAddr           = "localhost:10086"
	traceLogEnabled    = true
)

type nullClientArgs struct {
}

// Transport is the null implementation of the base.Transport interface.
type Transport struct{}

// Name returns the name of the null transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new nullClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := &nullClientFactory{transport: t}
	return cf, nil
}

// ServerFactory returns a new nullServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {

	// Store the arguments that should appear in our descriptor for the clients.
	ptArgs := pt.Args{}

	sf := &nullServerFactory{t, &ptArgs, rand.Intn(maxCloseDelay)}
	return sf, nil
}

type nullClientFactory struct {
	transport base.Transport
}

func (cf *nullClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *nullClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	return &nullClientArgs{}, nil
}

func (cf *nullClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	// Validate args before bothering to open connection.
	conn, err := dialFn(network, addr)
	if err != nil {
		return nil, err
	}
	dialConn := conn
	if conn, err = newNullClientConn(conn); err != nil {
		dialConn.Close()
		return nil, err
	}
	return conn, nil
}

type nullServerFactory struct {
	transport base.Transport
	args      *pt.Args
	closeDelay int
}

func (sf *nullServerFactory) Transport() base.Transport {
	return sf.transport
}

func (sf *nullServerFactory) Args() *pt.Args {
	return sf.args
}

func (sf *nullServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	logger := &traceLogger{gRPCServer: grpc.NewServer(), logOn: nil, logPath: nil}
	// The server's initial state is intentionally set to stateStart at the very beginning to obfuscate the RTT between client and server
	c := &nullConn{conn, true,  logger, nil}

	return c, nil
}

type nullConn struct {
	net.Conn
	isServer  bool
	logger *traceLogger
	loggerChan           chan []int64
}


func newNullClientConn(conn net.Conn) (c *nullConn, err error) {

	var loggerChan chan []int64
	if traceLogEnabled {
		loggerChan = make(chan []int64, 100)
	} else {
		loggerChan = nil
	}

	logPath := atomic.Value{}
	logPath.Store("")
	logOn  := atomic.Value{}
	logOn.Store(false)
	server := grpc.NewServer()
	logger := &traceLogger{gRPCServer: server, logOn: &logOn, logPath: &logPath}

	pb.RegisterTraceLoggingServer(logger.gRPCServer, &traceLoggingServer{callBack:logger.UpdateLogInfo})

	// Allocate the client structure.
	c = &nullConn{conn, false,logger, loggerChan}

	return
}

func (conn *nullConn) Read(b []byte) (n int, err error) {
	rdLen, err := conn.Conn.Read(b)
	if err != nil {
		return 0, err
	}
	if !conn.isServer && traceLogEnabled && conn.logger.logOn.Load().(bool) {
		conn.loggerChan <- []int64{time.Now().UnixNano(), -int64(rdLen), 0}
	}
	log.Debugf("[Rcv]  %-8s, %-6d+%d bytes at %v", pktTypeMap[packetTypePayload], -rdLen, 0, time.Now().Format("15:04:05.000"))
	return rdLen, nil
}

func (conn *nullConn) ReadFrom(r io.Reader) (written int64, err error) {
	closeChan := make(chan int)
	defer close(closeChan)

	errChan := make(chan error, 5)


	//client side launch trace logger routine
	if traceLogEnabled && !conn.isServer {
		//start gRPC routine
		listen, err := net.Listen("tcp", gRPCAddr)
		if err != nil {
			log.Errorf("Fail to launch gRPC service err: %v", err)
			return 0, err
		}
		go func() {
			log.Infof("[Routine] gRPC server starts listeners.")
			gErr := conn.logger.gRPCServer.Serve(listen)
			if gErr != nil {
				log.Infof("[Routine] gRPC server exits by gErr: %v", gErr)
				errChan <- gErr
				return
			} else {
				log.Infof("[Routine] gRPC server is closed.")
			}
		}()

		time.Sleep(50 * time.Millisecond)
		go func() {
			log.Infof("[Routine] Client traceLogger turns on.")
			for {
				select {
				case _, ok := <- closeChan:
					if !ok {
						conn.logger.gRPCServer.Stop()
						log.Infof("[Routine] traceLogger exits by closeChan signal.")
						return
					}
				case pktinfo, ok := <- conn.loggerChan:
					if !ok {
						log.Infof("[Routine] traceLogger exits: %v.")
						return
					}
					_ = conn.logger.LogTrace(pktinfo[0], pktinfo[1], pktinfo[2])
				}
			}
		}()
	}

	for {
		select {
		case conErr := <- errChan:
			log.Infof("downstream copy loop terminated at %v. Reason: %v", time.Now().Format("15:04:05.000000"), conErr)
			return written, conErr
		default:
			buf := make([]byte, 65535)
			rdLen, err := r.Read(buf[:])
			if err!= nil {
				log.Infof("Exit by read err:%v", err)
				return written, err
			}
			if rdLen > 0 {
				_, wtErr := conn.Conn.Write(buf[:rdLen])
				if wtErr != nil {
					log.Infof("downstream copy loop terminated at %v. Reason: %v", time.Now().Format("15:04:05.000000"), wtErr)
					return written, wtErr
				}
				if !conn.isServer && traceLogEnabled && conn.logger.logOn.Load().(bool) {
					conn.loggerChan <- []int64{time.Now().UnixNano(), int64(rdLen), 0}
				}
				log.Debugf("[Send] %-8s, %-6d+%d bytes at %v", pktTypeMap[packetTypePayload], rdLen, 0, time.Now().Format("15:04:05.000"))
			} else {
				log.Errorf("BUG? read 0 bytes, err: %v", err)
				return written, io.EOF
			}
		}
	}
}

func (conn *nullConn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *nullConn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *nullConn) closeAfterDelay(sf *nullServerFactory, startTime time.Time) {
	// I-it's not like I w-wanna handshake with you or anything.  B-b-baka!
	defer conn.Conn.Close()

	delay := time.Duration(sf.closeDelay)*time.Second
	deadline := startTime.Add(delay)
	if time.Now().After(deadline) {
		return
	}

	if err := conn.Conn.SetReadDeadline(deadline); err != nil {
		return
	}

	// Consume and discard data on this connection until the specified interval
	// passes.
	_, _ = io.Copy(ioutil.Discard, conn.Conn)
}

var _ base.ClientFactory = (*nullClientFactory)(nil)
var _ base.ServerFactory = (*nullServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*nullConn)(nil)
