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

// package front provides an implementation of the Tor Project's front
// obfuscation protocol.
package front // import "github.com/websitefingerprinting/wfdef.git/transports/front"

import (
	"context"
	queue "github.com/enriquebris/goconcurrentqueue"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/common/utils"
	"github.com/websitefingerprinting/wfdef.git/transports/defconn"
	expRand "golang.org/x/exp/rand"
	"gonum.org/v1/gonum/stat/distuv"
	"io"
	"math"
	"net"
	"sort"
	"sync/atomic"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/transports/base"
)

const (
	transportName = "front"

	wMinArg       = "w-min"
	wMaxArg       = "w-max"
	nServerArg    = "n-server"
	nClientArg    = "n-client"
)

type frontClientArgs struct {
	*defconn.DefConnClientArgs
	wMin       float32     // in seconds
	wMax       float32     // in seconds
	nServer    int
	nClient    int
}

// Transport is the front implementation of the base.Transport interface.
type Transport struct{
	defconn.Transport
}

// Name returns the name of the front transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new frontClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	parentFactory, err := t.Transport.ClientFactory(stateDir)
	return &frontClientFactory{
		parentFactory.(*defconn.DefConnClientFactory),
	}, err
}

// ServerFactory returns a new frontServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	sf, err := t.Transport.ServerFactory(stateDir, args)
	if err != nil {
		return nil, err
	}

	st, err := serverStateFromArgs(stateDir, args)
	if err != nil {
		return nil, err
	}

	frontSf := frontServerFactory{
		sf.(*defconn.DefConnServerFactory),
		st.wMin,
		st.wMax,
		st.nServer,
		st.nClient,
	}

	return &frontSf, nil
}

type frontClientFactory struct {
	*defconn.DefConnClientFactory
}

func (cf *frontClientFactory) Transport() base.Transport {
	return cf.DefConnClientFactory.Transport()
}

func (cf *frontClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	arguments, err := cf.DefConnClientFactory.ParseArgs(args)

	nClient, err := utils.GetIntArgFromStr(nClientArg, args)
	if err != nil {
		return nil, err
	}
	nServer, err := utils.GetIntArgFromStr(nServerArg, args)
	if err != nil {
		return nil, err
	}

	wMin, err := utils.GetFloatArgFromStr(wMinArg, args)
	if err != nil {
		return nil, err
	}

	wMax, err := utils.GetFloatArgFromStr(wMaxArg, args)
	if err != nil {
		return nil, err
	}

	return &frontClientArgs{
		arguments.(*defconn.DefConnClientArgs),
		float32(wMin.(float64)), float32(wMax.(float64)),nServer.(int), nClient.(int),
	}, nil
}

func (cf *frontClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	defConn, err := cf.DefConnClientFactory.Dial(network, addr, dialFn, args)
	if err != nil {
		return nil, err
	}

	paddingChan := make(chan bool)

	argsT := args.(*frontClientArgs)
	c := &frontConn {
		defConn.(*defconn.DefConn),
		argsT.wMin, argsT.wMax, argsT.nServer, argsT.nClient, paddingChan,
	}
	return c, nil
}

type frontServerFactory struct {
	*defconn.DefConnServerFactory
	wMin       float32     // in seconds
	wMax       float32     // in seconds
	nServer    int
	nClient    int
}

func (sf *frontServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	defConn, err := sf.DefConnServerFactory.WrapConn(conn)
	if err != nil {
		return nil, err
	}

	paddingChan := make(chan bool)
	c := &frontConn{
		defConn.(*defconn.DefConn),
		sf.wMin, sf.wMax, sf.nServer, sf.nClient, paddingChan,
	}
	return c, nil
}

type frontConn struct {
	*defconn.DefConn
	wMin       float32     // in seconds
	wMax       float32     // in seconds
	nServer    int
	nClient    int

	paddingChan chan bool  // true when start defense, false when stop defense
}


func (conn *frontConn) initFrontArgs(N int, tsQueue *queue.FixedFIFO, frontInitTime *atomic.Value) (err error){
	wSampler := distuv.Uniform{Min: float64(conn.wMin), Max: float64(conn.wMax),
		Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano()))}
	n_sampler := distuv.Uniform{Min: 1.0, Max: float64(N),
		Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano()))}
	w_tmp := wSampler.Rand()
	n_tmp := int(n_sampler.Rand())
	log.Infof("[Init] Sampled w: %.2fs, n: %d", w_tmp, n_tmp)
	tSampler := distuv.Weibull{K: 2, Lambda: math.Sqrt2 * w_tmp,
		Src: expRand.NewSource(uint64(time.Now().UTC().UnixNano()))}
	ts := make([]float64, n_tmp)
	for i := 0; i  < n_tmp; i++ {
		ts[i] = tSampler.Rand()
	}
	sort.Float64s(ts)
	for tsQueue.GetLen() > 0 {
		//empty the queue before refill it
		_, _ = tsQueue.Dequeue()
	}

	frontInitTime.Store(time.Now())
	for i:= 0; i< n_tmp; i++ {
		err := tsQueue.Enqueue(time.Duration(int64(ts[i] * 1e9)))
		if err != nil {
			return err
		}
	}
	return
}

func (conn *frontConn) ReadFrom(r io.Reader) (written int64, err error) {
	log.Infof("[State] FRONT Enter copyloop state: %v at %v", defconn.StateMap[conn.ConnState.LoadCurState()], time.Now().Format("15:04:05.000"))
	defer close(conn.CloseChan)

	var receiveBuf utils.SafeBuffer //read payload from upstream and buffer here
	var frontInitTime atomic.Value
	var tsQueue *queue.FixedFIFO // maintain a queue of timestamps sampled
	var maxPaddingN int

	if conn.IsServer {
		maxPaddingN = conn.nServer
	} else {
		maxPaddingN = conn.nClient
	}
	tsQueue = queue.NewFixedFIFO(maxPaddingN)

	//create a go routine to send out packets to the wire
	go conn.Send()

	//create a go routine to receive padding signal and schdule dummy pkts
	//true: need to init front params
	//false: need to cancel unsent dummy packets
	go func() {
		for{
			select{
			case _, ok := <- conn.CloseChan:
				if !ok{
					log.Infof("[Routine] padding factory exits by closedChan.")
					return
				}
			case startPadding := <- conn.paddingChan:
				if startPadding {
					err := conn.initFrontArgs(maxPaddingN, tsQueue, &frontInitTime)
					if err != nil {
						conn.ErrChan <- err
						log.Infof("[Routine] padding factory exits by err in init.")
						return
					}
					log.Debugf("[Event] Get %v dummy packets to send", tsQueue.GetLen())
				} else {
					log.Debugf("[Event] Empty the ts queue (len %v)", tsQueue.GetLen())
					for tsQueue.GetLen() > 0 {
						_, _ = tsQueue.Dequeue()
					}
				}
			}
		}
	}()

	go func() {
		for{
			select {
			case _, ok := <-conn.CloseChan:
				if !ok {
					log.Infof("[Routine] padding routine exits by closedChan.")
					return
				}
			default:
				// here to send out dummy packets
				if conn.ConnState.LoadCurState() == defconn.StateStop {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				timestamp, qErr := tsQueue.DequeueOrWaitForNextElementContext(ctx)
				if qErr == context.DeadlineExceeded {
					log.Infof("[Routine] Dequeue timeout after 5 seconds.")
					cancel()
					continue
				}
				cancel()
				if qErr != nil {
					log.Infof("[Routine] padding routine exits by dequeue err.")
					conn.ErrChan <- qErr
					return
				}
				cancel()
				utils.SleepRho(frontInitTime.Load().(time.Time) ,timestamp.(time.Duration))
				conn.SendChan <- defconn.PacketInfo{PktType: defconn.PacketTypeDummy, Data: []byte{},  PadLen: defconn.MaxPacketPaddingLength}
			}
		}
	}()

	// this go routine regularly check the real throughput
	// if it is small, change to stop state
	go func() {
		ticker := time.NewTicker(defconn.TWindow)
		defer ticker.Stop()
		for{
			select{
			case _, ok := <- conn.CloseChan:
				if !ok {
					log.Infof("[Routine] Ticker routine exits by closeChan.")
					return
				}
			case <- ticker.C:
				log.Debugf("[State] Real Sent: %v, Real Receive: %v, curState: %s at %v.",
					conn.NRealSegSentLoad(), conn.NRealSegRcvLoad(), defconn.StateMap[conn.ConnState.LoadCurState()], time.Now().Format("15:04:05.000000"))
				if !conn.IsServer && conn.ConnState.LoadCurState() != defconn.StateStop && (conn.NRealSegSentLoad() < 2 || conn.NRealSegRcvLoad() < 2) {
					log.Infof("[State] %s -> %s.", defconn.StateMap[conn.ConnState.LoadCurState()], defconn.StateMap[defconn.StateStop])
					conn.ConnState.SetState(defconn.StateStop)
					conn.SendChan <- defconn.PacketInfo{PktType: defconn.PacketTypeSignalStop, Data: []byte{}, PadLen: defconn.MaxPacketPaddingLength}
					conn.paddingChan <- false
				}
				conn.NRealSegReset()
			}
		}
	}()

	for {
		select {
		case conErr := <- conn.ErrChan:
			log.Infof("downstream copy loop terminated at %v. Reason: %v", time.Now().Format("15:04:05.000000"), conErr)
			return written, conErr
		default:
			buf := make([]byte, 65535)
			rdLen, err := r.Read(buf[:])
			if err!= nil {
				log.Errorf("Exit by read err:%v", err)
				return written, err
			}
			if rdLen > 0 {
				_, err := receiveBuf.Write(buf[: rdLen])
				if err != nil {
					return written, err
				}
			} else {
				log.Errorf("BUG? read 0 bytes, err: %v", err)
				return written, io.EOF
			}
			//signal server to start if there is more than one cell coming
			// else switch to padding state
			// stop -> ready -> start
			if !conn.IsServer {
				if (conn.ConnState.LoadCurState() == defconn.StateStop && rdLen > defconn.MaxPacketPayloadLength) ||
					(conn.ConnState.LoadCurState() == defconn.StateReady) {
					log.Infof("[State] %s -> %s.", defconn.StateMap[conn.ConnState.LoadCurState()], defconn.StateMap[defconn.StateStart])
					conn.ConnState.SetState(defconn.StateStart)
					conn.SendChan <- defconn.PacketInfo{PktType: defconn.PacketTypeSignalStart, Data: []byte{}, PadLen: defconn.MaxPacketPaddingLength}
					conn.paddingChan <- true
				} else if conn.ConnState.LoadCurState() == defconn.StateStop {
					log.Infof("[State] %s -> %s.", defconn.StateMap[defconn.StateStop], defconn.StateMap[defconn.StateReady])
					conn.ConnState.SetState(defconn.StateReady)
				}
			}
			for receiveBuf.GetLen() > 0 {
				var payload [defconn.MaxPacketPayloadLength]byte
				rdLen, rdErr := receiveBuf.Read(payload[:])
				written += int64(rdLen)
				if rdErr != nil {
					log.Infof("Exit by read buffer err:%v", rdErr)
					return written, rdErr
				}
				conn.SendChan <- defconn.PacketInfo{PktType: defconn.PacketTypePayload, Data: payload[:rdLen], PadLen: uint16(defconn.MaxPacketPaddingLength-rdLen)}
				conn.NRealSegSentIncrement()
			}
		}
	}
}

func (conn *frontConn) Read(b []byte) (n int, err error) {
	return conn.DefConn.MyRead(b, conn.readPackets)
}

var _ base.ClientFactory = (*frontClientFactory)(nil)
var _ base.ServerFactory = (*frontServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*frontConn)(nil)
