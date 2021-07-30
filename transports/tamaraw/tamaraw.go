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

// Package tamaraw provides an implementation of the Tor Project's tamaraw
// obfuscation protocol.
package tamaraw // import "github.com/websitefingerprinting/wfdef.git/transports/tamaraw"

import (
	"bytes"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/common/utils"
	"github.com/websitefingerprinting/wfdef.git/transports/defconn"
	"io"
	"net"
	"sync/atomic"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/transports/base"
)

const (
	transportName = "tamaraw"

	rhoServerArg  = "rho-server"
	rhoClientArg  = "rho-client"
	nSegArg       = "nseg"
)

type tamarawClientArgs struct {
	*defconn.DefConnClientArgs
	nSeg       int
	rhoServer  int   // in milliseconds
	rhoClient  int  // in milliseconds
}

// Transport is the tamaraw implementation of the base.Transport interface.
type Transport struct{
	defconn.Transport
}

// Name returns the name of the tamaraw transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new DefConnClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	log.Debugf("[Debug] Enter child client factory")
	return t.Transport.ClientFactory(stateDir)
}


// ServerFactory returns a new ServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	sf, err := t.Transport.ServerFactory(stateDir, args)
	if err != nil {
		return nil, err
	}
	//load additional params
	st, err := serverStateFromArgs(stateDir, args)
	if err != nil {
		return nil, err
	}

	tamarawSf := tamarawServerFactory{
		sf.(*defconn.DefConnServerFactory),
		st.nSeg,
		st.rhoClient,
		st.rhoServer,
	}
	return &tamarawSf, nil
}

type tamarawClientFactory struct {
	transport defconn.DefConnClientFactory
}

func (cf *tamarawClientFactory) Transport() base.Transport {
	return cf.transport.Transport()
}

func (cf *tamarawClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	arguments, err := cf.transport.ParseArgs(args)

	nSeg, err := utils.GetIntArgFromStr(nSegArg, args)
	if err != nil {
		return nil, err
	}
	rhoServer, err := utils.GetIntArgFromStr(rhoServerArg, args)
	if err != nil {
		return nil, err
	}

	rhoClient, err := utils.GetIntArgFromStr(rhoClientArg, args)
	if err != nil {
		return nil, err
	}


	return &tamarawClientArgs{
		arguments.(*defconn.DefConnClientArgs),
		 nSeg.(int), rhoServer.(int), rhoClient.(int),
	}, nil
}

func (cf *tamarawClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	defConn, err := cf.transport.Dial(network, addr, dialFn, args)
	log.Debugf("[Client] parent dial returned")
	if err != nil {
		return nil, err
	}

	argsT := args.(*tamarawClientArgs)
	c := &tamarawConn{
		defConn.(*defconn.DefConn),
		argsT.nSeg, argsT.rhoClient, argsT.rhoServer,
	}
	log.Debugf("[DEBUG] params %v %v, %v, %T", c.nSeg, c.rhoClient, c.rhoServer, c)
	return c, nil
}

type tamarawServerFactory struct {
	*defconn.DefConnServerFactory
	nSeg        int
	rhoServer    int
	rhoClient    int
}

func (sf *tamarawServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	defConn, err := sf.DefConnServerFactory.WrapConn(conn)
	if err != nil {
		return nil, err
	}
	c := &tamarawConn{
		defConn.(*defconn.DefConn),
		sf.nSeg, sf.rhoClient, sf.rhoServer,
	}
	return c, nil
}


type tamarawConn struct {
	*defconn.DefConn
	nSeg       int
	rhoClient  int
	rhoServer  int
}


func (conn *tamarawConn) ReadFrom(r io.Reader) (written int64, err error) {
	log.Debugf("[State] Tamaraw Enter copyloop state: %v at %v", defconn.StateMap[conn.ConnState.LoadCurState()], time.Now().Format("15:04:05.000"))
	closeChan := make(chan int)
	defer close(closeChan)

	errChan := make(chan error, 5)
	var rho time.Duration
	if conn.IsServer {
		rho = time.Duration(conn.rhoServer * 1e6)
	} else {
		rho = time.Duration(conn.rhoClient * 1e6)
	}

	var curNSeg uint32 = 0
	sendChan := make(chan defconn.PacketInfo, 65535) // all packed packets are sent through this channel
	var receiveBuf bytes.Buffer

	//create a go routine to send out packets to the wire
	go func() {
		ticker := time.NewTicker(rho)
		defer ticker.Stop()
		var pktType uint8
		var data []byte
		var padLen uint16
		for {
			select{
			case _, ok := <- closeChan:
				if !ok{
					log.Infof("[Routine] Send routine exits by closedChan.")
					return
				}
			case <- ticker.C:
				atomic.AddUint32(&curNSeg, 1)
				var frameBuf bytes.Buffer
				var curState uint32
				if len(sendChan) > 0 {
					// pkts in the queue: possibly signal ones or real ones
					packetInfo := <- sendChan
					pktType = packetInfo.PktType
					data    = packetInfo.Data
					padLen  = packetInfo.PadLen
				} else {
					pktType = defconn.PacketTypeDummy
					data = []byte{}
					padLen = defconn.MaxPacketPaddingLength
				}

				curState = conn.ConnState.LoadCurState()
				if (curState == defconn.StateStop || curState == defconn.StateReady) && pktType == defconn.PacketTypeDummy {
					// stop state should not send dummy packets
					continue
				}

				err = conn.MakePacket(&frameBuf, pktType, data, padLen)
				if err != nil {
					errChan <- err
					return
				}
				_, wtErr := conn.Conn.Write(frameBuf.Bytes())
				if wtErr != nil {
					errChan <- wtErr
					log.Infof("[Routine] Send routine exits by write err.")
					return
				}
				if !conn.IsServer && defconn.LogEnabled{
					log.Infof("[TRACE_LOG] %d %d %d", time.Now().UnixNano(), int64(len(data)), int64(padLen))
				}
				log.Debugf("[Send] %-8s, %-3d+ %-3d bytes at %v", defconn.PktTypeMap[pktType], len(data), padLen, time.Now().Format("15:04:05.000"))

				// update state for client
				// base.StateStop -(real pkt)-> base.StateReady
				// base.StateReady -(real pkt)-> base.StateStart and send a StartSignal to server
				// base.StatePadding -(curNSeg % NSeg == 0)-> base.StateStop and send a StopSignal to server
				if !conn.IsServer {
					curState = conn.ConnState.LoadCurState()
					if curState == defconn.StateStop && pktType == defconn.PacketTypePayload {
						conn.ConnState.SetState(defconn.StateReady)
						log.Debugf("[State] %-12s->%-12s", defconn.StateMap[atomic.LoadUint32(&curState)], defconn.StateMap[defconn.StateReady])
					} else if curState == defconn.StateReady && pktType == defconn.PacketTypePayload {
						conn.ConnState.SetState(defconn.StateStart)
						log.Debugf("[State] %-12s->%-12s", defconn.StateMap[atomic.LoadUint32(&curState)], defconn.StateMap[defconn.StateStart])
						sendChan <- defconn.PacketInfo{PktType: defconn.PacketTypeSignalStart, Data: []byte{}, PadLen: defconn.MaxPacketPaddingLength}
					} else  if curState == defconn.StatePadding {
						if int(curNSeg) % conn.nSeg == 0 {
							log.Debugf("[Event] current nseg is %v", curNSeg)
							conn.ConnState.SetState(defconn.StateStop)
							log.Debugf("[State] %-12s->%-12s", defconn.StateMap[atomic.LoadUint32(&curState)], defconn.StateMap[defconn.StateStop])
							sendChan <- defconn.PacketInfo{PktType: defconn.PacketTypeSignalStop, Data: []byte{}, PadLen: defconn.MaxPacketPaddingLength}
							atomic.StoreUint32(&curNSeg, 0)
						}
					}
				}
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
			case _, ok := <- closeChan:
				if !ok {
					log.Infof("[Routine] Ticker routine exits by closeChan.")
					return
				}
			case <- ticker.C:
				curState := conn.ConnState.LoadCurState()
				log.Debugf("[State] Real Sent: %v, Real Receive: %v, curState: %s at %v.", conn.NRealSegSent, conn.NRealSegRcv, defconn.StateMap[conn.ConnState.LoadCurState()], time.Now().Format("15:04:05.000000"))
				if !conn.IsServer && curState != defconn.StateStop && (atomic.LoadUint32(&conn.NRealSegSent) < 2 || atomic.LoadUint32(&conn.NRealSegRcv) < 2){
					// if throughput is small, change client's state:
					// StateReady -> StateStop
					// StateStart -> StatePadding
					if curState == defconn.StateReady {
						conn.ConnState.SetState(defconn.StateStop)
						log.Debugf("[State] %-12s->%-12s", defconn.StateMap[curState], defconn.StateMap[defconn.StateStop])
					} else if curState == defconn.StateStart {
						conn.ConnState.SetState(defconn.StatePadding)
						log.Debugf("[State] %-12s->%-12s", defconn.StateMap[curState], defconn.StateMap[defconn.StatePadding])
					}
				}

				atomic.StoreUint32(&conn.NRealSegSent, 0) //reset counter
				atomic.StoreUint32(&conn.NRealSegRcv, 0) //reset counter
			}
		}
	}()

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
				receiveBuf.Write(buf[: rdLen])
			} else {
				log.Errorf("BUG? read 0 bytes, err: %v", err)
				return written, io.EOF
			}

			for receiveBuf.Len() > 0 {
				var payload [defconn.MaxPacketPayloadLength]byte
				rdLen, rdErr := receiveBuf.Read(payload[:])
				written += int64(rdLen)
				if rdErr != nil {
					log.Infof("Exit by read buffer err:%v", rdErr)
					return written, rdErr
				}
				sendChan <- defconn.PacketInfo{PktType: defconn.PacketTypePayload, Data: payload[:rdLen], PadLen: uint16(defconn.MaxPacketPaddingLength-rdLen)}
				atomic.AddUint32(&conn.NRealSegSent, 1)
			}
		}
	}
}

func (conn *tamarawConn) Read(b []byte) (n int, err error) {
	return conn.DefConn.Read(b)
}


var _ base.ClientFactory = (*tamarawClientFactory)(nil)
var _ base.ServerFactory = (*tamarawServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*tamarawConn)(nil)
