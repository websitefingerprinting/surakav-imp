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


package wfgan

import (
	"context"
	"encoding/binary"
	pt "git.torproject.org/pluggable-transports/goptlib.git"
	queue "github.com/enriquebris/goconcurrentqueue"
	"github.com/websitefingerprinting/wfdef.git/common/log"

	"github.com/websitefingerprinting/wfdef.git/common/utils"
	"github.com/websitefingerprinting/wfdef.git/transports/base"
	"github.com/websitefingerprinting/wfdef.git/transports/defconn"
	"github.com/websitefingerprinting/wfdef.git/transports/wfgan/grpc/pb"
	"google.golang.org/grpc"
	"io"
	"math"
	"net"
	"os"
	"path"
	"time"
)

const (
	transportName = "wfgan"
	tolArg        = "tol"
	pArg          = "p"

	maxQueueSize       = 1000 * 3
	gRPCAddr           = "localhost:9999"
	o2oRelPath         = "../transports/wfgan/grpc/time_feature_0-100x0-1000_o2o.ipt"  //relative to wfdef/obfs4proxy
	o2iRelPath         = "../transports/wfgan/grpc/time_feature_0-100x0-1000_o2i.ipt"

	o2iEnabled         = false
	tmpRho             = 100 // ms, 98%
)

type wfganClientArgs struct {
	*defconn.DefConnClientArgs
	tol        float32
	p          float32
}

// Transport is the wfgan implementation of the base.Transport interface.
type Transport struct{
	defconn.Transport
}

// Name returns the name of the wfgan transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new wfganClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	parentFactory, err := t.Transport.ClientFactory(stateDir)
	return &wfganClientFactory{
		parentFactory.(*defconn.DefConnClientFactory),
	}, err
}

// ServerFactory returns a new wfganServerFactory instance.
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

	//read in the ipt file
	var iptList []float64
	if o2iEnabled {
		parPath, _ := path.Split(os.Args[0])
		iptList = utils.ReadFloatFromFile(path.Join(parPath, o2iRelPath))
	} else {
		log.Infof("O2I is not loaded.")
		iptList = []float64{}
	}

	wfganSf := wfganServerFactory{
		sf.(*defconn.DefConnServerFactory),
		st.tol, st.p, &iptList,
	}

	return &wfganSf, nil
}

type wfganClientFactory struct {
	*defconn.DefConnClientFactory
}

func (cf *wfganClientFactory) Transport() base.Transport {
	return cf.DefConnClientFactory.Transport()
}

func (cf *wfganClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	arguments, err := cf.DefConnClientFactory.ParseArgs(args)

	tol, err := utils.GetFloatArgFromStr(tolArg, args)
	if err != nil {
		return nil, err
	}
	p, err := utils.GetFloatArgFromStr(pArg, args)
	if err != nil {
		return nil, err
	}

	return &wfganClientArgs{ arguments.(*defconn.DefConnClientArgs),
		float32(tol.(float64)), float32(p.(float64)),
	}, nil
}

func (cf *wfganClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	defConn, err := cf.DefConnClientFactory.Dial(network, addr, dialFn, args)
	if err != nil {
		return nil, err
	}

	//read in the ipt file
	parPath, _ := path.Split(os.Args[0])
	iptList := utils.ReadFloatFromFile(path.Join(parPath, o2oRelPath))

	argsT := args.(*wfganClientArgs)
	c := &wfganConn {
		defConn.(*defconn.DefConn),
		argsT.tol, argsT.p, float64(argsT.p), nil,&iptList,
	}
	return c, nil
}

type wfganServerFactory struct {
	*defconn.DefConnServerFactory
	tol          float32
	p            float32
	iptList      *[]float64

}


func (sf *wfganServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	defConn, err := sf.DefConnServerFactory.WrapConn(conn)
	if err != nil {
		return nil, err
	}

	//read in the ipt file
	iptList := sf.iptList
	canSendChan := make(chan uint32, 100)  // just to make sure that this channel wont be blocked
	c := &wfganConn{
		defConn.(*defconn.DefConn),
		sf.tol, sf.p, float64(sf.p),canSendChan, iptList,
	}

	return c, nil
}


type wfganConn struct {
	*defconn.DefConn
	tol       float32
	p         float32    // the hyper param used to generate randomP
	randomP   float64    // the sampled p for each trace, i.e., the probability of proxy **not** to respond with a fake burst

	canSendChan          chan uint32
	iptList              *[]float64
}

type rrTuple struct {
	request  int32
	response int32
}


func (conn *wfganConn) Read(b []byte) (n int, err error) {
	return conn.DefConn.MyRead(b, conn.readPackets)
}

func (conn *wfganConn) ReadFrom(r io.Reader) (written int64, err error) {
	if conn.IsServer {
		return conn.ReadFromServer(r)
	} else {
		return conn.ReadFromClient(r)
	}
}

func (conn *wfganConn) ReadFromServer(r io.Reader) (written int64, err error) {
	log.Infof("[State] Enter copyloop state: %v", defconn.StateMap[conn.ConnState.LoadCurState()])
	defer close(conn.CloseChan)
	var receiveBuf utils.SafeBuffer //read payload from upstream and buffer here

	//create a go routine to send out packets to the wire
	go conn.Send()

	// go routine to receive data from upperstream
	go func() {
		for {
			select {
			case _, ok := <-conn.CloseChan:
				if !ok {
					log.Infof("[Routine] Send routine exits by closedChan.")
					return
				}
			default:
				buf := make([]byte, 65535)
				rdLen, err := r.Read(buf[:])
				if err!= nil {
					log.Errorf("[Routine] Exit by read err:%v", err)
					conn.ErrChan <- err
					return
				}
				if rdLen > 0 {
					_, werr := receiveBuf.Write(buf[: rdLen])
					if werr != nil {
						conn.ErrChan <- werr
						log.Errorf("[Routine] Exit by write err:%v", err)
						return
					}
				} else {
					log.Errorf("[Routine] BUG? read 0 bytes, err: %v", err)
					conn.ErrChan <- io.EOF
					return
				}
			}
		}
	}()

	//go routine to detect on/off
	go func() {
		for{
			select{
			case _, ok := <-conn.CloseChan:
				if !ok {
					log.Infof("[Routine] Detect on/off routine exits by closedChan.")
					return
				}
			default:
				if conn.ConnState.LoadCurState() == defconn.StateStop {
					conn.canSendChan <- 0
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	for {
		select {
		case conErr := <- conn.ErrChan:
			log.Infof("downstream copy loop terminated at %v. Reason: %v", time.Now().Format("15:04:05.000000"), conErr)
			return written, conErr
		case signalByteNum := <- conn.canSendChan:
			if signalByteNum == 0 {
				//defense off
				writtenTmp, werr := conn.sendRealBurst(&receiveBuf, conn.SendChan)
				written += writtenTmp
				if werr != nil {
					return written, werr
				}
			} else {
				//defense on
				skipRespond := utils.Bernoulli(conn.randomP)
				if receiveBuf.GetLen() == 0 && skipRespond == 1 {
					log.Infof("[Event] No data in buffer and get 1, skip this response.")
					continue
				}
				ipt := conn.sampleIPT()
				log.Debugf("[Event] Should sleep %v at %v", ipt, time.Now().Format("15:04:05.000000"))
				utils.SleepRho(time.Now(), ipt)
				//log.Debugf("[Event] Finish sleep at %v", time.Now().Format("15:04:05.000000"))

				writtenTmp := conn.sendRefBurst(signalByteNum, &receiveBuf, conn.SendChan)
				written += writtenTmp
			}
		}
	}
}

func (conn *wfganConn) ReadFromClient(r io.Reader) (written int64, err error) {
	log.Infof("[State] Enter copyloop state: %v", defconn.StateMap[conn.ConnState.LoadCurState()])
	defer close(conn.CloseChan)

	refillChan := make(chan bool, 1000) // signal gRPC to refill the burst sequence queue
	
	var receiveBuf utils.SafeBuffer //read payload from upstream and buffer here
	var burstQueue = queue.NewFixedFIFO(maxQueueSize)// maintain a queue of burst seqs

	//create a go routine to send out packets to the wire
	go conn.Send()

	//create a go routine to maintain burst sequence queue
	//true: need to refill the channel
	//false: need to dequeue the channel
	go func() {
		for{
			select{
			case _, ok := <- conn.CloseChan:
				if !ok{
					log.Infof("[Routine] padding factory exits by closedChan.")
					return
				}
			case <- refillChan:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				grpcConn, gErr := grpc.DialContext(ctx, gRPCAddr, grpc.WithInsecure(), grpc.WithBlock())
				cancel()
				if gErr != nil {
					log.Errorf("[gRPC] Cannot connect to py server. Exit the program.")
					conn.ErrChan <- gErr
					return
				}
				client := pb.NewGenerateTraceClient(grpcConn)
				//log.Debugf("[gRPC] Succeed to connect to py server.")
				req := &pb.GANRequest{Ask: 1}
				resp, rErr := client.Query(context.Background(), req)
				if rErr!= nil{
					log.Errorf("[gRPC] Error in request %v",err)
				}
				_  = grpcConn.Close()
				log.Debugf("[gRPC] Before: Refill queue (size %v) with %v elements at %v", burstQueue.GetLen(), len(resp.Packets)/2, time.Now().Format("15:04:05.000000"))
				for i := 0; i < len(resp.Packets) - 1; i += 2 {
					qerr := burstQueue.Enqueue(rrTuple{request: resp.Packets[i], response: resp.Packets[i+1]})
					if qerr != nil {
						log.Errorf("[gRPC] Error happened when enqueue: %v", qerr)
						break
					}
				}
				log.Debugf("[gRPC] After: Refilled queue (size %v) with %v elements at %v", burstQueue.GetLen(), len(resp.Packets)/2, time.Now().Format("15:04:05.000000"))
			default:
				//client, defense on
				// if the capacity of burstQueue is small, refill the queue
				capacity := float64(burstQueue.GetLen()) / float64(maxQueueSize)
				if !conn.IsServer && capacity < 0.1 {
					log.Debugf("[Event] Low queue capacity %.2f, triggering refill event at %v", capacity, time.Now().Format("15:04:05.000000"))
					refillChan <- true
				}
				time.Sleep(50 * time.Millisecond)
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
				log.Debugf("[State] Real Sent: %v, Real Receive: %v, curState: %s at %v.", conn.NRealSegSentLoad(), conn.NRealSegRcvLoad(), defconn.StateMap[conn.ConnState.LoadCurState()], time.Now().Format("15:04:05.000000"))
				if conn.ConnState.LoadCurState() != defconn.StateStop {
					if conn.NRealSegSentLoad() < 2 || conn.NRealSegRcvLoad() < 2 {
						log.Infof("[State] Real Sent: %v, Real Receive: %v, %s -> %s at %v.", conn.NRealSegSentLoad(), conn.NRealSegRcvLoad(), defconn.StateMap[conn.ConnState.LoadCurState()], defconn.StateMap[defconn.StateStop], time.Now().Format("15:04:05.000000"))
						conn.ConnState.SetState(defconn.StateStop)
						conn.SendChan <-defconn.PacketInfo{PktType: defconn.PacketTypeSignalStop, Data: []byte{}, PadLen: defconn.MaxPacketPaddingLength}
					}
				}
				conn.NRealSegReset()
			}
		}
	}()

	// go routine to receive data from upperstream
	go func() {
		for {
			select {
			case _, ok := <-conn.CloseChan:
				if !ok {
					log.Infof("[Routine] Send routine exits by closedChan.")
					return
				}
			default:
				buf := make([]byte, 65535)
				rdLen, err := r.Read(buf[:])
				if err!= nil {
					log.Errorf("Exit by read err:%v", err)
					conn.ErrChan <- err
					return
				}
				if rdLen > 0 {
					_, werr := receiveBuf.Write(buf[: rdLen])
					if werr != nil {
						conn.ErrChan <- werr
						return
					}
					//signal server to start if there is more than one cell coming
					// else switch to padding state
					// stop -> ready -> start
					if (conn.ConnState.LoadCurState() == defconn.StateStop && rdLen > defconn.MaxPacketPayloadLength) ||
						(conn.ConnState.LoadCurState() == defconn.StateReady) {
						// stateStop with >2 cells -> stateStart
						// or stateReady with >0 cell -> stateStart
						log.Infof("[State] Got %v bytes upstream, %s -> %s.", rdLen, defconn.StateMap[conn.ConnState.LoadCurState()], defconn.StateMap[defconn.StateStart])
						conn.ConnState.SetState(defconn.StateStart)
						conn.SendChan <- defconn.PacketInfo{PktType: defconn.PacketTypeSignalStart, Data: []byte{}, PadLen: defconn.MaxPacketPaddingLength}
					} else if conn.ConnState.LoadCurState() == defconn.StateStop {
						log.Infof("[State] Got %v bytes upstream, %s -> %s.", rdLen, defconn.StateMap[defconn.StateStop], defconn.StateMap[defconn.StateReady])
						conn.ConnState.SetState(defconn.StateReady)
					}
				} else {
					log.Errorf("BUG? read 0 bytes, err: %v", err)
					conn.ErrChan <- io.EOF
					return
				}
			}
		}
	}()

	for {
		select {
		case conErr := <- conn.ErrChan:
			log.Infof("downstream copy loop terminated at %v. Reason: %v", time.Now().Format("15:04:05.000000"), conErr)
			return written, conErr
		default:
			if conn.ConnState.LoadCurState() == defconn.StateStart {
				//defense on, client: sample an ipt and send out a burst
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				burstTuple, qerr := burstQueue.DequeueOrWaitForNextElementContext(ctx)
				cancel()
				if qerr != nil {
					log.Infof("The queue is empty for 1 second, something wrong happened? Try again.")
					break
				}
				log.Debugf("[Event] Sample a burst tuple: %v", burstTuple)
				requestSize := burstTuple.(rrTuple).request
				responseSize := burstTuple.(rrTuple).response
				writtenTmp := conn.sendRefBurst(uint32(requestSize), &receiveBuf, conn.SendChan)
				written += writtenTmp
				//send a finish signal
				var payload [4]byte
				binary.BigEndian.PutUint32(payload[:], uint32(responseSize))
				conn.SendChan <- defconn.PacketInfo{PktType: defconn.PacketTypeFinish, Data: payload[:], PadLen: uint16(defconn.MaxPacketPaddingLength-4)}
				log.Debugf("[ON] Response size %v", responseSize)

				ipt := conn.sampleIPT()
				log.Debugf("[Event] Should sleep %v at %v", ipt, time.Now().Format("15:04:05.000000"))
				utils.SleepRho(time.Now(), ipt)
				//log.Debugf("[Event] Finish sleep at %v", time.Now().Format("15:04:05.000000"))

			} else {
				//defense off (in stop or ready)
				writtenTmp, werr := conn.sendRealBurst(&receiveBuf, conn.SendChan)
				written += writtenTmp
				if werr != nil {
					return written, werr
				}
				time.Sleep(50 * time.Millisecond) //avoid infinite loop
			}
		}
	}
}


func (conn *wfganConn) sampleIPT() time.Duration {
	//// Fixed time gap code
	//if conn.isServer {
	//	return 0 * time.Millisecond
	//} else {
	//	return tmpRho * time.Millisecond
	//}
	var ipt float64
	if len(*conn.iptList) == 0 {
		//log.Debugf("iptList is not given, return 0.")
		ipt = 0
	} else {
		ipt = utils.SampleIPT(*conn.iptList)
	}
	if ipt > tmpRho {
		ipt = tmpRho
	}
	return time.Duration(ipt) * time.Millisecond
}

func (conn *wfganConn) sendRefBurst(refBurstSize uint32, receiveBuf *utils.SafeBuffer, sendChan chan defconn.PacketInfo) (written int64) {
	lowerBound := utils.IntMax(int(math.Round(float64(refBurstSize) * float64(1 - conn.tol))), 536)
	upperBound := int(math.Round(float64(refBurstSize) * float64(1 + conn.tol)))

	var toSend int
	bufSize := receiveBuf.GetLen()
	if bufSize < lowerBound {
		toSend = lowerBound
	} else if bufSize < upperBound {
		toSend = bufSize
	} else {
		toSend = upperBound
	}

	log.Debugf("[ON] Ref: %v bytes, lower: %v bytes, upper: %v bytes, bufSize: %v, toSend: %v bytes at %v", refBurstSize, lowerBound, upperBound, bufSize, toSend, time.Now().Format("15:04:05.000000"))
	for toSend >= defconn.MaxPacketPayloadLength {
		var payload [defconn.MaxPacketPayloadLength]byte
		rdLen, _ := receiveBuf.Read(payload[:])
		written += int64(rdLen)
		var pktType uint8
		if rdLen > 0{
			pktType = defconn.PacketTypePayload
			if !conn.IsServer {
				conn.NRealSegSentIncrement()
			}
		} else {
			// no data, send out a dummy packet
			pktType = defconn.PacketTypeDummy
		}
		sendChan <- defconn.PacketInfo{PktType: pktType, Data: payload[:rdLen], PadLen: uint16(defconn.MaxPacketPaddingLength-rdLen)}
		toSend -= defconn.MaxPacketPayloadLength
	}
	return written
}

func (conn *wfganConn) sendRealBurst(receiveBuf *utils.SafeBuffer, sendChan chan defconn.PacketInfo) (written int64, err error) {
	if size:= receiveBuf.GetLen(); size > 0 {
		log.Debugf("[OFF] Send %v bytes at %v", size, time.Now().Format("15:04:05.000000"))
	}
	for receiveBuf.GetLen() > 0 {
		var payload [defconn.MaxPacketPayloadLength]byte
		rdLen, rdErr := receiveBuf.Read(payload[:])
		written += int64(rdLen)
		if rdErr != nil {
			log.Infof("Exit by read buffer err:%v", rdErr)
			return written, rdErr
		}
		sendChan <- defconn.PacketInfo{PktType: defconn.PacketTypePayload, Data: payload[:rdLen], PadLen: uint16(defconn.MaxPacketPaddingLength-rdLen)}
		if !conn.IsServer {
			conn.NRealSegSentIncrement()
		}
	}
	return
}


var _ base.ClientFactory = (*wfganClientFactory)(nil)
var _ base.ServerFactory = (*wfganServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*wfganConn)(nil)