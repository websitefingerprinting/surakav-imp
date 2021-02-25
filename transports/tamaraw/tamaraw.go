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

// package tamaraw provides an implementation of the Tor Project's tamaraw
// obfuscation protocol.
package tamaraw // import "github.com/websitefingerprinting/wfdef.git/transports/tamaraw"

import (
	"bytes"
	"fmt"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/transports/pb"
	"google.golang.org/grpc"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/common/drbg"
	"github.com/websitefingerprinting/wfdef.git/common/ntor"
	"github.com/websitefingerprinting/wfdef.git/common/probdist"
	"github.com/websitefingerprinting/wfdef.git/common/replayfilter"
	"github.com/websitefingerprinting/wfdef.git/transports/base"
	"github.com/websitefingerprinting/wfdef.git/transports/tamaraw/framing"
)

const (
	transportName = "tamaraw"

	nodeIDArg     = "node-id"
	publicKeyArg  = "public-key"
	privateKeyArg = "private-key"
	seedArg       = "drbg-seed"
	certArg       = "cert"
	rhoServerArg  = "rho-server"
	rhoClientArg  = "rho-client"
	nSegArg       = "nseg"


	seedLength             = drbg.SeedLength
	headerLength           = framing.FrameOverhead + packetOverhead
	clientHandshakeTimeout = time.Duration(60) * time.Second
	serverHandshakeTimeout = time.Duration(30) * time.Second
	replayTTL              = time.Duration(3) * time.Hour

	maxCloseDelay      = 60
	tWindow            = 1000 * time.Millisecond

	gRPCAddr           = "localhost:10086"
	traceLogEnabled    = true
)

type tamarawClientArgs struct {
	nodeID     *ntor.NodeID
	publicKey  *ntor.PublicKey
	sessionKey *ntor.Keypair
	nSeg       int
	rhoServer  int   // in milliseconds
	rhoClient  int  // in milliseconds
}

// Transport is the tamaraw implementation of the base.Transport interface.
type Transport struct{}

// Name returns the name of the tamaraw transport protocol.
func (t *Transport) Name() string {
	return transportName
}

// ClientFactory returns a new tamarawClientFactory instance.
func (t *Transport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	cf := &tamarawClientFactory{transport: t}
	return cf, nil
}

// ServerFactory returns a new tamarawServerFactory instance.
func (t *Transport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	st, err := serverStateFromArgs(stateDir, args)
	if err != nil {
		return nil, err
	}


	// Store the arguments that should appear in our descriptor for the clients.
	ptArgs := pt.Args{}
	ptArgs.Add(certArg, st.cert.String())
	ptArgs.Add(nSegArg, strconv.Itoa(st.nSeg))
	ptArgs.Add(rhoServerArg, strconv.Itoa(st.rhoServer))
	ptArgs.Add(rhoClientArg, strconv.Itoa(st.rhoClient))


	// Initialize the replay filter.
	filter, err := replayfilter.New(replayTTL)
	if err != nil {
		return nil, err
	}

	// Initialize the close thresholds for failed connections.
	drbg, err := drbg.NewHashDrbg(st.drbgSeed)
	if err != nil {
		return nil, err
	}
	rng := rand.New(drbg)

	sf := &tamarawServerFactory{t, &ptArgs, st.nodeID, st.identityKey, st.drbgSeed, st.nSeg, st.rhoServer, st.rhoClient, filter, rng.Intn(maxCloseDelay)}
	return sf, nil
}

type tamarawClientFactory struct {
	transport base.Transport
}

func (cf *tamarawClientFactory) Transport() base.Transport {
	return cf.transport
}

func (cf *tamarawClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	var nodeID *ntor.NodeID
	var publicKey *ntor.PublicKey

	// The "new" (version >= 0.0.3) bridge lines use a unified "cert" argument
	// for the Node ID and Public Key.
	certStr, ok := args.Get(certArg)
	if ok {
		cert, err := serverCertFromString(certStr)
		if err != nil {
			return nil, err
		}
		nodeID, publicKey = cert.unpack()
	} else {
		// The "old" style (version <= 0.0.2) bridge lines use separate Node ID
		// and Public Key arguments in Base16 encoding and are a UX disaster.
		nodeIDStr, ok := args.Get(nodeIDArg)
		if !ok {
			return nil, fmt.Errorf("missing argument '%s'", nodeIDArg)
		}
		var err error
		if nodeID, err = ntor.NodeIDFromHex(nodeIDStr); err != nil {
			return nil, err
		}

		publicKeyStr, ok := args.Get(publicKeyArg)
		if !ok {
			return nil, fmt.Errorf("missing argument '%s'", publicKeyArg)
		}
		if publicKey, err = ntor.PublicKeyFromHex(publicKeyStr); err != nil {
			return nil, err
		}
	}


	nSegStr, nSegOk := args.Get(nSegArg)
	if !nSegOk {
		return nil, fmt.Errorf("missing argument '%s'", nSegArg)
	}
	nSeg, err := strconv.Atoi(nSegStr)
	if err != nil {
		return nil, fmt.Errorf("malformed nseg '%s'", nSegStr)
	}

	rhoServerStr, rhoServerOk := args.Get(rhoServerArg)
	if !rhoServerOk {
		return nil, fmt.Errorf("missing argument '%s'", rhoServerArg)

	}
	rhoServer, err := strconv.Atoi(rhoServerStr)
	if err != nil {
		return nil, fmt.Errorf("malformed rho-client '%s'", rhoServerStr)
	}
	
	rhoClientStr, rhoClientOk := args.Get(rhoClientArg)
	if !rhoClientOk {
		return nil, fmt.Errorf("missing argument '%s'", rhoClientArg)

	}
	rhoClient, err := strconv.Atoi(rhoClientStr)
	if err != nil {
		return nil, fmt.Errorf("malformed rho-client '%s'", rhoClientStr)
	}


	// Generate the session key pair before connectiong to hide the Elligator2
	// rejection sampling from network observers.
	sessionKey, err := ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}

	return &tamarawClientArgs{nodeID, publicKey, sessionKey, nSeg, rhoServer, rhoClient}, nil
}

func (cf *tamarawClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	// Validate args before bothering to open connection.
	ca, ok := args.(*tamarawClientArgs)
	if !ok {
		return nil, fmt.Errorf("invalid argument type for args")
	}
	conn, err := dialFn(network, addr)
	if err != nil {
		return nil, err
	}
	dialConn := conn
	if conn, err = newTamarawClientConn(conn, ca); err != nil {
		dialConn.Close()
		return nil, err
	}
	return conn, nil
}

type tamarawServerFactory struct {
	transport base.Transport
	args      *pt.Args

	nodeID       *ntor.NodeID
	identityKey  *ntor.Keypair
	lenSeed      *drbg.Seed
	
	nSeg        int
	rhoServer    int
	rhoClient    int
	
	replayFilter *replayfilter.ReplayFilter
	closeDelay int
}

func (sf *tamarawServerFactory) Transport() base.Transport {
	return sf.transport
}

func (sf *tamarawServerFactory) Args() *pt.Args {
	return sf.args
}

func (sf *tamarawServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	// Not much point in having a separate newObfs4ServerConn routine when
	// wrapping requires using values from the factory instance.

	// Generate the session keypair *before* consuming data from the peer, to
	// attempt to mask the rejection sampling due to use of Elligator2.  This
	// might be futile, but the timing differential isn't very large on modern
	// hardware, and there are far easier statistical attacks that can be
	// mounted as a distinguisher.
	sessionKey, err := ntor.NewKeypair(true)
	if err != nil {
		return nil, err
	}

	lenDist := probdist.New(sf.lenSeed, 0, framing.MaximumSegmentLength, false)
	logger := &traceLogger{gPRCServer: grpc.NewServer(), logOn: nil, logPath: nil}
	// The server's initial state is intentionally set to stateStart at the very beginning to obfuscate the RTT between client and server
	c := &tamarawConn{conn, true, lenDist,  sf.nSeg, sf.rhoClient, sf.rhoServer, logger, stateStop, nil, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}
	log.Debugf("Server pt con status: %v %v %v %v", c.isServer, c.nSeg, c.rhoClient, c.rhoServer)
	startTime := time.Now()

	if err = c.serverHandshake(sf, sessionKey); err != nil {
		log.Errorf("Handshake err %v", err)
		c.closeAfterDelay(sf, startTime)
		return nil, err
	}

	return c, nil
}

type tamarawConn struct {
	net.Conn

	isServer  bool

	lenDist   *probdist.WeightedDist
	nSeg       int
	rhoClient  int
	rhoServer  int

	logger *traceLogger

	state     uint32

	loggerChan           chan []int64
	receiveBuffer        *bytes.Buffer
	receiveDecodedBuffer *bytes.Buffer
	readBuffer           []byte

	encoder *framing.Encoder
	decoder *framing.Decoder
}


func newTamarawClientConn(conn net.Conn, args *tamarawClientArgs) (c *tamarawConn, err error) {
	// Generate the initial protocol polymorphism distribution(s).
	var seed *drbg.Seed
	if seed, err = drbg.NewSeed(); err != nil {
		return
	}
	lenDist := probdist.New(seed, 0, framing.MaximumSegmentLength, false)
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
	logger := &traceLogger{gPRCServer: server, logOn: &logOn, logPath: &logPath}

	pb.RegisterTraceLoggingServer(logger.gPRCServer, &traceLoggingServer{callBack:logger.UpdateLogInfo})
	if traceLogEnabled {
		listen, err := net.Listen("tcp", gRPCAddr)
		if err != nil {
			log.Errorf("Fail to launch gRPC service err: %v", err)
			return nil, err
		}
		go func() {
			log.Noticef("[Routine] gRPC server starts listeners.")
			server.Serve(listen)
			log.Noticef("[Routine] gRPC server exits.")
		}()
	}

	// Allocate the client structure.
	c = &tamarawConn{conn, false, lenDist, args.nSeg, args.rhoClient, args.rhoServer, logger, stateStop, loggerChan, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	log.Debugf("client pt con status: %v %v %v %v", c.isServer, c.nSeg, c.rhoClient, c.rhoServer)
	// Start the handshake timeout.
	deadline := time.Now().Add(clientHandshakeTimeout)
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	if err = c.clientHandshake(args.nodeID, args.publicKey, args.sessionKey); err != nil {
		return nil, err
	}

	// Stop the handshake timeout.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return
}

func (conn *tamarawConn) clientHandshake(nodeID *ntor.NodeID, peerIdentityKey *ntor.PublicKey, sessionKey *ntor.Keypair) error {
	if conn.isServer {
		return fmt.Errorf("clientHandshake called on server connection")
	}

	// Generate and send the client handshake.
	hs := newClientHandshake(nodeID, peerIdentityKey, sessionKey)
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	if _, err = conn.Conn.Write(blob); err != nil {
		return err
	}

	// Consume the server handshake.
	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])

		n, seed, err := hs.parseServerHandshake(conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		_ = conn.receiveBuffer.Next(n)

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[:framing.KeyLength])
		conn.decoder = framing.NewDecoder(okm[framing.KeyLength:])

		return nil
	}
}

func (conn *tamarawConn) serverHandshake(sf *tamarawServerFactory, sessionKey *ntor.Keypair) error {
	if !conn.isServer {
		return fmt.Errorf("serverHandshake called on client connection")
	}

	// Generate the server handshake, and arm the base timeout.
	hs := newServerHandshake(sf.nodeID, sf.identityKey, sessionKey)
	if err := conn.Conn.SetDeadline(time.Now().Add(serverHandshakeTimeout)); err != nil {
		return err
	}

	// Consume the client handshake.
	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])

		seed, err := hs.parseClientHandshake(sf.replayFilter, conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		conn.receiveBuffer.Reset()

		if err := conn.Conn.SetDeadline(time.Time{}); err != nil {
			return nil
		}

		// Use the derived key material to intialize the link crypto.
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[framing.KeyLength:])
		conn.decoder = framing.NewDecoder(okm[:framing.KeyLength])

		break
	}

	// Since the current and only implementation always sends a PRNG seed for
	// the length obfuscation, this makes the amount of data received from the
	// server inconsistent with the length sent from the client.
	//
	// Rebalance this by tweaking the client mimimum padding/server maximum
	// padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
	// as part of the server response).  See inlineSeedFrameLength in
	// handshake_ntor.go.

	// Generate/send the response.
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	var frameBuf bytes.Buffer
	if _, err = frameBuf.Write(blob); err != nil {
		return err
	}

	// Send the PRNG seed as the first packet.
	if err := conn.makePacket(&frameBuf, packetTypePrngSeed, sf.lenSeed.Bytes()[:], 0); err != nil {
		return err
	}
	if _, err = conn.Conn.Write(frameBuf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (conn *tamarawConn) Read(b []byte) (n int, err error) {
	// If there is no payload from the previous Read() calls, consume data off
	// the network.  Not all data received is guaranteed to be usable payload,
	// so do this in a loop till data is present or an error occurs.
	for conn.receiveDecodedBuffer.Len() == 0 {
		err = conn.readPackets()
		if err == framing.ErrAgain {
			// Don't proagate this back up the call stack if we happen to break
			// out of the loop.
			err = nil
			continue
		} else if err != nil {
			break
		}
	}

	// Even if err is set, attempt to do the read anyway so that all decoded
	// data gets relayed before the connection is torn down.
	if conn.receiveDecodedBuffer.Len() > 0 {
		var berr error
		n, berr = conn.receiveDecodedBuffer.Read(b)
		if err == nil {
			// Only propagate berr if there are not more important (fatal)
			// errors from the network/crypto/packet processing.
			err = berr
		}
	}

	return
}

func (conn *tamarawConn) ReadFrom(r io.Reader) (written int64, err error) {
	log.Debugf("[State] Enter copyloop state: %v (%v is stateStart, %v is statStop)", conn.state, stateStart, stateStop)
	closeChan := make(chan int)
	defer close(closeChan)
	defer close(conn.loggerChan)
	defer conn.logger.gPRCServer.Stop()

	errChan := make(chan error, 5)
	var rho time.Duration
	if conn.isServer {
		rho = time.Duration(conn.rhoServer * 1e6)
	} else {
		rho = time.Duration(conn.rhoClient * 1e6)
	}

	var curNSeg = 0
	var nRealSeg uint32 = 0 //the number of real packets over the latest windowSize time

	//client side launch trace logger routine
	if traceLogEnabled && !conn.isServer {
		go func() {
			log.Noticef("[Routine] Client traceLogger turns on.")
			for {
				select {
				case _, ok := <- closeChan:
					if !ok {
						log.Noticef("[Routine] traceLogger exits by closeChan signal.")
						return
					}
				case pktinfo, ok := <- conn.loggerChan:
					if !ok {
						log.Debugf("[Routine] traceLogger exits: %v.")
						return
					}
					_ = conn.logger.LogTrace(pktinfo[0], pktinfo[1], pktinfo[2])
				}
			}
		}()
	}

	//create a go routine to buffer data from upstream
	var ReceiveBuf bytes.Buffer
	go func() {
		log.Noticef("[Routine] Reader routine turns on.")
		for {
			select {
			case _, ok := <- closeChan:
				if !ok {
					log.Noticef("[Routine] Read go routine exits by closeChan signal.")
					return
				}
			default:
				buf := make([]byte, 65535)
				n, err := r.Read(buf)
				if err != nil {
					errChan <- err
					log.Noticef("[Routine] Read go routine exits: %v", err)
					return
				}
				if n > 0 {
					ReceiveBuf.Write(buf[:n])
					// stateStop -> stateStart
					if  !conn.isServer && atomic.LoadUint32(&conn.state) == stateStop {
						var frameBuf bytes.Buffer
						err = conn.makePacket(&frameBuf, uint8(packetTypeSignalStart), []byte{}, uint16(maxPacketPaddingLength))
						if err != nil {
							log.Noticef("[Routine] Read go routine exits: %v", err)
							errChan <- err
							return
						}
						_, err = conn.Conn.Write(frameBuf.Bytes())
						if err != nil {
							log.Noticef("[Routine] Read go routine exits: %v", err)
							errChan <- err
							return
						}
						log.Debugf("[State] stateStop -> stateStart. NRealSeg: %v. NSeg: %v", nRealSeg, curNSeg)
						atomic.StoreUint32(&conn.state, stateStart)
					}
				} else {
					log.Errorf("BUG? read 0 bytes, err: %v", err)
					errChan <- io.EOF
					return
				}
			}
		}
	}()

	lastSend := time.Now()
	lastWindowTime := time.Now()  // how much time has passed since last window reset
	for {
		select {
		case conErr := <- errChan:
			log.Noticef("downstream copy loop terminated at %v. Reason: %v", time.Now().Format("15:04:05.000000"), conErr)
			return written, conErr
		default:
			sleepRho(lastSend, rho)
			//log.Debugf("---Curstate:%v, CurNSeg:%v, CurNReal:%v, tElapse:%v at %v", atomic.LoadUint32(&conn.state), curNSeg, nRealSeg, tElapse, time.Now().Format("15:04:05.000000"))
			var payload [maxPacketPayloadLength]byte
			var frameBuf bytes.Buffer
			var packetType int
			readLen, readErr := ReceiveBuf.Read(payload[:])
			written += int64(readLen)
			if readLen == 0 {
				// ReceiveBuffer is empty
				packetType = packetTypeDummy
			} else {
				packetType = packetTypePayload
			}
			if readErr != nil && readErr != io.EOF {
				return written, readErr
			}
			if packetType == packetTypePayload || atomic.LoadUint32(&conn.state) != stateStop {
				err = conn.makePacket(&frameBuf, uint8(packetType), payload[:readLen], uint16(maxPacketPaddingLength-readLen))
				if err != nil {
					return 0, err
				}
				_, err = conn.Conn.Write(frameBuf.Bytes())
				if err != nil {
					log.Debugf("Can't write to connection. Reason: %v", err)
					return 0, err
				}
				if !conn.isServer && traceLogEnabled && conn.logger.logOn.Load().(bool) {
					//log.Debugf("Send %3d + %3d bytes, frame size %3d at %v", readLen, maxPacketPaddingLength-readLen, frameBuf.Len(), time.Now().Format("15:04:05.000000"))
					conn.loggerChan <- []int64{time.Now().UnixNano(), int64(readLen), int64(maxPacketPaddingLength-readLen)}
				}
				//log.Debugf("Send %3d + %3d bytes, frame size %3d at %v", readLen, maxPacketPaddingLength-readLen, frameBuf.Len(), time.Now().Format("15:04:05.000000"))
			}

			// update timestamp
			lastSend = time.Now()

			// The following updates are maintained by client.
			// 1. client regularly check the throughput over a time period (tWindow), if too few pkts, switch to statePaading
			// 2. when curNSeg % conn.NSeg == 0, stop padding and signal server.
			if !conn.isServer{
				// update curNSeg
				if atomic.LoadUint32(&conn.state) != stateStop {
					// only count the total pkts in stateStart/statePadding
					curNSeg += 1
					if packetType == packetTypePayload {
						nRealSeg += 1
					}
				}

				if time.Now().Sub(lastWindowTime) >= tWindow {
					// `tWindow` time has passed, time to check the number of real packets
					//log.Debugf("%v passed, NRealSeg: %v, NSeg: %v at %v", tWindow, nRealSeg, curNSeg, time.Now().Format("15:04:05.000000"))
					if atomic.LoadUint32(&conn.state) == stateStart && nRealSeg < 2 {
						//if `tWindow` time has passed, but number of real pkts no more than one,
						//(relax condition here, since sometimes even you are not loading pages, there is still some cells coming through)
						// we infer that the loading finishes and we should turn the machine into padding state.
						// stateStart -> statePadding
						log.Debugf("[State] stateStart -> statePadding. NRealSeg: %v. NSeg: %v", nRealSeg, curNSeg)
						atomic.StoreUint32(&conn.state, statePadding)
					}
					lastWindowTime = time.Now()
					nRealSeg = 0
				}

				if atomic.LoadUint32(&conn.state) == statePadding && curNSeg % conn.nSeg == 0 {
					// Tamaraw stop condition
					// statePadding -> stateStop
					// client is responsible to signal server to stop padding.
					// server does not stop padding until recieve client's signal
					log.Debugf("[State] statePadding -> stateStop. NRealSeg: %v. NSeg: %v", nRealSeg, curNSeg)
					atomic.StoreUint32(&conn.state, stateStop)
					curNSeg = 0
					sleepRho(lastSend, rho)

					var frameBuf bytes.Buffer
					err = conn.makePacket(&frameBuf, uint8(packetTypeSignalStop), []byte{}, uint16(maxPacketPaddingLength))
					if err != nil {
						return 0, err
					}
					_, err = conn.Conn.Write(frameBuf.Bytes())
					if err != nil {
						log.Errorf("Can't write to connection. Reason: %v", err)
						return 0, err
					}
					if !conn.isServer && traceLogEnabled && conn.logger.logOn.Load().(bool) {
						//log.Debugf("Send %3d + %3d bytes, frame size %3d at %v", len([]byte{}), maxPacketPaddingLength, frameBuf.Len(), time.Now().Format("15:04:05.000000"))
						conn.loggerChan <- []int64{time.Now().UnixNano(), 0, int64(maxPacketPaddingLength)}
					}
					//log.Debugf("Send %3d + %3d bytes, frame size %3d at %v", len([]byte{}), maxPacketPaddingLength, frameBuf.Len(), time.Now().Format("15:04:05.000000"))

					// update timestamp
					lastSend = time.Now()
				}
			}
		}
	}
}

func (conn *tamarawConn) SetDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *tamarawConn) SetWriteDeadline(t time.Time) error {
	return syscall.ENOTSUP
}

func (conn *tamarawConn) closeAfterDelay(sf *tamarawServerFactory, startTime time.Time) {
	// I-it's not like I w-wanna handshake with you or anything.  B-b-baka!
	defer conn.Conn.Close()

	delay := time.Duration(sf.closeDelay)*time.Second + serverHandshakeTimeout
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



var _ base.ClientFactory = (*tamarawClientFactory)(nil)
var _ base.ServerFactory = (*tamarawServerFactory)(nil)
var _ base.Transport = (*Transport)(nil)
var _ net.Conn = (*tamarawConn)(nil)
