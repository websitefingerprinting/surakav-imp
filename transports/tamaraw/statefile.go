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

package tamaraw

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/common/csrand"
	"github.com/websitefingerprinting/wfdef.git/common/drbg"
	"github.com/websitefingerprinting/wfdef.git/common/ntor"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	stateFile  = "tamaraw_state.json"
	bridgeFile = "tamaraw_bridgeline.txt"

	certSuffix = "=="
	certLength = ntor.NodeIDLength + ntor.PublicKeyLength
)

type jsonServerState struct {
	NodeID     string         `json:"node-id"`
	PrivateKey string         `json:"private-key"`
	PublicKey  string         `json:"public-key"`
	DrbgSeed   string         `json:"drbg-seed"`
	NSeg       int            `json:"nseg"`
	RhoServer  int            `json:"rho-server"`
	RhoClient  int            `json:"rho-client"`
}

type tamarawServerCert struct {
	raw []byte
}

func (cert *tamarawServerCert) String() string {
	return strings.TrimSuffix(base64.StdEncoding.EncodeToString(cert.raw), certSuffix)
}

func (cert *tamarawServerCert) unpack() (*ntor.NodeID, *ntor.PublicKey) {
	if len(cert.raw) != certLength {
		panic(fmt.Sprintf("cert length %d is invalid", len(cert.raw)))
	}

	nodeID, _ := ntor.NewNodeID(cert.raw[:ntor.NodeIDLength])
	pubKey, _ := ntor.NewPublicKey(cert.raw[ntor.NodeIDLength:])

	return nodeID, pubKey
}

func serverCertFromString(encoded string) (*tamarawServerCert, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded + certSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %s", err)
	}

	if len(decoded) != certLength {
		return nil, fmt.Errorf("cert length %d is invalid", len(decoded))
	}

	return &tamarawServerCert{raw: decoded}, nil
}

func serverCertFromState(st *tamarawServerState) *tamarawServerCert {
	cert := new(tamarawServerCert)
	cert.raw = append(st.nodeID.Bytes()[:], st.identityKey.Public().Bytes()[:]...)
	return cert
}

type tamarawServerState struct {
	nodeID      *ntor.NodeID
	identityKey *ntor.Keypair
	drbgSeed    *drbg.Seed
	nSeg        int
	rhoServer   int
	rhoClient   int
	cert        *tamarawServerCert
}

func (st *tamarawServerState) clientString() string {
	return fmt.Sprintf("%s=%s %s=%d %s=%d %s=%d", certArg, st.cert, nSegArg, st.nSeg,
		rhoServerArg, st.rhoServer, rhoClientArg, st.rhoClient)
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*tamarawServerState, error) {
	var js jsonServerState
	var nodeIDOk, privKeyOk, seedOk bool
	js.NodeID, nodeIDOk = args.Get(nodeIDArg)
	js.PrivateKey, privKeyOk = args.Get(privateKeyArg)
	js.DrbgSeed, seedOk = args.Get(seedArg)
	nSegStr, nSegOk := args.Get(nSegArg)
	rhoClientStr, rhoClientOk := args.Get(rhoClientArg)
	rhoServerStr, rhoServerOk := args.Get(rhoServerArg)

	// Either a private key, node id, and seed are ALL specified, or
	// they should be loaded from the state file.
	if !privKeyOk && !nodeIDOk && !seedOk {
		if err := jsonServerStateFromFile(stateDir, &js); err != nil {
			return nil, err
		}
	} else if !privKeyOk {
		return nil, fmt.Errorf("missing argument '%s'", privateKeyArg)
	} else if !nodeIDOk {
		return nil, fmt.Errorf("missing argument '%s'", nodeIDArg)
	} else if !seedOk {
		return nil, fmt.Errorf("missing argument '%s'", seedArg)
	}

	// The tamaraw params should be independently configurable.
	if nSegOk {
		nSeg, err := strconv.Atoi(nSegStr)
		if err != nil {
			return nil, fmt.Errorf("malformed nseg '%s'", nSegStr)
		}
		js.NSeg = nSeg
	} else {
		return nil, fmt.Errorf("missing argument '%s'", nSegArg)
	}

	if rhoClientOk {
		rhoClientInt, err := strconv.Atoi(rhoClientStr)
		if err != nil {
			return nil, fmt.Errorf("malformed rho-client '%s'", rhoClientStr)
		}
		js.RhoClient = rhoClientInt
	} else {
		return nil, fmt.Errorf("missing argument '%s'", rhoClientArg)
	}

	if rhoServerOk {
		rhoServerInt, err := strconv.Atoi(rhoServerStr)
		if err != nil {
			return nil, fmt.Errorf("malformed rho-server '%s'", rhoServerStr)
		}
		js.RhoServer = rhoServerInt
	} else {
		return nil, fmt.Errorf("missing argument '%s'", rhoServerArg)
	}
	return serverStateFromJSONServerState(stateDir, &js)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState) (*tamarawServerState, error) {
	var err error

	st := new(tamarawServerState)
	if st.nodeID, err = ntor.NodeIDFromHex(js.NodeID); err != nil {
		return nil, err
	}
	if st.identityKey, err = ntor.KeypairFromHex(js.PrivateKey); err != nil {
		return nil, err
	}
	if st.drbgSeed, err = drbg.SeedFromHex(js.DrbgSeed); err != nil {
		return nil, err
	}
	if js.NSeg < 0 {
		return nil, fmt.Errorf("invalid nseg '%d'", js.NSeg)
	}
	if js.RhoServer < 0 {
		return nil, fmt.Errorf("invalid rho-server '%d'", js.RhoServer)
	}
	if js.RhoClient < 0 {
		return nil, fmt.Errorf("invalid rho-client '%d'", js.RhoClient)
	}
	// time unit ms
	st.nSeg = js.NSeg
	st.rhoServer = js.RhoServer
	st.rhoClient = js.RhoClient

	st.cert = serverCertFromState(st)

	// Generate a human readable summary of the configured endpoint.
	if err = newBridgeFile(stateDir, st); err != nil {
		return nil, err
	}

	// Write back the possibly updated server state.
	return st, writeJSONServerState(stateDir, js)
}

func jsonServerStateFromFile(stateDir string, js *jsonServerState) error {
	fPath := path.Join(stateDir, stateFile)
	f, err := ioutil.ReadFile(fPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err = newJSONServerState(stateDir, js); err == nil {
				return nil
			}
		}
		return err
	}

	if err := json.Unmarshal(f, js); err != nil {
		return fmt.Errorf("failed to load statefile '%s': %s", fPath, err)
	}

	return nil
}

func newJSONServerState(stateDir string, js *jsonServerState) (err error) {
	// Generate everything a server needs, using the cryptographic PRNG.
	var st tamarawServerState
	rawID := make([]byte, ntor.NodeIDLength)
	if err = csrand.Bytes(rawID); err != nil {
		return
	}
	if st.nodeID, err = ntor.NewNodeID(rawID); err != nil {
		return
	}
	if st.identityKey, err = ntor.NewKeypair(false); err != nil {
		return
	}
	if st.drbgSeed, err = drbg.NewSeed(); err != nil {
		return
	}

	// Encode it into JSON format and write the state file.
	js.NodeID = st.nodeID.Hex()
	js.PrivateKey = st.identityKey.Private().Hex()
	js.PublicKey = st.identityKey.Public().Hex()
	js.DrbgSeed = st.drbgSeed.Hex()

	return writeJSONServerState(stateDir, js)
}

func writeJSONServerState(stateDir string, js *jsonServerState) error {
	var err error
	var encoded []byte
	if encoded, err = json.Marshal(js); err != nil {
		return err
	}
	if err = ioutil.WriteFile(path.Join(stateDir, stateFile), encoded, 0600); err != nil {
		return err
	}

	return nil
}

func newBridgeFile(stateDir string, st *tamarawServerState) error {
	const prefix = "# tamaraw torrc client bridge line\n" +
		"#\n" +
		"# This file is an automatically generated bridge line based on\n" +
		"# the current tamarawproxy configuration.  EDITING IT WILL HAVE\n" +
		"# NO EFFECT.\n" +
		"#\n" +
		"# Before distributing this Bridge, edit the placeholder fields\n" +
		"# to contain the actual values:\n" +
		"#  <IP ADDRESS>  - The public IP address of your tamaraw bridge.\n" +
		"#  <PORT>        - The TCP/IP port of your tamaraw bridge.\n" +
		"#  <FINGERPRINT> - The bridge's fingerprint.\n\n"

	bridgeLine := fmt.Sprintf("Bridge tamaraw <IP ADDRESS>:<PORT> <FINGERPRINT> %s\n",
		st.clientString())

	tmp := []byte(prefix + bridgeLine)
	if err := ioutil.WriteFile(path.Join(stateDir, bridgeFile), tmp, 0600); err != nil {
		return err
	}

	return nil
}
