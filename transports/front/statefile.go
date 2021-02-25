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

package front

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/common/csrand"
	"github.com/websitefingerprinting/wfdef.git/common/drbg"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/common/ntor"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	stateFile  = "front_state.json"
	bridgeFile = "front_bridgeline.txt"

	certSuffix = "=="
	certLength = ntor.NodeIDLength + ntor.PublicKeyLength
)

type jsonServerState struct {
	NodeID     string         `json:"node-id"`
	PrivateKey string         `json:"private-key"`
	PublicKey  string         `json:"public-key"`
	DrbgSeed   string         `json:"drbg-seed"`
	Wmin       float32        `json:"w-min"`
	Wmax       float32        `json:"w-max"`
	NServer    int            `json:"n-server"`
	NClient    int            `json:"n-client"`
}

type frontServerCert struct {
	raw []byte
}

func (cert *frontServerCert) String() string {
	return strings.TrimSuffix(base64.StdEncoding.EncodeToString(cert.raw), certSuffix)
}

func (cert *frontServerCert) unpack() (*ntor.NodeID, *ntor.PublicKey) {
	if len(cert.raw) != certLength {
		panic(fmt.Sprintf("cert length %d is invalid", len(cert.raw)))
	}

	nodeID, _ := ntor.NewNodeID(cert.raw[:ntor.NodeIDLength])
	pubKey, _ := ntor.NewPublicKey(cert.raw[ntor.NodeIDLength:])

	return nodeID, pubKey
}

func serverCertFromString(encoded string) (*frontServerCert, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded + certSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %s", err)
	}

	if len(decoded) != certLength {
		return nil, fmt.Errorf("cert length %d is invalid", len(decoded))
	}

	return &frontServerCert{raw: decoded}, nil
}

func serverCertFromState(st *frontServerState) *frontServerCert {
	cert := new(frontServerCert)
	cert.raw = append(st.nodeID.Bytes()[:], st.identityKey.Public().Bytes()[:]...)
	return cert
}

type frontServerState struct {
	nodeID      *ntor.NodeID
	identityKey *ntor.Keypair
	drbgSeed    *drbg.Seed
	wMin        float32
	wMax        float32
	nServer     int
	nClient     int
	cert        *frontServerCert
}

func (st *frontServerState) clientString() string {
	return fmt.Sprintf("%s=%s %s=%f %s=%f %s=%d %s=%d",
		certArg, st.cert, wMinArg, st.wMin, wMaxArg, st.wMax, nServerArg, st.nServer, nClientArg, st.nClient)
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*frontServerState, error) {
	var js jsonServerState
	var nodeIDOk, privKeyOk, seedOk bool
	js.NodeID, nodeIDOk = args.Get(nodeIDArg)
	js.PrivateKey, privKeyOk = args.Get(privateKeyArg)
	js.DrbgSeed, seedOk = args.Get(seedArg)
	wMinStr, wMinOk := args.Get(wMinArg)
	wMaxStr, wMaxOk := args.Get(wMaxArg)
	nServerStr, nServerOk := args.Get(nServerArg)
	nClientStr, nClientOk := args.Get(nClientArg)

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

	// The front params should be independently configurable.
	if wMaxOk {
		wMax, err := strconv.ParseFloat(wMaxStr, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed wMax '%s'", wMaxStr)
		}
		js.Wmax = float32(wMax)
	} else {
		return nil, fmt.Errorf("missing argument '%s'", wMaxArg)
	}

	if wMinOk {
		wMin, err := strconv.ParseFloat(wMinStr, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed wMin '%s'", wMinStr)
		}
		js.Wmin = float32(wMin)
	} else {
		log.Warnf("missing argument '%s', use default value 1.0.", wMinArg)
		js.Wmin = 1.0
	}

	if nServerOk {
		nServer, err := strconv.Atoi(nServerStr)
		if err != nil {
			return nil, fmt.Errorf("malformed nServer '%s'", nServerStr)
		}
		js.NServer = nServer
	} else {
		return nil, fmt.Errorf("missing argument '%s'", nServerArg)
	}

	if nClientOk {
		nClient, err := strconv.Atoi(nClientStr)
		if err != nil {
			return nil, fmt.Errorf("malformed nClient '%s'", nClientStr)
		}
		js.NClient = nClient
	} else {
		return nil, fmt.Errorf("missing argument '%s'", nClientArg)
	}

	return serverStateFromJSONServerState(stateDir, &js)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState) (*frontServerState, error) {
	var err error

	st := new(frontServerState)
	if st.nodeID, err = ntor.NodeIDFromHex(js.NodeID); err != nil {
		return nil, err
	}
	if st.identityKey, err = ntor.KeypairFromHex(js.PrivateKey); err != nil {
		return nil, err
	}
	if st.drbgSeed, err = drbg.SeedFromHex(js.DrbgSeed); err != nil {
		return nil, err
	}
	if js.NServer <= 0 || js.NClient <= 0{
		return nil, fmt.Errorf("invalid n-server '%d' or n-client '%d'", js.NServer, js.NClient)
	}
	if js.Wmin <= 0 || js.Wmax <= 0 {
		return nil, fmt.Errorf("invalid w-min '%f' or w-max '%f'", js.Wmin, js.Wmax)
	}

	// time unit ms
	st.nServer = js.NServer
	st.nClient = js.NClient
	st.wMin    = js.Wmin
	st.wMax    = js.Wmax

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
	var st frontServerState
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

func newBridgeFile(stateDir string, st *frontServerState) error {
	const prefix = "# front torrc client bridge line\n" +
		"#\n" +
		"# This file is an automatically generated bridge line based on\n" +
		"# the current frontproxy configuration.  EDITING IT WILL HAVE\n" +
		"# NO EFFECT.\n" +
		"#\n" +
		"# Before distributing this Bridge, edit the placeholder fields\n" +
		"# to contain the actual values:\n" +
		"#  <IP ADDRESS>  - The public IP address of your front bridge.\n" +
		"#  <PORT>        - The TCP/IP port of your front bridge.\n" +
		"#  <FINGERPRINT> - The bridge's fingerprint.\n\n"

	bridgeLine := fmt.Sprintf("Bridge front <IP ADDRESS>:<PORT> <FINGERPRINT> %s\n",
		st.clientString())

	tmp := []byte(prefix + bridgeLine)
	if err := ioutil.WriteFile(path.Join(stateDir, bridgeFile), tmp, 0600); err != nil {
		return err
	}

	return nil
}
