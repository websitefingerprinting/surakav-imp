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

package randomwt

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
	stateFile  = "randomwt_state.json"
	bridgeFile = "randomwt_bridgeline.txt"

	certSuffix = "=="
	certLength = ntor.NodeIDLength + ntor.PublicKeyLength
)

type jsonServerState struct {
	NodeID         string         `json:"node-id"`
	PrivateKey     string         `json:"private-key"`
	PublicKey      string         `json:"public-key"`
	DrbgSeed       string         `json:"drbg-seed"`
	NClientReal    int            `json:"n-client-real"`
	NServerReal    int            `json:"n-server-real"`
	NClientFake    int            `json:"n-client-fake"`
	NServerFake    int            `json:"n-server-fake"`
	PFake          float64        `json:"p-fake"`
}

type randomwtServerCert struct {
	raw []byte
}

func (cert *randomwtServerCert) String() string {
	return strings.TrimSuffix(base64.StdEncoding.EncodeToString(cert.raw), certSuffix)
}

func (cert *randomwtServerCert) unpack() (*ntor.NodeID, *ntor.PublicKey) {
	if len(cert.raw) != certLength {
		panic(fmt.Sprintf("cert length %d is invalid", len(cert.raw)))
	}

	nodeID, _ := ntor.NewNodeID(cert.raw[:ntor.NodeIDLength])
	pubKey, _ := ntor.NewPublicKey(cert.raw[ntor.NodeIDLength:])

	return nodeID, pubKey
}

func serverCertFromString(encoded string) (*randomwtServerCert, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded + certSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %s", err)
	}

	if len(decoded) != certLength {
		return nil, fmt.Errorf("cert length %d is invalid", len(decoded))
	}

	return &randomwtServerCert{raw: decoded}, nil
}

func serverCertFromState(st *randomwtServerState) *randomwtServerCert {
	cert := new(randomwtServerCert)
	cert.raw = append(st.nodeID.Bytes()[:], st.identityKey.Public().Bytes()[:]...)
	return cert
}

type randomwtServerState struct {
	nodeID         *ntor.NodeID
	identityKey    *ntor.Keypair
	drbgSeed       *drbg.Seed
	nClientReal    int
	nServerReal    int
	nClientFake    int
	nServerFake    int
	pFake          float64
	cert           *randomwtServerCert
}

func (st *randomwtServerState) clientString() string {
	return fmt.Sprintf("%s=%s %s=%d %s=%d %s=%d %s=%d %s=%1.1f",
		certArg, st.cert, nClientRealArg, st.nClientReal, nServerRealArg, st.nServerReal,
		nClientFakeArg, st.nClientFake, nServerFakeArg, st.nServerFake, pFakeArg, st.pFake)
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*randomwtServerState, error) {
	var js jsonServerState
	var nodeIDOk, privKeyOk, seedOk bool
	js.NodeID, nodeIDOk = args.Get(nodeIDArg)
	js.PrivateKey, privKeyOk = args.Get(privateKeyArg)
	js.DrbgSeed, seedOk = args.Get(seedArg)

	nClientRealStr, nClientRealOk := args.Get(nClientRealArg)
	nServerRealStr, nServerRealOk := args.Get(nServerRealArg)
	nClientFakeStr, nClientFakeOk := args.Get(nClientFakeArg)
	nServerFakeStr, nServerFakeOk := args.Get(nServerFakeArg)
	pFakeStr, pFakeOk             := args.Get(pFakeArg)

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

	// The randomwt params should be independently configurable.
	if !nClientRealOk || !nServerRealOk || !nClientFakeOk || !nServerFakeOk {
		return nil, fmt.Errorf("missing argument for one of the args: %s %s %s %s",
			nClientRealArg, nServerRealArg, nClientFakeArg, nServerFakeArg)
	} else {
		nClientReal, err := strconv.Atoi(nClientRealStr)
		if err != nil {
			return nil, fmt.Errorf("malformed n-client-real: '%s'", nClientRealStr)
		}
		nServerReal, err := strconv.Atoi(nServerRealStr)
		if err != nil {
			return nil, fmt.Errorf("malformed n-server-real: '%s'", nServerRealStr)
		}
		nClientFake, err := strconv.Atoi(nClientFakeStr)
		if err != nil {
			return nil, fmt.Errorf("malfromed n-client-fake: '%s'", nClientFakeStr)
		}
		nServerFake, err := strconv.Atoi(nServerFakeStr)
		if err != nil {
			return nil, fmt.Errorf("malfromed n-server-fake: '%s'", nServerFakeStr)
		}
		js.NClientReal = nClientReal
		js.NServerReal = nServerReal
		js.NClientFake = nClientFake
		js.NServerFake = nServerFake
	}

	if pFakeOk {
		pFake, err := strconv.ParseFloat(pFakeStr, 64)
		if err != nil {
			return nil, fmt.Errorf("malformed p-fake '%s'", pFakeStr)
		}
		js.PFake = pFake
	} else {
		return nil, fmt.Errorf("missing argument '%s'", pFakeArg)
	}

	return serverStateFromJSONServerState(stateDir, &js)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState) (*randomwtServerState, error) {
	var err error

	st := new(randomwtServerState)
	if st.nodeID, err = ntor.NodeIDFromHex(js.NodeID); err != nil {
		return nil, err
	}
	if st.identityKey, err = ntor.KeypairFromHex(js.PrivateKey); err != nil {
		return nil, err
	}
	if st.drbgSeed, err = drbg.SeedFromHex(js.DrbgSeed); err != nil {
		return nil, err
	}

	if (js.NClientReal < 0) || (js.NServerReal < 0) || (js.NClientFake < 0) || (js.NServerFake < 0) {
		return nil, fmt.Errorf("invalid n-client-real '%d' or n-server-real '%d' or n-client-fake '%d' or n-server-fake '%d'",
			js.NClientReal, js.NServerReal, js.NClientFake, js.NServerFake)
	}
	if js.PFake < 0 || js.PFake > 1 {
		return nil, fmt.Errorf("invalid p-fake '%.1f'", js.PFake)
	}

	st.nClientReal = js.NClientReal
	st.nServerReal = js.NServerReal
	st.nClientFake = js.NClientFake
	st.nServerFake = js.NServerFake
	st.pFake       = js.PFake

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
	var st randomwtServerState
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

func newBridgeFile(stateDir string, st *randomwtServerState) error {
	const prefix = "# randomwt torrc client bridge line\n" +
		"#\n" +
		"# This file is an automatically generated bridge line based on\n" +
		"# the current randomwtproxy configuration.  EDITING IT WILL HAVE\n" +
		"# NO EFFECT.\n" +
		"#\n" +
		"# Before distributing this Bridge, edit the placeholder fields\n" +
		"# to contain the actual values:\n" +
		"#  <IP ADDRESS>  - The public IP address of your randomwt bridge.\n" +
		"#  <PORT>        - The TCP/IP port of your randomwt bridge.\n" +
		"#  <FINGERPRINT> - The bridge's fingerprint.\n\n"

	bridgeLine := fmt.Sprintf("Bridge randomwt <IP ADDRESS>:<PORT> <FINGERPRINT> %s\n",
		st.clientString())

	tmp := []byte(prefix + bridgeLine)
	if err := ioutil.WriteFile(path.Join(stateDir, bridgeFile), tmp, 0600); err != nil {
		return err
	}

	return nil
}
