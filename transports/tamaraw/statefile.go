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
	"fmt"
	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/transports/defconn"
	"strconv"
)


type jsonServerState struct {
	defconn.JsonServerState
	NSeg       int            `json:"nseg"`
	RhoServer  int            `json:"rho-server"`
	RhoClient  int            `json:"rho-client"`
}


type tamarawServerState struct {
	defconn.DefConnServerState
	nSeg        int
	rhoServer   int
	rhoClient   int
}

func (st *tamarawServerState) clientString() string {
	return st.DefConnServerState.ClientString() +
		fmt.Sprintf("%s=%d %s=%d %s=%d", nSegArg, st.nSeg, rhoServerArg, st.rhoServer, rhoClientArg, st.rhoClient)
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*tamarawServerState, error) {
	js, err := defconn.ServerStateFromArgsInternal(stateDir, defconn.StateFile, args)
	if err != nil {
		return nil, err
	}

	nSegStr, nSegOk := args.Get(nSegArg)
	rhoClientStr, rhoClientOk := args.Get(rhoClientArg)
	rhoServerStr, rhoServerOk := args.Get(rhoServerArg)

	var jsTamaraw jsonServerState
	jsTamaraw.JsonServerState = js

	// The tamaraw params should be independently configurable.
	if nSegOk {
		nSeg, err := strconv.Atoi(nSegStr)
		if err != nil {
			return nil, fmt.Errorf("malformed nseg '%s'", nSegStr)
		}
		jsTamaraw.NSeg = nSeg
	} else {
		return nil, fmt.Errorf("missing argument '%s'", nSegArg)
	}

	if rhoClientOk {
		rhoClientInt, err := strconv.Atoi(rhoClientStr)
		if err != nil {
			return nil, fmt.Errorf("malformed rho-client '%s'", rhoClientStr)
		}
		jsTamaraw.RhoClient = rhoClientInt
	} else {
		return nil, fmt.Errorf("missing argument '%s'", rhoClientArg)
	}

	if rhoServerOk {
		rhoServerInt, err := strconv.Atoi(rhoServerStr)
		if err != nil {
			return nil, fmt.Errorf("malformed rho-server '%s'", rhoServerStr)
		}
		jsTamaraw.RhoServer = rhoServerInt
	} else {
		return nil, fmt.Errorf("missing argument '%s'", rhoServerArg)
	}
	return serverStateFromJSONServerState(stateDir, &jsTamaraw)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState) (*tamarawServerState, error) {
	st, err := defconn.ServerStateFromJsonServerStateInternal(js)

	if js.NSeg < 0 {
		return nil, fmt.Errorf("invalid nseg '%d'", js.NSeg)
	}
	if js.RhoServer < 0 {
		return nil, fmt.Errorf("invalid rho-server '%d'", js.RhoServer)
	}
	if js.RhoClient < 0 {
		return nil, fmt.Errorf("invalid rho-client '%d'", js.RhoClient)
	}

	var stTamaraw tamarawServerState

	stTamaraw.DefConnServerState = st

	// time unit ms
	stTamaraw.nSeg = js.NSeg
	stTamaraw.rhoServer = js.RhoServer
	stTamaraw.rhoClient = js.RhoClient

	// Generate a human readable summary of the configured endpoint.
	if err = defconn.NewBridgeFile(stateDir, defconn.BridgeFile, stTamaraw.clientString()); err != nil {
		return nil, err
	}

	// Write back the possibly updated server state.
	return &stTamaraw, defconn.WriteJSONServerState(stateDir, defconn.StateFile, js)
}




