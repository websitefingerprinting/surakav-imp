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
	"fmt"
	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/transports/defconn"
	"strconv"
)

type jsonServerState struct {
	defconn.JsonServerState
	Wmin       float32        `json:"w-min"`
	Wmax       float32        `json:"w-max"`
	NServer    int            `json:"n-server"`
	NClient    int            `json:"n-client"`
}

type frontServerState struct {
	defconn.DefConnServerState
	wMin        float32
	wMax        float32
	nServer     int
	nClient     int
}

func (st *frontServerState) clientString() string {
	return st.DefConnServerState.ClientString() +
	fmt.Sprintf("%s=%.1f %s=%.1f %s=%d %s=%d",
		wMinArg, st.wMin, wMaxArg, st.wMax, nServerArg, st.nServer, nClientArg, st.nClient)
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*frontServerState, error) {
	js, err := defconn.ServerStateFromArgsInternal(stateDir, defconn.StateFile, args)
	if err != nil {
		return nil, err
	}

	wMaxStr, wMaxOk := args.Get(wMaxArg)
	wMinStr, wMinOk := args.Get(wMinArg)
	nServerStr, nServerOk := args.Get(nServerArg)
	nClientStr, nClientOk := args.Get(nClientArg)

	var jsFRONT jsonServerState
	jsFRONT.JsonServerState = js

	// The front params should be independently configurable.
	if wMaxOk {
		wMax, err := strconv.ParseFloat(wMaxStr, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed wMax '%s'", wMaxStr)
		}
		jsFRONT.Wmax = float32(wMax)
	} else {
		return nil, fmt.Errorf("missing argument '%s'", wMaxArg)
	}

	if wMinOk {
		wMin, err := strconv.ParseFloat(wMinStr, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed wMin '%s'", wMinStr)
		}
		jsFRONT.Wmin = float32(wMin)
	} else {
		log.Warnf("missing argument '%s', use default value 1.0.", wMinArg)
		jsFRONT.Wmin = 1.0
	}

	if nServerOk {
		nServer, err := strconv.Atoi(nServerStr)
		if err != nil {
			return nil, fmt.Errorf("malformed nServer '%s'", nServerStr)
		}
		jsFRONT.NServer = nServer
	} else {
		return nil, fmt.Errorf("missing argument '%s'", nServerArg)
	}

	if nClientOk {
		nClient, err := strconv.Atoi(nClientStr)
		if err != nil {
			return nil, fmt.Errorf("malformed nClient '%s'", nClientStr)
		}
		jsFRONT.NClient = nClient
	} else {
		return nil, fmt.Errorf("missing argument '%s'", nClientArg)
	}

	return serverStateFromJSONServerState(stateDir, &jsFRONT)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState) (*frontServerState, error) {
	st, err := defconn.ServerStateFromJsonServerStateInternal(js)

	if js.NServer <= 0 || js.NClient <= 0{
		return nil, fmt.Errorf("invalid n-server '%d' or n-client '%d'", js.NServer, js.NClient)
	}
	if js.Wmin <= 0 || js.Wmax <= 0 {
		return nil, fmt.Errorf("invalid w-min '%f' or w-max '%f'", js.Wmin, js.Wmax)
	}

	var stFRONT frontServerState

	stFRONT.DefConnServerState = st

	stFRONT.nServer = js.NServer
	stFRONT.nClient = js.NClient
	stFRONT.wMin    = js.Wmin
	stFRONT.wMax    = js.Wmax

	// Generate a human readable summary of the configured endpoint.
	if err = defconn.NewBridgeFile(stateDir, defconn.BridgeFile, stFRONT.clientString()); err != nil {
		return nil, err
	}

	// Write back the possibly updated server state.
	return &stFRONT, defconn.WriteJSONServerState(stateDir, defconn.StateFile, js)
}
