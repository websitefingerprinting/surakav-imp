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
	"fmt"
	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/websitefingerprinting/wfdef.git/transports/defconn"
	"strconv"
)


type jsonServerState struct {
	defconn.JsonServerState
	Tol        float32        `json:"tol"`
	P          float32        `json:"p"`
}


type wfganServerState struct {
	defconn.DefConnServerState
	tol       float32
	p         float32
}

func (st *wfganServerState) clientString() string {
	return st.DefConnServerState.ClientString() +
		fmt.Sprintf("%s=%.1f %s=%.1f", tolArg, st.tol, pArg, st.p)
}

func serverStateFromArgs(stateDir string, args *pt.Args) (*wfganServerState, error) {
	js, err := defconn.ServerStateFromArgsInternal(stateDir, defconn.StateFile, args)
	if err != nil {
		return nil, err
	}

	tolStr, tolOk := args.Get(tolArg)
	pStr, pOk := args.Get(pArg)

	var jsWfgan jsonServerState
	jsWfgan.JsonServerState = js


	// The wfgan params should be independently configurable.
	if tolOk {
		tol, err := strconv.ParseFloat(tolStr, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed tol '%s'", tolStr)
		}
		jsWfgan.Tol = float32(tol)
	} else {
		return nil, fmt.Errorf("missing argument '%s'", tolArg)
	}
	if pOk {
		p, err := strconv.ParseFloat(pStr, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed p '%s'", pStr)
		}
		jsWfgan.P = float32(p)
	} else {
		return nil, fmt.Errorf("missing argument '%s'", pArg)
	}
	return serverStateFromJSONServerState(stateDir, &jsWfgan)
}

func serverStateFromJSONServerState(stateDir string, js *jsonServerState) (*wfganServerState, error) {
	st, err := defconn.ServerStateFromJsonServerStateInternal(js)

	if js.Tol < 0{
		return nil, fmt.Errorf("invalid tol '%.1f'", js.Tol)
	}
	if js.P < 0{
		return nil, fmt.Errorf("invalid p '%.1f'", js.P)
	}

	var stWfgan wfganServerState

	stWfgan.DefConnServerState = st
	stWfgan.tol = js.Tol
	stWfgan.p = js.P


	// Generate a human readable summary of the configured endpoint.
	if err = defconn.NewBridgeFile(stateDir, defconn.BridgeFile, stWfgan.clientString()); err != nil {
		return nil, err
	}

	// Write back the possibly updated server state.
	return &stWfgan, defconn.WriteJSONServerState(stateDir, defconn.StateFile, js)
}
