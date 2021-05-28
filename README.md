## WFDefProxy

### What?
WFDefProxy implements three defenses against Website Fingerprinting (WF) attack: FRONT, Tamaraw and Random-WT. 
It extends obfs4proxy [1], the state-of-the-art pluggable transport for Tor to circumvent censorship. 
It transforms the traffic between the client and the bridge according to a defense's protocol.
It makes use of the cryptographic system of obfs4 to do the handshake as well as to encrypt/decrypt the packets.
The workflow of WFDefProxy is shown in the figure below:
<div  align="center"> 
<img src="https://anonymous.4open.science/r/wfdef-11EF/imgs/wfdefproxy.png" style="zoom:50%;" />
</div>

### How to use? 
####  To build:

```go build -o obfs4proxy/obfs4proxy ./obfs4proxy```

Suppose we put the compiled binary at `/Users/example/wfdef/obfs4proxy/obfs4proxy`.

#### 1. To run a bridge with **FRONT**, the torrc configuration is like:
```
# Feel free to adapt the path.
DataDirectory /Users/example/tor-config/log-front-server  
Log notice stdout    
SOCKSPort 9052    
AssumeReachable 1    
PublishServerDescriptor 0    
Exitpolicy reject *:*    
ORPort auto   
ExtORPort auto
Nickname "wfdef"    
BridgeRelay 1    
ServerTransportListenAddr front 0.0.0.0:34000
ServerTransportPlugin front exec /Users/example/wfdef/obfs4proxy/obfs4proxy
ServerTransportOptions front w-min=1 w-max=13 n-client=3000 n-server=3000
```
It will generate a `front_bridgeline.txt` in `/Users/example/tor-config/log-front-server/pt_state`, 
containing a certification used for handshake as well as the configured parameters. 

The client's torrc file is like:
```
DataDirectory /Users/example/tor-config/log-front-client 
Log notice stdout    
SOCKSPort 9050  
ControlPort 9051  
UseBridges 1    
Bridge front 127.0.0.1:34000 cert=VdXiHCbwjXAC3+M2VZwasp+TAIbK0TuQD3MG3s024pE3brEygUOovIJo4f2oxZpBvlrNFQ w-min=1.0 w-max=13.0 n-server=3000 n-client=3000
ClientTransportPlugin front exec /Users/example/wfdef/obfs4proxy/obfs4proxy
```

You can launch Tor with command line `tor -f client-torrc` or replace Tor Browser's torrc file with it and launch the Tor Browser directly. 
Note that if is better to also include the relay's fingerprint in `Bridge` option due to some bugs of Tor Browser that may cause the launch failure.

#### 2. To run **Tamaraw**, the torrc for bridge is similar as FRONT, except that last two lines should be 
```
ServerTransportPlugin tamaraw exec /Users/example/wfdef/obfs4proxy/obfs4proxy
ServerTransportOptions tamaraw rho-client=12 rho-server=4 nseg=200
```
Also, on the client side, the last two lines of the torrc file should be
```
Bridge front 127.0.0.1:34000 cert=VdXiHCbwjXAC3+M2VZwasp+TAIbK0TuQD3MG3s024pE3brEygUOovIJo4f2oxZpBvlrNFQ rho-client=12 rho-server=4 nseg=200
ClientTransportPlugin front exec /Users/example/wfdef/obfs4proxy/obfs4proxy
```
Replace `Bridge` with the information in `tamaraw_bridgeline.txt` in `/Users/example/tor-config/log-front-server/pt_state`.

#### 3. To run **Random-WT**, the last two lines of torrc file for bridge:
```
ServerTransportPlugin randomwt exec /Users/example/wfdef/obfs4proxy/obfs4proxy
ServerTransportOptions randomwt n-client-real=4 n-server-real=45 n-client-fake=8 n-server-fake=90 p-fake=0.4
```
Similarly, the client side 
```
Bridge randomwt 127.0.0.1:34000 cert=VdXiHCbwjXAC3+M2VZwasp+TAIbK0TuQD3MG3s024pE3brEygUOovIJo4f2oxZpBvlrNFQ n-client-real=4 n-server-real=45 n-client-fake=8 n-server-fake=90 p-fake=0.4
ClientTransportPlugin randomwt exec /Users/example/wfdef/obfs4proxy/obfs4proxy
```

### How does WFDefProxy work?
We nearly keep the framework of obfs4proxy unchanged, except that we add four different transports in `./transports`:
* **null**: do nothing but forward the packets between client and the bridge, can be used for collecting undefended datasets
* **front**: implement FRONT defense
* **tamaraw**: implement tamaraw defense
* **random-wt**: implement random-wt defense

The key modules for each transport:
* `packet.go`: define the packet format, the types of packets and how to parse the packets
* `statefile.go`: define the parameters, validity checks for the parameter values and the format of bridgeline.txt
* `[defense].go`: implement the defense, control the state transitions
*  `state.go`: define the states of the defense

Below are the state machines for three defenses.
<div  align="center"> 
<img src="https://anonymous.4open.science/r/wfdef-11EF/imgs/front-fsm.png" style="zoom:50%;" />
<img src="https://anonymous.4open.science/r/wfdef-11EF/imgs/tamaraw-fsm.png" style="zoom:50%;" />
<img src="https://anonymous.4open.science/r/wfdef-11EF/imgs/randomwt-fsm.png" style="zoom:50%;" />
</div>



### Tips and tricks
 * 
### Dependencies

Build time library dependencies are handled by the Go module automatically.

If you are on Go versions earlier than 1.11, you might need to run `go get -d
./...` to download all the dependencies. Note however, that modules always use
the same dependency versions, while `go get -d` always downloads master.

* Go 1.11.0 or later. Patches to support up to 2 prior major releases will
  be accepted if they are not overly intrusive and well written.
* See `go.mod`, `go.sum` and `go list -m -u all` for build time dependencies.

### Thanks
 * Yawning Angel for explaining the code of obfs4proxy