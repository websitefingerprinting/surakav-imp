package randomwt

const (
	stateStart = iota
	stateStop
	stateReady
)

var stateMap = map[uint32]string {
	stateStart: "stateStart",
	stateStop: "stateStop",
	stateReady: "stateReady",
}

const (
	signalReal = iota
	signalDummy
	signalTearDown
)

var signalMap = map[uint32]string {
	signalReal : "signalReal",
	signalDummy : "signalDummy",
	signalTearDown : "signalTearDown",
}
