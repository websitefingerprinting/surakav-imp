package randomwt

const (
	stateStart = iota
	stateStop
	stateStartReady
	stateStopReady
)

var stateMap = map[uint32]string {
	stateStart: "stateStart",
	stateStop: "stateStop",
	stateStartReady : "startReady",
	stateStopReady : "stopReady",
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
