package tamaraw

const (
	stateReady = iota
	stateStart
	statePadding
	stateStop
)

var stateMap = map[uint32]string {
	stateStart: "stateStart",
	stateStop: "stateStop",
	stateReady: "stateReady",
	statePadding: "statePadding",
}