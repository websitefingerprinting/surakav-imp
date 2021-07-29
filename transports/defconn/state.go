package defconn

import "sync"

const (
	StateStart = iota
	StateStop
	StateReady
	StatePadding
)

var StateMap = map[uint32]string {
	StateStart: "StateStart",
	StateStop: "StateStop",
	StateReady: "StateReady",
	StatePadding: "StatePadding",
}


type State struct {
	curState	uint32
	lastState	uint32
	mutex 		sync.RWMutex
}

func (s *State) SetState(newState uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.lastState = s.curState
	s.curState = newState
	return
}

func (s *State) ReSetState() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.lastState = StateStop
	s.curState = StateStop
}

func (s *State) LoadCurState() (curState uint32){
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.curState
}

func (s *State) LoadLastState() (lastState uint32){
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.lastState
}

func NewState() (s *State) {
	return &State{
		curState: StateStop,
		lastState: StateStop,
	}
}