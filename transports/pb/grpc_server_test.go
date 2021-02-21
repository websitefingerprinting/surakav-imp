package pb

import (
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"google.golang.org/grpc"
	"net"
	"context"
	"testing"
	"time"
)


type traceLoggingServer struct {
	UnimplementedTraceLoggingServer
}


func (s *traceLoggingServer) SignalLogger(ctx context.Context, signal *SignalMsg) (*empty.Empty, error) {
	log.Debugf("[Event] Received gRPC service:%v at %v", signal, time.Now().Format("15:04:05.000000"))
	loggerOn := signal.TurnOn
	fPath := signal.FilePath
	log.Infof("%v, %v", loggerOn, fPath)
	return &empty.Empty{}, nil
}


func TestServer(t *testing.T) {
	server := grpc.NewServer()
	RegisterTraceLoggingServer(server, &traceLoggingServer{})
	listen, err := net.Listen("tcp", "localhost:10086")
	if err != nil {
		log.Errorf("Fail to launch gRPC service err: %v", err)
	}
	log.Debugf("tamaraw - Launch gRPC server")
	server.Serve(listen)

}
