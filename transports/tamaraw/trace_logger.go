package tamaraw

import (
	"bufio"
	"context"
	"fmt"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/transports/pb"
	"os"
	"sync/atomic"
	"time"
)

type traceLoggingServer struct {
	pb.UnimplementedTraceLoggingServer
	conn *tamarawConn
}

type traceLogger struct {
	logOn   *atomic.Value
	logPath *atomic.Value
}

func (s *traceLoggingServer) SignalLogger(ctx context.Context, signal *pb.SignalMsg) (*empty.Empty, error) {
	log.Debugf("[Event] Received gRPC service:%v at %v", signal, time.Now().Format("15:04:05.000000"))
	loggerOn := signal.TurnOn
	fPath := signal.FilePath
	s.conn.logger.logOn.Store(loggerOn)
	s.conn.logger.logPath.Store(fPath)
	return &empty.Empty{}, nil
}


func (s *traceLogger) LogTrace(curtime int64, realbytes int64, dummybytes int64) error {
	if s.logOn.Load().(bool) {
		filePath := s.logPath.Load().(string)
		err := WriteTrafficToFile(filePath, curtime, realbytes, dummybytes)
		if err != nil {
			// Do not propogate err here to kill the main process
			log.Errorf("Fail to write to file %v, reason: %v, at %v.",filePath, err, time.Now().Format("15:04:05.000000"))
		} else {
			log.Debugf("Write %v %v+%v to file at %v",curtime, realbytes, dummybytes, time.Now().Format("15:04:05.000000"))
		}
	}
	return nil
}

func WriteTrafficToFile(filePath string, curtime int64, realbytes int64, dummybytes int64) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	if err != nil {
		return err
	}
	defer file.Close()
	f := bufio.NewWriter(file)
	_, err = f.WriteString(fmt.Sprintf("%d\t%d\t%d\n",curtime, realbytes, dummybytes))
	_ = f.Flush()
	if err != nil {
		return err
	}
	return nil
}