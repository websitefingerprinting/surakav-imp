package front

import (
	"bufio"
	"context"
	"fmt"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/websitefingerprinting/wfdef.git/common/log"
	"github.com/websitefingerprinting/wfdef.git/transports/pb"
	"google.golang.org/grpc"
	"os"
	"sync/atomic"
	"time"
)


type Callback func(a bool, b string)

type traceLoggingServer struct {
	pb.UnimplementedTraceLoggingServer
	callBack Callback
}


func (s *traceLoggingServer) SignalLogger(ctx context.Context, signal *pb.SignalMsg) (*empty.Empty, error) {
	loggerOn := signal.TurnOn
	fPath := signal.FilePath
	log.Debugf("[Event] Received gRPC service: loggerOn:%v fPath: %v at %v", loggerOn, fPath, time.Now().Format("15:04:05.000000"))
	s.callBack(loggerOn, fPath)
	//log.Debugf("set con logger logOn:%v, logPath:%v", s.conn.logger.logOn, s.conn.logger.logPath)
	return &empty.Empty{}, nil
}


type traceLogger struct {
	gRPCServer    *grpc.Server
	logOn         *atomic.Value
	logPath       *atomic.Value
}


func (logger *traceLogger) UpdateLogInfo(loggerOn bool, fPath string) {
	logger.logOn.Store(loggerOn)
	logger.logPath.Store(fPath)
	//log.Debugf("logger update at %v", time.Now().UnixNano())
}


func (logger *traceLogger) LogTrace(curtime int64, realbytes int64, dummybytes int64) error {
	if logger.logOn.Load().(bool) {
		filePath := logger.logPath.Load().(string)
		err := WriteTrafficToFile(filePath, curtime, realbytes, dummybytes)
		if err != nil {
			// Do not propogate err here to kill the main process
			log.Errorf("Fail to write to file %v, reason: %v, at %v.",filePath, err, time.Now().Format("15:04:05.000000"))
		} else {
			//log.Debugf("Write %v %v+%v to file at %v",curtime, realbytes, dummybytes, time.Now().Format("15:04:05.000000"))
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