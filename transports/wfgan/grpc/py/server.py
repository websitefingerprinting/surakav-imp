import logging
import sys
from concurrent.futures import ThreadPoolExecutor

import grpc
from generate import *

from gan_pb2 import GANResponse
from gan_pb2_grpc import GenerateTraceServicer, add_GenerateTraceServicer_to_server

GAN_PORT_NUM = 9999

class GenerateTraceServer(GenerateTraceServicer):
    def Query(self, request, context):
        logging.info('Receive request {}'.format(request))
        packets = sample()
        resp = GANResponse(packets=packets)
        return resp


if __name__ == '__main__':
    filename = sys.argv[1]

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=filename
    )
    server = grpc.server(ThreadPoolExecutor())
    add_GenerateTraceServicer_to_server(GenerateTraceServer(), server)
    port = GAN_PORT_NUM
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    logging.info('server ready on port %r', port)
    server.wait_for_termination()