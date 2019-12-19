# -*- coding=utf-8 -*-

import zmq
from msgpack import dumps, loads

from zmq.eventloop import ioloop

import conf


class ZmqServer(object):

    def __init__(self, hwm, address, interval, timer):
        self.hwm = hwm
        self.address = address
        self.interval = interval
        self.QP_TIMER = timer
        self.socket = None
        self.receive_timer = None

    def run(self, func):
        context = zmq.Context()
        self.socket = context.socket(zmq.PAIR)
        self.socket.set_hwm(self.hwm)
        self.socket.bind(self.address)

        self.receive_timer = ioloop.PeriodicCallback(func, self.interval)
        self._start_timer()

    def _start_timer(self):
        self.receive_timer.start()

    def send(self, msg):
        msg = dumps(msg)
        self.socket.send(msg)

    def receive(self):
        response = self.socket.recv(zmq.NOBLOCK)
        recv_bytes = len(response)
        msg = loads(response)
        return recv_bytes, msg

    def close(self):
        self.receive_timer.stop()
        if self.socket is not None:
            self.socket.close()


# 以模块导入方式实现单例
zmq_server = ZmqServer(conf.ZMQ_SERVER_HWM, conf.ZMQ_ADDRESS, conf.DELAY, conf.QP_TIMER)


if __name__ == "__main__":
    pass
