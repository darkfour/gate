#!/usr/bin/env python
# -*- coding:utf-8 -*-

import logging
import time

from tornado import gen, ioloop

from tornado_conn import JSONConn
from tornado.tcpserver import TCPServer
import conf


class CtrlServer(JSONConn):
    """control服务器"""

    keepalive_time = 0  # 最近一次S2G_keepalive时间
    is_start = False  # 是否收到S2GCtrl_start消息,防止重复发送造成意外

    def __init__(self, address, stream, http_server):
        super(CtrlServer, self).__init__(address, stream)
        self.http_server = http_server

    @gen.coroutine
    def S2GCtrl_start(self, data):
        if CtrlServer.is_start:
            self.error("Retransmission S2GCtrl_start")
        else:
            self.debug("S2GCtrl_start[data:%s]", data)
            yield self.send_message("G2SCtrl_start", {"zmq_address": conf.ZMQ_CLIENT_ADDRESS})
            self.http_server.listen(conf.SERVER_PORT)
            logging.info("starting server...port:%d", conf.SERVER_PORT)
            CtrlServer.is_start = True

    @gen.coroutine
    def S2GCtrl_reload(self, data):
        self.debug("S2GCtrl_reload[data:%s]", data)
        reload(conf)
        self.info(conf.RELOAD_SETTINGS_MSGS.encode('utf-8'))

    def on_closed(self):
        self.error("closed! EXIT...")
        ioloop.IOLoop.current().stop()

    @staticmethod
    def keepalive_on_second():
        if CtrlServer.is_start and CtrlServer.keepalive_time:
            if int(time.time()) - CtrlServer.keepalive_time >= conf.KEEPALIVE_TIMER:
                logging.error("TCP timeout, closed! EXIT...")
                ioloop.IOLoop.current().stop()
    
    @gen.coroutine
    def S2G_keepalive(self, data):
        CtrlServer.keepalive_time = int(time.time())
        self.info("S2G_keepalive")
        yield self.send_message("G2S_keepalive", {"time": time.time()})


class MyTCPServer(TCPServer):
    """自定义TCP服务器"""

    def __init__(self, server_class, port, http_server=None):
        super(MyTCPServer, self).__init__()
        self.server_class = server_class
        self.port = port
        self.http_server = http_server

    def run(self):
        self.listen(self.port)

    @gen.coroutine
    def handle_stream(self, stream, address):
        self.server_class(address, stream, self.http_server).run()


if __name__ == '__main__':
    pass
