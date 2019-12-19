#!/usr/bin/env python
# -*- coding:utf-8 -*-
import logging
import signal

from tornado import ioloop
from tornado.web import Application
import tornado.httpserver

from tcp_server import CtrlServer, MyTCPServer
from zmq_server import zmq_server
import conf
from conn import Conn
import util


if __name__ == "__main__":
    if conf.DAEMONIZE:
        util.daemonize()
    util.init_logging(
        "log/gate_server.log",
        colorfy=True
    )
    logging.info("%s : starting at port:%d...", MyTCPServer.__name__, conf.port)

    handlers = [
        (r'/',                              Conn),
        (r'/snappy/',                       Conn, dict(compress="snappy", binary=True, conn_tag='SP')),

        (r'/msgpack-snappy-skip/',          Conn, dict(
            msgpack=True, compress="snappy", skip_size=512, binary=True, conn_tag='MP-SP-skip')),

        (r'/crypt/',                        Conn, dict(crypt=True, binary=True, conn_tag='CB')),
        (r'/crypts/',                       Conn, dict(crypt=True, simple=True, binary=True, conn_tag='CSB')),
        (r'/b64crypts/',                    Conn, dict(crypt=True, simple=True, base64=True, conn_tag='CS64')),
    ]

    http_server = tornado.httpserver.HTTPServer(
        Application(
            handlers=handlers,
            debug=False
        )
    )

    '''
    监听tcp
    启动消息队列
    监听ws端口
    发送接收消息
    '''

    # 初始化TCP连接 监听控制端口
    MyTCPServer(CtrlServer, conf.port, http_server).run()

    # 启动清理定时器
    Conn.on_server_start()
    
    # 启动消息队列 并开始接收定时器
    zmq_server.run(Conn.on_receive_timer)

    def server_stop():
        # 服务器结束
        logging.info('stopping gate...')
        ioloop.IOLoop.instance().stop()

    def sig_stop(sig, frame):
        # 退出信号处理
        logging.warning('caught signal: %s', sig)
        ioloop.IOLoop.instance().add_callback(server_stop)

    def server_reload():
        # 服务器重载
        logging.info('gate reloading...')
        reload(conf)
        reload(util)
        logging.info('gate reloaded.')

    def sig_reload(sig, frame):
        # 重载信号处理
        logging.warning('caught signal: %s', sig)
        ioloop.IOLoop.instance().add_callback(server_reload)

    if util.is_linux():
        signal.signal(signal.SIGHUP, sig_reload)

    signal.signal(signal.SIGTERM, sig_stop)
    signal.signal(signal.SIGINT, sig_stop)
    
    ioloop.IOLoop.instance().start()
