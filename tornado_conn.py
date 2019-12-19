#!/usr/bin/env python
# -*- coding:utf-8 -*-

import json
import time

import msgpack
from tornado.iostream import StreamClosedError
from tornado import gen

import util


class Conn(util.LogObject):
    """连接"""

    # 包边界字符串
    MAGIC = b"\r\rBi&g0\n\n"

    def __init__(self, address, stream, loads, dumps):
        # (地址, 端口)
        self.address = address
        # iostream
        self.stream = stream
        # 序列化
        self.loads = loads
        # 反序列化
        self.dumps = dumps

        self.message_cnt = 0
        self.message_start = 0

    def __str__(self):
        """类名(地址, 端口)"""
        return "%s%s" % (self.__class__.__name__, str(self.address))

    @gen.coroutine
    def run(self):
        """运行逻辑"""

        # 连接(客户端连接才需要)
        if self.closed():
            try:
                yield self.connect()
            except:
                self.on_connect_failed()
                raise

        # 连接成功
        try:
            self.stream.set_close_callback(self.on_closed)
            yield self.on_connected()
        except:
            self.exception("")

        # 消息处理
        while not self.closed():
            try:
                yield self._recv_message()
            except StreamClosedError:
                break
            # except KeyboardInterrupt:
            #     self.error("KeyboardInterrupt! CLOSE...")
            #     self.close()
            except:
                self.exception("")

    @gen.coroutine
    def connect(self):
        """连接(服务器): 客户端连接才需要"""
        pass

    def on_connect_failed(self):
        """连接(服务器)失败回调: 客户端连接才需要"""
        self.error("connect failed!")

    @gen.coroutine
    def on_connected(self):
        """连接成功通知"""
        self.info("connected.")

    def closed(self):
        """连接是否断开"""
        return not self.stream or self.stream.closed()

    def close(self):
        """关闭连接"""
        if not self.closed():
            self.stream.close()

    def on_closed(self):
        """连接断开通知"""
        self.info("closed.")

    def speed(self):
        """接收消息速率"""
        if self.message_cnt == 0:
            self.message_start = time.time()
        self.message_cnt += 1
        if self.message_cnt % 10000 == 0:
            self.info(
                "%d, %d/s",
                self.message_cnt,
                self.message_cnt / (time.time() - self.message_start)
            )

    @gen.coroutine
    def _recv_message(self):
        """接收消息"""
        msg_buffer = yield self.stream.read_until(Conn.MAGIC)
        msg = self.loads(msg_buffer[:-len(Conn.MAGIC)])
        msgtype = msg["type"]
        data = msg.get("data", {})

        # self.speed()

        msg_handler = getattr(self, msgtype, None)
        if msg_handler:
            yield msg_handler(data)
        else:
            self.error("unknown message[%s, %s]!" % (msgtype, data))

    @gen.coroutine
    def send_message(self, msgtype, data=None):
        """发送消息"""
        data = {} if data is None else data
        msg = {"type": msgtype, "data": data}
        msg_buffer = self.dumps(msg) + Conn.MAGIC
        yield self.stream.write(msg_buffer)


class JSONConn(Conn):
    """json连接"""

    def __init__(self, address, stream = None):
        super(JSONConn, self).__init__(address, stream, json.loads, json.dumps)


class MsgpackConn(Conn):
    """msgpack连接"""

    def __init__(self, address, stream = None):
        super(MsgpackConn, self).__init__(address, stream, msgpack.loads, msgpack.dumps)

