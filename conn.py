#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""连接"""

# 系统库
import json
from traceback import format_exc
import time
import functools
import logging

# 第三方
import tornado
from tornado.ioloop import PeriodicCallback
from tornado.websocket import WebSocketHandler
import msgpack
import snappy
import zmq

# 自己的
import util
import conf
import msg
import connect_log
from zmq_server import zmq_server


class ClientError(Exception):
    pass


class Conn(WebSocketHandler, util.LogObject):
    """连接类"""
    # 数据 #############################################################################################################
    # 所有(未关闭的)连接
    conns = dict()
    # 当前客户端连接id  从1开始, 自增ID
    cur_id = 1
    # 消息id
    msg_id = 1
    # 当前在处理的消息id
    handle_msg_id = 1
    # zmq实例
    zmq_server = zmq_server
    # 发送总包数
    total_send = 0
    # 发送总时间(秒)
    total_send_time = 0.0
    # 最近一段时间关闭的连接 {cur_id:time.time()}
    close_conns = dict()

    # 数据 #############################################################################################################

    def __init__(self, application, request, **kwargs):
        super(Conn, self).__init__(application, request, **kwargs)
        # 数据 #########################################################################################################
        self.ip = util.real_ip(self.request)
        # 端口
        self._port = ""
        # 连接时间
        self.conn_time = time.time()
        # 接入(websocket)时间
        self.open_time = 0.0
        # 发送包数
        self.send = 0
        # 接收包数
        self.recv = 0
        # 发送字节
        self.send_bytes = 0
        # 接受字节
        self.recv_bytes = 0
        # 消息处理过程中的发送字节
        self.send_bytes_in_message_handler = 0
        # 主动关闭
        self.server_close = False

        # 是否调试
        self.is_debug = True

        # 是否是服务器主动请求关闭的
        self.is_s2g_close = False

        # 客户端消息id
        self._client_msg_id_start = 0
        self._client_msg_id = 0

        # 包
        pg = ""
        # 是否 严格限制包代理服务器, 禁止串包登陆
        if not conf.STRICT_PG_PROXY:
            pg = request.arguments.get("pg", [""])[0]
        self._pg = pg or request.headers.get("Pg", conf.DEFAULT_PG)
        self._package_name = conf.get_package_name(self._pg)

        # 加密数据
        self._private_key = conf.get_pg_private_key(self._pg)
        self._crypt = kwargs.get("crypt", False)
        self._key = ""
        self._iv = ""
        # 简化(加密)
        self._simple = kwargs.get("simple", False)
        if self._simple:
            self._key = conf.get_pg_aes_key(self._pg)
            self._iv = conf.get_pg_aes_iv(self._pg)

        # 二进制
        self._binary = kwargs.get("binary", False)

        self._base64 = kwargs.get("base64", False)
        # 连接标签
        self._conn_tag = kwargs.get("conn_tag", "")
        # 标签
        self.pg_tag = "%s:%s" % (self._pg, self._conn_tag)

        # 序列化: json/msgpack
        self._loads = json.loads
        self._dumps = functools.partial(json.dumps, separators=(',', ':'))
        if kwargs.get("msgpack", False):
            self._loads = msgpack.loads
            self._dumps = msgpack.dumps

        # 压缩: 无/snappy
        self._compress = None
        self._decompress = None
        compress = kwargs.get("compress")
        if compress == "snappy":
            self._compress = snappy.compress
            self._decompress = snappy.decompress
        # 压缩跳过(长度): 首字节表示是否压缩: \0x00 未压缩 \x01 压缩了
        self._compress_skip_size = kwargs.get("skip_size", 0)
        
        self.conn_init(kwargs)
        # 数据 #########################################################################################################

    def conn_init(self, kv):
        """写入队列消息G2S_connect(连接ID, 地址，包代号等等Client需要用到的信息)"""
        self.cur_id = Conn.cur_id
        Conn.conns.update({self.cur_id: self})
        data = {
            "conn_id": self.cur_id,
            "pg": self.pg,
            "ip": self.ip,
            "port": self.port
        }
        data.update(kv)
        self.add_message("connect", data, zmq_type="G2S_connect")
        self.conn_log("connect")

        Conn.cur_id += 1  # 当前客户端连接id  从1开始, 自增ID

    def add_message(self, type_, data, zmq_type="G2S_message"):
        # 发送消息到消息队列
        message = {
            "type": zmq_type,
            "msg_id": Conn.msg_id,
            "data": {
                "conn_id": self.cur_id,
                "message": {
                    "type": type_,
                    "data": data
                }
            }
        }
        self.zmq_server.send(message)
        Conn.msg_id += 1

    @staticmethod
    def on_server_start():
        PeriodicCallback(Conn.on_second, 1000).start()

    @staticmethod
    def on_second():
        # 定时清理超过1分钟的记录
        for conn_id, close_time in Conn.close_conns.items():
            if close_time + int(conf.DELAY_CLOSE) <= time.time():
                del Conn.close_conns[conn_id]

    @classmethod
    def on_receive_timer(cls):
        zmq_ = cls.zmq_server
        for _ in range(zmq_.QP_TIMER):
            conn_id = 0
            try:
                _, msg = zmq_.receive()
                zmq_type = msg["type"]
                conn_id = msg["data"]["conn_id"]
                # 验证消息的连续性
                msg_id = msg["msg_id"]
                if msg_id != cls.handle_msg_id:
                    logging.error('The msg_id %d is lost! data:%s' % (msg_id, msg))
                    cls.handle_msg_id = msg_id
                cls.handle_msg_id += 1

                zmq_data = msg["data"]["message"]
                if zmq_type != 'S2G_broadcast':
                    client = cls.conns.get(conn_id)
                    if not client:
                        raise ClientError("conn_id:%s is not in conns" % conn_id)
                if zmq_type.startswith('S2G_'):
                    if zmq_type == "S2G_message":
                        client.send_message(zmq_data)
                    else:
                        # 处理S2G_broadcast
                        other_handler = getattr(cls, zmq_type, None)
                        if other_handler:
                            other_handler(msg["data"])
                        else:
                            raise Exception("unknown message:%s!" % zmq_type)
                else:
                    logging.error("unknown message_type:%s!" % zmq_type)
            except zmq.Again:
                break
            except ClientError:
                if conn_id not in cls.close_conns:
                    logging.error("ClientError:\n%s\n" % format_exc())
                else:
                    if zmq_type == 'S2G_closed_ack':
                        del cls.close_conns[conn_id]
                    else:
                        # 延迟close造成的字典不一致
                        logging.info("conn_id:%s delayed closure" % conn_id)
            except:
                logging.error("conn_id:%s,UnknownException:\n%s\n" % (conn_id, format_exc()))
            finally:
                pass
    
    @classmethod
    def S2G_broadcast(cls, data):
        conns_by_pg_tag = {}
        conn_ids = data.get("conn_id")
        message = data.get("message")
        assert isinstance(conn_ids, list) and all([isinstance(i, int) for i in conn_ids]), "conn_id is not int"
        for conn_id in conn_ids:
            if conn_id not in Conn.conns:
                continue
            conn = Conn.conns[conn_id]
            conns_by_pg_tag.setdefault(conn.pg_tag, set()).add(conn)
        
        # 按pg分组发送
        for pg_tag_conns in conns_by_pg_tag.values():
            pre_return = None
            for pg_tag_conn in pg_tag_conns:
                pre_return = pg_tag_conn.send_message(message, pre_return)

    @classmethod
    def S2G_close(cls, data):
        conn_id = data.get("conn_id")
        assert isinstance(conn_id, int), "conn_id is not int"
        conn = cls.conns[conn_id]
        conn.add_message("close", {}, zmq_type="G2S_close_ack")
        conn.is_s2g_close = True
        conn.close()

    @classmethod
    def S2G_closed_ack(cls, data):
        """
        正常情况下：由于收到这个消息之前已经close，因此在on_receive_timer中会抛出ClientError
        不会进入到这里，若进入到这里，说明已经是异常情况，记录错误日志
        """
        conn_id = data.get("conn_id")
        logging.error("conn_id:%s,G2S_close_ack:%s" % (conn_id, data))
    
    def initialize(self, **kwargs):
        """必须有的函数"""
        # 防止客户端websocket的头部信息未正确设置
        # 可能原因
        # 1.客户端篡改
        # 2.客户端库异常或者出错
        # 3.被中间(网关/路由/ISP等)修改  (解决: 改为https则更安全)
        #   原因: Connection有可能会被中间修改 尤其是80端口.
        self.request.headers["Connection"] = "Upgrade"
        self.request.headers["Upgrade"] = "websocket"
        # print self.request.headers

        # 防止客户端websocket的头部信息未正确设置

    @property
    def pg(self):
        """包代号"""
        return self._pg

    @property
    def port(self):
        """端口"""
        if not self._port:
            try:
                self._port = self.stream.socket.getpeername()[1]
            except:
                pass
        return self._port

    @property
    def addr(self):
        """地址"""
        return "%s:%s" % (self.ip, self.port)

    @property
    def name(self):
        """名称"""
        return ""

    @property
    def closed(self):
        """已经关闭"""
        return self not in self.conns.values()

    def check_origin(self, origin):
        """验证来源站点"""
        return True

    def is_debug_msg(self, msg_type):
        """是否调试信息"""
        return not conf.IS_PUBLISH_SERVER

    def conn_log(self, _type, data=None, err=""):
        data = {} if data is None else data
        connect_log.log(self.addr, _type, self.cur_id, self.name, data=data, err=err, pg=self.pg)

    def msg_log(self, _type, _dir="-->", data=None, err=""):
        if self.is_debug_msg(_type):
            data = {} if data is None else data
            msg.log(
                self.addr,
                _type,
                _dir,
                name=self.name,
                data=data,
                err=err,
                pg=self.pg,
                tag=self._conn_tag
            )

    def open(self):
        """websocket接入"""
        self.open_time = time.time()
        # self.info("opened at %.3fs.(total:%d)", self.open_time - self.conn_time, len(Conn.conns))

    def close(self, code=None, reason=None):
        """关闭"""
        # self.debug("closing...")
        self.server_close = True
        # self.on_close()
        super(Conn, self).close(code=code, reason=reason)

    def on_close(self):
        """断开"""
        if not self.is_s2g_close:
            # 服务器主动关闭的时候不会发送G2S_closed
            self.add_message("closed", {}, zmq_type="G2S_closed")
        if self.cur_id in self.conns:
            del Conn.conns[self.cur_id]
            Conn.close_conns.update({self.cur_id:time.time()})
            self.conn_log("closed")

    @tornado.gen.coroutine
    def on_message(self, message_str):
        """收到消息"""
        # 临时消息数据串
        message_str_tmp = message_str
        # 消息解码成功
        message_decoded = False

        message_type = None
        try:
            # on_message_start = time.time()
            # self.debug("<-- message_str[%r]", message_str)
            self.recv += 1
            recv_bytes = len(message_str)
            self.recv_bytes += recv_bytes

            # 解码
            if self._base64:
                message_str_tmp = util.base64_decode(message_str)

            # 解压
            if self._decompress:
                # 压缩跳过(长度): 首字节表示是否压缩: \0x00 未压缩 \x01 压缩了
                if self._compress_skip_size > 0:
                    if message_str_tmp[0] == "\x01":
                        message_str_tmp = self._decompress(message_str_tmp[1:])
                    else:
                        message_str_tmp = message_str_tmp[1:]
                # 正常解压
                else:
                    message_str_tmp = self._decompress(message_str_tmp)

            # 解密
            if self._crypt:
                # 没有_key/_iv, 一直尝试rsa解密
                if not self._key:
                    message_str_tmp = util.rsa_decrypt_c(
                        message_str_tmp,
                        self._private_key,
                        base64_encoded=False
                    )
                # 有_key了
                else:
                    message_str_tmp = util.aes_decrypt_smart(
                        self._key,
                        message_str_tmp[1 + ord(message_str_tmp[0]):],
                        self._iv
                    )

            # 序列化
            message = self._loads(message_str_tmp)
            message_type = message["type"]
            data = message.get("data", {})
            
            # 解码成功
            message_decoded = True

            # 客户端消息id
            client_msg_id = message.get("id", 0)
            if not self._client_msg_id_start:
                self._client_msg_id_start = client_msg_id
            else:
                assert self._client_msg_id < client_msg_id < self._client_msg_id_start + 100000000
            self._client_msg_id = client_msg_id

            # 加密: 没有_key/_iv
            if self._crypt:
                if not self._key:
                    self._key = data["key"]
                    self._iv = data["iv"]

            self.msg_log(message_type, _dir="<--", data=data)

            if self.closed:
                raise Exception("already closed! ignore received message...")
            
            self.add_message(message_type, data)
            
            return True
        except:
            # 解码成功
            if message_decoded:
                self.exception("Exception: message_str: %r", message_str_tmp)
            else:
                self.exception(
                    "Exception: message_str: %r%s",
                    message_str,
                    "(tmp:%r)" % message_str_tmp if message_str_tmp is not message_str else ""
                )
            # 记录异常日志
            self.error(message_type or "", "%r" % message_str_tmp, format_exc())
        return False

    # 基本消息接口 ######################################################################################################
    def send_message(self, message, prev_return=None):
        """发送消息"""

        message_type = ""
        data = {}
        err = ""
        try:
            send_message_start = time.time()
            message_type = message.get("type", "")
            data = message.get("data", {})
            err = message.get("err", "")

            # 如果有上一次(广播相同数据)的返回
            # 相同的包名和连接标志
            # 而且是无加密或简单加密
            # 可以跳过组包, 直接使用上一次的发送数据
            if prev_return \
                    and self.pg_tag == prev_return["tag"] \
                    and (not self._crypt or self._simple):

                message_str = prev_return["message_str"]
                packed = 0
            else:
                packed = 1
                self.msg_log(message_type, data=data, err=err)
                # 序列化 + 加密
                if self._crypt:

                    assert self._key, "no aes key! ignore sending message..."

                    random_bytes_length = \
                        util.crc32(self._package_name + message_type) % 31 + 1
                    message_str = \
                        chr(random_bytes_length) + \
                        util.random_bytes(random_bytes_length) + \
                        util.aes_encrypt_smart(self._key, self._dumps(message), self._iv)
                # 序列化
                else:
                    message_str = self._dumps(message)

                # 压缩
                if self._compress:
                    # 压缩跳过(长度): 首字节表示是否压缩: \0x00 未压缩 \x01 压缩了
                    if self._compress_skip_size > 0:
                        if len(message_str) > self._compress_skip_size:
                            message_str = "\x01" + self._compress(message_str)
                        else:
                            message_str = "\x00" + message_str
                    # 正常压缩
                    else:
                        message_str = self._compress(message_str)

                # 编码
                if self._base64:
                    message_str = util.base64_encode(message_str)

            try:
                self.write_message(message_str, binary=self._binary)
                self.send += 1
                self.send_bytes += len(message_str)

                # 平均发送延迟 #
                Conn.total_send += 1
                Conn.total_send_time += time.time() - send_message_start
                if Conn.total_send % 10000 == 0:
                    logging.debug(
                        "Conn: total-sent %d messages, avg:%.3fus",
                        Conn.total_send,
                        Conn.total_send_time * 1000000.0 / Conn.total_send
                    )
            except:
                pass

            return {"message_str": message_str, "tag": self.pg_tag, "packed": packed}

        except:
            self.error(
                "Exception:\n%son sending message error: type:%r %s %s\n",
                format_exc(),
                message_type,
                "data:%r" % data if data else "",
                "err:%r" % err if err else "",
            )
