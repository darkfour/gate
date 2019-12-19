#!/usr/bin/env python
# -*- coding:utf-8 -*-

from traceback import format_exc
from json import loads, dumps

import db
import util

# zmq start
ZMQ_SERVER_HWM = 200000
DELAY = 20  # ms
ZMQ_ADDRESS = "tcp://*:8888"
QP_TIMER = 100  # 每次最大处理100个消息
# zmq end

# mysql数据库配置
MYSQL_HOST = "172.20.231.128"  # localhost会使用unix socket, 127.0.0.1不会
MYSQL_PORT = 3306
MYSQL_USER = "Q8ybAUWi"
MYSQL_PASS = "hReHyIY0"
MYSQL_NAME = "makemoney"
MYSQL_SETTINGS_TABLE = "settings"

# TcpServer start
port = 6667
# TcpServer end

# Server start
# 服务器端口
SERVER_PORT = 8006
# 清理最近时间段DELAY_CLOSE关闭的连接
DELAY_CLOSE = 60  # s
# 后台化
DAEMONIZE = True
# 是否 严格限制包代理服务器, 禁止串包登陆
STRICT_PG_PROXY = True
# 默认包代号
DEFAULT_PG = "game"
# Server end
IS_PUBLISH_SERVER = True

try:
    from local_conf import *
except:
    pass

LOGIC_CONF = {
    # 包相关配置 ########################################################################################################
    # 默认包代号
    "default_pg": "game",
    # (MySQL)包配置
    "pgs": {},
    # (MySQL)旧包->新包替换规则: 支持旧包以新包方式登陆
    "pgs_subs": {},
    # (MySQL)包密钥
    "pg_keys": {}
}


def get_package_name(pg):
    """由包名代号取得完整包名"""
    return PGS_REV[pg]


def _get_pg_keys(pg):
    return PG_KEYS.get(pg, PG_KEYS["(default)"])


def get_pg_public_key(pg):
    """取得公钥"""
    return "-----BEGIN PUBLIC KEY-----\n" + \
           _get_pg_keys(pg).get("public", "") + \
           "\n-----END PUBLIC KEY-----"


def get_pg_private_key(pg):
    """取得私钥"""
    return "-----BEGIN RSA PRIVATE KEY-----\n" + \
           _get_pg_keys(pg).get("private", "") + \
           "\n-----END RSA PRIVATE KEY-----"


def get_pg_aes_key(pg):
    """取得aes密钥"""
    return _get_pg_keys(pg).get("key", "")


def get_pg_aes_iv(pg):
    """取得aes密钥"""
    return _get_pg_keys(pg).get("iv", "")


# 载入设置的信息
RELOAD_SETTINGS_MSGS = ""


def reload_settings(check=False):
    """载入设置，修改LOGIC_CONF"""

    mysql_db, mysql_cursor = db.mysql_connect(
        MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASS, MYSQL_NAME,
    )

    msgs = []
    error_msgs = []
    excepted = False

    def get_new_conf(table, sql):
        """从表里取得新的配置"""
        new_conf = {}
        try:
            rows = db.mysql_read_cursor(
                mysql_cursor,
                sql.format(table=table)
            )
            success_row_count = 0
            for row in rows:
                try:
                    new_conf[row[0]] = util.unicode2utf8(loads(row[1]))
                    success_row_count += 1
                except:
                    error_msgs.append(
                        '%s: <font color="red">!ERROR!</font>'
                        ' type:<font color="red"><b>%s</b></font>, '
                        'name:<font color="red">%s</font><br/>' % (table, row[0], row[2])
                    )
                    excepted = True
            msgs.append(
                '%s: %d rows <font color="green">OK.</font><br/>' % (table, success_row_count)
            )
        except:
            error_msgs.append(
                '%s: <font color="red">Exception:%s</font><br/>' % (table, format_exc())
            )
            excepted = True
        return new_conf

    # 设置
    new_logic_conf = get_new_conf(
        MYSQL_SETTINGS_TABLE,
        "SELECT type1, `value`, `name` FROM {table} WHERE `type` in ('', 'server') ORDER BY id"
    )

    if not check:
        LOGIC_CONF.update(new_logic_conf)

    global RELOAD_SETTINGS_MSGS
    RELOAD_SETTINGS_MSGS = "\n".join(("\n".join(error_msgs), "\n".join(msgs)))
    RELOAD_SETTINGS_MSGS = \
        '<!doctype html><html lang="zh-CN"><head><meta charset="UTF-8"></head><body>' + \
        RELOAD_SETTINGS_MSGS + \
        '</body></html>'

    db.mysql_close(mysql_db, mysql_cursor)

    return excepted


# 立即载入设置
reload_settings()

# 包配置
PGS = LOGIC_CONF["pgs"]
# 旧包->新包替换规则: 支持旧包以新包方式登陆
PGS_SUBS = LOGIC_CONF["pgs_subs"]
# 旧包, 不再自动登录测试
OLD_PGS = LOGIC_CONF["old_pgs"]
# 反向包配置 {代号:全称}
PGS_REV = {v: k for k, v in PGS.items()}

PG_KEYS = LOGIC_CONF["pg_keys"]
