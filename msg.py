#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""消息日志"""

# 系统库
import logging
from traceback import format_exc

# 自己的
import util

util.makedirs("log")


class MsgLog(object):
    """消息日志类"""

    # 数据 #############################################################################################################
    # 日志日期
    log_date = ""
    # 记录文件
    log_file = None

    # 数据 #############################################################################################################


def log(addr, _type, _dir, name="", data={}, err="", pg = "", tag = ""):
    """记录消息日志"""
    try:
        today = util.time2str(fmt="%Y-%m-%d")
        # 日期发生变化
        if MsgLog.log_date != today:
            # 关闭
            if MsgLog.log_file:
                MsgLog.log_file.close()
                MsgLog.log_file = None
            # 打开
            MsgLog.log_file = open("log/msg.%s.log" % today, "a")
            MsgLog.log_date = today

        MsgLog.log_file.write(
            "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                util.time2str(fmt="%H:%M:%S"),
                pg,
                tag,
                addr,
                name,
                _dir,
                _type,
                data if data else "",
                err if err else "")
            )
    except:
        logging.fatal("act.log(addr=%r, _type=%r, pg=%r, uid=%r, data=%r, err=%r)\nException: \n%s",
                      addr, _type, pg, name, data, err, format_exc())


if __name__ == '__main__':
    log(
        "127.0.0.1:12345",
        "C2S_hello",
        "==>",
        name="liuyaobin",
        data={"a":1},
        err="INVALID TOKEN"
    )

    log(
        "127.0.0.1:12345",
        "C2S_hello",
        "==>",
        err="INVALID TOKEN"
    )

