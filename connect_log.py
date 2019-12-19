#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""消息日志"""

# 系统库
import logging
from traceback import format_exc

# 自己的
import util

util.makedirs("log")


class ConnLog(object):
    """客户端连接日志类"""

    # 数据 #############################################################################################################
    # 日志日期
    log_date = ""
    # 记录文件
    log_file = None

    # 数据 #############################################################################################################


def log(addr, _type, conn_id, name, data={}, err="", pg = ""):
    """记录消息日志"""
    try:
        today = util.time2str(fmt="%Y-%m-%d")
        # 日期发生变化
        if ConnLog.log_date != today:
            # 关闭
            if ConnLog.log_file:
                ConnLog.log_file.close()
                ConnLog.log_file = None
            # 打开
            ConnLog.log_file = open("log/connect.%s.log" % today, "a")
            ConnLog.log_date = today

        ConnLog.log_file.write(
            "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                util.time2str(fmt="%H:%M:%S"),
                _type,
                conn_id,
                pg,
                addr,
                name,
                data if data else "",
                err if err else "")
            )
    except:
        logging.fatal("Conn.log(addr=%r, _type=%r, pg=%r, name=%r, conn_id=%r, data=%r, err=%r)\nException: \n%s",
                      addr, _type, pg, name, conn_id, data, err, format_exc())


if __name__ == '__main__':
    pass
