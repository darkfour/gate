#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""数据库"""

# 系统库
import time

# 第三方
import MySQLdb

# 自己的
import util


class MySQLDB(util.LogObject):
    """mysql类"""

    # 字符集
    CHARSET = 'utf8'
    # 连接超时
    CONNECT_TIMEOUT = 1

    def __init__(self, host, port, user, password, database, autocommit=True):
        """初始化"""
        self.host = host
        self.port = port
        self.user = user
        self.database = database
        self._password = password
        self._db_conn = None
        self._cursor = None
        self.connected_count = 0

        self.autocommit = autocommit

        self.connect()

    def connect(self):
        """连接"""
        self.debug(
            "%sconnecting to %s:%s:%s...",
            "re" if self.connected_count else "",
            self.host,
            self.port,
            self.database
        )
        now = time.time()

        self._db_conn = MySQLdb.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            passwd=self._password,
            db=self.database,
            connect_timeout=MySQLDB.CONNECT_TIMEOUT,
            charset=MySQLDB.CHARSET,
            autocommit=self.autocommit
        )
        self._cursor = self._db_conn.cursor()

        self.debug("connected in %.3fms.", 1000 * (time.time() - now))
        self.connected_count += 1

    def execute(self, sql, args=None, log_finished=False, many=False):
        """mysql执行(包括CALL存储过程), 异常自动重连
            如果是select/call返回所有数据
            如果是其他(insert/update/delete)则返回行数
        """
        try:
            if self._db_conn is None:
                self.connect()
            self.debug("executing: %r", sql)
            now = time.time()

            sql_upper = sql.upper()
            if sql_upper.startswith("SELECT ") or sql_upper.startswith("CALL "):
                self._cursor.execute(sql, args)
                result = self._cursor.fetchall()
                # 存储过程
                if sql.upper().startswith("CALL "):
                    while self._cursor.nextset():
                        pass
                result_str = '%d rows.' % len(result)
            else:
                if many:
                    result = self._cursor.executemany(sql, args)
                else:
                    result = self._cursor.execute(sql, args)
                result_str = '%d rows affected.' % result

            ms = 1000 * (time.time() - now)
            if ms >= 10 or log_finished:
                self.debug("finished in %.3fms, %s", 1000 * (time.time() - now), result_str)

            return result

        except Exception as e:
            self.exception("Exception: while executing: %r, %r", sql, args)
            self.close()
            raise e

    def commit(self):
        """提交"""
        if self._db_conn:
            self._db_conn.commit()

    def rollback(self):
        """回退"""
        if self._db_conn:
            self._db_conn.rollback()

    def ping(self):
        if self._db_conn:
            try:
                self._db_conn.ping()
            except:
                self._db_conn.ping(True)

    def close(self):
        """关闭"""
        try:
            if self._cursor:
                self._cursor.close()
        except:
            pass
        try:
            if self._db_conn:
                self._db_conn.close()
        except:
            pass
        self._db_conn = self._cursor = None


def mysql_read(host, port, user, password, dbname, sql, args=None):
    """mysql read"""
    db, cursor = mysql_connect(host, port, user, password, dbname)
    result = mysql_read_cursor(cursor, sql, args)
    mysql_close(db, cursor)
    return result


def mysql_connect(host, port, user, password, dbname):
    """mysql connect"""
    db = MySQLdb.connect(host=host,
                         port=port,
                         user=user,
                         passwd=password,
                         db=dbname,
                         connect_timeout=MySQLDB.CONNECT_TIMEOUT,
                         charset=MySQLDB.CHARSET,
                         autocommit=True
                         )
    cursor = db.cursor()
    return db, cursor


def mysql_read_cursor(cursor, sql, args=None):
    """mysql read cursor"""
    cursor.execute(sql, args)
    return cursor.fetchall()


def mysql_close(db, cursor):
    """mysql close"""
    try:
        cursor.close()
    except:
        pass
    try:
        db.close()
    except:
        pass
