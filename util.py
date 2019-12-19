#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""工具"""

# 系统库
import os
import sys
import logging
import logging.handlers
import platform
import time
import random
import base64
import binascii

# 第三方
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


def real_ip(request):
    """取得真实IP"""

    x_original_forwarded_for = request.headers.get('x-Original-Forwarded-For', '')
    if x_original_forwarded_for:
        return x_original_forwarded_for

    x_forwarded_for = request.headers.get('X-Forwarded-For', '').strip()
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    return request.headers.get('X-Real-IP', request.remote_ip)


def rsa_decrypt(string, key_str, base64_encoded=True):
    """rsa解密"""
    rsakey = RSA.importKey(key_str)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    crypted = string
    if base64_encoded:
        crypted = base64.b64decode(string)
    return cipher.decrypt(crypted, "")


def rsa_decrypt_c(string, key_str, base64_encoded=True):
    """rsa解密"""
    rsakey = serialization.load_pem_private_key(key_str, password=None, backend=default_backend())
    crypted = string
    if base64_encoded:
        crypted = base64.b64decode(string)
    return rsakey.decrypt(crypted, PKCS1v15())


def aes_encrypt(key, data, iv = ""):
    """AES加密
    """
    if len(data) % len(key):
        data = data + '\0' * (len(key) - len(data) % len(key))
    if not iv:
        return AES.new(key, mode = AES.MODE_ECB).encrypt(data)
    else:
        return AES.new(key, mode = AES.MODE_CBC, IV = iv).encrypt(data)


def aes_decrypt(key, data, iv = ""):
    """AES解密
    """
    if not iv:
        return AES.new(key, mode = AES.MODE_ECB).decrypt(data).rstrip('\x00')
    else:
        return AES.new(key, mode=AES.MODE_CBC, IV=iv).decrypt(data).rstrip('\x00')


def aes_encrypt_c(key, data, iv=""):
    """AES加密
    """
    if len(data) % len(key):
        data = data + '\0' * (len(key) - len(data) % len(key))
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv) if iv else modes.ECB(),
        backend=default_backend()).encryptor()
    return encryptor.update(data) # + encryptor.finalize()


def aes_decrypt_c(key, data, iv=""):
    """AES解密
    """
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv) if iv else modes.ECB(),
        backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(data) # + decryptor.finalize()
    return decrypted_data.rstrip("\x00")


def aes_encrypt_smart(key, data, iv=""):
    """AES加密智能版"""
    if len(data) >= 1024:
        return aes_encrypt_c(key, data, iv)
    return aes_encrypt(key, data, iv)


def aes_decrypt_smart(key, data, iv=""):
    """AES解密智能版"""
    if len(data) >= 1024:
        return aes_decrypt_c(key, data, iv)
    return aes_decrypt(key, data, iv)


def random_bytes(length):
    """随机字节"""
    if length <= 0:
        return ""
    r_bytes = ("%%0%dx" % (length * 2)) % random.randint(0, (0x100 << ((length - 1) * 8)) - 1)
    return r_bytes.decode('hex')


def crc32(string):
    """crc32"""
    return binascii.crc32(string)


def base64_encode(s):
    return base64.b64encode(s)


def base64_decode(s):
    return base64.b64decode(s)


def makedirs(path):
    """创建目录"""
    if not os.path.exists(path):
        os.makedirs(path)


def makefiledirs(filepath):
    """为文件创建目录"""
    if os.path.split(filepath)[0]:
        makedirs(os.path.split(filepath)[0])


def now():
    """当前时间timestamp(秒,整数)"""
    return int(time.time())


def time2str(t=None, fmt="%Y-%m-%d %H:%M:%S", offset_second=0):
    """时间timestamp转字符串
    """
    t = time.time() if t is None else t
    t += offset_second
    return time.strftime(fmt, time.localtime(t))


class UnicodeStreamFilter(object):
    """utf编码在win32中文命令行下输出转码"""

    def __init__(self, target):
        self.target = target

    def write(self, s):
        if type(s) == str:
            s = s.decode("utf-8")
        s = s.encode(self.target.encoding)
        self.target.write(s)


# utf编码在win32中文命令行下输出转码
if sys.stdout.encoding == 'cp936':
    sys.stdout = UnicodeStreamFilter(sys.stdout)
    sys.stderr = UnicodeStreamFilter(sys.stderr)


def is_linux():
    """是否linux系统"""
    return platform.system() in ('Linux', 'Darwin')


def is_windows():
    """是否Windows系统"""
    return platform.system() == 'Windows'


def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    """
    do the UNIX double-fork magic, see Stevens' "Advanced
    Programming in the UNIX Environment" for details (ISBN 0201563177)
    http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
    """
    sys.stdout.write("daemonizing...\n")
    if not is_linux():
        return
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # decouple from parent environment
    # os.chdir("/")     # 不需要
    os.setsid()
    # os.umask(0)       # 不需要

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


class LogObject(object):
    """日志对象"""

    def debug(self, fmt, *args, **kwargs):
        logging.debug("%s : " + fmt, self, *args, **kwargs)

    def info(self, fmt, *args, **kwargs):
        logging.info("%s : " + fmt, self, *args, **kwargs)

    def exception(self, fmt, *args, **kwargs):
        logging.exception("%s : " + fmt, self, *args, **kwargs)

    def warning(self, fmt, *args, **kwargs):
        logging.warning("%s : " + fmt, self, *args, **kwargs)

    def error(self, fmt, *args, **kwargs):
        logging.error("%s : " + fmt, self, *args, **kwargs)

    def fatal(self, fmt, *args, **kwargs):
        logging.fatal("%s : " + fmt, self, *args, **kwargs)

    def __str__(self):
        return "[%s]" % self.__class__.__name__


def unicode2utf8(obj):
    """转utf-8"""
    if isinstance(obj, dict):
        return {unicode2utf8(key): unicode2utf8(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [unicode2utf8(element) for element in obj]
    elif isinstance(obj, tuple):
        return tuple(unicode2utf8(element) for element in obj)
    elif isinstance(obj, set):
        return set(unicode2utf8(element) for element in obj)
    elif isinstance(obj, unicode):
        return obj.encode('utf-8')
    else:
        return obj


# 颜色
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(30, 38)
# 加颜色函数
colorfy = lambda bold, color, target: "\033[%d;%dm%s\033[0m" % (bold, color, target)
# 高亮颜色函数
black           = lambda target: colorfy(1, BLACK,   target)
red             = lambda target: colorfy(1, RED,     target)
green           = lambda target: colorfy(1, GREEN,   target)
yellow          = lambda target: colorfy(1, YELLOW,  target)
blue            = lambda target: colorfy(1, BLUE,    target)
magenta         = lambda target: colorfy(1, MAGENTA, target)
cyan            = lambda target: colorfy(1, CYAN,    target)
white           = lambda target: colorfy(1, WHITE,   target)
# 普通颜色函数
normal_black    = lambda target: colorfy(0, BLACK,   target)
normal_red      = lambda target: colorfy(0, RED,     target)
normal_green    = lambda target: colorfy(0, GREEN,   target)
normal_yellow   = lambda target: colorfy(0, YELLOW,  target)
normal_blue     = lambda target: colorfy(0, BLUE,    target)
normal_magenta  = lambda target: colorfy(0, MAGENTA, target)
normal_cyan     = lambda target: colorfy(0, CYAN,    target)
normal_white    = lambda target: colorfy(0, WHITE,   target)


def init_logging(log_filename,
                 log_filelevel=logging.DEBUG,
                 log_errorlevel=logging.ERROR,
                 log_streamlevel=logging.DEBUG,
                 daily=True,
                 datefmt='%H:%M:%S',
                 colorfy=False,
                 millseconds=True):
    """日志初始化"""
    if colorfy and is_linux():
        # logging.addLevelName(logging.DEBUG, green(logging.getLevelName(logging.DEBUG)))
        # logging.addLevelName(logging.INFO, normal_white(logging.getLevelName(logging.INFO)))
        logging.addLevelName(logging.WARNING, yellow(logging.getLevelName(logging.WARNING)))
        logging.addLevelName(logging.ERROR, red(logging.getLevelName(logging.ERROR)))
        logging.addLevelName(logging.FATAL, magenta(logging.getLevelName(logging.FATAL)))

    # 显示格式
    millseconds_fmt = ".%(msecs)03d" if millseconds else ""
    log_format = '%(asctime)s' + millseconds_fmt + ' %(levelname)s : %(message)s'

    logging.basicConfig(level=log_streamlevel,
                        format=log_format,
                        datefmt=datefmt)
    # 日志文件设置
    if log_filename:
        makefiledirs(log_filename)
        if daily:
            file_handler = logging.handlers.TimedRotatingFileHandler(log_filename, when='MIDNIGHT')
        else:
            file_handler = logging.FileHandler(log_filename)
        file_handler.setLevel(log_filelevel)
        file_handler.setFormatter(
            logging.Formatter(log_format, datefmt=datefmt)
        )
        logging.getLogger().addHandler(file_handler)

        if log_errorlevel:
            if daily:
                errorfile_handler = logging.handlers.TimedRotatingFileHandler(log_filename + ".ERROR", when='MIDNIGHT')
            else:
                errorfile_handler = logging.FileHandler(log_filename + ".ERROR")
            errorfile_handler.setLevel(log_errorlevel)
            errorfile_handler.setFormatter(
                logging.Formatter(log_format, datefmt=datefmt)
            )
            logging.getLogger().addHandler(errorfile_handler)


if __name__ == '__main__':
    pass
