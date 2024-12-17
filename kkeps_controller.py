# /usr/bin/python
"""Control the KanKun Smartplug without a phone.

# This is @0x00string's script to control the KanKun Smartplug without a phone
# Enjoy, feel free to check out my notes and slides on building this
#
# you'll want to modify the applyConfig() function to fit your situation
#
# greets to @zenofex, @exploiteers and the KanKun G+ group
#
"""
import datetime
import getopt
import random
import re
import select
import sys
import time
from socket import AF_INET, SOCK_DGRAM, socket

from Cryptodome.Cipher import AES


def get_local_timezone_offset() -> str:
    """Get the local timezone offset in the format +HHMM or -HHMM."""
    # Get the timezone offset in seconds
    timezone_offset_s = time.altzone if time.localtime().tm_isdst else time.timezone
    sign = "-" if timezone_offset_s > 0 else "+"
    # Convert the offset to hours and minutes
    offset_hours = timezone_offset_s // 3600
    offset_minutes = (timezone_offset_s % 3600) // 60

    # Format the offset as a string
    return f"{sign}{offset_hours:02d}{offset_minutes:02d}"

def banner() -> None:
    """Print ASCII Art Banner."""
    ascii_art = r"""
               ___        ___   ___      _        _             _
        ____  / _ \      / _ \ / _ \    | |      (_)           ( )
       / __ \| | | |_  _| | | | | | |___| |_ _ __ _ _ __   __ _|/ ___
      / / _` | | | \ \/ / | | | | | / __| __| '__| | '_ \ / _` | / __|
     | | (_| | |_| |>  <| |_| | |_| \__ \ |_| |  | | | | | (_| | \__ \
  _  _\ \__,_|\___//_/\_\\\\___/ \___/|___/\__|_|  |_|_| |_|\__, | |___/
 | |/ /\____/    | |/ /           / ____|          | |     __/ | | | |
 | ' / __ _ _ __ | ' /_   _ _ __ | |     ___  _ __ | |_ _ |___/_ | | | ___ _ __
 |  < / _` | '_ \|  <| | | | '_ \| |    / _ \| '_ \| __| '__/ _ \| | |/ _ \ '__|
 | . \ (_| | | | | . \ |_| | | | | |___| (_) | | | | |_| | | (_) | | |  __/ |
 |_|\_\__,_|_| |_|_|\_\__,_|_| |_|\_____\___/|_| |_|\__|_|  \___/|_|_|\___|_|

"""
    print(ascii_art)


def apply_config() -> int:
    """Load global config."""
    ##
    # you can change these to your liking
    ##
    global IFACE
    IFACE = "wlan0"
    global RHOST
    RHOST = "192.168.1.173"
    global RMAC
    RMAC = "00:15:61:bd:82:91"
    global PASSWORD
    PASSWORD = "nopassword"  # noqa: S105
    global NAME
    NAME = "lan_phone"
    global VERBOSE
    VERBOSE = False
    global SSID
    SSID = "pina"
    global WLANKEY
    WLANKEY = "pineapplekey"
    global INITPASS
    INITPASS = "nopassword"
    global DEVNAME
    DEVNAME = "name"
    ##
    # you'll likely not want to change these
    ##
    global KEY
    KEY = "fdsl;mewrjope456fds4fbvfnjwaugfo"
    global RPORT
    RPORT = 27431
    global SOCKET_TIMEOUT
    SOCKET_TIMEOUT = 1
    global RECV_BUF
    RECV_BUF = 1024
    return 0


def stdout(t: str, m: str) -> None:
    """Colorize symbols in output."""
    # TODO: rewrite with rich
    if t == "+":
        print(f"\x1b[32;1m[+]\x1b[0m\t{m}\n")
    elif t == "-":
        print(f"\x1b[31;1m[-]\x1b[0m\t{m}\n")
    elif t == "*":
        print(f"\x1b[34;1m[*]\x1b[0m\t{m}\n")
    elif t == "!":
        print(f"\x1b[33;1m[!]\x1b[0m\t{m}\n")


def create_dump(data: str) -> str:
    """Format packet data for display."""
    d, b, h = "", [], []
    u = list(data)
    for e in u:
        h.append(e.encode("hex"))
        if e == "0x0":
            b.append("0")
        elif ord(e) < 30 or ord(e) > 128:
            b.append(".")
        elif ord(e) > 30 or ord(e) < 128:
            b.append(e)
    i = 0
    while i < len(h):
        if (len(h) - i) >= 16:
            d += " ".join(h[i : i + 16])
            d += "         "
            d += " ".join(b[i : i + 16])
            d += "\n"
            i = i + 16
        else:
            d += " ".join(h[i : (len(h) - 1)])
            pad = len(" ".join(h[i : (len(h) - 1)]))
            d += " " * (56 - pad)
            d += " ".join(b[i : (len(h) - 1)])
            d += "\n"
            i = i + len(h)
    return d


def crypto(switch: str, data: bytes) -> bytes:
    """Encrypt/Decrypt data."""
    k = AES.new(KEY, AES.MODE_ECB)
    if data is not None:
        if switch == "e":
            return k.encrypt(data)
        if switch == "d":
            return k.decrypt(data)
    return b""


class SockObj:
    """Socket connection to device."""

    def __init__(self, s=None, proto="udp") -> None:
        """Initialize Socket and Proto."""
        if s is None:
            if proto == "udp":
                self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif proto == "tcp":
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.settimeout(SOCKET_TIMEOUT)
        else:
            self.s = s

    def connect(self, rhost, rport) -> None:
        """Connect to host on port."""
        self.s.connect((rhost, rport))

    def tx(self, m):
        """Encrypt and Transmit data."""
        self.s.send(crypto("e", m))

    def rx(self) -> bytes:
        """Receive and decrypt data."""
        try:
            m = self.s.recv(RECV_BUF)
            return crypto("d", m)
        except:  # noqa: E722
            return ""


def txrx(ip, port, m, s):
    sock = SockObj() if s is None else SockObj(None, "tcp")
    sock.connect(ip, port)
    sock.tx(m)
    ret = sock.rx()
    if ret != "":
        return ret
    stdout("!", "Nothing returned...")
    return None


def get_packet(  # noqa: PLR0912
    t,
    e=None,
    on_time="2015-02-10-11:11:11",
    off_time="2015-02-10-11:11:11",
    enabled="n",
    open_enabled="n",
    close_enabled="n",
    timer_id=None,
):
    d, c = "%", ""
    auth = NAME + d + RMAC + d + PASSWORD + d
    if t == "open":
        c = auth + "open" + d + "request"
    elif t == "check":
        c = auth + "check" + d + "request"
    elif t == "brmode":
        c = auth + "check" + d + "brmode"
    elif t == "close":
        c = auth + "close" + d + "request"
    elif t == "total timer":
        c = auth + "check#total" + d + "timer"
    elif t == "check timer":
        c = auth + "check#" + e + "%timer"
    elif t == "heart":
        now = datetime.datetime.now(tz="UTC")
        formatted_date = now.strftime("%y-%m-%d-%T")
        c = auth + formatted_date + d + "heart"
    elif t == "confirm":
        c = auth + "confirm#" + e + d + "request"
    elif t == "confirm timer":
        c = auth + "confirm#" + e + d + "timer"
    elif t == "set timer":
        c = (
            auth
            + "alarm#"
            + str(random.randint(100, 999))
            + "#"
            + enabled
            + "#"
            + on_time
            + "#"
            + open_enabled
            + "#"
            + off_time
            + "#"
            + close_enabled
            + "#"
            + e
            + "#set"
            + d
            + "timer"
            + d
            + "timer"
        )
    elif t == "unset timer":
        c = (
            auth
            + "alarm#"
            + timer_id
            + "#"
            + enabled
            + "#"
            + on_time
            + "#"
            + open_enabled
            + "#"
            + off_time
            + "#"
            + close_enabled
            + "#"
            + e
            + "#unset"
            + d
            + "timer"
            + d
            + "timer"
        )
    elif t == "wifi config":
        c = (
            "phone"
            + d
            + SSID
            + d
            + WLANKEY
            + d
            + INITPASS
            + d
            + DEVNAME
            + d
            + "GMT"
            + get_local_timezone_offset()
        )
    while len(c) % 16 != 0:
        c = c + "\x00"
    return c


def is_confirm(m):
    """Return 1st 5 digits or None."""
    q = re.compile(r".*?(\d\d\d\d\d).*?")
    p = q.search(m)
    if p is not None:
        return p.group(1)
    return None


def is_hack(m):
    q = re.compile(".*?(hack).*?")
    p = q.search(m)
    if p is not None:
        return p.group(1)
    return None


def is_check(m):
    q = re.compile(".*?%.*?%.*?%(.*?)%rack.*?")
    p = q.search(m)
    if p is not None:
        return p.group(1)
    return None


def is_total_timer(m):
    q = re.compile(r".*?\%.*?\%.*?\%check#(.*?)#.*?")
    p = q.search(m)
    if p is not None:
        return p.group(1)
    return None


def is_timer_status(m):
    q = re.compile(".*?%.*?%.*?%alarm#(.*?)#(.)#(.*?)#(.)#(.*?)#(.)#(.*?)#(.)tack.*?")
    p = q.search(m)
    if p is not None:
        return p
    return None


def parse_ret(m):
    ret = is_confirm(m)
    if ret is not None:
        stdout("*", "confirmation number: " + ret)
        return ret
    ret = is_hack(m)
    if ret is not None:
        stdout("*", "Heartbeat ackowledged")
        return None
    ret = is_check(m)
    if ret is not None:
        stdout("*", "switch is: " + ret)
        return None
    ret = is_total_timer(m)
    if ret is not None:
        stdout("*", "There are currently " + str(ret) + " timers set")
        return None
    ret = is_timer_status(m)
    if ret is not None:
        stdout(
            "timer ID "
            + id
            + "\nopen time: "
            + ret.group(3)
            + "\nclose time: "
            + ret.group(5)
            + "\ny1y2y3: "
            + ret.group(2)
            + ret.group(4)
            + ret.group(6)
            + "\ndays repeated: "
            + ret.group(7)
            + "\nenabled: "
            + ret.group(8),
        )
        return ret
    return None


# def setRMAC():
#     RMAC = (
#         os.popen(
#             "arp -i" + IFACE + " " + RHOST + " | awk {'print $4'}").read().strip()
#     )


def sendOp(op, e=None, ont=None, offt=None, y1=None, y2=None, y3=None, tid=None):  # noqa: PLR0912
    switch = None
    if op in ("set timer", "unset timer"):
        m = get_packet(op, e, ont, offt, y1, y2, y3, tid)
    elif op in ("open", "close"):
        m = get_packet(op)
    elif op == "wifi config":
        global RHOST
        RHOST = "192.168.10.253"
        global RPORT
        RPORT = 37092
        switch = 1
        m = get_packet(op, e, ont, y1, y2)
    else:
        m = get_packet(op)
        stdout("*", "Sending " + op + " packet...")
        if VERBOSE is not False:
            stdout("*", "\n" + create_dump(m))
        ret = txrx(RHOST, RPORT, m, switch)
        if ret is not None:
            stdout("+", "received reply packet...")
            if VERBOSE is not False:
                stdout("*", "\n" + create_dump(ret))
            parsed = parse_ret(ret)
            if parsed is not None:
                if op in ("set timer", "unset timer"):
                    m = get_packet("confirm timer", parsed)
                else:
                    m = get_packet("confirm", parsed)
                stdout("*", "sending confirmation #: " + str(parsed))
                if VERBOSE is not False:
                    stdout("*", "\n" + create_dump(m))
                ret = txrx(RHOST, RPORT, m, switch)
                if ret is not None:
                    stdout("*", "received reply packet...")
                    if VERBOSE is not False:
                        stdout("*", "\n" + create_dump(ret))
                    parsed = parse_ret(ret)


def passwordJack():
    key = AES.new(KEY, AES.MODE_ECB)
    s = socket(AF_INET, SOCK_DGRAM)
    s.bind(("", 27431))
    s.setblocking(0)
    p = re.compile("(.*?)%(.*?)%(.*?).*?")
    while True:
        ret = select.select([s], [], [])
        m = ret[0][0].recv(1024)
        if VERBOSE is not False:
            stdout("+", "\n" + key.decrypt(m))
        q = p.search(m)
        if q is not None:
            stdout(
                "+",
                "Got possible credentials: name: "
                + q.group(1)
                + " mac: "
                + q.group(2)
                + " password: "
                + q.group(3),
            )


def heartbeat():
    sendOp("heart")


def check():
    sendOp("check")


def checkBRMode():
    sendOp("brmode")


def totalTimer():
    sendOp("total timer")


def checkTimer(num):
    sendOp("check timer", num)


def setTimer(start, stop, enabled, onenable, offenable, repeatstr):
    sendOp("set timer", repeatstr, start, stop, enabled, onenable, offenable)


def unsetTimer(num):
    timer_info = sendOp("check timer", num, "r")
    sendOp(
        "set timer",
        timer_info[0],
        timer_info[1],
        timer_info[2],
        timer_info[3],
        timer_info[4],
        timer_info[5],
        timer_info[6],
    )


def wifiConfig(ssid, key, initpass="nopassword", devname="name"):
    global SSID
    SSID = ssid
    global WLANKEY
    WLANKEY = key
    global INITPASS
    INITPASS = initpass
    global DEVNAME
    DEVNAME = devname
    sendOp("wifi config", SSID, WLANKEY)


def on():
    sendOp("open")


def off():
    sendOp("close")


def usage():
    banner()
    usage_text = """


Usage:  script.py -a on

    make sure to vi this script and set the IP to that of your target

    arguments:
        required:
        -a, --action    <action name> what action to perform, e.g., -a heart
        actions: on, off, heart, check, brmode, totalTimer, checkTimer, setTimer, unsetTimer, wifiConfig

        optional:
        -v              verbose output

        actions that take additional arguments:

            unsetTimer
                script.py -a unsetTimer --num 3

                --num           a number, this is an argument required for checkTimer and unsetTimer actions


            setTimer
                script.py -a setTimer --start-time "`date +%y-%m-%d-%T`" --stop-time "2015-02-10-11:22:22" --enabled y [...] --repeatstr "1,2,3"

                --start-time    <date +%y-%m-%d-%T> this is a date-string
                --stop-time     ditto
                --enabled       <y|n> timer enabled?
                --on-enabled    <y|n> on-time enabled?
                --off-enabled   <y|n> off-time enabled?
                --repeatstr     <1,2,4,5,6,7>, setTimer argument, repeat on which days?


            wifiConfig
                script.py -a wifiConfig --ssid Linksys --key "P@ssw0rd!"

                --ssid          <string>, the ssid of the network to join the device to
                --key           <string>, the key for the network to join the device to
                --initial-password <string>, the password to set for the device (default is "noPASSWORD")
                --device-name   <string>, the name to give the device (this doesnt always take and changes with the wind)

"""  # noqa: E501
    print(usage_text)


def main():  # noqa: PLR0912, PLR0915
    if apply_config() > 0:
        usage()
        sys.exit(1)
    action = None
    options, _remainder = getopt.getopt(
        sys.argv[1:],
        "a:vh",
        [
            "action=",
            "verbose",
            "num=",
            "start-time=",
            "stop-time=",
            "enabled=",
            "on-enabled=",
            "off-enabled=",
            "repeatstr=",
            "ssid=",
            "key=",
            "initial-password=",
            "device-name=",
            "ip=",
            "help",
        ],
    )

    for opt, arg in options:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-a", "--action"):
            action = arg
        elif opt in ("-v", "--verbose"):
            global VERBOSE
            VERBOSE = True
        elif opt in ("num"):
            num = arg
        elif opt in ("start-time"):
            start_time = arg
        elif opt in ("stop-time"):
            stop_time = arg
        elif opt in ("enabled"):
            enabled = arg
        elif opt in ("on-enabled"):
            onenable = arg
        elif opt in ("off-enabled"):
            offenable = arg
        elif opt in ("repeatstr"):
            repeatstr = arg
        elif opt in ("ssid"):
            global SSID
            SSID = arg
        elif opt in ("key"):
            global WLANKEY
            WLANKEY = arg
        elif opt in ("initial-password"):
            global INITPASS
            INITPASS = arg
        elif opt in ("device-name"):
            global DEVNAME
            DEVNAME = arg
        elif opt in ("ip"):
            global RHOST
            RHOST = arg

    if action is None:
        usage()
        sys.exit(1)
    elif action == "heart":
        heartbeat()
    elif action == "check":
        check()
    elif action == "on":
        on()
    elif action == "off":
        off()
    elif action == "brmode":
        checkBRMode()
    elif action == "totalTimer":
        totalTimer()
    elif action == "checkTimer":
        checkTimer(num)
    elif action == "setTimer":
        setTimer(start_time, stop_time, enabled, onenable, offenable, repeatstr)
    elif action == "unsetTimer":
        unsetTimer(num)
    elif action == "wifiConfig":
        wifiConfig(SSID, WLANKEY, INITPASS, DEVNAME)
    else:
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
