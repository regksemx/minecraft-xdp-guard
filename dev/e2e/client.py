#!/usr/bin/env python3
"""Client side of dev/e2e/run.py: reads one command per line from stdin and
answers each with one line on stdout. Connections stay open between commands
so the test can check what survives a restart of the filter."""
import socket
import sys
import time

SERVER = "10.99.0.1"
SOURCE = sys.argv[1] if len(sys.argv) > 1 else ""  # local address to connect from
MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
TIMEOUT = 1.0
handles = {}


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def packet(body):
    return varint(len(body)) + body


def handshake(host, intention):
    host = host.encode()
    return packet(b"\x00" + varint(767) + varint(len(host)) + host + (25565).to_bytes(2, "big") + varint(intention))


def keep(sock):
    handle = str(len(handles) + 1)
    handles[handle] = sock
    return handle


def tcp_connect(port, timeout=TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.bind((SOURCE, 0))
    sock.connect((SERVER, port))
    return sock


def udp_exchange(sock, port, payload, attempts=1):
    """Sends a datagram and returns the answer. With several attempts it is
    resent every 0.5s, like RakNet and ICE do with their connection requests."""
    sock.settimeout(TIMEOUT if attempts == 1 else 0.5)
    try:
        for attempt in range(attempts):
            sock.sendto(payload, (SERVER, port))
            try:
                return sock.recv(2048)
            except socket.timeout:
                if attempt == attempts - 1:
                    raise
    finally:
        sock.settimeout(TIMEOUT)


def new_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    sock.bind((SOURCE, 0))
    return sock


def java_status(host):
    sock = tcp_connect(25565)
    sock.sendall(handshake(host, 1))
    sock.sendall(b"\x01\x00")
    reply = sock.recv(4096)
    sock.sendall(packet(b"\x01" + bytes(8)))
    pong = sock.recv(4096)
    sock.close()
    return "ok" if b"hello" in reply and len(pong) == 10 else "bad reply"


def java_login(name, host, split="0", timeout=TIMEOUT):
    sock = tcp_connect(25565, timeout=float(timeout))
    login = packet(b"\x00" + varint(len(name)) + name.encode() + bytes(16))
    if split == "1":
        sock.sendall(handshake(host, 2))
        time.sleep(0.05)
        sock.sendall(login)
    else:
        sock.sendall(handshake(host, 2) + login)
    reply = sock.recv(64)
    if reply != b"LOGIN_OK\n":
        sock.close()
        return "bad reply"
    return "ok " + keep(sock)


def echo(handle):
    sock = handles[handle]
    sock.sendall(b"keepalive")
    return "ok" if sock.recv(64) == b"keepalive" else "bad reply"


def tcp_raw(port, hex_payload):
    sock = tcp_connect(int(port))
    sock.sendall(bytes.fromhex(hex_payload))
    reply = sock.recv(64)
    sock.close()
    return "reply" if reply else "closed"


def http(port):
    sock = tcp_connect(int(port))
    sock.sendall(b"GET /v1/join HTTP/1.1\r\nHost: e2e\r\n\r\n")
    reply = sock.recv(256)
    sock.close()
    return "ok" if reply.startswith(b"HTTP/1.1 200") else "bad reply"


def connect_time(port):
    start = time.monotonic()
    sock = tcp_connect(int(port), timeout=5.0)
    sock.close()
    return f"ok {time.monotonic() - start:.2f}"


def syn_burst(port, count):
    connected = 0
    for _ in range(int(count)):
        try:
            tcp_connect(int(port), timeout=0.3).close()
            connected += 1
        except OSError:
            pass
    return f"ok {connected}"


def rak_ping(attempts="1"):
    reply = udp_exchange(new_udp(), 19132, b"\x01" + bytes(8) + MAGIC + bytes(8), int(attempts))
    return "ok" if reply[0] == 0x1C else "bad reply"


def rak_connect(attempts="1"):
    sock = new_udp()
    ocr1 = b"\x05" + MAGIC + b"\x0b"
    if udp_exchange(sock, 19132, ocr1 + bytes(1464 - len(ocr1)), int(attempts))[0] != 0x06:
        return "bad reply"
    ocr2 = b"\x07" + MAGIC + b"\x04\x0a\x63\x00\x01\x4a\xbc" + (1492).to_bytes(2, "big") + bytes(8)
    if udp_exchange(sock, 19132, ocr2)[0] != 0x08:
        return "bad reply"
    return "ok " + keep(sock)


def rak_data(handle):
    reply = udp_exchange(handles[handle], 19132, b"\x84\x01\x00\x00\x00\x00\x08\x15")
    return "ok" if reply[0] == 0xC0 else "bad reply"


def rak_stray():
    return rak_data(keep(new_udp()))


def stray_burst(seconds):
    """Sends game data without a session every 2ms and counts the answers:
    any answer means a packet got past the filter."""
    sock = new_udp()
    sock.setblocking(False)
    sent = answers = 0
    end = time.monotonic() + float(seconds)
    while time.monotonic() < end:
        sock.sendto(b"\x84\x01\x00\x00\x00\x00\x08\x15", (SERVER, 19132))
        sent += 1
        time.sleep(0.002)
        try:
            while True:
                sock.recv(2048)
                answers += 1
        except BlockingIOError:
            pass
    return f"ok {answers} {sent}"


def ice_open(attempts="1"):
    sock = new_udp()
    stun = b"\x00\x01\x00\x08\x21\x12\xa4\x42" + bytes(12) + bytes(8)
    if udp_exchange(sock, 27020, stun, int(attempts)) != stun:
        return "bad reply"
    return "ok " + keep(sock)


def ice_dtls(handle):
    record = b"\x16\xfe\xfd" + bytes(10) + b"\x00\x04abcd"
    return "ok" if udp_exchange(handles[handle], 27020, record) == record else "bad reply"


def ice_stray():
    return ice_dtls(keep(new_udp()))


for line in sys.stdin:
    command, *args = line.split()
    try:
        result = globals()[command](*args)
    except socket.timeout:
        result = "timeout"
    except OSError as error:
        result = f"error {error}"
    print(result, flush=True)
