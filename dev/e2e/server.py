#!/usr/bin/env python3
"""Stand-ins for the services behind the filter, for dev/e2e/run.py.

  tcp 25565  Minecraft Java: answers status + ping, accepts a login and then
             echoes everything it receives
  tcp 19132  HTTP (NetherNet signaling stand-in): answers every request with 200
  tcp 8080   plain echo, not protected by the filter
  udp 19132  RakNet: pong, OpenConnectionReply 1 and 2, ACK for frame sets
  udp 27020  echo (NetherNet ICE stand-in)
  udp 24454  echo (voice chat stand-in)

Every TCP connection that delivers data is appended to the file given as
first argument, so the test can tell what got through the filter.
"""
import socket
import sys
import threading

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
events = open(sys.argv[1], "a", buffering=1)


def read_varint(buf, pos):
    value = shift = 0
    while True:
        if pos >= len(buf):
            return None, pos
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def read_packet(conn, buf):
    """Returns (packet body, remaining buffer) or (None, buf) on EOF."""
    while True:
        length, pos = read_varint(buf, 0)
        if length is not None and len(buf) - pos >= length:
            return buf[pos:pos + length], buf[pos + length:]
        chunk = conn.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk


def java_client(conn):
    try:
        handshake, buf = read_packet(conn, b"")
        if handshake is None:
            return
        _, pos = read_varint(handshake, 0)         # packet id
        _, pos = read_varint(handshake, pos)       # protocol version
        host_len, pos = read_varint(handshake, pos)
        host = handshake[pos:pos + host_len].split(b"\0")[0].decode()
        intention = handshake[-1]
        if intention == 1:
            events.write(f"java status {host}\n")
            request, buf = read_packet(conn, buf)
            if request is None:
                return
            json = b'{"version":{"name":"e2e","protocol":767},"description":"hello"}'
            body = b"\x00" + varint(len(json)) + json
            conn.sendall(varint(len(body)) + body)
            ping, buf = read_packet(conn, buf)
            if ping is not None:
                conn.sendall(varint(len(ping)) + ping)
            return
        login, buf = read_packet(conn, buf)
        if login is None:
            return
        name_len, pos = read_varint(login, 1)
        name = login[pos:pos + name_len].decode()
        events.write(f"java login {host} {name}\n")
        conn.sendall(b"LOGIN_OK\n")
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def http_client(conn):
    try:
        data = conn.recv(4096)
        if data:
            events.write(f"http {data.split(b' ')[0].decode(errors='replace')}\n")
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    except OSError:
        pass
    finally:
        conn.close()


def echo_client(conn):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            events.write("echo\n")
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def dual_stack(kind, port):
    """A socket that serves IPv4 and IPv6 on the same port."""
    sock = socket.socket(socket.AF_INET6, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    return sock


def tcp_server(port, handler):
    listener = dual_stack(socket.SOCK_STREAM, port)
    listener.listen(128)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def raknet_server(port):
    sock = dual_stack(socket.SOCK_DGRAM, port)
    while True:
        data, addr = sock.recvfrom(2048)
        kind = data[0]
        if kind in (0x01, 0x02):
            events.write(f"raknet ping {addr[0].removeprefix('::ffff:')}\n")
            sock.sendto(b"\x1c" + data[1:9] + bytes(8) + MAGIC + b"\x00\x05MCPE;", addr)
        elif kind == 0x05:
            sock.sendto(b"\x06" + MAGIC + bytes(8) + b"\x00\x05\xd4", addr)
        elif kind == 0x07:
            sock.sendto(b"\x08" + MAGIC + bytes(8), addr)
        elif kind & 0x80:
            sock.sendto(b"\xc0\x00\x01\x01" + data[1:4], addr)


def udp_echo(port):
    sock = dual_stack(socket.SOCK_DGRAM, port)
    while True:
        data, addr = sock.recvfrom(2048)
        sock.sendto(data, addr)


for target, args in [
    (tcp_server, (25565, java_client)),
    (tcp_server, (19132, http_client)),
    (tcp_server, (8080, echo_client)),
    (raknet_server, (19132,)),
    (udp_echo, (27020,)),
    (udp_echo, (24454,)),
]:
    threading.Thread(target=target, args=args, daemon=True).start()

print("ready", flush=True)
threading.Event().wait()
