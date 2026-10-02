import json
import socket


def send_message(sock, message):
    data = json.dumps(message).encode("utf-8")
    header = len(data).to_bytes(4, "big")
    sock.sendall(header + data)


def receive_exact(sock, size):
    chunks = []
    remaining = size

    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed by peer.")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def receive_message(sock):
    header = receive_exact(sock, 4)
    size = int.from_bytes(header, "big")

    if size <= 0 or size > 10_000_000:
        raise ValueError("Invalid message size.")

    data = receive_exact(sock, size)
    return json.loads(data.decode("utf-8"))
