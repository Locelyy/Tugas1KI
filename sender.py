"""
sender.py
Run this file in Terminal A.

The sender and receiver both know the shared DES key beforehand.
The key is NEVER sent through the socket.
"""

import socket
from datetime import datetime
from des import encrypt_to_hex, decrypt_from_hex
from common import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000

# Shared beforehand. It is intentionally NOT transmitted.
SHARED_KEY = "MYKEY123"


def print_received_message(message):
    if message.get("type") != "ciphertext":
        print("\n[!] Unexpected message:", message)
        return

    ciphertext = message["data"]
    plaintext = decrypt_from_hex(ciphertext, SHARED_KEY)

    print("\n" + "=" * 60)
    print("INCOMING MESSAGE")
    print("=" * 60)
    print("Ciphertext received :", ciphertext)
    print("Decrypted plaintext :", plaintext)
    print("=" * 60)


def main():
    print("=" * 60)
    print("DES TWO-WAY COMMUNICATION - SENDER")
    print("=" * 60)
    print(f"Connecting to {HOST}:{PORT} ...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("[+] Connected to receiver.")
        print("[+] Shared key is already known by both sides.")
        print("[+] Key is NOT transmitted.\n")

        while True:
            text = input("You (Sender) > ")

            if text.lower() in {"exit", "quit"}:
                try:
                    send_message(sock, {"type": "close"})
                except OSError:
                    pass
                print("Connection closed.")
                break

            ciphertext = encrypt_to_hex(text, SHARED_KEY)

            print("  Plaintext  :", text)
            print("  Ciphertext :", ciphertext)
            print("  -> Sending ciphertext only...")

            send_message(sock, {
                "type": "ciphertext",
                "data": ciphertext,
                "timestamp": datetime.now().isoformat(timespec="seconds")
            })

            try:
                response = receive_message(sock)
            except (ConnectionError, OSError):
                print("[!] Receiver disconnected.")
                break

            if response.get("type") == "close":
                print("[!] Receiver closed the connection.")
                break

            print_received_message(response)


if __name__ == "__main__":
    main()
