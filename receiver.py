import socket
from datetime import datetime
from des import encrypt_to_hex, decrypt_from_hex
from common import send_message, receive_message

HOST = "0.0.0.0"
PORT = 5000

# Shared beforehand. It is intentionally NOT transmitted.
SHARED_KEY = "MYKEY123"


def main():
    print("=" * 60)
    print("DES TWO-WAY COMMUNICATION - RECEIVER")
    print("=" * 60)
    print(f"Listening on port {PORT} ...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)

        print("[+] Waiting for sender connection...")

        conn, address = server.accept()

        with conn:
            print(f"[+] Connected from {address}")
            print("[+] Shared key is already known by both sides.")
            print("[+] Key is NOT transmitted.\n")

            while True:
                try:
                    message = receive_message(conn)
                except (ConnectionError, OSError):
                    print("[!] Sender disconnected.")
                    break

                if message.get("type") == "close":
                    print("[!] Sender closed the connection.")
                    break

                if message.get("type") != "ciphertext":
                    print("[!] Unknown message type.")
                    continue

                ciphertext = message["data"]

                try:
                    plaintext = decrypt_from_hex(ciphertext, SHARED_KEY)
                except Exception as exc:
                    print(f"[!] Decryption error: {exc}")
                    continue

                print("\n" + "=" * 60)
                print("INCOMING MESSAGE")
                print("=" * 60)
                print("Ciphertext received :", ciphertext)
                print("Decrypted plaintext :", plaintext)
                print("=" * 60)

                reply = input("You (Receiver) > ")

                if reply.lower() in {"exit", "quit"}:
                    send_message(conn, {"type": "close"})
                    print("Connection closed.")
                    break

                reply_ciphertext = encrypt_to_hex(reply, SHARED_KEY)

                print("  Plaintext  :", reply)
                print("  Ciphertext :", reply_ciphertext)
                print("  -> Sending ciphertext only...")

                send_message(conn, {
                    "type": "ciphertext",
                    "data": reply_ciphertext,
                    "timestamp": datetime.now().isoformat(timespec="seconds")
                })


if __name__ == "__main__":
    main()
